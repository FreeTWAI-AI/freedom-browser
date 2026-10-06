// Freedom modification (AGPL-3.0-or-later §5(a) prominent notice).
// Added 2026-10-06. Managed-mode guard for the 自由工坊 neo client.
// Not part of upstream BrowserOS.

//! Managed-mode guard pipeline.
//!
//! Order, for every tool that can read a page or cause an effect:
//! native/MCP auth, bound attempt, schema/connection/scheme,
//! domain/control/target, begin, execute, observation, receipt.
//! A missing context denies. It does not fall through to upstream.
//! A session label is never sent to the verifier.

use std::{collections::BTreeMap, future::Future, net::IpAddr};

use axum::http::{HeaderMap, StatusCode, header};
use rmcp::{
    ErrorData as McpError,
    model::{CallToolResult, ContentBlock},
};
use serde_json::json;
use tokio_util::sync::CancellationToken;

use super::{ContextError, FreedomRunContext, FreedomRuntime, VerifyFailure};
use crate::freedom::{local_api, registry};

pub const CODE_CONTEXT_REQUIRED: &str = "freedom_context_required";
pub const CODE_TOKEN_INVALID: &str = "freedom_token_invalid";
pub const CODE_SCOPE: &str = "freedom_scope_denied";
pub const CODE_RAW_EXEC: &str = "freedom_raw_exec_denied";
pub const CODE_SCHEME: &str = "freedom_scheme_denied";
pub const CODE_UNSCOPED: &str = "freedom_unscoped_read_denied";
pub const CODE_TARGET: &str = "freedom_target_required";
pub const CODE_LATE_AUDIT: &str = "freedom_late_audit_only";
pub const CODE_MODE_FIXED: &str = "freedom_mode_fixed";
pub const CODE_PROFILE: &str = "freedom_profile_not_distinct";
pub const CODE_ATTEMPT_MISMATCH: &str = "freedom_attempt_mismatch";
pub const CODE_BINDING_MISMATCH: &str = "freedom_binding_mismatch";
pub const CODE_GRANT_REVOKED: &str = "freedom_grant_revoked";
pub const CODE_BUSINESS: &str = "freedom_business_acceptance_is_platform_owned";

pub const STEP_NATIVE_AUTH: &str = "native_auth";
pub const STEP_BOUND_ATTEMPT: &str = "bound_attempt";
pub const STEP_SCHEMA: &str = "schema_connection_scheme";
pub const STEP_DOMAIN: &str = "domain_control_target";
pub const STEP_BEGIN: &str = "begin";
pub const STEP_EXECUTE: &str = "execute";
pub const STEP_OBSERVATION: &str = "observation";
pub const STEP_RECEIPT: &str = "receipt";

const MSG_CONTEXT: &str = "需要已驗證的自由工坊上下文";
const MSG_TOKEN_INVALID: &str = "憑證無效";
const MSG_SCOPE: &str = "超出本次連接的範圍";
const MSG_RAW: &str = "受管理的執行環境拒絕任意程式碼";
const MSG_SCHEME: &str = "不允許這個網址配置";
const MSG_UNSCOPED: &str = "受管理的執行環境拒絕未限定範圍的讀取";
const MSG_TARGET: &str = "需要本次連接範圍內的分頁";
const MSG_LATE: &str = "已撤銷，這次操作只留下稽核紀錄";
const MSG_BUSINESS: &str = "業務接受狀態由自由工坊平台決定";

const RAW_TOOLS: &[&str] = &["run", "evaluate", "script_hook", "helper_runtime"];
const PAGE_TOOLS: &[&str] = &[
    "navigate",
    "snapshot",
    "diff",
    "act",
    "download",
    "upload",
    "read",
    "grep",
    "screenshot",
    "pdf",
    "wait",
];
const SESSION_TOOLS: &[&str] = &[
    "name_session",
    "save_skill",
    "mark_skill_run",
    "request_human_help",
    "await_human_help",
];
const UNSCOPED_TOOLS: &[&str] = &["history", "windows", "tab_groups"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    InFlight,
    Executed,
    AuditOnly,
}

#[derive(Debug, Clone)]
struct EffectTicket {
    disposition: Disposition,
    business_accepted: bool,
}

#[derive(Debug, Default)]
pub struct Journal {
    next_id: u64,
    tickets: BTreeMap<u64, EffectTicket>,
    notes: Vec<String>,
}

impl Journal {
    pub fn begin_effect(&mut self) -> u64 {
        self.next_id = self.next_id.saturating_add(1);
        let id = self.next_id;
        self.tickets.insert(
            id,
            EffectTicket {
                disposition: Disposition::InFlight,
                business_accepted: false,
            },
        );
        id
    }

    pub fn cancel_effect(&mut self, id: u64) {
        if let Some(ticket) = self.tickets.get_mut(&id) {
            ticket.disposition = Disposition::AuditOnly;
            ticket.business_accepted = false;
        }
        self.notes.push(format!("audit-only:{id}"));
    }

    pub fn settle_executed(&mut self, id: u64) {
        if let Some(ticket) = self.tickets.get_mut(&id) {
            if ticket.disposition != Disposition::AuditOnly {
                ticket.disposition = Disposition::Executed;
            }
            ticket.business_accepted = false;
        }
    }

    /// The client never sets business acceptance. Audit-only and in-flight
    /// tickets report [`CODE_LATE_AUDIT`]. An executed ticket reports
    /// [`CODE_BUSINESS`] because acceptance belongs to the platform.
    pub fn try_mark_business_accepted(&mut self, id: u64) -> Result<(), &'static str> {
        let Some(ticket) = self.tickets.get(&id) else {
            return Err(CODE_LATE_AUDIT);
        };
        match ticket.disposition {
            Disposition::AuditOnly | Disposition::InFlight => Err(CODE_LATE_AUDIT),
            Disposition::Executed => {
                self.notes.push(format!("{CODE_BUSINESS}: {MSG_BUSINESS}"));
                Err(CODE_BUSINESS)
            }
        }
    }

    #[must_use]
    pub fn business_accepted(&self, id: u64) -> bool {
        self.tickets
            .get(&id)
            .is_some_and(|ticket| ticket.business_accepted)
    }

    #[must_use]
    pub fn disposition(&self, id: u64) -> Option<Disposition> {
        self.tickets.get(&id).map(|ticket| ticket.disposition)
    }

    #[must_use]
    pub fn audit_notes(&self) -> &[String] {
        &self.notes
    }
}

/// Owned view of one MCP tool call. `session_label` is recorded and ignored.
#[derive(Debug, Clone)]
pub struct ToolRequest {
    pub tool: String,
    pub token: Option<String>,
    pub session_label: Option<String>,
    pub page: Option<u32>,
    pub url: Option<String>,
    pub tabs_action: Option<String>,
    pub cancel: CancellationToken,
}

impl ToolRequest {
    #[must_use]
    pub fn new(tool: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            token: None,
            session_label: None,
            page: None,
            url: None,
            tabs_action: None,
            cancel: CancellationToken::new(),
        }
    }
}

#[derive(Debug)]
pub struct PipelineOutcome {
    pub result: CallToolResult,
    pub steps: Vec<&'static str>,
    pub business_accepted: bool,
    pub upstream_called: bool,
    pub ticket: Option<u64>,
    pub principal: Option<String>,
}

#[derive(Debug)]
pub enum HttpGate {
    Continue {
        local_authorized: bool,
    },
    Deny {
        status: StatusCode,
        code: &'static str,
        message: &'static str,
    },
}

struct Denial {
    code: &'static str,
    message: &'static str,
    steps: Vec<&'static str>,
}

/// Standalone returns `None` and leaves the upstream path alone.
/// Managed mode returns `Some` when steps 1–4 deny the call.
#[must_use]
pub fn precheck_mcp_tool(
    runtime: &FreedomRuntime,
    tool: &str,
    token: Option<&str>,
    session_label: Option<&str>,
    page: Option<u32>,
    url: Option<&str>,
    tabs_action: Option<&str>,
) -> Option<CallToolResult> {
    if !runtime.is_managed() {
        return None;
    }
    let request = ToolRequest {
        tool: tool.to_string(),
        token: token.map(str::to_string),
        session_label: session_label.map(str::to_string),
        page,
        url: url.map(str::to_string),
        tabs_action: tabs_action.map(str::to_string),
        cancel: CancellationToken::new(),
    };
    match admit(runtime, &request) {
        Ok(_) => None,
        Err(denial) => Some(tool_denial(denial.code, denial.message)),
    }
}

pub async fn run_tool_pipeline<F, Fut>(
    runtime: &FreedomRuntime,
    request: ToolRequest,
    execute: F,
) -> PipelineOutcome
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<CallToolResult, McpError>>,
{
    runtime.record_decision();
    let (context, mut steps) = match admit(runtime, &request) {
        Ok(admitted) => admitted,
        Err(denial) => {
            return PipelineOutcome {
                result: tool_denial(denial.code, denial.message),
                steps: denial.steps,
                business_accepted: false,
                upstream_called: false,
                ticket: None,
                principal: None,
            };
        }
    };
    let principal = context.principal().to_string();
    let ticket = lock_journal(runtime, Journal::begin_effect);
    steps.push(STEP_BEGIN);
    if is_tabs_list(&request) {
        lock_journal(runtime, |journal| journal.settle_executed(ticket));
        steps.extend([STEP_EXECUTE, STEP_OBSERVATION, STEP_RECEIPT]);
        return finish(
            runtime,
            ticket,
            scoped_tabs(&context),
            steps,
            false,
            principal,
        );
    }
    if request.cancel.is_cancelled() {
        return audit_only(runtime, ticket, steps, false, principal);
    }
    let upstream = execute().await;
    steps.push(STEP_EXECUTE);
    if request.cancel.is_cancelled() {
        return audit_only(runtime, ticket, steps, true, principal);
    }
    lock_journal(runtime, |journal| journal.settle_executed(ticket));
    steps.extend([STEP_OBSERVATION, STEP_RECEIPT]);
    let result = match upstream {
        Ok(result) => result,
        Err(error) => tool_denial("freedom_upstream_error", &error.to_string()),
    };
    finish(runtime, ticket, result, steps, true, principal)
}

fn audit_only(
    runtime: &FreedomRuntime,
    ticket: u64,
    mut steps: Vec<&'static str>,
    upstream_called: bool,
    principal: String,
) -> PipelineOutcome {
    lock_journal(runtime, |journal| journal.cancel_effect(ticket));
    steps.extend([STEP_OBSERVATION, STEP_RECEIPT]);
    finish(
        runtime,
        ticket,
        tool_denial(CODE_LATE_AUDIT, MSG_LATE),
        steps,
        upstream_called,
        principal,
    )
}

fn finish(
    runtime: &FreedomRuntime,
    ticket: u64,
    result: CallToolResult,
    steps: Vec<&'static str>,
    upstream_called: bool,
    principal: String,
) -> PipelineOutcome {
    PipelineOutcome {
        business_accepted: lock_journal(runtime, |journal| journal.business_accepted(ticket)),
        result,
        steps,
        upstream_called,
        ticket: Some(ticket),
        principal: Some(principal),
    }
}

pub fn decide_http(
    runtime: &FreedomRuntime,
    method: &str,
    path: &str,
    headers: &HeaderMap,
    peer: Option<IpAddr>,
) -> HttpGate {
    runtime.record_decision();
    let freedom_route = path.starts_with("/freedom/v1");
    if method == "OPTIONS" {
        if (runtime.is_managed() || freedom_route) && registry::path_is_guarded(path) {
            return http_deny(StatusCode::FORBIDDEN, CODE_CONTEXT_REQUIRED, MSG_CONTEXT);
        }
        return HttpGate::Continue {
            local_authorized: false,
        };
    }
    if freedom_route {
        return match local_api::authorize(runtime, headers, peer) {
            Ok(()) => HttpGate::Continue {
                local_authorized: true,
            },
            Err(error) => http_deny(error.status(), error.code(), error.message()),
        };
    }
    if !runtime.is_managed() {
        return HttpGate::Continue {
            local_authorized: false,
        };
    }
    let Some(entry) = registry::match_http(method, path) else {
        return HttpGate::Continue {
            local_authorized: false,
        };
    };
    if entry.treatment == registry::Treatment::AllowedNoEffect {
        return HttpGate::Continue {
            local_authorized: false,
        };
    }
    if !peer.is_some_and(|addr| addr.is_loopback()) {
        return http_deny(
            StatusCode::FORBIDDEN,
            local_api::CODE_PEER,
            "只接受本機連線",
        );
    }
    if !local_api::host_allowed(headers, runtime.bound_port()) {
        return http_deny(
            StatusCode::FORBIDDEN,
            local_api::CODE_HOST,
            "不允許這個 Host",
        );
    }
    if !local_api::origin_allowed(headers, runtime.bound_port()) {
        return http_deny(
            StatusCode::FORBIDDEN,
            local_api::CODE_ORIGIN,
            "不允許這個來源",
        );
    }
    if entry.treatment == registry::Treatment::Denied {
        return http_deny(StatusCode::FORBIDDEN, CODE_RAW_EXEC, MSG_RAW);
    }
    let context = match admit_token(runtime, bearer(headers).as_deref()) {
        Ok(context) => context,
        Err(denial) => return http_deny(StatusCode::FORBIDDEN, denial.code, denial.message),
    };
    match http_scope(entry, &context, path) {
        Ok(()) => HttpGate::Continue {
            local_authorized: false,
        },
        Err(denial) => http_deny(StatusCode::FORBIDDEN, denial.code, denial.message),
    }
}

fn http_deny(status: StatusCode, code: &'static str, message: &'static str) -> HttpGate {
    HttpGate::Deny {
        status,
        code,
        message,
    }
}

fn admit(
    runtime: &FreedomRuntime,
    request: &ToolRequest,
) -> Result<(FreedomRunContext, Vec<&'static str>), Denial> {
    let context = admit_token(runtime, token_for_verifier(request))?;
    let mut steps = vec![STEP_NATIVE_AUTH, STEP_BOUND_ATTEMPT];
    if RAW_TOOLS.contains(&request.tool.as_str()) {
        steps.push(STEP_SCHEMA);
        return Err(denial(CODE_RAW_EXEC, MSG_RAW, steps));
    }
    if request.url.as_deref().is_some_and(scheme_denied) {
        steps.push(STEP_SCHEMA);
        return Err(denial(CODE_SCHEME, MSG_SCHEME, steps));
    }
    steps.push(STEP_SCHEMA);
    if let Err((code, message)) = domain(&context, request) {
        steps.push(STEP_DOMAIN);
        return Err(denial(code, message, steps));
    }
    steps.push(STEP_DOMAIN);
    Ok((context, steps))
}

fn admit_token(runtime: &FreedomRuntime, token: Option<&str>) -> Result<FreedomRunContext, Denial> {
    let Some(token) = token.filter(|token| !token.is_empty()) else {
        return Err(denial(
            CODE_CONTEXT_REQUIRED,
            MSG_CONTEXT,
            vec![STEP_NATIVE_AUTH],
        ));
    };
    if token.len() > 512 {
        return Err(denial(
            CODE_TOKEN_INVALID,
            MSG_TOKEN_INVALID,
            vec![STEP_NATIVE_AUTH],
        ));
    }
    match runtime.verifier().authenticate(token) {
        Err(VerifyFailure::UnknownToken | VerifyFailure::NoPlatformClient) => Err(denial(
            CODE_TOKEN_INVALID,
            MSG_TOKEN_INVALID,
            vec![STEP_NATIVE_AUTH],
        )),
        Ok((auth, attempt)) => match FreedomRunContext::try_new(&auth, &attempt) {
            Ok(context) => Ok(context),
            Err(error) => Err(denial(
                error.code(),
                context_message(error),
                vec![STEP_NATIVE_AUTH, STEP_BOUND_ATTEMPT],
            )),
        },
    }
}

/// The presented session label is not a credential and is not a fallback token.
fn token_for_verifier(request: &ToolRequest) -> Option<&str> {
    let _ignored_label = request.session_label.as_deref();
    request.token.as_deref().filter(|token| !token.is_empty())
}

fn domain(
    context: &FreedomRunContext,
    request: &ToolRequest,
) -> Result<(), (&'static str, &'static str)> {
    if UNSCOPED_TOOLS.contains(&request.tool.as_str()) {
        return Err((CODE_UNSCOPED, MSG_UNSCOPED));
    }
    if SESSION_TOOLS.contains(&request.tool.as_str()) {
        return Ok(());
    }
    if request.tool == "tabs" {
        return match request.tabs_action.as_deref().unwrap_or("list") {
            "list" | "new" => Ok(()),
            "close" | "active" => require_page(context, request.page),
            _ => Err((CODE_TARGET, MSG_TARGET)),
        };
    }
    if PAGE_TOOLS.contains(&request.tool.as_str()) {
        return require_page(context, request.page);
    }
    if let Some(page) = request.page {
        return require_page(context, Some(page));
    }
    Err((CODE_TARGET, MSG_TARGET))
}

fn require_page(
    context: &FreedomRunContext,
    page: Option<u32>,
) -> Result<(), (&'static str, &'static str)> {
    match page {
        Some(page) if context.allows_page(page) => Ok(()),
        Some(_) => Err((CODE_SCOPE, MSG_SCOPE)),
        None => Err((CODE_TARGET, MSG_TARGET)),
    }
}

fn http_scope(
    entry: &registry::SurfaceEntry,
    context: &FreedomRunContext,
    path: &str,
) -> Result<(), Denial> {
    match entry.scope {
        registry::HttpScope::Probe | registry::HttpScope::Process | registry::HttpScope::Local => {
            Ok(())
        }
        registry::HttpScope::NotHttp => Ok(()),
        registry::HttpScope::Aggregate => {
            if context.allows_aggregate() {
                Ok(())
            } else {
                Err(denial(CODE_SCOPE, MSG_SCOPE, Vec::new()))
            }
        }
        registry::HttpScope::Session => {
            let Some(session) = session_id_from_path(path) else {
                return Err(denial(CODE_SCOPE, MSG_SCOPE, Vec::new()));
            };
            if context.allows_session(&session) {
                Ok(())
            } else {
                Err(denial(CODE_SCOPE, MSG_SCOPE, Vec::new()))
            }
        }
    }
}

fn session_id_from_path(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    if parts.len() >= 4 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "sessions" {
        Some(parts[3].to_string())
    } else {
        None
    }
}

fn scheme_denied(url: &str) -> bool {
    let trimmed = url.trim().to_ascii_lowercase();
    trimmed.starts_with("javascript:")
        || trimmed.starts_with("file:")
        || trimmed.starts_with("data:")
}

fn is_tabs_list(request: &ToolRequest) -> bool {
    request.tool == "tabs" && matches!(request.tabs_action.as_deref(), None | Some("list"))
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let mut parts = raw.splitn(2, char::is_whitespace);
    let scheme = parts.next()?.trim();
    let token = parts.next()?.trim();
    if scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() && token.len() <= 512 {
        Some(token.to_string())
    } else {
        None
    }
}

fn denial(code: &'static str, message: &'static str, steps: Vec<&'static str>) -> Denial {
    Denial {
        code,
        message,
        steps,
    }
}

fn context_message(error: ContextError) -> &'static str {
    match error {
        ContextError::Incomplete => "綁定資料不完整",
        ContextError::PrincipalMismatch => "會員與憑證不一致",
        ContextError::AttemptMismatch => "嘗試編號不一致",
        ContextError::BindingMismatch => "綁定內容不一致",
        ContextError::GrantRevoked => "連接已撤銷",
        ContextError::StaleControlEpoch => "控制世代已過期",
        ContextError::StaleLeaseEpoch => "租約世代已過期",
        ContextError::StaleGrantRevision => "授權版本已過期",
        ContextError::StalePolicyRevision => "政策版本已過期",
        ContextError::StaleRecoveryGeneration => "復原世代已過期",
    }
}

pub fn tool_denial(code: &str, message: &str) -> CallToolResult {
    let mut result = CallToolResult::error(vec![ContentBlock::text(format!("{code}: {message}"))]);
    result.structured_content = Some(json!({
        "code": code,
        "businessAccepted": false,
    }));
    result.is_error = Some(true);
    result
}

fn scoped_tabs(context: &FreedomRunContext) -> CallToolResult {
    let pages = context.page_ids();
    let listed = pages
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let mut result = CallToolResult::success(vec![ContentBlock::text(format!(
        "freedom_scoped_tabs: {listed}"
    ))]);
    result.structured_content = Some(json!({
        "code": "freedom_scoped_tabs",
        "pages": pages,
        "businessAccepted": false,
    }));
    result.is_error = Some(false);
    result
}

fn lock_journal<T>(runtime: &FreedomRuntime, body: impl FnOnce(&mut Journal) -> T) -> T {
    let mut journal = runtime
        .journal()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    body(&mut journal)
}

#[cfg(test)]
mod tests {
    use super::{
        CODE_BUSINESS, CODE_CONTEXT_REQUIRED, CODE_LATE_AUDIT, CODE_RAW_EXEC, CODE_SCOPE,
        CODE_UNSCOPED, STEP_BEGIN, STEP_BOUND_ATTEMPT, STEP_DOMAIN, STEP_EXECUTE, STEP_NATIVE_AUTH,
        STEP_OBSERVATION, STEP_RECEIPT, STEP_SCHEMA, run_tool_pipeline, tool_denial,
    };
    use crate::freedom::{BoundAttempt, FreedomRuntime, InProcessVerifier, Scope};
    use rmcp::model::ContentBlock;
    use std::{path::PathBuf, sync::Arc};

    fn token() -> String {
        let mut bytes = [0_u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut bytes);
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn runtime(scope: Scope) -> (Arc<FreedomRuntime>, String) {
        let secret = token();
        let mut verifier = InProcessVerifier::new();
        let (auth, attempt) = BoundAttempt::matching_pair("alice", "attempt-1", scope);
        verifier.insert(secret.clone(), auth, attempt);
        let runtime = FreedomRuntime::managed(
            9200,
            PathBuf::from("/tmp/freedom-managed-profile"),
            Arc::new(verifier),
        );
        (runtime, secret)
    }

    fn text_of(result: &rmcp::model::CallToolResult) -> String {
        result
            .content
            .iter()
            .filter_map(|block| match block {
                ContentBlock::Text(text) => Some(text.text.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[tokio::test]
    async fn pipeline_order_is_fixed_for_an_authorized_read() {
        let (runtime, secret) = runtime(Scope::pages([4]));
        let mut request = super::ToolRequest::new("snapshot");
        request.token = Some(secret);
        request.session_label = Some("Ted".to_string());
        request.page = Some(4);
        let mut called = false;
        let outcome = run_tool_pipeline(&runtime, request, || {
            called = true;
            async { Ok(tool_denial("upstream", "no link to the browser yet")) }
        })
        .await;
        assert!(called);
        assert_eq!(
            outcome.steps,
            vec![
                STEP_NATIVE_AUTH,
                STEP_BOUND_ATTEMPT,
                STEP_SCHEMA,
                STEP_DOMAIN,
                STEP_BEGIN,
                STEP_EXECUTE,
                STEP_OBSERVATION,
                STEP_RECEIPT,
            ]
        );
        assert!(!outcome.business_accepted);
        assert_eq!(outcome.principal.as_deref(), Some("alice"));
        let ticket = outcome.ticket.unwrap_or_else(|| panic!("ticket"));
        let marked = runtime.try_mark_business_accepted(ticket);
        assert_eq!(marked, Err(CODE_BUSINESS));
        assert!(!runtime.effect_business_accepted(ticket));
    }

    #[tokio::test]
    async fn missing_context_stops_before_upstream() {
        let (runtime, _) = runtime(Scope::pages([1]));
        let request = super::ToolRequest::new("snapshot");
        let mut called = false;
        let outcome = run_tool_pipeline(&runtime, request, || {
            called = true;
            async { Ok(tool_denial("upstream", "ran")) }
        })
        .await;
        assert!(!called);
        assert_eq!(outcome.steps, vec![STEP_NATIVE_AUTH]);
        assert!(text_of(&outcome.result).contains(CODE_CONTEXT_REQUIRED));
        assert!(!text_of(&outcome.result).contains("no link to the browser"));
    }

    #[tokio::test]
    async fn raw_exec_with_context_does_not_execute() {
        let (runtime, secret) = runtime(Scope::pages([1]));
        for tool in ["run", "evaluate"] {
            let mut request = super::ToolRequest::new(tool);
            request.token = Some(secret.clone());
            let mut called = false;
            let outcome = run_tool_pipeline(&runtime, request, || {
                called = true;
                async { Ok(tool_denial("upstream", "ran")) }
            })
            .await;
            assert!(!called, "{tool}");
            assert!(text_of(&outcome.result).contains(CODE_RAW_EXEC), "{tool}");
            assert_eq!(
                outcome.steps,
                vec![STEP_NATIVE_AUTH, STEP_BOUND_ATTEMPT, STEP_SCHEMA]
            );
        }
    }

    #[tokio::test]
    async fn cancel_before_and_after_execute_stays_audit_only() {
        let (runtime, secret) = runtime(Scope::pages([1]));
        let mut before = super::ToolRequest::new("snapshot");
        before.token = Some(secret.clone());
        before.page = Some(1);
        before.cancel.cancel();
        let mut called = false;
        let outcome = run_tool_pipeline(&runtime, before, || {
            called = true;
            async { Ok(tool_denial("upstream", "ran")) }
        })
        .await;
        assert!(!called);
        assert!(text_of(&outcome.result).contains(CODE_LATE_AUDIT));
        assert!(!outcome.steps.contains(&STEP_EXECUTE));
        let ticket = outcome.ticket.unwrap_or_else(|| panic!("ticket"));
        assert!(runtime.effect_is_audit_only(ticket));
        assert_eq!(
            runtime.try_mark_business_accepted(ticket),
            Err(CODE_LATE_AUDIT)
        );
        assert!(!runtime.effect_business_accepted(ticket));

        let mut during = super::ToolRequest::new("snapshot");
        during.token = Some(secret);
        during.page = Some(1);
        let cancel = during.cancel.clone();
        let outcome = run_tool_pipeline(&runtime, during, || {
            cancel.cancel();
            async { Ok(tool_denial("upstream", "accepted-looking success")) }
        })
        .await;
        assert!(outcome.upstream_called);
        assert!(text_of(&outcome.result).contains(CODE_LATE_AUDIT));
        assert!(!text_of(&outcome.result).contains("accepted-looking"));
        assert!(!outcome.business_accepted);
        assert!(outcome.steps.contains(&STEP_EXECUTE));
        assert!(outcome.steps.contains(&STEP_OBSERVATION));
        assert!(outcome.steps.contains(&STEP_RECEIPT));
    }

    #[tokio::test]
    async fn scope_scheme_and_tabs_list() {
        let (runtime, secret) = runtime(Scope::pages([1]));
        let mut foreign = super::ToolRequest::new("snapshot");
        foreign.token = Some(secret.clone());
        foreign.page = Some(9);
        let outcome = run_tool_pipeline(&runtime, foreign, || async {
            Ok(tool_denial("upstream", "ran"))
        })
        .await;
        assert!(!outcome.upstream_called);
        assert!(text_of(&outcome.result).contains(CODE_SCOPE));

        let mut history = super::ToolRequest::new("history");
        history.token = Some(secret.clone());
        let outcome = run_tool_pipeline(&runtime, history, || async {
            Ok(tool_denial("upstream", "ran"))
        })
        .await;
        assert!(text_of(&outcome.result).contains(CODE_UNSCOPED));

        let mut navigate = super::ToolRequest::new("navigate");
        navigate.token = Some(secret.clone());
        navigate.page = Some(1);
        navigate.url = Some("javascript:alert(1)".to_string());
        let outcome = run_tool_pipeline(&runtime, navigate, || async {
            Ok(tool_denial("upstream", "ran"))
        })
        .await;
        assert!(text_of(&outcome.result).contains("freedom_scheme_denied"));

        let mut tabs = super::ToolRequest::new("tabs");
        tabs.token = Some(secret);
        tabs.tabs_action = Some("list".to_string());
        let mut called = false;
        let outcome = run_tool_pipeline(&runtime, tabs, || {
            called = true;
            async { Ok(tool_denial("upstream", "all-tabs")) }
        })
        .await;
        assert!(!called);
        let text = text_of(&outcome.result);
        assert!(text.contains("freedom_scoped_tabs:"));
        assert!(text.contains('1'));
        assert!(!text.contains('9'));
        assert_ne!(outcome.result.is_error, Some(true));
    }
}
