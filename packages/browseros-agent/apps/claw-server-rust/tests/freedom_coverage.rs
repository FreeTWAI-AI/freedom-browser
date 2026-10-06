// Freedom modification (AGPL-3.0-or-later §5(a) prominent notice).
// Added 2026-10-06. Managed-mode guard for the 自由工坊 neo client.
// Not part of upstream BrowserOS.

//! NEO-08. The registry must match the router source, the MCP catalog, and the
//! native entry points. Every effect surface is denied without a Freedom context.

use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode, header},
};
use browseros_mcp::InnerCallHook;
use claw_server_rust::{
    AppState,
    api::mcp::{
        dispatch::{ToolCall, dispatch_tool_call},
        helper_runtime::execute_nested,
        script_hook::ScriptInnerCallHook,
        server_tool_names,
    },
    build_router,
    config::Config,
    freedom::{
        BoundAttempt, CODE_CONTEXT_REQUIRED, CODE_RAW_EXEC, InProcessVerifier, Scope, SurfaceKind,
        Treatment, precheck_mcp_tool, surfaces,
    },
    ids::SessionId,
};
use rmcp::model::{CallToolResult, ContentBlock};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use syn::{
    Expr, ExprCall, ExprLit, ExprMethodCall, Lit,
    visit::{self, Visit},
};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

fn manifest_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_source(relative: &str) -> String {
    let path = manifest_path(relative);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn require_before(source: &str, earlier: &str, later: &str) {
    let earlier_at = source
        .find(earlier)
        .unwrap_or_else(|| panic!("missing `{earlier}`"));
    let later_at = source
        .find(later)
        .unwrap_or_else(|| panic!("missing `{later}`"));
    assert!(
        earlier_at < later_at,
        "`{earlier}` must appear before `{later}`"
    );
}

fn slice_fn<'a>(source: &'a str, name: &str) -> &'a str {
    let marker = format!("fn {name}");
    let start = source
        .find(&marker)
        .unwrap_or_else(|| panic!("missing function {name}"));
    let rest = &source[start + marker.len()..];
    let next = rest.find("\nfn ").or_else(|| rest.find("\n    fn "));
    match next {
        Some(end) => &source[start..start + marker.len() + end],
        None => &source[start..],
    }
}

fn quoted_names(body: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut rest = body;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        let end = after
            .find('"')
            .unwrap_or_else(|| panic!("unterminated string in {body}"));
        names.insert(after[..end].to_string());
        rest = &after[end + 1..];
    }
    names
}

#[derive(Default)]
struct RouteVisitor {
    ids: BTreeSet<String>,
    unknown: Vec<String>,
}

impl RouteVisitor {
    fn add_route(&mut self, path: &str, methods: &[String]) {
        if methods.is_empty() {
            self.unknown.push(format!("route {path} has no method"));
            return;
        }
        for method in methods {
            self.ids.insert(format!("{method} {path}"));
        }
    }
}

impl<'ast> Visit<'ast> for RouteVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let name = node.method.to_string();
        if name == "route" {
            let Some(path) = literal_str(node.args.first()) else {
                self.unknown
                    .push("route path is not a string literal".to_string());
                visit::visit_expr_method_call(self, node);
                return;
            };
            let methods = handler_methods(node.args.get(1), &mut self.unknown);
            self.add_route(&path, &methods);
        } else if name == "nest_service" {
            let Some(path) = literal_str(node.args.first()) else {
                self.unknown
                    .push("nest_service path is not a string literal".to_string());
                visit::visit_expr_method_call(self, node);
                return;
            };
            if path == "/mcp" {
                for method in ["GET", "POST", "DELETE"] {
                    self.ids.insert(format!("{method} {path}"));
                }
            } else {
                self.unknown
                    .push(format!("unclassified nest_service {path}"));
            }
        }
        visit::visit_expr_method_call(self, node);
    }
}

fn literal_str(expr: Option<&Expr>) -> Option<String> {
    match expr {
        Some(Expr::Lit(ExprLit {
            lit: Lit::Str(value),
            ..
        })) => Some(value.value()),
        _ => None,
    }
}

fn handler_methods(expr: Option<&Expr>, unknown: &mut Vec<String>) -> Vec<String> {
    let Some(expr) = expr else {
        unknown.push("route is missing a handler".to_string());
        return Vec::new();
    };
    match expr {
        Expr::MethodCall(call) => {
            let name = call.method.to_string();
            if name == "layer" {
                return handler_methods(Some(&call.receiver), unknown);
            }
            let mut methods = handler_methods(Some(&call.receiver), unknown);
            if matches!(name.as_str(), "get" | "post" | "put" | "delete" | "patch") {
                methods.push(name.to_ascii_uppercase());
            } else {
                unknown.push(format!("unknown handler method {name}"));
            }
            methods
        }
        Expr::Call(ExprCall { func, .. }) => match func.as_ref() {
            Expr::Path(path) => {
                let Some(ident) = path.path.get_ident() else {
                    unknown.push("handler call is not a path".to_string());
                    return Vec::new();
                };
                let name = ident.to_string();
                if matches!(name.as_str(), "get" | "post" | "put" | "delete" | "patch") {
                    vec![name.to_ascii_uppercase()]
                } else {
                    unknown.push(format!("unknown handler function {name}"));
                    Vec::new()
                }
            }
            _ => {
                unknown.push("handler call is not a path".to_string());
                Vec::new()
            }
        },
        _ => {
            unknown.push("handler expression is not a method chain".to_string());
            Vec::new()
        }
    }
}

fn discovered_http() -> BTreeSet<String> {
    let source = read_source("src/api/http/mod.rs");
    let file =
        syn::parse_file(&source).unwrap_or_else(|error| panic!("parse http router: {error}"));
    let mut visitor = RouteVisitor::default();
    visitor.visit_file(&file);
    assert!(
        visitor.unknown.is_empty(),
        "unclassified routes:\n{}",
        visitor.unknown.join("\n")
    );
    visitor.ids
}

fn registry_ids(prefix: &str) -> BTreeSet<String> {
    surfaces()
        .iter()
        .filter_map(|entry| entry.id.strip_prefix(prefix))
        .map(str::to_string)
        .collect()
}

fn http_registry_ids() -> BTreeSet<String> {
    surfaces()
        .iter()
        .filter(|entry| entry.id.split_once(' ').is_some())
        .map(|entry| entry.id.to_string())
        .collect()
}

#[test]
fn neo08_registry_matches_the_router_catalog_and_native_entries() {
    let mut seen = BTreeSet::new();
    for entry in surfaces() {
        assert!(seen.insert(entry.id), "duplicate registry id {}", entry.id);
        assert!(!entry.justification.is_empty(), "{}", entry.id);
        if matches!(entry.kind, SurfaceKind::Effect | SurfaceKind::RawExec) {
            assert_ne!(entry.treatment, Treatment::AllowedNoEffect, "{}", entry.id);
        }
    }

    let http = discovered_http();
    let registered_http = http_registry_ids();
    let missing_http: Vec<_> = http.difference(&registered_http).collect();
    let stale_http: Vec<_> = registered_http.difference(&http).collect();
    assert!(
        missing_http.is_empty() && stale_http.is_empty(),
        "http registry drift\nmissing: {missing_http:?}\nstale: {stale_http:?}"
    );

    let mut catalog_names = BTreeSet::new();
    for tool in browseros_mcp::catalog() {
        catalog_names.insert(tool.name.to_string());
    }
    for name in server_tool_names() {
        catalog_names.insert(name.to_string());
    }
    let registered_mcp = registry_ids("mcp:");
    let missing_mcp: Vec<_> = catalog_names.difference(&registered_mcp).collect();
    let stale_mcp: Vec<_> = registered_mcp.difference(&catalog_names).collect();
    assert!(
        missing_mcp.is_empty() && stale_mcp.is_empty(),
        "mcp registry drift\nmissing: {missing_mcp:?}\nstale: {stale_mcp:?}"
    );

    let native: BTreeSet<String> = ["script_hook", "helper_runtime"]
        .into_iter()
        .map(str::to_string)
        .collect();
    assert_eq!(registry_ids("native:"), native);

    let dispatch = read_source("src/api/mcp/dispatch.rs");
    let marker = "pub(crate) const ARBITRARY_SCRIPT_TOOLS: &[&str] = &[";
    let start = dispatch
        .find(marker)
        .unwrap_or_else(|| panic!("missing ARBITRARY_SCRIPT_TOOLS"));
    let rest = &dispatch[start + marker.len()..];
    let end = rest
        .find("];")
        .unwrap_or_else(|| panic!("ARBITRARY_SCRIPT_TOOLS is not closed"));
    let raw_names = quoted_names(&rest[..end]);
    let registered_raw: BTreeSet<String> = surfaces()
        .iter()
        .filter(|entry| entry.kind == SurfaceKind::RawExec && entry.id.starts_with("mcp:"))
        .filter_map(|entry| entry.id.strip_prefix("mcp:"))
        .map(str::to_string)
        .collect();
    assert_eq!(raw_names, registered_raw);
    for name in &raw_names {
        let entry = surfaces()
            .iter()
            .find(|entry| entry.id == format!("mcp:{name}"))
            .unwrap_or_else(|| panic!("missing mcp:{name}"));
        assert_eq!(entry.kind, SurfaceKind::RawExec);
        assert_eq!(entry.treatment, Treatment::Denied);
    }
}

#[test]
fn neo08_source_locks_the_guard_onto_every_dispatch_path() {
    let dispatch = read_source("src/api/mcp/dispatch.rs");
    require_before(
        &dispatch,
        "if call.state.freedom.is_managed() {\n        return dispatch_managed(call).await;",
        "dispatch_tool_call_with(call, GUARDS, EFFECTS, OBSERVERS).await",
    );
    let execute = slice_fn(&dispatch, "execute_with_cancellation");
    assert!(execute.contains("ARBITRARY_SCRIPT_TOOLS.contains"));
    assert!(execute.contains("CODE_RAW_EXEC"));

    let service = read_source("src/api/mcp/service.rs");
    require_before(&service, "precheck_mcp_tool(", "let is_name_session");

    let hook_source = read_source("src/api/mcp/script_hook.rs");
    let hook = slice_fn(&hook_source, "authorize");
    assert!(hook.contains("is_managed()"));
    assert!(hook.contains("CODE_RAW_EXEC"));

    let helper_source = read_source("src/api/mcp/helper_runtime.rs");
    let nested = slice_fn(&helper_source, "execute_nested");
    assert!(nested.contains("is_managed()"));
    assert!(nested.contains("CODE_RAW_EXEC"));
    assert!(nested.contains("let _ = source"));
}

fn fresh_token() -> String {
    let mut bytes = [0_u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn config_at(dir: &Path) -> Arc<Config> {
    Arc::new(Config {
        server_port: 9200,
        cdp_port: 49337,
        proxy_port: None,
        resources_dir: dir.join("resources"),
        browserclaw_dir: dir.to_path_buf(),
        session_idle: Duration::from_secs(300),
        session_retention: Duration::from_secs(7_200),
        session_sweep_interval: Duration::from_secs(60),
        replay_retention_days: 7,
        dev_mode: false,
    })
}

async fn managed_app() -> anyhow::Result<(tempfile::TempDir, AppState, String)> {
    let dir = tempfile::tempdir()?;
    let home = dir.path().join("home");
    let profile = dir.path().join("managed");
    let standalone = dir.path().join("standalone-default");
    tokio::fs::create_dir_all(&home).await?;
    let secret = fresh_token();
    let mut verifier = InProcessVerifier::new();
    let (auth, attempt) = BoundAttempt::matching_pair("alice", "attempt-1", Scope::pages([1]));
    verifier.insert(secret.clone(), auth, attempt);
    let state =
        AppState::new_managed_with_home(config_at(&profile), home, standalone, Arc::new(verifier))
            .await?;
    Ok((dir, state, secret))
}

fn tool_text(result: &CallToolResult) -> String {
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

fn assert_tool_denied(result: &CallToolResult, code: &str) {
    let text = tool_text(result);
    assert!(text.contains(code), "{text}");
    assert!(
        !text.contains("no link to the browser"),
        "upstream fallback ran: {text}"
    );
    assert_eq!(result.is_error, Some(true));
}

async fn dispatch_named(
    state: &AppState,
    tool: &str,
    token: Option<String>,
) -> anyhow::Result<CallToolResult> {
    let catalog = Arc::new(browseros_mcp::catalog());
    let tool_index = catalog
        .iter()
        .position(|entry| entry.name == tool)
        .ok_or_else(|| anyhow::anyhow!("missing catalog tool {tool}"))?;
    let mut call = ToolCall::new(
        catalog,
        tool_index,
        serde_json::json!({}),
        SessionId::new("s1"),
        None,
        None,
        CancellationToken::new(),
        CancellationToken::new(),
        CancellationToken::new(),
        None,
        state.clone(),
        browseros_mcp::output_file::create_browser_output_file_access(),
    );
    call.set_freedom_auth(token, Some("Ted".to_string()));
    dispatch_tool_call(call)
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))
}

fn concrete_path(pattern: &str) -> String {
    let path = pattern
        .replace("{session_id}", "s1")
        .replace("{screenshot_id}", "shot")
        .replace("{harness}", "claude")
        .replace("{name}", "skill");
    assert!(!path.contains('{'), "unsubstituted path {path}");
    path
}

fn loopback(method: &str, path: &str) -> anyhow::Result<Request<Body>> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "127.0.0.1:9200")
        .body(Body::empty())?;
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((Ipv4Addr::LOCALHOST, 9))));
    Ok(request)
}

async fn response_text(
    response: axum::response::Response,
) -> anyhow::Result<(StatusCode, String, Option<String>)> {
    let status = response.status();
    let allow_origin = response
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
    let text = String::from_utf8(bytes.to_vec())?;
    Ok((status, text, allow_origin))
}

async fn deny_http(router: &axum::Router, method: &str, path: &str) -> anyhow::Result<()> {
    let response = router.clone().oneshot(loopback(method, path)?).await?;
    let (status, text, origin) = response_text(response).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {text}");
    let body: Value = serde_json::from_str(&text)?;
    assert_eq!(body["code"], CODE_CONTEXT_REQUIRED, "{method} {path}");
    assert_ne!(origin.as_deref(), Some("*"), "{method} {path}");
    Ok(())
}

async fn deny_mcp_without_context(state: &AppState, name: &str) -> anyhow::Result<()> {
    let in_catalog = browseros_mcp::catalog()
        .iter()
        .any(|tool| tool.name == name);
    if in_catalog {
        let result = dispatch_named(state, name, None).await?;
        assert_tool_denied(&result, CODE_CONTEXT_REQUIRED);
        return Ok(());
    }
    let denial = precheck_mcp_tool(&state.freedom, name, None, Some("Ted"), None, None, None)
        .ok_or_else(|| anyhow::anyhow!("{name} passed the managed precheck without a context"))?;
    assert_tool_denied(&denial, CODE_CONTEXT_REQUIRED);
    Ok(())
}

#[tokio::test]
async fn neo08_every_effect_surface_is_denied_without_a_context() -> anyhow::Result<()> {
    let (_dir, state, _token) = managed_app().await?;
    let router = build_router(state.clone());
    let mut seen = 0_u32;
    for entry in surfaces() {
        if entry.kind != SurfaceKind::Effect {
            continue;
        }
        assert_ne!(entry.treatment, Treatment::AllowedNoEffect, "{}", entry.id);
        seen = seen.saturating_add(1);
        if let Some((method, path)) = entry.id.split_once(' ') {
            deny_http(&router, method, &concrete_path(path)).await?;
        } else if let Some(name) = entry.id.strip_prefix("mcp:") {
            deny_mcp_without_context(&state, name).await?;
        } else {
            anyhow::bail!("effect surface {} has no probe", entry.id);
        }
    }
    assert!(seen >= 10, "expected the effect catalog, saw {seen}");

    let (status, _, origin) = response_text(
        router
            .clone()
            .oneshot(loopback("OPTIONS", "/system/shutdown")?)
            .await?,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_ne!(origin.as_deref(), Some("*"));
    let (status, _, _) = response_text(
        router
            .oneshot(loopback("OPTIONS", "/system/health")?)
            .await?,
    )
    .await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    Ok(())
}

#[tokio::test]
async fn neo08_every_raw_exec_surface_is_denied_on_the_dispatch_path() -> anyhow::Result<()> {
    let (_dir, state, token) = managed_app().await?;
    for entry in surfaces() {
        if entry.kind != SurfaceKind::RawExec {
            continue;
        }
        assert_eq!(entry.treatment, Treatment::Denied, "{}", entry.id);
        if let Some(name) = entry.id.strip_prefix("mcp:") {
            let missing = dispatch_named(&state, name, None).await?;
            assert_tool_denied(&missing, CODE_CONTEXT_REQUIRED);
            let direct = dispatch_named(&state, name, Some(token.clone())).await?;
            assert_tool_denied(&direct, CODE_RAW_EXEC);
        }
    }
    let nested =
        execute_nested(&state, "pages.list()").map_or_else(|error| error, |_| String::new());
    assert!(nested.contains(CODE_RAW_EXEC), "{nested}");
    let catalog = Arc::new(browseros_mcp::catalog());
    let tool_index = catalog
        .iter()
        .position(|entry| entry.name == "run")
        .ok_or_else(|| anyhow::anyhow!("missing run"))?;
    let call = ToolCall::new(
        catalog,
        tool_index,
        serde_json::json!({}),
        SessionId::new("s1"),
        None,
        None,
        CancellationToken::new(),
        CancellationToken::new(),
        CancellationToken::new(),
        None,
        state,
        browseros_mcp::output_file::create_browser_output_file_access(),
    );
    let hook = ScriptInnerCallHook::new(call);
    let hook_error = hook
        .authorize(Some(1))
        .await
        .map_or_else(|error| error, |_| String::new());
    assert!(hook_error.contains(CODE_RAW_EXEC), "{hook_error}");
    Ok(())
}

#[tokio::test]
async fn neo08_guarded_reads_and_local_status_deny_without_credentials() -> anyhow::Result<()> {
    let (_dir, state, _token) = managed_app().await?;
    let router = build_router(state.clone());
    for entry in surfaces() {
        match entry.kind {
            SurfaceKind::Read if entry.treatment == Treatment::AllowedNoEffect => {
                let (method, path) = entry
                    .id
                    .split_once(' ')
                    .ok_or_else(|| anyhow::anyhow!("probe {} is not http", entry.id))?;
                let (status, text, origin) =
                    response_text(router.clone().oneshot(loopback(method, path)?).await?).await?;
                // `/system/ready` stays the upstream readiness gate: 503 while the
                // browser link is down. That is still not a Freedom denial.
                if path == "/system/ready" {
                    assert!(
                        status == StatusCode::OK || status == StatusCode::SERVICE_UNAVAILABLE,
                        "{}: {status} {text}",
                        entry.id
                    );
                } else {
                    assert_eq!(status, StatusCode::OK, "{}: {text}", entry.id);
                }
                assert!(
                    !text.contains(CODE_CONTEXT_REQUIRED),
                    "{} fell into the managed guard: {text}",
                    entry.id
                );
                assert_ne!(origin.as_deref(), Some("*"), "{}", entry.id);
            }
            SurfaceKind::Read if entry.treatment == Treatment::Guarded => {
                if let Some((method, path)) = entry.id.split_once(' ') {
                    deny_http(&router, method, &concrete_path(path)).await?;
                } else if let Some(name) = entry.id.strip_prefix("mcp:") {
                    deny_mcp_without_context(&state, name).await?;
                } else {
                    anyhow::bail!("read surface {} has no probe", entry.id);
                }
            }
            SurfaceKind::AdminLocal => {
                let (status, text, origin) = response_text(
                    router
                        .clone()
                        .oneshot(loopback("GET", "/freedom/v1/status")?)
                        .await?,
                )
                .await?;
                assert_eq!(status, StatusCode::UNAUTHORIZED, "{text}");
                assert!(text.contains("freedom_token_denied"), "{text}");
                assert_ne!(origin.as_deref(), Some("*"));
            }
            _ => {}
        }
    }
    Ok(())
}
