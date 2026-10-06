// Freedom modification (AGPL-3.0-or-later §5(a) prominent notice).
// Added 2026-10-06. Managed-mode guard for the 自由工坊 neo client.
// Not part of upstream BrowserOS.

//! Managed-mode negatives. The browser is not real: denials happen before
//! upstream execution, and an allowed call reaches the existing
//! "no link to the browser" message.

use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use browseros_cdp::{CdpError, CdpEvent, SessionId as CdpSessionId};
use browseros_core::{BrowserSession, BrowserSessionHooks, CdpConnection, PageId};
use browseros_mcp::InnerCallHook;
use claw_server_rust::{
    AppState,
    api::mcp::{
        dispatch::{ToolCall, ToolIdentity, dispatch_tool_call},
        helper_runtime::execute_nested,
        script_hook::ScriptInnerCallHook,
    },
    build_router,
    config::Config,
    freedom::{
        BoundAttempt, CODE_BUSINESS, CODE_CONTEXT_REQUIRED, CODE_LATE_AUDIT, CODE_MODE_FIXED,
        CODE_RAW_EXEC, CODE_SCHEME, CODE_SCOPE, CODE_UNSCOPED, ClosedVerifier, FreedomVerifier,
        InProcessVerifier, Scope, VerifyFailure,
    },
    identity::{ClientIdentity, ConversationIdentity},
    ids::SessionId,
    services::sessions::Session,
};
use futures_util::future::BoxFuture;
use rmcp::model::{CallToolResult, ContentBlock};
use serde_json::{Value, json};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

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

struct RecordingVerifier {
    inner: InProcessVerifier,
    seen: Arc<Mutex<Vec<String>>>,
}

impl FreedomVerifier for RecordingVerifier {
    fn authenticate(
        &self,
        token: &str,
    ) -> Result<(claw_server_rust::freedom::NativeAuthResult, BoundAttempt), VerifyFailure> {
        self.seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(token.to_string());
        self.inner.authenticate(token)
    }
}

async fn managed_app(scope: Scope) -> anyhow::Result<(tempfile::TempDir, AppState, String)> {
    let dir = tempfile::tempdir()?;
    let home = dir.path().join("home");
    let profile = dir.path().join("managed");
    let standalone = dir.path().join("standalone-default");
    tokio::fs::create_dir_all(&home).await?;
    let secret = fresh_token();
    let mut inner = InProcessVerifier::new();
    let (auth, attempt) = BoundAttempt::matching_pair("alice", "attempt-1", scope);
    inner.insert(secret.clone(), auth, attempt);
    let verifier = RecordingVerifier {
        inner,
        seen: Arc::new(Mutex::new(Vec::new())),
    };
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

async fn dispatch_named(
    state: &AppState,
    tool: &str,
    args: Value,
    token: Option<String>,
    label: Option<String>,
    cancel: bool,
) -> anyhow::Result<CallToolResult> {
    let catalog = Arc::new(browseros_mcp::catalog());
    let tool_index = catalog
        .iter()
        .position(|entry| entry.name == tool)
        .ok_or_else(|| anyhow::anyhow!("missing tool {tool}"))?;
    let dispatch_cancel = CancellationToken::new();
    if cancel {
        dispatch_cancel.cancel();
    }
    let mut call = ToolCall::new(
        catalog,
        tool_index,
        args,
        SessionId::new("s1"),
        None,
        None,
        CancellationToken::new(),
        CancellationToken::new(),
        dispatch_cancel,
        None,
        state.clone(),
        browseros_mcp::output_file::create_browser_output_file_access(),
    );
    call.set_freedom_auth(token, label);
    dispatch_tool_call(call)
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))
}

fn assert_denied(result: &CallToolResult, code: &str) {
    let text = tool_text(result);
    assert!(text.contains(code), "{text}");
    assert!(
        !text.contains("no link to the browser"),
        "upstream fallback ran: {text}"
    );
    assert_eq!(result.is_error, Some(true));
}

#[tokio::test]
async fn neo01_managed_mcp_without_context_is_denied_without_upstream_fallback()
-> anyhow::Result<()> {
    let (_dir, state, _token) = managed_app(Scope::pages([1])).await?;
    let result = dispatch_named(&state, "snapshot", json!({"page": 1}), None, None, false).await?;
    assert_denied(&result, CODE_CONTEXT_REQUIRED);
    Ok(())
}

#[tokio::test]
async fn neo02_cross_agent_and_human_tabs_are_scope_denied_despite_ownership_hints()
-> anyhow::Result<()> {
    let (_dir, state, token) = managed_app(Scope::pages([1, 3])).await?;
    let owner = Session::new(
        SessionId::new("self"),
        ClientIdentity::Ephemeral {
            slug: "self".to_string(),
            label: "Self".to_string(),
        },
        ConversationIdentity::new("self", "self-convo".to_string()),
        "Self".to_string(),
        tokio::time::Instant::now(),
    );
    let other = Session::new(
        SessionId::new("other"),
        ClientIdentity::Ephemeral {
            slug: "other".to_string(),
            label: "Other".to_string(),
        },
        ConversationIdentity::new("other", "other-convo".to_string()),
        "Other".to_string(),
        tokio::time::Instant::now(),
    );
    state.sessions.insert_for_testing(owner.clone()).await;
    state.sessions.insert_for_testing(other.clone()).await;
    state
        .sessions
        .ownership()
        .claim_page(owner.convo_id().clone(), PageId(2))
        .await;
    state
        .sessions
        .ownership()
        .claim_page(other.convo_id().clone(), PageId(3))
        .await;

    let hinted_own_but_out_of_scope = dispatch_named(
        &state,
        "snapshot",
        json!({"page": 2}),
        Some(token.clone()),
        None,
        false,
    )
    .await?;
    assert_denied(&hinted_own_but_out_of_scope, CODE_SCOPE);

    let human = dispatch_named(
        &state,
        "snapshot",
        json!({"page": 8}),
        Some(token.clone()),
        None,
        false,
    )
    .await?;
    assert_denied(&human, CODE_SCOPE);

    let in_scope_human = dispatch_named(
        &state,
        "snapshot",
        json!({"page": 1}),
        Some(token.clone()),
        None,
        false,
    )
    .await?;
    let in_scope_text = tool_text(&in_scope_human);
    assert!(
        in_scope_text.contains("no link to the browser"),
        "{in_scope_text}"
    );
    assert!(!in_scope_text.contains(CODE_SCOPE));

    let in_scope_other_agent = dispatch_named(
        &state,
        "snapshot",
        json!({"page": 3}),
        Some(token.clone()),
        None,
        false,
    )
    .await?;
    assert!(tool_text(&in_scope_other_agent).contains("no link to the browser"));

    let tabs = dispatch_named(
        &state,
        "tabs",
        json!({"action": "list"}),
        Some(token),
        None,
        false,
    )
    .await?;
    let tabs_text = tool_text(&tabs);
    assert!(tabs_text.contains("freedom_scoped_tabs:"));
    assert!(tabs_text.contains('1'));
    assert!(tabs_text.contains('3'));
    assert!(!tabs_text.contains('2'));
    assert!(!tabs_text.contains('8'));
    Ok(())
}

#[tokio::test]
async fn neo03_raw_run_and_evaluate_direct_calls_are_denied() -> anyhow::Result<()> {
    let (_dir, state, token) = managed_app(Scope::pages([1])).await?;
    for tool in ["run", "evaluate"] {
        let result = dispatch_named(
            &state,
            tool,
            json!({"code": "pages.list()"}),
            Some(token.clone()),
            None,
            false,
        )
        .await?;
        assert_denied(&result, CODE_RAW_EXEC);
    }
    Ok(())
}

#[tokio::test]
async fn neo04_nested_helper_and_script_execution_matches_direct_denial() -> anyhow::Result<()> {
    let (_dir, state, token) = managed_app(Scope::pages([1])).await?;
    let direct = dispatch_named(&state, "run", json!({}), Some(token), None, false).await?;
    let direct_text = tool_text(&direct);
    assert!(direct_text.contains(CODE_RAW_EXEC));
    let nested =
        execute_nested(&state, "pages.list()").map_or_else(|error| error, |_| String::new());
    assert!(nested.contains(CODE_RAW_EXEC));
    assert!(nested.contains(CODE_RAW_EXEC) && direct_text.contains(CODE_RAW_EXEC));

    let catalog = Arc::new(browseros_mcp::catalog());
    let tool_index = catalog
        .iter()
        .position(|entry| entry.name == "run")
        .ok_or_else(|| anyhow::anyhow!("missing run"))?;
    let call = ToolCall::new(
        catalog,
        tool_index,
        json!({}),
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
    let hook = ScriptInnerCallHook::new(call);
    let hook_error = hook
        .authorize(Some(1))
        .await
        .map_or_else(|error| error, |_| String::new());
    assert!(hook_error.contains(CODE_RAW_EXEC));
    let listed = hook.list_helpers("example.com").await;
    assert!(listed.is_empty());
    let read = hook.read_helper("example.com", "secret").await;
    assert!(read.is_none());
    let annotated = hook.annotate_pages(&[json!({"pageId": 9})]).await;
    assert!(annotated.is_empty());
    Ok(())
}

fn loopback_request(method: &str, path: &str) -> anyhow::Result<Request<Body>> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "127.0.0.1:9200")
        .body(Body::empty())?;
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((Ipv4Addr::LOCALHOST, 9))));
    Ok(request)
}

async fn response_json(response: axum::response::Response) -> anyhow::Result<(StatusCode, Value)> {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
    let text = String::from_utf8(bytes.to_vec())?;
    if text.is_empty() {
        return Ok((status, Value::Null));
    }
    Ok((status, serde_json::from_str(&text)?))
}

#[tokio::test]
async fn neo05_local_rest_rejects_bad_host_origin_nonce_and_peer() -> anyhow::Result<()> {
    let (_dir, state, _token) = managed_app(Scope::process_only()).await?;
    let router = build_router(state.clone());
    let native = state.freedom.native_token().to_string();

    let mut ok = loopback_request("GET", "/freedom/v1/status")?;
    ok.headers_mut().insert(
        "x-freedom-native-token",
        native
            .parse()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?,
    );
    ok.headers_mut().insert(
        "x-freedom-nonce",
        "nonce-a"
            .parse()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?,
    );
    let (status, body) = response_json(router.clone().oneshot(ok).await?).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["mode"], "managed");
    assert!(!body.to_string().contains(&native));

    let mut replay = loopback_request("GET", "/freedom/v1/status")?;
    replay.headers_mut().insert(
        "x-freedom-native-token",
        native
            .parse()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?,
    );
    replay.headers_mut().insert(
        "x-freedom-nonce",
        "nonce-a"
            .parse()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?,
    );
    let (status, body) = response_json(router.clone().oneshot(replay).await?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "freedom_nonce_replayed");

    let mut missing_nonce = loopback_request("GET", "/freedom/v1/status")?;
    missing_nonce.headers_mut().insert(
        "x-freedom-native-token",
        native
            .parse()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?,
    );
    let (status, body) = response_json(router.clone().oneshot(missing_nonce).await?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "freedom_nonce_missing");

    let mut bad_token = loopback_request("GET", "/freedom/v1/status")?;
    bad_token.headers_mut().insert(
        "x-freedom-native-token",
        "not-the-process-token"
            .parse()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?,
    );
    bad_token.headers_mut().insert(
        "x-freedom-nonce",
        "nonce-b"
            .parse()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?,
    );
    let (status, body) = response_json(router.clone().oneshot(bad_token).await?).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "freedom_token_denied");
    let mut nonce_survives = loopback_request("GET", "/freedom/v1/status")?;
    nonce_survives.headers_mut().insert(
        "x-freedom-native-token",
        native
            .parse()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?,
    );
    nonce_survives.headers_mut().insert(
        "x-freedom-nonce",
        "nonce-b"
            .parse()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?,
    );
    let (status, _) = response_json(router.clone().oneshot(nonce_survives).await?).await?;
    assert_eq!(status, StatusCode::OK);

    let mut bad_host = loopback_request("GET", "/freedom/v1/status")?;
    bad_host.headers_mut().insert(
        "host",
        "evil.example:9200"
            .parse()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?,
    );
    bad_host.headers_mut().insert(
        "x-freedom-native-token",
        native
            .parse()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?,
    );
    bad_host.headers_mut().insert(
        "x-freedom-nonce",
        "nonce-c"
            .parse()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?,
    );
    let (status, body) = response_json(router.clone().oneshot(bad_host).await?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "freedom_host_denied");

    let mut bad_origin = loopback_request("POST", "/system/shutdown")?;
    bad_origin.headers_mut().insert(
        "origin",
        "https://127.0.0.1:9200"
            .parse()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?,
    );
    bad_origin.headers_mut().insert(
        "authorization",
        format!("Bearer {}", fresh_token())
            .parse()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?,
    );
    let (status, body) = response_json(router.clone().oneshot(bad_origin).await?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "freedom_origin_denied");

    let mut null_origin = loopback_request("POST", "/system/shutdown")?;
    null_origin.headers_mut().insert(
        "origin",
        "null"
            .parse()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?,
    );
    let (status, body) = response_json(router.clone().oneshot(null_origin).await?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "freedom_origin_denied");

    let mut public_peer = Request::builder()
        .method("POST")
        .uri("/system/shutdown")
        .header("host", "127.0.0.1:9200")
        .body(Body::empty())?;
    public_peer
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            9,
        ))));
    let (status, body) = response_json(router.clone().oneshot(public_peer).await?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "freedom_peer_denied");

    let mut unspecified = Request::builder()
        .method("POST")
        .uri("/system/shutdown")
        .header("host", "127.0.0.1:9200")
        .body(Body::empty())?;
    unspecified
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 9))));
    let (status, body) = response_json(router.clone().oneshot(unspecified).await?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "freedom_peer_denied");

    let missing_peer = Request::builder()
        .method("POST")
        .uri("/system/shutdown")
        .header("host", "127.0.0.1:9200")
        .body(Body::empty())?;
    let (status, body) = response_json(router.clone().oneshot(missing_peer).await?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "freedom_peer_denied");

    let mut path_origin = loopback_request("GET", "/api/v1/settings/telemetry")?;
    path_origin.headers_mut().insert(
        "origin",
        "http://127.0.0.1:9200/extra"
            .parse()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?,
    );
    let (status, body) = response_json(router.clone().oneshot(path_origin).await?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "freedom_origin_denied");

    let health = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/system/health")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(health.status(), StatusCode::OK);
    assert!(
        health
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn neo06_standalone_settings_cannot_relax_managed_profile() -> anyhow::Result<()> {
    let (dir, state, token) = managed_app(Scope::process_only()).await?;
    let before = state.analytics.get_state().await;
    let standalone_dir = dir.path().join("standalone-profile");
    let standalone_home = dir.path().join("standalone-home");
    tokio::fs::create_dir_all(&standalone_home).await?;
    let standalone = AppState::new_with_home(config_at(&standalone_dir), standalone_home).await?;
    standalone.analytics.set_consent(!before.consent).await?;
    let after = state.analytics.get_state().await;
    assert_eq!(before.consent, after.consent);
    assert_eq!(before.distinct_id, after.distinct_id);
    assert_ne!(
        standalone.analytics.get_state().await.distinct_id,
        before.distinct_id
    );
    assert!(!standalone.freedom.is_managed());
    assert!(state.freedom.is_managed());

    let opened = AppState::new_with_home(
        config_at(state.freedom.profile_dir()),
        dir.path().join("home2"),
    )
    .await;
    assert!(opened.is_err(), "standalone opened a managed profile");

    let router = build_router(state.clone());
    let mut relax = loopback_request("PUT", "/api/v1/settings/telemetry")?;
    relax.headers_mut().insert(
        "content-type",
        "application/json"
            .parse()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?,
    );
    relax.headers_mut().insert(
        "authorization",
        format!("Bearer {token}")
            .parse()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?,
    );
    *relax.body_mut() = Body::from(r#"{"consent":false,"managed":true}"#);
    let (status, body) = response_json(router.clone().oneshot(relax).await?).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], CODE_MODE_FIXED);
    assert_eq!(state.analytics.get_state().await.consent, before.consent);
    assert!(state.freedom.is_managed());

    let mut consent = loopback_request("PUT", "/api/v1/settings/telemetry")?;
    consent.headers_mut().insert(
        "content-type",
        "application/json"
            .parse()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?,
    );
    consent.headers_mut().insert(
        "authorization",
        format!("Bearer {token}")
            .parse()
            .map_err(|error| anyhow::anyhow!("{error:?}"))?,
    );
    *consent.body_mut() = Body::from(r#"{"consent":false}"#);
    let (status, _) = response_json(router.clone().oneshot(consent).await?).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(state.freedom.is_managed());

    let still = dispatch_named(
        &state,
        "snapshot",
        json!({"page": 1}),
        None,
        Some("Ted".to_string()),
        false,
    )
    .await?;
    assert_denied(&still, CODE_CONTEXT_REQUIRED);

    let same = claw_server_rust::freedom::ensure_distinct(Path::new("/same"), Path::new("/same"));
    assert!(same.is_err());
    Ok(())
}

#[tokio::test]
async fn neo07_session_label_without_valid_token_is_denied() -> anyhow::Result<()> {
    let (_dir, state, token) = managed_app(Scope::pages([1])).await?;
    let denied = dispatch_named(
        &state,
        "snapshot",
        json!({"page": 1}),
        None,
        Some("Ted".to_string()),
        false,
    )
    .await?;
    assert_denied(&denied, CODE_CONTEXT_REQUIRED);

    let allowed = dispatch_named(
        &state,
        "snapshot",
        json!({"page": 1}),
        Some(token.clone()),
        Some("Ted".to_string()),
        false,
    )
    .await?;
    let text = tool_text(&allowed);
    assert!(text.contains("no link to the browser"), "{text}");
    assert!(!text.contains("Ted"));

    Ok(())
}

#[tokio::test]
async fn neo12_late_effect_after_cancel_is_audit_only_and_not_accepted() -> anyhow::Result<()> {
    let (_dir, state, token) = managed_app(Scope::pages([1])).await?;
    let late = dispatch_named(
        &state,
        "snapshot",
        json!({"page": 1}),
        Some(token),
        None,
        true,
    )
    .await?;
    assert_denied(&late, CODE_LATE_AUDIT);

    let ticket = state.freedom.begin_effect();
    state.freedom.cancel_effect(ticket);
    assert!(state.freedom.effect_is_audit_only(ticket));
    assert!(
        state
            .freedom
            .audit_trail()
            .iter()
            .any(|note| note == &format!("audit-only:{ticket}"))
    );
    assert_eq!(
        state.freedom.try_mark_business_accepted(ticket),
        Err(CODE_LATE_AUDIT)
    );
    assert!(!state.freedom.effect_business_accepted(ticket));

    let executed = state.freedom.begin_effect();
    state.freedom.settle_executed(executed);
    assert_eq!(
        state.freedom.try_mark_business_accepted(executed),
        Err(CODE_BUSINESS)
    );
    assert!(
        state
            .freedom
            .audit_trail()
            .iter()
            .any(|note| note.contains(CODE_BUSINESS))
    );
    assert!(!state.freedom.effect_business_accepted(executed));
    Ok(())
}

#[tokio::test]
async fn standalone_mode_does_not_require_a_freedom_context() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let home = dir.path().join("home");
    tokio::fs::create_dir_all(&home).await?;
    let state = AppState::new_with_home(config_at(&dir.path().join("profile")), home).await?;
    assert!(!state.freedom.is_managed());
    let result = dispatch_named(
        &state,
        "snapshot",
        json!({"page": 1}),
        None,
        Some("Ted".to_string()),
        false,
    )
    .await?;
    let text = tool_text(&result);
    assert!(text.contains("no link to the browser"), "{text}");
    assert!(!text.contains(CODE_CONTEXT_REQUIRED));
    let router = build_router(state);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/system/health")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("*")
    );
    Ok(())
}

#[tokio::test]
async fn label_is_not_sent_to_the_verifier() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let home = dir.path().join("home");
    let profile = dir.path().join("managed");
    let standalone = dir.path().join("standalone-default");
    tokio::fs::create_dir_all(&home).await?;
    let secret = fresh_token();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut inner = InProcessVerifier::new();
    let (auth, attempt) = BoundAttempt::matching_pair("alice", "attempt-1", Scope::pages([1]));
    inner.insert(secret.clone(), auth, attempt);
    let verifier = RecordingVerifier {
        inner,
        seen: Arc::clone(&seen),
    };
    let state =
        AppState::new_managed_with_home(config_at(&profile), home, standalone, Arc::new(verifier))
            .await?;
    let allowed = dispatch_named(
        &state,
        "snapshot",
        json!({"page": 1}),
        Some(secret.clone()),
        Some("Ted".to_string()),
        false,
    )
    .await?;
    assert!(tool_text(&allowed).contains("no link to the browser"));
    let recorded = seen.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(recorded.iter().any(|item| item == &secret));
    assert!(recorded.iter().all(|item| item != "Ted"));
    Ok(())
}

#[tokio::test]
async fn finding1_tabs_active_and_new_do_not_reach_upstream() -> anyhow::Result<()> {
    let (_dir, state, token) = managed_app(Scope::pages([1])).await?;
    let active = dispatch_named(
        &state,
        "tabs",
        json!({"action": "active", "page": 1}),
        Some(token.clone()),
        None,
        false,
    )
    .await?;
    assert_denied(&active, CODE_UNSCOPED);

    let opened = dispatch_named(
        &state,
        "tabs",
        json!({
            "action": "new",
            "url": "https://example.com/new",
            "groupId": "group-outside-the-grant"
        }),
        Some(token.clone()),
        None,
        false,
    )
    .await?;
    assert_denied(&opened, CODE_UNSCOPED);
    assert!(!tool_text(&opened).contains("group-outside-the-grant"));

    let wrapped = dispatch_named(
        &state,
        "tabs",
        json!({"action": "new", "url": "view-source:file:///etc/passwd"}),
        Some(token),
        None,
        false,
    )
    .await?;
    assert_denied(&wrapped, CODE_SCHEME);
    Ok(())
}

#[tokio::test]
async fn finding4_garbage_marker_refuses_standalone_opener() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let home = dir.path().join("home");
    tokio::fs::create_dir_all(&home).await?;
    let profile = dir.path().join("profile");
    tokio::fs::create_dir_all(&profile).await?;
    tokio::fs::write(
        profile.join("freedom-managed-profile.json"),
        br#"{"mode":"standalone"}"#,
    )
    .await?;
    let opened = AppState::new_with_home(config_at(&profile), home).await;
    assert!(opened.is_err(), "garbage marker opened as standalone");

    let blocked = dir.path().join("blocked");
    tokio::fs::create_dir_all(&blocked).await?;
    tokio::fs::create_dir(blocked.join("freedom-managed-profile.json")).await?;
    let unreadable =
        AppState::new_with_home(config_at(&blocked), dir.path().join("home-unreadable")).await;
    assert!(
        unreadable.is_err(),
        "unreadable marker opened as standalone"
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn finding5_symlink_onto_standalone_refuses_before_the_marker() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let home = dir.path().join("home");
    tokio::fs::create_dir_all(&home).await?;
    let standalone = dir.path().join("standalone");
    tokio::fs::create_dir_all(&standalone).await?;
    let link = dir.path().join("managed-link");
    std::os::unix::fs::symlink(&standalone, &link)?;
    let opened = AppState::new_managed_with_home(
        config_at(&link),
        home,
        standalone.clone(),
        Arc::new(ClosedVerifier),
    )
    .await;
    assert!(opened.is_err(), "symlink onto standalone was accepted");
    assert!(!standalone.join("freedom-managed-profile.json").exists());

    let third = dir.path().join("third");
    tokio::fs::create_dir_all(&third).await?;
    let distinct = dir.path().join("distinct-link");
    std::os::unix::fs::symlink(&third, &distinct)?;
    let accepted = AppState::new_managed_with_home(
        config_at(&distinct),
        dir.path().join("home-ok"),
        standalone,
        Arc::new(ClosedVerifier),
    )
    .await?;
    assert!(accepted.freedom.is_managed());
    assert!(third.join("freedom-managed-profile.json").is_file());
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn finding5_dotdot_through_symlink_refuses_before_the_marker() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let home = dir.path().join("home");
    tokio::fs::create_dir_all(&home).await?;
    let standalone = dir.path().join("standalone");
    let inside = standalone.join("inside");
    tokio::fs::create_dir_all(&inside).await?;
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&inside, &link)?;
    let managed = link.join("..").join("managed-profile");
    let opened = AppState::new_managed_with_home(
        config_at(&managed),
        home,
        standalone.clone(),
        Arc::new(ClosedVerifier),
    )
    .await;
    let Err(error) = opened else {
        panic!("link/../managed-profile inside standalone was accepted");
    };
    assert!(
        error.to_string().contains("freedom_profile_not_distinct"),
        "{error}"
    );
    assert!(!standalone.join("managed-profile").exists());
    assert_no_marker_under(dir.path());
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn finding5_middle_symlink_refuses_before_the_marker() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let home = dir.path().join("home");
    tokio::fs::create_dir_all(&home).await?;
    let standalone = dir.path().join("standalone");
    let inside = standalone.join("inside");
    tokio::fs::create_dir_all(&inside).await?;
    let middle = dir.path().join("middle");
    tokio::fs::create_dir_all(&middle).await?;
    let link = middle.join("link");
    std::os::unix::fs::symlink(&inside, &link)?;
    let managed = link.join("managed-profile");
    let opened = AppState::new_managed_with_home(
        config_at(&managed),
        home,
        standalone,
        Arc::new(ClosedVerifier),
    )
    .await;
    assert!(
        opened.is_err(),
        "symlinked ancestor inside standalone was accepted"
    );
    assert!(!inside.join("managed-profile").exists());
    assert_no_marker_under(dir.path());
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn finding5_reverse_symlink_ancestor_refuses_before_the_marker() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let home = dir.path().join("home");
    tokio::fs::create_dir_all(&home).await?;
    let managed = dir.path().join("managed");
    let inside = managed.join("inside");
    tokio::fs::create_dir_all(&inside).await?;
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&inside, &link)?;
    let standalone = link.join("..").join("nested");
    let opened = AppState::new_managed_with_home(
        config_at(&managed),
        home.clone(),
        standalone,
        Arc::new(ClosedVerifier),
    )
    .await;
    assert!(
        opened.is_err(),
        "standalone link/.. inside managed was accepted"
    );

    let middle = dir.path().join("middle");
    tokio::fs::create_dir_all(&middle).await?;
    let middle_link = middle.join("link");
    std::os::unix::fs::symlink(&inside, &middle_link)?;
    let opened = AppState::new_managed_with_home(
        config_at(&managed),
        home,
        middle_link.join("nested"),
        Arc::new(ClosedVerifier),
    )
    .await;
    assert!(
        opened.is_err(),
        "standalone symlink ancestor inside managed was accepted"
    );
    assert!(
        !inside
            .join("nested")
            .join("freedom-managed-profile.json")
            .exists()
    );
    assert!(!managed.join("freedom-managed-profile.json").exists());
    assert_no_marker_under(dir.path());
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn finding5_marker_is_written_on_the_resolved_directory() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let home = dir.path().join("home");
    tokio::fs::create_dir_all(&home).await?;
    let outside = dir.path().join("outside");
    tokio::fs::create_dir_all(outside.join("inside")).await?;
    let standalone = dir.path().join("standalone");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(outside.join("inside"), &link)?;
    let requested = link.join("..").join("managed-profile");
    let state = AppState::new_managed_with_home(
        config_at(&requested),
        home,
        standalone,
        Arc::new(ClosedVerifier),
    )
    .await?;
    let expected = std::fs::canonicalize(outside.join("managed-profile"))?;
    assert_eq!(state.config.browserclaw_dir, expected);
    assert_eq!(state.freedom.profile_dir(), expected.as_path());
    assert!(expected.join("freedom-managed-profile.json").is_file());
    assert!(!dir.path().join("managed-profile").exists());
    Ok(())
}

#[cfg(unix)]
fn assert_no_marker_under(root: &Path) {
    fn walk(dir: &Path) {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) => panic!("read {}: {error}", dir.display()),
        };
        for entry in entries {
            let entry = entry.unwrap_or_else(|error| panic!("{error}"));
            let path = entry.path();
            let kind = entry.file_type().unwrap_or_else(|error| panic!("{error}"));
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() {
                walk(&path);
            } else if path.file_name().and_then(|name| name.to_str())
                == Some("freedom-managed-profile.json")
            {
                panic!("marker written at {}", path.display());
            }
        }
    }
    if root.is_dir() {
        walk(root);
    }
}

struct FixtureConnection {
    events: broadcast::Sender<CdpEvent>,
    url: &'static str,
    cancel_on_tabs: Option<CancellationToken>,
}

impl FixtureConnection {
    fn new(url: &'static str, cancel_on_tabs: Option<CancellationToken>) -> Arc<Self> {
        let (events, _) = broadcast::channel(1);
        Arc::new(Self {
            events,
            url,
            cancel_on_tabs,
        })
    }
}

impl CdpConnection for FixtureConnection {
    fn send<'a>(
        &'a self,
        method: &'a str,
        _params: Value,
        _session: Option<&'a CdpSessionId>,
    ) -> BoxFuture<'a, Result<Value, CdpError>> {
        let url = self.url;
        let cancel = self.cancel_on_tabs.clone();
        Box::pin(async move {
            if method == "Browser.getTabs" {
                if let Some(cancel) = cancel {
                    cancel.cancel();
                }
                return Ok(json!({ "tabs": [{
                    "tabId": 11,
                    "targetId": "target-a",
                    "url": url,
                    "title": "Example",
                    "isActive": true,
                    "isLoading": false,
                    "loadProgress": 1.0,
                    "isPinned": false,
                    "isHidden": false,
                    "windowId": 1,
                    "index": 0
                }] }));
            }
            Err(CdpError::Protocol {
                code: -1,
                message: "fixture has no page session".to_string(),
            })
        })
    }

    fn send_raw_json<'a>(
        &'a self,
        _method: &'a str,
        _params_json: &'a str,
        _session: Option<&'a CdpSessionId>,
    ) -> BoxFuture<'a, Result<String, CdpError>> {
        Box::pin(async { Ok("{}".to_string()) })
    }

    fn events(&self) -> broadcast::Receiver<CdpEvent> {
        self.events.subscribe()
    }

    fn is_connected(&self) -> bool {
        true
    }

    fn connection_epoch(&self) -> u64 {
        1
    }
}

async fn dispatch_with_browser(
    state: &AppState,
    tool: &str,
    args: Value,
    token: Option<String>,
    identity: Option<ToolIdentity>,
    browser: Option<Arc<BrowserSession>>,
    client_cancel: CancellationToken,
) -> anyhow::Result<CallToolResult> {
    let catalog = Arc::new(browseros_mcp::catalog());
    let tool_index = catalog
        .iter()
        .position(|entry| entry.name == tool)
        .ok_or_else(|| anyhow::anyhow!("missing tool {tool}"))?;
    let mut call = ToolCall::new(
        catalog,
        tool_index,
        args,
        SessionId::new("s1"),
        identity,
        browser,
        CancellationToken::new(),
        client_cancel,
        CancellationToken::new(),
        None,
        state.clone(),
        browseros_mcp::output_file::create_browser_output_file_access(),
    );
    call.set_freedom_auth(token, None);
    dispatch_tool_call(call)
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))
}

fn fresh_session(id: &str) -> Arc<Session> {
    Session::new(
        SessionId::new(id),
        ClientIdentity::Ephemeral {
            slug: "self".to_string(),
            label: "Self".to_string(),
        },
        ConversationIdentity::new("self", format!("{id}-convo")),
        "Self".to_string(),
        tokio::time::Instant::now(),
    )
}

#[tokio::test]
async fn finding6_page_text_is_not_a_cancellation() -> anyhow::Result<()> {
    let (_dir, state, token) = managed_app(Scope::pages([1])).await?;
    let phrase = "Operation cancelled by the User";
    let browser = BrowserSession::new(
        FixtureConnection::new("https://example.test/Operation cancelled by the User", None),
        BrowserSessionHooks::default(),
    );
    assert_eq!(browser.pages.list().await?.len(), 1);
    let before = state.freedom.audit_trail();
    let result = dispatch_with_browser(
        &state,
        "read",
        json!({"page": 1, "format": "console"}),
        Some(token),
        None,
        Some(browser),
        CancellationToken::new(),
    )
    .await?;
    let text = tool_text(&result);
    assert!(text.contains(phrase), "{text}");
    assert!(!text.contains(CODE_LATE_AUDIT), "{text}");
    assert_ne!(result.is_error, Some(true), "{text}");
    assert_eq!(state.freedom.audit_trail(), before);
    assert!(!state.freedom.effect_is_audit_only(1));
    assert_eq!(
        state.freedom.try_mark_business_accepted(1),
        Err(CODE_BUSINESS)
    );
    assert!(!state.freedom.effect_business_accepted(1));
    Ok(())
}

#[tokio::test]
async fn finding6_operator_stop_settles_audit_only() -> anyhow::Result<()> {
    let (_dir, state, token) = managed_app(Scope::pages([1])).await?;
    let session = fresh_session("operator");
    session.request_operator_stop();
    state.sessions.insert_for_testing(session.clone()).await;
    let identity = ToolIdentity {
        agent: session.agent().clone(),
        ownership_key: session.convo_id().clone(),
        agent_label: "Self".to_string(),
        session,
    };
    let browser = BrowserSession::new(
        FixtureConnection::new("https://granted.example/ok", None),
        BrowserSessionHooks::default(),
    );
    assert_eq!(browser.pages.list().await?.len(), 1);
    let result = dispatch_with_browser(
        &state,
        "read",
        json!({"page": 1, "format": "console"}),
        Some(token),
        Some(identity),
        Some(browser),
        CancellationToken::new(),
    )
    .await?;
    let text = tool_text(&result);
    assert!(text.contains(CODE_LATE_AUDIT), "{text}");
    assert!(!text.contains("granted.example"), "{text}");
    assert!(state.freedom.effect_is_audit_only(1));
    assert_eq!(
        state.freedom.try_mark_business_accepted(1),
        Err(CODE_LATE_AUDIT)
    );
    assert!(!state.freedom.effect_business_accepted(1));
    Ok(())
}

#[tokio::test]
async fn finding6_client_cancel_during_tool_is_audit_only() -> anyhow::Result<()> {
    let (_dir, state, token) = managed_app(Scope::pages([1])).await?;
    let client_cancel = CancellationToken::new();
    let browser = BrowserSession::new(
        FixtureConnection::new("https://granted.example/slow", Some(client_cancel.clone())),
        BrowserSessionHooks::default(),
    );
    let result = dispatch_with_browser(
        &state,
        "read",
        json!({"page": 1}),
        Some(token),
        None,
        Some(browser),
        client_cancel,
    )
    .await?;
    let text = tool_text(&result);
    assert!(text.contains(CODE_LATE_AUDIT), "{text}");
    assert!(!text.contains("granted.example"), "{text}");
    assert!(state.freedom.effect_is_audit_only(1));
    assert_eq!(
        state.freedom.try_mark_business_accepted(1),
        Err(CODE_LATE_AUDIT)
    );
    Ok(())
}
