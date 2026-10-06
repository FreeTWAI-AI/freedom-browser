// Freedom modification (AGPL-3.0-or-later §5(a) prominent notice).
// Added 2026-10-06. Managed-mode guard for the 自由工坊 neo client.
// Not part of upstream BrowserOS.

//! Reachable surfaces and their managed-mode treatment.
//!
//! The table is checked against the live Axum router source and the MCP catalog
//! by `freedom_coverage`. An effect or raw-exec surface is never
//! `allowed_no_effect`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceKind {
    Read,
    Effect,
    RawExec,
    AdminLocal,
    UiOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Treatment {
    Guarded,
    Denied,
    AllowedNoEffect,
}

/// How a guarded HTTP route applies the verified scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpScope {
    /// Not an HTTP route.
    NotHttp,
    /// Liveness probe. No page or grant data.
    Probe,
    /// Any verified context. Not a tab or session read.
    Process,
    /// Denied unless the context opts into aggregate reads.
    Aggregate,
    /// `{session_id}` must be inside the context.
    Session,
    /// Loopback native token. Not a platform bearer.
    Local,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurfaceEntry {
    pub id: &'static str,
    pub kind: SurfaceKind,
    pub treatment: Treatment,
    pub scope: HttpScope,
    pub justification: &'static str,
}

const fn entry(
    id: &'static str,
    kind: SurfaceKind,
    treatment: Treatment,
    scope: HttpScope,
    justification: &'static str,
) -> SurfaceEntry {
    SurfaceEntry {
        id,
        kind,
        treatment,
        scope,
        justification,
    }
}

const PROBE: &str = "Liveness probe. Returns no page, session, or grant data.";
const PROCESS: &str = "Process admin. Requires a verified context and does not read foreign tabs.";
const AGGREGATE: &str = "Aggregate view. Denied unless the bound attempt allows it.";
const SESSION: &str = "Session-scoped. The session id must be inside the bound attempt.";
const LOCAL: &str = "Loopback status. Native token and single-use nonce, not a member bearer.";
const MCP_READ: &str = "Page or browser read. Limited to the bound attempt's pages.";
const MCP_EFFECT: &str = "Browser or session effect. Requires a verified context before dispatch.";
const RAW: &str = "Arbitrary execution. Denied on the dispatch path in managed mode.";
const UNSCOPED: &str =
    "Browser-wide read with no page target. Fail closed in managed mode until a scope exists.";

#[must_use]
pub fn surfaces() -> &'static [SurfaceEntry] {
    SURFACES
}

#[must_use]
pub fn match_http(method: &str, path: &str) -> Option<&'static SurfaceEntry> {
    surfaces().iter().find(|entry| {
        let Some((entry_method, entry_path)) = entry.id.split_once(' ') else {
            return false;
        };
        entry_method == method && path_matches(entry_path, path)
    })
}

#[must_use]
pub fn find_id(id: &str) -> Option<&'static SurfaceEntry> {
    surfaces().iter().find(|entry| entry.id == id)
}

/// True when any method on this path is guarded or denied.
#[must_use]
pub fn path_is_guarded(path: &str) -> bool {
    surfaces().iter().any(|entry| {
        let Some((_, entry_path)) = entry.id.split_once(' ') else {
            return false;
        };
        path_matches(entry_path, path)
            && matches!(entry.treatment, Treatment::Guarded | Treatment::Denied)
    })
}

fn path_matches(pattern: &str, path: &str) -> bool {
    let pattern: Vec<&str> = pattern.split('/').filter(|part| !part.is_empty()).collect();
    let path: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    if pattern.len() != path.len() {
        return false;
    }
    pattern.iter().zip(path.iter()).all(|(pattern, segment)| {
        if pattern.starts_with('{') && pattern.ends_with('}') {
            !segment.is_empty()
        } else {
            pattern == segment
        }
    })
}

const SURFACES: &[SurfaceEntry] = &[
    entry(
        "GET /system/health",
        SurfaceKind::Read,
        Treatment::AllowedNoEffect,
        HttpScope::Probe,
        PROBE,
    ),
    entry(
        "GET /system/ready",
        SurfaceKind::Read,
        Treatment::AllowedNoEffect,
        HttpScope::Probe,
        PROBE,
    ),
    entry(
        "GET /system/diagnostics",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::Process,
        PROCESS,
    ),
    entry(
        "POST /system/shutdown",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::Process,
        PROCESS,
    ),
    entry(
        "GET /api/v1/system",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::Process,
        PROCESS,
    ),
    entry(
        "POST /api/v1/extension/update-ready",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::Process,
        PROCESS,
    ),
    entry(
        "GET /api/v1/cockpit/stats",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::Aggregate,
        AGGREGATE,
    ),
    entry(
        "GET /api/v1/feedback/invitation",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::Process,
        PROCESS,
    ),
    entry(
        "POST /api/v1/feedback/invitation",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::Process,
        PROCESS,
    ),
    entry(
        "GET /api/v1/audit/storage",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::Process,
        PROCESS,
    ),
    entry(
        "PUT /api/v1/audit/retention",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::Process,
        PROCESS,
    ),
    entry(
        "POST /api/v1/audit/cleanup",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::Process,
        PROCESS,
    ),
    entry(
        "GET /api/v1/settings/telemetry",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::Process,
        PROCESS,
    ),
    entry(
        "PUT /api/v1/settings/telemetry",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::Process,
        PROCESS,
    ),
    entry(
        "GET /api/v1/sessions",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::Aggregate,
        AGGREGATE,
    ),
    entry(
        "GET /api/v1/sessions/{session_id}",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::Session,
        SESSION,
    ),
    entry(
        "GET /api/v1/sessions/{session_id}/preview",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::Session,
        SESSION,
    ),
    entry(
        "POST /api/v1/sessions/{session_id}/cancel",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::Session,
        SESSION,
    ),
    entry(
        "POST /api/v1/sessions/{session_id}/help/resolve",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::Session,
        SESSION,
    ),
    entry(
        "GET /api/v1/sessions/{session_id}/screenshots",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::Session,
        SESSION,
    ),
    entry(
        "GET /api/v1/sessions/{session_id}/screenshots/{screenshot_id}",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::Session,
        SESSION,
    ),
    entry(
        "GET /api/v1/sessions/{session_id}/recording",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::Session,
        SESSION,
    ),
    entry(
        "GET /api/v1/sessions/{session_id}/recording/events",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::Session,
        SESSION,
    ),
    entry(
        "GET /api/v1/sessions/{session_id}/recording/live",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::Session,
        SESSION,
    ),
    entry(
        "POST /api/v1/recordings/events",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::Aggregate,
        AGGREGATE,
    ),
    entry(
        "GET /api/v1/connections",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::Process,
        PROCESS,
    ),
    entry(
        "PUT /api/v1/connections/{harness}",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::Process,
        PROCESS,
    ),
    entry(
        "DELETE /api/v1/connections/{harness}",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::Process,
        PROCESS,
    ),
    entry(
        "GET /api/v1/skills",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::Process,
        PROCESS,
    ),
    entry(
        "POST /api/v1/skills",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::Process,
        PROCESS,
    ),
    entry(
        "GET /api/v1/skills/{name}",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::Process,
        PROCESS,
    ),
    entry(
        "PUT /api/v1/skills/{name}",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::Process,
        PROCESS,
    ),
    entry(
        "DELETE /api/v1/skills/{name}",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::Process,
        PROCESS,
    ),
    entry(
        "GET /api/v1/skills/{name}/runs",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::Process,
        PROCESS,
    ),
    entry(
        "GET /mcp",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::Process,
        "MCP stream. A session label is not a member.",
    ),
    entry(
        "POST /mcp",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::Process,
        "MCP messages. Guarded before the upstream handler.",
    ),
    entry(
        "DELETE /mcp",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::Process,
        "MCP session teardown. Guarded like every other effect.",
    ),
    entry(
        "GET /freedom/v1/status",
        SurfaceKind::AdminLocal,
        Treatment::Guarded,
        HttpScope::Local,
        LOCAL,
    ),
    entry(
        "mcp:tabs",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::NotHttp,
        MCP_EFFECT,
    ),
    entry(
        "mcp:tab_groups",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::NotHttp,
        UNSCOPED,
    ),
    entry(
        "mcp:history",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::NotHttp,
        UNSCOPED,
    ),
    entry(
        "mcp:navigate",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::NotHttp,
        MCP_EFFECT,
    ),
    entry(
        "mcp:snapshot",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::NotHttp,
        MCP_READ,
    ),
    entry(
        "mcp:diff",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::NotHttp,
        MCP_READ,
    ),
    entry(
        "mcp:act",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::NotHttp,
        MCP_EFFECT,
    ),
    entry(
        "mcp:download",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::NotHttp,
        MCP_EFFECT,
    ),
    entry(
        "mcp:upload",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::NotHttp,
        MCP_EFFECT,
    ),
    entry(
        "mcp:read",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::NotHttp,
        MCP_READ,
    ),
    entry(
        "mcp:grep",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::NotHttp,
        MCP_READ,
    ),
    entry(
        "mcp:screenshot",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::NotHttp,
        MCP_READ,
    ),
    entry(
        "mcp:pdf",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::NotHttp,
        MCP_READ,
    ),
    entry(
        "mcp:wait",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::NotHttp,
        MCP_READ,
    ),
    entry(
        "mcp:windows",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::NotHttp,
        UNSCOPED,
    ),
    entry(
        "mcp:evaluate",
        SurfaceKind::RawExec,
        Treatment::Denied,
        HttpScope::NotHttp,
        RAW,
    ),
    entry(
        "mcp:run",
        SurfaceKind::RawExec,
        Treatment::Denied,
        HttpScope::NotHttp,
        RAW,
    ),
    entry(
        "mcp:name_session",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::NotHttp,
        MCP_EFFECT,
    ),
    entry(
        "mcp:save_skill",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::NotHttp,
        MCP_EFFECT,
    ),
    entry(
        "mcp:mark_skill_run",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::NotHttp,
        MCP_EFFECT,
    ),
    entry(
        "mcp:request_human_help",
        SurfaceKind::Effect,
        Treatment::Guarded,
        HttpScope::NotHttp,
        MCP_EFFECT,
    ),
    entry(
        "mcp:await_human_help",
        SurfaceKind::Read,
        Treatment::Guarded,
        HttpScope::NotHttp,
        "Session-local wait. Still requires a verified context.",
    ),
    entry(
        "native:script_hook",
        SurfaceKind::RawExec,
        Treatment::Denied,
        HttpScope::NotHttp,
        RAW,
    ),
    entry(
        "native:helper_runtime",
        SurfaceKind::RawExec,
        Treatment::Denied,
        HttpScope::NotHttp,
        RAW,
    ),
];

#[cfg(test)]
mod tests {
    use super::{SurfaceKind, Treatment, find_id, match_http, surfaces};

    #[test]
    fn effect_and_raw_exec_are_never_unrestricted() {
        for entry in surfaces() {
            if matches!(entry.kind, SurfaceKind::Effect | SurfaceKind::RawExec) {
                assert_ne!(entry.treatment, Treatment::AllowedNoEffect, "{}", entry.id);
            }
            assert!(!entry.justification.is_empty(), "{}", entry.id);
        }
        assert!(find_id("mcp:run").is_some_and(|entry| entry.treatment == Treatment::Denied));
        assert!(
            match_http("GET", "/system/health")
                .is_some_and(|entry| { entry.treatment == Treatment::AllowedNoEffect })
        );
        assert!(match_http("POST", "/system/shutdown").is_some());
        assert!(match_http("GET", "/api/v1/sessions/abc/preview").is_some());
        assert!(
            match_http("GET", "/api/v1/sessions")
                .is_some_and(|entry| entry.id == "GET /api/v1/sessions")
        );
        assert!(match_http("GET", "/missing").is_none());
    }
}
