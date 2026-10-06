// Freedom modification (AGPL-3.0-or-later §5(a) prominent notice).
// Added 2026-10-06. Managed-mode guard for the 自由工坊 neo client.
// Not part of upstream BrowserOS.

//! Freedom managed mode: verified run context, effect guard, and loopback API.
//!
//! Standalone mode does not consult this module on the upstream dispatch path.
//! There is no platform client and no network here. Tests supply an in-process
//! [`FreedomVerifier`].

mod context;
mod guard;
mod local_api;
mod mode;
mod registry;

pub use context::{
    BoundAttempt, ClosedVerifier, ContextError, FreedomRunContext, FreedomVerifier,
    InProcessVerifier, NativeAuthResult, Scope, VerifyFailure,
};
pub use guard::{
    CODE_ATTEMPT_MISMATCH, CODE_BINDING_MISMATCH, CODE_BUSINESS, CODE_CONTEXT_REQUIRED,
    CODE_GRANT_REVOKED, CODE_LATE_AUDIT, CODE_MODE_FIXED, CODE_PROFILE, CODE_RAW_EXEC, CODE_SCHEME,
    CODE_SCOPE, CODE_TARGET, CODE_TOKEN_INVALID, CODE_UNSCOPED, Disposition, HttpGate,
    PipelineOutcome, STEP_BEGIN, STEP_BOUND_ATTEMPT, STEP_DOMAIN, STEP_EXECUTE, STEP_NATIVE_AUTH,
    STEP_OBSERVATION, STEP_RECEIPT, STEP_SCHEMA, ToolRequest, decide_http, precheck_mcp_tool,
    run_tool_pipeline, tool_denial,
};
pub use local_api::{FreedomLocalAuth, LocalError, loopback_bind_addr, refuse_non_loopback};
pub use mode::{
    ModeError, ProfileError, StartupRequest, ensure_distinct, profile_is_managed, resolve_startup,
    settings_try_to_relax, write_managed_marker,
};
pub use registry::{SurfaceEntry, SurfaceKind, Treatment, find_id, surfaces};

use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU16, Ordering},
    },
};

use guard::Journal;

/// Process-wide Freedom mode. Chosen only while the process is starting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreedomMode {
    Standalone,
    Managed,
}

/// In-memory managed-mode state for one process. Not reloadable from disk or HTTP.
pub struct FreedomRuntime {
    mode: FreedomMode,
    profile_dir: PathBuf,
    verifier: Arc<dyn FreedomVerifier>,
    native_token: String,
    bound_port: AtomicU16,
    nonces: Mutex<BTreeSet<String>>,
    journal: Mutex<Journal>,
    guard_decisions: std::sync::atomic::AtomicU64,
}

impl FreedomRuntime {
    /// Upstream default. Does not write a managed-profile marker.
    #[must_use]
    pub fn standalone(port: u16, profile_dir: PathBuf) -> Arc<Self> {
        Arc::new(Self::new(
            FreedomMode::Standalone,
            profile_dir,
            port,
            Arc::new(ClosedVerifier),
        ))
    }

    /// Managed mode. `verifier` is the only source of bound attempts.
    /// Production passes [`ClosedVerifier`], which accepts nothing and does not dial out.
    #[must_use]
    pub fn managed(
        port: u16,
        profile_dir: PathBuf,
        verifier: Arc<dyn FreedomVerifier>,
    ) -> Arc<Self> {
        Arc::new(Self::new(FreedomMode::Managed, profile_dir, port, verifier))
    }

    fn new(
        mode: FreedomMode,
        profile_dir: PathBuf,
        port: u16,
        verifier: Arc<dyn FreedomVerifier>,
    ) -> Self {
        Self {
            mode,
            profile_dir,
            verifier,
            native_token: local_api::generate_native_token(),
            bound_port: AtomicU16::new(port),
            nonces: Mutex::new(BTreeSet::new()),
            journal: Mutex::new(Journal::default()),
            guard_decisions: std::sync::atomic::AtomicU64::new(0),
        }
    }

    #[must_use]
    pub fn mode(&self) -> FreedomMode {
        self.mode
    }

    #[must_use]
    pub fn is_managed(&self) -> bool {
        self.mode == FreedomMode::Managed
    }

    #[must_use]
    pub fn mode_name(&self) -> &'static str {
        match self.mode {
            FreedomMode::Standalone => "standalone",
            FreedomMode::Managed => "managed",
        }
    }

    #[must_use]
    pub fn profile_dir(&self) -> &std::path::Path {
        &self.profile_dir
    }

    /// Per-process loopback credential. Not a platform token and not a member identity.
    #[must_use]
    pub fn native_token(&self) -> &str {
        &self.native_token
    }

    #[must_use]
    pub fn bound_port(&self) -> u16 {
        self.bound_port.load(Ordering::SeqCst)
    }

    /// Records the port the listener actually bound. Does not change mode or grants.
    pub fn publish_bound_port(&self, port: u16) {
        self.bound_port.store(port, Ordering::SeqCst);
    }

    pub(crate) fn record_decision(&self) {
        self.guard_decisions.fetch_add(1, Ordering::SeqCst);
    }

    #[must_use]
    pub fn guard_decisions(&self) -> u64 {
        self.guard_decisions.load(Ordering::SeqCst)
    }

    pub(crate) fn verifier(&self) -> &dyn FreedomVerifier {
        self.verifier.as_ref()
    }

    pub(crate) fn nonce_jar(&self) -> &Mutex<BTreeSet<String>> {
        &self.nonces
    }

    pub(crate) fn journal(&self) -> &Mutex<Journal> {
        &self.journal
    }

    fn with_journal<T>(&self, body: impl FnOnce(&mut Journal) -> T) -> T {
        let mut journal = self
            .journal
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        body(&mut journal)
    }

    /// Opens an effect ticket. Business acceptance stays false.
    pub fn begin_effect(&self) -> u64 {
        self.with_journal(Journal::begin_effect)
    }

    pub fn cancel_effect(&self, id: u64) {
        self.with_journal(|journal| journal.cancel_effect(id));
    }

    pub fn settle_executed(&self, id: u64) {
        self.with_journal(|journal| journal.settle_executed(id));
    }

    pub fn try_mark_business_accepted(&self, id: u64) -> Result<(), &'static str> {
        self.with_journal(|journal| journal.try_mark_business_accepted(id))
    }

    #[must_use]
    pub fn effect_business_accepted(&self, id: u64) -> bool {
        self.with_journal(|journal| journal.business_accepted(id))
    }

    #[must_use]
    pub fn effect_is_audit_only(&self, id: u64) -> bool {
        self.with_journal(|journal| journal.disposition(id) == Some(guard::Disposition::AuditOnly))
    }

    /// Audit lines written by cancel and by a refused business-acceptance mark.
    #[must_use]
    pub fn audit_trail(&self) -> Vec<String> {
        self.with_journal(|journal| journal.audit_notes().to_vec())
    }
}
