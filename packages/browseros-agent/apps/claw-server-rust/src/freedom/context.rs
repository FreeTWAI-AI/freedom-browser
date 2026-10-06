// Freedom modification (AGPL-3.0-or-later §5(a) prominent notice).
// Added 2026-10-06. Managed-mode guard for the 自由工坊 neo client.
// Not part of upstream BrowserOS.

//! Verified Freedom run context.
//!
//! [`FreedomRunContext`] is built only by [`FreedomRunContext::try_new`]. It has no
//! `Default`, no public fields, and no deserializer. An MCP session label is not
//! an argument to that constructor.

use std::{collections::BTreeSet, sync::Arc};

/// Pages and sessions a verified attempt may touch. Empty sets grant nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pages: BTreeSet<u32>,
    sessions: BTreeSet<String>,
    aggregate: bool,
}

impl Scope {
    #[must_use]
    pub fn pages(pages: impl IntoIterator<Item = u32>) -> Self {
        Self {
            pages: pages.into_iter().collect(),
            sessions: BTreeSet::new(),
            aggregate: false,
        }
    }

    #[must_use]
    pub fn process_only() -> Self {
        Self {
            pages: BTreeSet::new(),
            sessions: BTreeSet::new(),
            aggregate: false,
        }
    }

    #[must_use]
    pub fn with_sessions(mut self, sessions: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.sessions.extend(sessions.into_iter().map(Into::into));
        self
    }

    #[must_use]
    pub fn with_aggregate(mut self, aggregate: bool) -> Self {
        self.aggregate = aggregate;
        self
    }

    #[must_use]
    pub fn contains_page(&self, page: u32) -> bool {
        self.pages.contains(&page)
    }

    #[must_use]
    pub fn contains_session(&self, session: &str) -> bool {
        self.sessions.contains(session)
    }

    #[must_use]
    pub fn allows_aggregate(&self) -> bool {
        self.aggregate
    }

    pub fn page_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.pages.iter().copied()
    }
}

/// Claims carried by a native or MCP credential check. Not a session label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeAuthResult {
    pub principal: String,
    pub attempt_id: String,
    pub run_id: String,
    pub runtime_device_id: String,
    pub grant_ref: String,
    pub grant_revision: u64,
    pub control_epoch: u64,
    pub lease_epoch: u64,
    pub policy_revision: u64,
    pub recovery_generation: u64,
}

/// Bound attempt supplied by a [`FreedomVerifier`]. The constructor compares it
/// to [`NativeAuthResult`] and to the current epochs on this record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundAttempt {
    pub principal: String,
    pub attempt_id: String,
    pub current_attempt_id: String,
    pub run_id: String,
    pub runtime_device_id: String,
    pub grant_ref: String,
    pub grant_revision: u64,
    pub current_grant_revision: u64,
    pub grant_revoked: bool,
    pub control_epoch: u64,
    pub current_control_epoch: u64,
    pub lease_epoch: u64,
    pub current_lease_epoch: u64,
    pub policy_revision: u64,
    pub current_policy_revision: u64,
    pub recovery_generation: u64,
    pub current_recovery_generation: u64,
    pub scope: Scope,
}

impl BoundAttempt {
    /// Matching auth result and attempt for tests and the in-process fake.
    #[must_use]
    pub fn matching_pair(principal: &str, attempt: &str, scope: Scope) -> (NativeAuthResult, Self) {
        let auth = NativeAuthResult {
            principal: principal.to_string(),
            attempt_id: attempt.to_string(),
            run_id: "run-1".to_string(),
            runtime_device_id: "device-1".to_string(),
            grant_ref: "grant-1".to_string(),
            grant_revision: 1,
            control_epoch: 1,
            lease_epoch: 1,
            policy_revision: 1,
            recovery_generation: 1,
        };
        let attempt = Self {
            principal: auth.principal.clone(),
            attempt_id: auth.attempt_id.clone(),
            current_attempt_id: auth.attempt_id.clone(),
            run_id: auth.run_id.clone(),
            runtime_device_id: auth.runtime_device_id.clone(),
            grant_ref: auth.grant_ref.clone(),
            grant_revision: auth.grant_revision,
            current_grant_revision: auth.grant_revision,
            grant_revoked: false,
            control_epoch: auth.control_epoch,
            current_control_epoch: auth.control_epoch,
            lease_epoch: auth.lease_epoch,
            current_lease_epoch: auth.lease_epoch,
            policy_revision: auth.policy_revision,
            current_policy_revision: auth.policy_revision,
            recovery_generation: auth.recovery_generation,
            current_recovery_generation: auth.recovery_generation,
            scope,
        };
        (auth, attempt)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextError {
    Incomplete,
    PrincipalMismatch,
    AttemptMismatch,
    BindingMismatch,
    GrantRevoked,
    StaleControlEpoch,
    StaleLeaseEpoch,
    StaleGrantRevision,
    StalePolicyRevision,
    StaleRecoveryGeneration,
}

impl ContextError {
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Incomplete => "freedom_incomplete_binding",
            Self::PrincipalMismatch => "freedom_principal_mismatch",
            Self::AttemptMismatch => "freedom_attempt_mismatch",
            Self::BindingMismatch => "freedom_binding_mismatch",
            Self::GrantRevoked => "freedom_grant_revoked",
            Self::StaleControlEpoch => "freedom_stale_control_epoch",
            Self::StaleLeaseEpoch => "freedom_stale_lease_epoch",
            Self::StaleGrantRevision => "freedom_stale_grant_revision",
            Self::StalePolicyRevision => "freedom_stale_policy_revision",
            Self::StaleRecoveryGeneration => "freedom_stale_recovery_generation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyFailure {
    UnknownToken,
    /// Production verifier. It has no platform address and does not open a socket.
    NoPlatformClient,
}

/// Resolves a bearer token to a bound attempt. Implementations must not treat
/// a session label as a credential. The trait does not receive a label.
pub trait FreedomVerifier: Send + Sync {
    fn authenticate(&self, token: &str) -> Result<(NativeAuthResult, BoundAttempt), VerifyFailure>;
}

impl<T> FreedomVerifier for Arc<T>
where
    T: FreedomVerifier + ?Sized,
{
    fn authenticate(&self, token: &str) -> Result<(NativeAuthResult, BoundAttempt), VerifyFailure> {
        (**self).authenticate(token)
    }
}

/// Accepts no token. Used when managed mode has no platform verifier wired.
#[derive(Debug, Default)]
pub struct ClosedVerifier;

impl FreedomVerifier for ClosedVerifier {
    fn authenticate(
        &self,
        _token: &str,
    ) -> Result<(NativeAuthResult, BoundAttempt), VerifyFailure> {
        Err(VerifyFailure::NoPlatformClient)
    }
}

/// In-process map from token to a binding. Not a network client.
#[derive(Debug, Default, Clone)]
pub struct InProcessVerifier {
    by_token: std::collections::BTreeMap<String, (NativeAuthResult, BoundAttempt)>,
}

impl InProcessVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &mut self,
        token: impl Into<String>,
        auth: NativeAuthResult,
        attempt: BoundAttempt,
    ) {
        self.by_token.insert(token.into(), (auth, attempt));
    }
}

impl FreedomVerifier for InProcessVerifier {
    fn authenticate(&self, token: &str) -> Result<(NativeAuthResult, BoundAttempt), VerifyFailure> {
        self.by_token
            .get(token)
            .cloned()
            .ok_or(VerifyFailure::UnknownToken)
    }
}

/// Private verified context. Construct with [`Self::try_new`] only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreedomRunContext {
    principal: String,
    scope: Scope,
    run_id: String,
    attempt_id: String,
    runtime_device_id: String,
    grant_ref: String,
    grant_revision: u64,
    control_epoch: u64,
    lease_epoch: u64,
    policy_revision: u64,
    recovery_generation: u64,
}

impl FreedomRunContext {
    /// Verifying constructor. Fails closed on a mismatched attempt, a stale
    /// epoch or revision, or a revoked grant.
    pub fn try_new(auth: &NativeAuthResult, attempt: &BoundAttempt) -> Result<Self, ContextError> {
        if blank(&auth.principal)
            || blank(&auth.attempt_id)
            || blank(&auth.run_id)
            || blank(&auth.runtime_device_id)
            || blank(&auth.grant_ref)
            || blank(&attempt.principal)
            || blank(&attempt.attempt_id)
            || blank(&attempt.current_attempt_id)
        {
            return Err(ContextError::Incomplete);
        }
        if auth.principal != attempt.principal {
            return Err(ContextError::PrincipalMismatch);
        }
        if auth.attempt_id != attempt.attempt_id || attempt.attempt_id != attempt.current_attempt_id
        {
            return Err(ContextError::AttemptMismatch);
        }
        if auth.run_id != attempt.run_id
            || auth.runtime_device_id != attempt.runtime_device_id
            || auth.grant_ref != attempt.grant_ref
        {
            return Err(ContextError::BindingMismatch);
        }
        if attempt.grant_revoked {
            return Err(ContextError::GrantRevoked);
        }
        if auth.control_epoch != attempt.control_epoch
            || attempt.control_epoch != attempt.current_control_epoch
        {
            return Err(ContextError::StaleControlEpoch);
        }
        if auth.lease_epoch != attempt.lease_epoch
            || attempt.lease_epoch != attempt.current_lease_epoch
        {
            return Err(ContextError::StaleLeaseEpoch);
        }
        if auth.grant_revision != attempt.grant_revision
            || attempt.grant_revision != attempt.current_grant_revision
        {
            return Err(ContextError::StaleGrantRevision);
        }
        if auth.policy_revision != attempt.policy_revision
            || attempt.policy_revision != attempt.current_policy_revision
        {
            return Err(ContextError::StalePolicyRevision);
        }
        if auth.recovery_generation != attempt.recovery_generation
            || attempt.recovery_generation != attempt.current_recovery_generation
        {
            return Err(ContextError::StaleRecoveryGeneration);
        }
        Ok(Self {
            principal: auth.principal.clone(),
            scope: attempt.scope.clone(),
            run_id: auth.run_id.clone(),
            attempt_id: auth.attempt_id.clone(),
            runtime_device_id: auth.runtime_device_id.clone(),
            grant_ref: auth.grant_ref.clone(),
            grant_revision: auth.grant_revision,
            control_epoch: auth.control_epoch,
            lease_epoch: auth.lease_epoch,
            policy_revision: auth.policy_revision,
            recovery_generation: auth.recovery_generation,
        })
    }

    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }

    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    #[must_use]
    pub fn runtime_device_id(&self) -> &str {
        &self.runtime_device_id
    }

    #[must_use]
    pub fn grant_ref(&self) -> &str {
        &self.grant_ref
    }

    #[must_use]
    pub fn grant_revision(&self) -> u64 {
        self.grant_revision
    }

    #[must_use]
    pub fn control_epoch(&self) -> u64 {
        self.control_epoch
    }

    #[must_use]
    pub fn lease_epoch(&self) -> u64 {
        self.lease_epoch
    }

    #[must_use]
    pub fn policy_revision(&self) -> u64 {
        self.policy_revision
    }

    #[must_use]
    pub fn recovery_generation(&self) -> u64 {
        self.recovery_generation
    }

    #[must_use]
    pub fn allows_page(&self, page: u32) -> bool {
        self.scope.contains_page(page)
    }

    #[must_use]
    pub fn allows_session(&self, session: &str) -> bool {
        self.scope.contains_session(session)
    }

    #[must_use]
    pub fn allows_aggregate(&self) -> bool {
        self.scope.allows_aggregate()
    }

    #[must_use]
    pub fn page_ids(&self) -> Vec<u32> {
        self.scope.page_ids().collect()
    }
}

fn blank(value: &str) -> bool {
    value.trim().is_empty()
}

#[cfg(test)]
mod tests {
    use super::{
        BoundAttempt, ContextError, FreedomRunContext, FreedomVerifier, InProcessVerifier, Scope,
    };

    fn pair() -> (super::NativeAuthResult, BoundAttempt) {
        BoundAttempt::matching_pair("alice", "attempt-1", Scope::pages([1]))
    }

    #[test]
    fn accepts_a_consistent_binding() {
        let (auth, attempt) = pair();
        let context = FreedomRunContext::try_new(&auth, &attempt).expect_err_free();
        assert_eq!(context.principal(), "alice");
        assert_eq!(context.attempt_id(), "attempt-1");
        assert_eq!(context.run_id(), "run-1");
        assert_eq!(context.runtime_device_id(), "device-1");
        assert_eq!(context.grant_ref(), "grant-1");
        assert_eq!(context.control_epoch(), 1);
        assert_eq!(context.lease_epoch(), 1);
        assert_eq!(context.policy_revision(), 1);
        assert_eq!(context.recovery_generation(), 1);
        assert!(context.allows_page(1));
        assert!(!context.allows_page(2));
    }

    fn expect_err_free_helper(
        result: Result<FreedomRunContext, ContextError>,
    ) -> FreedomRunContext {
        match result {
            Ok(context) => context,
            Err(error) => panic!("expected a context, got {}", error.code()),
        }
    }

    trait ExpectOk {
        fn expect_err_free(self) -> FreedomRunContext;
    }

    impl ExpectOk for Result<FreedomRunContext, ContextError> {
        fn expect_err_free(self) -> FreedomRunContext {
            expect_err_free_helper(self)
        }
    }

    fn assert_code(result: Result<FreedomRunContext, ContextError>, error: ContextError) {
        match result {
            Err(actual) => assert_eq!(actual, error, "{}", actual.code()),
            Ok(_) => panic!("expected {}", error.code()),
        }
    }

    #[test]
    fn rejects_incomplete_binding() {
        let (mut auth, attempt) = pair();
        auth.principal.clear();
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::Incomplete,
        );
    }

    #[test]
    fn rejects_principal_mismatch() {
        let (mut auth, attempt) = pair();
        auth.principal = "ted".to_string();
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::PrincipalMismatch,
        );
    }

    #[test]
    fn rejects_mismatched_attempt() {
        let (mut auth, attempt) = pair();
        auth.attempt_id = "attempt-old".to_string();
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::AttemptMismatch,
        );
        let (auth, mut attempt) = pair();
        attempt.current_attempt_id = "attempt-other".to_string();
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::AttemptMismatch,
        );
    }

    #[test]
    fn rejects_binding_mismatch() {
        let (mut auth, attempt) = pair();
        auth.run_id = "run-other".to_string();
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::BindingMismatch,
        );
        let (mut auth, attempt) = pair();
        auth.runtime_device_id = "device-other".to_string();
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::BindingMismatch,
        );
        let (mut auth, attempt) = pair();
        auth.grant_ref = "grant-other".to_string();
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::BindingMismatch,
        );
    }

    #[test]
    fn rejects_revoked_grant() {
        let (auth, mut attempt) = pair();
        attempt.grant_revoked = true;
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::GrantRevoked,
        );
    }

    #[test]
    fn rejects_stale_control_epoch() {
        let (auth, mut attempt) = pair();
        attempt.current_control_epoch = 2;
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::StaleControlEpoch,
        );
    }

    #[test]
    fn rejects_stale_lease_epoch() {
        let (mut auth, attempt) = pair();
        auth.lease_epoch = 9;
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::StaleLeaseEpoch,
        );
    }

    #[test]
    fn rejects_stale_grant_revision() {
        let (auth, mut attempt) = pair();
        attempt.current_grant_revision = 4;
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::StaleGrantRevision,
        );
    }

    #[test]
    fn rejects_stale_policy_revision() {
        let (auth, mut attempt) = pair();
        attempt.current_policy_revision = 3;
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::StalePolicyRevision,
        );
    }

    #[test]
    fn rejects_stale_recovery_generation() {
        let (auth, mut attempt) = pair();
        attempt.current_recovery_generation = 8;
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::StaleRecoveryGeneration,
        );
    }

    #[test]
    fn verified_constructor_rejects_every_invalid_input() {
        let (mut auth, attempt) = pair();
        auth.principal.clear();
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::Incomplete,
        );
        let (mut auth, attempt) = pair();
        auth.principal = "ted".to_string();
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::PrincipalMismatch,
        );
        let (mut auth, attempt) = pair();
        auth.attempt_id = "other".to_string();
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::AttemptMismatch,
        );
        let (auth, mut attempt) = pair();
        attempt.current_attempt_id = "other".to_string();
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::AttemptMismatch,
        );
        let (mut auth, attempt) = pair();
        auth.run_id = "other".to_string();
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::BindingMismatch,
        );
        let (mut auth, attempt) = pair();
        auth.runtime_device_id = "other".to_string();
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::BindingMismatch,
        );
        let (mut auth, attempt) = pair();
        auth.grant_ref = "other".to_string();
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::BindingMismatch,
        );
        let (auth, mut attempt) = pair();
        attempt.grant_revoked = true;
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::GrantRevoked,
        );
        let (auth, mut attempt) = pair();
        attempt.current_control_epoch = 2;
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::StaleControlEpoch,
        );
        let (mut auth, attempt) = pair();
        auth.lease_epoch = 9;
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::StaleLeaseEpoch,
        );
        let (auth, mut attempt) = pair();
        attempt.current_grant_revision = 4;
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::StaleGrantRevision,
        );
        let (auth, mut attempt) = pair();
        attempt.current_policy_revision = 3;
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::StalePolicyRevision,
        );
        let (auth, mut attempt) = pair();
        attempt.current_recovery_generation = 8;
        assert_code(
            FreedomRunContext::try_new(&auth, &attempt),
            ContextError::StaleRecoveryGeneration,
        );
        let mut verifier = InProcessVerifier::new();
        let (auth, attempt) = pair();
        verifier.insert("token-alice", auth, attempt);
        match FreedomVerifier::authenticate(&verifier, "") {
            Err(super::VerifyFailure::UnknownToken) => {}
            other => panic!("empty token must fail: {other:?}"),
        }
    }

    #[test]
    fn verifier_unknown_token_fails_and_label_is_not_part_of_the_trait() {
        let mut verifier = InProcessVerifier::new();
        let (auth, attempt) = pair();
        verifier.insert("token-alice", auth, attempt);
        let err = match FreedomVerifier::authenticate(&verifier, "Ted") {
            Ok(_) => panic!("a session label must not authenticate"),
            Err(error) => error,
        };
        assert_eq!(err, super::VerifyFailure::UnknownToken);
        let (auth, _) = match FreedomVerifier::authenticate(&verifier, "token-alice") {
            Ok(pair) => pair,
            Err(error) => panic!("known token should verify: {error:?}"),
        };
        assert_eq!(auth.principal, "alice");
    }
}
