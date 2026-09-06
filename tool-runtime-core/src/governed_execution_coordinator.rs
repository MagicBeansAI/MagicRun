//! Phase 6F authorization-before-auth execution coordinator.
//!
//! Only this module can turn dormant executable authority into a batch or PTY process.
//! Exact policy/approval/grant/resource admission is verified before the credential
//! resolver is called, and every terminal path is settled through a secret-free audit.

use std::{
    cell::Cell,
    collections::BTreeSet,
    error::Error,
    fmt,
    panic::{catch_unwind, AssertUnwindSafe},
    time::{Duration, Instant},
};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    credential_filesystem::CredentialScratchAuthority,
    credential_injection::{
        CredentialCallId, CredentialExecutionFailure, CredentialExecutionOutcome,
        CredentialInjectionPlan, CredentialInjectionReceipt, CredentialInjectionTargetKind,
    },
    credential_materialization::{
        materialize_governed_credential_io, ChildEnvironmentValues,
        CredentialFilesystemMaterialization, MaterializedCredentialIo,
    },
    credential_preparation::{
        with_prepared_credential_material_before, CredentialMaterialResolver,
        CredentialPreparationPlan,
    },
    credential_profiles::CredentialProfileStatus,
    governed_batch_process::{
        GovernedBatchCancellation, GovernedBatchExecutor, GovernedBatchProcess,
    },
    governed_execution::{
        GovernedExecutionDispatch, GovernedExecutionIntent, GovernedExecutionTerminal,
        GovernedExecutionTerminalState,
    },
    governed_execution_authority::{
        GovernedExecutableProvenance, GovernedExecutionAuthority, GovernedExpectedExecutableDigest,
        GovernedWorkingDirectoryRoot,
    },
    governed_execution_result::{
        GovernedArtifactAuthority, GovernedArtifactMetadata, GovernedExecutionResult,
        GovernedExecutionResultSealer,
    },
    governed_process_jail::{GovernedProcessJail, GovernedProcessJailAudit},
    governed_pty_process::{
        GovernedPtyBridge, GovernedPtyExecutor, GovernedPtyPolicy, GovernedPtyProcess,
        GovernedPtySize,
    },
    manifest::{ApprovalClass, DataSensitivity, PolicyFloor},
    manifest_validation::ValidatedSkillRuntimeContract,
    scoped_paths::ScopedPath,
};

pub const GOVERNED_EXECUTION_COORDINATOR_V1: &str =
    "tool-runtime.governed-execution-coordinator.v1";
pub const MAX_GOVERNED_AUTHORIZATION_IDENTIFIER_BYTES: usize = 128;
pub const MAX_GOVERNED_AUTHORIZATION_EVIDENCE_ITEMS: usize = 64;

thread_local! {
    static GOVERNED_EXECUTION_ACTIVE: Cell<bool> = const { Cell::new(false) };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedExecutionCoordinatorErrorCode {
    InvalidCallContext,
    ContractMismatch,
    UnsupportedCredentialTarget,
    AuthorizationDenied,
    ApprovalRequired,
    AuthorizationUnavailable,
    InvalidAuthorizationEvidence,
    Cancelled,
    TimedOut,
    ProfileAuthorityUnavailable,
    CredentialPreparationFailed,
    CredentialMaterializationFailed,
    ExecutionAuthorityFailed,
    ProcessFailed,
    ResultSealingFailed,
    AuditFailed,
    ReentrantExecution,
    InternalFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GovernedExecutionCoordinatorError {
    pub code: GovernedExecutionCoordinatorErrorCode,
    pub field: &'static str,
    pub message: &'static str,
    dispatch: GovernedExecutionDispatch,
}

impl GovernedExecutionCoordinatorError {
    const fn new(
        code: GovernedExecutionCoordinatorErrorCode,
        field: &'static str,
        message: &'static str,
        dispatch: GovernedExecutionDispatch,
    ) -> Self {
        Self {
            code,
            field,
            message,
            dispatch,
        }
    }

    pub fn dispatch(self) -> GovernedExecutionDispatch {
        self.dispatch
    }
}

impl fmt::Display for GovernedExecutionCoordinatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for GovernedExecutionCoordinatorError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GovernedExecutionCallContext {
    call_id: CredentialCallId,
    capability_id: String,
    action_id: String,
}

impl GovernedExecutionCallContext {
    pub fn new(
        call_id: CredentialCallId,
        capability_id: impl Into<String>,
        action_id: impl Into<String>,
    ) -> Result<Self, GovernedExecutionCoordinatorError> {
        let capability_id = capability_id.into();
        let action_id = action_id.into();
        if !valid_identifier(&capability_id) || !valid_identifier(&action_id) {
            return Err(invalid_call_context());
        }
        Ok(Self {
            call_id,
            capability_id,
            action_id,
        })
    }

    pub fn call_id(&self) -> &CredentialCallId {
        &self.call_id
    }

    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    pub fn action_id(&self) -> &str {
        &self.action_id
    }
}

/// Exact trusted authorization view. It deliberately has no Debug/Serialize/Clone
/// surface because argument tokens may carry private user content.
pub struct GovernedAuthorizationRequest<'a> {
    context: &'a GovernedExecutionCallContext,
    intent: &'a GovernedExecutionIntent,
    preparation: &'a CredentialPreparationPlan,
    policy_floor: PolicyFloor,
    request_digest: [u8; 32],
    contract_digest: [u8; 32],
    credential_plan_digest: [u8; 32],
    stdin_digest: Option<[u8; 32]>,
    deadline: Instant,
}

impl GovernedAuthorizationRequest<'_> {
    pub fn context(&self) -> &GovernedExecutionCallContext {
        self.context
    }

    pub fn arguments(&self) -> &[String] {
        self.intent.arguments()
    }

    pub fn working_directory(&self) -> &[String] {
        self.intent.working_directory()
    }

    pub fn has_stdin(&self) -> bool {
        self.intent.has_stdin()
    }

    pub fn stdin_digest(&self) -> Option<[u8; 32]> {
        self.stdin_digest
    }

    pub fn policy_floor(&self) -> &PolicyFloor {
        &self.policy_floor
    }

    pub fn selected_profile(&self) -> Option<&crate::credential_profiles::CredentialProfileKey> {
        self.preparation.selected_profile_key()
    }

    pub fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    pub fn contract_digest(&self) -> [u8; 32] {
        self.contract_digest
    }

    pub fn credential_plan_digest(&self) -> [u8; 32] {
        self.credential_plan_digest
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GovernedAuthorizationEvidence {
    request_digest: [u8; 32],
    policy_revision: String,
    approved_class: ApprovalClass,
    approval_receipt_id: Option<String>,
    granted_grants: BTreeSet<String>,
    granted_resource_scopes: BTreeSet<String>,
    granted_resource_authorities: BTreeSet<String>,
}

impl GovernedAuthorizationEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_digest: [u8; 32],
        policy_revision: impl Into<String>,
        approved_class: ApprovalClass,
        approval_receipt_id: Option<String>,
        granted_grants: BTreeSet<String>,
        granted_resource_scopes: BTreeSet<String>,
        granted_resource_authorities: BTreeSet<String>,
    ) -> Result<Self, GovernedExecutionCoordinatorError> {
        let policy_revision = policy_revision.into();
        if !valid_identifier(&policy_revision)
            || approval_receipt_id
                .as_ref()
                .is_some_and(|value| !valid_identifier(value))
            || !valid_evidence_set(&granted_grants)
            || !valid_evidence_set(&granted_resource_scopes)
            || !valid_evidence_set(&granted_resource_authorities)
        {
            return Err(invalid_authorization_evidence());
        }
        Ok(Self {
            request_digest,
            policy_revision,
            approved_class,
            approval_receipt_id,
            granted_grants,
            granted_resource_scopes,
            granted_resource_authorities,
        })
    }
}

pub enum GovernedAuthorizationDecision {
    Approved(GovernedAuthorizationEvidence),
    Denied,
    ApprovalRequired,
    Unavailable,
}

pub trait GovernedExecutionAuthorizer {
    /// Implementations must enforce their own I/O deadline using `request.deadline()`.
    /// The coordinator rejects a late return but cannot safely preempt arbitrary
    /// synchronous adapter code.
    fn authorize(
        &mut self,
        request: &GovernedAuthorizationRequest<'_>,
    ) -> GovernedAuthorizationDecision;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedExecutionAuditOutcome {
    AuthorizationDenied,
    ApprovalRequired,
    AuthorizationUnavailable,
    Cancelled,
    TimedOut,
    PreparationFailed,
    ExecutionFailed,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GovernedAuthorizationAudit {
    pub policy_revision: String,
    pub approved_class: ApprovalClass,
    pub approval_receipt_id: Option<String>,
    pub granted_grant_count: usize,
    pub granted_resource_scope_count: usize,
    pub granted_resource_authority_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GovernedExecutionAuditReceipt {
    pub schema_version: &'static str,
    pub context: GovernedExecutionCallContext,
    pub request_digest: [u8; 32],
    pub contract_digest: [u8; 32],
    pub credential_plan_digest: [u8; 32],
    pub authorization: Option<GovernedAuthorizationAudit>,
    pub outcome: GovernedExecutionAuditOutcome,
    pub terminal: GovernedExecutionTerminalState,
    pub credential: CredentialInjectionReceipt,
    pub executable: Option<GovernedExecutableProvenance>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jail: Option<GovernedProcessJailAudit>,
    pub artifacts: Option<GovernedArtifactMetadata>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GovernedExecutionAuditError {
    pub field: &'static str,
    pub message: &'static str,
}

impl GovernedExecutionAuditError {
    pub const fn unavailable() -> Self {
        Self {
            field: "audit",
            message: "the governed execution audit sink is unavailable",
        }
    }
}

pub trait GovernedExecutionAuditSink {
    /// The audit sink is a trusted settlement boundary and must provide its own bounded
    /// I/O behavior. It is invoked under the same-thread execution re-entry guard.
    fn record(
        &mut self,
        receipt: &GovernedExecutionAuditReceipt,
    ) -> Result<(), GovernedExecutionAuditError>;
}

/// Deferred references needed only if the admitted credential plan materializes files
/// or profile-owned paths. Ready-profile authority is created only after authorization.
pub struct GovernedCredentialFilesystemRequest<'a> {
    scratch: &'a CredentialScratchAuthority,
    ready_profile: Option<(&'a ScopedPath, &'a CredentialProfileStatus)>,
}

impl<'a> GovernedCredentialFilesystemRequest<'a> {
    pub fn new(
        scratch: &'a CredentialScratchAuthority,
        ready_profile: Option<(&'a ScopedPath, &'a CredentialProfileStatus)>,
    ) -> Self {
        Self {
            scratch,
            ready_profile,
        }
    }
}

pub struct GovernedExecutionInvocation<'a> {
    context: GovernedExecutionCallContext,
    validated: ValidatedSkillRuntimeContract<'a>,
    intent: GovernedExecutionIntent,
    preparation: &'a CredentialPreparationPlan,
    injection: &'a CredentialInjectionPlan,
    baseline_values: ChildEnvironmentValues,
    expected_executable_digest: Option<GovernedExpectedExecutableDigest>,
    working_directory_root: Option<GovernedWorkingDirectoryRoot>,
    artifact_authority: Option<GovernedArtifactAuthority>,
    credential_filesystem: Option<GovernedCredentialFilesystemRequest<'a>>,
}

impl<'a> GovernedExecutionInvocation<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: GovernedExecutionCallContext,
        validated: ValidatedSkillRuntimeContract<'a>,
        intent: GovernedExecutionIntent,
        preparation: &'a CredentialPreparationPlan,
        injection: &'a CredentialInjectionPlan,
        baseline_values: ChildEnvironmentValues,
        working_directory_root: Option<GovernedWorkingDirectoryRoot>,
        artifact_authority: Option<GovernedArtifactAuthority>,
        credential_filesystem: Option<GovernedCredentialFilesystemRequest<'a>>,
    ) -> Result<Self, GovernedExecutionCoordinatorError> {
        if !intent.matches_validated_contract(validated)
            || !preparation.matches_validated_contract(validated)
        {
            return Err(contract_mismatch());
        }
        if injection.injections().iter().any(|binding| {
            matches!(
                binding.target().kind(),
                CredentialInjectionTargetKind::ScopedFile
                    | CredentialInjectionTargetKind::ConfigDirectory
            )
        }) {
            if credential_filesystem.is_none() {
                return Err(unsupported_credential_target());
            }
        }
        let expected =
            CredentialInjectionPlan::compile(validated, preparation, injection.baseline().clone())
                .map_err(|_| contract_mismatch())?;
        if &expected != injection {
            return Err(contract_mismatch());
        }
        Ok(Self {
            context,
            validated,
            intent,
            preparation,
            injection,
            baseline_values,
            expected_executable_digest: None,
            working_directory_root,
            artifact_authority,
            credential_filesystem,
        })
    }

    /// Require exact install-reviewed executable bytes at the final governed
    /// resolution fence. This only narrows the fixed executable already named
    /// by the validated contract and never changes PATH or argv.
    pub fn with_expected_executable_digest(
        mut self,
        expected: GovernedExpectedExecutableDigest,
    ) -> Self {
        self.expected_executable_digest = Some(expected);
        self
    }

    pub fn execute_batch(
        self,
        authorizer: &mut dyn GovernedExecutionAuthorizer,
        resolver: &mut dyn CredentialMaterialResolver,
        audit: &mut dyn GovernedExecutionAuditSink,
        cancellation: &GovernedBatchCancellation,
    ) -> Result<GovernedExecutionSettlement, GovernedExecutionCoordinatorError> {
        execute(
            self,
            GovernedExecutorMode::Batch,
            authorizer,
            resolver,
            audit,
            cancellation,
        )
    }

    /// Execute the already-admitted governed batch in a fail-closed strict OS
    /// jail. The jail is move-only, owns the private workdir and cannot be
    /// replaced with caller argv or a raw sandbox profile.
    pub fn execute_batch_in_jail(
        self,
        jail: GovernedProcessJail,
        authorizer: &mut dyn GovernedExecutionAuthorizer,
        resolver: &mut dyn CredentialMaterialResolver,
        audit: &mut dyn GovernedExecutionAuditSink,
        cancellation: &GovernedBatchCancellation,
    ) -> Result<GovernedExecutionSettlement, GovernedExecutionCoordinatorError> {
        execute(
            self,
            GovernedExecutorMode::JailedBatch(Some(jail)),
            authorizer,
            resolver,
            audit,
            cancellation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute_pty(
        self,
        policy: GovernedPtyPolicy,
        initial_size: GovernedPtySize,
        bridge: &mut dyn GovernedPtyBridge,
        authorizer: &mut dyn GovernedExecutionAuthorizer,
        resolver: &mut dyn CredentialMaterialResolver,
        audit: &mut dyn GovernedExecutionAuditSink,
        cancellation: &GovernedBatchCancellation,
    ) -> Result<GovernedExecutionSettlement, GovernedExecutionCoordinatorError> {
        execute(
            self,
            GovernedExecutorMode::Pty {
                policy,
                initial_size,
                bridge,
            },
            authorizer,
            resolver,
            audit,
            cancellation,
        )
    }
}

pub struct GovernedExecutionSettlement {
    result: GovernedExecutionResult,
    audit: GovernedExecutionAuditReceipt,
}

impl GovernedExecutionSettlement {
    pub fn result(&self) -> &GovernedExecutionResult {
        &self.result
    }

    pub fn audit(&self) -> &GovernedExecutionAuditReceipt {
        &self.audit
    }

    pub fn into_parts(self) -> (GovernedExecutionResult, GovernedExecutionAuditReceipt) {
        (self.result, self.audit)
    }
}

enum GovernedExecutorMode<'a> {
    Batch,
    JailedBatch(Option<GovernedProcessJail>),
    Pty {
        policy: GovernedPtyPolicy,
        initial_size: GovernedPtySize,
        bridge: &'a mut dyn GovernedPtyBridge,
    },
}

impl GovernedExecutorMode<'_> {
    fn matches(&self, interaction: crate::manifest::CliInteraction) -> bool {
        matches!(
            (self, interaction),
            (Self::Batch, crate::manifest::CliInteraction::Batch)
                | (Self::JailedBatch(_), crate::manifest::CliInteraction::Batch)
                | (Self::Pty { .. }, crate::manifest::CliInteraction::Pty)
        )
    }

    fn wall_seconds_ceiling(&self) -> Option<u64> {
        match self {
            Self::JailedBatch(Some(jail)) => Some(jail.limits().wall_seconds),
            Self::Batch | Self::JailedBatch(None) | Self::Pty { .. } => None,
        }
    }

    fn jail_audit(&self) -> Option<GovernedProcessJailAudit> {
        match self {
            Self::JailedBatch(Some(jail)) => Some(jail.audit()),
            Self::Batch | Self::JailedBatch(None) | Self::Pty { .. } => None,
        }
    }
}

#[derive(Clone, Copy)]
struct AuthorizationAuditFields {
    request_digest: [u8; 32],
    contract_digest: [u8; 32],
    credential_plan_digest: [u8; 32],
}

impl From<&GovernedAuthorizationRequest<'_>> for AuthorizationAuditFields {
    fn from(request: &GovernedAuthorizationRequest<'_>) -> Self {
        Self {
            request_digest: request.request_digest,
            contract_digest: request.contract_digest,
            credential_plan_digest: request.credential_plan_digest,
        }
    }
}

struct ExecutionBundle {
    result: GovernedExecutionResult,
    provenance: GovernedExecutableProvenance,
}

#[derive(Debug)]
struct GovernedExecutionReentryGuard;

impl GovernedExecutionReentryGuard {
    fn enter() -> Result<Self, GovernedExecutionCoordinatorError> {
        GOVERNED_EXECUTION_ACTIVE.with(|active| {
            if active.replace(true) {
                Err(reentrant_execution())
            } else {
                Ok(Self)
            }
        })
    }
}

impl Drop for GovernedExecutionReentryGuard {
    fn drop(&mut self) {
        GOVERNED_EXECUTION_ACTIVE.with(|active| active.set(false));
    }
}

#[allow(clippy::too_many_arguments)]
fn execute(
    invocation: GovernedExecutionInvocation<'_>,
    mut mode: GovernedExecutorMode<'_>,
    authorizer: &mut dyn GovernedExecutionAuthorizer,
    resolver: &mut dyn CredentialMaterialResolver,
    audit: &mut dyn GovernedExecutionAuditSink,
    cancellation: &GovernedBatchCancellation,
) -> Result<GovernedExecutionSettlement, GovernedExecutionCoordinatorError> {
    let _reentry_guard = GovernedExecutionReentryGuard::enter()?;
    let jail_audit = mode.jail_audit();
    let invocation_wall_seconds = u64::from(invocation.intent.timeout_secs());
    let wall_seconds = mode
        .wall_seconds_ceiling()
        .map_or(invocation_wall_seconds, |ceiling| {
            invocation_wall_seconds.min(ceiling)
        });
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(wall_seconds))
        .ok_or_else(|| internal_failure(GovernedExecutionDispatch::NotDispatched))?;
    let request = build_authorization_request(&invocation, deadline)?;
    if cancellation.is_cancelled() {
        let receipt = failure_receipt(
            &invocation,
            &request,
            None,
            GovernedExecutionAuditOutcome::Cancelled,
            cancelled_terminal(GovernedExecutionDispatch::NotDispatched),
            CredentialExecutionOutcome::Cancelled,
            None,
        );
        record_audit(audit, &receipt, GovernedExecutionDispatch::NotDispatched)?;
        return Err(cancelled_before_dispatch());
    }
    if Instant::now() >= deadline {
        let receipt = failure_receipt(
            &invocation,
            &request,
            None,
            GovernedExecutionAuditOutcome::TimedOut,
            timed_out_terminal(GovernedExecutionDispatch::NotDispatched),
            CredentialExecutionOutcome::Failed {
                failure: CredentialExecutionFailure::ProcessTimedOut,
            },
            None,
        );
        record_audit(audit, &receipt, GovernedExecutionDispatch::NotDispatched)?;
        return Err(timed_out_before_dispatch());
    }
    if !mode.matches(invocation.intent.interaction()) {
        let receipt = failure_receipt(
            &invocation,
            &request,
            None,
            GovernedExecutionAuditOutcome::PreparationFailed,
            launch_rejected_terminal(),
            CredentialExecutionOutcome::Failed {
                failure: CredentialExecutionFailure::Internal,
            },
            None,
        );
        record_audit(audit, &receipt, GovernedExecutionDispatch::NotDispatched)?;
        return Err(contract_mismatch());
    }
    let decision = catch_unwind(AssertUnwindSafe(|| authorizer.authorize(&request)))
        .unwrap_or(GovernedAuthorizationDecision::Unavailable);
    if cancellation.is_cancelled() {
        let receipt = failure_receipt(
            &invocation,
            &request,
            None,
            GovernedExecutionAuditOutcome::Cancelled,
            cancelled_terminal(GovernedExecutionDispatch::NotDispatched),
            CredentialExecutionOutcome::Cancelled,
            None,
        );
        record_audit(audit, &receipt, GovernedExecutionDispatch::NotDispatched)?;
        return Err(cancelled_before_dispatch());
    }
    if Instant::now() >= deadline {
        let receipt = failure_receipt(
            &invocation,
            &request,
            None,
            GovernedExecutionAuditOutcome::TimedOut,
            timed_out_terminal(GovernedExecutionDispatch::NotDispatched),
            CredentialExecutionOutcome::Failed {
                failure: CredentialExecutionFailure::ProcessTimedOut,
            },
            None,
        );
        record_audit(audit, &receipt, GovernedExecutionDispatch::NotDispatched)?;
        return Err(timed_out_before_dispatch());
    }
    let evidence = match decision {
        GovernedAuthorizationDecision::Approved(evidence) => {
            if !authorization_matches(&request, &evidence) {
                let receipt = failure_receipt(
                    &invocation,
                    &request,
                    None,
                    GovernedExecutionAuditOutcome::AuthorizationDenied,
                    launch_rejected_terminal(),
                    CredentialExecutionOutcome::Failed {
                        failure: CredentialExecutionFailure::AuthorizationDenied,
                    },
                    None,
                );
                record_audit(audit, &receipt, GovernedExecutionDispatch::NotDispatched)?;
                return Err(invalid_authorization_evidence());
            }
            evidence
        },
        GovernedAuthorizationDecision::Denied => {
            return audit_authorization_failure(
                &invocation,
                &request,
                audit,
                GovernedExecutionAuditOutcome::AuthorizationDenied,
                authorization_denied(),
                CredentialExecutionFailure::AuthorizationDenied,
            );
        },
        GovernedAuthorizationDecision::ApprovalRequired => {
            return audit_authorization_failure(
                &invocation,
                &request,
                audit,
                GovernedExecutionAuditOutcome::ApprovalRequired,
                approval_required(),
                CredentialExecutionFailure::ApprovalDenied,
            );
        },
        GovernedAuthorizationDecision::Unavailable => {
            return audit_authorization_failure(
                &invocation,
                &request,
                audit,
                GovernedExecutionAuditOutcome::AuthorizationUnavailable,
                authorization_unavailable(),
                CredentialExecutionFailure::AuthorizationDenied,
            );
        },
    };
    let authorization_audit = authorization_audit(&evidence);
    drop(evidence);
    if cancellation.is_cancelled() {
        let receipt = failure_receipt(
            &invocation,
            &request,
            Some(authorization_audit),
            GovernedExecutionAuditOutcome::Cancelled,
            cancelled_terminal(GovernedExecutionDispatch::NotDispatched),
            CredentialExecutionOutcome::Cancelled,
            None,
        );
        record_audit(audit, &receipt, GovernedExecutionDispatch::NotDispatched)?;
        return Err(cancelled_before_dispatch());
    }
    if Instant::now() >= deadline {
        let receipt = failure_receipt(
            &invocation,
            &request,
            Some(authorization_audit),
            GovernedExecutionAuditOutcome::TimedOut,
            timed_out_terminal(GovernedExecutionDispatch::NotDispatched),
            CredentialExecutionOutcome::Failed {
                failure: CredentialExecutionFailure::ProcessTimedOut,
            },
            None,
        );
        record_audit(audit, &receipt, GovernedExecutionDispatch::NotDispatched)?;
        return Err(timed_out_before_dispatch());
    }

    // The authorization request borrows exact argument and path data. Preserve only
    // the non-secret digests needed by audit before consuming the move-only invocation.
    let authorization_fields = AuthorizationAuditFields::from(&request);
    drop(request);
    let GovernedExecutionInvocation {
        context,
        validated: _,
        intent,
        preparation,
        injection,
        baseline_values,
        expected_executable_digest,
        working_directory_root,
        artifact_authority,
        credential_filesystem,
    } = invocation;

    let profile_authority = credential_filesystem
        .as_ref()
        .and_then(|filesystem| filesystem.ready_profile)
        .map(|(path, status)| path.authorize_ready_profile(status))
        .transpose()
        .map_err(|_| profile_authority_unavailable());
    if cancellation.is_cancelled() || Instant::now() >= deadline {
        let (outcome, terminal, credential, error) = if cancellation.is_cancelled() {
            (
                GovernedExecutionAuditOutcome::Cancelled,
                cancelled_terminal(GovernedExecutionDispatch::NotDispatched),
                CredentialExecutionOutcome::Cancelled,
                cancelled_before_dispatch(),
            )
        } else {
            (
                GovernedExecutionAuditOutcome::TimedOut,
                timed_out_terminal(GovernedExecutionDispatch::NotDispatched),
                CredentialExecutionOutcome::Failed {
                    failure: CredentialExecutionFailure::ProcessTimedOut,
                },
                timed_out_before_dispatch(),
            )
        };
        let receipt = failure_receipt_from_parts(
            &context,
            injection,
            authorization_fields,
            Some(authorization_audit),
            outcome,
            terminal,
            credential,
            None,
        );
        record_audit(audit, &receipt, GovernedExecutionDispatch::NotDispatched)?;
        return Err(error);
    }
    let profile_authority = match profile_authority {
        Ok(authority) => authority,
        Err(error) => {
            let receipt = failure_receipt_from_parts(
                &context,
                injection,
                authorization_fields,
                Some(authorization_audit),
                GovernedExecutionAuditOutcome::PreparationFailed,
                launch_rejected_terminal(),
                CredentialExecutionOutcome::Failed {
                    failure: CredentialExecutionFailure::ScopedPathUnavailable,
                },
                None,
            );
            record_audit(audit, &receipt, GovernedExecutionDispatch::NotDispatched)?;
            return Err(error);
        },
    };

    let filesystem = credential_filesystem.as_ref().map(|filesystem| {
        CredentialFilesystemMaterialization::new(
            context.call_id(),
            filesystem.scratch,
            profile_authority.as_ref(),
        )
    });
    let dispatch_observed = Cell::new(GovernedExecutionDispatch::NotDispatched);
    let terminal_observed = Cell::new(None);
    let provenance_observed = Cell::new(None);
    let authority_values = baseline_values.duplicate_for_sealed_call();
    let preparation = catch_unwind(AssertUnwindSafe(|| {
        with_prepared_credential_material_before(preparation, resolver, deadline, |prepared| {
            materialize_governed_credential_io(
                injection,
                prepared,
                baseline_values,
                filesystem,
                |materialized| {
                    execute_materialized(
                        intent,
                        injection,
                        authority_values,
                        expected_executable_digest,
                        working_directory_root,
                        artifact_authority,
                        materialized,
                        &mut mode,
                        cancellation,
                        &dispatch_observed,
                        &terminal_observed,
                        &provenance_observed,
                        deadline,
                    )
                },
            )
        })
    }));

    let bundle = match preparation {
        Ok(Ok(Ok(Ok(bundle)))) => bundle,
        Ok(Ok(Ok(Err(error)))) => {
            return audit_execution_error(
                &context,
                injection,
                authorization_fields,
                authorization_audit,
                error,
                audit,
                terminal_observed.get(),
                provenance_observed.get(),
                jail_audit,
            );
        },
        Ok(Ok(Err(_))) => {
            let error = if dispatch_observed.get() == GovernedExecutionDispatch::NotDispatched
                && Instant::now() >= deadline
            {
                timed_out_before_dispatch()
            } else {
                credential_materialization_failed(dispatch_observed.get())
            };
            return audit_execution_error(
                &context,
                injection,
                authorization_fields,
                authorization_audit,
                error,
                audit,
                terminal_observed.get(),
                provenance_observed.get(),
                jail_audit,
            );
        },
        Ok(Err(_)) => {
            let error = if Instant::now() >= deadline {
                timed_out_before_dispatch()
            } else {
                credential_preparation_failed()
            };
            return audit_execution_error(
                &context,
                injection,
                authorization_fields,
                authorization_audit,
                error,
                audit,
                terminal_observed.get(),
                provenance_observed.get(),
                jail_audit,
            );
        },
        Err(_) => {
            let error = internal_failure(dispatch_observed.get());
            return audit_execution_error(
                &context,
                injection,
                authorization_fields,
                authorization_audit,
                error,
                audit,
                terminal_observed.get(),
                provenance_observed.get(),
                jail_audit,
            );
        },
    };

    let credential_outcome = credential_outcome_for_terminal(bundle.result.terminal());
    let receipt = GovernedExecutionAuditReceipt {
        schema_version: GOVERNED_EXECUTION_COORDINATOR_V1,
        context: context.clone(),
        request_digest: authorization_fields.request_digest,
        contract_digest: authorization_fields.contract_digest,
        credential_plan_digest: authorization_fields.credential_plan_digest,
        authorization: Some(authorization_audit),
        outcome: audit_outcome_for_terminal(bundle.result.terminal()),
        terminal: bundle.result.terminal(),
        credential: CredentialInjectionReceipt::new(
            context.call_id().clone(),
            injection,
            credential_outcome,
        ),
        executable: Some(bundle.provenance),
        jail: jail_audit,
        artifacts: Some(bundle.result.artifact_metadata()),
    };
    record_audit(audit, &receipt, bundle.result.terminal().dispatch())?;
    Ok(GovernedExecutionSettlement {
        result: bundle.result,
        audit: receipt,
    })
}

#[allow(clippy::too_many_arguments)]
fn execute_materialized(
    intent: GovernedExecutionIntent,
    injection: &CredentialInjectionPlan,
    authority_values: ChildEnvironmentValues,
    expected_executable_digest: Option<GovernedExpectedExecutableDigest>,
    working_directory_root: Option<GovernedWorkingDirectoryRoot>,
    artifact_authority: Option<GovernedArtifactAuthority>,
    materialized: &MaterializedCredentialIo<'_>,
    mode: &mut GovernedExecutorMode<'_>,
    cancellation: &GovernedBatchCancellation,
    dispatch_observed: &Cell<GovernedExecutionDispatch>,
    terminal_observed: &Cell<Option<GovernedExecutionTerminalState>>,
    provenance_observed: &Cell<Option<GovernedExecutableProvenance>>,
    deadline: Instant,
) -> Result<ExecutionBundle, GovernedExecutionCoordinatorError> {
    if cancellation.is_cancelled() {
        return Err(cancelled_before_dispatch());
    }
    if Instant::now() >= deadline {
        return Err(timed_out_before_dispatch());
    }
    let intent = intent
        .bind_materialized_stdin(materialized.stdin())
        .map_err(|_| contract_mismatch())?;
    let redactor = materialized
        .governed_redactor_with_additional_secret(
            (intent.stdin_sensitivity() == DataSensitivity::Secret)
                .then(|| intent.stdin())
                .flatten(),
        )
        .map_err(|_| result_sealing_failed(GovernedExecutionDispatch::NotDispatched))?;
    let authority = match expected_executable_digest {
        Some(expected) => GovernedExecutionAuthority::bind_expected_executable(
            intent,
            injection.baseline(),
            authority_values,
            working_directory_root,
            expected,
        ),
        None => GovernedExecutionAuthority::bind(
            intent,
            injection.baseline(),
            authority_values,
            working_directory_root,
        ),
    }
    .map_err(|_| execution_authority_failed())?;
    let provenance = authority.provenance();
    provenance_observed.set(Some(provenance));
    let parts = authority.into_parts();
    let environment = materialized
        .governed_environment()
        .map_err(|_| credential_materialization_failed(GovernedExecutionDispatch::NotDispatched))?;
    match mode {
        GovernedExecutorMode::Batch | GovernedExecutorMode::JailedBatch(_) => {
            let process = match mode {
                GovernedExecutorMode::JailedBatch(jail) => {
                    let jail = jail.take().ok_or_else(|| {
                        internal_failure(GovernedExecutionDispatch::NotDispatched)
                    })?;
                    GovernedBatchProcess::from_authorized_parts_in_jail(parts, environment, jail)
                },
                GovernedExecutorMode::Batch => {
                    GovernedBatchProcess::from_authorized_parts(parts, environment)
                },
                GovernedExecutorMode::Pty { .. } => unreachable!(),
            }
            .map_err(|error| process_failed(error.dispatch()))?;
            dispatch_observed.set(GovernedExecutionDispatch::UnknownAfterDispatch);
            let raw = GovernedBatchExecutor::execute_until(process, cancellation, deadline)
                .map_err(|error| {
                    dispatch_observed.set(error.dispatch());
                    process_failed(error.dispatch())
                })?;
            dispatch_observed.set(raw.terminal().dispatch());
            terminal_observed.set(Some(raw.terminal()));
            let result =
                GovernedExecutionResultSealer::seal_batch(raw, &redactor, artifact_authority)
                    .map_err(|error| result_sealing_failed(error.dispatch()))?;
            terminal_observed.set(Some(result.terminal()));
            Ok(ExecutionBundle { result, provenance })
        },
        GovernedExecutorMode::Pty {
            policy,
            initial_size,
            bridge,
        } => {
            let process_redactor = redactor
                .duplicate()
                .map_err(|_| result_sealing_failed(GovernedExecutionDispatch::NotDispatched))?;
            let process = GovernedPtyProcess::from_authorized_parts(
                parts,
                environment,
                process_redactor,
                *policy,
                *initial_size,
            )
            .map_err(|error| process_failed(error.dispatch()))?;
            dispatch_observed.set(GovernedExecutionDispatch::UnknownAfterDispatch);
            let raw =
                GovernedPtyExecutor::execute_until(process, cancellation, &mut **bridge, deadline)
                    .map_err(|error| {
                        dispatch_observed.set(error.dispatch());
                        process_failed(error.dispatch())
                    })?;
            dispatch_observed.set(raw.terminal().dispatch());
            terminal_observed.set(Some(raw.terminal()));
            let result =
                GovernedExecutionResultSealer::seal_pty(raw, &redactor, artifact_authority)
                    .map_err(|error| result_sealing_failed(error.dispatch()))?;
            terminal_observed.set(Some(result.terminal()));
            Ok(ExecutionBundle { result, provenance })
        },
    }
}

fn build_authorization_request<'request, 'contract>(
    invocation: &'request GovernedExecutionInvocation<'contract>,
    deadline: Instant,
) -> Result<GovernedAuthorizationRequest<'request>, GovernedExecutionCoordinatorError> {
    let contract_bytes =
        serde_json::to_vec(invocation.validated.contract()).map_err(|_| contract_mismatch())?;
    let credential_bytes =
        serde_json::to_vec(invocation.injection).map_err(|_| contract_mismatch())?;
    let contract_digest: [u8; 32] = Sha256::digest(&contract_bytes).into();
    let credential_plan_digest: [u8; 32] = Sha256::digest(&credential_bytes).into();
    let stdin_digest = invocation
        .intent
        .stdin()
        .map(|value| <[u8; 32]>::from(Sha256::digest(value)));
    let policy_floor = invocation.validated.contract().policy_floor.clone();
    let mut hasher = Sha256::new();
    hasher.update(b"tool-runtime-governed-authorization-v1\0");
    hash_bytes(
        &mut hasher,
        invocation.context.call_id().as_str().as_bytes(),
    );
    hash_bytes(&mut hasher, invocation.context.capability_id().as_bytes());
    hash_bytes(&mut hasher, invocation.context.action_id().as_bytes());
    hasher.update(contract_digest);
    hasher.update(credential_plan_digest);
    hash_bytes(&mut hasher, invocation.intent.executable().as_bytes());
    hash_strings(&mut hasher, invocation.intent.command_prefix());
    hash_strings(&mut hasher, invocation.intent.arguments());
    hash_strings(&mut hasher, invocation.intent.working_directory());
    hasher.update([match invocation.intent.interaction() {
        crate::manifest::CliInteraction::Batch => 0,
        crate::manifest::CliInteraction::Pty => 1,
    }]);
    hasher.update(invocation.intent.timeout_secs().to_be_bytes());
    hasher.update(invocation.intent.max_stdin_bytes().to_be_bytes());
    hasher.update(invocation.intent.max_stdout_bytes().to_be_bytes());
    hasher.update(invocation.intent.max_stderr_bytes().to_be_bytes());
    match invocation.intent.max_memory_bytes() {
        Some(bytes) => {
            hasher.update([1]);
            hasher.update(bytes.to_be_bytes());
        },
        None => {
            hasher.update([0]);
        },
    }
    match stdin_digest {
        Some(digest) => {
            hasher.update([1]);
            hasher.update(digest);
        },
        None => hasher.update([0]),
    }
    let request_digest = hasher.finalize().into();
    Ok(GovernedAuthorizationRequest {
        context: &invocation.context,
        intent: &invocation.intent,
        preparation: invocation.preparation,
        policy_floor,
        request_digest,
        contract_digest,
        credential_plan_digest,
        stdin_digest,
        deadline,
    })
}

fn authorization_matches(
    request: &GovernedAuthorizationRequest<'_>,
    evidence: &GovernedAuthorizationEvidence,
) -> bool {
    evidence.request_digest == request.request_digest
        && evidence.approved_class >= request.policy_floor.approval
        && (request.policy_floor.approval == ApprovalClass::Ordinary
            || evidence.approval_receipt_id.is_some())
        && request
            .policy_floor
            .required_grants
            .is_subset(&evidence.granted_grants)
        && request
            .policy_floor
            .resource_scopes
            .is_subset(&evidence.granted_resource_scopes)
        && request
            .policy_floor
            .required_resource_authorities
            .is_subset(&evidence.granted_resource_authorities)
}

fn authorization_audit(evidence: &GovernedAuthorizationEvidence) -> GovernedAuthorizationAudit {
    GovernedAuthorizationAudit {
        policy_revision: evidence.policy_revision.clone(),
        approved_class: evidence.approved_class,
        approval_receipt_id: evidence.approval_receipt_id.clone(),
        granted_grant_count: evidence.granted_grants.len(),
        granted_resource_scope_count: evidence.granted_resource_scopes.len(),
        granted_resource_authority_count: evidence.granted_resource_authorities.len(),
    }
}

#[allow(clippy::too_many_arguments)]
fn failure_receipt(
    invocation: &GovernedExecutionInvocation<'_>,
    request: &GovernedAuthorizationRequest<'_>,
    authorization: Option<GovernedAuthorizationAudit>,
    outcome: GovernedExecutionAuditOutcome,
    terminal: GovernedExecutionTerminalState,
    credential_outcome: CredentialExecutionOutcome,
    executable: Option<GovernedExecutableProvenance>,
) -> GovernedExecutionAuditReceipt {
    failure_receipt_from_parts(
        &invocation.context,
        invocation.injection,
        AuthorizationAuditFields::from(request),
        authorization,
        outcome,
        terminal,
        credential_outcome,
        executable,
    )
}

#[allow(clippy::too_many_arguments)]
fn failure_receipt_from_parts(
    context: &GovernedExecutionCallContext,
    injection: &CredentialInjectionPlan,
    authorization_fields: AuthorizationAuditFields,
    authorization: Option<GovernedAuthorizationAudit>,
    outcome: GovernedExecutionAuditOutcome,
    terminal: GovernedExecutionTerminalState,
    credential_outcome: CredentialExecutionOutcome,
    executable: Option<GovernedExecutableProvenance>,
) -> GovernedExecutionAuditReceipt {
    GovernedExecutionAuditReceipt {
        schema_version: GOVERNED_EXECUTION_COORDINATOR_V1,
        context: context.clone(),
        request_digest: authorization_fields.request_digest,
        contract_digest: authorization_fields.contract_digest,
        credential_plan_digest: authorization_fields.credential_plan_digest,
        authorization,
        outcome,
        terminal,
        credential: CredentialInjectionReceipt::new(
            context.call_id().clone(),
            injection,
            credential_outcome,
        ),
        executable,
        jail: None,
        artifacts: None,
    }
}

fn audit_authorization_failure<T>(
    invocation: &GovernedExecutionInvocation<'_>,
    request: &GovernedAuthorizationRequest<'_>,
    audit: &mut dyn GovernedExecutionAuditSink,
    outcome: GovernedExecutionAuditOutcome,
    error: GovernedExecutionCoordinatorError,
    credential_failure: CredentialExecutionFailure,
) -> Result<T, GovernedExecutionCoordinatorError> {
    let receipt = failure_receipt(
        invocation,
        request,
        None,
        outcome,
        launch_rejected_terminal(),
        CredentialExecutionOutcome::Failed {
            failure: credential_failure,
        },
        None,
    );
    record_audit(audit, &receipt, GovernedExecutionDispatch::NotDispatched)?;
    Err(error)
}

#[allow(clippy::too_many_arguments)]
fn audit_execution_error<T>(
    context: &GovernedExecutionCallContext,
    injection: &CredentialInjectionPlan,
    authorization_fields: AuthorizationAuditFields,
    authorization: GovernedAuthorizationAudit,
    error: GovernedExecutionCoordinatorError,
    audit: &mut dyn GovernedExecutionAuditSink,
    observed_terminal: Option<GovernedExecutionTerminalState>,
    executable: Option<GovernedExecutableProvenance>,
    jail: Option<GovernedProcessJailAudit>,
) -> Result<T, GovernedExecutionCoordinatorError> {
    let terminal = match error.code {
        GovernedExecutionCoordinatorErrorCode::Cancelled => cancelled_terminal(error.dispatch),
        GovernedExecutionCoordinatorErrorCode::TimedOut => timed_out_terminal(error.dispatch),
        _ => match observed_terminal {
            Some(terminal) if terminal.terminal() != GovernedExecutionTerminal::Success => terminal,
            Some(_) | None => runtime_failure_terminal(error.dispatch),
        },
    };
    let credential_outcome = credential_outcome_for_terminal(terminal);
    let receipt = GovernedExecutionAuditReceipt {
        schema_version: GOVERNED_EXECUTION_COORDINATOR_V1,
        context: context.clone(),
        request_digest: authorization_fields.request_digest,
        contract_digest: authorization_fields.contract_digest,
        credential_plan_digest: authorization_fields.credential_plan_digest,
        authorization: Some(authorization),
        outcome: if error.code == GovernedExecutionCoordinatorErrorCode::Cancelled {
            GovernedExecutionAuditOutcome::Cancelled
        } else if error.code == GovernedExecutionCoordinatorErrorCode::TimedOut {
            GovernedExecutionAuditOutcome::TimedOut
        } else if error.dispatch == GovernedExecutionDispatch::NotDispatched {
            GovernedExecutionAuditOutcome::PreparationFailed
        } else {
            GovernedExecutionAuditOutcome::ExecutionFailed
        },
        terminal,
        credential: CredentialInjectionReceipt::new(
            context.call_id().clone(),
            injection,
            credential_outcome,
        ),
        executable,
        jail,
        artifacts: None,
    };
    record_audit(audit, &receipt, error.dispatch)?;
    Err(error)
}

fn record_audit(
    audit: &mut dyn GovernedExecutionAuditSink,
    receipt: &GovernedExecutionAuditReceipt,
    dispatch: GovernedExecutionDispatch,
) -> Result<(), GovernedExecutionCoordinatorError> {
    match catch_unwind(AssertUnwindSafe(|| audit.record(receipt))) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) | Err(_) => Err(audit_failed(dispatch)),
    }
}

fn credential_outcome_for_terminal(
    terminal: GovernedExecutionTerminalState,
) -> CredentialExecutionOutcome {
    match terminal.terminal() {
        GovernedExecutionTerminal::Success => CredentialExecutionOutcome::Succeeded,
        GovernedExecutionTerminal::Cancelled => CredentialExecutionOutcome::Cancelled,
        GovernedExecutionTerminal::TimedOut => CredentialExecutionOutcome::Failed {
            failure: CredentialExecutionFailure::ProcessTimedOut,
        },
        GovernedExecutionTerminal::NonZeroExit => CredentialExecutionOutcome::Failed {
            failure: CredentialExecutionFailure::ProcessExitedNonZero,
        },
        GovernedExecutionTerminal::OutputLimitExceeded => CredentialExecutionOutcome::Failed {
            failure: CredentialExecutionFailure::OutputTruncated,
        },
        GovernedExecutionTerminal::MemoryLimitExceeded => CredentialExecutionOutcome::Failed {
            failure: CredentialExecutionFailure::ProcessMemoryExceeded,
        },
        GovernedExecutionTerminal::CpuLimitExceeded
        | GovernedExecutionTerminal::ProcessLimitExceeded
        | GovernedExecutionTerminal::FileLimitExceeded => CredentialExecutionOutcome::Failed {
            failure: CredentialExecutionFailure::Internal,
        },
        GovernedExecutionTerminal::ArtifactRejected => CredentialExecutionOutcome::Failed {
            failure: CredentialExecutionFailure::OutputMalformed,
        },
        GovernedExecutionTerminal::LaunchRejected | GovernedExecutionTerminal::RuntimeFailure => {
            CredentialExecutionOutcome::Failed {
                failure: CredentialExecutionFailure::Internal,
            }
        },
    }
}

fn audit_outcome_for_terminal(
    terminal: GovernedExecutionTerminalState,
) -> GovernedExecutionAuditOutcome {
    match terminal.terminal() {
        GovernedExecutionTerminal::Success => GovernedExecutionAuditOutcome::Completed,
        GovernedExecutionTerminal::Cancelled => GovernedExecutionAuditOutcome::Cancelled,
        GovernedExecutionTerminal::TimedOut => GovernedExecutionAuditOutcome::TimedOut,
        GovernedExecutionTerminal::NonZeroExit
        | GovernedExecutionTerminal::OutputLimitExceeded
        | GovernedExecutionTerminal::MemoryLimitExceeded
        | GovernedExecutionTerminal::CpuLimitExceeded
        | GovernedExecutionTerminal::ProcessLimitExceeded
        | GovernedExecutionTerminal::FileLimitExceeded
        | GovernedExecutionTerminal::ArtifactRejected
        | GovernedExecutionTerminal::LaunchRejected
        | GovernedExecutionTerminal::RuntimeFailure => {
            GovernedExecutionAuditOutcome::ExecutionFailed
        },
    }
}

fn launch_rejected_terminal() -> GovernedExecutionTerminalState {
    GovernedExecutionTerminalState::launch_rejected()
}

fn cancelled_terminal(dispatch: GovernedExecutionDispatch) -> GovernedExecutionTerminalState {
    GovernedExecutionTerminalState::cancelled(dispatch)
}

fn timed_out_terminal(dispatch: GovernedExecutionDispatch) -> GovernedExecutionTerminalState {
    GovernedExecutionTerminalState::timed_out(dispatch)
}

fn runtime_failure_terminal(dispatch: GovernedExecutionDispatch) -> GovernedExecutionTerminalState {
    GovernedExecutionTerminalState::runtime_failure(dispatch)
}

fn hash_strings(hasher: &mut Sha256, values: &[String]) {
    hasher.update((values.len() as u64).to_be_bytes());
    for value in values {
        hash_bytes(hasher, value.as_bytes());
    }
}

fn hash_bytes(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn valid_evidence_set(values: &BTreeSet<String>) -> bool {
    values.len() <= MAX_GOVERNED_AUTHORIZATION_EVIDENCE_ITEMS
        && values.iter().all(|value| valid_identifier(value))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_GOVERNED_AUTHORIZATION_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/')
        })
}

const fn invalid_call_context() -> GovernedExecutionCoordinatorError {
    GovernedExecutionCoordinatorError::new(
        GovernedExecutionCoordinatorErrorCode::InvalidCallContext,
        "call_context",
        "the governed execution call context contains an invalid identifier",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn contract_mismatch() -> GovernedExecutionCoordinatorError {
    GovernedExecutionCoordinatorError::new(
        GovernedExecutionCoordinatorErrorCode::ContractMismatch,
        "runtime_contract",
        "the execution, credential, and validated runtime contracts do not match exactly",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn unsupported_credential_target() -> GovernedExecutionCoordinatorError {
    GovernedExecutionCoordinatorError::new(
        GovernedExecutionCoordinatorErrorCode::UnsupportedCredentialTarget,
        "credential_plan",
        "the direct CLI runtime has no declared placement for a filesystem credential target",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn authorization_denied() -> GovernedExecutionCoordinatorError {
    GovernedExecutionCoordinatorError::new(
        GovernedExecutionCoordinatorErrorCode::AuthorizationDenied,
        "authorization",
        "the exact governed invocation was denied by local policy",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn approval_required() -> GovernedExecutionCoordinatorError {
    GovernedExecutionCoordinatorError::new(
        GovernedExecutionCoordinatorErrorCode::ApprovalRequired,
        "approval",
        "the exact governed invocation requires explicit approval",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn authorization_unavailable() -> GovernedExecutionCoordinatorError {
    GovernedExecutionCoordinatorError::new(
        GovernedExecutionCoordinatorErrorCode::AuthorizationUnavailable,
        "authorization",
        "the governed authorization service is unavailable",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn invalid_authorization_evidence() -> GovernedExecutionCoordinatorError {
    GovernedExecutionCoordinatorError::new(
        GovernedExecutionCoordinatorErrorCode::InvalidAuthorizationEvidence,
        "authorization",
        "authorization evidence does not bind the exact request and required policy floor",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn cancelled_before_dispatch() -> GovernedExecutionCoordinatorError {
    GovernedExecutionCoordinatorError::new(
        GovernedExecutionCoordinatorErrorCode::Cancelled,
        "cancellation",
        "the governed invocation was cancelled before dispatch",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn timed_out_before_dispatch() -> GovernedExecutionCoordinatorError {
    GovernedExecutionCoordinatorError::new(
        GovernedExecutionCoordinatorErrorCode::TimedOut,
        "deadline",
        "the total governed invocation deadline expired before process dispatch",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn profile_authority_unavailable() -> GovernedExecutionCoordinatorError {
    GovernedExecutionCoordinatorError::new(
        GovernedExecutionCoordinatorErrorCode::ProfileAuthorityUnavailable,
        "profile_authority",
        "the selected ready profile could not issue exact filesystem authority",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn credential_preparation_failed() -> GovernedExecutionCoordinatorError {
    GovernedExecutionCoordinatorError::new(
        GovernedExecutionCoordinatorErrorCode::CredentialPreparationFailed,
        "credential_preparation",
        "authorized credential material could not be prepared",
        GovernedExecutionDispatch::NotDispatched,
    )
}

fn credential_materialization_failed(
    dispatch: GovernedExecutionDispatch,
) -> GovernedExecutionCoordinatorError {
    GovernedExecutionCoordinatorError::new(
        GovernedExecutionCoordinatorErrorCode::CredentialMaterializationFailed,
        "credential_materialization",
        "authorized credential material could not be materialized or cleaned up",
        dispatch,
    )
}

const fn execution_authority_failed() -> GovernedExecutionCoordinatorError {
    GovernedExecutionCoordinatorError::new(
        GovernedExecutionCoordinatorErrorCode::ExecutionAuthorityFailed,
        "execution_authority",
        "exact executable or working-directory authority could not be bound",
        GovernedExecutionDispatch::NotDispatched,
    )
}

fn process_failed(dispatch: GovernedExecutionDispatch) -> GovernedExecutionCoordinatorError {
    GovernedExecutionCoordinatorError::new(
        GovernedExecutionCoordinatorErrorCode::ProcessFailed,
        "process",
        "the governed process owner failed",
        dispatch,
    )
}

fn result_sealing_failed(dispatch: GovernedExecutionDispatch) -> GovernedExecutionCoordinatorError {
    GovernedExecutionCoordinatorError::new(
        GovernedExecutionCoordinatorErrorCode::ResultSealingFailed,
        "execution_result",
        "the governed result could not be safely sealed",
        dispatch,
    )
}

fn audit_failed(dispatch: GovernedExecutionDispatch) -> GovernedExecutionCoordinatorError {
    GovernedExecutionCoordinatorError::new(
        GovernedExecutionCoordinatorErrorCode::AuditFailed,
        "audit",
        "the governed execution audit receipt could not be committed",
        dispatch,
    )
}

const fn reentrant_execution() -> GovernedExecutionCoordinatorError {
    GovernedExecutionCoordinatorError::new(
        GovernedExecutionCoordinatorErrorCode::ReentrantExecution,
        "execution",
        "a governed execution callback attempted same-thread recursive execution",
        GovernedExecutionDispatch::NotDispatched,
    )
}

fn internal_failure(dispatch: GovernedExecutionDispatch) -> GovernedExecutionCoordinatorError {
    GovernedExecutionCoordinatorError::new(
        GovernedExecutionCoordinatorErrorCode::InternalFailure,
        "execution",
        "the governed execution boundary failed internally",
        dispatch,
    )
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        fmt, fs,
        path::PathBuf,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    #[cfg(unix)]
    use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt};

    use serde::Serialize;
    use static_assertions::assert_not_impl_any;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        credential_injection::{ChildEnvironmentBaseline, ChildEnvironmentVariable},
        credential_preparation::{
            CredentialMaterialBindingName, CredentialMaterialKind, CredentialMaterialSink,
            CredentialPreparationBinding, CredentialPreparationError,
        },
        credential_profiles::{
            CredentialProfileBinding, CredentialProfileRegistrySnapshot, CredentialScope,
        },
        governed_execution::{
            GovernedExecutionContract, GovernedExecutionPolicy, GovernedExecutionRequest,
        },
        manifest::{
            AuthContract, AuthKind, AuthRequirement, CliInteraction, DataSensitivity,
            InjectionBinding, InjectionSource, InjectionTarget, PolicyFloor, ProfileSelection,
            RuntimeLimits, RuntimeProtocol, RuntimeRequirements, SecretBindingRef,
            SkillRuntimeContract, SkillRuntimeContractVersion, StdinContract, StdinMode,
            WorkingDirectoryContract, WorkingDirectoryMode,
        },
        manifest_validation::validate_skill_runtime_contract,
        profile_selection::{
            select_credential_profile_from_snapshot, CredentialProfileSelectionRequest,
        },
    };

    struct Fixture {
        _root: TempDir,
        bin: PathBuf,
        workspace: PathBuf,
        contract: SkillRuntimeContract,
        preparation: CredentialPreparationPlan,
        injection: CredentialInjectionPlan,
    }

    impl Fixture {
        fn none() -> Self {
            let root = tempfile::tempdir().unwrap();
            let bin = root.path().join("bin");
            let workspace = root.path().join("workspace");
            fs::create_dir(&bin).unwrap();
            fs::create_dir(&workspace).unwrap();
            let executable = bin.join("fixture-cli");
            fs::write(&executable, b"#!/bin/sh\nprintf 'ok'").unwrap();
            #[cfg(unix)]
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
            let contract = SkillRuntimeContract {
                schema_version: SkillRuntimeContractVersion::v1(),
                requires: RuntimeRequirements {
                    bins: BTreeSet::from(["fixture-cli".to_owned()]),
                    entrypoint: Default::default(),
                    environment: Default::default(),
                },
                runtime: RuntimeProtocol::Cli {
                    command_prefix: vec![],
                    interaction: CliInteraction::Batch,
                    stdin: StdinContract {
                        mode: StdinMode::Optional,
                        sensitivity: DataSensitivity::Public,
                    },
                    working_directory: WorkingDirectoryContract {
                        mode: WorkingDirectoryMode::Workspace,
                    },
                    limits: RuntimeLimits {
                        timeout_secs: Some(3),
                        stdin_bytes: Some(1024),
                        stdout_bytes: Some(4096),
                        stderr_bytes: Some(4096),
                        memory_bytes: None,
                    },
                },
                auth: AuthContract::default(),
                policy_floor: PolicyFloor::default(),
            };
            let validated = validate_skill_runtime_contract(&contract).unwrap();
            let scope = CredentialScope::new("owner", "default").unwrap();
            let selection = select_credential_profile_from_snapshot(
                &CredentialProfileSelectionRequest::new(
                    scope.clone(),
                    None,
                    CredentialProfileBinding::Provider,
                    &ProfileSelection::None,
                    None,
                )
                .unwrap(),
                &CredentialProfileRegistrySnapshot::new(scope, Vec::new()).unwrap(),
            )
            .unwrap();
            let preparation = CredentialPreparationPlan::new(
                selection.scope().clone(),
                AuthKind::None,
                &selection,
                vec![],
            )
            .unwrap();
            let baseline = ChildEnvironmentBaseline::portable_cli();
            let injection =
                CredentialInjectionPlan::compile(validated, &preparation, baseline).unwrap();
            Self {
                _root: root,
                bin,
                workspace,
                contract,
                preparation,
                injection,
            }
        }

        fn invocation(&self) -> GovernedExecutionInvocation<'_> {
            self.invocation_with(vec![], None, "call-1")
        }

        fn invocation_with(
            &self,
            arguments: Vec<String>,
            working_directory: Option<String>,
            call_id: &str,
        ) -> GovernedExecutionInvocation<'_> {
            self.invocation_with_request(arguments, None, working_directory, call_id)
        }

        fn invocation_with_request(
            &self,
            arguments: Vec<String>,
            stdin: Option<Vec<u8>>,
            working_directory: Option<String>,
            call_id: &str,
        ) -> GovernedExecutionInvocation<'_> {
            self.invocation_with_policy(arguments, stdin, working_directory, call_id, 1024)
        }

        fn invocation_with_policy(
            &self,
            arguments: Vec<String>,
            stdin: Option<Vec<u8>>,
            working_directory: Option<String>,
            call_id: &str,
            max_stdin_bytes: u64,
        ) -> GovernedExecutionInvocation<'_> {
            let validated = validate_skill_runtime_contract(&self.contract).unwrap();
            let contract = GovernedExecutionContract::compile(
                validated,
                GovernedExecutionPolicy::new(3, 3, max_stdin_bytes, 4096, 4096).unwrap(),
            )
            .unwrap();
            let intent = contract
                .admit(GovernedExecutionRequest::new(
                    arguments,
                    stdin,
                    working_directory,
                    Some(3),
                ))
                .unwrap();
            let mut values = ChildEnvironmentValues::new(self.injection.baseline());
            values
                .provide(
                    ChildEnvironmentVariable::Path,
                    self.bin.as_os_str().as_bytes().to_vec(),
                )
                .unwrap();
            values
                .provide(ChildEnvironmentVariable::Lang, b"C.UTF-8".to_vec())
                .unwrap();
            GovernedExecutionInvocation::new(
                GovernedExecutionCallContext::new(
                    CredentialCallId::new(call_id).unwrap(),
                    "fixture",
                    "run",
                )
                .unwrap(),
                validated,
                intent,
                &self.preparation,
                &self.injection,
                values,
                Some(
                    GovernedWorkingDirectoryRoot::open(
                        WorkingDirectoryMode::Workspace,
                        &self.workspace,
                    )
                    .unwrap(),
                ),
                None,
                None,
            )
            .unwrap()
        }
    }

    struct CountingResolver {
        calls: Arc<AtomicUsize>,
    }

    impl CredentialMaterialResolver for CountingResolver {
        fn resolve_once(
            &mut self,
            _plan: &CredentialPreparationPlan,
            _sink: &mut CredentialMaterialSink<'_>,
        ) -> Result<(), CredentialPreparationError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct SecretResolver {
        binding: CredentialMaterialBindingName,
        value: Vec<u8>,
        calls: Arc<AtomicUsize>,
    }

    impl CredentialMaterialResolver for SecretResolver {
        fn resolve_once(
            &mut self,
            _plan: &CredentialPreparationPlan,
            sink: &mut CredentialMaterialSink<'_>,
        ) -> Result<(), CredentialPreparationError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            sink.provide(&self.binding, self.value.clone())
        }
    }

    struct PanicResolver;

    impl CredentialMaterialResolver for PanicResolver {
        fn resolve_once(
            &mut self,
            _plan: &CredentialPreparationPlan,
            _sink: &mut CredentialMaterialSink<'_>,
        ) -> Result<(), CredentialPreparationError> {
            panic!("resolver failure")
        }
    }

    fn secret_contract(targets: Vec<InjectionTarget>) -> SkillRuntimeContract {
        let mut contract = Fixture::none().contract;
        contract.runtime = RuntimeProtocol::Cli {
            command_prefix: vec![],
            interaction: CliInteraction::Batch,
            stdin: StdinContract {
                mode: StdinMode::Denied,
                sensitivity: Default::default(),
            },
            working_directory: WorkingDirectoryContract {
                mode: WorkingDirectoryMode::Workspace,
            },
            limits: RuntimeLimits {
                timeout_secs: Some(3),
                stdin_bytes: None,
                stdout_bytes: Some(4096),
                stderr_bytes: Some(4096),
                memory_bytes: None,
            },
        };
        contract.auth = AuthContract {
            kind: AuthKind::Secrets,
            requirement: AuthRequirement::Required,
            secret_bindings: vec![SecretBindingRef {
                name: "token".to_owned(),
                secret_ref: "VAULT_TEST_TOKEN".to_owned(),
            }],
            injections: targets
                .into_iter()
                .map(|target| InjectionBinding {
                    source: InjectionSource::Secret {
                        binding: "token".to_owned(),
                    },
                    target,
                })
                .collect(),
            ..AuthContract::default()
        };
        contract
    }

    fn secret_preparation(scope: &CredentialScope) -> CredentialPreparationPlan {
        let selection = select_credential_profile_from_snapshot(
            &CredentialProfileSelectionRequest::new(
                scope.clone(),
                None,
                CredentialProfileBinding::Provider,
                &ProfileSelection::None,
                None,
            )
            .unwrap(),
            &CredentialProfileRegistrySnapshot::new(scope.clone(), Vec::new()).unwrap(),
        )
        .unwrap();
        CredentialPreparationPlan::new(
            scope.clone(),
            AuthKind::Secrets,
            &selection,
            vec![CredentialPreparationBinding::new(
                CredentialMaterialBindingName::new("token").unwrap(),
                CredentialMaterialKind::SecretBinding,
                1024,
            )
            .unwrap()],
        )
        .unwrap()
    }

    struct DecisionAuthorizer {
        decision: Option<GovernedAuthorizationDecision>,
    }

    impl GovernedExecutionAuthorizer for DecisionAuthorizer {
        fn authorize(
            &mut self,
            request: &GovernedAuthorizationRequest<'_>,
        ) -> GovernedAuthorizationDecision {
            self.decision.take().unwrap_or_else(|| {
                GovernedAuthorizationDecision::Approved(
                    GovernedAuthorizationEvidence::new(
                        request.request_digest(),
                        "policy-1",
                        ApprovalClass::Ordinary,
                        None,
                        BTreeSet::new(),
                        BTreeSet::new(),
                        BTreeSet::new(),
                    )
                    .unwrap(),
                )
            })
        }
    }

    struct InsufficientAuthorizer;

    impl GovernedExecutionAuthorizer for InsufficientAuthorizer {
        fn authorize(
            &mut self,
            request: &GovernedAuthorizationRequest<'_>,
        ) -> GovernedAuthorizationDecision {
            GovernedAuthorizationDecision::Approved(
                GovernedAuthorizationEvidence::new(
                    request.request_digest(),
                    "policy-1",
                    ApprovalClass::Ordinary,
                    None,
                    BTreeSet::new(),
                    BTreeSet::new(),
                    BTreeSet::new(),
                )
                .unwrap(),
            )
        }
    }

    struct PanicAuthorizer;

    impl GovernedExecutionAuthorizer for PanicAuthorizer {
        fn authorize(
            &mut self,
            _request: &GovernedAuthorizationRequest<'_>,
        ) -> GovernedAuthorizationDecision {
            panic!("authorizer failure")
        }
    }

    struct ReentrantAuthorizer {
        nested_error: Option<GovernedExecutionCoordinatorErrorCode>,
    }

    impl GovernedExecutionAuthorizer for ReentrantAuthorizer {
        fn authorize(
            &mut self,
            request: &GovernedAuthorizationRequest<'_>,
        ) -> GovernedAuthorizationDecision {
            let nested_fixture = Fixture::none();
            let mut nested_authorizer = DecisionAuthorizer { decision: None };
            let mut nested_resolver = CountingResolver {
                calls: Arc::new(AtomicUsize::new(0)),
            };
            let mut nested_audit = Audit::default();
            self.nested_error = nested_fixture
                .invocation()
                .execute_batch(
                    &mut nested_authorizer,
                    &mut nested_resolver,
                    &mut nested_audit,
                    &GovernedBatchCancellation::new(),
                )
                .err()
                .map(|error| error.code);
            GovernedAuthorizationDecision::Approved(
                GovernedAuthorizationEvidence::new(
                    request.request_digest(),
                    "policy-1",
                    ApprovalClass::Ordinary,
                    None,
                    BTreeSet::new(),
                    BTreeSet::new(),
                    BTreeSet::new(),
                )
                .unwrap(),
            )
        }
    }

    struct CountingAuthorizer {
        calls: Arc<AtomicUsize>,
    }

    struct NoopBridge;

    impl GovernedPtyBridge for NoopBridge {
        fn on_output(
            &mut self,
            _output: crate::governed_pty_process::GovernedPtyOutputEvent,
        ) -> Result<
            crate::governed_pty_process::GovernedPtyAction,
            crate::governed_pty_process::GovernedPtyError,
        > {
            Ok(crate::governed_pty_process::GovernedPtyAction::Continue)
        }
    }

    impl GovernedExecutionAuthorizer for CountingAuthorizer {
        fn authorize(
            &mut self,
            _request: &GovernedAuthorizationRequest<'_>,
        ) -> GovernedAuthorizationDecision {
            self.calls.fetch_add(1, Ordering::SeqCst);
            GovernedAuthorizationDecision::Denied
        }
    }

    #[derive(Default)]
    struct Audit {
        receipts: Vec<GovernedExecutionAuditReceipt>,
    }

    impl GovernedExecutionAuditSink for Audit {
        fn record(
            &mut self,
            receipt: &GovernedExecutionAuditReceipt,
        ) -> Result<(), GovernedExecutionAuditError> {
            self.receipts.push(receipt.clone());
            Ok(())
        }
    }

    struct FailingAudit;

    impl GovernedExecutionAuditSink for FailingAudit {
        fn record(
            &mut self,
            _receipt: &GovernedExecutionAuditReceipt,
        ) -> Result<(), GovernedExecutionAuditError> {
            Err(GovernedExecutionAuditError::unavailable())
        }
    }

    #[test]
    fn authorization_denial_is_audited_before_the_resolver_can_run() {
        let fixture = Fixture::none();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut resolver = CountingResolver {
            calls: Arc::clone(&calls),
        };
        let mut authorizer = DecisionAuthorizer {
            decision: Some(GovernedAuthorizationDecision::Denied),
        };
        let mut audit = Audit::default();
        let error = fixture
            .invocation()
            .execute_batch(
                &mut authorizer,
                &mut resolver,
                &mut audit,
                &GovernedBatchCancellation::new(),
            )
            .err()
            .unwrap();
        assert_eq!(
            error.code,
            GovernedExecutionCoordinatorErrorCode::AuthorizationDenied
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(audit.receipts.len(), 1);
        assert_eq!(
            audit.receipts[0].terminal.dispatch(),
            GovernedExecutionDispatch::NotDispatched
        );
    }

    #[test]
    fn authorization_digest_binds_call_arguments_and_requested_working_directory() {
        let fixture = Fixture::none();
        let baseline = fixture.invocation();
        let argument_change = fixture.invocation_with(
            vec!["two words".to_owned(), "हैलो".to_owned()],
            None,
            "call-1",
        );
        let cwd_change = fixture.invocation_with(vec![], Some("reports".to_owned()), "call-1");
        let call_change = fixture.invocation_with(vec![], None, "call-2");
        let stdin_limit_change = fixture.invocation_with_policy(vec![], None, None, "call-1", 512);
        let deadline = Instant::now() + Duration::from_secs(30);
        let baseline_digest = build_authorization_request(&baseline, deadline)
            .unwrap()
            .request_digest();
        assert_ne!(
            baseline_digest,
            build_authorization_request(&argument_change, deadline)
                .unwrap()
                .request_digest()
        );
        assert_ne!(
            baseline_digest,
            build_authorization_request(&cwd_change, deadline)
                .unwrap()
                .request_digest()
        );
        assert_ne!(
            baseline_digest,
            build_authorization_request(&call_change, deadline)
                .unwrap()
                .request_digest()
        );
        assert_ne!(
            baseline_digest,
            build_authorization_request(&stdin_limit_change, deadline)
                .unwrap()
                .request_digest()
        );
    }

    #[test]
    fn secret_model_stdin_is_redacted_even_without_credential_injection() {
        let mut fixture = Fixture::none();
        fs::write(fixture.bin.join("fixture-cli"), b"#!/bin/sh\n/bin/cat\n").unwrap();
        let RuntimeProtocol::Cli { stdin, .. } = &mut fixture.contract.runtime else {
            unreachable!();
        };
        stdin.mode = StdinMode::Required;
        stdin.sensitivity = DataSensitivity::Secret;
        let secret = b"model-owned-private-stdin".to_vec();
        let mut resolver = CountingResolver {
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let mut authorizer = DecisionAuthorizer { decision: None };
        let mut audit = Audit::default();
        let settlement = fixture
            .invocation_with_request(vec![], Some(secret.clone()), None, "secret-stdin")
            .execute_batch(
                &mut authorizer,
                &mut resolver,
                &mut audit,
                &GovernedBatchCancellation::new(),
            )
            .unwrap();
        assert!(!settlement
            .result()
            .stdout()
            .windows(secret.len())
            .any(|window| window == secret.as_slice()));
        assert_eq!(settlement.result().stdout().len(), secret.len());
    }

    #[test]
    fn approved_batch_resolves_once_executes_and_commits_one_safe_audit() {
        let fixture = Fixture::none();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut resolver = CountingResolver {
            calls: Arc::clone(&calls),
        };
        let mut authorizer = DecisionAuthorizer { decision: None };
        let mut audit = Audit::default();
        let settlement = fixture
            .invocation()
            .execute_batch(
                &mut authorizer,
                &mut resolver,
                &mut audit,
                &GovernedBatchCancellation::new(),
            )
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(settlement.result().stdout(), b"ok");
        assert!(settlement.result().retains_output_capacity());
        assert_eq!(audit.receipts.len(), 1);
        assert_eq!(
            settlement.result().terminal().terminal(),
            GovernedExecutionTerminal::Success
        );
    }

    #[test]
    fn nonzero_process_completion_is_audited_as_execution_failure() {
        let fixture = Fixture::none();
        fs::write(
            fixture.bin.join("fixture-cli"),
            b"#!/bin/sh\nprintf 'partial'\nexit 7\n",
        )
        .unwrap();
        let mut resolver = CountingResolver {
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let mut authorizer = DecisionAuthorizer { decision: None };
        let mut audit = Audit::default();
        let settlement = fixture
            .invocation()
            .execute_batch(
                &mut authorizer,
                &mut resolver,
                &mut audit,
                &GovernedBatchCancellation::new(),
            )
            .unwrap();
        assert_eq!(
            settlement.result().terminal().terminal(),
            GovernedExecutionTerminal::NonZeroExit
        );
        assert_eq!(
            settlement.audit().outcome,
            GovernedExecutionAuditOutcome::ExecutionFailed
        );
    }

    #[test]
    fn authorized_environment_and_stdin_credentials_are_redacted_before_settlement() {
        let fixture = Fixture::none();
        let executable = fixture.bin.join("fixture-cli");
        fs::write(
            &executable,
            b"#!/bin/sh\nprintf '%s|' \"$SECRET_TOKEN\"\n/bin/cat\n",
        )
        .unwrap();
        #[cfg(unix)]
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let contract = secret_contract(vec![
            InjectionTarget::Environment {
                name: "SECRET_TOKEN".to_owned(),
            },
            InjectionTarget::Stdin,
        ]);
        let validated = validate_skill_runtime_contract(&contract).unwrap();
        let scope = CredentialScope::new("owner", "default").unwrap();
        let preparation = secret_preparation(&scope);
        let injection = CredentialInjectionPlan::compile(
            validated,
            &preparation,
            ChildEnvironmentBaseline::portable_cli(),
        )
        .unwrap();
        let intent = GovernedExecutionContract::compile(
            validated,
            GovernedExecutionPolicy::new(3, 3, 1024, 4096, 4096).unwrap(),
        )
        .unwrap()
        .admit(GovernedExecutionRequest::new(vec![], None, None, Some(3)))
        .unwrap();
        let mut values = ChildEnvironmentValues::new(injection.baseline());
        values
            .provide(
                ChildEnvironmentVariable::Path,
                fixture.bin.as_os_str().as_bytes().to_vec(),
            )
            .unwrap();
        values
            .provide(ChildEnvironmentVariable::Lang, b"C.UTF-8".to_vec())
            .unwrap();
        let invocation = GovernedExecutionInvocation::new(
            GovernedExecutionCallContext::new(
                CredentialCallId::new("call-secret").unwrap(),
                "fixture",
                "run",
            )
            .unwrap(),
            validated,
            intent,
            &preparation,
            &injection,
            values,
            Some(
                GovernedWorkingDirectoryRoot::open(
                    WorkingDirectoryMode::Workspace,
                    &fixture.workspace,
                )
                .unwrap(),
            ),
            None,
            None,
        )
        .unwrap();
        let secret = b"s3cr3t-value".to_vec();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut resolver = SecretResolver {
            binding: CredentialMaterialBindingName::new("token").unwrap(),
            value: secret.clone(),
            calls: Arc::clone(&calls),
        };
        let mut authorizer = DecisionAuthorizer { decision: None };
        let mut audit = Audit::default();
        let settlement = invocation
            .execute_batch(
                &mut authorizer,
                &mut resolver,
                &mut audit,
                &GovernedBatchCancellation::new(),
            )
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!settlement
            .result()
            .stdout()
            .windows(secret.len())
            .any(|window| window == secret.as_slice()));
        assert!(!serde_json::to_vec(settlement.audit())
            .unwrap()
            .windows(secret.len())
            .any(|window| window == secret.as_slice()));
    }

    #[test]
    fn filesystem_credential_without_declared_process_placement_fails_closed() {
        let fixture = Fixture::none();
        let contract = secret_contract(vec![InjectionTarget::ScopedFile {
            relative_path: "credential/token".to_owned(),
        }]);
        let validated = validate_skill_runtime_contract(&contract).unwrap();
        let scope = CredentialScope::new("owner", "default").unwrap();
        let preparation = secret_preparation(&scope);
        let injection = CredentialInjectionPlan::compile(
            validated,
            &preparation,
            ChildEnvironmentBaseline::portable_cli(),
        )
        .unwrap();
        let intent = GovernedExecutionContract::compile(
            validated,
            GovernedExecutionPolicy::new(3, 3, 1024, 4096, 4096).unwrap(),
        )
        .unwrap()
        .admit(GovernedExecutionRequest::new(vec![], None, None, Some(3)))
        .unwrap();
        let mut values = ChildEnvironmentValues::new(injection.baseline());
        values
            .provide(
                ChildEnvironmentVariable::Path,
                fixture.bin.as_os_str().as_bytes().to_vec(),
            )
            .unwrap();
        let error = GovernedExecutionInvocation::new(
            GovernedExecutionCallContext::new(
                CredentialCallId::new("call-file").unwrap(),
                "fixture",
                "run",
            )
            .unwrap(),
            validated,
            intent,
            &preparation,
            &injection,
            values,
            Some(
                GovernedWorkingDirectoryRoot::open(
                    WorkingDirectoryMode::Workspace,
                    &fixture.workspace,
                )
                .unwrap(),
            ),
            None,
            None,
        )
        .err()
        .unwrap();
        assert_eq!(
            error.code,
            GovernedExecutionCoordinatorErrorCode::UnsupportedCredentialTarget
        );
    }

    #[test]
    fn missing_required_approval_and_resource_evidence_blocks_auth_resolution() {
        let mut fixture = Fixture::none();
        fixture.contract.policy_floor.approval = ApprovalClass::NativeUiControl;
        fixture
            .contract
            .policy_floor
            .required_resource_authorities
            .insert("workspace-control".to_owned());
        let validated = validate_skill_runtime_contract(&fixture.contract).unwrap();
        let intent = GovernedExecutionContract::compile(
            validated,
            GovernedExecutionPolicy::new(3, 3, 1024, 4096, 4096).unwrap(),
        )
        .unwrap()
        .admit(GovernedExecutionRequest::new(vec![], None, None, Some(3)))
        .unwrap();
        let mut values = ChildEnvironmentValues::new(fixture.injection.baseline());
        values
            .provide(
                ChildEnvironmentVariable::Path,
                fixture.bin.as_os_str().as_bytes().to_vec(),
            )
            .unwrap();
        values
            .provide(ChildEnvironmentVariable::Lang, b"C.UTF-8".to_vec())
            .unwrap();
        let invocation = GovernedExecutionInvocation::new(
            GovernedExecutionCallContext::new(
                CredentialCallId::new("call-policy").unwrap(),
                "fixture",
                "run",
            )
            .unwrap(),
            validated,
            intent,
            &fixture.preparation,
            &fixture.injection,
            values,
            Some(
                GovernedWorkingDirectoryRoot::open(
                    WorkingDirectoryMode::Workspace,
                    &fixture.workspace,
                )
                .unwrap(),
            ),
            None,
            None,
        )
        .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut resolver = CountingResolver {
            calls: Arc::clone(&calls),
        };
        let mut authorizer = InsufficientAuthorizer;
        let mut audit = Audit::default();
        let error = invocation
            .execute_batch(
                &mut authorizer,
                &mut resolver,
                &mut audit,
                &GovernedBatchCancellation::new(),
            )
            .err()
            .unwrap();
        assert_eq!(
            error.code,
            GovernedExecutionCoordinatorErrorCode::InvalidAuthorizationEvidence
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(audit.receipts.len(), 1);
        assert_eq!(
            audit.receipts[0].outcome,
            GovernedExecutionAuditOutcome::AuthorizationDenied
        );
    }

    #[test]
    fn authorizer_panic_is_unavailable_and_never_reaches_credentials() {
        let fixture = Fixture::none();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut resolver = CountingResolver {
            calls: Arc::clone(&calls),
        };
        let mut authorizer = PanicAuthorizer;
        let mut audit = Audit::default();
        let error = fixture
            .invocation()
            .execute_batch(
                &mut authorizer,
                &mut resolver,
                &mut audit,
                &GovernedBatchCancellation::new(),
            )
            .err()
            .unwrap();
        assert_eq!(
            error.code,
            GovernedExecutionCoordinatorErrorCode::AuthorizationUnavailable
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(audit.receipts.len(), 1);
    }

    #[test]
    fn resolver_panic_is_contained_and_audited_without_dispatch() {
        let fixture = Fixture::none();
        let mut resolver = PanicResolver;
        let mut authorizer = DecisionAuthorizer { decision: None };
        let mut audit = Audit::default();
        let error = fixture
            .invocation()
            .execute_batch(
                &mut authorizer,
                &mut resolver,
                &mut audit,
                &GovernedBatchCancellation::new(),
            )
            .err()
            .unwrap();
        assert_eq!(
            error.code,
            GovernedExecutionCoordinatorErrorCode::InternalFailure
        );
        assert_eq!(error.dispatch(), GovernedExecutionDispatch::NotDispatched);
        assert_eq!(audit.receipts.len(), 1);
        assert_eq!(
            audit.receipts[0].outcome,
            GovernedExecutionAuditOutcome::PreparationFailed
        );
    }

    #[test]
    fn post_dispatch_boundary_failure_cannot_be_audited_as_success() {
        let fixture = Fixture::none();
        let invocation = fixture.invocation();
        let deadline = Instant::now() + Duration::from_secs(30);
        let request = build_authorization_request(&invocation, deadline).unwrap();
        let fields = AuthorizationAuditFields::from(&request);
        let authorization = GovernedAuthorizationAudit {
            policy_revision: "policy-1".to_owned(),
            approved_class: ApprovalClass::Ordinary,
            approval_receipt_id: None,
            granted_grant_count: 0,
            granted_resource_scope_count: 0,
            granted_resource_authority_count: 0,
        };
        let mut audit = Audit::default();
        let observed = GovernedExecutionTerminalState::new(
            GovernedExecutionTerminal::Success,
            GovernedExecutionDispatch::Dispatched,
        )
        .unwrap();
        let error = result_sealing_failed(GovernedExecutionDispatch::Dispatched);
        let result: Result<(), _> = audit_execution_error(
            &invocation.context,
            &fixture.injection,
            fields,
            authorization,
            error,
            &mut audit,
            Some(observed),
            None,
            None,
        );
        assert_eq!(
            result.unwrap_err().code,
            GovernedExecutionCoordinatorErrorCode::ResultSealingFailed
        );
        assert_eq!(audit.receipts.len(), 1);
        assert_eq!(
            audit.receipts[0].terminal.terminal(),
            GovernedExecutionTerminal::RuntimeFailure
        );
        assert!(matches!(
            audit.receipts[0].credential.outcome(),
            CredentialExecutionOutcome::Failed { .. }
        ));
    }

    #[test]
    fn same_thread_governed_execution_reentry_is_rejected_without_recursion() {
        let outer = GovernedExecutionReentryGuard::enter().unwrap();
        assert_eq!(
            GovernedExecutionReentryGuard::enter().unwrap_err().code,
            GovernedExecutionCoordinatorErrorCode::ReentrantExecution
        );
        drop(outer);
        assert!(GovernedExecutionReentryGuard::enter().is_ok());
    }

    #[test]
    fn authorizer_callback_cannot_recursively_enter_governed_execution() {
        let fixture = Fixture::none();
        let mut authorizer = ReentrantAuthorizer { nested_error: None };
        let mut resolver = CountingResolver {
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let mut audit = Audit::default();
        let settlement = fixture
            .invocation()
            .execute_batch(
                &mut authorizer,
                &mut resolver,
                &mut audit,
                &GovernedBatchCancellation::new(),
            )
            .unwrap();
        assert_eq!(
            authorizer.nested_error,
            Some(GovernedExecutionCoordinatorErrorCode::ReentrantExecution)
        );
        assert_eq!(
            settlement.result().terminal().terminal(),
            GovernedExecutionTerminal::Success
        );
    }

    #[test]
    fn audit_failure_is_explicit_and_cannot_enable_resolution() {
        let fixture = Fixture::none();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut resolver = CountingResolver {
            calls: Arc::clone(&calls),
        };
        let mut authorizer = DecisionAuthorizer {
            decision: Some(GovernedAuthorizationDecision::Denied),
        };
        let mut audit = FailingAudit;
        let error = fixture
            .invocation()
            .execute_batch(
                &mut authorizer,
                &mut resolver,
                &mut audit,
                &GovernedBatchCancellation::new(),
            )
            .err()
            .unwrap();
        assert_eq!(
            error.code,
            GovernedExecutionCoordinatorErrorCode::AuditFailed
        );
        assert_eq!(error.dispatch(), GovernedExecutionDispatch::NotDispatched);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn pre_cancelled_invocation_never_calls_authorizer_or_resolver() {
        let fixture = Fixture::none();
        let authorization_calls = Arc::new(AtomicUsize::new(0));
        let resolution_calls = Arc::new(AtomicUsize::new(0));
        let mut authorizer = CountingAuthorizer {
            calls: Arc::clone(&authorization_calls),
        };
        let mut resolver = CountingResolver {
            calls: Arc::clone(&resolution_calls),
        };
        let mut audit = Audit::default();
        let cancellation = GovernedBatchCancellation::new();
        cancellation.cancel();
        let error = fixture
            .invocation()
            .execute_batch(&mut authorizer, &mut resolver, &mut audit, &cancellation)
            .err()
            .unwrap();
        assert_eq!(error.code, GovernedExecutionCoordinatorErrorCode::Cancelled);
        assert_eq!(authorization_calls.load(Ordering::SeqCst), 0);
        assert_eq!(resolution_calls.load(Ordering::SeqCst), 0);
        assert_eq!(audit.receipts.len(), 1);
    }

    #[test]
    fn executor_mode_mismatch_is_audited_before_authorization_or_resolution() {
        let fixture = Fixture::none();
        let authorization_calls = Arc::new(AtomicUsize::new(0));
        let resolution_calls = Arc::new(AtomicUsize::new(0));
        let mut authorizer = CountingAuthorizer {
            calls: Arc::clone(&authorization_calls),
        };
        let mut resolver = CountingResolver {
            calls: Arc::clone(&resolution_calls),
        };
        let mut audit = Audit::default();
        let mut bridge = NoopBridge;
        let error = fixture
            .invocation()
            .execute_pty(
                GovernedPtyPolicy::new(1, 1, 1024, 4096).unwrap(),
                GovernedPtySize::new(24, 80, 0, 0).unwrap(),
                &mut bridge,
                &mut authorizer,
                &mut resolver,
                &mut audit,
                &GovernedBatchCancellation::new(),
            )
            .err()
            .unwrap();
        assert_eq!(
            error.code,
            GovernedExecutionCoordinatorErrorCode::ContractMismatch
        );
        assert_eq!(authorization_calls.load(Ordering::SeqCst), 0);
        assert_eq!(resolution_calls.load(Ordering::SeqCst), 0);
        assert_eq!(audit.receipts.len(), 1);
    }

    #[test]
    fn complete_coordinator_chain_fits_a_small_non_recursive_stack() {
        std::thread::Builder::new()
            .name("governed-coordinator-small-stack".to_owned())
            .stack_size(256 * 1024)
            .spawn(|| {
                let fixture = Fixture::none();
                let calls = Arc::new(AtomicUsize::new(0));
                let mut resolver = CountingResolver {
                    calls: Arc::clone(&calls),
                };
                let mut authorizer = DecisionAuthorizer { decision: None };
                let mut audit = Audit::default();
                let settlement = fixture
                    .invocation()
                    .execute_batch(
                        &mut authorizer,
                        &mut resolver,
                        &mut audit,
                        &GovernedBatchCancellation::new(),
                    )
                    .unwrap();
                assert_eq!(
                    settlement.result().terminal().terminal(),
                    GovernedExecutionTerminal::Success
                );
                assert_eq!(calls.load(Ordering::SeqCst), 1);
            })
            .expect("small-stack coordinator thread")
            .join()
            .expect("small-stack coordinator execution");
    }
    assert_not_impl_any!(GovernedAuthorizationRequest<'_>: Clone, fmt::Debug, Serialize);
    assert_not_impl_any!(GovernedExecutionInvocation<'_>: Clone, fmt::Debug, Serialize);
    assert_not_impl_any!(GovernedExecutionSettlement: Clone, fmt::Debug, Serialize);
}
