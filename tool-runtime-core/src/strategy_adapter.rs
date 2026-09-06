//! Strategy-neutral status and outcome contract for non-CLI runtime adapters.
//!
//! Phase 5B gives MCP, browser-profile, native-permission, and delegated-credential
//! adapters one bounded vocabulary without introducing a second authentication state
//! machine. The canonical [`AuthState`] and [`ApprovalClass`] values remain owned by the
//! validated skill runtime contract. This module only compiles their safe projection and
//! fixes pending, delivery, retry, and invalidation semantics across strategies.
//!
//! The contract is deliberately transport-free. It cannot connect to an MCP server,
//! open a browser, request an operating-system permission, mint a delegated grant,
//! retain a provider interaction payload, or authorize an invocation. Those authorities
//! stay with later adapters and the product Auth Broker.

use std::{error::Error, fmt, num::NonZeroU64};

use serde::Serialize;

use crate::{
    manifest::{
        ApprovalClass, AuthKind, AuthRequirement, AuthState, ProfileSelection, RuntimeProtocol,
    },
    manifest_validation::ValidatedSkillRuntimeContract,
};

pub const STRATEGY_ADAPTER_CONTRACT_V1: &str = "tool-runtime.strategy-adapter-contract.v1";

/// Adapter that owns the invocation boundary. `auth_kind` remains a separate axis: an
/// MCP invocation may, for example, authenticate with a delegated credential or a
/// native permission without relabeling the protocol owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyAdapterKind {
    Mcp,
    BrowserProfile,
    NativePermission,
    DelegatedCredential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyProfileMode {
    None,
    Selectable,
    Fixed,
    Implicit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyAdapterContractErrorCode {
    UnsupportedContract,
    InvalidRevision,
    InvalidAuthState,
    NoPendingAction,
    IncompatiblePendingAction,
    InvalidInvocationFailure,
    IncompatibleInvalidation,
}

/// Stable, value-free contract diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StrategyAdapterContractError {
    pub code: StrategyAdapterContractErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl StrategyAdapterContractError {
    const fn new(
        code: StrategyAdapterContractErrorCode,
        field: &'static str,
        message: &'static str,
    ) -> Self {
        Self {
            code,
            field,
            message,
        }
    }
}

impl fmt::Display for StrategyAdapterContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for StrategyAdapterContractError {}

/// Immutable safe projection of one validated strategy contract.
///
/// Profile aliases, endpoints, executable paths, issuer/resource URLs, permissions,
/// grants, and credential material are intentionally absent. Callers must retain the
/// original validated runtime contract for exact execution authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StrategyAdapterContract {
    pub schema_version: &'static str,
    kind: StrategyAdapterKind,
    auth_kind: AuthKind,
    auth_requirement: AuthRequirement,
    profile_mode: StrategyProfileMode,
    approval_floor: ApprovalClass,
}

impl StrategyAdapterContract {
    pub fn compile(
        validated: ValidatedSkillRuntimeContract<'_>,
    ) -> Result<Self, StrategyAdapterContractError> {
        let contract = validated.contract();
        let kind = match (&contract.runtime, contract.auth.kind) {
            (RuntimeProtocol::Mcp { .. }, _) => StrategyAdapterKind::Mcp,
            (_, AuthKind::BrowserProfile) => StrategyAdapterKind::BrowserProfile,
            (_, AuthKind::NativePermission) => StrategyAdapterKind::NativePermission,
            (_, AuthKind::DelegatedCredential) => StrategyAdapterKind::DelegatedCredential,
            _ => return Err(unsupported_contract()),
        };
        let profile_mode = match &contract.auth.profile_selection {
            ProfileSelection::None => StrategyProfileMode::None,
            ProfileSelection::Selectable { .. } => StrategyProfileMode::Selectable,
            ProfileSelection::Fixed { .. } => StrategyProfileMode::Fixed,
            ProfileSelection::Implicit => StrategyProfileMode::Implicit,
        };
        Ok(Self {
            schema_version: STRATEGY_ADAPTER_CONTRACT_V1,
            kind,
            auth_kind: contract.auth.kind,
            auth_requirement: contract.auth.requirement,
            profile_mode,
            approval_floor: contract.policy_floor.approval,
        })
    }

    pub fn kind(self) -> StrategyAdapterKind {
        self.kind
    }

    pub fn auth_kind(self) -> AuthKind {
        self.auth_kind
    }

    pub fn auth_requirement(self) -> AuthRequirement {
        self.auth_requirement
    }

    pub fn profile_mode(self) -> StrategyProfileMode {
        self.profile_mode
    }

    pub fn approval_floor(self) -> ApprovalClass {
        self.approval_floor
    }

    pub fn status(
        self,
        revision: StrategyStateRevision,
        state: AuthState,
    ) -> Result<StrategyAuthStatus, StrategyAdapterContractError> {
        if self.auth_kind == AuthKind::None && state != AuthState::Ready {
            return Err(invalid_auth_state());
        }
        Ok(StrategyAuthStatus {
            schema_version: STRATEGY_ADAPTER_CONTRACT_V1,
            kind: self.kind,
            auth_kind: self.auth_kind,
            auth_requirement: self.auth_requirement,
            revision,
            state,
        })
    }

    /// The declared minimum approval class. This is policy metadata, not an approval
    /// receipt, and cannot authorize execution by itself.
    pub fn approval_requirement(self) -> StrategyApprovalRequirement {
        StrategyApprovalRequirement {
            schema_version: STRATEGY_ADAPTER_CONTRACT_V1,
            kind: self.kind,
            auth_kind: self.auth_kind,
            minimum_class: self.approval_floor,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct StrategyStateRevision(NonZeroU64);

impl StrategyStateRevision {
    pub fn new(value: u64) -> Result<Self, StrategyAdapterContractError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(invalid_revision)
    }

    pub fn get(self) -> u64 {
        self.0.get()
    }

    pub fn next(self) -> Result<Self, StrategyAdapterContractError> {
        self.get()
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .map(Self)
            .ok_or_else(invalid_revision)
    }
}

impl TryFrom<u64> for StrategyStateRevision {
    type Error = StrategyAdapterContractError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyAuthReadiness {
    Ready,
    ReadyWithoutAuthentication,
    VerificationRequired,
    InteractionRequired,
    AuthenticationInProgress,
    Blocked,
}

/// Whether the selected, locally validated action can run without authentication.
/// Trusted catalog/policy code owns this decision; it is not a model-facing parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyAuthDemand {
    UnauthenticatedAllowed,
    AuthenticationRequired,
}

/// Safe, non-authorizing status snapshot. A `ready` snapshot remains observational;
/// exact credentials/session/permission/grant authority must be revalidated at dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StrategyAuthStatus {
    pub schema_version: &'static str,
    kind: StrategyAdapterKind,
    auth_kind: AuthKind,
    auth_requirement: AuthRequirement,
    revision: StrategyStateRevision,
    state: AuthState,
}

impl StrategyAuthStatus {
    pub fn kind(self) -> StrategyAdapterKind {
        self.kind
    }

    pub fn auth_kind(self) -> AuthKind {
        self.auth_kind
    }

    pub fn auth_requirement(self) -> AuthRequirement {
        self.auth_requirement
    }

    pub fn revision(self) -> StrategyStateRevision {
        self.revision
    }

    pub fn state(self) -> AuthState {
        self.state
    }

    pub fn readiness(self, demand: StrategyAuthDemand) -> StrategyAuthReadiness {
        let authentication_required = match self.auth_requirement {
            AuthRequirement::None => false,
            AuthRequirement::Optional | AuthRequirement::Conditional => {
                demand == StrategyAuthDemand::AuthenticationRequired
            },
            AuthRequirement::Required | AuthRequirement::AtLeastOne => true,
        };
        if !authentication_required && self.state != AuthState::Ready {
            return StrategyAuthReadiness::ReadyWithoutAuthentication;
        }
        match self.state {
            AuthState::Ready => StrategyAuthReadiness::Ready,
            AuthState::Unknown => StrategyAuthReadiness::VerificationRequired,
            AuthState::Missing | AuthState::InteractionRequired | AuthState::Expired => {
                StrategyAuthReadiness::InteractionRequired
            },
            AuthState::Authenticating => StrategyAuthReadiness::AuthenticationInProgress,
            AuthState::Revoked
            | AuthState::IdentityMismatch
            | AuthState::Denied
            | AuthState::Error => StrategyAuthReadiness::Blocked,
        }
    }

    pub fn is_ready(self, demand: StrategyAuthDemand) -> bool {
        matches!(
            self.readiness(demand),
            StrategyAuthReadiness::Ready | StrategyAuthReadiness::ReadyWithoutAuthentication
        )
    }

    pub fn pending_action(self) -> Result<StrategyPendingAction, StrategyAdapterContractError> {
        let action = match self.state {
            AuthState::Ready => return Err(no_pending_action()),
            AuthState::Unknown => StrategyPendingActionKind::VerifyStatus,
            AuthState::Authenticating => StrategyPendingActionKind::AwaitAuthorization,
            AuthState::IdentityMismatch => StrategyPendingActionKind::CorrectIdentity,
            AuthState::Denied => match self.auth_kind {
                AuthKind::NativePermission => StrategyPendingActionKind::OpenSystemSettings,
                _ => StrategyPendingActionKind::AuthorizationDenied,
            },
            AuthState::Error => StrategyPendingActionKind::RepairAuthentication,
            AuthState::Missing
            | AuthState::InteractionRequired
            | AuthState::Expired
            | AuthState::Revoked => match self.auth_kind {
                AuthKind::None => return Err(invalid_auth_state()),
                AuthKind::Secrets => StrategyPendingActionKind::ConfigureCredentials,
                AuthKind::CliProfile => StrategyPendingActionKind::AuthenticateProfile,
                AuthKind::OAuthSession => StrategyPendingActionKind::Authorize,
                AuthKind::BrowserProfile => StrategyPendingActionKind::OpenBrowserLogin,
                AuthKind::NativePermission => StrategyPendingActionKind::RequestNativePermission,
                AuthKind::DelegatedCredential => StrategyPendingActionKind::RequestDelegatedGrant,
            },
        };
        Ok(StrategyPendingAction::new(
            self.kind,
            self.auth_kind,
            self.revision,
            action,
            None,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StrategyApprovalRequirement {
    pub schema_version: &'static str,
    kind: StrategyAdapterKind,
    auth_kind: AuthKind,
    minimum_class: ApprovalClass,
}

/// Result of the trusted product policy evaluation for one invocation. This value is a
/// projection input only; it is not an approval receipt and must never come from model
/// arguments or remote adapter metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrategyApprovalDecision {
    NotRequired,
    Required,
}

impl StrategyApprovalRequirement {
    pub fn kind(self) -> StrategyAdapterKind {
        self.kind
    }

    pub fn minimum_class(self) -> ApprovalClass {
        self.minimum_class
    }

    pub fn auth_kind(self) -> AuthKind {
        self.auth_kind
    }

    pub fn pending_action(
        self,
        revision: StrategyStateRevision,
        decision: StrategyApprovalDecision,
    ) -> Option<StrategyPendingAction> {
        if decision == StrategyApprovalDecision::NotRequired {
            return None;
        }
        Some(StrategyPendingAction::new(
            self.kind,
            self.auth_kind,
            revision,
            StrategyPendingActionKind::Approval,
            Some(self.minimum_class),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyPendingActionKind {
    VerifyStatus,
    ConfigureCredentials,
    AuthenticateProfile,
    Authorize,
    OpenBrowserLogin,
    RequestNativePermission,
    OpenSystemSettings,
    RequestDelegatedGrant,
    AwaitAuthorization,
    CorrectIdentity,
    AuthorizationDenied,
    RepairAuthentication,
    Approval,
    AdditionalInput,
    RemoteTask,
}

/// Payload-free pending projection. OAuth URLs/state, cookies, device codes, native
/// handles, user input, task tokens, and grant material remain in the owning adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StrategyPendingAction {
    pub schema_version: &'static str,
    kind: StrategyAdapterKind,
    auth_kind: AuthKind,
    revision: StrategyStateRevision,
    action: StrategyPendingActionKind,
    approval_class: Option<ApprovalClass>,
}

impl StrategyPendingAction {
    fn new(
        kind: StrategyAdapterKind,
        auth_kind: AuthKind,
        revision: StrategyStateRevision,
        action: StrategyPendingActionKind,
        approval_class: Option<ApprovalClass>,
    ) -> Self {
        Self {
            schema_version: STRATEGY_ADAPTER_CONTRACT_V1,
            kind,
            auth_kind,
            revision,
            action,
            approval_class,
        }
    }

    pub fn additional_input(
        contract: StrategyAdapterContract,
        revision: StrategyStateRevision,
    ) -> Result<Self, StrategyAdapterContractError> {
        if contract.kind != StrategyAdapterKind::Mcp {
            return Err(incompatible_pending_action());
        }
        Ok(Self::new(
            contract.kind,
            contract.auth_kind,
            revision,
            StrategyPendingActionKind::AdditionalInput,
            None,
        ))
    }

    pub fn remote_task(
        contract: StrategyAdapterContract,
        revision: StrategyStateRevision,
    ) -> Result<Self, StrategyAdapterContractError> {
        if contract.kind != StrategyAdapterKind::Mcp {
            return Err(incompatible_pending_action());
        }
        Ok(Self::new(
            contract.kind,
            contract.auth_kind,
            revision,
            StrategyPendingActionKind::RemoteTask,
            None,
        ))
    }

    pub fn kind(self) -> StrategyAdapterKind {
        self.kind
    }

    pub fn auth_kind(self) -> AuthKind {
        self.auth_kind
    }

    pub fn revision(self) -> StrategyStateRevision {
        self.revision
    }

    pub fn action(self) -> StrategyPendingActionKind {
        self.action
    }

    pub fn approval_class(self) -> Option<ApprovalClass> {
        self.approval_class
    }

    pub fn dispatch_certainty(self) -> StrategyDispatchCertainty {
        match self.action {
            StrategyPendingActionKind::AdditionalInput | StrategyPendingActionKind::RemoteTask => {
                StrategyDispatchCertainty::Dispatched
            },
            _ => StrategyDispatchCertainty::NotDispatched,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyCompletionKind {
    Success,
    RemoteError,
}

/// Completed adapter payload. This wrapper deliberately implements neither `Debug` nor
/// `Serialize`, so an arbitrary provider result cannot escape through generic logging.
pub struct StrategyCompletion<T> {
    kind: StrategyCompletionKind,
    result: T,
}

impl<T> StrategyCompletion<T> {
    pub fn success(result: T) -> Self {
        Self {
            kind: StrategyCompletionKind::Success,
            result,
        }
    }

    pub fn remote_error(result: T) -> Self {
        Self {
            kind: StrategyCompletionKind::RemoteError,
            result,
        }
    }

    pub fn kind(&self) -> StrategyCompletionKind {
        self.kind
    }

    pub fn result(&self) -> &T {
        &self.result
    }

    pub fn into_result(self) -> T {
        self.result
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyDispatchCertainty {
    NotDispatched,
    Dispatched,
    UnknownAfterDispatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyInvocationFailureCode {
    PolicyDenied,
    Cancelled,
    TimedOut,
    TransportFailure,
    MalformedResponse,
    Invalidated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyRetryDisposition {
    SafeBeforeDispatch,
    RequiresIdempotencyDecision,
    NeverAutomatic,
}

/// Value-free invocation failure with explicit delivery ambiguity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StrategyInvocationFailure {
    pub schema_version: &'static str,
    code: StrategyInvocationFailureCode,
    dispatch: StrategyDispatchCertainty,
}

impl StrategyInvocationFailure {
    pub fn new(
        code: StrategyInvocationFailureCode,
        dispatch: StrategyDispatchCertainty,
    ) -> Result<Self, StrategyAdapterContractError> {
        if (code == StrategyInvocationFailureCode::PolicyDenied
            && dispatch != StrategyDispatchCertainty::NotDispatched)
            || (code == StrategyInvocationFailureCode::MalformedResponse
                && dispatch == StrategyDispatchCertainty::NotDispatched)
        {
            return Err(invalid_invocation_failure());
        }
        Ok(Self {
            schema_version: STRATEGY_ADAPTER_CONTRACT_V1,
            code,
            dispatch,
        })
    }

    pub fn code(self) -> StrategyInvocationFailureCode {
        self.code
    }

    pub fn dispatch(self) -> StrategyDispatchCertainty {
        self.dispatch
    }

    pub fn retry_disposition(self) -> StrategyRetryDisposition {
        match self.dispatch {
            StrategyDispatchCertainty::NotDispatched => {
                StrategyRetryDisposition::SafeBeforeDispatch
            },
            StrategyDispatchCertainty::Dispatched => {
                StrategyRetryDisposition::RequiresIdempotencyDecision
            },
            StrategyDispatchCertainty::UnknownAfterDispatch => {
                StrategyRetryDisposition::NeverAutomatic
            },
        }
    }
}

/// Common invocation envelope. Adapter payloads remain opaque and cannot be logged or
/// serialized through this type.
pub enum StrategyInvocationOutcome<T> {
    Complete(StrategyCompletion<T>),
    Pending(StrategyPendingAction),
    Failed(StrategyInvocationFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyInvalidationCause {
    ProcessRestart,
    AuthenticationFailure,
    CredentialChanged,
    BrowserSessionChanged,
    NativePermissionChanged,
    DelegatedGrantChanged,
    AuthorizationServerChanged,
    ResourceBindingChanged,
    ScopeChanged,
    PolicyChanged,
    TransportClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategyInvalidationDisposition {
    Preserve,
    Invalidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StrategyInvalidationEffect {
    pub schema_version: &'static str,
    auth_status: StrategyInvalidationDisposition,
    session: StrategyInvalidationDisposition,
    auth_interactions: StrategyInvalidationDisposition,
    invocations: StrategyInvalidationDisposition,
    approval: StrategyInvalidationDisposition,
}

impl StrategyInvalidationEffect {
    pub fn auth_status(self) -> StrategyInvalidationDisposition {
        self.auth_status
    }

    pub fn session(self) -> StrategyInvalidationDisposition {
        self.session
    }

    pub fn auth_interactions(self) -> StrategyInvalidationDisposition {
        self.auth_interactions
    }

    pub fn invocations(self) -> StrategyInvalidationDisposition {
        self.invocations
    }

    pub fn approval(self) -> StrategyInvalidationDisposition {
        self.approval
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StrategyInvalidation {
    pub schema_version: &'static str,
    kind: StrategyAdapterKind,
    auth_kind: AuthKind,
    cause: StrategyInvalidationCause,
    next_revision: StrategyStateRevision,
    effect: StrategyInvalidationEffect,
}

impl StrategyInvalidation {
    pub fn new(
        contract: StrategyAdapterContract,
        cause: StrategyInvalidationCause,
        next_revision: StrategyStateRevision,
    ) -> Result<Self, StrategyAdapterContractError> {
        if !invalidation_applies(contract, cause) {
            return Err(incompatible_invalidation());
        }
        let invalidate_all = StrategyInvalidationDisposition::Invalidate;
        let preserve = StrategyInvalidationDisposition::Preserve;
        let effect = match cause {
            StrategyInvalidationCause::PolicyChanged => StrategyInvalidationEffect {
                schema_version: STRATEGY_ADAPTER_CONTRACT_V1,
                auth_status: preserve,
                session: preserve,
                auth_interactions: preserve,
                invocations: invalidate_all,
                approval: invalidate_all,
            },
            StrategyInvalidationCause::TransportClosed => StrategyInvalidationEffect {
                schema_version: STRATEGY_ADAPTER_CONTRACT_V1,
                auth_status: preserve,
                session: invalidate_all,
                auth_interactions: invalidate_all,
                invocations: invalidate_all,
                approval: preserve,
            },
            _ => StrategyInvalidationEffect {
                schema_version: STRATEGY_ADAPTER_CONTRACT_V1,
                auth_status: invalidate_all,
                session: invalidate_all,
                auth_interactions: invalidate_all,
                invocations: invalidate_all,
                approval: invalidate_all,
            },
        };
        Ok(Self {
            schema_version: STRATEGY_ADAPTER_CONTRACT_V1,
            kind: contract.kind,
            auth_kind: contract.auth_kind,
            cause,
            next_revision,
            effect,
        })
    }

    pub fn kind(self) -> StrategyAdapterKind {
        self.kind
    }

    pub fn cause(self) -> StrategyInvalidationCause {
        self.cause
    }

    pub fn auth_kind(self) -> AuthKind {
        self.auth_kind
    }

    pub fn next_revision(self) -> StrategyStateRevision {
        self.next_revision
    }

    pub fn effect(self) -> StrategyInvalidationEffect {
        self.effect
    }

    pub fn supersedes(self, status: StrategyAuthStatus) -> bool {
        self.kind == status.kind
            && self.auth_kind == status.auth_kind
            && self.next_revision > status.revision
    }
}

fn invalidation_applies(
    contract: StrategyAdapterContract,
    cause: StrategyInvalidationCause,
) -> bool {
    match cause {
        StrategyInvalidationCause::BrowserSessionChanged => {
            contract.auth_kind == AuthKind::BrowserProfile
        },
        StrategyInvalidationCause::NativePermissionChanged => {
            contract.auth_kind == AuthKind::NativePermission
        },
        StrategyInvalidationCause::DelegatedGrantChanged => {
            contract.auth_kind == AuthKind::DelegatedCredential
        },
        StrategyInvalidationCause::AuthorizationServerChanged
        | StrategyInvalidationCause::ResourceBindingChanged
        | StrategyInvalidationCause::ScopeChanged => {
            contract.kind == StrategyAdapterKind::Mcp
                && contract.auth_kind == AuthKind::OAuthSession
        },
        StrategyInvalidationCause::TransportClosed => matches!(
            contract.kind,
            StrategyAdapterKind::Mcp
                | StrategyAdapterKind::BrowserProfile
                | StrategyAdapterKind::DelegatedCredential
        ),
        StrategyInvalidationCause::AuthenticationFailure => contract.auth_kind != AuthKind::None,
        StrategyInvalidationCause::CredentialChanged => matches!(
            contract.auth_kind,
            AuthKind::Secrets | AuthKind::CliProfile | AuthKind::OAuthSession
        ),
        StrategyInvalidationCause::ProcessRestart | StrategyInvalidationCause::PolicyChanged => {
            true
        },
    }
}

const fn unsupported_contract() -> StrategyAdapterContractError {
    StrategyAdapterContractError::new(
        StrategyAdapterContractErrorCode::UnsupportedContract,
        "runtime_contract",
        "the validated runtime contract is not owned by a Phase 5 strategy adapter",
    )
}

const fn invalid_revision() -> StrategyAdapterContractError {
    StrategyAdapterContractError::new(
        StrategyAdapterContractErrorCode::InvalidRevision,
        "revision",
        "a strategy state revision must be non-zero and must not overflow",
    )
}

const fn invalid_auth_state() -> StrategyAdapterContractError {
    StrategyAdapterContractError::new(
        StrategyAdapterContractErrorCode::InvalidAuthState,
        "auth_state",
        "the authentication state contradicts the validated strategy contract",
    )
}

const fn no_pending_action() -> StrategyAdapterContractError {
    StrategyAdapterContractError::new(
        StrategyAdapterContractErrorCode::NoPendingAction,
        "pending_action",
        "a ready strategy has no authentication action pending",
    )
}

const fn incompatible_pending_action() -> StrategyAdapterContractError {
    StrategyAdapterContractError::new(
        StrategyAdapterContractErrorCode::IncompatiblePendingAction,
        "pending_action",
        "the pending action is not supported by this strategy",
    )
}

const fn invalid_invocation_failure() -> StrategyAdapterContractError {
    StrategyAdapterContractError::new(
        StrategyAdapterContractErrorCode::InvalidInvocationFailure,
        "invocation_failure",
        "the invocation failure contradicts its dispatch certainty",
    )
}

const fn incompatible_invalidation() -> StrategyAdapterContractError {
    StrategyAdapterContractError::new(
        StrategyAdapterContractErrorCode::IncompatibleInvalidation,
        "invalidation",
        "the invalidation cause does not apply to this strategy",
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, thread};

    use serde::Serialize;
    use static_assertions::assert_not_impl_any;

    use super::*;
    use crate::{
        manifest::{
            AuthContract, AuthStorage, McpDiscoveryPolicy, McpTransport, PolicyFloor,
            RuntimeLimits, RuntimeRequirements, SkillRuntimeContract, SkillRuntimeContractVersion,
        },
        manifest_validation::validate_skill_runtime_contract,
    };

    fn contract(kind: StrategyAdapterKind) -> SkillRuntimeContract {
        let (runtime, auth) = match kind {
            StrategyAdapterKind::Mcp => (
                RuntimeProtocol::Mcp {
                    transport: McpTransport::StreamableHttp {
                        endpoint: "https://tools.example.test/mcp".to_owned(),
                    },
                    discovery: McpDiscoveryPolicy {
                        oauth: Some(crate::manifest::McpOAuthConnectionPolicy {
                            authorization_issuer: "https://issuer.example".to_owned(),
                            scopes: Default::default(),
                        }),
                        ..McpDiscoveryPolicy::default()
                    },
                    limits: RuntimeLimits::default(),
                },
                AuthContract {
                    kind: AuthKind::OAuthSession,
                    requirement: AuthRequirement::Required,
                    provider: Some("example".to_owned()),
                    profile_selection: ProfileSelection::Selectable {
                        default: Some("personal".to_owned()),
                    },
                    storage: AuthStorage::None,
                    ..AuthContract::default()
                },
            ),
            StrategyAdapterKind::BrowserProfile => (
                cli_runtime(),
                AuthContract {
                    kind: AuthKind::BrowserProfile,
                    requirement: AuthRequirement::Required,
                    provider: Some("browser".to_owned()),
                    profile_selection: ProfileSelection::Fixed {
                        alias: "personal".to_owned(),
                    },
                    storage: AuthStorage::BrowserProfile,
                    ..AuthContract::default()
                },
            ),
            StrategyAdapterKind::NativePermission => (
                cli_runtime(),
                AuthContract {
                    kind: AuthKind::NativePermission,
                    requirement: AuthRequirement::Required,
                    provider: Some("screen-recording".to_owned()),
                    storage: AuthStorage::OperatingSystem,
                    ..AuthContract::default()
                },
            ),
            StrategyAdapterKind::DelegatedCredential => (
                cli_runtime(),
                AuthContract {
                    kind: AuthKind::DelegatedCredential,
                    requirement: AuthRequirement::Required,
                    provider: Some("verified-executor".to_owned()),
                    storage: AuthStorage::EphemeralGrant,
                    ..AuthContract::default()
                },
            ),
        };
        let requires = if matches!(&runtime, RuntimeProtocol::Cli { .. }) {
            RuntimeRequirements {
                bins: BTreeSet::from(["strategy-adapter-fixture".to_owned()]),
                entrypoint: Default::default(),
                environment: Default::default(),
            }
        } else {
            RuntimeRequirements::default()
        };
        SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires,
            runtime,
            auth,
            policy_floor: PolicyFloor {
                approval: ApprovalClass::ConditionalExternalSideEffect,
                ..PolicyFloor::default()
            },
        }
    }

    fn cli_runtime() -> RuntimeProtocol {
        RuntimeProtocol::Cli {
            command_prefix: Vec::new(),
            interaction: Default::default(),
            stdin: Default::default(),
            working_directory: Default::default(),
            limits: RuntimeLimits::default(),
        }
    }

    fn compile(kind: StrategyAdapterKind) -> StrategyAdapterContract {
        let contract = contract(kind);
        let validated = validate_skill_runtime_contract(&contract).expect("valid contract");
        StrategyAdapterContract::compile(validated).expect("supported strategy")
    }

    #[test]
    fn compiles_all_four_strategies_without_copying_authority_values() {
        let cases = [
            (StrategyAdapterKind::Mcp, StrategyProfileMode::Selectable),
            (
                StrategyAdapterKind::BrowserProfile,
                StrategyProfileMode::Fixed,
            ),
            (
                StrategyAdapterKind::NativePermission,
                StrategyProfileMode::None,
            ),
            (
                StrategyAdapterKind::DelegatedCredential,
                StrategyProfileMode::None,
            ),
        ];
        for (kind, profile_mode) in cases {
            let compiled = compile(kind);
            assert_eq!(compiled.kind(), kind);
            assert_eq!(compiled.profile_mode(), profile_mode);
            assert_eq!(
                compiled.approval_floor(),
                ApprovalClass::ConditionalExternalSideEffect
            );
            let json = serde_json::to_string(&compiled).expect("safe projection");
            assert!(!json.contains("personal"));
            assert!(!json.contains("tools.example"));
            assert!(!json.contains("screen-recording"));
            assert!(!json.contains("verified-executor"));
        }
    }

    #[test]
    fn ordinary_cli_contract_is_outside_the_phase5_strategy_boundary() {
        let contract = SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires: RuntimeRequirements {
                bins: BTreeSet::from(["ordinary-cli-fixture".to_owned()]),
                entrypoint: Default::default(),
                environment: Default::default(),
            },
            runtime: cli_runtime(),
            auth: AuthContract::default(),
            policy_floor: PolicyFloor::default(),
        };
        let validated = validate_skill_runtime_contract(&contract).expect("valid CLI contract");
        let error = StrategyAdapterContract::compile(validated).expect_err("not Phase 5");
        assert_eq!(
            error.code,
            StrategyAdapterContractErrorCode::UnsupportedContract
        );
    }

    #[test]
    fn auth_readiness_reuses_the_canonical_state_machine() {
        let contract = compile(StrategyAdapterKind::Mcp);
        let revision = StrategyStateRevision::new(1).unwrap();
        let cases = [
            (
                AuthState::Unknown,
                StrategyAuthReadiness::VerificationRequired,
            ),
            (
                AuthState::Missing,
                StrategyAuthReadiness::InteractionRequired,
            ),
            (
                AuthState::InteractionRequired,
                StrategyAuthReadiness::InteractionRequired,
            ),
            (
                AuthState::Authenticating,
                StrategyAuthReadiness::AuthenticationInProgress,
            ),
            (AuthState::Ready, StrategyAuthReadiness::Ready),
            (
                AuthState::Expired,
                StrategyAuthReadiness::InteractionRequired,
            ),
            (AuthState::Revoked, StrategyAuthReadiness::Blocked),
            (AuthState::IdentityMismatch, StrategyAuthReadiness::Blocked),
            (AuthState::Denied, StrategyAuthReadiness::Blocked),
            (AuthState::Error, StrategyAuthReadiness::Blocked),
        ];
        for (state, readiness) in cases {
            assert_eq!(
                contract
                    .status(revision, state)
                    .unwrap()
                    .readiness(StrategyAuthDemand::AuthenticationRequired),
                readiness
            );
        }
    }

    #[test]
    fn unauthenticated_mcp_status_cannot_claim_an_auth_failure() {
        let mut contract = contract(StrategyAdapterKind::Mcp);
        contract.auth = AuthContract::default();
        let RuntimeProtocol::Mcp { discovery, .. } = &mut contract.runtime else {
            unreachable!("the MCP strategy fixture must use an MCP runtime");
        };
        discovery.oauth = None;
        let validated = validate_skill_runtime_contract(&contract).expect("valid public MCP");
        let compiled = StrategyAdapterContract::compile(validated).unwrap();
        let revision = StrategyStateRevision::new(1).unwrap();
        assert!(compiled.status(revision, AuthState::Ready).is_ok());
        assert_eq!(
            compiled
                .status(revision, AuthState::Unknown)
                .expect_err("no authentication status to verify")
                .code,
            StrategyAdapterContractErrorCode::InvalidAuthState
        );
        assert_eq!(
            compiled
                .status(revision, AuthState::Missing)
                .expect_err("no auth to be missing")
                .code,
            StrategyAdapterContractErrorCode::InvalidAuthState
        );
    }

    #[test]
    fn auth_pending_actions_are_strategy_specific_and_payload_free() {
        let revision = StrategyStateRevision::new(7).unwrap();
        let cases = [
            (
                StrategyAdapterKind::Mcp,
                StrategyPendingActionKind::Authorize,
            ),
            (
                StrategyAdapterKind::BrowserProfile,
                StrategyPendingActionKind::OpenBrowserLogin,
            ),
            (
                StrategyAdapterKind::NativePermission,
                StrategyPendingActionKind::RequestNativePermission,
            ),
            (
                StrategyAdapterKind::DelegatedCredential,
                StrategyPendingActionKind::RequestDelegatedGrant,
            ),
        ];
        for (kind, action) in cases {
            let pending = compile(kind)
                .status(revision, AuthState::Missing)
                .unwrap()
                .pending_action()
                .unwrap();
            assert_eq!(pending.kind(), kind);
            assert_eq!(pending.action(), action);
            assert_eq!(pending.revision(), revision);
            assert_eq!(pending.approval_class(), None);
        }
        let ready = compile(StrategyAdapterKind::Mcp)
            .status(revision, AuthState::Ready)
            .unwrap();
        assert_eq!(
            ready.pending_action().unwrap_err().code,
            StrategyAdapterContractErrorCode::NoPendingAction
        );
    }

    #[test]
    fn complete_cross_strategy_auth_and_invalidation_matrix_fails_closed() {
        let strategies = [
            StrategyAdapterKind::Mcp,
            StrategyAdapterKind::BrowserProfile,
            StrategyAdapterKind::NativePermission,
            StrategyAdapterKind::DelegatedCredential,
        ];
        let states = [
            (
                AuthState::Unknown,
                StrategyAuthReadiness::VerificationRequired,
            ),
            (
                AuthState::Missing,
                StrategyAuthReadiness::InteractionRequired,
            ),
            (
                AuthState::InteractionRequired,
                StrategyAuthReadiness::InteractionRequired,
            ),
            (
                AuthState::Authenticating,
                StrategyAuthReadiness::AuthenticationInProgress,
            ),
            (AuthState::Ready, StrategyAuthReadiness::Ready),
            (
                AuthState::Expired,
                StrategyAuthReadiness::InteractionRequired,
            ),
            (AuthState::Revoked, StrategyAuthReadiness::Blocked),
            (AuthState::IdentityMismatch, StrategyAuthReadiness::Blocked),
            (AuthState::Denied, StrategyAuthReadiness::Blocked),
            (AuthState::Error, StrategyAuthReadiness::Blocked),
        ];

        for kind in strategies {
            let compiled = compile(kind);
            for (state, readiness) in states {
                let status = compiled
                    .status(StrategyStateRevision::new(1).unwrap(), state)
                    .unwrap();
                assert_eq!(
                    status.readiness(StrategyAuthDemand::AuthenticationRequired),
                    readiness,
                    "readiness drift for {kind:?}/{state:?}"
                );
                if state == AuthState::Ready {
                    assert_eq!(
                        status.pending_action().unwrap_err().code,
                        StrategyAdapterContractErrorCode::NoPendingAction
                    );
                    continue;
                }
                let expected_action = match state {
                    AuthState::Unknown => StrategyPendingActionKind::VerifyStatus,
                    AuthState::Authenticating => StrategyPendingActionKind::AwaitAuthorization,
                    AuthState::IdentityMismatch => StrategyPendingActionKind::CorrectIdentity,
                    AuthState::Denied if kind == StrategyAdapterKind::NativePermission => {
                        StrategyPendingActionKind::OpenSystemSettings
                    },
                    AuthState::Denied => StrategyPendingActionKind::AuthorizationDenied,
                    AuthState::Error => StrategyPendingActionKind::RepairAuthentication,
                    AuthState::Missing
                    | AuthState::InteractionRequired
                    | AuthState::Expired
                    | AuthState::Revoked => match kind {
                        StrategyAdapterKind::Mcp => StrategyPendingActionKind::Authorize,
                        StrategyAdapterKind::BrowserProfile => {
                            StrategyPendingActionKind::OpenBrowserLogin
                        },
                        StrategyAdapterKind::NativePermission => {
                            StrategyPendingActionKind::RequestNativePermission
                        },
                        StrategyAdapterKind::DelegatedCredential => {
                            StrategyPendingActionKind::RequestDelegatedGrant
                        },
                    },
                    AuthState::Ready => unreachable!("handled above"),
                };
                let pending = status.pending_action().unwrap();
                assert_eq!(pending.kind(), kind);
                assert_eq!(pending.action(), expected_action);
            }
        }

        let all = strategies.as_slice();
        let mcp_only = [StrategyAdapterKind::Mcp];
        let browser_only = [StrategyAdapterKind::BrowserProfile];
        let native_only = [StrategyAdapterKind::NativePermission];
        let delegated_only = [StrategyAdapterKind::DelegatedCredential];
        let transport_strategies = [
            StrategyAdapterKind::Mcp,
            StrategyAdapterKind::BrowserProfile,
            StrategyAdapterKind::DelegatedCredential,
        ];
        let invalidation_cases: [(StrategyInvalidationCause, &[StrategyAdapterKind]); 11] = [
            (StrategyInvalidationCause::ProcessRestart, all),
            (StrategyInvalidationCause::AuthenticationFailure, all),
            (StrategyInvalidationCause::CredentialChanged, &mcp_only),
            (
                StrategyInvalidationCause::BrowserSessionChanged,
                &browser_only,
            ),
            (
                StrategyInvalidationCause::NativePermissionChanged,
                &native_only,
            ),
            (
                StrategyInvalidationCause::DelegatedGrantChanged,
                &delegated_only,
            ),
            (
                StrategyInvalidationCause::AuthorizationServerChanged,
                &mcp_only,
            ),
            (StrategyInvalidationCause::ResourceBindingChanged, &mcp_only),
            (StrategyInvalidationCause::ScopeChanged, &mcp_only),
            (StrategyInvalidationCause::PolicyChanged, all),
            (
                StrategyInvalidationCause::TransportClosed,
                &transport_strategies,
            ),
        ];

        for kind in strategies {
            let compiled = compile(kind);
            for (cause, permitted) in invalidation_cases {
                let result = StrategyInvalidation::new(
                    compiled,
                    cause,
                    StrategyStateRevision::new(2).unwrap(),
                );
                if !permitted.contains(&kind) {
                    assert_eq!(
                        result.unwrap_err().code,
                        StrategyAdapterContractErrorCode::IncompatibleInvalidation,
                        "invalidation crossed strategy boundary for {kind:?}/{cause:?}"
                    );
                    continue;
                }
                let effect = result.unwrap().effect();
                match cause {
                    StrategyInvalidationCause::PolicyChanged => {
                        assert_eq!(
                            effect.auth_status(),
                            StrategyInvalidationDisposition::Preserve
                        );
                        assert_eq!(effect.session(), StrategyInvalidationDisposition::Preserve);
                        assert_eq!(
                            effect.auth_interactions(),
                            StrategyInvalidationDisposition::Preserve
                        );
                        assert_eq!(
                            effect.invocations(),
                            StrategyInvalidationDisposition::Invalidate
                        );
                        assert_eq!(
                            effect.approval(),
                            StrategyInvalidationDisposition::Invalidate
                        );
                    },
                    StrategyInvalidationCause::TransportClosed => {
                        assert_eq!(
                            effect.auth_status(),
                            StrategyInvalidationDisposition::Preserve
                        );
                        assert_eq!(
                            effect.session(),
                            StrategyInvalidationDisposition::Invalidate
                        );
                        assert_eq!(
                            effect.auth_interactions(),
                            StrategyInvalidationDisposition::Invalidate
                        );
                        assert_eq!(
                            effect.invocations(),
                            StrategyInvalidationDisposition::Invalidate
                        );
                        assert_eq!(effect.approval(), StrategyInvalidationDisposition::Preserve);
                    },
                    _ => {
                        assert_eq!(
                            effect.auth_status(),
                            StrategyInvalidationDisposition::Invalidate
                        );
                        assert_eq!(
                            effect.session(),
                            StrategyInvalidationDisposition::Invalidate
                        );
                        assert_eq!(
                            effect.auth_interactions(),
                            StrategyInvalidationDisposition::Invalidate
                        );
                        assert_eq!(
                            effect.invocations(),
                            StrategyInvalidationDisposition::Invalidate
                        );
                        assert_eq!(
                            effect.approval(),
                            StrategyInvalidationDisposition::Invalidate
                        );
                    },
                }
            }
        }

        let revision = StrategyStateRevision::new(9).unwrap();
        for kind in strategies {
            let compiled = compile(kind);
            let additional_input = StrategyPendingAction::additional_input(compiled, revision);
            let remote_task = StrategyPendingAction::remote_task(compiled, revision);
            assert_eq!(additional_input.is_ok(), kind == StrategyAdapterKind::Mcp);
            assert_eq!(remote_task.is_ok(), kind == StrategyAdapterKind::Mcp);
        }
    }

    #[test]
    fn optional_and_conditional_auth_require_an_invocation_demand() {
        for requirement in [AuthRequirement::Optional, AuthRequirement::Conditional] {
            let mut source = contract(StrategyAdapterKind::Mcp);
            source.auth.requirement = requirement;
            let validated = validate_skill_runtime_contract(&source).unwrap();
            let status = StrategyAdapterContract::compile(validated)
                .unwrap()
                .status(StrategyStateRevision::new(1).unwrap(), AuthState::Missing)
                .unwrap();
            assert_eq!(
                status.readiness(StrategyAuthDemand::UnauthenticatedAllowed),
                StrategyAuthReadiness::ReadyWithoutAuthentication
            );
            assert_eq!(
                status.readiness(StrategyAuthDemand::AuthenticationRequired),
                StrategyAuthReadiness::InteractionRequired
            );
            assert!(status.is_ready(StrategyAuthDemand::UnauthenticatedAllowed));
            assert!(!status.is_ready(StrategyAuthDemand::AuthenticationRequired));
        }
    }

    #[test]
    fn mcp_protocol_uses_its_declared_delegated_auth_strategy() {
        let mut source = contract(StrategyAdapterKind::Mcp);
        source.auth = AuthContract {
            kind: AuthKind::DelegatedCredential,
            requirement: AuthRequirement::Required,
            provider: Some("verified-executor".to_owned()),
            storage: AuthStorage::EphemeralGrant,
            ..AuthContract::default()
        };
        let RuntimeProtocol::Mcp { discovery, .. } = &mut source.runtime else {
            unreachable!("the MCP strategy fixture must use an MCP runtime");
        };
        discovery.oauth = None;
        let validated = validate_skill_runtime_contract(&source).expect("valid delegated MCP");
        let compiled = StrategyAdapterContract::compile(validated).unwrap();
        assert_eq!(compiled.kind(), StrategyAdapterKind::Mcp);
        assert_eq!(compiled.auth_kind(), AuthKind::DelegatedCredential);

        let pending = compiled
            .status(StrategyStateRevision::new(1).unwrap(), AuthState::Missing)
            .unwrap()
            .pending_action()
            .unwrap();
        assert_eq!(pending.kind(), StrategyAdapterKind::Mcp);
        assert_eq!(pending.auth_kind(), AuthKind::DelegatedCredential);
        assert_eq!(
            pending.action(),
            StrategyPendingActionKind::RequestDelegatedGrant
        );
        assert!(StrategyInvalidation::new(
            compiled,
            StrategyInvalidationCause::DelegatedGrantChanged,
            StrategyStateRevision::new(2).unwrap(),
        )
        .is_ok());
        assert_eq!(
            StrategyInvalidation::new(
                compiled,
                StrategyInvalidationCause::AuthorizationServerChanged,
                StrategyStateRevision::new(2).unwrap(),
            )
            .unwrap_err()
            .code,
            StrategyAdapterContractErrorCode::IncompatibleInvalidation
        );

        let mut native_source = contract(StrategyAdapterKind::NativePermission);
        native_source.runtime = RuntimeProtocol::Mcp {
            transport: McpTransport::Stdio {
                executable: "strategy-adapter-fixture".to_owned(),
                args: Vec::new(),
            },
            discovery: McpDiscoveryPolicy::default(),
            limits: RuntimeLimits::default(),
        };
        let validated = validate_skill_runtime_contract(&native_source).expect("valid native MCP");
        let native_mcp = StrategyAdapterContract::compile(validated).unwrap();
        assert_eq!(native_mcp.kind(), StrategyAdapterKind::Mcp);
        assert_eq!(native_mcp.auth_kind(), AuthKind::NativePermission);
        assert_eq!(
            native_mcp
                .status(StrategyStateRevision::new(1).unwrap(), AuthState::Denied)
                .unwrap()
                .pending_action()
                .unwrap()
                .action(),
            StrategyPendingActionKind::OpenSystemSettings
        );
        assert!(StrategyInvalidation::new(
            native_mcp,
            StrategyInvalidationCause::NativePermissionChanged,
            StrategyStateRevision::new(2).unwrap(),
        )
        .is_ok());
    }

    #[test]
    fn denied_native_permission_points_to_settings_not_a_false_grant() {
        let pending = compile(StrategyAdapterKind::NativePermission)
            .status(StrategyStateRevision::new(1).unwrap(), AuthState::Denied)
            .unwrap()
            .pending_action()
            .unwrap();
        assert_eq!(
            pending.action(),
            StrategyPendingActionKind::OpenSystemSettings
        );
    }

    #[test]
    fn mcp_only_pending_protocol_states_fail_closed_on_other_strategies() {
        let revision = StrategyStateRevision::new(1).unwrap();
        let mcp = compile(StrategyAdapterKind::Mcp);
        assert_eq!(
            StrategyPendingAction::additional_input(mcp, revision)
                .unwrap()
                .action(),
            StrategyPendingActionKind::AdditionalInput
        );
        assert_eq!(
            StrategyPendingAction::remote_task(mcp, revision)
                .unwrap()
                .action(),
            StrategyPendingActionKind::RemoteTask
        );
        let browser = compile(StrategyAdapterKind::BrowserProfile);
        assert_eq!(
            StrategyPendingAction::remote_task(browser, revision)
                .unwrap_err()
                .code,
            StrategyAdapterContractErrorCode::IncompatiblePendingAction
        );
    }

    #[test]
    fn approval_projection_is_not_an_authorization_receipt() {
        let requirement = compile(StrategyAdapterKind::Mcp).approval_requirement();
        assert_eq!(
            requirement.minimum_class(),
            ApprovalClass::ConditionalExternalSideEffect
        );
        let pending = requirement
            .pending_action(
                StrategyStateRevision::new(3).unwrap(),
                StrategyApprovalDecision::Required,
            )
            .unwrap();
        assert_eq!(pending.action(), StrategyPendingActionKind::Approval);
        assert_eq!(
            pending.approval_class(),
            Some(ApprovalClass::ConditionalExternalSideEffect)
        );

        let mut ordinary = contract(StrategyAdapterKind::Mcp);
        ordinary.policy_floor.approval = ApprovalClass::Ordinary;
        let validated = validate_skill_runtime_contract(&ordinary).unwrap();
        let requirement = StrategyAdapterContract::compile(validated)
            .unwrap()
            .approval_requirement();
        assert_eq!(
            requirement.pending_action(
                StrategyStateRevision::new(4).unwrap(),
                StrategyApprovalDecision::NotRequired,
            ),
            None
        );
        assert!(requirement
            .pending_action(
                StrategyStateRevision::new(4).unwrap(),
                StrategyApprovalDecision::Required,
            )
            .is_some());
    }

    #[test]
    fn invocation_outcomes_keep_payloads_opaque_and_delivery_explicit() {
        let success = StrategyCompletion::success(vec!["provider payload"]);
        assert_eq!(success.kind(), StrategyCompletionKind::Success);
        assert_eq!(success.result(), &["provider payload"]);
        assert_eq!(success.into_result(), vec!["provider payload"]);

        let cases = [
            (
                StrategyDispatchCertainty::NotDispatched,
                StrategyRetryDisposition::SafeBeforeDispatch,
            ),
            (
                StrategyDispatchCertainty::Dispatched,
                StrategyRetryDisposition::RequiresIdempotencyDecision,
            ),
            (
                StrategyDispatchCertainty::UnknownAfterDispatch,
                StrategyRetryDisposition::NeverAutomatic,
            ),
        ];
        for (dispatch, expected) in cases {
            let failure = StrategyInvocationFailure::new(
                StrategyInvocationFailureCode::TransportFailure,
                dispatch,
            )
            .unwrap();
            assert_eq!(failure.retry_disposition(), expected);
        }

        assert_eq!(
            StrategyInvocationFailure::new(
                StrategyInvocationFailureCode::PolicyDenied,
                StrategyDispatchCertainty::UnknownAfterDispatch,
            )
            .unwrap_err()
            .code,
            StrategyAdapterContractErrorCode::InvalidInvocationFailure
        );
        assert_eq!(
            StrategyInvocationFailure::new(
                StrategyInvocationFailureCode::MalformedResponse,
                StrategyDispatchCertainty::NotDispatched,
            )
            .unwrap_err()
            .code,
            StrategyAdapterContractErrorCode::InvalidInvocationFailure
        );

        let pending = StrategyPendingAction::remote_task(
            compile(StrategyAdapterKind::Mcp),
            StrategyStateRevision::new(1).unwrap(),
        )
        .unwrap();
        assert_eq!(
            pending.dispatch_certainty(),
            StrategyDispatchCertainty::Dispatched
        );
        let outcome: StrategyInvocationOutcome<Vec<u8>> =
            StrategyInvocationOutcome::Pending(pending);
        assert!(matches!(outcome, StrategyInvocationOutcome::Pending(_)));
    }

    #[test]
    fn invalidation_semantics_are_common_but_strategy_scoped() {
        let revision = StrategyStateRevision::new(2).unwrap();
        let policy = StrategyInvalidation::new(
            compile(StrategyAdapterKind::NativePermission),
            StrategyInvalidationCause::PolicyChanged,
            revision,
        )
        .unwrap();
        assert_eq!(
            policy.effect().auth_status(),
            StrategyInvalidationDisposition::Preserve
        );
        assert_eq!(
            policy.effect().approval(),
            StrategyInvalidationDisposition::Invalidate
        );
        assert_eq!(
            policy.effect().auth_interactions(),
            StrategyInvalidationDisposition::Preserve
        );
        assert_eq!(
            policy.effect().invocations(),
            StrategyInvalidationDisposition::Invalidate
        );

        let auth = StrategyInvalidation::new(
            compile(StrategyAdapterKind::Mcp),
            StrategyInvalidationCause::ResourceBindingChanged,
            revision,
        )
        .unwrap();
        assert_eq!(
            auth.effect().auth_status(),
            StrategyInvalidationDisposition::Invalidate
        );
        assert_eq!(
            auth.effect().session(),
            StrategyInvalidationDisposition::Invalidate
        );

        assert_eq!(
            StrategyInvalidation::new(
                compile(StrategyAdapterKind::BrowserProfile),
                StrategyInvalidationCause::NativePermissionChanged,
                revision,
            )
            .unwrap_err()
            .code,
            StrategyAdapterContractErrorCode::IncompatibleInvalidation
        );
    }

    #[test]
    fn invalidation_revision_prevents_stale_status_reuse() {
        let contract = compile(StrategyAdapterKind::Mcp);
        let status = contract
            .status(StrategyStateRevision::new(4).unwrap(), AuthState::Ready)
            .unwrap();
        let stale = StrategyInvalidation::new(
            contract,
            StrategyInvalidationCause::CredentialChanged,
            StrategyStateRevision::new(4).unwrap(),
        )
        .unwrap();
        let fresh = StrategyInvalidation::new(
            contract,
            StrategyInvalidationCause::CredentialChanged,
            StrategyStateRevision::new(5).unwrap(),
        )
        .unwrap();
        assert!(!stale.supersedes(status));
        assert!(fresh.supersedes(status));
        assert_eq!(
            StrategyStateRevision::new(u64::MAX)
                .unwrap()
                .next()
                .unwrap_err()
                .code,
            StrategyAdapterContractErrorCode::InvalidRevision
        );
    }

    #[test]
    fn contract_and_status_walks_remain_iterative_on_a_small_stack() {
        thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(|| {
                let contracts = [
                    compile(StrategyAdapterKind::Mcp),
                    compile(StrategyAdapterKind::BrowserProfile),
                    compile(StrategyAdapterKind::NativePermission),
                    compile(StrategyAdapterKind::DelegatedCredential),
                ];
                let states = [
                    AuthState::Unknown,
                    AuthState::Missing,
                    AuthState::InteractionRequired,
                    AuthState::Authenticating,
                    AuthState::Ready,
                    AuthState::Expired,
                    AuthState::Revoked,
                    AuthState::IdentityMismatch,
                    AuthState::Denied,
                    AuthState::Error,
                ];
                let causes = [
                    StrategyInvalidationCause::ProcessRestart,
                    StrategyInvalidationCause::AuthenticationFailure,
                    StrategyInvalidationCause::CredentialChanged,
                    StrategyInvalidationCause::BrowserSessionChanged,
                    StrategyInvalidationCause::NativePermissionChanged,
                    StrategyInvalidationCause::DelegatedGrantChanged,
                    StrategyInvalidationCause::AuthorizationServerChanged,
                    StrategyInvalidationCause::ResourceBindingChanged,
                    StrategyInvalidationCause::ScopeChanged,
                    StrategyInvalidationCause::PolicyChanged,
                    StrategyInvalidationCause::TransportClosed,
                ];
                let mut revision = StrategyStateRevision::new(1).unwrap();
                for index in 0..20_000 {
                    let contract = contracts[index % contracts.len()];
                    let state = states[index % states.len()];
                    let status = contract.status(revision, state).unwrap();
                    if status.is_ready(StrategyAuthDemand::AuthenticationRequired) {
                        assert!(status.pending_action().is_err());
                    } else {
                        assert!(status.pending_action().is_ok());
                    }
                    let _ = StrategyInvalidation::new(
                        contract,
                        causes[index % causes.len()],
                        revision.next().unwrap(),
                    );
                    revision = revision.next().unwrap();
                }
            })
            .expect("spawn small-stack test")
            .join()
            .expect("iterative contract walk");
    }

    #[test]
    fn arbitrary_provider_payloads_have_no_generic_debug_or_serialization_escape() {
        assert_not_impl_any!(StrategyCompletion<Vec<u8>>: fmt::Debug, Serialize);
        assert_not_impl_any!(StrategyInvocationOutcome<Vec<u8>>: fmt::Debug, Serialize);
    }
}
