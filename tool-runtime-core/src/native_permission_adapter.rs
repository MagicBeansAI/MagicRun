//! Truthful native-permission status projection without permission authority.
//!
//! The operating-system integration remains the only owner of permission queries,
//! prompts, settings navigation, and native handles. This module accepts a typed,
//! metadata-only observation from that owner and projects it into the common strategy
//! status vocabulary plus exact product guidance. A `ready` projection is observational
//! only: it cannot grant a permission or authorize native dispatch, and the native owner
//! must query the operating system again at the actual use boundary.

use std::{error::Error, fmt, num::NonZeroU64};

use serde::Serialize;

use crate::{
    manifest::{AuthKind, AuthState, AuthStorage, ProfileSelection},
    manifest_validation::ValidatedSkillRuntimeContract,
    strategy_adapter::{
        StrategyAdapterContract, StrategyAdapterKind, StrategyAuthStatus, StrategyStateRevision,
    },
};

pub const NATIVE_PERMISSION_PROJECTION_V1: &str = "tool-runtime.native-permission-projection.v1";

/// Product-supported permission classes. These are deliberately closed and contain no
/// bundle identifier, target application, device id, or operating-system handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativePermissionKind {
    Accessibility,
    ScreenRecording,
    Microphone,
    Notifications,
    Automation,
}

impl NativePermissionKind {
    pub const ALL: [Self; 5] = [
        Self::Accessibility,
        Self::ScreenRecording,
        Self::Microphone,
        Self::Notifications,
        Self::Automation,
    ];
}

/// Opaque digest of the native permission subject and, where applicable, target.
///
/// Accessibility, Screen Recording, Microphone, and Notifications are tied to an OS
/// subject; Automation is additionally target-specific. The trusted native owner
/// computes this domain-separated digest. It is equality-only, non-debuggable, and
/// non-serializable, and is not a permission or dispatch authority.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NativePermissionBindingId([u8; 32]);

impl NativePermissionBindingId {
    pub fn from_digest(digest: [u8; 32]) -> Result<Self, NativePermissionAdapterError> {
        if digest == [0; 32] {
            return Err(invalid_binding());
        }
        Ok(Self(digest))
    }
}

/// Authoritative state reported by the operating-system integration.
///
/// `Requesting` means the OS owns an outstanding decision UI. `Error` means the state
/// could not be observed and never degrades to a grant. `Unavailable` is a stable host
/// capability result rather than an authentication failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativePermissionAuthorityState {
    NotDetermined,
    Requesting,
    Granted,
    Denied,
    Restricted,
    Unavailable,
    Error,
}

/// Monotonic revision assigned by the native permission owner. A zero revision cannot
/// enter an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NativePermissionRevision(NonZeroU64);

impl NativePermissionRevision {
    pub fn new(value: u64) -> Result<Self, NativePermissionAdapterError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(invalid_revision)
    }

    pub fn get(self) -> u64 {
        self.0.get()
    }
}

impl TryFrom<u64> for NativePermissionRevision {
    type Error = NativePermissionAdapterError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Metadata-only observation from the trusted native integration.
///
/// This is intentionally not serializable or debuggable. Its fields are closed enums,
/// an opaque equality-only binding, and a revision, so a native permission handle cannot
/// be smuggled through it.
pub struct NativePermissionObservation {
    kind: NativePermissionKind,
    binding: NativePermissionBindingId,
    revision: NativePermissionRevision,
    state: NativePermissionAuthorityState,
}

impl NativePermissionObservation {
    pub fn new(
        kind: NativePermissionKind,
        binding: NativePermissionBindingId,
        revision: NativePermissionRevision,
        state: NativePermissionAuthorityState,
    ) -> Self {
        Self {
            kind,
            binding,
            revision,
            state,
        }
    }

    pub fn kind(&self) -> NativePermissionKind {
        self.kind
    }

    pub fn revision(&self) -> NativePermissionRevision {
        self.revision
    }

    pub fn state(&self) -> NativePermissionAuthorityState {
        self.state
    }
}

/// Exact product guidance accompanying the common authentication status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativePermissionGuidance {
    None,
    RequestFromOperatingSystem,
    AwaitOperatingSystemDecision,
    OpenSystemSettings,
    RestrictedBySystemOrAdministrator,
    UnavailableOnThisHost,
    RecheckPermissionStatus,
}

/// Safe, non-authorizing projection suitable for product state and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct NativePermissionProjection {
    pub schema_version: &'static str,
    permission: NativePermissionKind,
    status: StrategyAuthStatus,
    guidance: NativePermissionGuidance,
}

impl NativePermissionProjection {
    pub fn permission(self) -> NativePermissionKind {
        self.permission
    }

    pub fn status(self) -> StrategyAuthStatus {
        self.status
    }

    pub fn guidance(self) -> NativePermissionGuidance {
        self.guidance
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativePermissionAdapterErrorCode {
    ContractMismatch,
    PermissionMismatch,
    BindingMismatch,
    InvalidBinding,
    InvalidRevision,
}

/// Stable, value-free diagnostic. Platform/provider names and OS error payloads remain
/// with the native owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct NativePermissionAdapterError {
    pub code: NativePermissionAdapterErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl NativePermissionAdapterError {
    const fn new(
        code: NativePermissionAdapterErrorCode,
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

impl fmt::Display for NativePermissionAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for NativePermissionAdapterError {}

/// Pure adapter bound to one validated native permission requirement.
///
/// The adapter has no request, settings, or dispatch method by design. Those effects
/// must be performed by the trusted OS integration after product policy admits them.
pub struct NativePermissionAdapter {
    strategy: StrategyAdapterContract,
    permission: NativePermissionKind,
    binding: NativePermissionBindingId,
}

impl NativePermissionAdapter {
    pub fn new(
        validated: ValidatedSkillRuntimeContract<'_>,
        permission: NativePermissionKind,
        binding: NativePermissionBindingId,
    ) -> Result<Self, NativePermissionAdapterError> {
        let contract = validated.contract();
        if contract.auth.kind != AuthKind::NativePermission
            || contract.auth.storage != AuthStorage::OperatingSystem
            || contract.auth.profile_selection != ProfileSelection::None
        {
            return Err(contract_mismatch());
        }
        let strategy =
            StrategyAdapterContract::compile(validated).map_err(|_| contract_mismatch())?;
        if strategy.auth_kind() != AuthKind::NativePermission
            || !matches!(
                strategy.kind(),
                StrategyAdapterKind::NativePermission | StrategyAdapterKind::Mcp
            )
        {
            return Err(contract_mismatch());
        }
        Ok(Self {
            strategy,
            permission,
            binding,
        })
    }

    /// Project one authoritative observation. This method performs no I/O and returns
    /// no dispatch authority even when the state is `Granted`.
    pub fn project(
        &self,
        observation: &NativePermissionObservation,
    ) -> Result<NativePermissionProjection, NativePermissionAdapterError> {
        if observation.kind != self.permission {
            return Err(permission_mismatch());
        }
        if observation.binding != self.binding {
            return Err(binding_mismatch());
        }
        let (state, guidance) = match observation.state {
            NativePermissionAuthorityState::NotDetermined => (
                AuthState::InteractionRequired,
                NativePermissionGuidance::RequestFromOperatingSystem,
            ),
            NativePermissionAuthorityState::Requesting => (
                AuthState::Authenticating,
                NativePermissionGuidance::AwaitOperatingSystemDecision,
            ),
            NativePermissionAuthorityState::Granted => {
                (AuthState::Ready, NativePermissionGuidance::None)
            },
            NativePermissionAuthorityState::Denied => (
                AuthState::Denied,
                NativePermissionGuidance::OpenSystemSettings,
            ),
            NativePermissionAuthorityState::Restricted => (
                AuthState::Denied,
                NativePermissionGuidance::RestrictedBySystemOrAdministrator,
            ),
            NativePermissionAuthorityState::Unavailable => (
                AuthState::Error,
                NativePermissionGuidance::UnavailableOnThisHost,
            ),
            NativePermissionAuthorityState::Error => (
                AuthState::Error,
                NativePermissionGuidance::RecheckPermissionStatus,
            ),
        };
        let revision = StrategyStateRevision::new(observation.revision.get())
            .map_err(|_| invalid_revision())?;
        let status = self
            .strategy
            .status(revision, state)
            .map_err(|_| contract_mismatch())?;
        Ok(NativePermissionProjection {
            schema_version: NATIVE_PERMISSION_PROJECTION_V1,
            permission: self.permission,
            status,
            guidance,
        })
    }
}

const fn contract_mismatch() -> NativePermissionAdapterError {
    NativePermissionAdapterError::new(
        NativePermissionAdapterErrorCode::ContractMismatch,
        "runtime_contract",
        "the validated contract is not compatible with native permission projection",
    )
}

const fn permission_mismatch() -> NativePermissionAdapterError {
    NativePermissionAdapterError::new(
        NativePermissionAdapterErrorCode::PermissionMismatch,
        "permission",
        "the operating-system observation is for a different permission",
    )
}

const fn binding_mismatch() -> NativePermissionAdapterError {
    NativePermissionAdapterError::new(
        NativePermissionAdapterErrorCode::BindingMismatch,
        "permission_binding",
        "the operating-system observation is for a different native subject or target",
    )
}

const fn invalid_binding() -> NativePermissionAdapterError {
    NativePermissionAdapterError::new(
        NativePermissionAdapterErrorCode::InvalidBinding,
        "permission_binding",
        "the native permission binding digest must be initialized",
    )
}

const fn invalid_revision() -> NativePermissionAdapterError {
    NativePermissionAdapterError::new(
        NativePermissionAdapterErrorCode::InvalidRevision,
        "revision",
        "the native permission observation revision must be non-zero",
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fmt, thread};

    use static_assertions::assert_not_impl_any;

    use super::*;
    use crate::{
        manifest::{
            ApprovalClass, AuthContract, AuthRequirement, McpDiscoveryPolicy, McpTransport,
            PolicyFloor, RuntimeLimits, RuntimeProtocol, RuntimeRequirements, SkillRuntimeContract,
            SkillRuntimeContractVersion,
        },
        manifest_validation::validate_skill_runtime_contract,
        strategy_adapter::{StrategyAuthDemand, StrategyAuthReadiness, StrategyPendingActionKind},
    };

    fn cli_contract() -> SkillRuntimeContract {
        SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires: RuntimeRequirements {
                bins: BTreeSet::from(["native-owner-fixture".to_owned()]),
                entrypoint: Default::default(),
                environment: Default::default(),
            },
            runtime: RuntimeProtocol::Cli {
                command_prefix: Vec::new(),
                interaction: Default::default(),
                stdin: Default::default(),
                working_directory: Default::default(),
                limits: RuntimeLimits::default(),
            },
            auth: AuthContract {
                kind: AuthKind::NativePermission,
                requirement: AuthRequirement::Required,
                provider: Some("macos".to_owned()),
                storage: AuthStorage::OperatingSystem,
                ..AuthContract::default()
            },
            policy_floor: PolicyFloor {
                approval: ApprovalClass::NativeUiControl,
                ..PolicyFloor::default()
            },
        }
    }

    fn stdio_mcp_contract() -> SkillRuntimeContract {
        let mut contract = cli_contract();
        contract.runtime = RuntimeProtocol::Mcp {
            transport: McpTransport::Stdio {
                executable: "native-owner-fixture".to_owned(),
                args: Vec::new(),
            },
            discovery: McpDiscoveryPolicy::default(),
            limits: RuntimeLimits::default(),
        };
        contract
    }

    fn adapter(permission: NativePermissionKind) -> NativePermissionAdapter {
        let source = cli_contract();
        let validated = validate_skill_runtime_contract(&source).expect("contract");
        NativePermissionAdapter::new(validated, permission, binding(7)).expect("adapter")
    }

    fn binding(byte: u8) -> NativePermissionBindingId {
        NativePermissionBindingId::from_digest([byte; 32]).expect("binding")
    }

    fn observation(
        permission: NativePermissionKind,
        state: NativePermissionAuthorityState,
    ) -> NativePermissionObservation {
        NativePermissionObservation::new(
            permission,
            binding(7),
            NativePermissionRevision::new(7).expect("revision"),
            state,
        )
    }

    #[test]
    fn all_supported_permissions_project_from_the_same_platform_contract() {
        for permission in NativePermissionKind::ALL {
            let adapter = adapter(permission);
            let projected = adapter
                .project(&observation(
                    permission,
                    NativePermissionAuthorityState::Granted,
                ))
                .expect("projection");
            assert_eq!(projected.permission(), permission);
            assert_eq!(projected.status().state(), AuthState::Ready);
            assert_eq!(projected.guidance(), NativePermissionGuidance::None);
        }
    }

    #[test]
    fn authoritative_states_have_exact_status_and_guidance() {
        let cases = [
            (
                NativePermissionAuthorityState::NotDetermined,
                AuthState::InteractionRequired,
                NativePermissionGuidance::RequestFromOperatingSystem,
            ),
            (
                NativePermissionAuthorityState::Requesting,
                AuthState::Authenticating,
                NativePermissionGuidance::AwaitOperatingSystemDecision,
            ),
            (
                NativePermissionAuthorityState::Granted,
                AuthState::Ready,
                NativePermissionGuidance::None,
            ),
            (
                NativePermissionAuthorityState::Denied,
                AuthState::Denied,
                NativePermissionGuidance::OpenSystemSettings,
            ),
            (
                NativePermissionAuthorityState::Restricted,
                AuthState::Denied,
                NativePermissionGuidance::RestrictedBySystemOrAdministrator,
            ),
            (
                NativePermissionAuthorityState::Unavailable,
                AuthState::Error,
                NativePermissionGuidance::UnavailableOnThisHost,
            ),
            (
                NativePermissionAuthorityState::Error,
                AuthState::Error,
                NativePermissionGuidance::RecheckPermissionStatus,
            ),
        ];
        let adapter = adapter(NativePermissionKind::Microphone);
        for (authority_state, status, guidance) in cases {
            let projected = adapter
                .project(&observation(
                    NativePermissionKind::Microphone,
                    authority_state,
                ))
                .expect("projection");
            assert_eq!(projected.status().state(), status);
            assert_eq!(projected.guidance(), guidance);
        }
    }

    #[test]
    fn denied_restricted_unavailable_and_observation_error_remain_distinct() {
        let adapter = adapter(NativePermissionKind::Notifications);
        let denied = adapter
            .project(&observation(
                NativePermissionKind::Notifications,
                NativePermissionAuthorityState::Denied,
            ))
            .expect("denied");
        let restricted = adapter
            .project(&observation(
                NativePermissionKind::Notifications,
                NativePermissionAuthorityState::Restricted,
            ))
            .expect("restricted");
        let unavailable = adapter
            .project(&observation(
                NativePermissionKind::Notifications,
                NativePermissionAuthorityState::Unavailable,
            ))
            .expect("unavailable");
        let failed = adapter
            .project(&observation(
                NativePermissionKind::Notifications,
                NativePermissionAuthorityState::Error,
            ))
            .expect("failed observation");

        assert_eq!(
            denied.status().pending_action().expect("pending").action(),
            StrategyPendingActionKind::OpenSystemSettings
        );
        assert_eq!(
            [
                denied.guidance(),
                restricted.guidance(),
                unavailable.guidance(),
                failed.guidance(),
            ],
            [
                NativePermissionGuidance::OpenSystemSettings,
                NativePermissionGuidance::RestrictedBySystemOrAdministrator,
                NativePermissionGuidance::UnavailableOnThisHost,
                NativePermissionGuidance::RecheckPermissionStatus,
            ]
        );
    }

    #[test]
    fn projection_rejects_an_observation_for_another_permission() {
        let adapter = adapter(NativePermissionKind::Accessibility);
        let error = adapter
            .project(&observation(
                NativePermissionKind::ScreenRecording,
                NativePermissionAuthorityState::Granted,
            ))
            .expect_err("wrong permission");
        assert_eq!(
            error.code,
            NativePermissionAdapterErrorCode::PermissionMismatch
        );
    }

    #[test]
    fn subject_or_automation_target_binding_cannot_be_crossed() {
        let adapter = adapter(NativePermissionKind::Automation);
        let observation = NativePermissionObservation::new(
            NativePermissionKind::Automation,
            binding(8),
            NativePermissionRevision::new(7).expect("revision"),
            NativePermissionAuthorityState::Granted,
        );
        let error = adapter
            .project(&observation)
            .expect_err("wrong target binding");
        assert_eq!(
            error.code,
            NativePermissionAdapterErrorCode::BindingMismatch
        );
        assert!(!serde_json::to_string(&error).unwrap().contains('8'));
    }

    #[test]
    fn non_native_contract_is_rejected_without_provider_data() {
        let mut source = cli_contract();
        source.auth = AuthContract::default();
        let validated = validate_skill_runtime_contract(&source).expect("contract");
        let error =
            NativePermissionAdapter::new(validated, NativePermissionKind::Automation, binding(7))
                .err()
                .expect("contract mismatch");
        assert_eq!(
            error.code,
            NativePermissionAdapterErrorCode::ContractMismatch
        );
        assert!(!serde_json::to_string(&error).unwrap().contains("macos"));
    }

    #[test]
    fn stdio_mcp_keeps_protocol_ownership_while_using_native_auth() {
        let source = stdio_mcp_contract();
        let validated = validate_skill_runtime_contract(&source).expect("contract");
        let adapter = NativePermissionAdapter::new(
            validated,
            NativePermissionKind::ScreenRecording,
            binding(7),
        )
        .expect("adapter");
        let projected = adapter
            .project(&observation(
                NativePermissionKind::ScreenRecording,
                NativePermissionAuthorityState::Granted,
            ))
            .expect("projection");
        assert_eq!(projected.status().kind(), StrategyAdapterKind::Mcp);
        assert_eq!(projected.status().auth_kind(), AuthKind::NativePermission);
        assert_eq!(
            projected
                .status()
                .readiness(StrategyAuthDemand::AuthenticationRequired),
            StrategyAuthReadiness::Ready
        );
    }

    #[test]
    fn safe_projection_contains_no_provider_or_native_payload() {
        let projected = adapter(NativePermissionKind::Automation)
            .project(&observation(
                NativePermissionKind::Automation,
                NativePermissionAuthorityState::Restricted,
            ))
            .expect("projection");
        let json = serde_json::to_string(&projected).expect("safe projection");
        assert!(json.contains("automation"));
        assert!(json.contains("restricted_by_system_or_administrator"));
        assert!(!json.contains("macos"));
        assert!(!json.contains("handle"));
        assert!(!json.contains("bundle"));
        assert!(!json.contains("target"));
    }

    #[test]
    fn observation_and_adapter_cannot_become_generic_payloads_or_authorities() {
        assert_not_impl_any!(NativePermissionBindingId: fmt::Debug, serde::Serialize);
        assert_not_impl_any!(NativePermissionObservation: Clone, Copy, fmt::Debug, serde::Serialize);
        assert_not_impl_any!(NativePermissionAdapter: Clone, Copy, fmt::Debug, serde::Serialize);
    }

    #[test]
    fn uninitialized_binding_is_value_free() {
        let error = match NativePermissionBindingId::from_digest([0; 32]) {
            Ok(_) => panic!("zero binding must fail"),
            Err(error) => error,
        };
        assert_eq!(error.code, NativePermissionAdapterErrorCode::InvalidBinding);
        assert_eq!(
            serde_json::to_string(&error).expect("safe error"),
            r#"{"code":"invalid_binding","field":"permission_binding","message":"the native permission binding digest must be initialized"}"#
        );
    }

    #[test]
    fn invalid_zero_revision_is_value_free() {
        let error = NativePermissionRevision::new(0).expect_err("zero revision");
        assert_eq!(
            error.code,
            NativePermissionAdapterErrorCode::InvalidRevision
        );
        assert_eq!(
            serde_json::to_string(&error).expect("safe error"),
            r#"{"code":"invalid_revision","field":"revision","message":"the native permission observation revision must be non-zero"}"#
        );
    }

    #[test]
    fn repeated_projection_is_iterative_on_a_small_stack() {
        thread::Builder::new()
            .name("native-permission-small-stack".to_owned())
            .stack_size(64 * 1024)
            .spawn(|| {
                let adapter = adapter(NativePermissionKind::Accessibility);
                let observation = observation(
                    NativePermissionKind::Accessibility,
                    NativePermissionAuthorityState::Granted,
                );
                for _ in 0..100_000 {
                    assert_eq!(
                        adapter
                            .project(&observation)
                            .expect("projection")
                            .status()
                            .state(),
                        AuthState::Ready
                    );
                }
            })
            .expect("spawn")
            .join()
            .expect("projection must not panic or overflow");
    }
}
