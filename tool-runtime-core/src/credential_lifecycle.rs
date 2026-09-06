//! Exact, registry-bound command authority for CLI authentication lifecycles.
//!
//! Phase 4A compiles a validated runtime contract and trusted profile metadata into an
//! immutable lifecycle plan. It does not resolve an executable path, open a profile
//! directory, spawn a process, interpret output, cache status, acquire a login lease, or
//! enable a production route. In particular, lifecycle argv never comes from model input
//! and never inherits the model-facing CLI command prefix.

use std::{error::Error, fmt};

use serde::Serialize;

use crate::{
    credential_profiles::{
        CredentialProfileAvailability, CredentialProfileBinding, CredentialProfileKey,
        CredentialProfileRegistry, CredentialProfileRevision, CredentialProfileStatus,
        CredentialProviderId, CredentialScope, ExpectedCredentialIdentity,
    },
    manifest::{
        AuthKind, CliInteraction, IdentityContract, LifecycleHook, LifecycleStatusObservation,
        ProfileSelection, RuntimeProtocol, SkillRuntimeContract,
    },
    manifest_validation::ValidatedSkillRuntimeContract,
};

pub const CREDENTIAL_LIFECYCLE_PLAN_V1: &str = "tool-runtime.credential-lifecycle-plan.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialLifecycleOperation {
    Status,
    Login,
    Logout,
    Refresh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialLifecycleErrorCode {
    UnsupportedContract,
    TargetMismatch,
    ProfileDisabled,
    ProfileNotFound,
    RegistryUnavailable,
    HookUnavailable,
    MissingExpectedIdentity,
}

/// Stable, value-free lifecycle planning diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CredentialLifecycleError {
    pub code: CredentialLifecycleErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl CredentialLifecycleError {
    const fn new(
        code: CredentialLifecycleErrorCode,
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

impl fmt::Display for CredentialLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for CredentialLifecycleError {}

#[derive(Clone, PartialEq, Eq)]
enum CredentialLifecycleTarget {
    Profile {
        key: CredentialProfileKey,
        revision: CredentialProfileRevision,
        expected_identity: Option<ExpectedCredentialIdentity>,
    },
    Implicit {
        scope: CredentialScope,
        provider: CredentialProviderId,
        binding: CredentialProfileBinding,
    },
}

/// Immutable command authority for one declared lifecycle operation.
///
/// Fields are private and the type is intentionally not serializable. Product code can
/// hand the exact executable identity and argv to the later governed lifecycle executor,
/// but cannot construct or rewrite a plan without crossing this compiler again.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialLifecyclePlan {
    schema_version: &'static str,
    contract: SkillRuntimeContract,
    operation: CredentialLifecycleOperation,
    target: CredentialLifecycleTarget,
    auth_kind: AuthKind,
    executable: String,
    args: Vec<String>,
    interaction: CliInteraction,
    timeout_secs: Option<u32>,
    status_observation: Option<LifecycleStatusObservation>,
    identity_contract: IdentityContract,
}

impl fmt::Debug for CredentialLifecyclePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialLifecyclePlan")
            .field("schema_version", &self.schema_version)
            .field("operation", &self.operation)
            .field("auth_kind", &self.auth_kind)
            .field("target_mode", &self.target_mode())
            .field("argument_count", &self.args.len())
            .field("interaction", &self.interaction)
            .field("timeout_secs", &self.timeout_secs)
            .finish()
    }
}

impl CredentialLifecyclePlan {
    /// Compile a lifecycle operation for an exact metadata/status record returned by the
    /// credential-profile registry. Selectable profiles may vary only through that trusted
    /// record; fixed profiles must match the manifest alias exactly.
    pub fn for_profile(
        registry: &dyn CredentialProfileRegistry,
        validated: ValidatedSkillRuntimeContract<'_>,
        key: &CredentialProfileKey,
        operation: CredentialLifecycleOperation,
    ) -> Result<Self, CredentialLifecycleError> {
        let contract = validated.contract();
        let executable = lifecycle_executable(contract)?;
        let provider = contract
            .auth
            .provider
            .as_deref()
            .ok_or_else(unsupported_contract)?;

        if key.provider.as_str() != provider
            || !matches!(&key.binding, CredentialProfileBinding::Provider)
            || !profile_selection_accepts_key(&contract.auth.profile_selection, key)
        {
            return Err(target_mismatch());
        }
        let profile = registry
            .status(key)
            .map_err(|_| registry_unavailable())?
            .ok_or_else(profile_not_found)?;
        if profile.key() != key {
            return Err(registry_unavailable());
        }
        Self::for_registry_status(contract, executable, &profile, operation)
    }

    fn for_registry_status(
        contract: &crate::manifest::SkillRuntimeContract,
        executable: &str,
        profile: &CredentialProfileStatus,
        operation: CredentialLifecycleOperation,
    ) -> Result<Self, CredentialLifecycleError> {
        let metadata = profile.metadata();
        if metadata.availability() == CredentialProfileAvailability::Disabled
            && matches!(
                operation,
                CredentialLifecycleOperation::Login | CredentialLifecycleOperation::Refresh
            )
        {
            return Err(profile_disabled());
        }
        if matches!(
            &contract.auth.identity,
            IdentityContract::ProfileExpected { .. }
        ) && metadata.expected_identity().is_none()
        {
            return Err(missing_expected_identity());
        }

        let hook = lifecycle_hook(contract, operation)?;
        Ok(Self::from_hook(
            operation,
            CredentialLifecycleTarget::Profile {
                key: metadata.key().clone(),
                revision: metadata.revision(),
                expected_identity: metadata.expected_identity().cloned(),
            },
            contract,
            executable,
            hook,
        ))
    }

    /// Compile a lifecycle operation for a CLI-owned implicit identity. The caller supplies
    /// only the trusted product scope; provider and binding are derived from the validated
    /// contract, so no profile alias or provider override can cross this boundary.
    pub fn for_implicit(
        validated: ValidatedSkillRuntimeContract<'_>,
        scope: CredentialScope,
        operation: CredentialLifecycleOperation,
    ) -> Result<Self, CredentialLifecycleError> {
        let contract = validated.contract();
        let executable = lifecycle_executable(contract)?;
        if !matches!(&contract.auth.profile_selection, ProfileSelection::Implicit) {
            return Err(target_mismatch());
        }
        let provider = contract
            .auth
            .provider
            .as_deref()
            .ok_or_else(unsupported_contract)
            .and_then(|value| {
                CredentialProviderId::new(value.to_owned()).map_err(|_| unsupported_contract())
            })?;
        let hook = lifecycle_hook(contract, operation)?;
        Ok(Self::from_hook(
            operation,
            CredentialLifecycleTarget::Implicit {
                scope,
                provider,
                binding: CredentialProfileBinding::Provider,
            },
            contract,
            executable,
            hook,
        ))
    }

    fn from_hook(
        operation: CredentialLifecycleOperation,
        target: CredentialLifecycleTarget,
        contract: &crate::manifest::SkillRuntimeContract,
        executable: &str,
        hook: &LifecycleHook,
    ) -> Self {
        Self {
            schema_version: CREDENTIAL_LIFECYCLE_PLAN_V1,
            contract: contract.clone(),
            operation,
            target,
            auth_kind: contract.auth.kind,
            executable: executable.to_owned(),
            args: hook.args.clone(),
            interaction: hook.interaction,
            timeout_secs: hook.timeout_secs,
            status_observation: if operation == CredentialLifecycleOperation::Status {
                contract.auth.lifecycle.status_observation.clone()
            } else {
                None
            },
            identity_contract: contract.auth.identity.clone(),
        }
    }

    pub fn schema_version(&self) -> &'static str {
        self.schema_version
    }

    pub fn operation(&self) -> CredentialLifecycleOperation {
        self.operation
    }

    pub fn auth_kind(&self) -> AuthKind {
        self.auth_kind
    }

    pub fn executable(&self) -> &str {
        &self.executable
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }

    pub fn interaction(&self) -> CliInteraction {
        self.interaction
    }

    pub fn timeout_secs(&self) -> Option<u32> {
        self.timeout_secs
    }

    pub fn scope(&self) -> &CredentialScope {
        match &self.target {
            CredentialLifecycleTarget::Profile { key, .. } => &key.scope,
            CredentialLifecycleTarget::Implicit { scope, .. } => scope,
        }
    }

    pub fn selected_profile_key(&self) -> Option<&CredentialProfileKey> {
        match &self.target {
            CredentialLifecycleTarget::Profile { key, .. } => Some(key),
            CredentialLifecycleTarget::Implicit { .. } => None,
        }
    }

    pub fn selected_profile_revision(&self) -> Option<CredentialProfileRevision> {
        match &self.target {
            CredentialLifecycleTarget::Profile { revision, .. } => Some(*revision),
            CredentialLifecycleTarget::Implicit { .. } => None,
        }
    }

    pub fn expected_identity(&self) -> Option<&ExpectedCredentialIdentity> {
        match &self.target {
            CredentialLifecycleTarget::Profile {
                expected_identity, ..
            } => expected_identity.as_ref(),
            CredentialLifecycleTarget::Implicit { .. } => None,
        }
    }

    pub fn implicit_identity(&self) -> Option<(&CredentialProviderId, &CredentialProfileBinding)> {
        match &self.target {
            CredentialLifecycleTarget::Implicit {
                provider, binding, ..
            } => Some((provider, binding)),
            CredentialLifecycleTarget::Profile { .. } => None,
        }
    }

    /// Confirm that this immutable plan still belongs to the exact complete validated
    /// contract about to bind its lifecycle environment. The private contract copy has
    /// no debug or serialization surface; it prevents runtime, injection, storage,
    /// policy, identity, target, status, or hook drift from reusing older authority.
    pub fn matches_validated_contract(&self, validated: ValidatedSkillRuntimeContract<'_>) -> bool {
        &self.contract == validated.contract()
    }

    pub(crate) fn status_observation(&self) -> Option<&LifecycleStatusObservation> {
        self.status_observation.as_ref()
    }

    pub(crate) fn identity_contract(&self) -> &IdentityContract {
        &self.identity_contract
    }

    fn target_mode(&self) -> &'static str {
        match &self.target {
            CredentialLifecycleTarget::Profile { .. } => "profile",
            CredentialLifecycleTarget::Implicit { .. } => "implicit",
        }
    }
}

fn lifecycle_executable(
    contract: &crate::manifest::SkillRuntimeContract,
) -> Result<&str, CredentialLifecycleError> {
    if !matches!(
        contract.auth.kind,
        AuthKind::CliProfile | AuthKind::OAuthSession
    ) || !matches!(&contract.runtime, RuntimeProtocol::Cli { .. })
    {
        return Err(unsupported_contract());
    }
    contract
        .requires
        .bins
        .first()
        .map(String::as_str)
        .ok_or_else(unsupported_contract)
}

fn profile_selection_accepts_key(selection: &ProfileSelection, key: &CredentialProfileKey) -> bool {
    match selection {
        ProfileSelection::Selectable { .. } => true,
        ProfileSelection::Fixed { alias } => key.alias.as_str() == alias,
        ProfileSelection::None | ProfileSelection::Implicit => false,
    }
}

fn lifecycle_hook(
    contract: &crate::manifest::SkillRuntimeContract,
    operation: CredentialLifecycleOperation,
) -> Result<&LifecycleHook, CredentialLifecycleError> {
    let hook = match operation {
        CredentialLifecycleOperation::Status => contract.auth.lifecycle.status.as_ref(),
        CredentialLifecycleOperation::Login => contract.auth.lifecycle.login.as_ref(),
        CredentialLifecycleOperation::Logout => contract.auth.lifecycle.logout.as_ref(),
        CredentialLifecycleOperation::Refresh => contract.auth.lifecycle.refresh.as_ref(),
    };
    hook.ok_or_else(hook_unavailable)
}

const fn unsupported_contract() -> CredentialLifecycleError {
    CredentialLifecycleError::new(
        CredentialLifecycleErrorCode::UnsupportedContract,
        "auth.lifecycle",
        "the validated contract does not support a local CLI authentication lifecycle",
    )
}

const fn target_mismatch() -> CredentialLifecycleError {
    CredentialLifecycleError::new(
        CredentialLifecycleErrorCode::TargetMismatch,
        "auth.profile_selection",
        "the lifecycle target does not match the validated profile contract",
    )
}

const fn profile_disabled() -> CredentialLifecycleError {
    CredentialLifecycleError::new(
        CredentialLifecycleErrorCode::ProfileDisabled,
        "profile.availability",
        "a disabled credential profile cannot authenticate or refresh",
    )
}

const fn profile_not_found() -> CredentialLifecycleError {
    CredentialLifecycleError::new(
        CredentialLifecycleErrorCode::ProfileNotFound,
        "profile",
        "the credential profile was not found",
    )
}

const fn registry_unavailable() -> CredentialLifecycleError {
    CredentialLifecycleError::new(
        CredentialLifecycleErrorCode::RegistryUnavailable,
        "registry",
        "the credential profile registry is unavailable",
    )
}

const fn hook_unavailable() -> CredentialLifecycleError {
    CredentialLifecycleError::new(
        CredentialLifecycleErrorCode::HookUnavailable,
        "auth.lifecycle",
        "the requested authentication lifecycle hook is not declared",
    )
}

const fn missing_expected_identity() -> CredentialLifecycleError {
    CredentialLifecycleError::new(
        CredentialLifecycleErrorCode::MissingExpectedIdentity,
        "profile.expected_identity",
        "the credential profile is missing its declared expected identity",
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fmt};

    use serde::Serialize;
    use static_assertions::assert_not_impl_any;

    use super::*;
    use crate::{
        credential_profiles::{
            CreateCredentialProfileReference, CredentialProfileError, CredentialProfileMetadata,
            CredentialProfileRegistrySnapshot, CredentialProfileRevision,
            SetCredentialProfileDisabled, UpdateCredentialProfileMetadata,
        },
        manifest::{
            AuthContract, AuthLifecycle, AuthRequirement, AuthState, AuthStorage, IdentitySelector,
            LifecycleJsonPredicate, LifecycleJsonScalar, LifecycleObservedAuthState,
            LifecycleStatusObservation, LifecycleStatusOutputFormat, LifecycleStatusRule,
            RuntimeRequirements, SkillRuntimeContract, SkillRuntimeContractVersion, StdinContract,
            WorkingDirectoryContract,
        },
        manifest_validation::validate_skill_runtime_contract,
    };

    struct TestRegistry {
        profile: Option<CredentialProfileStatus>,
        fail: bool,
    }

    impl TestRegistry {
        fn one(profile: CredentialProfileStatus) -> Self {
            Self {
                profile: Some(profile),
                fail: false,
            }
        }

        fn missing() -> Self {
            Self {
                profile: None,
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                profile: None,
                fail: true,
            }
        }
    }

    impl CredentialProfileRegistry for TestRegistry {
        fn snapshot(
            &self,
            scope: &CredentialScope,
        ) -> Result<CredentialProfileRegistrySnapshot, CredentialProfileError> {
            if self.fail {
                return Err(CredentialProfileError::registry_unavailable());
            }
            CredentialProfileRegistrySnapshot::new(
                scope.clone(),
                self.profile.iter().cloned().collect(),
            )
        }

        fn status(
            &self,
            _key: &CredentialProfileKey,
        ) -> Result<Option<CredentialProfileStatus>, CredentialProfileError> {
            if self.fail {
                Err(CredentialProfileError::registry_unavailable())
            } else {
                Ok(self.profile.clone())
            }
        }

        fn create_reference(
            &self,
            _request: CreateCredentialProfileReference,
        ) -> Result<CredentialProfileStatus, CredentialProfileError> {
            Err(CredentialProfileError::registry_unavailable())
        }

        fn update_metadata(
            &self,
            _request: UpdateCredentialProfileMetadata,
        ) -> Result<CredentialProfileStatus, CredentialProfileError> {
            Err(CredentialProfileError::registry_unavailable())
        }

        fn set_disabled(
            &self,
            _request: SetCredentialProfileDisabled,
        ) -> Result<CredentialProfileStatus, CredentialProfileError> {
            Err(CredentialProfileError::registry_unavailable())
        }
    }

    fn scope() -> CredentialScope {
        CredentialScope::new("owner", "default").expect("scope")
    }

    fn contract(selection: ProfileSelection) -> SkillRuntimeContract {
        SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires: RuntimeRequirements {
                bins: BTreeSet::from(["gws".to_owned()]),
                entrypoint: Default::default(),
                environment: Default::default(),
            },
            runtime: RuntimeProtocol::Cli {
                command_prefix: vec!["gmail".to_owned()],
                interaction: CliInteraction::Batch,
                stdin: StdinContract::default(),
                working_directory: WorkingDirectoryContract::default(),
                limits: Default::default(),
            },
            auth: AuthContract {
                kind: AuthKind::CliProfile,
                requirement: AuthRequirement::Required,
                provider: Some("google-workspace".to_owned()),
                profile_selection: selection,
                storage: AuthStorage::ScopedDirectory {
                    namespace: "gws".to_owned(),
                    partition_by_profile: true,
                },
                lifecycle: AuthLifecycle {
                    status: Some(LifecycleHook {
                        args: vec![
                            "auth".to_owned(),
                            "status".to_owned(),
                            "--format".to_owned(),
                            "json".to_owned(),
                        ],
                        interaction: CliInteraction::Batch,
                        timeout_secs: Some(30),
                    }),
                    status_observation: Some(LifecycleStatusObservation {
                        format: LifecycleStatusOutputFormat::Json,
                        rules: vec![LifecycleStatusRule {
                            state: LifecycleObservedAuthState::Ready,
                            exit_codes: BTreeSet::from([0]),
                            all: vec![LifecycleJsonPredicate::Equals {
                                pointer: "/ready".to_owned(),
                                value: LifecycleJsonScalar::Boolean { value: true },
                            }],
                        }],
                    }),
                    login: Some(LifecycleHook {
                        args: vec!["auth".to_owned(), "login".to_owned()],
                        interaction: CliInteraction::Pty,
                        timeout_secs: Some(300),
                    }),
                    logout: Some(LifecycleHook {
                        args: vec!["auth".to_owned(), "logout".to_owned()],
                        interaction: CliInteraction::Batch,
                        timeout_secs: Some(30),
                    }),
                    refresh: Some(LifecycleHook {
                        args: vec!["auth".to_owned(), "refresh".to_owned()],
                        interaction: CliInteraction::Batch,
                        timeout_secs: Some(30),
                    }),
                },
                ..AuthContract::default()
            },
            policy_floor: Default::default(),
        }
    }

    fn status(
        alias: &str,
        expected_identity: Option<&str>,
        availability: CredentialProfileAvailability,
        auth_state: AuthState,
    ) -> CredentialProfileStatus {
        let key = CredentialProfileKey::new(
            scope(),
            "google-workspace",
            alias,
            CredentialProfileBinding::Provider,
        )
        .expect("key");
        let metadata = CredentialProfileMetadata::new(
            key,
            expected_identity
                .map(|value| ExpectedCredentialIdentity::new(value.to_owned()).expect("identity")),
            false,
            availability,
            CredentialProfileRevision::new(7).expect("revision"),
        )
        .expect("metadata");
        CredentialProfileStatus::new(metadata, auth_state).expect("status")
    }

    fn plan_for_status(
        validated: ValidatedSkillRuntimeContract<'_>,
        profile: &CredentialProfileStatus,
        operation: CredentialLifecycleOperation,
    ) -> Result<CredentialLifecyclePlan, CredentialLifecycleError> {
        let registry = TestRegistry::one(profile.clone());
        CredentialLifecyclePlan::for_profile(&registry, validated, profile.key(), operation)
    }

    #[test]
    fn selected_plan_uses_only_exact_lifecycle_argv_and_registry_identity() {
        let contract = contract(ProfileSelection::Selectable {
            default: Some("work".to_owned()),
        });
        let validated = validate_skill_runtime_contract(&contract).expect("contract");
        let profile = status(
            "personal",
            Some("person@example.com"),
            CredentialProfileAvailability::Enabled,
            AuthState::Missing,
        );

        let plan = plan_for_status(validated, &profile, CredentialLifecycleOperation::Login)
            .expect("login plan");

        assert_eq!(plan.schema_version(), CREDENTIAL_LIFECYCLE_PLAN_V1);
        assert_eq!(plan.operation(), CredentialLifecycleOperation::Login);
        assert_eq!(plan.executable(), "gws");
        assert_eq!(plan.args(), ["auth", "login"]);
        assert!(!plan.args().iter().any(|argument| argument == "gmail"));
        assert_eq!(plan.interaction(), CliInteraction::Pty);
        assert_eq!(plan.timeout_secs(), Some(300));
        assert_eq!(plan.scope(), &scope());
        assert_eq!(
            plan.selected_profile_key().map(|key| key.alias.as_str()),
            Some("personal")
        );
        assert_eq!(
            plan.selected_profile_revision().map(|value| value.get()),
            Some(7)
        );
        assert_eq!(
            plan.expected_identity()
                .map(ExpectedCredentialIdentity::as_str),
            Some("person@example.com")
        );
    }

    #[test]
    fn fixed_profile_cannot_be_replaced_by_another_registry_target() {
        let contract = contract(ProfileSelection::Fixed {
            alias: "presto".to_owned(),
        });
        let validated = validate_skill_runtime_contract(&contract).expect("contract");
        let wrong = status(
            "work",
            None,
            CredentialProfileAvailability::Enabled,
            AuthState::Missing,
        );

        let registry = TestRegistry::one(wrong.clone());
        let error = CredentialLifecyclePlan::for_profile(
            &registry,
            validated,
            wrong.key(),
            CredentialLifecycleOperation::Login,
        )
        .expect_err("fixed profile override must fail");
        assert_eq!(error.code, CredentialLifecycleErrorCode::TargetMismatch);
    }

    #[test]
    fn profile_provider_and_binding_must_match_the_validated_cli_contract() {
        let contract = contract(ProfileSelection::Selectable { default: None });
        let validated = validate_skill_runtime_contract(&contract).expect("contract");
        let key = CredentialProfileKey::new(
            scope(),
            "other-provider",
            "work",
            CredentialProfileBinding::Provider,
        )
        .expect("key");
        let metadata = CredentialProfileMetadata::new(
            key,
            None,
            false,
            CredentialProfileAvailability::Enabled,
            CredentialProfileRevision::new(1).expect("revision"),
        )
        .expect("metadata");
        let wrong = CredentialProfileStatus::new(metadata, AuthState::Missing).expect("status");

        assert_eq!(
            plan_for_status(validated, &wrong, CredentialLifecycleOperation::Status)
                .expect_err("provider replacement must fail")
                .code,
            CredentialLifecycleErrorCode::TargetMismatch
        );
    }

    #[test]
    fn selected_profile_must_cross_the_registry_boundary_and_match_the_requested_key() {
        let contract = contract(ProfileSelection::Selectable { default: None });
        let validated = validate_skill_runtime_contract(&contract).expect("contract");
        let requested = status(
            "work",
            None,
            CredentialProfileAvailability::Enabled,
            AuthState::Missing,
        );

        assert_eq!(
            CredentialLifecyclePlan::for_profile(
                &TestRegistry::missing(),
                validated,
                requested.key(),
                CredentialLifecycleOperation::Status,
            )
            .expect_err("missing registry row")
            .code,
            CredentialLifecycleErrorCode::ProfileNotFound
        );
        assert_eq!(
            CredentialLifecyclePlan::for_profile(
                &TestRegistry::failing(),
                validated,
                requested.key(),
                CredentialLifecycleOperation::Status,
            )
            .expect_err("registry failure")
            .code,
            CredentialLifecycleErrorCode::RegistryUnavailable
        );

        let substituted = status(
            "personal",
            None,
            CredentialProfileAvailability::Enabled,
            AuthState::Ready,
        );
        assert_eq!(
            CredentialLifecyclePlan::for_profile(
                &TestRegistry::one(substituted),
                validated,
                requested.key(),
                CredentialLifecycleOperation::Status,
            )
            .expect_err("registry cannot substitute a different profile")
            .code,
            CredentialLifecycleErrorCode::RegistryUnavailable
        );
    }

    #[test]
    fn implicit_plan_derives_provider_and_exposes_no_profile_alias() {
        let mut contract = contract(ProfileSelection::Implicit);
        contract.auth.storage = AuthStorage::CliOwned;
        let validated = validate_skill_runtime_contract(&contract).expect("contract");

        let plan = CredentialLifecyclePlan::for_implicit(
            validated,
            scope(),
            CredentialLifecycleOperation::Status,
        )
        .expect("implicit status plan");

        assert!(plan.selected_profile_key().is_none());
        assert!(plan.selected_profile_revision().is_none());
        assert!(plan.expected_identity().is_none());
        let (provider, binding) = plan.implicit_identity().expect("implicit identity");
        assert_eq!(provider.as_str(), "google-workspace");
        assert_eq!(binding, &CredentialProfileBinding::Provider);
    }

    #[test]
    fn selected_and_implicit_target_modes_cannot_be_crossed() {
        let selectable = contract(ProfileSelection::Selectable { default: None });
        let selectable = validate_skill_runtime_contract(&selectable).expect("selectable");
        assert_eq!(
            CredentialLifecyclePlan::for_implicit(
                selectable,
                scope(),
                CredentialLifecycleOperation::Status,
            )
            .expect_err("selected contract cannot become implicit")
            .code,
            CredentialLifecycleErrorCode::TargetMismatch
        );

        let mut implicit = contract(ProfileSelection::Implicit);
        implicit.auth.storage = AuthStorage::CliOwned;
        let implicit = validate_skill_runtime_contract(&implicit).expect("implicit");
        let profile = status(
            "work",
            None,
            CredentialProfileAvailability::Enabled,
            AuthState::Missing,
        );
        assert_eq!(
            plan_for_status(implicit, &profile, CredentialLifecycleOperation::Status)
                .expect_err("implicit contract cannot accept a selected profile")
                .code,
            CredentialLifecycleErrorCode::TargetMismatch
        );
    }

    #[test]
    fn declared_expected_identity_must_exist_in_registry_metadata() {
        let mut contract = contract(ProfileSelection::Fixed {
            alias: "work".to_owned(),
        });
        contract.auth.identity = IdentityContract::ProfileExpected {
            selector: IdentitySelector::JsonPointer {
                pointer: "/user".to_owned(),
            },
        };
        let validated = validate_skill_runtime_contract(&contract).expect("contract");
        let profile = status(
            "work",
            None,
            CredentialProfileAvailability::Enabled,
            AuthState::Unknown,
        );

        assert_eq!(
            plan_for_status(validated, &profile, CredentialLifecycleOperation::Status)
                .expect_err("declared identity cannot disappear")
                .code,
            CredentialLifecycleErrorCode::MissingExpectedIdentity
        );
    }

    #[test]
    fn disabled_profiles_allow_status_and_logout_but_not_login_or_refresh() {
        let contract = contract(ProfileSelection::Fixed {
            alias: "work".to_owned(),
        });
        let validated = validate_skill_runtime_contract(&contract).expect("contract");
        let profile = status(
            "work",
            None,
            CredentialProfileAvailability::Disabled,
            AuthState::Denied,
        );

        for operation in [
            CredentialLifecycleOperation::Status,
            CredentialLifecycleOperation::Logout,
        ] {
            plan_for_status(validated, &profile, operation)
                .expect("non-authenticating operator operation");
        }
        for operation in [
            CredentialLifecycleOperation::Login,
            CredentialLifecycleOperation::Refresh,
        ] {
            assert_eq!(
                plan_for_status(validated, &profile, operation)
                    .expect_err("disabled profile cannot authenticate")
                    .code,
                CredentialLifecycleErrorCode::ProfileDisabled
            );
        }
    }

    #[test]
    fn undeclared_hook_and_non_profile_contract_fail_with_typed_errors() {
        let mut profile_contract = contract(ProfileSelection::Fixed {
            alias: "work".to_owned(),
        });
        profile_contract.auth.lifecycle.refresh = None;
        let profile_validated =
            validate_skill_runtime_contract(&profile_contract).expect("contract");
        let profile = status(
            "work",
            None,
            CredentialProfileAvailability::Enabled,
            AuthState::Ready,
        );
        assert_eq!(
            plan_for_status(
                profile_validated,
                &profile,
                CredentialLifecycleOperation::Refresh,
            )
            .expect_err("missing hook")
            .code,
            CredentialLifecycleErrorCode::HookUnavailable
        );

        let mut no_auth = contract(ProfileSelection::Fixed {
            alias: "work".to_owned(),
        });
        no_auth.auth = AuthContract::default();
        let no_auth = validate_skill_runtime_contract(&no_auth).expect("no-auth contract");
        assert_eq!(
            plan_for_status(no_auth, &profile, CredentialLifecycleOperation::Status)
                .expect_err("non-profile auth")
                .code,
            CredentialLifecycleErrorCode::UnsupportedContract
        );
    }

    #[test]
    fn debug_and_error_surfaces_do_not_copy_command_or_identity_values() {
        assert_not_impl_any!(CredentialLifecyclePlan: Serialize);

        let contract = contract(ProfileSelection::Fixed {
            alias: "work".to_owned(),
        });
        let validated = validate_skill_runtime_contract(&contract).expect("contract");
        let profile = status(
            "work",
            Some("owner@example.com"),
            CredentialProfileAvailability::Enabled,
            AuthState::Ready,
        );
        let plan = plan_for_status(validated, &profile, CredentialLifecycleOperation::Status)
            .expect("plan");
        let debug = format!("{plan:?}");

        assert!(!debug.contains("gws"));
        assert!(!debug.contains("--format"));
        assert!(!debug.contains("owner@example.com"));
        assert!(debug.contains("argument_count"));
        let _: &dyn fmt::Debug = &plan;
    }

    #[test]
    fn lifecycle_error_serialization_is_fixed_and_value_free() {
        let error = target_mismatch();
        let encoded = serde_json::to_string(&error).expect("serialize error");
        assert_eq!(
            encoded,
            r#"{"code":"target_mismatch","field":"auth.profile_selection","message":"the lifecycle target does not match the validated profile contract"}"#
        );
    }
}
