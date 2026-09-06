//! Deterministic credential-profile selection over the metadata-only registry.
//!
//! Selection chooses a logical profile and reports its public readiness state. It does
//! not resolve credentials, inspect profile paths, authenticate, mutate the registry,
//! touch process-global state, or enable an execution route.

use std::{error::Error, fmt};

use serde::Serialize;

use crate::{
    credential_profiles::{
        CredentialProfileAlias, CredentialProfileAvailability, CredentialProfileBinding,
        CredentialProfileErrorCode, CredentialProfileRegistry, CredentialProfileRegistrySnapshot,
        CredentialProfileStatus, CredentialProviderId, CredentialScope,
    },
    manifest::{AuthState, ProfileSelection},
};

pub const CREDENTIAL_PROFILE_SELECTION_V1: &str = "tool-runtime.credential-profile-selection.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialProfileSelectionErrorCode {
    InvalidProvider,
    InvalidPolicy,
    InvalidRequestedProfile,
    MissingProvider,
    UnexpectedRequestedProfile,
    MissingProfileSelection,
    ProfileNotFound,
    ProfileDisabled,
    SnapshotScopeMismatch,
    RegistryUnavailable,
}

/// Stable, bounded, value-free diagnostics for the selection boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CredentialProfileSelectionError {
    pub code: CredentialProfileSelectionErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl CredentialProfileSelectionError {
    const fn new(
        code: CredentialProfileSelectionErrorCode,
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

impl fmt::Display for CredentialProfileSelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for CredentialProfileSelectionError {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ValidatedProfileSelection {
    None,
    Selectable {
        default: Option<CredentialProfileAlias>,
    },
    Fixed {
        alias: CredentialProfileAlias,
    },
    Implicit,
}

/// Validated, scope-bound input to profile selection.
///
/// The requested alias is the only field permitted to originate in model input; scope,
/// provider, binding, and policy are runtime-owned. Construction rejects a requested
/// alias for `none`, `fixed`, and `implicit` policies before parsing or retaining it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialProfileSelectionRequest {
    scope: CredentialScope,
    provider: Option<CredentialProviderId>,
    binding: CredentialProfileBinding,
    policy: ValidatedProfileSelection,
    requested_alias: Option<CredentialProfileAlias>,
}

impl CredentialProfileSelectionRequest {
    pub fn new(
        scope: CredentialScope,
        provider: Option<&str>,
        binding: CredentialProfileBinding,
        policy: &ProfileSelection,
        requested_alias: Option<&str>,
    ) -> Result<Self, CredentialProfileSelectionError> {
        if requested_alias.is_some() && !matches!(policy, ProfileSelection::Selectable { .. }) {
            return Err(unexpected_requested_profile());
        }

        let provider = provider
            .map(CredentialProviderId::new)
            .transpose()
            .map_err(|_| invalid_provider())?;
        let policy = match policy {
            ProfileSelection::None => ValidatedProfileSelection::None,
            ProfileSelection::Selectable { default } => ValidatedProfileSelection::Selectable {
                default: default
                    .as_deref()
                    .map(CredentialProfileAlias::new)
                    .transpose()
                    .map_err(|_| invalid_policy())?,
            },
            ProfileSelection::Fixed { alias } => ValidatedProfileSelection::Fixed {
                alias: CredentialProfileAlias::new(alias).map_err(|_| invalid_policy())?,
            },
            ProfileSelection::Implicit => ValidatedProfileSelection::Implicit,
        };
        if !matches!(policy, ValidatedProfileSelection::None) && provider.is_none() {
            return Err(missing_provider());
        }
        let requested_alias = requested_alias
            .map(CredentialProfileAlias::new)
            .transpose()
            .map_err(|_| invalid_requested_profile())?;

        Ok(Self {
            scope,
            provider,
            binding,
            policy,
            requested_alias,
        })
    }

    pub fn scope(&self) -> &CredentialScope {
        &self.scope
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialProfileSelectionSource {
    Requested,
    ContractDefault,
    RegistryDefault,
    Fixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialProfileReadiness {
    Ready,
    VerificationRequired,
    AuthenticationRequired,
    AuthenticationInProgress,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialProfileSelectionMode {
    None,
    Implicit,
    Selected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
enum CredentialProfileSelectionDecisionInner {
    None {
        schema_version: &'static str,
        scope: CredentialScope,
    },
    Implicit {
        schema_version: &'static str,
        scope: CredentialScope,
        provider: CredentialProviderId,
        binding: CredentialProfileBinding,
    },
    Selected {
        schema_version: &'static str,
        source: CredentialProfileSelectionSource,
        readiness: CredentialProfileReadiness,
        profile: CredentialProfileStatus,
    },
}

/// Opaque selection proof. Callers can inspect and serialize a decision but cannot
/// construct one or replace its selected profile/readiness fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CredentialProfileSelectionDecision {
    inner: CredentialProfileSelectionDecisionInner,
}

impl CredentialProfileSelectionDecision {
    pub fn scope(&self) -> &CredentialScope {
        match &self.inner {
            CredentialProfileSelectionDecisionInner::None { scope, .. }
            | CredentialProfileSelectionDecisionInner::Implicit { scope, .. } => scope,
            CredentialProfileSelectionDecisionInner::Selected { profile, .. } => {
                &profile.key().scope
            },
        }
    }

    pub fn mode(&self) -> CredentialProfileSelectionMode {
        match &self.inner {
            CredentialProfileSelectionDecisionInner::None { .. } => {
                CredentialProfileSelectionMode::None
            },
            CredentialProfileSelectionDecisionInner::Implicit { .. } => {
                CredentialProfileSelectionMode::Implicit
            },
            CredentialProfileSelectionDecisionInner::Selected { .. } => {
                CredentialProfileSelectionMode::Selected
            },
        }
    }

    pub fn selected_profile(&self) -> Option<&CredentialProfileStatus> {
        match &self.inner {
            CredentialProfileSelectionDecisionInner::Selected { profile, .. } => Some(profile),
            CredentialProfileSelectionDecisionInner::None { .. }
            | CredentialProfileSelectionDecisionInner::Implicit { .. } => None,
        }
    }

    pub fn readiness(&self) -> Option<CredentialProfileReadiness> {
        match &self.inner {
            CredentialProfileSelectionDecisionInner::Selected { readiness, .. } => Some(*readiness),
            CredentialProfileSelectionDecisionInner::None { .. }
            | CredentialProfileSelectionDecisionInner::Implicit { .. } => None,
        }
    }

    pub fn source(&self) -> Option<CredentialProfileSelectionSource> {
        match &self.inner {
            CredentialProfileSelectionDecisionInner::Selected { source, .. } => Some(*source),
            CredentialProfileSelectionDecisionInner::None { .. }
            | CredentialProfileSelectionDecisionInner::Implicit { .. } => None,
        }
    }

    pub fn implicit_identity(&self) -> Option<(&CredentialProviderId, &CredentialProfileBinding)> {
        match &self.inner {
            CredentialProfileSelectionDecisionInner::Implicit {
                provider, binding, ..
            } => Some((provider, binding)),
            CredentialProfileSelectionDecisionInner::None { .. }
            | CredentialProfileSelectionDecisionInner::Selected { .. } => None,
        }
    }
}

/// Resolve selection against a registry. Policies that own no explicit registry profile
/// (`none` and `implicit`) deliberately do not touch the registry.
pub fn select_credential_profile(
    registry: &dyn CredentialProfileRegistry,
    request: &CredentialProfileSelectionRequest,
) -> Result<CredentialProfileSelectionDecision, CredentialProfileSelectionError> {
    match &request.policy {
        ValidatedProfileSelection::None => Ok(none_decision(request)),
        ValidatedProfileSelection::Implicit => implicit_decision(request),
        ValidatedProfileSelection::Selectable { .. } | ValidatedProfileSelection::Fixed { .. } => {
            let snapshot = registry
                .snapshot(&request.scope)
                .map_err(map_registry_error)?;
            select_credential_profile_from_snapshot(request, &snapshot)
        },
    }
}

/// Pure deterministic selection over one already bounded metadata snapshot.
///
/// This helper stays crate-private so public callers cross the registry trust
/// boundary instead of manufacturing an execution decision from arbitrary metadata.
pub(crate) fn select_credential_profile_from_snapshot(
    request: &CredentialProfileSelectionRequest,
    snapshot: &CredentialProfileRegistrySnapshot,
) -> Result<CredentialProfileSelectionDecision, CredentialProfileSelectionError> {
    match &request.policy {
        ValidatedProfileSelection::None => return Ok(none_decision(request)),
        ValidatedProfileSelection::Implicit => return implicit_decision(request),
        ValidatedProfileSelection::Selectable { .. } | ValidatedProfileSelection::Fixed { .. } => {
        },
    }
    if snapshot.scope() != &request.scope {
        return Err(snapshot_scope_mismatch());
    }

    let provider = request.provider.as_ref().ok_or_else(missing_provider)?;
    let mut candidates = snapshot.profiles().iter().filter(|profile| {
        profile.key().provider == *provider && profile.key().binding == request.binding
    });

    let (alias, source) = match &request.policy {
        ValidatedProfileSelection::Selectable { default } => {
            if let Some(alias) = &request.requested_alias {
                (alias, CredentialProfileSelectionSource::Requested)
            } else if let Some(alias) = default {
                (alias, CredentialProfileSelectionSource::ContractDefault)
            } else {
                let profile = candidates
                    .clone()
                    .find(|profile| profile.metadata().is_default())
                    .ok_or_else(missing_profile_selection)?;
                return selected_decision(
                    profile,
                    CredentialProfileSelectionSource::RegistryDefault,
                );
            }
        },
        ValidatedProfileSelection::Fixed { alias } => {
            (alias, CredentialProfileSelectionSource::Fixed)
        },
        ValidatedProfileSelection::None | ValidatedProfileSelection::Implicit => {
            return Err(invalid_policy());
        },
    };

    let profile = candidates
        .find(|profile| profile.key().alias == *alias)
        .ok_or_else(profile_not_found)?;
    selected_decision(profile, source)
}

fn none_decision(
    request: &CredentialProfileSelectionRequest,
) -> CredentialProfileSelectionDecision {
    CredentialProfileSelectionDecision {
        inner: CredentialProfileSelectionDecisionInner::None {
            schema_version: CREDENTIAL_PROFILE_SELECTION_V1,
            scope: request.scope.clone(),
        },
    }
}

fn implicit_decision(
    request: &CredentialProfileSelectionRequest,
) -> Result<CredentialProfileSelectionDecision, CredentialProfileSelectionError> {
    let provider = request.provider.as_ref().ok_or_else(missing_provider)?;
    Ok(CredentialProfileSelectionDecision {
        inner: CredentialProfileSelectionDecisionInner::Implicit {
            schema_version: CREDENTIAL_PROFILE_SELECTION_V1,
            scope: request.scope.clone(),
            provider: provider.clone(),
            binding: request.binding.clone(),
        },
    })
}

fn selected_decision(
    profile: &CredentialProfileStatus,
    source: CredentialProfileSelectionSource,
) -> Result<CredentialProfileSelectionDecision, CredentialProfileSelectionError> {
    if profile.metadata().availability() == CredentialProfileAvailability::Disabled {
        return Err(profile_disabled());
    }
    Ok(CredentialProfileSelectionDecision {
        inner: CredentialProfileSelectionDecisionInner::Selected {
            schema_version: CREDENTIAL_PROFILE_SELECTION_V1,
            source,
            readiness: readiness(profile.auth_state()),
            profile: profile.clone(),
        },
    })
}

const fn readiness(state: AuthState) -> CredentialProfileReadiness {
    match state {
        AuthState::Ready => CredentialProfileReadiness::Ready,
        AuthState::Unknown => CredentialProfileReadiness::VerificationRequired,
        AuthState::Missing | AuthState::InteractionRequired | AuthState::Expired => {
            CredentialProfileReadiness::AuthenticationRequired
        },
        AuthState::Authenticating => CredentialProfileReadiness::AuthenticationInProgress,
        AuthState::Revoked | AuthState::IdentityMismatch | AuthState::Denied | AuthState::Error => {
            CredentialProfileReadiness::Blocked
        },
    }
}

fn map_registry_error(
    error: crate::credential_profiles::CredentialProfileError,
) -> CredentialProfileSelectionError {
    if error.code == CredentialProfileErrorCode::ScopeMismatch {
        snapshot_scope_mismatch()
    } else {
        registry_unavailable()
    }
}

const fn invalid_provider() -> CredentialProfileSelectionError {
    CredentialProfileSelectionError::new(
        CredentialProfileSelectionErrorCode::InvalidProvider,
        "provider",
        "the credential profile provider is invalid",
    )
}

const fn invalid_policy() -> CredentialProfileSelectionError {
    CredentialProfileSelectionError::new(
        CredentialProfileSelectionErrorCode::InvalidPolicy,
        "profile_selection",
        "the credential profile selection policy is invalid",
    )
}

const fn invalid_requested_profile() -> CredentialProfileSelectionError {
    CredentialProfileSelectionError::new(
        CredentialProfileSelectionErrorCode::InvalidRequestedProfile,
        "profile",
        "the requested credential profile alias is invalid",
    )
}

const fn missing_provider() -> CredentialProfileSelectionError {
    CredentialProfileSelectionError::new(
        CredentialProfileSelectionErrorCode::MissingProvider,
        "provider",
        "credential profile selection requires a provider",
    )
}

const fn unexpected_requested_profile() -> CredentialProfileSelectionError {
    CredentialProfileSelectionError::new(
        CredentialProfileSelectionErrorCode::UnexpectedRequestedProfile,
        "profile",
        "the selected profile policy does not accept a requested alias",
    )
}

const fn missing_profile_selection() -> CredentialProfileSelectionError {
    CredentialProfileSelectionError::new(
        CredentialProfileSelectionErrorCode::MissingProfileSelection,
        "profile",
        "no requested, contract-default, or registry-default profile is available",
    )
}

const fn profile_not_found() -> CredentialProfileSelectionError {
    CredentialProfileSelectionError::new(
        CredentialProfileSelectionErrorCode::ProfileNotFound,
        "profile",
        "the selected credential profile was not found",
    )
}

const fn profile_disabled() -> CredentialProfileSelectionError {
    CredentialProfileSelectionError::new(
        CredentialProfileSelectionErrorCode::ProfileDisabled,
        "profile",
        "the selected credential profile is disabled",
    )
}

const fn snapshot_scope_mismatch() -> CredentialProfileSelectionError {
    CredentialProfileSelectionError::new(
        CredentialProfileSelectionErrorCode::SnapshotScopeMismatch,
        "scope",
        "the credential profile snapshot belongs to a different scope",
    )
}

const fn registry_unavailable() -> CredentialProfileSelectionError {
    CredentialProfileSelectionError::new(
        CredentialProfileSelectionErrorCode::RegistryUnavailable,
        "registry",
        "the credential profile registry is unavailable",
    )
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::credential_profiles::{
        CreateCredentialProfileReference, CredentialProfileError, CredentialProfileKey,
        CredentialProfileMetadata, CredentialProfileRevision, SetCredentialProfileDisabled,
        UpdateCredentialProfileMetadata, MAX_PROFILES_PER_SCOPE,
    };

    fn scope(principal: &str) -> CredentialScope {
        CredentialScope::new(principal, "default").expect("valid scope")
    }

    fn status_for(
        scope: &CredentialScope,
        provider: &str,
        alias: &str,
        binding: CredentialProfileBinding,
        is_default: bool,
        availability: CredentialProfileAvailability,
        auth_state: AuthState,
    ) -> CredentialProfileStatus {
        let key =
            CredentialProfileKey::new(scope.clone(), provider, alias, binding).expect("valid key");
        let metadata = CredentialProfileMetadata::new(
            key,
            None,
            is_default,
            availability,
            CredentialProfileRevision::new(1).expect("revision"),
        )
        .expect("valid metadata");
        CredentialProfileStatus::new(metadata, auth_state).expect("valid status")
    }

    fn enabled_status(
        scope: &CredentialScope,
        alias: &str,
        is_default: bool,
        auth_state: AuthState,
    ) -> CredentialProfileStatus {
        status_for(
            scope,
            "google-workspace",
            alias,
            CredentialProfileBinding::Provider,
            is_default,
            CredentialProfileAvailability::Enabled,
            auth_state,
        )
    }

    fn request(
        scope: &CredentialScope,
        policy: ProfileSelection,
        requested_alias: Option<&str>,
    ) -> Result<CredentialProfileSelectionRequest, CredentialProfileSelectionError> {
        CredentialProfileSelectionRequest::new(
            scope.clone(),
            Some("google-workspace"),
            CredentialProfileBinding::Provider,
            &policy,
            requested_alias,
        )
    }

    struct TestRegistry {
        snapshot: Result<CredentialProfileRegistrySnapshot, CredentialProfileError>,
        snapshot_calls: AtomicUsize,
    }

    impl CredentialProfileRegistry for TestRegistry {
        fn snapshot(
            &self,
            _scope: &CredentialScope,
        ) -> Result<CredentialProfileRegistrySnapshot, CredentialProfileError> {
            self.snapshot_calls.fetch_add(1, Ordering::SeqCst);
            self.snapshot.clone()
        }

        fn status(
            &self,
            _key: &CredentialProfileKey,
        ) -> Result<Option<CredentialProfileStatus>, CredentialProfileError> {
            panic!("selection must use one bounded snapshot")
        }

        fn create_reference(
            &self,
            _request: CreateCredentialProfileReference,
        ) -> Result<CredentialProfileStatus, CredentialProfileError> {
            panic!("selection must not mutate the registry")
        }

        fn update_metadata(
            &self,
            _request: UpdateCredentialProfileMetadata,
        ) -> Result<CredentialProfileStatus, CredentialProfileError> {
            panic!("selection must not mutate the registry")
        }

        fn set_disabled(
            &self,
            _request: SetCredentialProfileDisabled,
        ) -> Result<CredentialProfileStatus, CredentialProfileError> {
            panic!("selection must not mutate the registry")
        }
    }

    #[test]
    fn none_and_implicit_never_touch_the_registry_and_reject_model_selection() {
        let registry = TestRegistry {
            snapshot: Err(CredentialProfileError::registry_unavailable()),
            snapshot_calls: AtomicUsize::new(0),
        };
        let selected_scope = scope("owner");

        let none = CredentialProfileSelectionRequest::new(
            selected_scope.clone(),
            None,
            CredentialProfileBinding::Provider,
            &ProfileSelection::None,
            None,
        )
        .expect("none request");
        assert_eq!(
            select_credential_profile(&registry, &none)
                .expect("none selection")
                .mode(),
            CredentialProfileSelectionMode::None
        );

        let implicit =
            request(&selected_scope, ProfileSelection::Implicit, None).expect("implicit request");
        let implicit = select_credential_profile(&registry, &implicit).expect("implicit selection");
        assert_eq!(implicit.mode(), CredentialProfileSelectionMode::Implicit);
        assert_eq!(
            implicit
                .implicit_identity()
                .expect("implicit identity")
                .0
                .as_str(),
            "google-workspace"
        );
        assert_eq!(registry.snapshot_calls.load(Ordering::SeqCst), 0);

        for policy in [
            ProfileSelection::None,
            ProfileSelection::Fixed {
                alias: "work".to_owned(),
            },
            ProfileSelection::Implicit,
        ] {
            let error = request(&selected_scope, policy, Some("work"))
                .expect_err("model profile must be rejected");
            assert_eq!(
                error.code,
                CredentialProfileSelectionErrorCode::UnexpectedRequestedProfile
            );
        }
    }

    #[test]
    fn selectable_precedence_is_requested_then_contract_default_then_registry_default() {
        let selected_scope = scope("owner");
        let snapshot = CredentialProfileRegistrySnapshot::new(
            selected_scope.clone(),
            vec![
                enabled_status(&selected_scope, "personal", true, AuthState::Ready),
                enabled_status(&selected_scope, "work", false, AuthState::Unknown),
            ],
        )
        .expect("snapshot");

        let explicit = request(
            &selected_scope,
            ProfileSelection::Selectable {
                default: Some("personal".to_owned()),
            },
            Some("work"),
        )
        .expect("explicit request");
        let explicit = select_credential_profile_from_snapshot(&explicit, &snapshot)
            .expect("explicit selection");
        assert_eq!(
            explicit.source(),
            Some(CredentialProfileSelectionSource::Requested)
        );
        assert_eq!(
            explicit.selected_profile().unwrap().key().alias.as_str(),
            "work"
        );

        let contract_default = request(
            &selected_scope,
            ProfileSelection::Selectable {
                default: Some("work".to_owned()),
            },
            None,
        )
        .expect("contract-default request");
        let contract_default =
            select_credential_profile_from_snapshot(&contract_default, &snapshot)
                .expect("contract-default selection");
        assert_eq!(
            contract_default.source(),
            Some(CredentialProfileSelectionSource::ContractDefault)
        );

        let registry_default = request(
            &selected_scope,
            ProfileSelection::Selectable { default: None },
            None,
        )
        .expect("registry-default request");
        let registry_default =
            select_credential_profile_from_snapshot(&registry_default, &snapshot)
                .expect("registry-default selection");
        assert_eq!(
            registry_default.source(),
            Some(CredentialProfileSelectionSource::RegistryDefault)
        );
        assert_eq!(
            registry_default
                .selected_profile()
                .unwrap()
                .key()
                .alias
                .as_str(),
            "personal"
        );
    }

    #[test]
    fn fixed_selection_is_manifest_owned_and_missing_profiles_never_fall_back() {
        let selected_scope = scope("owner");
        let snapshot = CredentialProfileRegistrySnapshot::new(
            selected_scope.clone(),
            vec![enabled_status(
                &selected_scope,
                "personal",
                true,
                AuthState::Ready,
            )],
        )
        .expect("snapshot");
        let fixed = request(
            &selected_scope,
            ProfileSelection::Fixed {
                alias: "work".to_owned(),
            },
            None,
        )
        .expect("fixed request");
        let error = select_credential_profile_from_snapshot(&fixed, &snapshot)
            .expect_err("missing fixed profile");
        assert_eq!(
            error.code,
            CredentialProfileSelectionErrorCode::ProfileNotFound
        );

        let fixed_personal = request(
            &selected_scope,
            ProfileSelection::Fixed {
                alias: "personal".to_owned(),
            },
            None,
        )
        .expect("fixed request");
        let fixed_personal = select_credential_profile_from_snapshot(&fixed_personal, &snapshot)
            .expect("fixed selection");
        assert_eq!(
            fixed_personal.source(),
            Some(CredentialProfileSelectionSource::Fixed)
        );

        let requested = request(
            &selected_scope,
            ProfileSelection::Selectable {
                default: Some("personal".to_owned()),
            },
            Some("work"),
        )
        .expect("requested profile");
        let error = select_credential_profile_from_snapshot(&requested, &snapshot)
            .expect_err("missing requested profile must not use default");
        assert_eq!(
            error.code,
            CredentialProfileSelectionErrorCode::ProfileNotFound
        );

        let missing_contract_default = request(
            &selected_scope,
            ProfileSelection::Selectable {
                default: Some("work".to_owned()),
            },
            None,
        )
        .expect("contract-default request");
        assert_eq!(
            select_credential_profile_from_snapshot(&missing_contract_default, &snapshot)
                .expect_err("a missing contract default must not use the registry default")
                .code,
            CredentialProfileSelectionErrorCode::ProfileNotFound
        );
    }

    #[test]
    fn selection_is_exact_to_provider_binding_and_scope() {
        let selected_scope = scope("owner");
        let other_scope = scope("other");
        let mcp_binding = CredentialProfileBinding::McpOauth {
            resource_url: crate::credential_profiles::CanonicalCredentialUrl::new(
                "https://provider.example/mcp",
            )
            .unwrap(),
            authorization_issuer: crate::credential_profiles::CanonicalCredentialUrl::new(
                "https://auth.example/oauth/",
            )
            .unwrap(),
        };
        let snapshot = CredentialProfileRegistrySnapshot::new(
            selected_scope.clone(),
            vec![
                status_for(
                    &selected_scope,
                    "other-provider",
                    "work",
                    CredentialProfileBinding::Provider,
                    true,
                    CredentialProfileAvailability::Enabled,
                    AuthState::Ready,
                ),
                status_for(
                    &selected_scope,
                    "google-workspace",
                    "work",
                    mcp_binding,
                    true,
                    CredentialProfileAvailability::Enabled,
                    AuthState::Ready,
                ),
            ],
        )
        .expect("snapshot");
        let selected = request(
            &selected_scope,
            ProfileSelection::Selectable { default: None },
            Some("work"),
        )
        .expect("request");
        assert_eq!(
            select_credential_profile_from_snapshot(&selected, &snapshot)
                .expect_err("other provider and binding must not match")
                .code,
            CredentialProfileSelectionErrorCode::ProfileNotFound
        );

        let other_snapshot = CredentialProfileRegistrySnapshot::new(other_scope, Vec::new())
            .expect("other snapshot");
        assert_eq!(
            select_credential_profile_from_snapshot(&selected, &other_snapshot)
                .expect_err("scope mismatch")
                .code,
            CredentialProfileSelectionErrorCode::SnapshotScopeMismatch
        );
    }

    #[test]
    fn disabled_profiles_and_absent_defaults_fail_closed() {
        let selected_scope = scope("owner");
        let disabled = status_for(
            &selected_scope,
            "google-workspace",
            "work",
            CredentialProfileBinding::Provider,
            false,
            CredentialProfileAvailability::Disabled,
            AuthState::Denied,
        );
        let snapshot =
            CredentialProfileRegistrySnapshot::new(selected_scope.clone(), vec![disabled])
                .expect("snapshot");
        let explicit = request(
            &selected_scope,
            ProfileSelection::Selectable { default: None },
            Some("work"),
        )
        .expect("request");
        assert_eq!(
            select_credential_profile_from_snapshot(&explicit, &snapshot)
                .expect_err("disabled profile")
                .code,
            CredentialProfileSelectionErrorCode::ProfileDisabled
        );

        let no_default = request(
            &selected_scope,
            ProfileSelection::Selectable { default: None },
            None,
        )
        .expect("request");
        assert_eq!(
            select_credential_profile_from_snapshot(&no_default, &snapshot)
                .expect_err("no enabled default")
                .code,
            CredentialProfileSelectionErrorCode::MissingProfileSelection
        );
    }

    #[test]
    fn every_auth_state_maps_to_one_non_escalating_readiness() {
        let cases = [
            (AuthState::Ready, CredentialProfileReadiness::Ready),
            (
                AuthState::Unknown,
                CredentialProfileReadiness::VerificationRequired,
            ),
            (
                AuthState::Missing,
                CredentialProfileReadiness::AuthenticationRequired,
            ),
            (
                AuthState::InteractionRequired,
                CredentialProfileReadiness::AuthenticationRequired,
            ),
            (
                AuthState::Expired,
                CredentialProfileReadiness::AuthenticationRequired,
            ),
            (
                AuthState::Authenticating,
                CredentialProfileReadiness::AuthenticationInProgress,
            ),
            (AuthState::Revoked, CredentialProfileReadiness::Blocked),
            (
                AuthState::IdentityMismatch,
                CredentialProfileReadiness::Blocked,
            ),
            (AuthState::Denied, CredentialProfileReadiness::Blocked),
            (AuthState::Error, CredentialProfileReadiness::Blocked),
        ];
        let selected_scope = scope("owner");

        for (state, expected) in cases {
            let snapshot = CredentialProfileRegistrySnapshot::new(
                selected_scope.clone(),
                vec![enabled_status(&selected_scope, "work", false, state)],
            )
            .expect("snapshot");
            let selected = request(
                &selected_scope,
                ProfileSelection::Fixed {
                    alias: "work".to_owned(),
                },
                None,
            )
            .expect("request");
            let decision =
                select_credential_profile_from_snapshot(&selected, &snapshot).expect("selection");
            assert_eq!(decision.readiness(), Some(expected), "state {state:?}");
        }
    }

    #[test]
    fn registry_failures_and_invalid_inputs_are_value_free() {
        let selected_scope = scope("owner");
        let registry = TestRegistry {
            snapshot: Err(CredentialProfileError::registry_unavailable()),
            snapshot_calls: AtomicUsize::new(0),
        };
        let selected = request(
            &selected_scope,
            ProfileSelection::Fixed {
                alias: "work".to_owned(),
            },
            None,
        )
        .expect("request");
        assert_eq!(
            select_credential_profile(&registry, &selected)
                .expect_err("unavailable registry")
                .code,
            CredentialProfileSelectionErrorCode::RegistryUnavailable
        );
        assert_eq!(registry.snapshot_calls.load(Ordering::SeqCst), 1);

        let canary = "INVALID/PROFILE/CANARY";
        let error = request(
            &selected_scope,
            ProfileSelection::Selectable { default: None },
            Some(canary),
        )
        .expect_err("invalid model alias");
        let serialized = serde_json::to_string(&error).expect("serialize error");
        assert!(!error.to_string().contains(canary));
        assert!(!serialized.contains(canary));

        assert_eq!(
            CredentialProfileSelectionRequest::new(
                selected_scope.clone(),
                None,
                CredentialProfileBinding::Provider,
                &ProfileSelection::Implicit,
                None,
            )
            .expect_err("profile selection without a provider")
            .code,
            CredentialProfileSelectionErrorCode::MissingProvider
        );
        assert_eq!(
            CredentialProfileSelectionRequest::new(
                selected_scope,
                Some("invalid/provider"),
                CredentialProfileBinding::Provider,
                &ProfileSelection::Implicit,
                None,
            )
            .expect_err("invalid provider")
            .code,
            CredentialProfileSelectionErrorCode::InvalidProvider
        );
    }

    #[test]
    fn maximum_snapshot_selection_is_deterministic_on_a_small_stack() {
        let result = std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| {
                let selected_scope = scope("owner");
                let profiles = (0..MAX_PROFILES_PER_SCOPE)
                    .rev()
                    .map(|index| {
                        enabled_status(
                            &selected_scope,
                            &format!("profile-{index:03}"),
                            index == MAX_PROFILES_PER_SCOPE - 1,
                            AuthState::Ready,
                        )
                    })
                    .collect();
                let snapshot =
                    CredentialProfileRegistrySnapshot::new(selected_scope.clone(), profiles)
                        .expect("maximum snapshot");
                let selected = request(
                    &selected_scope,
                    ProfileSelection::Selectable { default: None },
                    None,
                )
                .expect("request");
                let first = select_credential_profile_from_snapshot(&selected, &snapshot)
                    .expect("first selection");
                let second = select_credential_profile_from_snapshot(&selected, &snapshot)
                    .expect("second selection");
                assert_eq!(
                    serde_json::to_vec(&first).expect("serialize first"),
                    serde_json::to_vec(&second).expect("serialize second")
                );
                assert_eq!(
                    first.selected_profile().unwrap().key().alias.as_str(),
                    "profile-255"
                );
            })
            .expect("spawn small-stack selector")
            .join();
        assert!(result.is_ok());
    }
}
