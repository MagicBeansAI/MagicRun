//! Browser-profile delegation without browser credential export.
//!
//! The browser controller remains the sole owner of cookies, browser storage, CDP
//! credentials, and on-disk profiles. This module binds an opaque dispatch authority to
//! a selected or implicit credential-profile identity, the exact selected-profile
//! registry revision where applicable, browser session class, and browser-owner session
//! revision. The authority is prepared from one observation and must be revalidated
//! against a fresh observation immediately before dispatch.
//!
//! No type in this module can carry browser credential material. The final authority is
//! move-only, non-debuggable, and non-serializable; it only lets the trusted browser
//! controller recover the public profile key and exact session metadata it must own.

use std::{error::Error, fmt, num::NonZeroU64};

use serde::Serialize;

use crate::{
    credential_profiles::{
        CredentialProfileBinding, CredentialProfileKey, CredentialProfileRevision,
        CredentialProfileStatus, CredentialProviderId, CredentialScope,
    },
    manifest::{AuthKind, AuthState, AuthStorage, ProfileSelection, RuntimeProtocol},
    manifest_validation::ValidatedSkillRuntimeContract,
    profile_selection::{CredentialProfileSelectionDecision, CredentialProfileSelectionMode},
    strategy_adapter::{
        StrategyAdapterContract, StrategyAdapterKind, StrategyAuthStatus, StrategyStateRevision,
    },
};

pub const BROWSER_PROFILE_DELEGATION_V1: &str = "tool-runtime.browser-profile-delegation.v1";

/// Existing browser execution classes retain their different isolation semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserProfileSessionClass {
    /// Attach to the controller-owned signed-in user browser through CDP.
    CdpUserProfile,
    /// Use a controller-owned isolated visible session.
    IsolatedHeaded,
    /// Use a controller-owned isolated headless session.
    IsolatedHeadless,
}

/// Monotonic revision assigned by the browser controller to one logical session.
/// A restarted or replaced browser session must receive a newer revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct BrowserProfileSessionRevision(NonZeroU64);

impl BrowserProfileSessionRevision {
    pub fn new(value: u64) -> Result<Self, BrowserProfileAdapterError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or_else(invalid_session_revision)
    }

    pub fn get(self) -> u64 {
        self.0.get()
    }
}

impl TryFrom<u64> for BrowserProfileSessionRevision {
    type Error = BrowserProfileAdapterError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserProfileAdapterErrorCode {
    ContractMismatch,
    SelectionMismatch,
    ObservationMismatch,
    InvalidSessionRevision,
    NotReady,
    StalePreparedDelegation,
}

/// Bounded, value-free diagnostic. Profile aliases, endpoints, session ids, and browser
/// state are deliberately absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BrowserProfileAdapterError {
    pub code: BrowserProfileAdapterErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl BrowserProfileAdapterError {
    const fn new(
        code: BrowserProfileAdapterErrorCode,
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

impl fmt::Display for BrowserProfileAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for BrowserProfileAdapterError {}

/// Fresh metadata-only observation from the browser controller.
///
/// It intentionally contains only selected/implicit profile identity metadata rather
/// than browser storage or a session handle. Construction is cheap enough for immediate
/// pre-dispatch revalidation. It is non-debuggable and non-serializable so internal
/// profile aliases cannot drift into generic diagnostics.
pub struct BrowserProfileObservation {
    identity: BrowserProfileObservedIdentity,
    state: AuthState,
    session_class: BrowserProfileSessionClass,
    session_revision: BrowserProfileSessionRevision,
}

enum BrowserProfileObservedIdentity {
    Selected {
        key: CredentialProfileKey,
        revision: CredentialProfileRevision,
    },
    Implicit {
        scope: CredentialScope,
        provider: CredentialProviderId,
        binding: CredentialProfileBinding,
    },
}

impl BrowserProfileObservation {
    pub fn selected(
        profile: CredentialProfileStatus,
        session_class: BrowserProfileSessionClass,
        session_revision: BrowserProfileSessionRevision,
    ) -> Self {
        Self {
            identity: BrowserProfileObservedIdentity::Selected {
                key: profile.key().clone(),
                revision: profile.metadata().revision(),
            },
            state: profile.auth_state(),
            session_class,
            session_revision,
        }
    }

    pub fn implicit(
        scope: CredentialScope,
        provider: CredentialProviderId,
        binding: CredentialProfileBinding,
        state: AuthState,
        session_class: BrowserProfileSessionClass,
        session_revision: BrowserProfileSessionRevision,
    ) -> Self {
        Self {
            identity: BrowserProfileObservedIdentity::Implicit {
                scope,
                provider,
                binding,
            },
            state,
            session_class,
            session_revision,
        }
    }

    pub fn state(&self) -> AuthState {
        self.state
    }

    pub fn session_class(&self) -> BrowserProfileSessionClass {
        self.session_class
    }

    pub fn session_revision(&self) -> BrowserProfileSessionRevision {
        self.session_revision
    }
}

/// Exact browser authority adapter compiled from a validated skill contract and the
/// trusted profile registry's opaque selection decision.
///
/// This type intentionally implements neither `Debug` nor `Serialize`, avoiding an
/// accidental profile-identity projection through generic logs or APIs.
pub struct BrowserProfileAdapter {
    strategy: StrategyAdapterContract,
    identity: BrowserProfileAuthorityIdentity,
    session_class: BrowserProfileSessionClass,
}

#[derive(Clone, PartialEq, Eq)]
enum BrowserProfileAuthorityIdentity {
    Selected {
        key: CredentialProfileKey,
        revision: CredentialProfileRevision,
    },
    Implicit {
        scope: CredentialScope,
        provider: CredentialProviderId,
        binding: CredentialProfileBinding,
    },
}

impl BrowserProfileAdapter {
    pub fn new(
        validated: ValidatedSkillRuntimeContract<'_>,
        selection: &CredentialProfileSelectionDecision,
        session_class: BrowserProfileSessionClass,
    ) -> Result<Self, BrowserProfileAdapterError> {
        let contract = validated.contract();
        if contract.auth.kind != AuthKind::BrowserProfile
            || contract.auth.storage != AuthStorage::BrowserProfile
            || !matches!(contract.runtime, RuntimeProtocol::Cli { .. })
        {
            return Err(contract_mismatch());
        }
        let strategy =
            StrategyAdapterContract::compile(validated).map_err(|_| contract_mismatch())?;
        if strategy.kind() != StrategyAdapterKind::BrowserProfile {
            return Err(contract_mismatch());
        }
        let identity = match selection.mode() {
            CredentialProfileSelectionMode::Selected => {
                let profile = selection
                    .selected_profile()
                    .ok_or_else(selection_mismatch)?;
                let key = profile.key();
                if selection.scope() != &key.scope
                    || contract.auth.provider.as_deref() != Some(key.provider.as_str())
                    || key.binding != CredentialProfileBinding::Provider
                    || !selection_matches_contract(&contract.auth.profile_selection, key)
                {
                    return Err(selection_mismatch());
                }
                BrowserProfileAuthorityIdentity::Selected {
                    key: key.clone(),
                    revision: profile.metadata().revision(),
                }
            },
            CredentialProfileSelectionMode::Implicit => {
                let Some((provider, binding)) = selection.implicit_identity() else {
                    return Err(selection_mismatch());
                };
                if !matches!(contract.auth.profile_selection, ProfileSelection::Implicit)
                    || contract.auth.provider.as_deref() != Some(provider.as_str())
                    || binding != &CredentialProfileBinding::Provider
                {
                    return Err(selection_mismatch());
                }
                BrowserProfileAuthorityIdentity::Implicit {
                    scope: selection.scope().clone(),
                    provider: provider.clone(),
                    binding: binding.clone(),
                }
            },
            CredentialProfileSelectionMode::None => return Err(selection_mismatch()),
        };

        Ok(Self {
            strategy,
            identity,
            session_class,
        })
    }

    /// Produce the common, model-safe status projection after exact binding checks.
    pub fn project_status(
        &self,
        observation: &BrowserProfileObservation,
    ) -> Result<StrategyAuthStatus, BrowserProfileAdapterError> {
        self.validate_observation(observation)?;
        let revision = StrategyStateRevision::new(observation.session_revision.get())
            .map_err(|_| invalid_session_revision())?;
        self.strategy
            .status(revision, observation.state)
            .map_err(|_| contract_mismatch())
    }

    /// Prepare a move-only delegation from one ready browser-controller observation.
    /// This does not authorize dispatch by itself; [`Self::authorize_dispatch`] must
    /// consume it after checking a fresh observation.
    pub fn prepare_dispatch(
        &self,
        observation: &BrowserProfileObservation,
    ) -> Result<PreparedBrowserProfileDelegation, BrowserProfileAdapterError> {
        self.validate_ready_observation(observation)?;
        Ok(PreparedBrowserProfileDelegation {
            identity: self.identity.clone(),
            session_class: self.session_class,
            session_revision: observation.session_revision,
        })
    }

    /// Revalidate immediately before browser dispatch. Any profile/session replacement
    /// or readiness change invalidates the prepared delegation instead of falling back
    /// to another profile or exporting credentials.
    pub fn authorize_dispatch(
        &self,
        prepared: PreparedBrowserProfileDelegation,
        current: &BrowserProfileObservation,
    ) -> Result<BrowserProfileDispatchAuthority, BrowserProfileAdapterError> {
        self.validate_ready_observation(current)?;
        if prepared.identity != self.identity
            || prepared.session_class != self.session_class
            || prepared.session_revision != current.session_revision
        {
            return Err(stale_prepared_delegation());
        }
        Ok(BrowserProfileDispatchAuthority {
            identity: prepared.identity,
            session_class: prepared.session_class,
            session_revision: prepared.session_revision,
        })
    }

    fn validate_ready_observation(
        &self,
        observation: &BrowserProfileObservation,
    ) -> Result<(), BrowserProfileAdapterError> {
        self.validate_observation(observation)?;
        if observation.state != AuthState::Ready {
            return Err(not_ready());
        }
        Ok(())
    }

    fn validate_observation(
        &self,
        observation: &BrowserProfileObservation,
    ) -> Result<(), BrowserProfileAdapterError> {
        let identity_matches = match (&self.identity, &observation.identity) {
            (
                BrowserProfileAuthorityIdentity::Selected { key, revision },
                BrowserProfileObservedIdentity::Selected {
                    key: observed_key,
                    revision: observed_revision,
                },
            ) => key == observed_key && revision == observed_revision,
            (
                BrowserProfileAuthorityIdentity::Implicit {
                    scope,
                    provider,
                    binding,
                },
                BrowserProfileObservedIdentity::Implicit {
                    scope: observed_scope,
                    provider: observed_provider,
                    binding: observed_binding,
                },
            ) => {
                scope == observed_scope
                    && provider == observed_provider
                    && binding == observed_binding
            },
            _ => false,
        };
        if !identity_matches || observation.session_class != self.session_class {
            return Err(observation_mismatch());
        }
        Ok(())
    }
}

/// First half of the pre-dispatch revalidation protocol. It is deliberately move-only
/// and contains no browser session handle or credential material.
pub struct PreparedBrowserProfileDelegation {
    identity: BrowserProfileAuthorityIdentity,
    session_class: BrowserProfileSessionClass,
    session_revision: BrowserProfileSessionRevision,
}

/// Final one-call authority consumed by the trusted browser controller. The controller
/// uses the public profile key only to resolve its own profile/session; it must not
/// return cookies or copied profile state to the generic runtime.
pub struct BrowserProfileDispatchAuthority {
    identity: BrowserProfileAuthorityIdentity,
    session_class: BrowserProfileSessionClass,
    session_revision: BrowserProfileSessionRevision,
}

impl BrowserProfileDispatchAuthority {
    pub fn selected_profile_key(&self) -> Option<&CredentialProfileKey> {
        match &self.identity {
            BrowserProfileAuthorityIdentity::Selected { key, .. } => Some(key),
            BrowserProfileAuthorityIdentity::Implicit { .. } => None,
        }
    }

    pub fn selected_profile_revision(&self) -> Option<CredentialProfileRevision> {
        match &self.identity {
            BrowserProfileAuthorityIdentity::Selected { revision, .. } => Some(*revision),
            BrowserProfileAuthorityIdentity::Implicit { .. } => None,
        }
    }

    pub fn implicit_identity(
        &self,
    ) -> Option<(
        &CredentialScope,
        &CredentialProviderId,
        &CredentialProfileBinding,
    )> {
        match &self.identity {
            BrowserProfileAuthorityIdentity::Implicit {
                scope,
                provider,
                binding,
            } => Some((scope, provider, binding)),
            BrowserProfileAuthorityIdentity::Selected { .. } => None,
        }
    }

    pub fn session_class(&self) -> BrowserProfileSessionClass {
        self.session_class
    }

    pub fn session_revision(&self) -> BrowserProfileSessionRevision {
        self.session_revision
    }
}

fn selection_matches_contract(selection: &ProfileSelection, key: &CredentialProfileKey) -> bool {
    match selection {
        ProfileSelection::Fixed { alias } => key.alias.as_str() == alias,
        ProfileSelection::Selectable { .. } => true,
        ProfileSelection::None | ProfileSelection::Implicit => false,
    }
}

const fn contract_mismatch() -> BrowserProfileAdapterError {
    BrowserProfileAdapterError::new(
        BrowserProfileAdapterErrorCode::ContractMismatch,
        "runtime_contract",
        "the runtime contract is not a supported browser-profile delegation",
    )
}

const fn selection_mismatch() -> BrowserProfileAdapterError {
    BrowserProfileAdapterError::new(
        BrowserProfileAdapterErrorCode::SelectionMismatch,
        "profile_selection",
        "the selected browser profile does not match the validated runtime contract",
    )
}

const fn observation_mismatch() -> BrowserProfileAdapterError {
    BrowserProfileAdapterError::new(
        BrowserProfileAdapterErrorCode::ObservationMismatch,
        "browser_observation",
        "the browser observation does not match the bound profile identity and session class",
    )
}

const fn invalid_session_revision() -> BrowserProfileAdapterError {
    BrowserProfileAdapterError::new(
        BrowserProfileAdapterErrorCode::InvalidSessionRevision,
        "session_revision",
        "the browser session revision must be non-zero",
    )
}

const fn not_ready() -> BrowserProfileAdapterError {
    BrowserProfileAdapterError::new(
        BrowserProfileAdapterErrorCode::NotReady,
        "browser_observation",
        "the exact browser profile session is not ready for dispatch",
    )
}

const fn stale_prepared_delegation() -> BrowserProfileAdapterError {
    BrowserProfileAdapterError::new(
        BrowserProfileAdapterErrorCode::StalePreparedDelegation,
        "prepared_delegation",
        "the browser profile session changed after delegation preparation",
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use static_assertions::assert_not_impl_any;

    use super::*;
    use crate::{
        credential_profiles::{
            CredentialProfileAvailability, CredentialProfileMetadata,
            CredentialProfileRegistrySnapshot,
        },
        manifest::{
            ApprovalClass, AuthContract, AuthRequirement, PolicyFloor, RuntimeLimits,
            RuntimeProtocol, RuntimeRequirements, SkillRuntimeContract,
            SkillRuntimeContractVersion,
        },
        manifest_validation::validate_skill_runtime_contract,
        profile_selection::{
            select_credential_profile_from_snapshot, CredentialProfileSelectionRequest,
        },
        strategy_adapter::{StrategyAuthDemand, StrategyAuthReadiness},
    };

    fn scope(principal: &str) -> crate::credential_profiles::CredentialScope {
        crate::credential_profiles::CredentialScope::new(principal, "default").expect("scope")
    }

    fn contract(alias: &str) -> SkillRuntimeContract {
        SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires: RuntimeRequirements {
                bins: BTreeSet::from(["browser-controller-fixture".to_owned()]),
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
                kind: AuthKind::BrowserProfile,
                requirement: AuthRequirement::Required,
                provider: Some("browser".to_owned()),
                profile_selection: ProfileSelection::Fixed {
                    alias: alias.to_owned(),
                },
                storage: AuthStorage::BrowserProfile,
                ..AuthContract::default()
            },
            policy_floor: PolicyFloor {
                approval: ApprovalClass::ConditionalExternalSideEffect,
                ..PolicyFloor::default()
            },
        }
    }

    fn profile(
        principal: &str,
        alias: &str,
        profile_revision: u64,
        state: AuthState,
    ) -> CredentialProfileStatus {
        let key = CredentialProfileKey::new(
            scope(principal),
            "browser",
            alias,
            CredentialProfileBinding::Provider,
        )
        .expect("key");
        let metadata = CredentialProfileMetadata::new(
            key,
            None,
            false,
            CredentialProfileAvailability::Enabled,
            CredentialProfileRevision::new(profile_revision).expect("profile revision"),
        )
        .expect("metadata");
        CredentialProfileStatus::new(metadata, state).expect("status")
    }

    fn selection(
        profile: CredentialProfileStatus,
        alias: &str,
    ) -> CredentialProfileSelectionDecision {
        let selected_scope = profile.key().scope.clone();
        let snapshot =
            CredentialProfileRegistrySnapshot::new(selected_scope.clone(), vec![profile])
                .expect("snapshot");
        let request = CredentialProfileSelectionRequest::new(
            selected_scope,
            Some("browser"),
            CredentialProfileBinding::Provider,
            &ProfileSelection::Fixed {
                alias: alias.to_owned(),
            },
            None,
        )
        .expect("request");
        select_credential_profile_from_snapshot(&request, &snapshot).expect("selection")
    }

    fn implicit_selection(selected_scope: &CredentialScope) -> CredentialProfileSelectionDecision {
        let snapshot = CredentialProfileRegistrySnapshot::new(selected_scope.clone(), Vec::new())
            .expect("snapshot");
        let request = CredentialProfileSelectionRequest::new(
            selected_scope.clone(),
            Some("browser"),
            CredentialProfileBinding::Provider,
            &ProfileSelection::Implicit,
            None,
        )
        .expect("request");
        select_credential_profile_from_snapshot(&request, &snapshot).expect("selection")
    }

    fn adapter_and_observation(
        state: AuthState,
    ) -> (BrowserProfileAdapter, BrowserProfileObservation) {
        let selected = profile("owner", "personal", 7, state);
        let decision = selection(selected.clone(), "personal");
        let source = contract("personal");
        let validated = validate_skill_runtime_contract(&source).expect("contract");
        let adapter = BrowserProfileAdapter::new(
            validated,
            &decision,
            BrowserProfileSessionClass::CdpUserProfile,
        )
        .expect("adapter");
        let observation = BrowserProfileObservation::selected(
            selected,
            BrowserProfileSessionClass::CdpUserProfile,
            BrowserProfileSessionRevision::new(11).expect("session revision"),
        );
        (adapter, observation)
    }

    #[test]
    fn ready_profile_requires_fresh_two_step_dispatch_authority() {
        let (adapter, observation) = adapter_and_observation(AuthState::Ready);
        let status = adapter.project_status(&observation).expect("status");
        assert_eq!(
            status.readiness(StrategyAuthDemand::AuthenticationRequired),
            StrategyAuthReadiness::Ready
        );
        let prepared = adapter.prepare_dispatch(&observation).expect("prepared");
        let authority = adapter
            .authorize_dispatch(prepared, &observation)
            .expect("authority");
        assert_eq!(
            authority
                .selected_profile_key()
                .expect("selected profile")
                .alias
                .as_str(),
            "personal"
        );
        assert_eq!(
            authority
                .selected_profile_revision()
                .expect("selected revision")
                .get(),
            7
        );
        assert_eq!(authority.session_revision().get(), 11);
        assert_eq!(
            authority.session_class(),
            BrowserProfileSessionClass::CdpUserProfile
        );
    }

    #[test]
    fn status_projection_is_safe_and_contains_no_profile_identity() {
        let (adapter, observation) = adapter_and_observation(AuthState::Missing);
        let status = adapter.project_status(&observation).expect("status");
        let json = serde_json::to_string(&status).expect("safe status");
        assert!(!json.contains("personal"));
        assert!(!json.contains("owner"));
        assert!(!json.contains("profile_selection"));
        assert!(!json.contains("profile_revision"));
        assert_eq!(
            status.readiness(StrategyAuthDemand::AuthenticationRequired),
            StrategyAuthReadiness::InteractionRequired
        );
        assert_eq!(
            adapter
                .prepare_dispatch(&observation)
                .err()
                .expect("not ready")
                .code,
            BrowserProfileAdapterErrorCode::NotReady
        );
    }

    #[test]
    fn profile_scope_alias_revision_and_session_class_are_exact() {
        let (adapter, _observation) = adapter_and_observation(AuthState::Ready);
        let cases = [
            BrowserProfileObservation::selected(
                profile("other", "personal", 7, AuthState::Ready),
                BrowserProfileSessionClass::CdpUserProfile,
                BrowserProfileSessionRevision::new(11).unwrap(),
            ),
            BrowserProfileObservation::selected(
                profile("owner", "other", 7, AuthState::Ready),
                BrowserProfileSessionClass::CdpUserProfile,
                BrowserProfileSessionRevision::new(11).unwrap(),
            ),
            BrowserProfileObservation::selected(
                profile("owner", "personal", 8, AuthState::Ready),
                BrowserProfileSessionClass::CdpUserProfile,
                BrowserProfileSessionRevision::new(11).unwrap(),
            ),
            BrowserProfileObservation::selected(
                profile("owner", "personal", 7, AuthState::Ready),
                BrowserProfileSessionClass::IsolatedHeaded,
                BrowserProfileSessionRevision::new(11).unwrap(),
            ),
        ];
        for candidate in cases {
            assert_eq!(
                adapter
                    .project_status(&candidate)
                    .expect_err("binding drift")
                    .code,
                BrowserProfileAdapterErrorCode::ObservationMismatch
            );
        }
    }

    #[test]
    fn session_replacement_or_readiness_change_invalidates_prepared_delegation() {
        let (adapter, observation) = adapter_and_observation(AuthState::Ready);
        let prepared = adapter.prepare_dispatch(&observation).expect("prepared");
        let replacement = BrowserProfileObservation::selected(
            profile("owner", "personal", 7, AuthState::Ready),
            observation.session_class(),
            BrowserProfileSessionRevision::new(12).unwrap(),
        );
        let replacement_error = match adapter.authorize_dispatch(prepared, &replacement) {
            Ok(_) => panic!("session replacement must fail closed"),
            Err(error) => error,
        };
        assert_eq!(
            replacement_error.code,
            BrowserProfileAdapterErrorCode::StalePreparedDelegation
        );

        let signed_out = profile("owner", "personal", 7, AuthState::Missing);
        let signed_out = BrowserProfileObservation::selected(
            signed_out,
            observation.session_class(),
            observation.session_revision(),
        );
        let signed_out_error = match adapter.prepare_dispatch(&signed_out) {
            Ok(_) => panic!("signed-out profile must not prepare dispatch"),
            Err(error) => error,
        };
        assert_eq!(
            signed_out_error.code,
            BrowserProfileAdapterErrorCode::NotReady
        );
    }

    #[test]
    fn fixed_profile_selection_cannot_be_rebound_by_an_adapter_caller() {
        let selected = profile("owner", "work", 1, AuthState::Ready);
        let decision = selection(selected, "work");
        let source = contract("personal");
        let validated = validate_skill_runtime_contract(&source).expect("contract");
        let error = BrowserProfileAdapter::new(
            validated,
            &decision,
            BrowserProfileSessionClass::CdpUserProfile,
        )
        .err()
        .expect("fixed alias mismatch");
        assert_eq!(
            error.code,
            BrowserProfileAdapterErrorCode::SelectionMismatch
        );
    }

    #[test]
    fn implicit_controller_owned_profile_is_bound_without_exporting_an_alias() {
        let selected_scope = scope("owner");
        let decision = implicit_selection(&selected_scope);
        let mut source = contract("unused");
        source.auth.profile_selection = ProfileSelection::Implicit;
        let validated = validate_skill_runtime_contract(&source).expect("contract");
        let adapter = BrowserProfileAdapter::new(
            validated,
            &decision,
            BrowserProfileSessionClass::CdpUserProfile,
        )
        .expect("adapter");
        let observation = BrowserProfileObservation::implicit(
            selected_scope.clone(),
            CredentialProviderId::new("browser").unwrap(),
            CredentialProfileBinding::Provider,
            AuthState::Ready,
            BrowserProfileSessionClass::CdpUserProfile,
            BrowserProfileSessionRevision::new(3).unwrap(),
        );
        let prepared = adapter.prepare_dispatch(&observation).expect("prepared");
        let authority = adapter
            .authorize_dispatch(prepared, &observation)
            .expect("authority");
        assert!(authority.selected_profile_key().is_none());
        let (authority_scope, provider, binding) =
            authority.implicit_identity().expect("implicit identity");
        assert_eq!(authority_scope, &selected_scope);
        assert_eq!(provider.as_str(), "browser");
        assert_eq!(binding, &CredentialProfileBinding::Provider);
    }

    #[test]
    fn implicit_profile_rejects_scope_provider_and_identity_mode_drift() {
        let selected_scope = scope("owner");
        let decision = implicit_selection(&selected_scope);
        let mut source = contract("unused");
        source.auth.profile_selection = ProfileSelection::Implicit;
        let validated = validate_skill_runtime_contract(&source).expect("contract");
        let adapter = BrowserProfileAdapter::new(
            validated,
            &decision,
            BrowserProfileSessionClass::CdpUserProfile,
        )
        .expect("adapter");
        let cases = [
            BrowserProfileObservation::implicit(
                scope("other"),
                CredentialProviderId::new("browser").unwrap(),
                CredentialProfileBinding::Provider,
                AuthState::Ready,
                BrowserProfileSessionClass::CdpUserProfile,
                BrowserProfileSessionRevision::new(3).unwrap(),
            ),
            BrowserProfileObservation::implicit(
                selected_scope,
                CredentialProviderId::new("other-browser").unwrap(),
                CredentialProfileBinding::Provider,
                AuthState::Ready,
                BrowserProfileSessionClass::CdpUserProfile,
                BrowserProfileSessionRevision::new(3).unwrap(),
            ),
            BrowserProfileObservation::selected(
                profile("owner", "personal", 1, AuthState::Ready),
                BrowserProfileSessionClass::CdpUserProfile,
                BrowserProfileSessionRevision::new(3).unwrap(),
            ),
        ];
        for observation in cases {
            assert_eq!(
                adapter
                    .project_status(&observation)
                    .expect_err("identity drift")
                    .code,
                BrowserProfileAdapterErrorCode::ObservationMismatch
            );
        }
    }

    #[test]
    fn dispatch_authorities_are_move_only_non_debug_and_nonserializable() {
        assert_not_impl_any!(BrowserProfileObservation: Clone, Copy, fmt::Debug, serde::Serialize);
        assert_not_impl_any!(PreparedBrowserProfileDelegation: Clone, Copy, fmt::Debug, serde::Serialize);
        assert_not_impl_any!(BrowserProfileDispatchAuthority: Clone, Copy, fmt::Debug, serde::Serialize);
        assert_not_impl_any!(BrowserProfileAdapter: Clone, Copy, fmt::Debug, serde::Serialize);
    }

    #[test]
    fn invalid_zero_session_revision_is_value_free() {
        let error = BrowserProfileSessionRevision::new(0).expect_err("zero revision");
        assert_eq!(
            error.code,
            BrowserProfileAdapterErrorCode::InvalidSessionRevision
        );
        assert_eq!(
            serde_json::to_string(&error).expect("safe error"),
            r#"{"code":"invalid_session_revision","field":"session_revision","message":"the browser session revision must be non-zero"}"#
        );
    }
}
