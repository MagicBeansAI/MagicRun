//! Bounded, in-memory cache for verified CLI authentication status.
//!
//! Phase 4C stores only a sanitized readiness projection produced by Phase 4B and binds
//! it to the exact lifecycle plan, process epoch, profile revision, scoped directory
//! identity/revision, policy revision, and monotonic expiry. The cache is advisory status,
//! not execution authority; the eventual executor must still revalidate profile and path
//! authority immediately before materialization.

use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    sync::Mutex,
    time::{Duration, Instant},
};

use serde::Serialize;

use crate::{
    credential_lifecycle::{CredentialLifecycleOperation, CredentialLifecyclePlan},
    credential_lifecycle_observation::{
        CredentialIdentityVerification, CredentialLifecycleStatusResult,
    },
    credential_profiles::{
        CredentialProfileBinding, CredentialProfileKey, CredentialProviderId, CredentialScope,
    },
    manifest::AuthState,
    scoped_paths::{ScopedPath, ScopedPathKind},
};

pub const CREDENTIAL_VERIFIED_STATUS_CACHE_V1: &str =
    "tool-runtime.credential-verified-status-cache.v1";
pub const MAX_CREDENTIAL_STATUS_CACHE_ENTRIES: usize = 256;
pub const MAX_CREDENTIAL_STATUS_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatusCacheErrorCode {
    InvalidProcessEpoch,
    ProcessEpochMismatch,
    InvalidPolicyRevision,
    InvalidDirectoryRevision,
    InvalidTtl,
    WrongOperation,
    DirectoryTargetMismatch,
    DirectoryUnavailable,
    UncacheableStatus,
    ObservationPlanMismatch,
    StaleObservation,
    CapacityExceeded,
    LockPoisoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CredentialStatusCacheError {
    pub code: CredentialStatusCacheErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl CredentialStatusCacheError {
    const fn new(
        code: CredentialStatusCacheErrorCode,
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

impl fmt::Display for CredentialStatusCacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for CredentialStatusCacheError {}

macro_rules! nonzero_revision {
    ($name:ident, $invalid:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);

        impl $name {
            pub fn new(value: u64) -> Result<Self, CredentialStatusCacheError> {
                if value == 0 {
                    return Err($invalid());
                }
                Ok(Self(value))
            }

            pub fn get(self) -> u64 {
                self.0
            }
        }
    };
}

nonzero_revision!(CredentialProcessEpoch, invalid_process_epoch);
nonzero_revision!(CredentialPolicyRevision, invalid_policy_revision);
nonzero_revision!(CredentialAuthDirectoryRevision, invalid_directory_revision);

/// Monotonic observation time. It cannot be persisted or reconstructed from wall time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CredentialStatusCacheInstant(Instant);

impl CredentialStatusCacheInstant {
    pub fn now() -> Self {
        Self(Instant::now())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialStatusCacheTtl(Duration);

impl CredentialStatusCacheTtl {
    pub fn new(value: Duration) -> Result<Self, CredentialStatusCacheError> {
        if value.is_zero() || value > MAX_CREDENTIAL_STATUS_CACHE_TTL {
            return Err(invalid_ttl());
        }
        Ok(Self(value))
    }

    pub fn get(self) -> Duration {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatusCacheMissReason {
    Absent,
    Expired,
    ProcessEpochChanged,
    PolicyChanged,
    ProfileRevisionChanged,
    LifecycleContractChanged,
    DirectoryRevisionChanged,
    DirectoryChanged,
}

/// Non-authorizing snapshot of a successful cache lookup.
#[derive(Debug, PartialEq, Eq)]
pub struct CredentialStatusCacheHit {
    schema_version: &'static str,
    identity_verification: CredentialIdentityVerification,
}

impl CredentialStatusCacheHit {
    pub fn schema_version(&self) -> &'static str {
        self.schema_version
    }

    pub fn state(&self) -> AuthState {
        AuthState::Ready
    }

    pub fn identity_verification(&self) -> CredentialIdentityVerification {
        self.identity_verification
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CredentialStatusCacheLookup {
    Hit(CredentialStatusCacheHit),
    Miss(CredentialStatusCacheMissReason),
}

/// One consume-once right to publish the result of a status probe that starts under an
/// exact cache mutation generation. Authentication or lifecycle invalidation makes every
/// older ticket stale, preventing an in-flight probe from resurrecting readiness.
pub struct CredentialStatusObservationTicket {
    process_epoch: CredentialProcessEpoch,
    policy_revision: CredentialPolicyRevision,
    mutation_generation: u64,
    target: CredentialStatusCacheTarget,
    plan: CredentialLifecyclePlan,
    directory: ScopedPath,
    directory_revision: CredentialAuthDirectoryRevision,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum CredentialStatusCacheTarget {
    Profile(CredentialProfileKey),
    Implicit {
        scope: CredentialScope,
        provider: CredentialProviderId,
        binding: CredentialProfileBinding,
    },
}

struct CredentialStatusCacheEntry {
    process_epoch: CredentialProcessEpoch,
    policy_revision: CredentialPolicyRevision,
    plan: CredentialLifecyclePlan,
    directory: ScopedPath,
    directory_revision: CredentialAuthDirectoryRevision,
    identity_verification: CredentialIdentityVerification,
    expires_at: Instant,
}

struct CredentialStatusCacheState {
    process_epoch: CredentialProcessEpoch,
    policy_revision: CredentialPolicyRevision,
    mutation_generation: u64,
    entries: BTreeMap<CredentialStatusCacheTarget, CredentialStatusCacheEntry>,
}

/// Process-local verified-status cache. Entries and keys are intentionally neither
/// serializable nor exposed through debug formatting.
pub struct CredentialVerifiedStatusCache {
    state: Mutex<CredentialStatusCacheState>,
}

impl fmt::Debug for CredentialVerifiedStatusCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entry_count = self
            .state
            .lock()
            .map(|state| state.entries.len())
            .unwrap_or_default();
        formatter
            .debug_struct("CredentialVerifiedStatusCache")
            .field("schema_version", &CREDENTIAL_VERIFIED_STATUS_CACHE_V1)
            .field("entry_count", &entry_count)
            .finish()
    }
}

impl CredentialVerifiedStatusCache {
    pub fn new(
        process_epoch: CredentialProcessEpoch,
        policy_revision: CredentialPolicyRevision,
    ) -> Self {
        Self {
            state: Mutex::new(CredentialStatusCacheState {
                process_epoch,
                policy_revision,
                mutation_generation: 1,
                entries: BTreeMap::new(),
            }),
        }
    }

    /// Begin one status probe after validating its exact plan and credential directory.
    pub fn begin_observation(
        &self,
        plan: &CredentialLifecyclePlan,
        directory: &ScopedPath,
        directory_revision: CredentialAuthDirectoryRevision,
    ) -> Result<CredentialStatusObservationTicket, CredentialStatusCacheError> {
        ensure_status_plan(plan)?;
        validate_directory_target(plan, directory)?;
        directory
            .revalidate()
            .map_err(|_| directory_unavailable())?;
        let state = self.state.lock().map_err(|_| lock_poisoned())?;
        Ok(CredentialStatusObservationTicket {
            process_epoch: state.process_epoch,
            policy_revision: state.policy_revision,
            mutation_generation: state.mutation_generation,
            target: cache_target(plan),
            plan: plan.clone(),
            directory: directory.clone(),
            directory_revision,
        })
    }

    /// Consume a ticket and ready Phase 4B result, retaining only a sanitized verification
    /// class when no lifecycle/authentication invalidation intervened.
    pub fn store_ready(
        &self,
        ticket: CredentialStatusObservationTicket,
        result: CredentialLifecycleStatusResult,
        observed_at: CredentialStatusCacheInstant,
        ttl: CredentialStatusCacheTtl,
    ) -> Result<(), CredentialStatusCacheError> {
        if result.plan() != &ticket.plan {
            return Err(observation_plan_mismatch());
        }
        let verification = result.identity_verification();
        if result.state() != AuthState::Ready
            || !matches!(
                verification,
                CredentialIdentityVerification::NotDeclared
                    | CredentialIdentityVerification::Matched
            )
        {
            return Err(uncacheable_status());
        }
        if ticket.directory.revalidate().is_err() {
            self.invalidate_target(&ticket.target)?;
            return Err(directory_unavailable());
        }
        let expires_at = observed_at.0.checked_add(ttl.0).ok_or_else(invalid_ttl)?;
        let mut state = self.state.lock().map_err(|_| lock_poisoned())?;
        if state.process_epoch != ticket.process_epoch
            || state.policy_revision != ticket.policy_revision
            || state.mutation_generation != ticket.mutation_generation
        {
            return Err(stale_observation());
        }
        state
            .entries
            .retain(|_, entry| entry.expires_at > observed_at.0);
        if !state.entries.contains_key(&ticket.target)
            && state.entries.len() >= MAX_CREDENTIAL_STATUS_CACHE_ENTRIES
        {
            return Err(capacity_exceeded());
        }
        let entry = CredentialStatusCacheEntry {
            process_epoch: state.process_epoch,
            policy_revision: state.policy_revision,
            plan: ticket.plan,
            directory: ticket.directory,
            directory_revision: ticket.directory_revision,
            identity_verification: verification,
            expires_at,
        };
        state.entries.insert(ticket.target, entry);
        Ok(())
    }

    pub fn lookup(
        &self,
        plan: &CredentialLifecyclePlan,
        directory: &ScopedPath,
        directory_revision: CredentialAuthDirectoryRevision,
        now: CredentialStatusCacheInstant,
    ) -> Result<CredentialStatusCacheLookup, CredentialStatusCacheError> {
        ensure_status_plan(plan)?;
        validate_directory_target(plan, directory)?;
        let target = cache_target(plan);
        if directory.revalidate().is_err() {
            self.invalidate_target(&target)?;
            return Ok(CredentialStatusCacheLookup::Miss(
                CredentialStatusCacheMissReason::DirectoryChanged,
            ));
        }

        let mut state = self.state.lock().map_err(|_| lock_poisoned())?;
        let Some(entry) = state.entries.get(&target) else {
            return Ok(CredentialStatusCacheLookup::Miss(
                CredentialStatusCacheMissReason::Absent,
            ));
        };
        let (miss, identity_verification) = (
            if entry.expires_at <= now.0 {
                Some(CredentialStatusCacheMissReason::Expired)
            } else if entry.process_epoch != state.process_epoch {
                Some(CredentialStatusCacheMissReason::ProcessEpochChanged)
            } else if entry.policy_revision != state.policy_revision {
                Some(CredentialStatusCacheMissReason::PolicyChanged)
            } else if entry.plan.selected_profile_revision() != plan.selected_profile_revision() {
                Some(CredentialStatusCacheMissReason::ProfileRevisionChanged)
            } else if entry.plan != *plan {
                Some(CredentialStatusCacheMissReason::LifecycleContractChanged)
            } else if entry.directory_revision != directory_revision {
                Some(CredentialStatusCacheMissReason::DirectoryRevisionChanged)
            } else if !entry.directory.has_same_directory_identity(directory) {
                Some(CredentialStatusCacheMissReason::DirectoryChanged)
            } else {
                None
            },
            entry.identity_verification,
        );
        if let Some(reason) = miss {
            state.entries.remove(&target);
            advance_mutation_generation(&mut state);
            return Ok(CredentialStatusCacheLookup::Miss(reason));
        }
        Ok(CredentialStatusCacheLookup::Hit(CredentialStatusCacheHit {
            schema_version: CREDENTIAL_VERIFIED_STATUS_CACHE_V1,
            identity_verification,
        }))
    }

    /// Invalidate one target after any downstream authentication failure.
    pub fn invalidate_after_auth_failure(
        &self,
        plan: &CredentialLifecyclePlan,
    ) -> Result<bool, CredentialStatusCacheError> {
        self.invalidate_target(&cache_target(plan))
    }

    /// A successful login, logout, or refresh invalidates status and requires a fresh probe.
    pub fn invalidate_after_lifecycle_mutation(
        &self,
        plan: &CredentialLifecyclePlan,
    ) -> Result<bool, CredentialStatusCacheError> {
        if plan.operation() == CredentialLifecycleOperation::Status {
            return Err(wrong_operation());
        }
        self.invalidate_target(&cache_target(plan))
    }

    /// Atomically require the caller's exact process epoch and invalidate readiness for a
    /// lifecycle mutation. This closes the check/invalidate race for adjacent coordinators.
    pub fn invalidate_after_lifecycle_mutation_for_process_epoch(
        &self,
        plan: &CredentialLifecyclePlan,
        expected_process_epoch: CredentialProcessEpoch,
    ) -> Result<bool, CredentialStatusCacheError> {
        if plan.operation() == CredentialLifecycleOperation::Status {
            return Err(wrong_operation());
        }
        let target = cache_target(plan);
        let mut state = self.state.lock().map_err(|_| lock_poisoned())?;
        if state.process_epoch != expected_process_epoch {
            return Err(process_epoch_mismatch());
        }
        let removed = state.entries.remove(&target).is_some();
        advance_mutation_generation(&mut state);
        Ok(removed)
    }

    pub fn invalidate_directory(
        &self,
        directory: &ScopedPath,
    ) -> Result<usize, CredentialStatusCacheError> {
        let mut state = self.state.lock().map_err(|_| lock_poisoned())?;
        let before = state.entries.len();
        state
            .entries
            .retain(|_, entry| !entry.directory.has_same_directory_identity(directory));
        let removed = before - state.entries.len();
        advance_mutation_generation(&mut state);
        Ok(removed)
    }

    pub fn replace_process_epoch(
        &self,
        process_epoch: CredentialProcessEpoch,
    ) -> Result<usize, CredentialStatusCacheError> {
        let mut state = self.state.lock().map_err(|_| lock_poisoned())?;
        if state.process_epoch == process_epoch {
            return Ok(0);
        }
        let removed = state.entries.len();
        state.entries.clear();
        state.process_epoch = process_epoch;
        advance_mutation_generation(&mut state);
        Ok(removed)
    }

    pub fn replace_policy_revision(
        &self,
        policy_revision: CredentialPolicyRevision,
    ) -> Result<usize, CredentialStatusCacheError> {
        let mut state = self.state.lock().map_err(|_| lock_poisoned())?;
        if state.policy_revision == policy_revision {
            return Ok(0);
        }
        let removed = state.entries.len();
        state.entries.clear();
        state.policy_revision = policy_revision;
        advance_mutation_generation(&mut state);
        Ok(removed)
    }

    pub fn entry_count(&self) -> Result<usize, CredentialStatusCacheError> {
        self.state
            .lock()
            .map(|state| state.entries.len())
            .map_err(|_| lock_poisoned())
    }

    fn invalidate_target(
        &self,
        target: &CredentialStatusCacheTarget,
    ) -> Result<bool, CredentialStatusCacheError> {
        self.state
            .lock()
            .map(|mut state| {
                let removed = state.entries.remove(target).is_some();
                advance_mutation_generation(&mut state);
                removed
            })
            .map_err(|_| lock_poisoned())
    }
}

fn advance_mutation_generation(state: &mut CredentialStatusCacheState) {
    let Some(next) = state.mutation_generation.checked_add(1) else {
        state.mutation_generation = 1;
        state.entries.clear();
        return;
    };
    state.mutation_generation = next;
}

fn ensure_status_plan(plan: &CredentialLifecyclePlan) -> Result<(), CredentialStatusCacheError> {
    if plan.operation() != CredentialLifecycleOperation::Status {
        return Err(wrong_operation());
    }
    Ok(())
}

fn validate_directory_target(
    plan: &CredentialLifecyclePlan,
    directory: &ScopedPath,
) -> Result<(), CredentialStatusCacheError> {
    let valid = match plan.selected_profile_key() {
        Some(key) => {
            directory.kind() == ScopedPathKind::CredentialProfile
                && directory.profile_key() == Some(key)
        },
        None => {
            plan.implicit_identity().is_some()
                && directory.kind() == ScopedPathKind::Auth
                && directory.scope() == plan.scope()
        },
    };
    if !valid {
        return Err(directory_target_mismatch());
    }
    Ok(())
}

fn cache_target(plan: &CredentialLifecyclePlan) -> CredentialStatusCacheTarget {
    if let Some(key) = plan.selected_profile_key() {
        return CredentialStatusCacheTarget::Profile(key.clone());
    }
    let (provider, binding) = plan
        .implicit_identity()
        .expect("validated lifecycle plans always have one target mode");
    CredentialStatusCacheTarget::Implicit {
        scope: plan.scope().clone(),
        provider: provider.clone(),
        binding: binding.clone(),
    }
}

const fn invalid_process_epoch() -> CredentialStatusCacheError {
    CredentialStatusCacheError::new(
        CredentialStatusCacheErrorCode::InvalidProcessEpoch,
        "status_cache.process_epoch",
        "the process epoch must be nonzero",
    )
}

const fn invalid_policy_revision() -> CredentialStatusCacheError {
    CredentialStatusCacheError::new(
        CredentialStatusCacheErrorCode::InvalidPolicyRevision,
        "status_cache.policy_revision",
        "the credential policy revision must be nonzero",
    )
}

const fn process_epoch_mismatch() -> CredentialStatusCacheError {
    CredentialStatusCacheError::new(
        CredentialStatusCacheErrorCode::ProcessEpochMismatch,
        "status_cache.process_epoch",
        "the verified-status cache belongs to a different process epoch",
    )
}

const fn invalid_directory_revision() -> CredentialStatusCacheError {
    CredentialStatusCacheError::new(
        CredentialStatusCacheErrorCode::InvalidDirectoryRevision,
        "status_cache.directory_revision",
        "the credential directory revision must be nonzero",
    )
}

const fn invalid_ttl() -> CredentialStatusCacheError {
    CredentialStatusCacheError::new(
        CredentialStatusCacheErrorCode::InvalidTtl,
        "status_cache.ttl",
        "the verified status TTL must be positive and within its fixed ceiling",
    )
}

const fn wrong_operation() -> CredentialStatusCacheError {
    CredentialStatusCacheError::new(
        CredentialStatusCacheErrorCode::WrongOperation,
        "status_cache.operation",
        "the status cache operation requires the declared lifecycle operation",
    )
}

const fn directory_target_mismatch() -> CredentialStatusCacheError {
    CredentialStatusCacheError::new(
        CredentialStatusCacheErrorCode::DirectoryTargetMismatch,
        "status_cache.directory",
        "the credential directory does not belong to the lifecycle target",
    )
}

const fn directory_unavailable() -> CredentialStatusCacheError {
    CredentialStatusCacheError::new(
        CredentialStatusCacheErrorCode::DirectoryUnavailable,
        "status_cache.directory",
        "the credential directory could not be revalidated",
    )
}

const fn uncacheable_status() -> CredentialStatusCacheError {
    CredentialStatusCacheError::new(
        CredentialStatusCacheErrorCode::UncacheableStatus,
        "status_cache.result",
        "only verified ready status may enter the credential status cache",
    )
}

const fn observation_plan_mismatch() -> CredentialStatusCacheError {
    CredentialStatusCacheError::new(
        CredentialStatusCacheErrorCode::ObservationPlanMismatch,
        "status_cache.observation",
        "the status result belongs to a different lifecycle observation",
    )
}

const fn stale_observation() -> CredentialStatusCacheError {
    CredentialStatusCacheError::new(
        CredentialStatusCacheErrorCode::StaleObservation,
        "status_cache.observation",
        "the status observation was invalidated before publication",
    )
}

const fn capacity_exceeded() -> CredentialStatusCacheError {
    CredentialStatusCacheError::new(
        CredentialStatusCacheErrorCode::CapacityExceeded,
        "status_cache.entries",
        "the credential status cache reached its fixed entry limit",
    )
}

const fn lock_poisoned() -> CredentialStatusCacheError {
    CredentialStatusCacheError::new(
        CredentialStatusCacheErrorCode::LockPoisoned,
        "status_cache",
        "the credential status cache is unavailable",
    )
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        collections::BTreeSet,
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        },
        thread,
    };

    use static_assertions::assert_not_impl_any;

    use super::*;
    use crate::{
        credential_lifecycle::CredentialLifecyclePlan,
        credential_lifecycle_observation::{
            evaluate_lifecycle_status, CredentialLifecycleCommandObservation,
            CredentialLifecycleTermination,
        },
        credential_profiles::{
            CreateCredentialProfileReference, CredentialProfileAvailability,
            CredentialProfileError, CredentialProfileMetadata, CredentialProfileRegistry,
            CredentialProfileRegistrySnapshot, CredentialProfileRevision, CredentialProfileStatus,
            ExpectedCredentialIdentity, SetCredentialProfileDisabled,
            UpdateCredentialProfileMetadata,
        },
        manifest::{
            AuthContract, AuthKind, AuthLifecycle, AuthRequirement, AuthStorage, CliInteraction,
            IdentityContract, IdentitySelector, LifecycleHook, LifecycleJsonPredicate,
            LifecycleJsonScalar, LifecycleObservedAuthState, LifecycleStatusObservation,
            LifecycleStatusOutputFormat, LifecycleStatusRule, ProfileSelection, RuntimeLimits,
            RuntimeProtocol, RuntimeRequirements, SkillRuntimeContract,
            SkillRuntimeContractVersion, StdinContract, WorkingDirectoryContract,
        },
        manifest_validation::validate_skill_runtime_contract,
        scoped_paths::{ScopedPathAuthority, ScopedPathComponent},
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        container: PathBuf,
        scopes_root: PathBuf,
        scope: CredentialScope,
    }

    impl Fixture {
        fn new() -> Self {
            let temp_root = fs::canonicalize(std::env::temp_dir()).expect("canonical temp root");
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let container = temp_root.join(format!(
                "tool-runtime-status-cache-{}-{sequence}",
                std::process::id()
            ));
            let scopes_root = container.join("scopes");
            let scope = CredentialScope::new("owner", "default").expect("scope");
            fs::create_dir_all(
                scopes_root
                    .join(scope.principal.as_str())
                    .join(scope.workspace.as_str())
                    .join("auth"),
            )
            .expect("fixture");
            set_mode(&container, 0o700);
            set_mode(&scopes_root, 0o755);
            set_mode(&scopes_root.join(scope.principal.as_str()), 0o755);
            set_mode(
                &scopes_root
                    .join(scope.principal.as_str())
                    .join(scope.workspace.as_str()),
                0o755,
            );
            set_mode(&Self::auth_root_for(&scopes_root, &scope), 0o700);
            Self {
                container,
                scopes_root,
                scope,
            }
        }

        fn auth_root_for(scopes_root: &Path, scope: &CredentialScope) -> PathBuf {
            scopes_root
                .join(scope.principal.as_str())
                .join(scope.workspace.as_str())
                .join("auth")
        }

        fn auth_root(&self) -> PathBuf {
            Self::auth_root_for(&self.scopes_root, &self.scope)
        }

        fn key(&self, provider: &str, alias: &str) -> CredentialProfileKey {
            CredentialProfileKey::new(
                self.scope.clone(),
                provider,
                alias,
                CredentialProfileBinding::Provider,
            )
            .expect("key")
        }

        fn create_profile_directory(&self, key: &CredentialProfileKey) -> ScopedPath {
            let name = format!("profile-{}", key.alias.as_str());
            let path = self.auth_root().join(&name);
            fs::create_dir(&path).expect("profile directory");
            set_mode(&path, 0o700);
            ScopedPathAuthority::open(&self.scopes_root)
                .expect("authority")
                .resolve_profile_root(key, ScopedPathComponent::new(name).expect("component"))
                .expect("profile authority")
        }

        fn resolve_profile_directory(&self, key: &CredentialProfileKey) -> ScopedPath {
            let name = format!("profile-{}", key.alias.as_str());
            ScopedPathAuthority::open(&self.scopes_root)
                .expect("authority")
                .resolve_profile_root(key, ScopedPathComponent::new(name).expect("component"))
                .expect("profile authority")
        }

        fn resolve_auth_root(&self) -> ScopedPath {
            ScopedPathAuthority::open(&self.scopes_root)
                .expect("authority")
                .resolve_auth_root(&self.scope)
                .expect("auth root")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.container);
        }
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("permissions");
    }

    struct OneRegistry(CredentialProfileStatus);

    impl CredentialProfileRegistry for OneRegistry {
        fn snapshot(
            &self,
            scope: &CredentialScope,
        ) -> Result<CredentialProfileRegistrySnapshot, CredentialProfileError> {
            CredentialProfileRegistrySnapshot::new(scope.clone(), vec![self.0.clone()])
        }

        fn status(
            &self,
            key: &CredentialProfileKey,
        ) -> Result<Option<CredentialProfileStatus>, CredentialProfileError> {
            Ok((self.0.key() == key).then(|| self.0.clone()))
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

    fn contract(
        provider: &str,
        selection: ProfileSelection,
        identity: IdentityContract,
        status_variant: &str,
    ) -> SkillRuntimeContract {
        let storage = if selection == ProfileSelection::Implicit {
            AuthStorage::CliOwned
        } else {
            AuthStorage::ScopedDirectory {
                namespace: "provider".to_owned(),
                partition_by_profile: true,
            }
        };
        SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires: RuntimeRequirements {
                bins: BTreeSet::from(["provider-cli".to_owned()]),
                entrypoint: Default::default(),
                environment: Default::default(),
            },
            runtime: RuntimeProtocol::Cli {
                command_prefix: vec!["resource".to_owned()],
                interaction: CliInteraction::Batch,
                stdin: StdinContract::default(),
                working_directory: WorkingDirectoryContract::default(),
                limits: RuntimeLimits::default(),
            },
            auth: AuthContract {
                kind: AuthKind::CliProfile,
                requirement: AuthRequirement::Required,
                provider: Some(provider.to_owned()),
                profile_selection: selection,
                storage,
                lifecycle: AuthLifecycle {
                    status: Some(LifecycleHook {
                        args: vec![
                            "auth".to_owned(),
                            "status".to_owned(),
                            status_variant.to_owned(),
                        ],
                        interaction: CliInteraction::Batch,
                        timeout_secs: Some(30),
                    }),
                    status_observation: Some(LifecycleStatusObservation {
                        format: LifecycleStatusOutputFormat::Json,
                        rules: vec![
                            LifecycleStatusRule {
                                state: LifecycleObservedAuthState::Ready,
                                exit_codes: BTreeSet::from([0]),
                                all: vec![LifecycleJsonPredicate::Equals {
                                    pointer: "/state".to_owned(),
                                    value: LifecycleJsonScalar::String {
                                        value: "ready".to_owned(),
                                    },
                                }],
                            },
                            LifecycleStatusRule {
                                state: LifecycleObservedAuthState::Expired,
                                exit_codes: BTreeSet::from([0]),
                                all: vec![LifecycleJsonPredicate::Equals {
                                    pointer: "/state".to_owned(),
                                    value: LifecycleJsonScalar::String {
                                        value: "expired".to_owned(),
                                    },
                                }],
                            },
                        ],
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
                identity,
                ..AuthContract::default()
            },
            policy_floor: Default::default(),
        }
    }

    fn profile_status(
        key: CredentialProfileKey,
        revision: u64,
        expected_identity: Option<&str>,
    ) -> CredentialProfileStatus {
        CredentialProfileStatus::new(
            CredentialProfileMetadata::new(
                key,
                expected_identity
                    .map(ExpectedCredentialIdentity::new)
                    .transpose()
                    .expect("identity"),
                false,
                CredentialProfileAvailability::Enabled,
                CredentialProfileRevision::new(revision).expect("revision"),
            )
            .expect("metadata"),
            AuthState::Unknown,
        )
        .expect("status")
    }

    fn profile_plan(
        contract: &SkillRuntimeContract,
        status: &CredentialProfileStatus,
        operation: CredentialLifecycleOperation,
    ) -> CredentialLifecyclePlan {
        CredentialLifecyclePlan::for_profile(
            &OneRegistry(status.clone()),
            validate_skill_runtime_contract(contract).expect("validated"),
            status.key(),
            operation,
        )
        .expect("plan")
    }

    fn result(plan: &CredentialLifecyclePlan, payload: &[u8]) -> CredentialLifecycleStatusResult {
        let observation = CredentialLifecycleCommandObservation::new(
            CredentialLifecycleOperation::Status,
            CredentialLifecycleTermination::Exited { code: 0 },
            payload,
            &[],
        )
        .expect("observation");
        evaluate_lifecycle_status(plan, &observation).expect("status result")
    }

    fn cache() -> CredentialVerifiedStatusCache {
        CredentialVerifiedStatusCache::new(
            CredentialProcessEpoch::new(1).expect("epoch"),
            CredentialPolicyRevision::new(1).expect("policy"),
        )
    }

    fn directory_revision(value: u64) -> CredentialAuthDirectoryRevision {
        CredentialAuthDirectoryRevision::new(value).expect("directory revision")
    }

    fn ttl() -> CredentialStatusCacheTtl {
        CredentialStatusCacheTtl::new(Duration::from_secs(30)).expect("ttl")
    }

    fn publish_ready(
        cache: &CredentialVerifiedStatusCache,
        plan: &CredentialLifecyclePlan,
        result: CredentialLifecycleStatusResult,
        directory: &ScopedPath,
        directory_revision: CredentialAuthDirectoryRevision,
        observed_at: CredentialStatusCacheInstant,
        ttl: CredentialStatusCacheTtl,
    ) -> Result<(), CredentialStatusCacheError> {
        let ticket = cache.begin_observation(plan, directory, directory_revision)?;
        cache.store_ready(ticket, result, observed_at, ttl)
    }

    #[test]
    fn verified_ready_status_round_trips_without_cache_authority_or_identity_values() {
        assert_not_impl_any!(CredentialLifecycleStatusResult: Clone);
        assert_not_impl_any!(CredentialStatusCacheHit: Clone, Serialize);
        assert_not_impl_any!(CredentialStatusObservationTicket: Clone, std::fmt::Debug, Serialize);
        let fixture = Fixture::new();
        let key = fixture.key("provider", "work");
        let directory = fixture.create_profile_directory(&key);
        let contract = contract(
            "provider",
            ProfileSelection::Fixed {
                alias: "work".to_owned(),
            },
            IdentityContract::ProfileExpected {
                selector: IdentitySelector::JsonPointer {
                    pointer: "/user".to_owned(),
                },
            },
            "v1",
        );
        let status = profile_status(key, 7, Some("owner@example.com"));
        let plan = profile_plan(&contract, &status, CredentialLifecycleOperation::Status);
        let cache = cache();
        let now = CredentialStatusCacheInstant::now();
        publish_ready(
            &cache,
            &plan,
            result(
                &plan,
                br#"{"state":"ready","user":"owner@example.com","discarded":"CANARY"}"#,
            ),
            &directory,
            directory_revision(3),
            now,
            ttl(),
        )
        .expect("store");

        let CredentialStatusCacheLookup::Hit(hit) = cache
            .lookup(&plan, &directory, directory_revision(3), now)
            .expect("lookup")
        else {
            panic!("expected hit");
        };
        assert_eq!(hit.state(), AuthState::Ready);
        assert_eq!(
            hit.identity_verification(),
            CredentialIdentityVerification::Matched
        );
        assert!(!format!("{cache:?}").contains("owner@example.com"));
        assert!(!format!("{cache:?}").contains("CANARY"));
    }

    #[test]
    fn invalidation_generation_prevents_in_flight_status_from_restoring_readiness() {
        let fixture = Fixture::new();
        let key = fixture.key("provider", "work");
        let directory = fixture.create_profile_directory(&key);
        let contract_v1 = contract(
            "provider",
            ProfileSelection::Fixed {
                alias: "work".to_owned(),
            },
            IdentityContract::None,
            "v1",
        );
        let contract_v2 = contract(
            "provider",
            ProfileSelection::Fixed {
                alias: "work".to_owned(),
            },
            IdentityContract::None,
            "v2",
        );
        let status = profile_status(key, 1, None);
        let plan_v1 = profile_plan(&contract_v1, &status, CredentialLifecycleOperation::Status);
        let plan_v2 = profile_plan(&contract_v2, &status, CredentialLifecycleOperation::Status);
        let cache = cache();
        let now = CredentialStatusCacheInstant::now();

        let stale_ticket = cache
            .begin_observation(&plan_v1, &directory, directory_revision(1))
            .unwrap();
        assert!(!cache.invalidate_after_auth_failure(&plan_v1).unwrap());
        assert_eq!(
            cache
                .store_ready(
                    stale_ticket,
                    result(&plan_v1, br#"{"state":"ready"}"#),
                    now,
                    ttl(),
                )
                .expect_err("invalidation wins")
                .code,
            CredentialStatusCacheErrorCode::StaleObservation
        );

        let wrong_plan_ticket = cache
            .begin_observation(&plan_v1, &directory, directory_revision(1))
            .unwrap();
        assert_eq!(
            cache
                .store_ready(
                    wrong_plan_ticket,
                    result(&plan_v2, br#"{"state":"ready"}"#),
                    now,
                    ttl(),
                )
                .expect_err("plan mismatch")
                .code,
            CredentialStatusCacheErrorCode::ObservationPlanMismatch
        );
        assert_eq!(cache.entry_count().unwrap(), 0);
    }

    #[test]
    fn expiry_profile_revision_lifecycle_and_directory_revision_each_invalidate() {
        let fixture = Fixture::new();
        let key = fixture.key("provider", "work");
        let directory = fixture.create_profile_directory(&key);
        let original_contract = contract(
            "provider",
            ProfileSelection::Fixed {
                alias: "work".to_owned(),
            },
            IdentityContract::None,
            "v1",
        );
        let changed_contract = contract(
            "provider",
            ProfileSelection::Fixed {
                alias: "work".to_owned(),
            },
            IdentityContract::None,
            "v2",
        );
        let status_v1 = profile_status(key.clone(), 1, None);
        let status_v2 = profile_status(key, 2, None);
        let plan = profile_plan(
            &original_contract,
            &status_v1,
            CredentialLifecycleOperation::Status,
        );
        let revised_plan = profile_plan(
            &original_contract,
            &status_v2,
            CredentialLifecycleOperation::Status,
        );
        let changed_plan = profile_plan(
            &changed_contract,
            &status_v1,
            CredentialLifecycleOperation::Status,
        );
        let cache = cache();
        let now = CredentialStatusCacheInstant::now();
        let ready = || result(&plan, br#"{"state":"ready"}"#);

        publish_ready(
            &cache,
            &plan,
            ready(),
            &directory,
            directory_revision(1),
            now,
            ttl(),
        )
        .unwrap();
        assert_eq!(
            cache
                .lookup(&revised_plan, &directory, directory_revision(1), now)
                .unwrap(),
            CredentialStatusCacheLookup::Miss(
                CredentialStatusCacheMissReason::ProfileRevisionChanged
            )
        );
        publish_ready(
            &cache,
            &plan,
            ready(),
            &directory,
            directory_revision(1),
            now,
            ttl(),
        )
        .unwrap();
        assert_eq!(
            cache
                .lookup(&changed_plan, &directory, directory_revision(1), now)
                .unwrap(),
            CredentialStatusCacheLookup::Miss(
                CredentialStatusCacheMissReason::LifecycleContractChanged
            )
        );
        publish_ready(
            &cache,
            &plan,
            ready(),
            &directory,
            directory_revision(1),
            now,
            ttl(),
        )
        .unwrap();
        assert_eq!(
            cache
                .lookup(&plan, &directory, directory_revision(2), now)
                .unwrap(),
            CredentialStatusCacheLookup::Miss(
                CredentialStatusCacheMissReason::DirectoryRevisionChanged
            )
        );
        publish_ready(
            &cache,
            &plan,
            ready(),
            &directory,
            directory_revision(1),
            now,
            CredentialStatusCacheTtl::new(Duration::from_secs(1)).unwrap(),
        )
        .unwrap();
        let expired_at = CredentialStatusCacheInstant(now.0 + Duration::from_secs(1));
        assert_eq!(
            cache
                .lookup(&plan, &directory, directory_revision(1), expired_at)
                .unwrap(),
            CredentialStatusCacheLookup::Miss(CredentialStatusCacheMissReason::Expired)
        );
    }

    #[test]
    fn replaced_directory_identity_invalidates_even_with_the_same_logical_revision() {
        let fixture = Fixture::new();
        let key = fixture.key("provider", "work");
        let directory = fixture.create_profile_directory(&key);
        let contract = contract(
            "provider",
            ProfileSelection::Fixed {
                alias: "work".to_owned(),
            },
            IdentityContract::None,
            "v1",
        );
        let status = profile_status(key.clone(), 1, None);
        let plan = profile_plan(&contract, &status, CredentialLifecycleOperation::Status);
        let cache = cache();
        let now = CredentialStatusCacheInstant::now();
        publish_ready(
            &cache,
            &plan,
            result(&plan, br#"{"state":"ready"}"#),
            &directory,
            directory_revision(1),
            now,
            ttl(),
        )
        .unwrap();

        let path = fixture.auth_root().join("profile-work");
        let old = fixture.auth_root().join("profile-work-old");
        fs::rename(&path, old).expect("move old");
        fs::create_dir(&path).expect("replacement");
        set_mode(&path, 0o700);
        let replacement = fixture.resolve_profile_directory(&key);
        assert_eq!(
            cache
                .lookup(&plan, &replacement, directory_revision(1), now)
                .unwrap(),
            CredentialStatusCacheLookup::Miss(CredentialStatusCacheMissReason::DirectoryChanged)
        );
    }

    #[test]
    fn process_policy_mutation_and_auth_failure_invalidation_are_explicit() {
        let fixture = Fixture::new();
        let key = fixture.key("provider", "work");
        let directory = fixture.create_profile_directory(&key);
        let contract = contract(
            "provider",
            ProfileSelection::Fixed {
                alias: "work".to_owned(),
            },
            IdentityContract::None,
            "v1",
        );
        let status = profile_status(key, 1, None);
        let status_plan = profile_plan(&contract, &status, CredentialLifecycleOperation::Status);
        let login_plan = profile_plan(&contract, &status, CredentialLifecycleOperation::Login);
        let cache = cache();
        let now = CredentialStatusCacheInstant::now();
        let store = || {
            publish_ready(
                &cache,
                &status_plan,
                result(&status_plan, br#"{"state":"ready"}"#),
                &directory,
                directory_revision(1),
                now,
                ttl(),
            )
        };

        store().unwrap();
        assert_eq!(
            cache
                .replace_process_epoch(CredentialProcessEpoch::new(1).unwrap())
                .unwrap(),
            0
        );
        assert_eq!(
            cache
                .replace_process_epoch(CredentialProcessEpoch::new(2).unwrap())
                .unwrap(),
            1
        );
        store().unwrap();
        assert_eq!(
            cache
                .replace_policy_revision(CredentialPolicyRevision::new(2).unwrap())
                .unwrap(),
            1
        );
        store().unwrap();
        assert!(cache
            .invalidate_after_lifecycle_mutation(&login_plan)
            .unwrap());
        store().unwrap();
        assert!(cache.invalidate_after_auth_failure(&status_plan).unwrap());
        assert_eq!(
            cache
                .invalidate_after_lifecycle_mutation(&status_plan)
                .expect_err("status is not mutation")
                .code,
            CredentialStatusCacheErrorCode::WrongOperation
        );
    }

    #[test]
    fn non_ready_and_explicitly_unverified_identity_results_never_enter_cache() {
        let fixture = Fixture::new();
        let key = fixture.key("provider", "work");
        let directory = fixture.create_profile_directory(&key);
        let selected = ProfileSelection::Fixed {
            alias: "work".to_owned(),
        };
        let status = profile_status(key, 1, None);
        let ordinary = contract("provider", selected.clone(), IdentityContract::None, "v1");
        let unverified = contract(
            "provider",
            selected,
            IdentityContract::Unverified {
                reason: "provider exposes no identity".to_owned(),
            },
            "v1",
        );
        let ordinary_plan = profile_plan(&ordinary, &status, CredentialLifecycleOperation::Status);
        let unverified_plan =
            profile_plan(&unverified, &status, CredentialLifecycleOperation::Status);
        let cache = cache();
        let now = CredentialStatusCacheInstant::now();
        for value in [
            result(&ordinary_plan, br#"{"state":"expired"}"#),
            result(&unverified_plan, br#"{"state":"ready"}"#),
        ] {
            let plan = if value.plan() == &ordinary_plan {
                &ordinary_plan
            } else {
                &unverified_plan
            };
            assert_eq!(
                publish_ready(
                    &cache,
                    plan,
                    value,
                    &directory,
                    directory_revision(1),
                    now,
                    ttl(),
                )
                .expect_err("uncacheable")
                .code,
                CredentialStatusCacheErrorCode::UncacheableStatus
            );
        }
        assert_eq!(cache.entry_count().unwrap(), 0);
    }

    #[test]
    fn implicit_cli_status_is_bound_to_the_scope_auth_directory() {
        let fixture = Fixture::new();
        let directory = fixture.resolve_auth_root();
        let contract = contract(
            "provider",
            ProfileSelection::Implicit,
            IdentityContract::None,
            "v1",
        );
        let plan = CredentialLifecyclePlan::for_implicit(
            validate_skill_runtime_contract(&contract).unwrap(),
            fixture.scope.clone(),
            CredentialLifecycleOperation::Status,
        )
        .unwrap();
        let cache = cache();
        let now = CredentialStatusCacheInstant::now();
        publish_ready(
            &cache,
            &plan,
            result(&plan, br#"{"state":"ready"}"#),
            &directory,
            directory_revision(1),
            now,
            ttl(),
        )
        .unwrap();
        assert!(matches!(
            cache
                .lookup(&plan, &directory, directory_revision(1), now)
                .unwrap(),
            CredentialStatusCacheLookup::Hit(_)
        ));
    }

    #[test]
    fn cache_is_capacity_bounded_iterative_and_thread_safe() {
        let handle = thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(|| {
                let fixture = Fixture::new();
                let contract = contract(
                    "provider",
                    ProfileSelection::Selectable { default: None },
                    IdentityContract::None,
                    "v1",
                );
                let cache = cache();
                let now = CredentialStatusCacheInstant::now();
                for index in 0..=MAX_CREDENTIAL_STATUS_CACHE_ENTRIES {
                    let key = fixture.key("provider", &format!("p-{index}"));
                    let directory = fixture.create_profile_directory(&key);
                    let status = profile_status(key, 1, None);
                    let plan =
                        profile_plan(&contract, &status, CredentialLifecycleOperation::Status);
                    let stored = publish_ready(
                        &cache,
                        &plan,
                        result(&plan, br#"{"state":"ready"}"#),
                        &directory,
                        directory_revision(1),
                        now,
                        ttl(),
                    );
                    if index < MAX_CREDENTIAL_STATUS_CACHE_ENTRIES {
                        stored.expect("within capacity");
                    } else {
                        assert_eq!(
                            stored.expect_err("capacity").code,
                            CredentialStatusCacheErrorCode::CapacityExceeded
                        );
                    }
                }
                cache.entry_count().unwrap()
            })
            .expect("thread");
        assert_eq!(
            handle.join().expect("join"),
            MAX_CREDENTIAL_STATUS_CACHE_ENTRIES
        );
    }

    #[test]
    fn concurrent_store_and_lookup_remain_consistent_and_lock_poisoning_fails_closed() {
        let fixture = Fixture::new();
        let key = fixture.key("provider", "work");
        let directory = fixture.create_profile_directory(&key);
        let contract = contract(
            "provider",
            ProfileSelection::Fixed {
                alias: "work".to_owned(),
            },
            IdentityContract::None,
            "v1",
        );
        let status = profile_status(key, 1, None);
        let plan = profile_plan(&contract, &status, CredentialLifecycleOperation::Status);
        let shared_cache = Arc::new(cache());
        let now = CredentialStatusCacheInstant::now();
        let mut threads = Vec::new();
        for _ in 0..16 {
            let cache = Arc::clone(&shared_cache);
            let plan = plan.clone();
            let directory = directory.clone();
            threads.push(thread::spawn(move || {
                publish_ready(
                    &cache,
                    &plan,
                    result(&plan, br#"{"state":"ready"}"#),
                    &directory,
                    directory_revision(1),
                    now,
                    ttl(),
                )
                .unwrap();
                assert!(matches!(
                    cache
                        .lookup(&plan, &directory, directory_revision(1), now)
                        .unwrap(),
                    CredentialStatusCacheLookup::Hit(_)
                ));
            }));
        }
        for handle in threads {
            handle.join().expect("worker");
        }

        let poisoned = Arc::new(cache());
        let worker = Arc::clone(&poisoned);
        assert!(thread::spawn(move || {
            let _guard = worker.state.lock().unwrap();
            panic!("poison cache");
        })
        .join()
        .is_err());
        assert_eq!(
            poisoned.entry_count().expect_err("poisoned").code,
            CredentialStatusCacheErrorCode::LockPoisoned
        );
    }

    #[test]
    fn constructors_targets_and_diagnostics_fail_closed_without_values() {
        assert_eq!(
            CredentialProcessEpoch::new(0).unwrap_err().code,
            CredentialStatusCacheErrorCode::InvalidProcessEpoch
        );
        assert_eq!(
            CredentialPolicyRevision::new(0).unwrap_err().code,
            CredentialStatusCacheErrorCode::InvalidPolicyRevision
        );
        assert_eq!(
            CredentialAuthDirectoryRevision::new(0).unwrap_err().code,
            CredentialStatusCacheErrorCode::InvalidDirectoryRevision
        );
        assert_eq!(
            CredentialStatusCacheTtl::new(Duration::ZERO)
                .unwrap_err()
                .code,
            CredentialStatusCacheErrorCode::InvalidTtl
        );
        assert_eq!(
            CredentialStatusCacheTtl::new(MAX_CREDENTIAL_STATUS_CACHE_TTL + Duration::from_secs(1))
                .unwrap_err()
                .code,
            CredentialStatusCacheErrorCode::InvalidTtl
        );

        let fixture = Fixture::new();
        let work_key = fixture.key("provider", "work");
        let other_key = fixture.key("provider", "other");
        let work_directory = fixture.create_profile_directory(&work_key);
        let other_directory = fixture.create_profile_directory(&other_key);
        let contract = contract(
            "provider",
            ProfileSelection::Fixed {
                alias: "work".to_owned(),
            },
            IdentityContract::None,
            "v1",
        );
        let plan = profile_plan(
            &contract,
            &profile_status(work_key, 1, None),
            CredentialLifecycleOperation::Status,
        );
        let cache = cache();
        let error = publish_ready(
            &cache,
            &plan,
            result(&plan, br#"{"state":"ready"}"#),
            &other_directory,
            directory_revision(1),
            CredentialStatusCacheInstant::now(),
            ttl(),
        )
        .expect_err("wrong directory");
        assert_eq!(
            error.code,
            CredentialStatusCacheErrorCode::DirectoryTargetMismatch
        );
        assert!(!format!("{error:?} {error}").contains("CANARY"));
        assert!(work_directory.revalidate().is_ok());
    }
}
