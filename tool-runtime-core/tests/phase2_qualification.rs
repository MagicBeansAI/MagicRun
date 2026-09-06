//! Phase 2G public-boundary isolation and concurrency qualification.
//!
//! These tests compose only the public Phase 2 APIs. Credential values remain inside
//! the sealed preparation call, filesystem paths are obtained only from revalidated
//! capabilities, and the registry surface returns metadata/status rather than material.

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Barrier,
    },
    thread,
};

#[cfg(unix)]
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::AtomicU64,
};

use static_assertions::assert_not_impl_any;
use tool_runtime_core::{
    credential_preparation::{
        with_prepared_credential_material, CredentialMaterialBindingName, CredentialMaterialKind,
        CredentialMaterialResolver, CredentialMaterialSink, CredentialPreparationBinding,
        CredentialPreparationError, CredentialPreparationErrorCode, CredentialPreparationPlan,
        CredentialSecretReference, PreparedCredentialMaterial, MAX_PREPARED_CREDENTIAL_BINDINGS,
    },
    credential_profile_store::{LegacyCredentialProfileSet, LocalCredentialProfileRegistry},
    credential_profiles::{
        CreateCredentialProfileReference, CredentialProfileAvailability, CredentialProfileBinding,
        CredentialProfileErrorCode, CredentialProfileKey, CredentialProfileMetadata,
        CredentialProfileRegistry, CredentialProfileRegistrySnapshot, CredentialProfileRevision,
        CredentialProfileStatus, CredentialScope, DefaultProfileUpdate, ExpectedCredentialIdentity,
        ExpectedIdentityUpdate, SetCredentialProfileDisabled, UpdateCredentialProfileMetadata,
    },
    manifest::{AuthKind, AuthState, ProfileSelection},
    profile_selection::{
        select_credential_profile, CredentialProfileSelectionErrorCode,
        CredentialProfileSelectionRequest, CredentialProfileSelectionSource,
    },
    scoped_paths::{
        ScopedPath, ScopedPathAuthority, ScopedPathComponent, ScopedPathErrorCode, ScopedPathKind,
    },
};

struct SnapshotRegistry(CredentialProfileRegistrySnapshot);

impl CredentialProfileRegistry for SnapshotRegistry {
    fn snapshot(
        &self,
        _scope: &CredentialScope,
    ) -> Result<
        CredentialProfileRegistrySnapshot,
        tool_runtime_core::credential_profiles::CredentialProfileError,
    > {
        Ok(self.0.clone())
    }

    fn status(
        &self,
        key: &CredentialProfileKey,
    ) -> Result<
        Option<CredentialProfileStatus>,
        tool_runtime_core::credential_profiles::CredentialProfileError,
    > {
        Ok(self
            .0
            .profiles()
            .iter()
            .find(|status| status.key() == key)
            .cloned())
    }

    fn create_reference(
        &self,
        _request: CreateCredentialProfileReference,
    ) -> Result<
        CredentialProfileStatus,
        tool_runtime_core::credential_profiles::CredentialProfileError,
    > {
        panic!("read-only qualification registry")
    }

    fn update_metadata(
        &self,
        _request: UpdateCredentialProfileMetadata,
    ) -> Result<
        CredentialProfileStatus,
        tool_runtime_core::credential_profiles::CredentialProfileError,
    > {
        panic!("read-only qualification registry")
    }

    fn set_disabled(
        &self,
        _request: SetCredentialProfileDisabled,
    ) -> Result<
        CredentialProfileStatus,
        tool_runtime_core::credential_profiles::CredentialProfileError,
    > {
        panic!("read-only qualification registry")
    }
}

fn select_from_registry(
    request: &CredentialProfileSelectionRequest,
    snapshot: &CredentialProfileRegistrySnapshot,
) -> Result<
    tool_runtime_core::profile_selection::CredentialProfileSelectionDecision,
    tool_runtime_core::profile_selection::CredentialProfileSelectionError,
> {
    select_credential_profile(&SnapshotRegistry(snapshot.clone()), request)
}

fn scope(principal: &str, workspace: &str) -> CredentialScope {
    CredentialScope::new(principal, workspace).expect("valid qualification scope")
}

fn profile_key(scope: &CredentialScope, alias: &str) -> CredentialProfileKey {
    CredentialProfileKey::new(
        scope.clone(),
        "qualification-provider",
        alias,
        CredentialProfileBinding::Provider,
    )
    .expect("valid qualification profile key")
}

fn ready_snapshot(
    scope: &CredentialScope,
    aliases: &[(&str, bool)],
) -> CredentialProfileRegistrySnapshot {
    let profiles = aliases
        .iter()
        .map(|(alias, is_default)| {
            let metadata = CredentialProfileMetadata::new(
                profile_key(scope, alias),
                None,
                *is_default,
                CredentialProfileAvailability::Enabled,
                CredentialProfileRevision::new(1).expect("revision"),
            )
            .expect("metadata");
            CredentialProfileStatus::new(metadata, AuthState::Ready).expect("ready status")
        })
        .collect();
    CredentialProfileRegistrySnapshot::new(scope.clone(), profiles).expect("snapshot")
}

fn none_selection(
    scope: &CredentialScope,
) -> tool_runtime_core::profile_selection::CredentialProfileSelectionDecision {
    let request = CredentialProfileSelectionRequest::new(
        scope.clone(),
        None,
        CredentialProfileBinding::Provider,
        &ProfileSelection::None,
        None,
    )
    .expect("none request");
    let snapshot =
        CredentialProfileRegistrySnapshot::new(scope.clone(), Vec::new()).expect("empty snapshot");
    select_from_registry(&request, &snapshot).expect("none selection")
}

fn secret_binding(name: &str, max_bytes: usize) -> CredentialPreparationBinding {
    CredentialPreparationBinding::new(
        CredentialMaterialBindingName::new(name).expect("binding name"),
        CredentialMaterialKind::SecretBinding,
        max_bytes,
    )
    .expect("secret binding")
}

#[test]
fn scope_profile_and_fixed_policy_authority_survives_selection_through_preparation() {
    let owner = scope("owner", "default");
    let other = scope("other", "default");
    let snapshot = ready_snapshot(&owner, &[("personal", false), ("work", true)]);

    let fixed = CredentialProfileSelectionRequest::new(
        owner.clone(),
        Some("qualification-provider"),
        CredentialProfileBinding::Provider,
        &ProfileSelection::Fixed {
            alias: "work".to_owned(),
        },
        None,
    )
    .expect("fixed request");
    let selection = select_from_registry(&fixed, &snapshot).expect("fixed profile selection");
    assert_eq!(
        selection.source(),
        Some(CredentialProfileSelectionSource::Fixed)
    );
    assert_eq!(
        selection
            .selected_profile()
            .expect("selected profile")
            .key(),
        &profile_key(&owner, "work")
    );

    let plan =
        CredentialPreparationPlan::new(owner.clone(), AuthKind::CliProfile, &selection, Vec::new())
            .expect("profile preparation plan");
    assert_eq!(plan.scope(), &owner);
    assert_eq!(
        plan.selected_profile_key(),
        Some(&profile_key(&owner, "work"))
    );

    assert_eq!(
        CredentialPreparationPlan::new(other.clone(), AuthKind::CliProfile, &selection, Vec::new())
            .expect_err("selection proof cannot cross scopes")
            .code,
        CredentialPreparationErrorCode::ScopeMismatch
    );

    let other_request = CredentialProfileSelectionRequest::new(
        other,
        Some("qualification-provider"),
        CredentialProfileBinding::Provider,
        &ProfileSelection::Fixed {
            alias: "work".to_owned(),
        },
        None,
    )
    .expect("other request");
    assert_eq!(
        select_from_registry(&other_request, &snapshot)
            .expect_err("snapshot cannot cross scopes")
            .code,
        CredentialProfileSelectionErrorCode::SnapshotScopeMismatch
    );

    assert_eq!(
        CredentialProfileSelectionRequest::new(
            owner,
            Some("qualification-provider"),
            CredentialProfileBinding::Provider,
            &ProfileSelection::Fixed {
                alias: "work".to_owned(),
            },
            Some("personal"),
        )
        .expect_err("model input cannot replace a fixed profile")
        .code,
        CredentialProfileSelectionErrorCode::UnexpectedRequestedProfile
    );
}

struct MapResolver {
    expected_scope: CredentialScope,
    values: BTreeMap<String, Vec<u8>>,
    calls: Arc<AtomicUsize>,
}

impl CredentialMaterialResolver for MapResolver {
    fn resolve_once(
        &mut self,
        plan: &CredentialPreparationPlan,
        sink: &mut CredentialMaterialSink<'_>,
    ) -> Result<(), CredentialPreparationError> {
        assert_eq!(plan.scope(), &self.expected_scope);
        self.calls.fetch_add(1, Ordering::SeqCst);
        for binding in plan.bindings() {
            let value = self
                .values
                .remove(binding.name().as_str())
                .expect("resolver value for every declared binding");
            sink.provide(binding.name(), value)?;
        }
        Ok(())
    }
}

#[test]
fn parallel_sealed_preparations_are_scope_local_and_leave_parent_environment_unchanged() {
    let variable = "TOOL_RUNTIME_CORE_PHASE2G_PARENT_ENV_CANARY";
    let previous = std::env::var_os(variable);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut joins = Vec::new();

    for index in 0..32 {
        let calls = Arc::clone(&calls);
        joins.push(thread::spawn(move || {
            let selected_scope = scope(&format!("owner-{index:02}"), "default");
            let plan = CredentialPreparationPlan::new(
                selected_scope.clone(),
                AuthKind::Secrets,
                &none_selection(&selected_scope),
                vec![secret_binding("api_key", 64), secret_binding("session", 64)],
            )
            .expect("scope-local plan");
            let mut resolver = MapResolver {
                expected_scope: selected_scope,
                values: BTreeMap::from([
                    (
                        "api_key".to_owned(),
                        format!("SECRET_API_{index:02}").into_bytes(),
                    ),
                    (
                        "session".to_owned(),
                        format!("SECRET_SESSION_{index:02}").into_bytes(),
                    ),
                ]),
                calls,
            };
            with_prepared_credential_material(&plan, &mut resolver, |prepared| {
                assert_eq!(prepared.len(), 2);
                assert_eq!(
                    prepared.kind(&CredentialMaterialBindingName::new("api_key").unwrap()),
                    Some(CredentialMaterialKind::SecretBinding)
                );
            })
            .expect("sealed preparation");
        }));
    }

    for join in joins {
        join.join().expect("preparation thread");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 32);
    assert_eq!(std::env::var_os(variable), previous);
}

#[test]
fn maximum_public_preparation_stays_iterative_and_deterministic_on_a_small_stack() {
    let join = thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(|| {
            let selected_scope = scope("small-stack-owner", "default");
            let bindings = (0..MAX_PREPARED_CREDENTIAL_BINDINGS)
                .rev()
                .map(|index| secret_binding(&format!("binding-{index:02}"), 32))
                .collect::<Vec<_>>();
            let plan = CredentialPreparationPlan::new(
                selected_scope.clone(),
                AuthKind::Secrets,
                &none_selection(&selected_scope),
                bindings,
            )
            .expect("maximum plan");
            let values = plan
                .bindings()
                .iter()
                .map(|binding| (binding.name().as_str().to_owned(), vec![b'x'; 32]))
                .collect();
            let mut resolver = MapResolver {
                expected_scope: selected_scope,
                values,
                calls: Arc::new(AtomicUsize::new(0)),
            };
            let count =
                with_prepared_credential_material(&plan, &mut resolver, |prepared| prepared.len())
                    .expect("maximum sealed preparation");
            assert_eq!(count, MAX_PREPARED_CREDENTIAL_BINDINGS);
            assert_eq!(
                serde_json::to_vec(&plan).expect("serialize plan"),
                serde_json::to_vec(&plan).expect("serialize plan again")
            );
        })
        .expect("spawn small-stack qualification");
    assert!(join.join().is_ok());
}

#[test]
fn public_phase2_surfaces_expose_metadata_but_not_paths_or_prepared_values() {
    assert_not_impl_any!(PreparedCredentialMaterial<'static>: Clone, std::fmt::Debug, serde::Serialize);
    assert_not_impl_any!(CredentialMaterialSink<'static>: Clone, std::fmt::Debug, serde::Serialize);
    assert_not_impl_any!(ScopedPath: serde::Serialize);

    let owner = scope("metadata-owner", "default");
    let snapshot = ready_snapshot(&owner, &[("work", true)]);
    let request = CredentialProfileSelectionRequest::new(
        owner.clone(),
        Some("qualification-provider"),
        CredentialProfileBinding::Provider,
        &ProfileSelection::Selectable { default: None },
        None,
    )
    .expect("selection request");
    let selection = select_from_registry(&request, &snapshot).expect("registry default selection");
    let plan =
        CredentialPreparationPlan::new(owner.clone(), AuthKind::CliProfile, &selection, Vec::new())
            .expect("metadata plan");

    let credential_canary = "PHASE2G_CREDENTIAL_VALUE_MUST_NEVER_SERIALIZE";
    for value in [
        serde_json::to_string(&snapshot).expect("serialize snapshot"),
        serde_json::to_string(&selection).expect("serialize selection"),
        serde_json::to_string(&plan).expect("serialize plan"),
    ] {
        assert!(!value.contains(credential_canary));
        assert!(!value.contains("/Users/"));
    }
    assert_eq!(
        CredentialSecretReference::new("vault/provider/api-key")
            .expect("metadata-only secret reference")
            .as_str(),
        "vault/provider/api-key"
    );
}

#[cfg(unix)]
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

#[cfg(unix)]
struct FilesystemFixture {
    container: PathBuf,
    scopes_root: PathBuf,
}

#[cfg(unix)]
impl FilesystemFixture {
    fn new(name: &str) -> Self {
        let temp_root = fs::canonicalize(std::env::temp_dir()).expect("canonical temp root");
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let container = temp_root.join(format!(
            "tool-runtime-phase2g-{name}-{}-{sequence}",
            std::process::id()
        ));
        let scopes_root = container.join("scopes");
        fs::create_dir_all(&scopes_root).expect("create scopes root");
        set_mode(&container, 0o700);
        set_mode(&scopes_root, 0o755);
        Self {
            container,
            scopes_root,
        }
    }

    fn add_scope(&self, scope: &CredentialScope) -> PathBuf {
        let principal = self.scopes_root.join(scope.principal.as_str());
        let workspace = principal.join(scope.workspace.as_str());
        let auth = workspace.join("auth");
        fs::create_dir_all(&auth).expect("create scope auth tree");
        set_mode(&principal, 0o755);
        set_mode(&workspace, 0o755);
        set_mode(&auth, 0o700);
        auth
    }

    fn registry(&self, scope: &CredentialScope) -> LocalCredentialProfileRegistry {
        let authority = ScopedPathAuthority::open(&self.scopes_root).expect("path authority");
        let auth = authority.resolve_auth_root(scope).expect("scope auth root");
        LocalCredentialProfileRegistry::open(
            scope.clone(),
            auth,
            LegacyCredentialProfileSet::empty(scope.clone()),
        )
        .expect("local profile registry")
    }
}

#[cfg(unix)]
impl Drop for FilesystemFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.container);
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set fixture mode");
}

#[cfg(unix)]
#[test]
fn public_scoped_path_authority_rejects_traversal_symlink_and_permission_changes() {
    let fixture = FilesystemFixture::new("paths");
    let owner = scope("owner", "default");
    let auth_path = fixture.add_scope(&owner);
    let profile_path = auth_path.join("qualification-work");
    fs::create_dir(&profile_path).expect("create profile root");
    set_mode(&profile_path, 0o700);

    let authority = ScopedPathAuthority::open(&fixture.scopes_root).expect("path authority");
    let auth = authority
        .resolve_auth_root(&owner)
        .expect("auth capability");
    let selected_key = profile_key(&owner, "work");
    let profile = authority
        .resolve_profile_root(
            &selected_key,
            ScopedPathComponent::new("qualification-work").expect("component"),
        )
        .expect("profile capability");
    assert_eq!(auth.kind(), ScopedPathKind::Auth);
    assert_eq!(profile.kind(), ScopedPathKind::CredentialProfile);
    assert!(!format!("{profile:?}").contains(profile_path.to_str().unwrap()));
    assert_eq!(
        ScopedPathComponent::new("../escape")
            .expect_err("traversal component")
            .code,
        ScopedPathErrorCode::InvalidComponent
    );

    set_mode(&auth_path, 0o755);
    assert_eq!(
        auth.revalidate().expect_err("unsafe auth mode").code,
        ScopedPathErrorCode::UnsafePermissions
    );
    set_mode(&auth_path, 0o700);
    auth.revalidate().expect("restored auth mode");

    fs::remove_dir(&profile_path).expect("remove profile root");
    let outside = fixture.container.join("outside");
    fs::create_dir(&outside).expect("create outside directory");
    set_mode(&outside, 0o700);
    symlink(&outside, &profile_path).expect("replace profile with symlink");
    assert_eq!(
        profile.revalidate().expect_err("symlink replacement").code,
        ScopedPathErrorCode::Symlink
    );
}

#[cfg(unix)]
#[test]
fn concurrent_registry_writers_preserve_scope_and_reject_one_stale_revision() {
    let fixture = FilesystemFixture::new("registry");
    let owner = scope("owner", "default");
    let other = scope("other", "default");
    fixture.add_scope(&owner);
    fixture.add_scope(&other);

    let seed = fixture.registry(&owner);
    let shared = profile_key(&owner, "shared");
    seed.create_reference(CreateCredentialProfileReference::new(
        shared.clone(),
        None,
        false,
    ))
    .expect("seed profile");
    drop(seed);

    let left = Arc::new(fixture.registry(&owner));
    let right = Arc::new(fixture.registry(&owner));
    let barrier = Arc::new(Barrier::new(3));
    let mut joins = Vec::new();
    for (registry, identity) in [(left, "left@example.test"), (right, "right@example.test")] {
        let barrier = Arc::clone(&barrier);
        let shared = shared.clone();
        joins.push(thread::spawn(move || {
            barrier.wait();
            registry.update_metadata(UpdateCredentialProfileMetadata::new(
                shared,
                ExpectedIdentityUpdate::Set {
                    value: ExpectedCredentialIdentity::new(identity).expect("identity"),
                },
                DefaultProfileUpdate::Preserve,
                CredentialProfileRevision::new(1).expect("revision"),
            ))
        }));
    }
    barrier.wait();
    let results = joins
        .into_iter()
        .map(|join| join.join().expect("registry writer"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| result
                .as_ref()
                .is_err_and(|error| error.code == CredentialProfileErrorCode::Conflict))
            .count(),
        1
    );

    let other_registry = fixture.registry(&other);
    assert_eq!(
        other_registry
            .snapshot(&other)
            .expect("other snapshot")
            .profiles()
            .len(),
        0
    );
    assert_eq!(
        other_registry
            .status(&shared)
            .expect_err("cross-scope profile key")
            .code,
        CredentialProfileErrorCode::ScopeMismatch
    );
    let final_status = fixture
        .registry(&owner)
        .status(&shared)
        .expect("status read")
        .expect("shared profile");
    assert_eq!(final_status.metadata().revision().get(), 2);
}
