//! Phase 3E cross-boundary credential security qualification.
//!
//! This module is test-only so qualification can compose crate-private value and
//! filesystem owners without adding a production escape hatch. The assertions are on
//! the public escape surfaces: metadata plans/receipts, redacted persistence batches,
//! stable diagnostics, cleanup state, and audit-sink projection.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    thread,
};

#[cfg(unix)]
use std::{
    fmt, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(unix)]
use serde::Serialize;
#[cfg(unix)]
use static_assertions::assert_not_impl_any;

use crate::{
    credential_injection::{
        ChildEnvironmentBaseline, CredentialCallId, CredentialExecutionFailure,
        CredentialExecutionOutcome, CredentialInjectionPlan,
    },
    credential_materialization::{
        materialize_environment_and_stdin, ChildEnvironmentValues, CredentialRedactedOutput,
    },
    credential_persistence::{
        persist_credential_audit_receipt, seal_credential_persistence, CredentialAuditSink,
        CredentialPersistenceDraft, CredentialPersistenceErrorCode, CredentialPersistenceSurface,
        MAX_CREDENTIAL_PERSISTENCE_RECORDS,
    },
    credential_preparation::{
        with_prepared_credential_material, CredentialMaterialBindingName, CredentialMaterialKind,
        CredentialMaterialResolver, CredentialMaterialSink, CredentialPreparationBinding,
        CredentialPreparationError, CredentialPreparationPlan, MAX_PREPARED_CREDENTIAL_BINDINGS,
    },
    credential_profiles::{
        CredentialProfileBinding, CredentialProfileRegistrySnapshot, CredentialScope,
    },
    manifest::{
        AuthContract, AuthKind, AuthRequirement, CliInteraction, InjectionBinding, InjectionSource,
        InjectionTarget, PolicyFloor, ProfileSelection, RuntimeLimits, RuntimeProtocol,
        RuntimeRequirements, SecretBindingRef, SkillRuntimeContract, SkillRuntimeContractVersion,
        StdinContract, WorkingDirectoryContract,
    },
    manifest_validation::validate_skill_runtime_contract,
    profile_selection::{
        select_credential_profile_from_snapshot, CredentialProfileSelectionDecision,
        CredentialProfileSelectionRequest,
    },
};

#[cfg(unix)]
use crate::{
    credential_filesystem::CredentialScratchAuthority,
    credential_injection::CredentialInjectionTarget,
    credential_materialization::{materialize_credential_io, CredentialFilesystemMaterialization},
    credential_persistence::{CredentialPersistenceBatch, CredentialRedactedPersistenceRecord},
    credential_preparation::PreparedCredentialMaterial,
    scoped_paths::{ScopedPath, ScopedPathAuthority},
};

#[cfg(unix)]
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

const ENV_CANARY: &[u8] = b"phase3-environment-secret";
const STDIN_CANARY: &[u8] = b"phase3-stdin-secret\0\xff";
const FILE_CANARY: &[u8] = b"phase3-file-secret";

struct MapResolver {
    values: BTreeMap<String, Vec<u8>>,
}

impl CredentialMaterialResolver for MapResolver {
    fn resolve_once(
        &mut self,
        plan: &CredentialPreparationPlan,
        sink: &mut CredentialMaterialSink<'_>,
    ) -> Result<(), CredentialPreparationError> {
        for binding in plan.bindings() {
            let value = self
                .values
                .remove(binding.name().as_str())
                .expect("qualification value for every binding");
            sink.provide(binding.name(), value)?;
        }
        Ok(())
    }
}

#[cfg(unix)]
struct FilesystemFixture {
    container: PathBuf,
    scopes_root: PathBuf,
    scope: CredentialScope,
}

#[cfg(unix)]
impl FilesystemFixture {
    fn new(label: &str) -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let temp_root = fs::canonicalize(std::env::temp_dir()).expect("canonical temp root");
        let container = temp_root.join(format!(
            "tool-runtime-phase3e-{label}-{}-{sequence}",
            std::process::id()
        ));
        let scopes_root = container.join("scopes");
        let scope = CredentialScope::new(format!("owner-{sequence}"), "default")
            .expect("qualification scope");
        let workspace = scopes_root
            .join(scope.principal.as_str())
            .join(scope.workspace.as_str());
        fs::create_dir_all(&workspace).expect("qualification workspace");
        set_mode(&container, 0o700);
        set_mode(&scopes_root, 0o755);
        set_mode(&scopes_root.join(scope.principal.as_str()), 0o755);
        set_mode(&workspace, 0o755);
        Self {
            container,
            scopes_root,
            scope,
        }
    }

    fn scope_root(&self) -> ScopedPath {
        ScopedPathAuthority::open(&self.scopes_root)
            .expect("scope authority")
            .resolve_scope_root(&self.scope)
            .expect("scope root")
    }

    fn scratch(&self) -> CredentialScratchAuthority {
        CredentialScratchAuthority::open_or_create(&self.scope_root()).expect("scratch authority")
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

fn call_id(value: &str) -> CredentialCallId {
    CredentialCallId::new(value).expect("qualification call id")
}

fn none_selection(scope: &CredentialScope) -> CredentialProfileSelectionDecision {
    let request = CredentialProfileSelectionRequest::new(
        scope.clone(),
        None,
        CredentialProfileBinding::Provider,
        &ProfileSelection::None,
        None,
    )
    .expect("none selection request");
    let snapshot =
        CredentialProfileRegistrySnapshot::new(scope.clone(), Vec::new()).expect("snapshot");
    select_credential_profile_from_snapshot(&request, &snapshot).expect("none selection")
}

fn binding(name: &str, max_bytes: usize) -> CredentialPreparationBinding {
    CredentialPreparationBinding::new(
        CredentialMaterialBindingName::new(name).expect("binding name"),
        CredentialMaterialKind::SecretBinding,
        max_bytes,
    )
    .expect("preparation binding")
}

fn cli_contract(auth: AuthContract) -> SkillRuntimeContract {
    SkillRuntimeContract {
        schema_version: SkillRuntimeContractVersion::v1(),
        requires: RuntimeRequirements {
            bins: BTreeSet::from(["qualification-cli".to_owned()]),
            entrypoint: Default::default(),
            environment: Default::default(),
        },
        runtime: RuntimeProtocol::Cli {
            command_prefix: Vec::new(),
            interaction: CliInteraction::Batch,
            stdin: StdinContract::default(),
            working_directory: WorkingDirectoryContract::default(),
            limits: RuntimeLimits::default(),
        },
        auth,
        policy_floor: PolicyFloor::default(),
    }
}

fn local_secret_boundary(
    scope: &CredentialScope,
) -> (CredentialPreparationPlan, CredentialInjectionPlan) {
    let contract = cli_contract(AuthContract {
        kind: AuthKind::Secrets,
        requirement: AuthRequirement::Required,
        secret_bindings: vec![
            SecretBindingRef {
                name: "environment".to_owned(),
                secret_ref: "QUALIFICATION_ENV_REF".to_owned(),
            },
            SecretBindingRef {
                name: "stdin".to_owned(),
                secret_ref: "QUALIFICATION_STDIN_REF".to_owned(),
            },
            SecretBindingRef {
                name: "file".to_owned(),
                secret_ref: "QUALIFICATION_FILE_REF".to_owned(),
            },
        ],
        injections: vec![
            InjectionBinding {
                source: InjectionSource::Secret {
                    binding: "environment".to_owned(),
                },
                target: InjectionTarget::Environment {
                    name: "QUALIFICATION_API_KEY".to_owned(),
                },
            },
            InjectionBinding {
                source: InjectionSource::Secret {
                    binding: "stdin".to_owned(),
                },
                target: InjectionTarget::Stdin,
            },
            InjectionBinding {
                source: InjectionSource::Secret {
                    binding: "file".to_owned(),
                },
                target: InjectionTarget::ScopedFile {
                    relative_path: "qualification/token.bin".to_owned(),
                },
            },
        ],
        ..AuthContract::default()
    });
    let preparation = CredentialPreparationPlan::new(
        scope.clone(),
        AuthKind::Secrets,
        &none_selection(scope),
        vec![
            binding("environment", 128),
            binding("stdin", 128),
            binding("file", 128),
        ],
    )
    .expect("qualification preparation");
    let injection = CredentialInjectionPlan::compile(
        validate_skill_runtime_contract(&contract).expect("qualification contract"),
        &preparation,
        ChildEnvironmentBaseline::hermetic(),
    )
    .expect("qualification injection");
    (preparation, injection)
}

fn resolver() -> MapResolver {
    MapResolver {
        values: BTreeMap::from([
            ("environment".to_owned(), ENV_CANARY.to_vec()),
            ("stdin".to_owned(), STDIN_CANARY.to_vec()),
            ("file".to_owned(), FILE_CANARY.to_vec()),
        ]),
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn assert_no_canary(bytes: &[u8]) {
    for canary in [ENV_CANARY, STDIN_CANARY, FILE_CANARY] {
        assert!(!contains_bytes(bytes, canary), "credential canary escaped");
    }
}

#[cfg(unix)]
#[test]
fn canaries_and_split_malformed_output_cannot_cross_the_persistence_boundary() {
    assert_not_impl_any!(PreparedCredentialMaterial<'static>: Clone, fmt::Debug, Serialize);
    assert_not_impl_any!(CredentialPersistenceBatch: Clone, Serialize);
    assert_not_impl_any!(CredentialRedactedPersistenceRecord: Clone, Serialize);

    let fixture = FilesystemFixture::new("canary");
    let (preparation, injection) = local_secret_boundary(&fixture.scope);
    let scratch = fixture.scratch();
    let id = call_id("phase3e-canary");
    let mut resolver = resolver();
    let mut observed_paths = Vec::<Vec<u8>>::new();

    let batch = with_prepared_credential_material(&preparation, &mut resolver, |prepared| {
        materialize_credential_io(
            &injection,
            prepared,
            ChildEnvironmentValues::new(injection.baseline()),
            CredentialFilesystemMaterialization::new(&id, &scratch, None),
            |materialized| {
                assert_eq!(materialized.environment_len(), 1);
                assert_eq!(materialized.stdin(), Some(STDIN_CANARY));
                let (_, environment) = materialized
                    .environment_entry(0)
                    .expect("environment revalidation")
                    .expect("environment entry");
                assert_eq!(environment, ENV_CANARY);
                let (_, file_path) = materialized
                    .scoped_file(0)
                    .expect("file revalidation")
                    .expect("scoped file");
                assert_eq!(fs::read(file_path).expect("secret file"), FILE_CANARY);
                let root = materialized
                    .scoped_file_root()
                    .expect("root revalidation")
                    .expect("session root");
                observed_paths.push(root.to_string_lossy().as_bytes().to_vec());
                observed_paths.push(file_path.to_string_lossy().as_bytes().to_vec());

                let split = ENV_CANARY.len() / 2;
                let mut raw = [
                    [b"\xffmalformed:".as_slice(), &ENV_CANARY[..split]].concat(),
                    [&ENV_CANARY[split..], b" stdin=", STDIN_CANARY].concat(),
                    [b"file=".as_slice(), FILE_CANARY].concat(),
                    root.to_string_lossy().as_bytes().to_vec(),
                    file_path.to_string_lossy().as_bytes().to_vec(),
                    [ENV_CANARY, b"/", STDIN_CANARY, b"/", FILE_CANARY].concat(),
                    [b"analytics=".as_slice(), ENV_CANARY].concat(),
                ];
                raw[0].insert(0, 0xff);
                let surfaces = [
                    CredentialPersistenceSurface::ProcessDiagnostic,
                    CredentialPersistenceSurface::ToolOutput,
                    CredentialPersistenceSurface::ToolError,
                    CredentialPersistenceSurface::Artifact,
                    CredentialPersistenceSurface::Log,
                    CredentialPersistenceSurface::Trace,
                    CredentialPersistenceSurface::Analytics,
                ];
                let drafts = raw
                    .iter()
                    .zip(surfaces)
                    .map(|(bytes, surface)| CredentialPersistenceDraft::new(surface, bytes))
                    .collect::<Vec<_>>();
                materialized.seal_persistence(
                    id.clone(),
                    CredentialExecutionOutcome::Cancelled,
                    &drafts,
                )
            },
        )
    })
    .expect("credential resolution")
    .expect("materialization")
    .expect("sealed persistence");

    assert_eq!(batch.records().len(), 7);
    assert_eq!(
        batch.receipt().outcome(),
        CredentialExecutionOutcome::Cancelled
    );
    let joined = batch
        .records()
        .iter()
        .flat_map(|record| record.bytes().iter().copied())
        .collect::<Vec<_>>();
    assert_no_canary(&joined);
    for path in &observed_paths {
        assert!(!contains_bytes(&joined, path));
        assert!(!Path::new(std::str::from_utf8(path).expect("fixture path")).exists());
    }

    let preparation_json = serde_json::to_vec(&preparation).expect("preparation json");
    let injection_json = serde_json::to_vec(&injection).expect("injection json");
    let receipt_json = serde_json::to_vec(batch.receipt()).expect("receipt json");
    for public_bytes in [&preparation_json, &injection_json, &receipt_json] {
        assert_no_canary(public_bytes);
        for path in &observed_paths {
            assert!(!contains_bytes(public_bytes, path));
        }
    }
    assert_no_canary(format!("{injection:?} {batch:?}").as_bytes());
    assert_eq!(
        scratch
            .recover_stale_sessions()
            .expect("post-cancellation recovery")
            .recovered_sessions,
        0
    );

    struct JsonSink(Vec<u8>);
    impl CredentialAuditSink for JsonSink {
        type Error = ();

        fn persist(
            &mut self,
            receipt: &crate::credential_injection::CredentialInjectionReceipt,
        ) -> Result<(), Self::Error> {
            self.0 = serde_json::to_vec(receipt).expect("receipt serialization");
            Ok(())
        }
    }
    let mut sink = JsonSink(Vec::new());
    persist_credential_audit_receipt(&mut sink, batch.receipt()).expect("audit receipt");
    assert_no_canary(&sink.0);
}

#[test]
fn malformed_redactor_and_hostile_audit_errors_collapse_to_fixed_failures() {
    let scope = CredentialScope::new("error-owner", "default").expect("scope");
    let (preparation, injection) = local_secret_boundary(&scope);
    let receipt = crate::credential_injection::CredentialInjectionReceipt::new(
        call_id("phase3e-errors"),
        &injection,
        CredentialExecutionOutcome::Failed {
            failure: CredentialExecutionFailure::OutputMalformed,
        },
    );
    let raw = [ENV_CANARY, STDIN_CANARY, FILE_CANARY].concat();
    let drafts = [CredentialPersistenceDraft::new(
        CredentialPersistenceSurface::ToolError,
        &raw,
    )];
    let malformed = seal_credential_persistence(receipt.clone(), &drafts, |_| Ok(Vec::new()))
        .expect_err("record cardinality mismatch");
    assert_eq!(
        malformed.code,
        CredentialPersistenceErrorCode::RedactionFailed
    );
    assert_eq!(
        malformed.execution_failure(),
        CredentialExecutionFailure::RedactionFailed
    );
    assert_no_canary(format!("{malformed:?} {malformed}").as_bytes());

    struct HostileSink(Vec<u8>);
    impl CredentialAuditSink for HostileSink {
        type Error = Vec<u8>;

        fn persist(
            &mut self,
            _receipt: &crate::credential_injection::CredentialInjectionReceipt,
        ) -> Result<(), Self::Error> {
            Err(std::mem::take(&mut self.0))
        }
    }
    let hostile = [ENV_CANARY, STDIN_CANARY, FILE_CANARY].concat();
    let error = persist_credential_audit_receipt(&mut HostileSink(hostile), &receipt)
        .expect_err("hostile audit failure");
    assert_eq!(error.code, CredentialPersistenceErrorCode::AuditFailed);
    assert_no_canary(format!("{error:?} {error}").as_bytes());
    assert_no_canary(serde_json::to_string(&preparation).unwrap().as_bytes());
}

#[cfg(unix)]
#[test]
fn crash_left_material_is_recovered_without_following_an_active_call() {
    let fixture = FilesystemFixture::new("crash");
    let (preparation, injection) = local_secret_boundary(&fixture.scope);
    let target = injection
        .injections()
        .iter()
        .find_map(|binding| match binding.target() {
            CredentialInjectionTarget::ScopedFile { relative_path } => Some(relative_path.clone()),
            _ => None,
        })
        .expect("scoped-file target");
    let scratch = fixture.scratch();
    let mut session = scratch
        .start_session(&call_id("phase3e-crash"), &fixture.scope)
        .expect("crash session");
    let root = session
        .revalidated_path()
        .expect("session path")
        .to_path_buf();
    let file = session
        .write_file(&target, FILE_CANARY)
        .expect("crash secret file")
        .revalidated_path()
        .expect("file path")
        .to_path_buf();
    assert_eq!(
        scratch
            .recover_stale_sessions()
            .expect_err("active call blocks recovery")
            .code,
        crate::credential_filesystem::CredentialFilesystemErrorCode::RecoveryWhileActive
    );

    set_mode(&root, 0o755);
    drop(session);
    assert!(root.exists());
    set_mode(&root, 0o700);
    let report = scratch
        .recover_stale_sessions()
        .expect("bootstrap recovery");
    assert_eq!(report.recovered_sessions, 1);
    assert!(!root.exists());
    assert!(!file.exists());
    assert_no_canary(format!("{report:?} {preparation:?}").as_bytes());
}

#[test]
fn concurrent_scope_local_batches_do_not_cross_contaminate() {
    let barrier = Arc::new(std::sync::Barrier::new(16));
    let threads = (0..16)
        .map(|index| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let scope = CredentialScope::new(format!("parallel-owner-{index:02}"), "default")
                    .expect("parallel scope");
                let contract = cli_contract(AuthContract {
                    kind: AuthKind::Secrets,
                    requirement: AuthRequirement::Required,
                    secret_bindings: vec![SecretBindingRef {
                        name: "token".to_owned(),
                        secret_ref: "PARALLEL_TOKEN_REF".to_owned(),
                    }],
                    injections: vec![InjectionBinding {
                        source: InjectionSource::Secret {
                            binding: "token".to_owned(),
                        },
                        target: InjectionTarget::Environment {
                            name: "PARALLEL_TOKEN".to_owned(),
                        },
                    }],
                    ..AuthContract::default()
                });
                let preparation = CredentialPreparationPlan::new(
                    scope.clone(),
                    AuthKind::Secrets,
                    &none_selection(&scope),
                    vec![binding("token", 64)],
                )
                .expect("parallel preparation");
                let injection = CredentialInjectionPlan::compile(
                    validate_skill_runtime_contract(&contract).expect("parallel contract"),
                    &preparation,
                    ChildEnvironmentBaseline::hermetic(),
                )
                .expect("parallel injection");
                let canary = format!("parallel-secret-{index:02}").into_bytes();
                let mut resolver = MapResolver {
                    values: BTreeMap::from([("token".to_owned(), canary.clone())]),
                };
                barrier.wait();
                let batch =
                    with_prepared_credential_material(&preparation, &mut resolver, |prepared| {
                        materialize_environment_and_stdin(
                            &injection,
                            prepared,
                            ChildEnvironmentValues::new(injection.baseline()),
                            |materialized| {
                                let raw = [b"diagnostic=".as_slice(), &canary].concat();
                                materialized.seal_persistence(
                                    call_id(&format!("phase3e-parallel-{index:02}")),
                                    CredentialExecutionOutcome::Succeeded,
                                    &[CredentialPersistenceDraft::new(
                                        CredentialPersistenceSurface::ProcessDiagnostic,
                                        &raw,
                                    )],
                                )
                            },
                        )
                    })
                    .expect("parallel resolution")
                    .expect("parallel materialization")
                    .expect("parallel persistence");
                assert_eq!(batch.receipt().scope(), &scope);
                assert!(!contains_bytes(batch.records()[0].bytes(), &canary));
            })
        })
        .collect::<Vec<_>>();
    for thread in threads {
        thread.join().expect("parallel qualification");
    }
}

#[test]
fn maximum_phase3_boundary_remains_iterative_on_a_small_stack() {
    thread::Builder::new()
        .name("phase3e-small-stack".to_owned())
        .stack_size(128 * 1024)
        .spawn(|| {
            let scope = CredentialScope::new("small-stack-owner", "default").expect("scope");
            let secret_bindings = (0..MAX_PREPARED_CREDENTIAL_BINDINGS)
                .map(|index| SecretBindingRef {
                    name: format!("binding-{index:02}"),
                    secret_ref: format!("QUALIFICATION_REF_{index:02}"),
                })
                .collect::<Vec<_>>();
            let injections = (0..MAX_PREPARED_CREDENTIAL_BINDINGS)
                .map(|index| InjectionBinding {
                    source: InjectionSource::Secret {
                        binding: format!("binding-{index:02}"),
                    },
                    target: InjectionTarget::Environment {
                        name: format!("QUALIFICATION_SECRET_{index:02}"),
                    },
                })
                .collect::<Vec<_>>();
            let contract = cli_contract(AuthContract {
                kind: AuthKind::Secrets,
                requirement: AuthRequirement::Required,
                secret_bindings,
                injections,
                ..AuthContract::default()
            });
            let preparation = CredentialPreparationPlan::new(
                scope.clone(),
                AuthKind::Secrets,
                &none_selection(&scope),
                (0..MAX_PREPARED_CREDENTIAL_BINDINGS)
                    .rev()
                    .map(|index| binding(&format!("binding-{index:02}"), 64))
                    .collect(),
            )
            .expect("maximum preparation");
            let injection = CredentialInjectionPlan::compile(
                validate_skill_runtime_contract(&contract).expect("maximum contract"),
                &preparation,
                ChildEnvironmentBaseline::hermetic(),
            )
            .expect("maximum injection");
            let mut resolver = MapResolver {
                values: (0..MAX_PREPARED_CREDENTIAL_BINDINGS)
                    .map(|index| {
                        (
                            format!("binding-{index:02}"),
                            format!("value-canary-{index:02}").into_bytes(),
                        )
                    })
                    .collect(),
            };
            let batch =
                with_prepared_credential_material(&preparation, &mut resolver, |prepared| {
                    materialize_environment_and_stdin(
                        &injection,
                        prepared,
                        ChildEnvironmentValues::new(injection.baseline()),
                        |materialized| {
                            assert_eq!(materialized.environment_len(), 64);
                            let raw = b"value-canary-00 value-canary-63";
                            let drafts = (0..MAX_CREDENTIAL_PERSISTENCE_RECORDS)
                                .map(|_| {
                                    CredentialPersistenceDraft::new(
                                        CredentialPersistenceSurface::Trace,
                                        raw,
                                    )
                                })
                                .collect::<Vec<_>>();
                            materialized.seal_persistence(
                                call_id("phase3e-small-stack"),
                                CredentialExecutionOutcome::Succeeded,
                                &drafts,
                            )
                        },
                    )
                })
                .expect("maximum resolution")
                .expect("maximum materialization")
                .expect("maximum persistence");
            assert_eq!(batch.records().len(), MAX_CREDENTIAL_PERSISTENCE_RECORDS);
            for record in batch.records() {
                assert!(!contains_bytes(record.bytes(), b"value-canary-00"));
                assert!(!contains_bytes(record.bytes(), b"value-canary-63"));
            }
        })
        .expect("small-stack thread")
        .join()
        .expect("small-stack qualification");
}

#[test]
fn segmented_redaction_projection_must_preserve_record_cardinality() {
    let scope = CredentialScope::new("projection-owner", "default").expect("scope");
    let (_, injection) = local_secret_boundary(&scope);
    let raw = b"safe";
    let drafts = [CredentialPersistenceDraft::new(
        CredentialPersistenceSurface::Log,
        raw,
    )];
    let error = seal_credential_persistence(
        crate::credential_injection::CredentialInjectionReceipt::new(
            call_id("phase3e-projection"),
            &injection,
            CredentialExecutionOutcome::Succeeded,
        ),
        &drafts,
        |_| {
            Ok(vec![
                CredentialRedactedOutput(Vec::new()),
                CredentialRedactedOutput(Vec::new()),
            ])
        },
    )
    .expect_err("extra projected record");
    assert_eq!(error.code, CredentialPersistenceErrorCode::RedactionFailed);

    let error = seal_credential_persistence(
        crate::credential_injection::CredentialInjectionReceipt::new(
            call_id("phase3e-projection-length"),
            &injection,
            CredentialExecutionOutcome::Succeeded,
        ),
        &drafts,
        |_| Ok(vec![CredentialRedactedOutput(Vec::new())]),
    )
    .expect_err("projected record length mismatch");
    assert_eq!(error.code, CredentialPersistenceErrorCode::RedactionFailed);
}
