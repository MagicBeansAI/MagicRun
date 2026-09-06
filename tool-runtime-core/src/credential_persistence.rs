//! Secret-safe persistence and audit projection for credential-bearing calls.
//!
//! This dormant Phase 3D boundary accepts raw persistence candidates only from
//! crate-owned execution code while the sealed credential materializer is alive. It
//! returns non-serializable records whose bytes have already passed exact-value
//! redaction, plus the metadata-only Phase 3A receipt. External persistence adapters
//! can never construct a redacted record from arbitrary bytes.

use std::{error::Error, fmt};

use serde::Serialize;

use crate::{
    credential_injection::{CredentialExecutionFailure, CredentialInjectionReceipt},
    credential_materialization::{
        CredentialMaterializationError, CredentialRedactedOutput, MAX_REDACTION_INPUT_BYTES,
        MAX_REDACTION_OUTPUT_BYTES,
    },
};

pub const CREDENTIAL_PERSISTENCE_V1: &str = "tool-runtime.credential-persistence.v1";
pub const MAX_CREDENTIAL_PERSISTENCE_RECORDS: usize = 16;
pub const MAX_CREDENTIAL_PERSISTENCE_TOTAL_BYTES: usize = MAX_REDACTION_OUTPUT_BYTES;

/// A persistence surface that may receive dynamic execution bytes. Prompts and tool
/// schemas are deliberately absent: credential values are never admitted to either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialPersistenceSurface {
    ProcessDiagnostic,
    ToolOutput,
    ToolError,
    Artifact,
    Log,
    Trace,
    Analytics,
}

impl CredentialPersistenceSurface {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessDiagnostic => "process_diagnostic",
            Self::ToolOutput => "tool_output",
            Self::ToolError => "tool_error",
            Self::Artifact => "artifact",
            Self::Log => "log",
            Self::Trace => "trace",
            Self::Analytics => "analytics",
        }
    }
}

/// Raw bytes are constructible only inside this crate and must be consumed before the
/// one-call credential owner is dropped.
pub(crate) struct CredentialPersistenceDraft<'a> {
    surface: CredentialPersistenceSurface,
    bytes: &'a [u8],
}

impl<'a> CredentialPersistenceDraft<'a> {
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "Phase 6 governed execution constructs persistence drafts"
        )
    )]
    pub(crate) const fn new(surface: CredentialPersistenceSurface, bytes: &'a [u8]) -> Self {
        Self { surface, bytes }
    }
}

/// One redacted persistence record. It is intentionally not serializable or cloneable;
/// the owning adapter must choose an explicit destination and consume or borrow it.
pub struct CredentialRedactedPersistenceRecord {
    surface: CredentialPersistenceSurface,
    output: CredentialRedactedOutput,
}

impl CredentialRedactedPersistenceRecord {
    pub fn surface(&self) -> CredentialPersistenceSurface {
        self.surface
    }

    pub fn bytes(&self) -> &[u8] {
        self.output.as_bytes()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.output.into_bytes()
    }
}

impl fmt::Debug for CredentialRedactedPersistenceRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialRedactedPersistenceRecord")
            .field("surface", &self.surface)
            .field("bytes", &self.output.as_bytes().len())
            .finish()
    }
}

/// Complete secret-safe handoff from sealed execution to persistence owners. The
/// receipt is serializable metadata; records remain explicit byte capabilities.
pub struct CredentialPersistenceBatch {
    schema_version: &'static str,
    receipt: CredentialInjectionReceipt,
    records: Vec<CredentialRedactedPersistenceRecord>,
    total_bytes: usize,
}

impl CredentialPersistenceBatch {
    pub fn schema_version(&self) -> &'static str {
        self.schema_version
    }

    pub fn receipt(&self) -> &CredentialInjectionReceipt {
        &self.receipt
    }

    pub fn records(&self) -> &[CredentialRedactedPersistenceRecord] {
        &self.records
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn into_parts(
        self,
    ) -> (
        CredentialInjectionReceipt,
        Vec<CredentialRedactedPersistenceRecord>,
    ) {
        (self.receipt, self.records)
    }
}

impl fmt::Debug for CredentialPersistenceBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialPersistenceBatch")
            .field("schema_version", &self.schema_version)
            .field("records", &self.records.len())
            .field("total_bytes", &self.total_bytes)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialPersistenceErrorCode {
    RecordLimitExceeded,
    TotalBytesExceeded,
    RedactionFailed,
    AuditFailed,
}

/// Fixed, value-free persistence failure. Sink errors, output bytes, paths, and
/// credentials are deliberately discarded rather than copied into diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CredentialPersistenceError {
    pub code: CredentialPersistenceErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl CredentialPersistenceError {
    const fn new(
        code: CredentialPersistenceErrorCode,
        field: &'static str,
        message: &'static str,
    ) -> Self {
        Self {
            code,
            field,
            message,
        }
    }

    pub const fn execution_failure(self) -> CredentialExecutionFailure {
        match self.code {
            CredentialPersistenceErrorCode::RecordLimitExceeded
            | CredentialPersistenceErrorCode::TotalBytesExceeded => {
                CredentialExecutionFailure::OutputTruncated
            },
            CredentialPersistenceErrorCode::RedactionFailed => {
                CredentialExecutionFailure::RedactionFailed
            },
            CredentialPersistenceErrorCode::AuditFailed => CredentialExecutionFailure::AuditFailed,
        }
    }
}

impl fmt::Display for CredentialPersistenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for CredentialPersistenceError {}

/// Minimal adapter implemented by a product-owned durable audit boundary. The sink's
/// native error is never returned because it may contain a path or provider diagnostic.
pub trait CredentialAuditSink {
    type Error;

    fn persist(&mut self, receipt: &CredentialInjectionReceipt) -> Result<(), Self::Error>;
}

/// Persist one metadata-only receipt and collapse every sink failure to the stable
/// `audit_failed` execution outcome.
pub fn persist_credential_audit_receipt<S: CredentialAuditSink>(
    sink: &mut S,
    receipt: &CredentialInjectionReceipt,
) -> Result<(), CredentialPersistenceError> {
    sink.persist(receipt).map_err(|_| audit_failed())
}

pub(crate) fn seal_credential_persistence(
    receipt: CredentialInjectionReceipt,
    drafts: &[CredentialPersistenceDraft<'_>],
    mut redact: impl FnMut(
        &[&[u8]],
    ) -> Result<Vec<CredentialRedactedOutput>, CredentialMaterializationError>,
) -> Result<CredentialPersistenceBatch, CredentialPersistenceError> {
    if drafts.len() > MAX_CREDENTIAL_PERSISTENCE_RECORDS {
        return Err(record_limit_exceeded());
    }

    let mut input_total_bytes = 0usize;
    for draft in drafts {
        if draft.bytes.len() > MAX_REDACTION_INPUT_BYTES {
            return Err(redaction_failed());
        }
        input_total_bytes = input_total_bytes
            .checked_add(draft.bytes.len())
            .ok_or_else(total_bytes_exceeded)?;
        if input_total_bytes > MAX_CREDENTIAL_PERSISTENCE_TOTAL_BYTES {
            return Err(total_bytes_exceeded());
        }
    }

    let inputs = drafts.iter().map(|draft| draft.bytes).collect::<Vec<_>>();
    let outputs = redact(&inputs).map_err(|_| redaction_failed())?;
    if outputs.len() != drafts.len() {
        return Err(redaction_failed());
    }

    let mut redacted_total_bytes = 0usize;
    let mut records = Vec::with_capacity(drafts.len());
    for (draft, output) in drafts.iter().zip(outputs) {
        if output.as_bytes().len() != draft.bytes.len() {
            return Err(redaction_failed());
        }
        redacted_total_bytes = redacted_total_bytes
            .checked_add(output.as_bytes().len())
            .ok_or_else(total_bytes_exceeded)?;
        if redacted_total_bytes > MAX_CREDENTIAL_PERSISTENCE_TOTAL_BYTES {
            return Err(total_bytes_exceeded());
        }
        records.push(CredentialRedactedPersistenceRecord {
            surface: draft.surface,
            output,
        });
    }

    Ok(CredentialPersistenceBatch {
        schema_version: CREDENTIAL_PERSISTENCE_V1,
        receipt,
        records,
        total_bytes: redacted_total_bytes,
    })
}

const fn record_limit_exceeded() -> CredentialPersistenceError {
    CredentialPersistenceError::new(
        CredentialPersistenceErrorCode::RecordLimitExceeded,
        "persistence_records",
        "credential-safe persistence exceeded its bounded record count",
    )
}

const fn total_bytes_exceeded() -> CredentialPersistenceError {
    CredentialPersistenceError::new(
        CredentialPersistenceErrorCode::TotalBytesExceeded,
        "persistence_records",
        "credential-safe persistence exceeded its bounded aggregate input",
    )
}

const fn redaction_failed() -> CredentialPersistenceError {
    CredentialPersistenceError::new(
        CredentialPersistenceErrorCode::RedactionFailed,
        "persistence_redaction",
        "credential-safe persistence could not redact an output record",
    )
}

const fn audit_failed() -> CredentialPersistenceError {
    CredentialPersistenceError::new(
        CredentialPersistenceErrorCode::AuditFailed,
        "credential_audit",
        "the credential execution receipt could not be persisted",
    )
}

#[cfg(test)]
mod tests {
    use static_assertions::{assert_impl_all, assert_not_impl_any};

    use super::*;
    use crate::{
        credential_injection::{
            CredentialCallId, CredentialExecutionOutcome, CredentialInjectionPlan,
        },
        credential_materialization::{CredentialRedactedOutput, MAX_REDACTION_INPUT_BYTES},
        credential_preparation::CredentialPreparationPlan,
        credential_profiles::{
            CredentialProfileBinding, CredentialProfileRegistrySnapshot, CredentialScope,
        },
        manifest::{
            AuthContract, CliInteraction, PolicyFloor, ProfileSelection, RuntimeLimits,
            RuntimeProtocol, RuntimeRequirements, SkillRuntimeContract,
            SkillRuntimeContractVersion, StdinContract, WorkingDirectoryContract,
        },
        manifest_validation::validate_skill_runtime_contract,
        profile_selection::{
            select_credential_profile_from_snapshot, CredentialProfileSelectionRequest,
        },
    };

    fn receipt() -> CredentialInjectionReceipt {
        let scope = CredentialScope::new("owner", "default").expect("scope");
        let contract = SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires: RuntimeRequirements {
                bins: ["fixture-cli".to_owned()].into_iter().collect(),
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
            auth: AuthContract::default(),
            policy_floor: PolicyFloor::default(),
        };
        let validated = validate_skill_runtime_contract(&contract).expect("validated contract");
        let request = CredentialProfileSelectionRequest::new(
            scope.clone(),
            None,
            CredentialProfileBinding::Provider,
            &ProfileSelection::None,
            None,
        )
        .expect("selection request");
        let snapshot =
            CredentialProfileRegistrySnapshot::new(scope, Vec::new()).expect("empty snapshot");
        let selection =
            select_credential_profile_from_snapshot(&request, &snapshot).expect("none selection");
        let preparation = CredentialPreparationPlan::new(
            snapshot.scope().clone(),
            crate::manifest::AuthKind::None,
            &selection,
            Vec::new(),
        )
        .expect("preparation plan");
        let injection =
            CredentialInjectionPlan::compile(validated, &preparation, Default::default())
                .expect("injection plan");
        CredentialInjectionReceipt::new(
            CredentialCallId::new("call-fixture").expect("call id"),
            &injection,
            CredentialExecutionOutcome::Succeeded,
        )
    }

    #[test]
    fn redacted_records_and_batches_are_not_cloneable_or_serializable() {
        assert_impl_all!(CredentialPersistenceSurface: Send, Sync, Serialize);
        assert_not_impl_any!(CredentialRedactedPersistenceRecord: Clone, Serialize);
        assert_not_impl_any!(CredentialPersistenceBatch: Clone, Serialize);
    }

    #[test]
    fn sealing_redacts_every_surface_before_returning_a_batch() {
        let canary = b"credential-canary";
        let inputs = [
            (
                CredentialPersistenceSurface::ToolOutput,
                b"result credential-canary".as_slice(),
            ),
            (
                CredentialPersistenceSurface::Artifact,
                b"artifact credential-canary".as_slice(),
            ),
            (
                CredentialPersistenceSurface::Log,
                b"log credential-canary".as_slice(),
            ),
        ];
        let drafts = inputs
            .iter()
            .map(|(surface, bytes)| CredentialPersistenceDraft::new(*surface, bytes))
            .collect::<Vec<_>>();
        let batch = seal_credential_persistence(receipt(), &drafts, |inputs| {
            let outputs = inputs
                .iter()
                .map(|bytes| {
                    let start = bytes
                        .windows(canary.len())
                        .position(|window| window == canary)
                        .expect("canary in fixture");
                    let mut output = bytes.to_vec();
                    output[start..start + canary.len()].fill(b'*');
                    CredentialRedactedOutput(output)
                })
                .collect();
            Ok(outputs)
        })
        .expect("sealed persistence");

        assert_eq!(batch.schema_version(), CREDENTIAL_PERSISTENCE_V1);
        assert_eq!(batch.records().len(), 3);
        assert_eq!(batch.receipt().call_id().as_str(), "call-fixture");
        for record in batch.records() {
            assert!(!record
                .bytes()
                .windows(canary.len())
                .any(|part| part == canary));
        }
        assert!(!format!("{batch:?}").contains("credential-canary"));
    }

    #[test]
    fn record_and_aggregate_limits_fail_before_unbounded_redaction() {
        let input = [b'x'];
        let too_many = (0..=MAX_CREDENTIAL_PERSISTENCE_RECORDS)
            .map(|_| CredentialPersistenceDraft::new(CredentialPersistenceSurface::Log, &input))
            .collect::<Vec<_>>();
        let mut calls = 0usize;
        let error = seal_credential_persistence(receipt(), &too_many, |_| {
            calls += 1;
            Ok(Vec::new())
        })
        .expect_err("record limit");
        assert_eq!(
            error.code,
            CredentialPersistenceErrorCode::RecordLimitExceeded
        );
        assert_eq!(calls, 0);

        let maximum_record = vec![b'x'; MAX_REDACTION_INPUT_BYTES];
        let final_byte = [b'y'];
        let mut drafts = (0..(MAX_CREDENTIAL_PERSISTENCE_TOTAL_BYTES / MAX_REDACTION_INPUT_BYTES))
            .map(|_| {
                CredentialPersistenceDraft::new(
                    CredentialPersistenceSurface::ToolOutput,
                    &maximum_record,
                )
            })
            .collect::<Vec<_>>();
        drafts.push(CredentialPersistenceDraft::new(
            CredentialPersistenceSurface::ToolError,
            &final_byte,
        ));
        let mut calls = 0usize;
        let error = seal_credential_persistence(receipt(), &drafts, |inputs| {
            calls += 1;
            Ok(inputs
                .iter()
                .map(|bytes| CredentialRedactedOutput(Vec::with_capacity(bytes.len())))
                .collect())
        })
        .expect_err("aggregate limit");
        assert_eq!(
            error.code,
            CredentialPersistenceErrorCode::TotalBytesExceeded
        );
        assert_eq!(calls, 0);
    }

    #[test]
    fn redaction_and_audit_failures_are_fixed_and_typed() {
        let canary = b"sink-error-credential-canary";
        let drafts = [CredentialPersistenceDraft::new(
            CredentialPersistenceSurface::Trace,
            canary,
        )];
        let redaction_error = seal_credential_persistence(receipt(), &drafts, |_| {
            Err(crate::credential_materialization::CredentialMaterializationError {
                code: crate::credential_materialization::CredentialMaterializationErrorCode::RedactionInputTooLarge,
                field: "redaction_input",
                message: "fixed",
            })
        })
        .expect_err("redaction failure");
        assert_eq!(
            redaction_error.execution_failure(),
            CredentialExecutionFailure::RedactionFailed
        );
        assert!(!redaction_error.to_string().contains("credential-canary"));

        struct FailingSink(Vec<u8>);
        impl CredentialAuditSink for FailingSink {
            type Error = Vec<u8>;

            fn persist(
                &mut self,
                _receipt: &CredentialInjectionReceipt,
            ) -> Result<(), Self::Error> {
                Err(std::mem::take(&mut self.0))
            }
        }

        let audit_error =
            persist_credential_audit_receipt(&mut FailingSink(canary.to_vec()), &receipt())
                .expect_err("audit failure");
        assert_eq!(
            audit_error.code,
            CredentialPersistenceErrorCode::AuditFailed
        );
        assert_eq!(
            audit_error.execution_failure(),
            CredentialExecutionFailure::AuditFailed
        );
        assert!(!audit_error.to_string().contains("credential-canary"));
    }
}
