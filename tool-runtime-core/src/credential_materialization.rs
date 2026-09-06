//! Sealed materialization of credential-backed child I/O.
//!
//! Phase 3B consumes the metadata-only Phase 3A plan only while Phase 2 prepared
//! material is alive. Phase 3C2 adds permission-safe scoped files and revalidated
//! existing profile directories beneath the same one-call owner. Values and physical
//! paths stay in crate-private call storage; callers outside this crate cannot inspect
//! them. This module does not read the parent environment, spawn a process, persist
//! output, or enable a production route.

#![cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "sealed Phase 3 materialization pipeline stays dormant until governed dispatch migration"
    )
)]

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    path::Path,
    sync::Arc,
};

use serde::Serialize;
use serde_json::{json, to_vec};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    credential_filesystem::{
        CredentialFileSession, CredentialFilesystemError, CredentialMaterializedDirectory,
        CredentialMaterializedFile, CredentialProfileDirectory, CredentialScratchAuthority,
    },
    credential_injection::{
        ChildEnvironmentBaseline, ChildEnvironmentVariable, CredentialCallId,
        CredentialExecutionFailure, CredentialExecutionOutcome, CredentialInjectionPlan,
        CredentialInjectionReceipt, CredentialInjectionSource, CredentialInjectionTarget,
        CredentialRelativePath,
    },
    credential_persistence::{
        seal_credential_persistence, CredentialPersistenceBatch, CredentialPersistenceDraft,
        CredentialPersistenceError,
    },
    credential_preparation::{
        CredentialMaterialBindingName, PreparedCredentialMaterial,
        MAX_PREPARED_CREDENTIAL_BINDINGS, MAX_TOTAL_PREPARED_CREDENTIAL_BYTES,
    },
    manifest::{MMX_CONFIG_DIR, MMX_CONFIG_FILE},
    manifest_validation::MAX_AUTH_INJECTIONS,
    scoped_paths::{CredentialProfilePathAuthority, ScopedPathComponent},
};

#[cfg(test)]
use crate::manifest::MINIMAX_PROVIDER;

pub const PREFERRED_CREDENTIAL_REDACTION_BYTE: u8 = b'*';
pub const MAX_REDACTION_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_REDACTION_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_REDACTION_COMPARISON_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_REDACTION_PATTERN_BYTES: usize =
    MAX_TOTAL_PREPARED_CREDENTIAL_BYTES + (2 * 1024 * 1024);
pub const MAX_REDACTION_PATTERNS: usize =
    MAX_PREPARED_CREDENTIAL_BINDINGS + MAX_AUTH_INJECTIONS + 1;
pub const MAX_CHILD_ENVIRONMENT_VALUE_BYTES: usize = 64 * 1024;
pub const MAX_CHILD_ENVIRONMENT_TOTAL_BYTES: usize = 256 * 1024;

const DEFAULT_MMX_REGION: &str = "global";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialMaterializationErrorCode {
    BaselineMismatch,
    BaselineVariableNotAllowed,
    DuplicateBaselineValue,
    InvalidEnvironmentValue,
    PreparedMaterialMismatch,
    UnsupportedTarget,
    FilesystemUnavailable,
    ScopedPathUnavailable,
    CleanupFailed,
    RedactionMarkerUnavailable,
    RedactionInputTooLarge,
    RedactionOutputTooLarge,
    RedactionPatternLimitExceeded,
    RedactionWorkLimitExceeded,
    EnvironmentValueTooLarge,
    EnvironmentTotalTooLarge,
}

/// Fixed, value-free error. No authored environment value, credential byte, process
/// output, or filesystem path can be copied into its fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CredentialMaterializationError {
    pub code: CredentialMaterializationErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl CredentialMaterializationError {
    const fn new(
        code: CredentialMaterializationErrorCode,
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
            CredentialMaterializationErrorCode::BaselineMismatch
            | CredentialMaterializationErrorCode::BaselineVariableNotAllowed
            | CredentialMaterializationErrorCode::DuplicateBaselineValue
            | CredentialMaterializationErrorCode::InvalidEnvironmentValue
            | CredentialMaterializationErrorCode::EnvironmentValueTooLarge
            | CredentialMaterializationErrorCode::EnvironmentTotalTooLarge => {
                CredentialExecutionFailure::EnvironmentUnavailable
            },
            CredentialMaterializationErrorCode::RedactionMarkerUnavailable
            | CredentialMaterializationErrorCode::RedactionInputTooLarge
            | CredentialMaterializationErrorCode::RedactionOutputTooLarge
            | CredentialMaterializationErrorCode::RedactionPatternLimitExceeded
            | CredentialMaterializationErrorCode::RedactionWorkLimitExceeded => {
                CredentialExecutionFailure::RedactionFailed
            },
            CredentialMaterializationErrorCode::PreparedMaterialMismatch
            | CredentialMaterializationErrorCode::UnsupportedTarget
            | CredentialMaterializationErrorCode::FilesystemUnavailable => {
                CredentialExecutionFailure::MaterializationFailed
            },
            CredentialMaterializationErrorCode::ScopedPathUnavailable => {
                CredentialExecutionFailure::ScopedPathUnavailable
            },
            CredentialMaterializationErrorCode::CleanupFailed => {
                CredentialExecutionFailure::CleanupFailed
            },
        }
    }
}

impl fmt::Display for CredentialMaterializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for CredentialMaterializationError {}

/// Explicit runtime-owned values for the finite Phase 3A baseline. The constructor
/// binds the values to one exact baseline; no ambient environment is read and no
/// arbitrary variable name can be admitted.
pub struct ChildEnvironmentValues {
    baseline: BTreeSet<ChildEnvironmentVariable>,
    values: BTreeMap<String, Zeroizing<Vec<u8>>>,
    total_bytes: usize,
}

impl ChildEnvironmentValues {
    pub fn new(baseline: &ChildEnvironmentBaseline) -> Self {
        Self {
            baseline: baseline.variables().clone(),
            values: BTreeMap::new(),
            total_bytes: 0,
        }
    }

    pub fn provide(
        &mut self,
        variable: ChildEnvironmentVariable,
        value: Vec<u8>,
    ) -> Result<(), CredentialMaterializationError> {
        let value = Zeroizing::new(value);
        if !self.baseline.contains(&variable) {
            return Err(baseline_variable_not_allowed());
        }
        let name = variable.as_str().to_owned();
        if self.values.contains_key(&name) {
            return Err(duplicate_baseline_value());
        }
        validate_environment_value(&value)?;
        let total_bytes = self
            .total_bytes
            .checked_add(name.len())
            .and_then(|total| total.checked_add(value.len()))
            .ok_or_else(environment_total_too_large)?;
        if total_bytes > MAX_CHILD_ENVIRONMENT_TOTAL_BYTES {
            return Err(environment_total_too_large());
        }
        self.values.insert(name, value);
        self.total_bytes = total_bytes;
        Ok(())
    }

    /// Add one already semantically validated, package-authored non-secret
    /// environment value. It cannot replace the finite runtime baseline.
    pub fn provide_fixed(
        &mut self,
        name: impl Into<String>,
        value: Vec<u8>,
    ) -> Result<(), CredentialMaterializationError> {
        let name = name.into();
        let value = Zeroizing::new(value);
        if name.is_empty()
            || name.len() > 128
            || self
                .baseline
                .iter()
                .any(|variable| variable.as_str().eq_ignore_ascii_case(&name))
            || self.values.contains_key(&name)
        {
            return Err(duplicate_baseline_value());
        }
        validate_environment_value(&value)?;
        let total_bytes = self
            .total_bytes
            .checked_add(name.len())
            .and_then(|total| total.checked_add(value.len()))
            .ok_or_else(environment_total_too_large)?;
        if total_bytes > MAX_CHILD_ENVIRONMENT_TOTAL_BYTES {
            return Err(environment_total_too_large());
        }
        self.values.insert(name, value);
        self.total_bytes = total_bytes;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub(crate) fn duplicate_for_sealed_call(&self) -> Self {
        Self {
            baseline: self.baseline.clone(),
            values: self.values.clone(),
            total_bytes: self.total_bytes,
        }
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        BTreeSet<ChildEnvironmentVariable>,
        BTreeMap<String, Zeroizing<Vec<u8>>>,
    ) {
        (self.baseline, self.values)
    }
}

enum MaterializedValue {
    Runtime(Zeroizing<Vec<u8>>),
    Sensitive(Arc<Zeroizing<Vec<u8>>>),
}

impl MaterializedValue {
    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Runtime(value) => value,
            Self::Sensitive(value) => value,
        }
    }
}

struct MaterializedEnvironmentEntry {
    name: String,
    value: MaterializedValue,
    profile_guard: Option<usize>,
}

impl MaterializedEnvironmentEntry {
    fn name(&self) -> &str {
        &self.name
    }

    fn value(&self) -> &[u8] {
        self.value.as_bytes()
    }
}

struct MaterializedScopedFile {
    relative_path: CredentialRelativePath,
    file: CredentialMaterializedFile,
}

enum MaterializedConfigDirectoryContents {
    Profile(CredentialProfileDirectory),
    Session(CredentialMaterializedDirectory),
}

struct MaterializedConfigDirectory {
    name: ScopedPathComponent,
    directory: MaterializedConfigDirectoryContents,
}

impl MaterializedConfigDirectory {
    fn directory_revalidated_path(&self) -> Result<&Path, CredentialMaterializationError> {
        match &self.directory {
            MaterializedConfigDirectoryContents::Profile(profile) => {
                profile.revalidated_path().map_err(profile_filesystem_error)
            },
            MaterializedConfigDirectoryContents::Session(session) => session
                .revalidated_path()
                .map_err(materialization_filesystem_error),
        }
    }
}

/// Exact filesystem authorities for one sealed materialization call. It is
/// intentionally crate-private and cannot reveal a path by itself.
pub(crate) struct CredentialFilesystemMaterialization<'a> {
    call_id: &'a CredentialCallId,
    scratch: &'a CredentialScratchAuthority,
    profile_root: Option<&'a CredentialProfilePathAuthority>,
}

impl<'a> CredentialFilesystemMaterialization<'a> {
    pub(crate) fn new(
        call_id: &'a CredentialCallId,
        scratch: &'a CredentialScratchAuthority,
        profile_root: Option<&'a CredentialProfilePathAuthority>,
    ) -> Self {
        Self {
            call_id,
            scratch,
            profile_root,
        }
    }
}

/// Safe output from exact-value credential redaction. Debug formatting deliberately
/// reports only length; byte access exists for the later governed execution adapter.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialRedactedOutput(pub(crate) Vec<u8>);

impl CredentialRedactedOutput {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for CredentialRedactedOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialRedactedOutput")
            .field("bytes", &self.0.len())
            .finish()
    }
}

struct CredentialPatternPrefix {
    key: u32,
    pattern_index: usize,
}

impl Zeroize for CredentialPatternPrefix {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.pattern_index.zeroize();
    }
}

pub(crate) struct CredentialValueRedactor {
    patterns: Vec<Arc<Zeroizing<Vec<u8>>>>,
    prefixes: Zeroizing<Vec<CredentialPatternPrefix>>,
    replacement: u8,
}

impl CredentialValueRedactor {
    pub(crate) fn new(
        mut patterns: Vec<Arc<Zeroizing<Vec<u8>>>>,
    ) -> Result<Self, CredentialMaterializationError> {
        patterns.sort_by(|left, right| {
            right
                .len()
                .cmp(&left.len())
                .then_with(|| left.as_slice().cmp(right.as_slice()))
        });
        patterns.dedup_by(|left, right| left.as_slice() == right.as_slice());
        if patterns.len() > MAX_REDACTION_PATTERNS
            || patterns.iter().any(|pattern| pattern.is_empty())
        {
            return Err(redaction_pattern_limit_exceeded());
        }
        let total_pattern_bytes = patterns
            .iter()
            .try_fold(0usize, |total, pattern| total.checked_add(pattern.len()));
        if !matches!(total_pattern_bytes, Some(total) if total <= MAX_REDACTION_PATTERN_BYTES) {
            return Err(redaction_pattern_limit_exceeded());
        }
        let replacement = (0..=u8::MAX)
            .map(|offset| PREFERRED_CREDENTIAL_REDACTION_BYTE.wrapping_add(offset))
            .find(|candidate| patterns.iter().all(|pattern| !pattern.contains(candidate)))
            .ok_or_else(redaction_marker_unavailable)?;
        let mut prefixes = Zeroizing::new(
            patterns
                .iter()
                .enumerate()
                .map(|(pattern_index, pattern)| CredentialPatternPrefix {
                    key: credential_pattern_prefix(pattern),
                    pattern_index,
                })
                .collect::<Vec<_>>(),
        );
        prefixes.sort_by(|left, right| {
            left.key.cmp(&right.key).then_with(|| {
                patterns[right.pattern_index]
                    .len()
                    .cmp(&patterns[left.pattern_index].len())
            })
        });
        Ok(Self {
            patterns,
            prefixes,
            replacement,
        })
    }

    pub(crate) fn max_pattern_len(&self) -> usize {
        self.patterns.first().map_or(0, |pattern| pattern.len())
    }

    pub(crate) fn streaming(&self) -> CredentialStreamingRedactor<'_> {
        CredentialStreamingRedactor {
            redactor: self,
            pending: Zeroizing::new(Vec::new()),
            cursor: 0,
            compared_bytes: 0,
        }
    }

    pub(crate) fn duplicate(&self) -> Result<Self, CredentialMaterializationError> {
        Self::new(self.patterns.clone())
    }

    pub(crate) fn duplicate_with_additional_secret(
        &self,
        secret: Option<&[u8]>,
    ) -> Result<Self, CredentialMaterializationError> {
        let mut patterns = self.patterns.clone();
        if let Some(secret) = secret {
            if secret.is_empty() {
                return Err(redaction_pattern_limit_exceeded());
            }
            patterns.push(Arc::new(Zeroizing::new(secret.to_vec())));
        }
        Self::new(patterns)
    }

    fn find_next(
        &self,
        input: &[u8],
        start: usize,
        compared_bytes: &mut usize,
    ) -> Result<Option<(usize, usize)>, CredentialMaterializationError> {
        let mut position = start;
        while position < input.len() {
            if position + 1 < input.len() {
                let key = 256 + ((input[position] as u32) << 8) + input[position + 1] as u32;
                if let Some(end) = self.match_at_key(input, position, key, compared_bytes)? {
                    return Ok(Some((position, end)));
                }
            }
            if let Some(end) =
                self.match_at_key(input, position, input[position] as u32, compared_bytes)?
            {
                return Ok(Some((position, end)));
            }
            position = position.saturating_add(1);
        }
        Ok(None)
    }

    fn match_at_key(
        &self,
        input: &[u8],
        position: usize,
        key: u32,
        compared_bytes: &mut usize,
    ) -> Result<Option<usize>, CredentialMaterializationError> {
        let first = self.prefixes.partition_point(|entry| entry.key < key);
        for entry in self.prefixes[first..]
            .iter()
            .take_while(|entry| entry.key == key)
        {
            let Some(pattern) = self.patterns.get(entry.pattern_index) else {
                return Err(prepared_material_mismatch());
            };
            let Some(end) = position.checked_add(pattern.len()) else {
                return Err(redaction_work_limit_exceeded());
            };
            *compared_bytes = compared_bytes
                .checked_add(pattern.len())
                .ok_or_else(redaction_work_limit_exceeded)?;
            if *compared_bytes > MAX_REDACTION_COMPARISON_BYTES {
                return Err(redaction_work_limit_exceeded());
            }
            if input.get(position..end) == Some(pattern.as_slice()) {
                return Ok(Some(end));
            }
        }
        Ok(None)
    }

    pub(crate) fn redact(
        &self,
        input: &[u8],
    ) -> Result<CredentialRedactedOutput, CredentialMaterializationError> {
        self.redact_with_limits(input, MAX_REDACTION_INPUT_BYTES, MAX_REDACTION_OUTPUT_BYTES)
    }

    fn redact_with_limits(
        &self,
        input: &[u8],
        max_input: usize,
        max_output: usize,
    ) -> Result<CredentialRedactedOutput, CredentialMaterializationError> {
        if input.len() > max_input {
            return Err(redaction_input_too_large());
        }
        if self.patterns.is_empty() {
            return Ok(CredentialRedactedOutput(input.to_vec()));
        }
        let mut output = Vec::with_capacity(input.len());
        let mut cursor = 0usize;
        let mut compared_bytes = 0usize;
        while let Some((start, end)) = self.find_next(input, cursor, &mut compared_bytes)? {
            append_bounded_to(&mut output, &input[cursor..start], max_output)?;
            append_bounded_to(&mut output, &[self.replacement], max_output)?;
            cursor = end;
        }
        append_bounded_to(&mut output, &input[cursor..], max_output)?;
        Ok(CredentialRedactedOutput(output))
    }

    /// Redact already-bounded governed execution segments in place. Keeping segment
    /// boundaries in one logical stream prevents a credential split across stdout,
    /// stderr, or adjacent declared artifacts from evading the matcher, while avoiding
    /// another aggregate-sized copy of raw process output. Matches preserve length so
    /// original segment boundaries remain exact.
    pub(crate) fn redact_governed_segments_owned(
        &self,
        mut inputs: Vec<Zeroizing<Vec<u8>>>,
        max_total_bytes: usize,
    ) -> Result<(Vec<CredentialRedactedOutput>, Vec<bool>), CredentialMaterializationError> {
        let mut offsets = Vec::with_capacity(inputs.len());
        let mut total_bytes = 0usize;
        for input in &inputs {
            offsets.push(total_bytes);
            total_bytes = total_bytes
                .checked_add(input.len())
                .ok_or_else(redaction_input_too_large)?;
            if total_bytes > max_total_bytes {
                return Err(redaction_input_too_large());
            }
        }

        let mut matched_segments = vec![false; inputs.len()];
        let mut position = 0usize;
        let mut segment_index = 0usize;
        let mut compared_bytes = 0usize;
        while !self.patterns.is_empty() && position < total_bytes {
            while segment_index + 1 < offsets.len() && offsets[segment_index + 1] <= position {
                segment_index = segment_index.saturating_add(1);
            }
            let local = position
                .checked_sub(
                    *offsets
                        .get(segment_index)
                        .ok_or_else(prepared_material_mismatch)?,
                )
                .ok_or_else(prepared_material_mismatch)?;
            let first = inputs
                .get(segment_index)
                .and_then(|input| input.get(local))
                .copied()
                .ok_or_else(prepared_material_mismatch)?;
            let second = inputs
                .get(segment_index)
                .and_then(|input| input.get(local.saturating_add(1)))
                .copied()
                .or_else(|| segmented_byte(&inputs, &offsets, position.saturating_add(1)));
            let two_byte_key = second.map(|second| 256 + ((first as u32) << 8) + second as u32);
            let mut end = match two_byte_key {
                Some(key) => {
                    self.match_segmented_at(&inputs, &offsets, position, key, &mut compared_bytes)?
                },
                None => None,
            };
            if end.is_none() {
                end = self.match_segmented_at(
                    &inputs,
                    &offsets,
                    position,
                    first as u32,
                    &mut compared_bytes,
                )?;
            }
            if let Some(end) = end {
                mark_segment_range(&offsets, &mut matched_segments, position, end)?;
                fill_segmented(&mut inputs, &offsets, position, end, self.replacement)?;
                position = end;
            } else {
                position = position.saturating_add(1);
            }
        }

        let outputs = inputs
            .iter_mut()
            .map(|input| CredentialRedactedOutput(std::mem::take(&mut **input)))
            .collect();
        Ok((outputs, matched_segments))
    }

    fn match_segmented_at(
        &self,
        inputs: &[Zeroizing<Vec<u8>>],
        offsets: &[usize],
        position: usize,
        key: u32,
        compared_bytes: &mut usize,
    ) -> Result<Option<usize>, CredentialMaterializationError> {
        let first = self.prefixes.partition_point(|entry| entry.key < key);
        for entry in self.prefixes[first..]
            .iter()
            .take_while(|entry| entry.key == key)
        {
            let pattern = self
                .patterns
                .get(entry.pattern_index)
                .ok_or_else(prepared_material_mismatch)?;
            let end = position
                .checked_add(pattern.len())
                .ok_or_else(redaction_work_limit_exceeded)?;
            *compared_bytes = compared_bytes
                .checked_add(pattern.len())
                .ok_or_else(redaction_work_limit_exceeded)?;
            if *compared_bytes > MAX_REDACTION_COMPARISON_BYTES {
                return Err(redaction_work_limit_exceeded());
            }
            if pattern.iter().enumerate().all(|(delta, expected)| {
                segmented_byte(inputs, offsets, position + delta) == Some(*expected)
            }) {
                return Ok(Some(end));
            }
        }
        Ok(None)
    }

    /// Redact one persistence batch as a single byte stream, then restore its original
    /// record boundaries. Matches are replaced in-place so a credential split across
    /// adjacent records cannot evade the exact-value matcher or become reconstructable
    /// after persistence.
    fn redact_segments(
        &self,
        inputs: &[&[u8]],
    ) -> Result<Vec<CredentialRedactedOutput>, CredentialMaterializationError> {
        let mut total_bytes = 0usize;
        for input in inputs {
            total_bytes = total_bytes
                .checked_add(input.len())
                .ok_or_else(redaction_output_too_large)?;
            if total_bytes > MAX_REDACTION_OUTPUT_BYTES {
                return Err(redaction_output_too_large());
            }
        }

        if self.patterns.is_empty() {
            return Ok(inputs
                .iter()
                .map(|input| CredentialRedactedOutput(input.to_vec()))
                .collect());
        }

        let mut current = Vec::with_capacity(total_bytes);
        for input in inputs {
            append_bounded(&mut current, input)?;
        }
        let mut cursor = 0usize;
        let mut compared_bytes = 0usize;
        while let Some((start, end)) = self.find_next(&current, cursor, &mut compared_bytes)? {
            current[start..end].fill(self.replacement);
            cursor = end;
        }
        split_redacted_segments(current, inputs)
    }
}

pub(crate) struct CredentialStreamingRedactor<'a> {
    redactor: &'a CredentialValueRedactor,
    pending: Zeroizing<Vec<u8>>,
    cursor: usize,
    compared_bytes: usize,
}

impl CredentialStreamingRedactor<'_> {
    pub(crate) fn push(
        &mut self,
        input: &[u8],
    ) -> Result<CredentialRedactedOutput, CredentialMaterializationError> {
        if self.redactor.patterns.is_empty() {
            if input.len() > MAX_REDACTION_INPUT_BYTES {
                return Err(redaction_input_too_large());
            }
            return Ok(CredentialRedactedOutput(input.to_vec()));
        }
        self.compact();
        let next = self
            .pending
            .len()
            .checked_add(input.len())
            .ok_or_else(redaction_input_too_large)?;
        let maximum = self.redactor.max_pattern_len().max(1);
        if next > MAX_REDACTION_INPUT_BYTES.saturating_add(maximum) {
            return Err(redaction_input_too_large());
        }
        self.pending.extend_from_slice(input);
        self.drain_stable(false)
    }

    pub(crate) fn into_pending(mut self) -> Zeroizing<Vec<u8>> {
        self.compact();
        self.pending
    }

    fn compact(&mut self) {
        if self.cursor > 0 {
            self.pending.drain(..self.cursor);
            self.cursor = 0;
        }
    }

    fn drain_stable(
        &mut self,
        final_input: bool,
    ) -> Result<CredentialRedactedOutput, CredentialMaterializationError> {
        let mut output = Vec::new();
        let max_output = MAX_REDACTION_INPUT_BYTES.saturating_add(self.redactor.max_pattern_len());
        while self.cursor < self.pending.len() {
            match self.next_decision(final_input)? {
                StreamingDecision::Wait => break,
                StreamingDecision::EmitOne => {
                    append_bounded_to(
                        &mut output,
                        &self.pending[self.cursor..self.cursor + 1],
                        max_output,
                    )?;
                    self.cursor = self.cursor.saturating_add(1);
                },
                StreamingDecision::Redact(length) => {
                    let next = output
                        .len()
                        .checked_add(length)
                        .ok_or_else(redaction_output_too_large)?;
                    if next > max_output {
                        return Err(redaction_output_too_large());
                    }
                    output.resize(next, self.redactor.replacement);
                    self.cursor = self.cursor.saturating_add(length);
                },
            }
        }
        Ok(CredentialRedactedOutput(output))
    }

    fn next_decision(
        &mut self,
        final_input: bool,
    ) -> Result<StreamingDecision, CredentialMaterializationError> {
        let pending = self
            .pending
            .get(self.cursor..)
            .ok_or_else(prepared_material_mismatch)?;
        let Some(first) = pending.first().copied() else {
            return Ok(StreamingDecision::Wait);
        };
        if self.redactor.patterns.is_empty() {
            return Ok(StreamingDecision::EmitOne);
        }
        let mut longest_exact = None;
        let mut needs_more = false;
        if let Some(second) = pending.get(1).copied() {
            evaluate_streaming_key(
                self.redactor,
                256 + ((first as u32) << 8) + second as u32,
                pending,
                final_input,
                &mut self.compared_bytes,
                &mut longest_exact,
                &mut needs_more,
            )?;
            evaluate_streaming_key(
                self.redactor,
                first as u32,
                pending,
                final_input,
                &mut self.compared_bytes,
                &mut longest_exact,
                &mut needs_more,
            )?;
        } else {
            for pattern in &self.redactor.patterns {
                if pattern.first().copied() == Some(first) {
                    evaluate_streaming_pattern(
                        pattern,
                        pending,
                        final_input,
                        &mut self.compared_bytes,
                        &mut longest_exact,
                        &mut needs_more,
                    )?;
                }
            }
        }
        if needs_more && !final_input {
            Ok(StreamingDecision::Wait)
        } else if let Some(length) = longest_exact {
            Ok(StreamingDecision::Redact(length))
        } else {
            Ok(StreamingDecision::EmitOne)
        }
    }
}

enum StreamingDecision {
    Wait,
    EmitOne,
    Redact(usize),
}

fn evaluate_streaming_key(
    redactor: &CredentialValueRedactor,
    key: u32,
    pending: &[u8],
    final_input: bool,
    compared_bytes: &mut usize,
    longest_exact: &mut Option<usize>,
    needs_more: &mut bool,
) -> Result<(), CredentialMaterializationError> {
    let first = redactor.prefixes.partition_point(|entry| entry.key < key);
    for entry in redactor.prefixes[first..]
        .iter()
        .take_while(|entry| entry.key == key)
    {
        let pattern = redactor
            .patterns
            .get(entry.pattern_index)
            .ok_or_else(prepared_material_mismatch)?;
        evaluate_streaming_pattern(
            pattern,
            pending,
            final_input,
            compared_bytes,
            longest_exact,
            needs_more,
        )?;
    }
    Ok(())
}

fn evaluate_streaming_pattern(
    pattern: &[u8],
    pending: &[u8],
    final_input: bool,
    compared_bytes: &mut usize,
    longest_exact: &mut Option<usize>,
    needs_more: &mut bool,
) -> Result<(), CredentialMaterializationError> {
    let compared = pattern.len().min(pending.len());
    *compared_bytes = compared_bytes
        .checked_add(compared)
        .ok_or_else(redaction_work_limit_exceeded)?;
    if *compared_bytes > MAX_REDACTION_COMPARISON_BYTES {
        return Err(redaction_work_limit_exceeded());
    }
    if pattern.get(..compared) != pending.get(..compared) {
        return Ok(());
    }
    if pending.len() < pattern.len() {
        if !final_input {
            *needs_more = true;
        }
        return Ok(());
    }
    if longest_exact.is_none_or(|current| pattern.len() > current) {
        *longest_exact = Some(pattern.len());
    }
    Ok(())
}

fn segmented_byte(inputs: &[Zeroizing<Vec<u8>>], offsets: &[usize], position: usize) -> Option<u8> {
    let index = offsets
        .partition_point(|offset| *offset <= position)
        .checked_sub(1)?;
    let local = position.checked_sub(*offsets.get(index)?)?;
    inputs.get(index)?.get(local).copied()
}

fn fill_segmented(
    inputs: &mut [Zeroizing<Vec<u8>>],
    offsets: &[usize],
    start: usize,
    end: usize,
    replacement: u8,
) -> Result<(), CredentialMaterializationError> {
    for position in start..end {
        let index = offsets
            .partition_point(|offset| *offset <= position)
            .checked_sub(1)
            .ok_or_else(prepared_material_mismatch)?;
        let local = position
            .checked_sub(*offsets.get(index).ok_or_else(prepared_material_mismatch)?)
            .ok_or_else(prepared_material_mismatch)?;
        *inputs
            .get_mut(index)
            .and_then(|input| input.get_mut(local))
            .ok_or_else(prepared_material_mismatch)? = replacement;
    }
    Ok(())
}

fn mark_segment_range(
    offsets: &[usize],
    matched: &mut [bool],
    start: usize,
    end: usize,
) -> Result<(), CredentialMaterializationError> {
    let first = offsets
        .partition_point(|offset| *offset <= start)
        .checked_sub(1)
        .ok_or_else(prepared_material_mismatch)?;
    let last_position = end.checked_sub(1).ok_or_else(prepared_material_mismatch)?;
    let last = offsets
        .partition_point(|offset| *offset <= last_position)
        .checked_sub(1)
        .ok_or_else(prepared_material_mismatch)?;
    for index in first..=last {
        *matched
            .get_mut(index)
            .ok_or_else(prepared_material_mismatch)? = true;
    }
    Ok(())
}

fn credential_pattern_prefix(pattern: &[u8]) -> u32 {
    if pattern.len() == 1 {
        pattern[0] as u32
    } else {
        256 + ((pattern[0] as u32) << 8) + pattern[1] as u32
    }
}

fn split_redacted_segments(
    combined: Vec<u8>,
    inputs: &[&[u8]],
) -> Result<Vec<CredentialRedactedOutput>, CredentialMaterializationError> {
    let mut output = Vec::with_capacity(inputs.len());
    let mut cursor = 0usize;
    for input in inputs {
        let end = cursor
            .checked_add(input.len())
            .ok_or_else(redaction_output_too_large)?;
        let bytes = combined
            .get(cursor..end)
            .ok_or_else(redaction_output_too_large)?
            .to_vec();
        output.push(CredentialRedactedOutput(bytes));
        cursor = end;
    }
    if cursor != combined.len() {
        return Err(redaction_output_too_large());
    }
    Ok(output)
}

/// Crate-private, zeroizing child-call material. The eventual executor consumes only
/// these revalidated views without exposing values or paths through the public runtime
/// surface.
pub(crate) struct MaterializedCredentialIo<'plan> {
    plan: &'plan CredentialInjectionPlan,
    environment: Vec<MaterializedEnvironmentEntry>,
    stdin: Option<MaterializedValue>,
    file_session: Option<CredentialFileSession>,
    scoped_files: Vec<MaterializedScopedFile>,
    environment_profile_guards: Vec<CredentialProfileDirectory>,
    config_directories: Vec<MaterializedConfigDirectory>,
    redactor: CredentialValueRedactor,
}

pub(crate) type GovernedChildEnvironment = Vec<(String, Zeroizing<Vec<u8>>)>;

impl MaterializedCredentialIo<'_> {
    pub(crate) fn environment_len(&self) -> usize {
        self.environment.len()
    }

    pub(crate) fn environment_entry(
        &self,
        index: usize,
    ) -> Result<Option<(&str, &[u8])>, CredentialMaterializationError> {
        let Some(entry) = self.environment.get(index) else {
            return Ok(None);
        };
        if let Some(guard) = entry.profile_guard {
            self.environment_profile_guards
                .get(guard)
                .ok_or_else(prepared_material_mismatch)?
                .revalidated_path()
                .map_err(profile_filesystem_error)?;
        }
        Ok(Some((entry.name(), entry.value())))
    }

    pub(crate) fn stdin(&self) -> Option<&[u8]> {
        self.stdin.as_ref().map(MaterializedValue::as_bytes)
    }

    pub(crate) fn governed_environment(
        &self,
    ) -> Result<GovernedChildEnvironment, CredentialMaterializationError> {
        self.revalidate_filesystem()?;
        if self.environment.iter().any(|entry| {
            self.plan
                .child_environment_names()
                .binary_search_by(|name| name.as_str().cmp(entry.name()))
                .is_err()
        }) {
            return Err(baseline_mismatch());
        }
        Ok(self
            .environment
            .iter()
            .map(|entry| {
                (
                    entry.name().to_owned(),
                    Zeroizing::new(entry.value().to_vec()),
                )
            })
            .collect())
    }

    pub(crate) fn governed_redactor_with_additional_secret(
        &self,
        secret: Option<&[u8]>,
    ) -> Result<CredentialValueRedactor, CredentialMaterializationError> {
        self.redactor.duplicate_with_additional_secret(secret)
    }

    pub(crate) fn scoped_file_root(&self) -> Result<Option<&Path>, CredentialMaterializationError> {
        self.file_session
            .as_ref()
            .map(|session| {
                session
                    .revalidated_path()
                    .map_err(materialization_filesystem_error)
            })
            .transpose()
    }

    pub(crate) fn scoped_file(
        &self,
        index: usize,
    ) -> Result<Option<(&str, &Path)>, CredentialMaterializationError> {
        self.scoped_files
            .get(index)
            .map(|file| {
                file.file
                    .revalidated_path()
                    .map(|path| (file.relative_path.as_str(), path))
                    .map_err(materialization_filesystem_error)
            })
            .transpose()
    }

    pub(crate) fn scoped_file_len(&self) -> usize {
        self.scoped_files.len()
    }

    pub(crate) fn config_directory(
        &self,
        index: usize,
    ) -> Result<Option<(&str, &Path)>, CredentialMaterializationError> {
        self.config_directories
            .get(index)
            .map(|directory| {
                directory
                    .directory_revalidated_path()
                    .map(|path| (directory.name.as_str(), path))
            })
            .transpose()
    }

    pub(crate) fn config_directory_len(&self) -> usize {
        self.config_directories.len()
    }

    pub(crate) fn redact_output(
        &self,
        input: &[u8],
    ) -> Result<CredentialRedactedOutput, CredentialMaterializationError> {
        self.redactor.redact(input)
    }

    /// Seal every dynamic persistence candidate while exact credential values and
    /// physical paths are still available to the call-owned redactor. Only the
    /// redacted batch can cross into product persistence adapters.
    pub(crate) fn seal_persistence(
        &self,
        call_id: CredentialCallId,
        outcome: CredentialExecutionOutcome,
        drafts: &[CredentialPersistenceDraft<'_>],
    ) -> Result<CredentialPersistenceBatch, CredentialPersistenceError> {
        let receipt = CredentialInjectionReceipt::new(call_id, self.plan, outcome);
        seal_credential_persistence(receipt, drafts, |inputs| {
            self.redactor.redact_segments(inputs)
        })
    }

    fn cleanup_filesystem(&mut self) -> Result<(), CredentialMaterializationError> {
        if let Some(session) = &mut self.file_session {
            session.cleanup().map_err(|_| cleanup_failed())?;
        }
        Ok(())
    }

    fn revalidate_filesystem(&self) -> Result<(), CredentialMaterializationError> {
        if let Some(session) = &self.file_session {
            session
                .revalidated_path()
                .map_err(materialization_filesystem_error)?;
        }
        for file in &self.scoped_files {
            file.file
                .revalidated_path()
                .map_err(materialization_filesystem_error)?;
        }
        self.revalidate_profiles()
    }

    fn revalidate_profiles(&self) -> Result<(), CredentialMaterializationError> {
        for directory in &self.environment_profile_guards {
            directory
                .revalidated_path()
                .map_err(profile_filesystem_error)?;
        }
        for directory in &self.config_directories {
            directory.directory_revalidated_path()?;
        }
        Ok(())
    }
}

/// Phase 3B compatibility entrypoint. Filesystem-bearing plans fail closed unless the
/// caller uses [`materialize_credential_io`] with exact scoped authorities.
pub(crate) fn materialize_environment_and_stdin<'plan, T>(
    plan: &'plan CredentialInjectionPlan,
    prepared: &PreparedCredentialMaterial<'_>,
    baseline_values: ChildEnvironmentValues,
    consumer: impl for<'call> FnOnce(&'call MaterializedCredentialIo<'plan>) -> T,
) -> Result<T, CredentialMaterializationError> {
    materialize_credential_io_inner(plan, prepared, baseline_values, None, consumer)
}

/// Materialize every declared local credential target within one sealed callback.
/// Normal return performs explicit scratch cleanup before returning the consumer's
/// value; panic/unwind and later cancellation rely on the non-cloneable session owner.
pub(crate) fn materialize_credential_io<'plan, T>(
    plan: &'plan CredentialInjectionPlan,
    prepared: &PreparedCredentialMaterial<'_>,
    baseline_values: ChildEnvironmentValues,
    filesystem: CredentialFilesystemMaterialization<'_>,
    consumer: impl for<'call> FnOnce(&'call MaterializedCredentialIo<'plan>) -> T,
) -> Result<T, CredentialMaterializationError> {
    materialize_credential_io_inner(plan, prepared, baseline_values, Some(filesystem), consumer)
}

pub(crate) fn materialize_governed_credential_io<'plan, T>(
    plan: &'plan CredentialInjectionPlan,
    prepared: &PreparedCredentialMaterial<'_>,
    baseline_values: ChildEnvironmentValues,
    filesystem: Option<CredentialFilesystemMaterialization<'_>>,
    consumer: impl for<'call> FnOnce(&'call MaterializedCredentialIo<'plan>) -> T,
) -> Result<T, CredentialMaterializationError> {
    materialize_credential_io_inner(plan, prepared, baseline_values, filesystem, consumer)
}

fn materialize_credential_io_inner<'plan, T>(
    plan: &'plan CredentialInjectionPlan,
    prepared: &PreparedCredentialMaterial<'_>,
    baseline_values: ChildEnvironmentValues,
    filesystem: Option<CredentialFilesystemMaterialization<'_>>,
    consumer: impl for<'call> FnOnce(&'call MaterializedCredentialIo<'plan>) -> T,
) -> Result<T, CredentialMaterializationError> {
    if baseline_values.baseline != *plan.baseline().variables() {
        return Err(baseline_mismatch());
    }
    if prepared.len() > plan.redaction_bindings().len()
        || prepared.len() > MAX_PREPARED_CREDENTIAL_BINDINGS
    {
        return Err(prepared_material_mismatch());
    }

    let mut prepared_values = BTreeMap::new();
    for redaction in plan.redaction_bindings() {
        match prepared.kind(redaction.binding()) {
            Some(kind) if kind == redaction.material_kind() => {
                let value = prepared
                    .with_value(redaction.binding(), |value| {
                        Arc::new(Zeroizing::new(value.to_vec()))
                    })
                    .ok_or_else(prepared_material_mismatch)?;
                prepared_values.insert(redaction.binding().clone(), value);
            },
            None if !redaction.is_required() => {},
            _ => return Err(prepared_material_mismatch()),
        }
    }
    if prepared_values.len() != prepared.len() {
        return Err(prepared_material_mismatch());
    }

    let mut sensitive_patterns = prepared_values.values().cloned().collect::<Vec<_>>();
    let mut environment = BTreeMap::new();
    for (variable, value) in baseline_values.values {
        environment.insert(variable, (MaterializedValue::Runtime(value), None));
    }

    let needs_file_session = plan.injections().iter().any(|injection| {
        matches!(
            injection.target(),
            CredentialInjectionTarget::ScopedFile { .. }
        ) || matches!(
            (injection.source(), injection.target()),
            (
                CredentialInjectionSource::PreparedBinding { .. },
                CredentialInjectionTarget::ConfigDirectory { .. }
            )
        )
    });
    let mut file_session = if needs_file_session {
        let authority = filesystem.as_ref().ok_or_else(unsupported_target)?;
        Some(
            authority
                .scratch
                .start_session(authority.call_id, plan.scope())
                .map_err(materialization_filesystem_error)?,
        )
    } else {
        None
    };

    let mut stdin = None;
    let mut scoped_files = Vec::new();
    let mut environment_profile_guards = Vec::new();
    let mut config_directories = Vec::new();
    for injection in plan.injections() {
        match (injection.source(), injection.target()) {
            (
                CredentialInjectionSource::ProfileAuthRoot { path },
                CredentialInjectionTarget::Environment { name },
            ) => {
                let directory = resolve_profile_directory(&filesystem, plan, path)?;
                let value = sensitive_path_value(
                    directory
                        .revalidated_path()
                        .map_err(profile_filesystem_error)?,
                )?;
                validate_environment_value(value.as_slice())?;
                sensitive_patterns.push(value.clone());
                let guard = environment_profile_guards.len();
                if environment
                    .insert(
                        name.clone(),
                        (MaterializedValue::Sensitive(value), Some(guard)),
                    )
                    .is_some()
                {
                    return Err(baseline_mismatch());
                }
                environment_profile_guards.push(directory);
            },
            (
                CredentialInjectionSource::ProfileAuthRoot { path },
                CredentialInjectionTarget::ConfigDirectory { name },
            ) => {
                let directory = resolve_profile_directory(&filesystem, plan, path)?;
                let value = sensitive_path_value(
                    directory
                        .revalidated_path()
                        .map_err(profile_filesystem_error)?,
                )?;
                sensitive_patterns.push(value.clone());
                config_directories.push(MaterializedConfigDirectory {
                    name: name.clone(),
                    directory: MaterializedConfigDirectoryContents::Profile(directory),
                });
            },
            (source, CredentialInjectionTarget::ConfigDirectory { name }) => {
                let Some(value) =
                    materialize_non_filesystem_source(plan, source, &prepared_values)?
                else {
                    continue;
                };
                if let MaterializedValue::Sensitive(value) = &value {
                    sensitive_patterns.push(value.clone());
                }
                let session = file_session.as_mut().ok_or_else(unsupported_target)?;
                if name.as_str() != MMX_CONFIG_DIR {
                    return Err(unsupported_target());
                }
                let directory = session
                    .create_config_directory(name)
                    .map_err(materialization_filesystem_error)?;
                write_minimax_config_json(session, name, value.as_bytes())?;
                let directory_value = sensitive_path_value(
                    directory
                        .revalidated_path()
                        .map_err(materialization_filesystem_error)?,
                )?;
                validate_environment_value(directory_value.as_slice())?;
                if environment
                    .insert(
                        name.as_str().to_string(),
                        (MaterializedValue::Sensitive(directory_value), None),
                    )
                    .is_some()
                {
                    return Err(baseline_mismatch());
                }
                config_directories.push(MaterializedConfigDirectory {
                    name: name.clone(),
                    directory: MaterializedConfigDirectoryContents::Session(directory),
                });
            },
            (source, CredentialInjectionTarget::Environment { name }) => {
                let Some(value) =
                    materialize_non_filesystem_source(plan, source, &prepared_values)?
                else {
                    continue;
                };
                validate_environment_value(value.as_bytes())?;
                if environment.insert(name.clone(), (value, None)).is_some() {
                    return Err(baseline_mismatch());
                }
            },
            (source, CredentialInjectionTarget::Stdin) => {
                let Some(value) =
                    materialize_non_filesystem_source(plan, source, &prepared_values)?
                else {
                    continue;
                };
                if stdin.replace(value).is_some() {
                    return Err(prepared_material_mismatch());
                }
            },
            (source, CredentialInjectionTarget::ScopedFile { relative_path }) => {
                let Some(value) =
                    materialize_non_filesystem_source(plan, source, &prepared_values)?
                else {
                    continue;
                };
                let session = file_session.as_mut().ok_or_else(unsupported_target)?;
                let file = session
                    .write_file(relative_path, value.as_bytes())
                    .map_err(materialization_filesystem_error)?;
                scoped_files.push(MaterializedScopedFile {
                    relative_path: relative_path.clone(),
                    file,
                });
            },
        }
    }

    if let Some(session) = &file_session {
        sensitive_patterns.push(sensitive_path_value(
            session
                .revalidated_path()
                .map_err(materialization_filesystem_error)?,
        )?);
    }
    for file in &scoped_files {
        sensitive_patterns.push(sensitive_path_value(
            file.file
                .revalidated_path()
                .map_err(materialization_filesystem_error)?,
        )?);
    }

    validate_child_environment_total(&environment)?;

    let redactor = CredentialValueRedactor::new(sensitive_patterns)?;
    let mut materialized = MaterializedCredentialIo {
        plan,
        environment: environment
            .into_iter()
            .map(
                |(name, (value, profile_guard))| MaterializedEnvironmentEntry {
                    name,
                    value,
                    profile_guard,
                },
            )
            .collect(),
        stdin,
        file_session,
        scoped_files,
        environment_profile_guards,
        config_directories,
        redactor,
    };
    materialized.revalidate_filesystem()?;
    let output = consumer(&materialized);
    materialized.revalidate_profiles()?;
    materialized.cleanup_filesystem()?;
    Ok(output)
}

fn materialize_non_filesystem_source(
    plan: &CredentialInjectionPlan,
    source: &CredentialInjectionSource,
    prepared_values: &BTreeMap<CredentialMaterialBindingName, Arc<Zeroizing<Vec<u8>>>>,
) -> Result<Option<MaterializedValue>, CredentialMaterializationError> {
    match source {
        CredentialInjectionSource::PreparedBinding { binding, required } => {
            match prepared_values.get(binding).cloned() {
                Some(value) => Ok(Some(MaterializedValue::Sensitive(value))),
                None if !required => Ok(None),
                None => Err(prepared_material_mismatch()),
            }
        },
        CredentialInjectionSource::ProfileAlias => plan
            .selected_profile()
            .map(|profile| {
                MaterializedValue::Runtime(Zeroizing::new(
                    profile.alias.as_str().as_bytes().to_vec(),
                ))
            })
            .map(Some)
            .ok_or_else(prepared_material_mismatch),
        CredentialInjectionSource::ExpectedIdentity => plan
            .selected_expected_identity()
            .map(|identity| {
                MaterializedValue::Runtime(Zeroizing::new(identity.as_str().as_bytes().to_vec()))
            })
            .map(Some)
            .ok_or_else(prepared_material_mismatch),
        CredentialInjectionSource::ProfileAuthRoot { .. } => Err(unsupported_target()),
    }
}

fn resolve_profile_directory(
    filesystem: &Option<CredentialFilesystemMaterialization<'_>>,
    plan: &CredentialInjectionPlan,
    path: &[ScopedPathComponent],
) -> Result<CredentialProfileDirectory, CredentialMaterializationError> {
    let authority = filesystem.as_ref().ok_or_else(unsupported_target)?;
    let profile_root = authority.profile_root.ok_or_else(scoped_path_unavailable)?;
    let expected_key = plan
        .selected_profile()
        .ok_or_else(scoped_path_unavailable)?;
    let expected_revision = plan
        .selected_profile_revision()
        .ok_or_else(scoped_path_unavailable)?;
    CredentialProfileDirectory::resolve(
        profile_root,
        plan.scope(),
        expected_key,
        expected_revision,
        path,
    )
    .map_err(profile_filesystem_error)
}

fn sensitive_path_value(
    path: &Path,
) -> Result<Arc<Zeroizing<Vec<u8>>>, CredentialMaterializationError> {
    let value = path.to_str().ok_or_else(scoped_path_unavailable)?;
    Ok(Arc::new(Zeroizing::new(value.as_bytes().to_vec())))
}

fn write_minimax_config_json(
    session: &mut CredentialFileSession,
    name: &ScopedPathComponent,
    value: &[u8],
) -> Result<(), CredentialMaterializationError> {
    let config_json =
        CredentialRelativePath::from_string(format!("{}/{}", name.as_str(), MMX_CONFIG_FILE));
    let api_key = std::str::from_utf8(value).map_err(|_| invalid_environment_value())?;
    let mut serialized = to_vec(&json!({
        "api_key": api_key,
        "region": DEFAULT_MMX_REGION,
    }))
    .map_err(|_| filesystem_unavailable())?;
    session
        .write_file(&config_json, &serialized)
        .map_err(materialization_filesystem_error)?;
    serialized.zeroize();
    Ok(())
}

fn validate_environment_value(value: &[u8]) -> Result<(), CredentialMaterializationError> {
    if value.len() > MAX_CHILD_ENVIRONMENT_VALUE_BYTES {
        return Err(environment_value_too_large());
    }
    if value.contains(&0) || std::str::from_utf8(value).is_err() {
        return Err(invalid_environment_value());
    }
    Ok(())
}

fn validate_child_environment_total(
    environment: &BTreeMap<String, (MaterializedValue, Option<usize>)>,
) -> Result<(), CredentialMaterializationError> {
    let mut total = 0usize;
    for (name, (value, _)) in environment {
        total = total
            .checked_add(name.len())
            .and_then(|current| current.checked_add(value.as_bytes().len()))
            .ok_or_else(environment_total_too_large)?;
        if total > MAX_CHILD_ENVIRONMENT_TOTAL_BYTES {
            return Err(environment_total_too_large());
        }
    }
    Ok(())
}

fn append_bounded(
    output: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), CredentialMaterializationError> {
    append_bounded_to(output, bytes, MAX_REDACTION_OUTPUT_BYTES)
}

fn append_bounded_to(
    output: &mut Vec<u8>,
    bytes: &[u8],
    maximum: usize,
) -> Result<(), CredentialMaterializationError> {
    let next = output
        .len()
        .checked_add(bytes.len())
        .ok_or_else(redaction_output_too_large)?;
    if next > maximum {
        return Err(redaction_output_too_large());
    }
    output.extend_from_slice(bytes);
    Ok(())
}

const fn baseline_mismatch() -> CredentialMaterializationError {
    CredentialMaterializationError::new(
        CredentialMaterializationErrorCode::BaselineMismatch,
        "child_environment",
        "runtime environment values belong to a different child-environment baseline",
    )
}

const fn baseline_variable_not_allowed() -> CredentialMaterializationError {
    CredentialMaterializationError::new(
        CredentialMaterializationErrorCode::BaselineVariableNotAllowed,
        "child_environment",
        "the runtime environment variable is outside the finite child baseline",
    )
}

const fn duplicate_baseline_value() -> CredentialMaterializationError {
    CredentialMaterializationError::new(
        CredentialMaterializationErrorCode::DuplicateBaselineValue,
        "child_environment",
        "the runtime provided one child-environment variable more than once",
    )
}

const fn invalid_environment_value() -> CredentialMaterializationError {
    CredentialMaterializationError::new(
        CredentialMaterializationErrorCode::InvalidEnvironmentValue,
        "child_environment",
        "a child-environment value is not portable UTF-8 or contains a nul byte",
    )
}

const fn prepared_material_mismatch() -> CredentialMaterializationError {
    CredentialMaterializationError::new(
        CredentialMaterializationErrorCode::PreparedMaterialMismatch,
        "credential_material",
        "prepared credential material does not exactly match the injection plan",
    )
}

const fn unsupported_target() -> CredentialMaterializationError {
    CredentialMaterializationError::new(
        CredentialMaterializationErrorCode::UnsupportedTarget,
        "credential_target",
        "this materialization slice cannot consume the declared credential target",
    )
}

fn materialization_filesystem_error(
    error: CredentialFilesystemError,
) -> CredentialMaterializationError {
    match error.execution_failure() {
        CredentialExecutionFailure::ScopedPathUnavailable => scoped_path_unavailable(),
        CredentialExecutionFailure::CleanupFailed => cleanup_failed(),
        _ => filesystem_unavailable(),
    }
}

fn profile_filesystem_error(_: CredentialFilesystemError) -> CredentialMaterializationError {
    scoped_path_unavailable()
}

const fn filesystem_unavailable() -> CredentialMaterializationError {
    CredentialMaterializationError::new(
        CredentialMaterializationErrorCode::FilesystemUnavailable,
        "credential_filesystem",
        "credential filesystem materialization failed",
    )
}

const fn scoped_path_unavailable() -> CredentialMaterializationError {
    CredentialMaterializationError::new(
        CredentialMaterializationErrorCode::ScopedPathUnavailable,
        "credential_profile",
        "the selected credential profile path is unavailable or changed",
    )
}

const fn cleanup_failed() -> CredentialMaterializationError {
    CredentialMaterializationError::new(
        CredentialMaterializationErrorCode::CleanupFailed,
        "credential_cleanup",
        "credential filesystem cleanup did not complete",
    )
}

const fn redaction_input_too_large() -> CredentialMaterializationError {
    CredentialMaterializationError::new(
        CredentialMaterializationErrorCode::RedactionInputTooLarge,
        "process_output",
        "the output segment exceeds the bounded credential-redaction input limit",
    )
}

const fn redaction_marker_unavailable() -> CredentialMaterializationError {
    CredentialMaterializationError::new(
        CredentialMaterializationErrorCode::RedactionMarkerUnavailable,
        "credential_material",
        "credential redaction could not allocate a value-safe replacement byte",
    )
}

const fn redaction_output_too_large() -> CredentialMaterializationError {
    CredentialMaterializationError::new(
        CredentialMaterializationErrorCode::RedactionOutputTooLarge,
        "process_output",
        "credential redaction would exceed its bounded output limit",
    )
}

const fn redaction_pattern_limit_exceeded() -> CredentialMaterializationError {
    CredentialMaterializationError::new(
        CredentialMaterializationErrorCode::RedactionPatternLimitExceeded,
        "credential_material",
        "credential redaction patterns exceed their count or aggregate byte limit",
    )
}

const fn redaction_work_limit_exceeded() -> CredentialMaterializationError {
    CredentialMaterializationError::new(
        CredentialMaterializationErrorCode::RedactionWorkLimitExceeded,
        "process_output",
        "credential redaction exceeded its bounded comparison budget",
    )
}

const fn environment_value_too_large() -> CredentialMaterializationError {
    CredentialMaterializationError::new(
        CredentialMaterializationErrorCode::EnvironmentValueTooLarge,
        "child_environment",
        "a child-environment value exceeds its byte limit",
    )
}

const fn environment_total_too_large() -> CredentialMaterializationError {
    CredentialMaterializationError::new(
        CredentialMaterializationErrorCode::EnvironmentTotalTooLarge,
        "child_environment",
        "the child environment exceeds its aggregate byte limit",
    )
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        collections::{BTreeMap, BTreeSet},
        fmt, fs,
        panic::{catch_unwind, AssertUnwindSafe},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        thread,
    };

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use serde::Serialize;
    use static_assertions::assert_not_impl_any;

    use super::*;
    use crate::{
        credential_injection::{CredentialInjectionErrorCode, CredentialInjectionPlan},
        credential_persistence::CredentialPersistenceSurface,
        credential_preparation::{
            with_prepared_credential_material, CredentialMaterialKind, CredentialMaterialResolver,
            CredentialMaterialSink, CredentialPreparationBinding, CredentialPreparationError,
            CredentialPreparationPlan,
        },
        credential_profiles::{
            CredentialProfileAvailability, CredentialProfileBinding, CredentialProfileKey,
            CredentialProfileMetadata, CredentialProfileRegistrySnapshot,
            CredentialProfileRevision, CredentialProfileStatus, CredentialScope,
            ExpectedCredentialIdentity,
        },
        manifest::{
            AuthContract, AuthKind, AuthLifecycle, AuthRequirement, AuthState, AuthStorage,
            CliInteraction, IdentityContract, IdentitySelector, InjectionBinding, InjectionSource,
            InjectionTarget, LifecycleHook, LifecycleJsonPredicate, LifecycleJsonScalar,
            LifecycleObservedAuthState, LifecycleStatusObservation, LifecycleStatusOutputFormat,
            LifecycleStatusRule, PolicyFloor, ProfileSelection, RuntimeLimits, RuntimeProtocol,
            RuntimeRequirements, SecretBindingRef, SkillRuntimeContract,
            SkillRuntimeContractVersion, StdinContract, WorkingDirectoryContract,
        },
        manifest_validation::validate_skill_runtime_contract,
        manifest_validation::MAX_PROFILE_PATH_SEGMENTS,
        profile_selection::{
            select_credential_profile_from_snapshot, CredentialProfileSelectionDecision,
            CredentialProfileSelectionRequest,
        },
        scoped_paths::{ScopedPath, ScopedPathAuthority},
    };

    static NEXT_FILESYSTEM_FIXTURE: AtomicU64 = AtomicU64::new(1);

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
                if let Some(value) = self.values.remove(binding.name().as_str()) {
                    sink.provide(binding.name(), value)?;
                }
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
        fn new() -> Self {
            let sequence = NEXT_FILESYSTEM_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let temp_root = fs::canonicalize(std::env::temp_dir()).expect("canonical temp root");
            let container = temp_root.join(format!(
                "tool-runtime-materialization-{}-{sequence}",
                std::process::id()
            ));
            let scopes_root = container.join("scopes");
            let scope = scope();
            let workspace = scopes_root
                .join(scope.principal.as_str())
                .join(scope.workspace.as_str());
            fs::create_dir_all(workspace.join("auth").join("work").join("cloudsdk"))
                .expect("filesystem fixture");
            set_mode(&container, 0o700);
            set_mode(&scopes_root, 0o755);
            set_mode(&scopes_root.join(scope.principal.as_str()), 0o755);
            set_mode(&workspace, 0o755);
            set_mode(&workspace.join("auth"), 0o700);
            set_mode(&workspace.join("auth").join("work"), 0o700);
            set_mode(&workspace.join("auth").join("work").join("cloudsdk"), 0o700);
            Self {
                container,
                scopes_root,
                scope,
            }
        }

        fn authority(&self) -> ScopedPathAuthority {
            ScopedPathAuthority::open(&self.scopes_root).expect("scoped path authority")
        }

        fn scope_root(&self) -> ScopedPath {
            self.authority()
                .resolve_scope_root(&self.scope)
                .expect("scope root")
        }

        fn profile_root(&self) -> ScopedPath {
            self.authority()
                .resolve_profile_root(
                    &self.profile_key(),
                    ScopedPathComponent::new("work").expect("profile component"),
                )
                .expect("profile root")
        }

        fn profile_key(&self) -> CredentialProfileKey {
            self.profile_key_for("work")
        }

        fn profile_key_for(&self, alias: &str) -> CredentialProfileKey {
            CredentialProfileKey::new(
                self.scope.clone(),
                "provider-cli",
                alias,
                CredentialProfileBinding::Provider,
            )
            .expect("profile key")
        }

        fn profile_status(&self, revision: u64, state: AuthState) -> CredentialProfileStatus {
            self.profile_status_for("work", revision, state)
        }

        fn profile_status_for(
            &self,
            alias: &str,
            revision: u64,
            state: AuthState,
        ) -> CredentialProfileStatus {
            let metadata = CredentialProfileMetadata::new(
                self.profile_key_for(alias),
                None,
                true,
                CredentialProfileAvailability::Enabled,
                CredentialProfileRevision::new(revision).expect("revision"),
            )
            .expect("profile metadata");
            CredentialProfileStatus::new(metadata, state).expect("profile status")
        }

        fn add_profile(&self, alias: &str) -> ScopedPath {
            let path = self
                .scope_root()
                .revalidated_path()
                .expect("scope root")
                .join("auth")
                .join(alias);
            fs::create_dir(&path).expect("profile directory");
            set_mode(&path, 0o700);
            self.authority()
                .resolve_profile_root(
                    &self.profile_key_for(alias),
                    ScopedPathComponent::new(alias).expect("profile component"),
                )
                .expect("profile root")
        }

        fn scratch(&self) -> CredentialScratchAuthority {
            CredentialScratchAuthority::open_or_create(&self.scope_root())
                .expect("scratch authority")
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
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set mode");
    }

    fn call_id(value: &str) -> CredentialCallId {
        CredentialCallId::new(value).expect("call id")
    }

    fn scope() -> CredentialScope {
        CredentialScope::new("owner", "default").expect("scope")
    }

    fn cli_contract(auth: AuthContract) -> SkillRuntimeContract {
        SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires: RuntimeRequirements {
                bins: BTreeSet::from(["fixture-cli".to_owned()]),
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

    fn none_selection(selected_scope: &CredentialScope) -> CredentialProfileSelectionDecision {
        let request = CredentialProfileSelectionRequest::new(
            selected_scope.clone(),
            None,
            CredentialProfileBinding::Provider,
            &ProfileSelection::None,
            None,
        )
        .expect("none request");
        let snapshot = CredentialProfileRegistrySnapshot::new(selected_scope.clone(), Vec::new())
            .expect("empty snapshot");
        select_credential_profile_from_snapshot(&request, &snapshot).expect("none selection")
    }

    fn selected_profile(
        selected_scope: &CredentialScope,
        expected_identity: Option<&str>,
    ) -> CredentialProfileSelectionDecision {
        let key = CredentialProfileKey::new(
            selected_scope.clone(),
            "provider-cli",
            "work",
            CredentialProfileBinding::Provider,
        )
        .expect("profile key");
        let metadata = CredentialProfileMetadata::new(
            key,
            expected_identity
                .map(|value| ExpectedCredentialIdentity::new(value).expect("expected identity")),
            true,
            CredentialProfileAvailability::Enabled,
            CredentialProfileRevision::new(1).expect("revision"),
        )
        .expect("metadata");
        let status = CredentialProfileStatus::new(metadata, AuthState::Ready).expect("status");
        let snapshot = CredentialProfileRegistrySnapshot::new(selected_scope.clone(), vec![status])
            .expect("snapshot");
        let request = CredentialProfileSelectionRequest::new(
            selected_scope.clone(),
            Some("provider-cli"),
            CredentialProfileBinding::Provider,
            &ProfileSelection::Fixed {
                alias: "work".to_owned(),
            },
            None,
        )
        .expect("fixed request");
        select_credential_profile_from_snapshot(&request, &snapshot).expect("fixed selection")
    }

    fn preparation_binding(name: &str) -> CredentialPreparationBinding {
        CredentialPreparationBinding::new(
            CredentialMaterialBindingName::new(name).expect("binding name"),
            CredentialMaterialKind::SecretBinding,
            1024,
        )
        .expect("preparation binding")
    }

    fn environment_stdin_contract() -> SkillRuntimeContract {
        cli_contract(AuthContract {
            kind: AuthKind::Secrets,
            requirement: AuthRequirement::Required,
            secret_bindings: vec![
                SecretBindingRef {
                    name: "api_key".to_owned(),
                    secret_ref: "VAULT_API_KEY".to_owned(),
                },
                SecretBindingRef {
                    name: "password".to_owned(),
                    secret_ref: "VAULT_PASSWORD".to_owned(),
                },
            ],
            injections: vec![
                InjectionBinding {
                    source: InjectionSource::Secret {
                        binding: "api_key".to_owned(),
                    },
                    target: InjectionTarget::Environment {
                        name: "PROVIDER_API_KEY".to_owned(),
                    },
                },
                InjectionBinding {
                    source: InjectionSource::Secret {
                        binding: "password".to_owned(),
                    },
                    target: InjectionTarget::Stdin,
                },
            ],
            ..AuthContract::default()
        })
    }

    fn environment_stdin_plan(
        selected_scope: &CredentialScope,
    ) -> (SkillRuntimeContract, CredentialPreparationPlan) {
        let contract = environment_stdin_contract();
        let plan = CredentialPreparationPlan::new(
            selected_scope.clone(),
            AuthKind::Secrets,
            &none_selection(selected_scope),
            vec![
                preparation_binding("password"),
                preparation_binding("api_key"),
            ],
        )
        .expect("preparation plan");
        (contract, plan)
    }

    fn scoped_file_plan(
        selected_scope: &CredentialScope,
    ) -> (SkillRuntimeContract, CredentialPreparationPlan) {
        let contract = cli_contract(AuthContract {
            kind: AuthKind::Secrets,
            requirement: AuthRequirement::Required,
            secret_bindings: vec![SecretBindingRef {
                name: "token".to_owned(),
                secret_ref: "VAULT_TOKEN".to_owned(),
            }],
            injections: vec![InjectionBinding {
                source: InjectionSource::Secret {
                    binding: "token".to_owned(),
                },
                target: InjectionTarget::ScopedFile {
                    relative_path: "provider/token.txt".to_owned(),
                },
            }],
            ..AuthContract::default()
        });
        let preparation = CredentialPreparationPlan::new(
            selected_scope.clone(),
            AuthKind::Secrets,
            &none_selection(selected_scope),
            vec![preparation_binding("token")],
        )
        .expect("file preparation");
        (contract, preparation)
    }

    fn profile_filesystem_plan(
        selected_scope: &CredentialScope,
    ) -> (SkillRuntimeContract, CredentialPreparationPlan) {
        let contract = cli_contract(AuthContract {
            kind: AuthKind::CliProfile,
            requirement: AuthRequirement::Required,
            provider: Some("provider-cli".to_owned()),
            profile_selection: ProfileSelection::Fixed {
                alias: "work".to_owned(),
            },
            storage: AuthStorage::CliOwned,
            injections: vec![
                InjectionBinding {
                    source: InjectionSource::ProfileAuthRoot { path: Vec::new() },
                    target: InjectionTarget::Environment {
                        name: "PROFILE_HOME".to_owned(),
                    },
                },
                InjectionBinding {
                    source: InjectionSource::ProfileAuthRoot {
                        path: vec!["cloudsdk".to_owned()],
                    },
                    target: InjectionTarget::ConfigDirectory {
                        name: "gcloud_config".to_owned(),
                    },
                },
            ],
            ..AuthContract::default()
        });
        let preparation = CredentialPreparationPlan::new(
            selected_scope.clone(),
            AuthKind::CliProfile,
            &selected_profile(selected_scope, None),
            Vec::new(),
        )
        .expect("profile filesystem preparation");
        (contract, preparation)
    }

    fn config_directory_plan(
        selected_scope: &CredentialScope,
        variable_name: &str,
    ) -> (SkillRuntimeContract, CredentialPreparationPlan) {
        let contract = cli_contract(AuthContract {
            kind: AuthKind::Secrets,
            requirement: AuthRequirement::Required,
            provider: Some(MINIMAX_PROVIDER.to_owned()),
            secret_bindings: vec![SecretBindingRef {
                name: variable_name.to_owned(),
                secret_ref: format!("VAULT_{variable_name}"),
            }],
            injections: vec![InjectionBinding {
                source: InjectionSource::Secret {
                    binding: variable_name.to_owned(),
                },
                target: InjectionTarget::ConfigDirectory {
                    name: "MMX_CONFIG_DIR".to_owned(),
                },
            }],
            ..AuthContract::default()
        });
        let preparation = CredentialPreparationPlan::new(
            selected_scope.clone(),
            AuthKind::Secrets,
            &none_selection(selected_scope),
            vec![preparation_binding(variable_name)],
        )
        .expect("config directory preparation");
        (contract, preparation)
    }

    #[test]
    fn clean_environment_and_stdin_exist_only_inside_the_sealed_call() {
        let selected_scope = scope();
        let (contract, preparation) = environment_stdin_plan(&selected_scope);
        let baseline = ChildEnvironmentBaseline::portable_cli();
        let injection = CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract).expect("validated contract"),
            &preparation,
            baseline.clone(),
        )
        .expect("injection plan");
        let mut baseline_values = ChildEnvironmentValues::new(&baseline);
        baseline_values
            .provide(ChildEnvironmentVariable::Path, b"/usr/bin".to_vec())
            .expect("path");
        let mut resolver = MapResolver {
            values: BTreeMap::from([
                ("api_key".to_owned(), b"api-key-canary".to_vec()),
                ("password".to_owned(), b"password-canary".to_vec()),
            ]),
        };

        let result = with_prepared_credential_material(&preparation, &mut resolver, |prepared| {
            materialize_environment_and_stdin(
                &injection,
                prepared,
                baseline_values,
                |materialized| {
                    assert_eq!(materialized.environment_len(), 2);
                    assert_eq!(
                        materialized.environment_entry(0).expect("PATH entry"),
                        Some(("PATH", b"/usr/bin".as_slice()))
                    );
                    assert_eq!(
                        materialized.environment_entry(1).expect("credential entry"),
                        Some(("PROVIDER_API_KEY", b"api-key-canary".as_slice()))
                    );
                    assert_eq!(materialized.stdin(), Some(b"password-canary".as_slice()));

                    let output = materialized
                        .redact_output(b"bad=api-key-canary pass=password-canary trailing=\xff")
                        .expect("redacted output");
                    assert_eq!(output.as_bytes(), b"bad=* pass=* trailing=\xff");
                    assert!(!format!("{output:?}").contains("api-key-canary"));
                },
            )
        })
        .expect("resolved material");
        result.expect("materialized call");
    }

    #[test]
    fn every_dynamic_persistence_surface_is_redacted_inside_the_sealed_call() {
        let selected_scope = scope();
        let (contract, preparation) = environment_stdin_plan(&selected_scope);
        let baseline = ChildEnvironmentBaseline::portable_cli();
        let injection = CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract).expect("validated contract"),
            &preparation,
            baseline.clone(),
        )
        .expect("injection plan");
        let mut resolver = MapResolver {
            values: BTreeMap::from([
                ("api_key".to_owned(), b"api-key-canary".to_vec()),
                ("password".to_owned(), b"password-canary".to_vec()),
            ]),
        };

        let batch = with_prepared_credential_material(&preparation, &mut resolver, |prepared| {
            materialize_environment_and_stdin(
                &injection,
                prepared,
                ChildEnvironmentValues::new(&baseline),
                |materialized| {
                    let output = b"api-key-canary password-canary";
                    let drafts = [
                        CredentialPersistenceDraft::new(
                            CredentialPersistenceSurface::ProcessDiagnostic,
                            output,
                        ),
                        CredentialPersistenceDraft::new(
                            CredentialPersistenceSurface::ToolOutput,
                            output,
                        ),
                        CredentialPersistenceDraft::new(
                            CredentialPersistenceSurface::ToolError,
                            output,
                        ),
                        CredentialPersistenceDraft::new(
                            CredentialPersistenceSurface::Artifact,
                            output,
                        ),
                        CredentialPersistenceDraft::new(CredentialPersistenceSurface::Log, output),
                        CredentialPersistenceDraft::new(
                            CredentialPersistenceSurface::Trace,
                            output,
                        ),
                        CredentialPersistenceDraft::new(
                            CredentialPersistenceSurface::Analytics,
                            output,
                        ),
                    ];
                    materialized.seal_persistence(
                        call_id("call-persistence"),
                        crate::credential_injection::CredentialExecutionOutcome::Succeeded,
                        &drafts,
                    )
                },
            )
        })
        .expect("resolved material")
        .expect("materialized call")
        .expect("sealed persistence");

        assert_eq!(batch.records().len(), 7);
        assert_eq!(
            batch.total_bytes(),
            output_len_for_persistence_fixture() * 7
        );
        assert_eq!(batch.receipt().call_id().as_str(), "call-persistence");
        assert_eq!(batch.receipt().scope(), injection.scope());
        assert_eq!(batch.receipt().auth_kind(), injection.auth_kind());
        assert_eq!(
            batch.receipt().injection_count(),
            injection.injections().len()
        );
        for record in batch.records() {
            assert_eq!(record.bytes().len(), output_len_for_persistence_fixture());
            assert!(!record
                .bytes()
                .windows(b"api-key-canary".len())
                .any(|window| window == b"api-key-canary"));
            assert!(!record
                .bytes()
                .windows(b"password-canary".len())
                .any(|window| window == b"password-canary"));
        }
        let debug = format!("{batch:?}");
        assert!(!debug.contains("api-key-canary") && !debug.contains("password-canary"));
    }

    fn output_len_for_persistence_fixture() -> usize {
        b"api-key-canary password-canary".len()
    }

    #[test]
    fn baseline_is_exact_finite_and_cannot_admit_an_arbitrary_parent_variable() {
        assert_not_impl_any!(ChildEnvironmentValues: Clone, fmt::Debug, Serialize);
        assert_not_impl_any!(MaterializedCredentialIo: Clone, fmt::Debug, Serialize);

        let hermetic = ChildEnvironmentBaseline::hermetic();
        let mut values = ChildEnvironmentValues::new(&hermetic);
        assert_eq!(
            values
                .provide(ChildEnvironmentVariable::Path, b"/usr/bin".to_vec())
                .expect_err("PATH outside hermetic baseline")
                .code,
            CredentialMaterializationErrorCode::BaselineVariableNotAllowed
        );

        let portable = ChildEnvironmentBaseline::portable_cli();
        let mut values = ChildEnvironmentValues::new(&portable);
        values
            .provide(ChildEnvironmentVariable::Lang, b"en_US.UTF-8".to_vec())
            .expect("LANG");
        assert_eq!(
            values
                .provide(ChildEnvironmentVariable::Lang, b"C".to_vec())
                .expect_err("duplicate LANG")
                .code,
            CredentialMaterializationErrorCode::DuplicateBaselineValue
        );
        assert_eq!(values.len(), 1);

        let cli_owned = ChildEnvironmentBaseline::cli_owned_session();
        assert!(cli_owned
            .variables()
            .contains(&ChildEnvironmentVariable::Home));
        assert!(!portable
            .variables()
            .contains(&ChildEnvironmentVariable::Home));
    }

    #[test]
    fn child_environment_values_enforce_per_value_and_aggregate_byte_limits() {
        let baseline = ChildEnvironmentBaseline::portable_cli();
        let mut oversized = ChildEnvironmentValues::new(&baseline);
        assert_eq!(
            oversized
                .provide(
                    ChildEnvironmentVariable::Path,
                    vec![b'x'; MAX_CHILD_ENVIRONMENT_VALUE_BYTES + 1],
                )
                .unwrap_err()
                .code,
            CredentialMaterializationErrorCode::EnvironmentValueTooLarge
        );

        let mut aggregate = ChildEnvironmentValues::new(&baseline);
        for variable in [
            ChildEnvironmentVariable::Path,
            ChildEnvironmentVariable::Lang,
            ChildEnvironmentVariable::LcAll,
            ChildEnvironmentVariable::LcCtype,
        ] {
            aggregate
                .provide(variable, vec![b'x'; MAX_CHILD_ENVIRONMENT_VALUE_BYTES - 32])
                .expect("aggregate remains within limit");
        }
        assert_eq!(
            aggregate
                .provide(
                    ChildEnvironmentVariable::Term,
                    vec![b'x'; MAX_CHILD_ENVIRONMENT_VALUE_BYTES],
                )
                .unwrap_err()
                .code,
            CredentialMaterializationErrorCode::EnvironmentTotalTooLarge
        );
    }

    #[test]
    fn non_utf8_and_nul_environment_secrets_fail_without_echoing_values() {
        let selected_scope = scope();
        let mut contract = environment_stdin_contract();
        contract.auth.secret_bindings.remove(1);
        contract.auth.injections.remove(1);
        let preparation = CredentialPreparationPlan::new(
            selected_scope.clone(),
            AuthKind::Secrets,
            &none_selection(&selected_scope),
            vec![preparation_binding("api_key")],
        )
        .expect("preparation");
        let baseline = ChildEnvironmentBaseline::hermetic();
        let injection = CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract).expect("validated contract"),
            &preparation,
            baseline.clone(),
        )
        .expect("injection");

        for value in [vec![0xff, b'x'], b"nul\0canary".to_vec()] {
            let mut resolver = MapResolver {
                values: BTreeMap::from([("api_key".to_owned(), value.clone())]),
            };
            let error =
                with_prepared_credential_material(&preparation, &mut resolver, |prepared| {
                    materialize_environment_and_stdin(
                        &injection,
                        prepared,
                        ChildEnvironmentValues::new(&baseline),
                        |_| (),
                    )
                })
                .expect("resolution")
                .expect_err("invalid environment value");
            assert_eq!(
                error.code,
                CredentialMaterializationErrorCode::InvalidEnvironmentValue
            );
            assert!(!format!("{error:?} {error}").contains("canary"));
        }
    }

    #[test]
    fn selected_alias_and_expected_identity_are_carried_from_the_opaque_proof() {
        let selected_scope = scope();
        let mut contract = cli_contract(AuthContract {
            kind: AuthKind::CliProfile,
            requirement: AuthRequirement::Required,
            provider: Some("provider-cli".to_owned()),
            profile_selection: ProfileSelection::Fixed {
                alias: "work".to_owned(),
            },
            storage: AuthStorage::CliOwned,
            lifecycle: AuthLifecycle {
                status: Some(LifecycleHook {
                    args: vec!["auth".to_owned(), "status".to_owned(), "--json".to_owned()],
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
                ..AuthLifecycle::default()
            },
            identity: IdentityContract::ProfileExpected {
                selector: IdentitySelector::JsonPointer {
                    pointer: "/account/email".to_owned(),
                },
            },
            injections: vec![
                InjectionBinding {
                    source: InjectionSource::ProfileAlias,
                    target: InjectionTarget::Environment {
                        name: "PROFILE_ALIAS".to_owned(),
                    },
                },
                InjectionBinding {
                    source: InjectionSource::ExpectedIdentity,
                    target: InjectionTarget::Environment {
                        name: "EXPECTED_IDENTITY".to_owned(),
                    },
                },
            ],
            ..AuthContract::default()
        });
        let selection = selected_profile(&selected_scope, Some("work@example.com"));
        let preparation = CredentialPreparationPlan::new(
            selected_scope.clone(),
            AuthKind::CliProfile,
            &selection,
            Vec::new(),
        )
        .expect("profile preparation");
        assert_eq!(
            preparation
                .selected_expected_identity()
                .expect("expected identity")
                .as_str(),
            "work@example.com"
        );
        let baseline = ChildEnvironmentBaseline::hermetic();
        let injection = CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract).expect("validated profile contract"),
            &preparation,
            baseline.clone(),
        )
        .expect("profile injection");
        let mut resolver = MapResolver {
            values: BTreeMap::new(),
        };
        with_prepared_credential_material(&preparation, &mut resolver, |prepared| {
            materialize_environment_and_stdin(
                &injection,
                prepared,
                ChildEnvironmentValues::new(&baseline),
                |materialized| {
                    assert_eq!(
                        materialized.environment_entry(0).expect("identity entry"),
                        Some(("EXPECTED_IDENTITY", b"work@example.com".as_slice()))
                    );
                    assert_eq!(
                        materialized.environment_entry(1).expect("alias entry"),
                        Some(("PROFILE_ALIAS", b"work".as_slice()))
                    );
                },
            )
            .expect("profile materialization")
        })
        .expect("empty preparation");

        let missing_identity = selected_profile(&selected_scope, None);
        let missing_preparation = CredentialPreparationPlan::new(
            selected_scope,
            AuthKind::CliProfile,
            &missing_identity,
            Vec::new(),
        )
        .expect("profile preparation without expected identity");
        assert_eq!(
            CredentialInjectionPlan::compile(
                validate_skill_runtime_contract(&contract).expect("validated profile contract"),
                &missing_preparation,
                ChildEnvironmentBaseline::hermetic(),
            )
            .expect_err("expected identity is required")
            .code,
            CredentialInjectionErrorCode::PlanMismatch
        );

        contract.auth.injections.pop();
        CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract).expect("alias-only contract"),
            &missing_preparation,
            ChildEnvironmentBaseline::hermetic(),
        )
        .expect("alias does not require expected identity");
    }

    #[test]
    fn file_targets_fail_closed_until_the_scoped_cleanup_owner_exists() {
        let selected_scope = scope();
        let (mut contract, preparation) = environment_stdin_plan(&selected_scope);
        contract.auth.injections.push(InjectionBinding {
            source: InjectionSource::Secret {
                binding: "api_key".to_owned(),
            },
            target: InjectionTarget::ScopedFile {
                relative_path: "provider/token".to_owned(),
            },
        });
        let baseline = ChildEnvironmentBaseline::hermetic();
        let injection = CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract).expect("validated file contract"),
            &preparation,
            baseline.clone(),
        )
        .expect("file injection plan");
        let mut resolver = MapResolver {
            values: BTreeMap::from([
                ("api_key".to_owned(), b"api-key-canary".to_vec()),
                ("password".to_owned(), b"password-canary".to_vec()),
            ]),
        };
        let error = with_prepared_credential_material(&preparation, &mut resolver, |prepared| {
            materialize_environment_and_stdin(
                &injection,
                prepared,
                ChildEnvironmentValues::new(&baseline),
                |_| (),
            )
        })
        .expect("resolution")
        .expect_err("file target cannot be partially materialized");
        assert_eq!(
            error.code,
            CredentialMaterializationErrorCode::UnsupportedTarget
        );
        assert_eq!(
            error.execution_failure(),
            CredentialExecutionFailure::MaterializationFailed
        );
    }

    #[cfg(unix)]
    #[test]
    fn scoped_secret_files_are_private_redacted_and_cleaned_before_return() {
        assert_not_impl_any!(
            CredentialFilesystemMaterialization<'static>: Clone,
            fmt::Debug,
            Serialize
        );
        assert_not_impl_any!(MaterializedScopedFile: Clone, fmt::Debug, Serialize);
        assert_not_impl_any!(MaterializedConfigDirectory: Clone, fmt::Debug, Serialize);

        let fixture = FilesystemFixture::new();
        let (contract, preparation) = scoped_file_plan(&fixture.scope);
        let baseline = ChildEnvironmentBaseline::hermetic();
        let plan = CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract).expect("file contract"),
            &preparation,
            baseline.clone(),
        )
        .expect("file plan");
        let scratch = fixture.scratch();
        let id = call_id("exec_materialized_file");
        let observed_root = RefCell::new(None::<PathBuf>);
        let observed_file = RefCell::new(None::<PathBuf>);
        let mut resolver = MapResolver {
            values: BTreeMap::from([("token".to_owned(), b"file-secret-canary".to_vec())]),
        };

        with_prepared_credential_material(&preparation, &mut resolver, |prepared| {
            materialize_credential_io(
                &plan,
                prepared,
                ChildEnvironmentValues::new(&baseline),
                CredentialFilesystemMaterialization::new(&id, &scratch, None),
                |materialized| {
                    assert_eq!(materialized.scoped_file_len(), 1);
                    assert_eq!(materialized.config_directory_len(), 0);
                    let root = materialized
                        .scoped_file_root()
                        .expect("root revalidation")
                        .expect("file root");
                    let (relative, path) = materialized
                        .scoped_file(0)
                        .expect("file revalidation")
                        .expect("file");
                    assert_eq!(relative, "provider/token.txt");
                    assert!(path.starts_with(root));
                    assert_eq!(
                        fs::read(path).expect("materialized secret"),
                        b"file-secret-canary"
                    );
                    assert_eq!(
                        fs::metadata(root)
                            .expect("root metadata")
                            .permissions()
                            .mode()
                            & 0o7777,
                        0o700
                    );
                    assert_eq!(
                        fs::metadata(path)
                            .expect("file metadata")
                            .permissions()
                            .mode()
                            & 0o7777,
                        0o600
                    );

                    let output = format!(
                        "secret=file-secret-canary root={} file={}",
                        root.display(),
                        path.display()
                    );
                    let redacted = materialized
                        .redact_output(output.as_bytes())
                        .expect("path-aware redaction");
                    let rendered = String::from_utf8(redacted.into_bytes()).expect("utf8 output");
                    assert!(!rendered.contains("file-secret-canary"));
                    assert!(!rendered.contains(fixture.container.to_string_lossy().as_ref()));
                    observed_root.replace(Some(root.to_path_buf()));
                    observed_file.replace(Some(path.to_path_buf()));
                },
            )
        })
        .expect("file resolution")
        .expect("file materialization");

        assert!(!observed_root
            .borrow()
            .as_ref()
            .expect("observed root")
            .exists());
        assert!(!observed_file
            .borrow()
            .as_ref()
            .expect("observed file")
            .exists());
    }

    #[cfg(unix)]
    #[test]
    fn maximum_valid_scoped_file_depth_materializes_and_cleans() {
        let fixture = FilesystemFixture::new();
        let (mut contract, preparation) = scoped_file_plan(&fixture.scope);
        let relative_path = (0..MAX_PROFILE_PATH_SEGMENTS)
            .map(|index| format!("segment-{index:02}"))
            .collect::<Vec<_>>()
            .join("/");
        contract.auth.injections[0].target = InjectionTarget::ScopedFile {
            relative_path: relative_path.clone(),
        };
        let baseline = ChildEnvironmentBaseline::hermetic();
        let plan = CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract).expect("maximum-depth contract"),
            &preparation,
            baseline.clone(),
        )
        .expect("maximum-depth plan");
        let scratch = fixture.scratch();
        let id = call_id("exec_maximum_file_depth");
        let mut resolver = MapResolver {
            values: BTreeMap::from([("token".to_owned(), b"maximum-depth-canary".to_vec())]),
        };

        with_prepared_credential_material(&preparation, &mut resolver, |prepared| {
            materialize_credential_io(
                &plan,
                prepared,
                ChildEnvironmentValues::new(&baseline),
                CredentialFilesystemMaterialization::new(&id, &scratch, None),
                |materialized| {
                    let (relative, path) = materialized
                        .scoped_file(0)
                        .expect("file revalidation")
                        .expect("maximum-depth file");
                    assert_eq!(relative, relative_path);
                    assert_eq!(
                        fs::read(path).expect("secret file"),
                        b"maximum-depth-canary"
                    );
                },
            )
        })
        .expect("file resolution")
        .expect("maximum-depth materialization");
        assert_eq!(
            scratch
                .recover_stale_sessions()
                .expect("empty recovery")
                .recovered_sessions,
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn profile_paths_are_revalidated_named_and_redacted_without_copying_profiles() {
        let fixture = FilesystemFixture::new();
        let (contract, preparation) = profile_filesystem_plan(&fixture.scope);
        let baseline = ChildEnvironmentBaseline::hermetic();
        let plan = CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract).expect("profile contract"),
            &preparation,
            baseline.clone(),
        )
        .expect("profile plan");
        let scratch = fixture.scratch();
        let profile_root = fixture.profile_root();
        let profile_authority = profile_root
            .authorize_ready_profile(&fixture.profile_status(1, AuthState::Ready))
            .expect("ready profile authority");
        let id = call_id("exec_materialized_profile");
        let mut resolver = MapResolver {
            values: BTreeMap::new(),
        };

        with_prepared_credential_material(&preparation, &mut resolver, |prepared| {
            materialize_credential_io(
                &plan,
                prepared,
                ChildEnvironmentValues::new(&baseline),
                CredentialFilesystemMaterialization::new(&id, &scratch, Some(&profile_authority)),
                |materialized| {
                    assert_eq!(materialized.environment_len(), 1);
                    assert_eq!(materialized.scoped_file_len(), 0);
                    assert_eq!(materialized.config_directory_len(), 1);
                    let (_, environment_path) = materialized
                        .environment_entry(0)
                        .expect("profile environment revalidation")
                        .expect("profile environment");
                    let environment_path =
                        std::str::from_utf8(environment_path).expect("profile path utf8");
                    let (name, config_path) = materialized
                        .config_directory(0)
                        .expect("config revalidation")
                        .expect("config directory");
                    assert_eq!(name, "gcloud_config");
                    assert_eq!(
                        Path::new(environment_path),
                        profile_root.revalidated_path().unwrap()
                    );
                    assert_eq!(
                        config_path,
                        profile_root
                            .revalidated_path()
                            .unwrap()
                            .join("cloudsdk")
                            .as_path()
                    );

                    let output =
                        format!("home={environment_path} config={}", config_path.display());
                    let redacted = materialized
                        .redact_output(output.as_bytes())
                        .expect("profile path redaction");
                    let rendered = String::from_utf8(redacted.into_bytes()).expect("utf8 output");
                    assert!(!rendered.contains(fixture.container.to_string_lossy().as_ref()));
                },
            )
        })
        .expect("profile resolution")
        .expect("profile materialization");

        assert!(profile_root
            .revalidated_path()
            .expect("profile retained")
            .is_dir());
        assert!(profile_root
            .revalidated_path()
            .expect("profile retained")
            .join("cloudsdk")
            .is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn prep_secret_config_directories_write_mmx_config_json_and_clean_before_return() {
        let fixture = FilesystemFixture::new();
        let (contract, preparation) = config_directory_plan(&fixture.scope, "api_key");
        let baseline = ChildEnvironmentBaseline::hermetic();
        let plan = CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract).expect("config directory contract"),
            &preparation,
            baseline.clone(),
        )
        .expect("config directory plan");
        let scratch = fixture.scratch();
        let id = call_id("exec_materialized_config_directory");
        let observed_root = RefCell::new(None::<PathBuf>);
        let observed_config = RefCell::new(None::<PathBuf>);
        let mut resolver = MapResolver {
            values: BTreeMap::from([("api_key".to_owned(), b"mmx-secret-canary".to_vec())]),
        };

        with_prepared_credential_material(&preparation, &mut resolver, |prepared| {
            materialize_credential_io(
                &plan,
                prepared,
                ChildEnvironmentValues::new(&baseline),
                CredentialFilesystemMaterialization::new(&id, &scratch, None),
                |materialized| {
                    assert_eq!(materialized.environment_len(), 1);
                    assert_eq!(materialized.scoped_file_len(), 0);
                    assert_eq!(materialized.config_directory_len(), 1);
                    let (_, config_directory) = materialized
                        .config_directory(0)
                        .expect("config directory revalidation")
                        .expect("config directory");
                    let config_json = config_directory.join("config.json");
                    let config_path =
                        fs::read_to_string(&config_json).expect("materialized mmx config");
                    let parsed: serde_json::Value =
                        serde_json::from_str(&config_path).expect("json config payload");
                    assert_eq!(parsed["api_key"], "mmx-secret-canary");
                    assert_eq!(parsed["region"], DEFAULT_MMX_REGION);
                    let (env_name, env_value) = materialized
                        .environment_entry(0)
                        .expect("environment entry")
                        .expect("directory env");
                    assert_eq!(env_name, "MMX_CONFIG_DIR");
                    assert_eq!(
                        env_value,
                        config_directory.to_string_lossy().as_bytes().as_ref()
                    );
                    assert_eq!(
                        fs::metadata(
                            materialized
                                .scoped_file_root()
                                .expect("file session root")
                                .expect("session"),
                        )
                        .expect("root metadata")
                        .permissions()
                        .mode()
                            & 0o7777,
                        0o700
                    );
                    assert_eq!(
                        fs::metadata(&config_json)
                            .expect("config metadata")
                            .permissions()
                            .mode()
                            & 0o7777,
                        0o600
                    );

                    let output = format!(
                        "mmx-config-dir={}; path={}",
                        config_directory.display(),
                        config_json.display()
                    );
                    let redacted = materialized
                        .redact_output(output.as_bytes())
                        .expect("config-path redaction");
                    let rendered = String::from_utf8(redacted.into_bytes()).expect("utf8 output");
                    assert!(!rendered.contains("mmx-secret-canary"));
                    assert!(
                        !rendered.contains(fixture.container.to_string_lossy().as_ref()),
                        "container path was not redacted"
                    );

                    observed_root.replace(Some(
                        materialized
                            .scoped_file_root()
                            .unwrap()
                            .expect("root")
                            .to_path_buf(),
                    ));
                    observed_config.replace(Some(config_json));
                },
            )
        })
        .expect("config resolution")
        .expect("config materialization");

        assert!(!observed_root
            .borrow()
            .as_ref()
            .expect("observed root")
            .exists());
        assert!(!observed_config
            .borrow()
            .as_ref()
            .expect("observed config")
            .exists());
    }

    #[cfg(unix)]
    #[test]
    fn missing_or_changed_profile_authority_fails_before_or_during_the_call() {
        let fixture = FilesystemFixture::new();
        let (contract, preparation) = profile_filesystem_plan(&fixture.scope);
        let baseline = ChildEnvironmentBaseline::hermetic();
        let plan = CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract).expect("profile contract"),
            &preparation,
            baseline.clone(),
        )
        .expect("profile plan");
        let scratch = fixture.scratch();
        let id = call_id("exec_missing_profile");
        let called = Cell::new(false);
        let mut resolver = MapResolver {
            values: BTreeMap::new(),
        };
        let error = with_prepared_credential_material(&preparation, &mut resolver, |prepared| {
            materialize_credential_io(
                &plan,
                prepared,
                ChildEnvironmentValues::new(&baseline),
                CredentialFilesystemMaterialization::new(&id, &scratch, None),
                |_| called.set(true),
            )
        })
        .expect("profile resolution")
        .expect_err("missing profile root");
        assert!(!called.get());
        assert_eq!(
            error.code,
            CredentialMaterializationErrorCode::ScopedPathUnavailable
        );

        let profile_root = fixture.profile_root();
        let config_path = profile_root
            .revalidated_path()
            .expect("profile path")
            .join("cloudsdk");
        let profile_authority = profile_root
            .authorize_ready_profile(&fixture.profile_status(1, AuthState::Ready))
            .expect("ready profile authority");
        let id = call_id("exec_changed_profile");
        let mut resolver = MapResolver {
            values: BTreeMap::new(),
        };
        let error = with_prepared_credential_material(&preparation, &mut resolver, |prepared| {
            materialize_credential_io(
                &plan,
                prepared,
                ChildEnvironmentValues::new(&baseline),
                CredentialFilesystemMaterialization::new(&id, &scratch, Some(&profile_authority)),
                |_| set_mode(&config_path, 0o755),
            )
        })
        .expect("profile resolution")
        .expect_err("changed profile directory");
        assert_eq!(
            error.code,
            CredentialMaterializationErrorCode::ScopedPathUnavailable
        );
        assert!(!format!("{error:?} {error}").contains(config_path.to_string_lossy().as_ref()));
        set_mode(&config_path, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn profile_materialization_rejects_stale_not_ready_and_same_scope_cross_profile_authority() {
        let fixture = FilesystemFixture::new();
        let (contract, preparation) = profile_filesystem_plan(&fixture.scope);
        let baseline = ChildEnvironmentBaseline::hermetic();
        let plan = CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract).expect("profile contract"),
            &preparation,
            baseline.clone(),
        )
        .expect("profile plan");
        assert_eq!(
            plan.selected_profile_revision(),
            Some(CredentialProfileRevision::new(1).unwrap())
        );
        let scratch = fixture.scratch();
        let id = call_id("exec_profile_authority_binding");

        let work = fixture.profile_root();
        assert_eq!(
            work.authorize_ready_profile(&fixture.profile_status(1, AuthState::Missing))
                .expect_err("not-ready authority")
                .code,
            crate::scoped_paths::ScopedPathErrorCode::ProfileNotReady
        );

        let stale = work
            .authorize_ready_profile(&fixture.profile_status(2, AuthState::Ready))
            .expect("fresh but different revision authority");
        let mut resolver = MapResolver {
            values: BTreeMap::new(),
        };
        let called = Cell::new(false);
        let error = with_prepared_credential_material(&preparation, &mut resolver, |prepared| {
            materialize_credential_io(
                &plan,
                prepared,
                ChildEnvironmentValues::new(&baseline),
                CredentialFilesystemMaterialization::new(&id, &scratch, Some(&stale)),
                |_| called.set(true),
            )
        })
        .unwrap()
        .unwrap_err();
        assert_eq!(
            error.code,
            CredentialMaterializationErrorCode::ScopedPathUnavailable
        );
        assert!(!called.get());

        let personal = fixture.add_profile("personal");
        let personal_authority = personal
            .authorize_ready_profile(&fixture.profile_status_for("personal", 1, AuthState::Ready))
            .expect("personal authority");
        let mut resolver = MapResolver {
            values: BTreeMap::new(),
        };
        let called = Cell::new(false);
        let error = with_prepared_credential_material(&preparation, &mut resolver, |prepared| {
            materialize_credential_io(
                &plan,
                prepared,
                ChildEnvironmentValues::new(&baseline),
                CredentialFilesystemMaterialization::new(&id, &scratch, Some(&personal_authority)),
                |_| called.set(true),
            )
        })
        .unwrap()
        .unwrap_err();
        assert_eq!(
            error.code,
            CredentialMaterializationErrorCode::ScopedPathUnavailable
        );
        assert!(!called.get());
    }

    #[cfg(unix)]
    #[test]
    fn explicit_cleanup_failure_is_typed_and_bootstrap_recoverable() {
        let fixture = FilesystemFixture::new();
        let (contract, preparation) = scoped_file_plan(&fixture.scope);
        let baseline = ChildEnvironmentBaseline::hermetic();
        let plan = CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract).expect("file contract"),
            &preparation,
            baseline.clone(),
        )
        .expect("file plan");
        let scratch = fixture.scratch();
        let id = call_id("exec_cleanup_failure");
        let observed_root = RefCell::new(None::<PathBuf>);
        let mut resolver = MapResolver {
            values: BTreeMap::from([("token".to_owned(), b"cleanup-canary".to_vec())]),
        };
        let error = with_prepared_credential_material(&preparation, &mut resolver, |prepared| {
            materialize_credential_io(
                &plan,
                prepared,
                ChildEnvironmentValues::new(&baseline),
                CredentialFilesystemMaterialization::new(&id, &scratch, None),
                |materialized| {
                    let root = materialized
                        .scoped_file_root()
                        .expect("root revalidation")
                        .expect("root")
                        .to_path_buf();
                    observed_root.replace(Some(root.clone()));
                    set_mode(&root, 0o755);
                },
            )
        })
        .expect("file resolution")
        .expect_err("cleanup failure");
        assert_eq!(
            error.code,
            CredentialMaterializationErrorCode::CleanupFailed
        );
        assert_eq!(
            error.execution_failure(),
            CredentialExecutionFailure::CleanupFailed
        );

        let root = observed_root
            .borrow()
            .as_ref()
            .expect("observed root")
            .clone();
        assert!(root.exists());
        set_mode(&root, 0o700);
        assert_eq!(
            scratch
                .recover_stale_sessions()
                .expect("bootstrap recovery")
                .recovered_sessions,
            1
        );
        assert!(!root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn callback_unwind_drops_and_cleans_the_scoped_file_session() {
        let fixture = FilesystemFixture::new();
        let (contract, preparation) = scoped_file_plan(&fixture.scope);
        let baseline = ChildEnvironmentBaseline::hermetic();
        let plan = CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract).expect("file contract"),
            &preparation,
            baseline.clone(),
        )
        .expect("file plan");
        let scratch = fixture.scratch();
        let id = call_id("exec_unwind_file");
        let mut resolver = MapResolver {
            values: BTreeMap::from([("token".to_owned(), b"unwind-canary".to_vec())]),
        };

        let panic = catch_unwind(AssertUnwindSafe(|| {
            with_prepared_credential_material(&preparation, &mut resolver, |prepared| {
                materialize_credential_io(
                    &plan,
                    prepared,
                    ChildEnvironmentValues::new(&baseline),
                    CredentialFilesystemMaterialization::new(&id, &scratch, None),
                    |_| -> () { panic!("fixture unwind") },
                )
            })
            .expect("file resolution")
            .expect("unreachable materialization");
        }));
        assert!(panic.is_err());
        assert_eq!(
            scratch
                .recover_stale_sessions()
                .expect("post-unwind recovery")
                .recovered_sessions,
            0
        );
    }

    #[test]
    fn exact_value_redaction_is_binary_safe_longest_first_and_bounded() {
        let selected_scope = scope();
        let (contract, preparation) = environment_stdin_plan(&selected_scope);
        let baseline = ChildEnvironmentBaseline::hermetic();
        let injection = CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract).expect("validated contract"),
            &preparation,
            baseline.clone(),
        )
        .expect("injection");
        let mut resolver = MapResolver {
            values: BTreeMap::from([
                ("api_key".to_owned(), b"token-long".to_vec()),
                ("password".to_owned(), b"token".to_vec()),
            ]),
        };
        with_prepared_credential_material(&preparation, &mut resolver, |prepared| {
            materialize_environment_and_stdin(
                &injection,
                prepared,
                ChildEnvironmentValues::new(&baseline),
                |materialized| {
                    let redacted = materialized
                        .redact_output(b"\xfftoken-long/token/token-longer")
                        .expect("binary output");
                    assert_eq!(redacted.as_bytes(), b"\xff*/*/*er");
                    assert_eq!(
                        materialized
                            .redact_output(&vec![b'x'; MAX_REDACTION_INPUT_BYTES + 1])
                            .expect_err("input bound")
                            .code,
                        CredentialMaterializationErrorCode::RedactionInputTooLarge
                    );
                    let maximum = vec![b'x'; MAX_REDACTION_INPUT_BYTES];
                    assert!(
                        materialized
                            .redact_output(&maximum)
                            .expect("non-expanding redaction")
                            .as_bytes()
                            .len()
                            <= maximum.len()
                    );
                },
            )
            .expect("materialized")
        })
        .expect("resolved");
    }

    #[test]
    fn redaction_marker_and_join_boundaries_cannot_recreate_a_credential() {
        let patterns = [b"*".as_slice(), b"TOKEN".as_slice(), b"a+b".as_slice()];
        let redactor = CredentialValueRedactor::new(
            patterns
                .iter()
                .map(|pattern| Arc::new(Zeroizing::new(pattern.to_vec())))
                .collect(),
        )
        .expect("value-safe redactor");
        assert!(patterns
            .iter()
            .all(|pattern| !pattern.contains(&redactor.replacement)));

        let input = b"aTOKENb/*";
        let output = redactor.redact(input).expect("closed redaction");
        assert!(output.as_bytes().len() <= input.len());
        for pattern in patterns {
            assert!(
                !output
                    .as_bytes()
                    .windows(pattern.len())
                    .any(|window| window == pattern),
                "redacted output recreated a credential pattern"
            );
        }
    }

    #[test]
    fn exact_redaction_does_not_claim_transformed_credential_detection() {
        let redactor =
            CredentialValueRedactor::new(vec![Arc::new(Zeroizing::new(b"secret".to_vec()))])
                .expect("redactor");
        let transformed = b"736563726574";
        assert_eq!(
            redactor.redact(transformed).unwrap().as_bytes(),
            transformed,
            "encoded or transformed output is outside exact-value redaction"
        );
    }

    #[test]
    fn streaming_redaction_emits_ordinary_prompts_and_holds_only_real_secret_prefixes() {
        let redactor =
            CredentialValueRedactor::new(vec![Arc::new(Zeroizing::new(b"credential".to_vec()))])
                .expect("redactor");
        let mut streaming = redactor.streaming();
        assert_eq!(
            streaming.push(b"Password: ").unwrap().as_bytes(),
            b"Password: "
        );
        assert!(streaming.push(b"creden").unwrap().as_bytes().is_empty());
        assert_eq!(
            streaming.push(b"tial ready").unwrap().as_bytes(),
            b"********** ready"
        );
        assert!(streaming.into_pending().is_empty());
    }

    #[test]
    fn credential_free_streaming_redaction_emits_each_chunk_in_bulk() {
        let redactor = CredentialValueRedactor::new(Vec::new()).expect("empty redactor");
        let mut streaming = redactor.streaming();
        let input = vec![b'x'; MAX_REDACTION_INPUT_BYTES];
        assert_eq!(streaming.push(&input).unwrap().as_bytes(), input);
        assert_eq!(streaming.push(&input).unwrap().as_bytes(), input);
        assert!(streaming.into_pending().is_empty());
    }

    #[test]
    fn streaming_redaction_preserves_a_partial_non_secret_suffix_for_final_sealing() {
        let redactor =
            CredentialValueRedactor::new(vec![Arc::new(Zeroizing::new(b"secret".to_vec()))])
                .expect("redactor");
        let mut streaming = redactor.streaming();
        assert_eq!(streaming.push(b"done: se").unwrap().as_bytes(), b"done: ");
        assert_eq!(streaming.into_pending().as_slice(), b"se");
    }

    #[test]
    fn adversarial_shared_prefix_output_fails_at_the_comparison_budget() {
        let mut pattern = vec![b'x'; 1024];
        pattern[..2].copy_from_slice(b"ab");
        let redactor = CredentialValueRedactor::new(vec![Arc::new(Zeroizing::new(pattern))])
            .expect("redactor");
        let input = b"ab".repeat(MAX_REDACTION_INPUT_BYTES / 2);
        assert_eq!(
            redactor.redact(&input).unwrap_err().code,
            CredentialMaterializationErrorCode::RedactionWorkLimitExceeded
        );
    }

    #[test]
    fn redaction_index_is_zeroizing_bounded_and_iterative_at_maximum_pattern_bytes() {
        thread::Builder::new()
            .name("credential-redaction-byte-bound".to_owned())
            .stack_size(128 * 1024)
            .spawn(|| {
                let pattern_size = MAX_REDACTION_PATTERN_BYTES / 6;
                let patterns = (0..6)
                    .map(|index| {
                        let mut value = vec![b'a' + index as u8; pattern_size];
                        value[0] = b'A' + index as u8;
                        Arc::new(Zeroizing::new(value))
                    })
                    .collect();
                let mut redactor = CredentialValueRedactor::new(patterns).expect("redactor");
                assert_eq!(redactor.prefixes.len(), 6);
                assert_eq!(
                    redactor.redact(b"ordinary output").unwrap().as_bytes(),
                    b"ordinary output"
                );
                redactor.prefixes.zeroize();
                assert!(redactor
                    .prefixes
                    .iter()
                    .all(|prefix| prefix.key == 0 && prefix.pattern_index == 0));
                drop(redactor);

                let mut too_large = (0..6)
                    .map(|index| {
                        let mut value = vec![b'k' + index as u8; 1024 * 1024];
                        value[0] = b'K' + index as u8;
                        Arc::new(Zeroizing::new(value))
                    })
                    .collect::<Vec<_>>();
                too_large.push(Arc::new(Zeroizing::new(vec![b'z'])));
                let error = match CredentialValueRedactor::new(too_large) {
                    Err(error) => error,
                    Ok(_) => panic!("aggregate pattern byte limit must fail"),
                };
                assert_eq!(
                    error.code,
                    CredentialMaterializationErrorCode::RedactionPatternLimitExceeded
                );
            })
            .expect("spawn bounded redactor")
            .join()
            .expect("bounded redactor");

        let too_many = (0..=MAX_REDACTION_PATTERNS)
            .map(|index| Arc::new(Zeroizing::new(format!("pattern-{index}").into_bytes())))
            .collect();
        let error = match CredentialValueRedactor::new(too_many) {
            Err(error) => error,
            Ok(_) => panic!("pattern count limit must fail"),
        };
        assert_eq!(
            error.code,
            CredentialMaterializationErrorCode::RedactionPatternLimitExceeded
        );
    }

    #[test]
    fn maximum_environment_materialization_and_redaction_fit_a_small_stack() {
        thread::Builder::new()
            .name("phase3b-small-stack".to_owned())
            .stack_size(128 * 1024)
            .spawn(|| {
                let selected_scope = scope();
                let mut contract = cli_contract(AuthContract {
                    kind: AuthKind::Secrets,
                    requirement: AuthRequirement::Required,
                    ..AuthContract::default()
                });
                let mut bindings = Vec::new();
                let mut values = BTreeMap::new();
                for index in 0..MAX_PREPARED_CREDENTIAL_BINDINGS {
                    let binding = format!("secret_{index:02}");
                    let environment = format!("SECRET_{index:02}");
                    let value = format!("value-canary-{index:02}").into_bytes();
                    contract.auth.secret_bindings.push(SecretBindingRef {
                        name: binding.clone(),
                        secret_ref: format!("VAULT_SECRET_{index:02}"),
                    });
                    contract.auth.injections.push(InjectionBinding {
                        source: InjectionSource::Secret {
                            binding: binding.clone(),
                        },
                        target: InjectionTarget::Environment { name: environment },
                    });
                    bindings.push(preparation_binding(&binding));
                    values.insert(binding, value);
                }
                let preparation = CredentialPreparationPlan::new(
                    selected_scope.clone(),
                    AuthKind::Secrets,
                    &none_selection(&selected_scope),
                    bindings,
                )
                .expect("maximum preparation");
                let baseline = ChildEnvironmentBaseline::hermetic();
                let injection = CredentialInjectionPlan::compile(
                    validate_skill_runtime_contract(&contract).expect("maximum contract"),
                    &preparation,
                    baseline.clone(),
                )
                .expect("maximum injection");
                let mut resolver = MapResolver { values };
                with_prepared_credential_material(&preparation, &mut resolver, |prepared| {
                    materialize_environment_and_stdin(
                        &injection,
                        prepared,
                        ChildEnvironmentValues::new(&baseline),
                        |materialized| {
                            assert_eq!(
                                materialized.environment_len(),
                                MAX_PREPARED_CREDENTIAL_BINDINGS
                            );
                            let output = materialized
                                .redact_output(b"value-canary-00 value-canary-63")
                                .expect("maximum redaction");
                            assert_eq!(output.as_bytes(), b"* *");
                        },
                    )
                    .expect("maximum materialization")
                })
                .expect("maximum resolution");
            })
            .expect("spawn small-stack materializer")
            .join()
            .expect("small-stack materializer");
    }

    #[test]
    fn error_surface_is_fixed_and_contains_no_runtime_or_credential_value() {
        let canary = "RUNTIME_ENV_VALUE_CANARY";
        let error = invalid_environment_value();
        assert!(!format!("{error:?} {error}").contains(canary));
        assert_eq!(
            error.execution_failure(),
            CredentialExecutionFailure::EnvironmentUnavailable
        );
    }
}
