//! Phase 6D declared-artifact collection and safe execution-result sealing.
//!
//! Artifact authority is descriptor pinned and accepts only exact trusted declarations.
//! Raw process bytes and artifact bytes remain crate-private and zeroizing until one
//! logical exact-value redaction pass has completed.

use std::{
    error::Error,
    ffi::CString,
    fmt, fs,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::{
    fs::MetadataExt,
    io::{AsRawFd, FromRawFd, RawFd},
};

use serde::Serialize;
use zeroize::Zeroizing;

use crate::{
    credential_materialization::{CredentialRedactedOutput, CredentialValueRedactor},
    governed_batch_process::{
        release_governed_result_bytes, try_reserve_governed_result_bytes, GovernedOutputRetention,
        GovernedRawBatchExecution, GovernedRawBatchExecutionParts,
    },
    governed_execution::{
        GovernedExecutionDispatch, GovernedExecutionTerminal, GovernedExecutionTerminalState,
    },
    governed_pty_process::{GovernedRawPtyExecution, GovernedRawPtyExecutionParts},
    manifest_validation::MAX_RUNTIME_STREAM_BYTES,
};

pub const GOVERNED_EXECUTION_RESULT_V1: &str = "tool-runtime.governed-execution-result.v1";
pub const MAX_GOVERNED_ARTIFACTS: usize = 64;
pub const MAX_GOVERNED_ARTIFACT_DEPTH: usize = 16;
pub const MAX_GOVERNED_ARTIFACT_PATH_BYTES: usize = 1024;
pub const MAX_GOVERNED_ARTIFACT_FILE_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_GOVERNED_ARTIFACT_TOTAL_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedArtifactErrorCode {
    InvalidPolicy,
    InvalidDeclaration,
    DuplicateDeclaration,
    ConflictingDeclaration,
    UnsafeOutputRoot,
    ExistingArtifact,
    OutputAuthorityChanged,
    MissingParentIsNotDirectory,
    SymlinkRejected,
    HardLinkRejected,
    NonRegularFile,
    WrongOwner,
    CrossFilesystem,
    FileTooLarge,
    AggregateTooLarge,
    FileChangedDuringCollection,
    FileReadFailed,
    CredentialDetected,
    RedactionFailed,
    CapacityExceeded,
}

/// Fixed, path-free artifact error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GovernedArtifactError {
    pub code: GovernedArtifactErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl GovernedArtifactError {
    const fn new(
        code: GovernedArtifactErrorCode,
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

impl fmt::Display for GovernedArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for GovernedArtifactError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GovernedArtifactPolicy {
    max_count: usize,
    max_depth: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
}

impl GovernedArtifactPolicy {
    pub fn new(
        max_count: usize,
        max_depth: usize,
        max_file_bytes: u64,
        max_total_bytes: u64,
    ) -> Result<Self, GovernedArtifactError> {
        if max_count == 0
            || max_count > MAX_GOVERNED_ARTIFACTS
            || max_depth == 0
            || max_depth > MAX_GOVERNED_ARTIFACT_DEPTH
            || max_file_bytes == 0
            || max_file_bytes > MAX_GOVERNED_ARTIFACT_FILE_BYTES
            || max_total_bytes == 0
            || max_total_bytes > MAX_GOVERNED_ARTIFACT_TOTAL_BYTES
            || max_file_bytes > max_total_bytes
        {
            return Err(invalid_policy());
        }
        Ok(Self {
            max_count,
            max_depth,
            max_file_bytes,
            max_total_bytes,
        })
    }

    pub fn max_count(self) -> usize {
        self.max_count
    }

    pub fn max_depth(self) -> usize {
        self.max_depth
    }

    pub fn max_file_bytes(self) -> u64 {
        self.max_file_bytes
    }

    pub fn max_total_bytes(self) -> u64 {
        self.max_total_bytes
    }
}

/// Validated exact relative artifact declarations. Declarations are trusted runtime
/// policy, never model-selected output paths.
pub struct GovernedArtifactDeclarations {
    paths: Vec<DeclaredArtifactPath>,
}

impl GovernedArtifactDeclarations {
    pub fn compile(
        relative_paths: Vec<String>,
        policy: GovernedArtifactPolicy,
    ) -> Result<Self, GovernedArtifactError> {
        if relative_paths.len() > policy.max_count {
            return Err(invalid_declaration());
        }
        let mut paths = relative_paths
            .into_iter()
            .map(|path| DeclaredArtifactPath::parse(path, policy.max_depth))
            .collect::<Result<Vec<_>, _>>()?;
        paths.sort_by(|left, right| left.value.cmp(&right.value));
        for pair in paths.windows(2) {
            if pair[0].components == pair[1].components {
                return Err(duplicate_declaration());
            }
        }
        let declared = paths
            .iter()
            .map(|path| path.value.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        for path in &paths {
            let mut parent = path.value.as_str();
            while let Some((ancestor, _)) = parent.rsplit_once('/') {
                if declared.contains(ancestor) {
                    return Err(conflicting_declaration());
                }
                parent = ancestor;
            }
        }
        Ok(Self { paths })
    }

    pub fn len(&self) -> usize {
        self.paths.len()
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

struct DeclaredArtifactPath {
    value: String,
    components: Vec<CString>,
}

impl DeclaredArtifactPath {
    fn parse(value: String, max_depth: usize) -> Result<Self, GovernedArtifactError> {
        if value.is_empty()
            || value.len() > MAX_GOVERNED_ARTIFACT_PATH_BYTES
            || value.starts_with('/')
            || value.ends_with('/')
            || value.contains('\\')
            || value.chars().any(char::is_control)
        {
            return Err(invalid_declaration());
        }
        let raw_components = value.split('/').collect::<Vec<_>>();
        if raw_components.is_empty()
            || raw_components.len() > max_depth
            || raw_components
                .iter()
                .any(|component| component.is_empty() || *component == "." || *component == "..")
        {
            return Err(invalid_declaration());
        }
        let components = raw_components
            .into_iter()
            .map(|component| {
                if component.len() > 255 {
                    return Err(invalid_declaration());
                }
                CString::new(component.as_bytes()).map_err(|_| invalid_declaration())
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { value, components })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct RootIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    owner: u32,
    #[cfg(unix)]
    mode: u32,
}

/// Pinned exact output-root authority. Every declaration must be absent when authority
/// is bound, preventing a later invocation from returning stale pre-existing files.
pub struct GovernedArtifactAuthority {
    schema_version: &'static str,
    root_path: PathBuf,
    root: File,
    root_identity: RootIdentity,
    declarations: GovernedArtifactDeclarations,
    policy: GovernedArtifactPolicy,
}

impl GovernedArtifactAuthority {
    pub fn bind(
        output_root: impl AsRef<Path>,
        declarations: GovernedArtifactDeclarations,
        policy: GovernedArtifactPolicy,
    ) -> Result<Self, GovernedArtifactError> {
        #[cfg(not(unix))]
        {
            let _ = (output_root, declarations, policy);
            return Err(unsafe_output_root());
        }
        #[cfg(unix)]
        {
            let root_path = output_root.as_ref();
            if !root_path.is_absolute() {
                return Err(unsafe_output_root());
            }
            let named = fs::symlink_metadata(root_path).map_err(|_| unsafe_output_root())?;
            if named.file_type().is_symlink() || !named.is_dir() {
                return Err(unsafe_output_root());
            }
            let canonical = fs::canonicalize(root_path).map_err(|_| unsafe_output_root())?;
            let canonical_metadata =
                fs::symlink_metadata(&canonical).map_err(|_| unsafe_output_root())?;
            if canonical_metadata.file_type().is_symlink()
                || !canonical_metadata.is_dir()
                || root_identity(&canonical_metadata)? != root_identity(&named)?
            {
                return Err(unsafe_output_root());
            }
            let root_id = root_identity(&canonical_metadata)?;
            if root_id.owner != unsafe { libc::geteuid() } || root_id.mode & 0o022 != 0 {
                return Err(unsafe_output_root());
            }
            let root = File::open(&canonical).map_err(|_| unsafe_output_root())?;
            if root_identity(&root.metadata().map_err(|_| unsafe_output_root())?)? != root_id {
                return Err(unsafe_output_root());
            }
            for declaration in &declarations.paths {
                if !declared_path_absent(root.as_raw_fd(), root_id, declaration)? {
                    return Err(existing_artifact());
                }
            }
            Ok(Self {
                schema_version: GOVERNED_EXECUTION_RESULT_V1,
                root_path: canonical,
                root,
                root_identity: root_id,
                declarations,
                policy,
            })
        }
    }

    pub fn schema_version(&self) -> &'static str {
        self.schema_version
    }

    pub fn declaration_count(&self) -> usize {
        self.declarations.len()
    }

    fn revalidate(&self) -> Result<(), GovernedArtifactError> {
        let named =
            fs::symlink_metadata(&self.root_path).map_err(|_| output_authority_changed())?;
        if named.file_type().is_symlink()
            || !named.is_dir()
            || root_identity(&named)? != self.root_identity
            || fs::canonicalize(&self.root_path).map_err(|_| output_authority_changed())?
                != self.root_path
            || root_identity(
                &self
                    .root
                    .metadata()
                    .map_err(|_| output_authority_changed())?,
            )? != self.root_identity
        {
            return Err(output_authority_changed());
        }
        Ok(())
    }

    fn collect_raw(self) -> Result<RawArtifactCollection, GovernedArtifactError> {
        self.revalidate()?;
        let mut retention = GovernedArtifactRetention::acquire(self.policy.max_total_bytes)?;
        let mut files = Vec::new();
        let mut missing = 0usize;
        let mut total = 0u64;
        for declaration in &self.declarations.paths {
            let Some(mut file) = open_declared_file(
                artifact_root_fd(&self.root)?,
                self.root_identity,
                declaration,
            )?
            else {
                missing = missing.saturating_add(1);
                continue;
            };
            let before = artifact_identity(
                &file.metadata().map_err(|_| file_read_failed())?,
                self.root_identity,
            )?;
            if before.length > self.policy.max_file_bytes {
                return Err(file_too_large());
            }
            total = total
                .checked_add(before.length)
                .ok_or_else(aggregate_too_large)?;
            if total > self.policy.max_total_bytes {
                return Err(aggregate_too_large());
            }
            let exact_length = usize::try_from(before.length).map_err(|_| file_too_large())?;
            let mut bytes = Zeroizing::new(vec![0u8; exact_length]);
            file.read_exact(&mut bytes)
                .map_err(|_| file_read_failed())?;
            if bytes.len() as u64 != before.length {
                return Err(file_changed_during_collection());
            }
            let after = artifact_identity(
                &file.metadata().map_err(|_| file_read_failed())?,
                self.root_identity,
            )?;
            if after != before {
                return Err(file_changed_during_collection());
            }
            files.push(RawCollectedArtifact {
                relative_path: declaration.value.clone(),
                bytes,
            });
        }
        self.revalidate()?;
        retention.shrink_to(total);
        Ok(RawArtifactCollection {
            declared: self.declarations.len(),
            missing,
            total_bytes: total,
            files,
            retention,
        })
    }
}

struct RawArtifactCollection {
    declared: usize,
    missing: usize,
    total_bytes: u64,
    files: Vec<RawCollectedArtifact>,
    retention: GovernedArtifactRetention,
}

struct GovernedArtifactRetention {
    reserved_bytes: u64,
}

impl GovernedArtifactRetention {
    fn acquire(reserved_bytes: u64) -> Result<Self, GovernedArtifactError> {
        if reserved_bytes == 0
            || reserved_bytes > MAX_GOVERNED_ARTIFACT_TOTAL_BYTES
            || !try_reserve_governed_result_bytes(reserved_bytes)
        {
            return Err(capacity_exceeded());
        }
        Ok(Self { reserved_bytes })
    }

    fn shrink_to(&mut self, retained_bytes: u64) {
        let retained_bytes = retained_bytes.min(self.reserved_bytes);
        let released = self.reserved_bytes - retained_bytes;
        if released != 0 {
            release_governed_result_bytes(released);
            self.reserved_bytes = retained_bytes;
        }
    }
}

impl Drop for GovernedArtifactRetention {
    fn drop(&mut self) {
        release_governed_result_bytes(self.reserved_bytes);
    }
}

struct RawCollectedArtifact {
    relative_path: String,
    bytes: Zeroizing<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedArtifactOutcome {
    Complete,
    Partial,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GovernedArtifactMetadata {
    pub outcome: GovernedArtifactOutcome,
    pub declared_count: usize,
    pub collected_count: usize,
    pub missing_count: usize,
    pub total_bytes: u64,
    pub rejection: Option<GovernedArtifactErrorCode>,
}

/// Safe collected artifact. Byte access is possible only after the combined execution
/// redaction pass proves that no prepared credential touched this segment.
pub struct GovernedCollectedArtifact {
    relative_path: String,
    content: CredentialRedactedOutput,
}

impl GovernedCollectedArtifact {
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    pub fn content(&self) -> &[u8] {
        self.content.as_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GovernedStreamMetadata {
    pub bytes: usize,
    pub truncated: bool,
}

/// Public safe result. It is deliberately not serializable or cloneable; product
/// adapters must explicitly project the already-redacted output and artifacts.
pub struct GovernedExecutionResult {
    schema_version: &'static str,
    terminal: GovernedExecutionTerminalState,
    exit_code: Option<i32>,
    elapsed: Duration,
    stdout: CredentialRedactedOutput,
    stderr: CredentialRedactedOutput,
    pty: Option<CredentialRedactedOutput>,
    stdout_metadata: GovernedStreamMetadata,
    stderr_metadata: GovernedStreamMetadata,
    pty_metadata: Option<GovernedStreamMetadata>,
    artifact_metadata: GovernedArtifactMetadata,
    artifacts: Vec<GovernedCollectedArtifact>,
    // These private leases deliberately live as long as the public result bytes. A
    // caller can borrow output and artifacts, but cannot detach their storage from the
    // process-wide result-retention budget.
    _output_retention: Option<GovernedOutputRetention>,
    _artifact_retention: Option<GovernedArtifactRetention>,
}

impl GovernedExecutionResult {
    pub fn schema_version(&self) -> &'static str {
        self.schema_version
    }

    pub fn terminal(&self) -> GovernedExecutionTerminalState {
        self.terminal
    }

    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    pub fn stdout(&self) -> &[u8] {
        self.stdout.as_bytes()
    }

    pub fn stderr(&self) -> &[u8] {
        self.stderr.as_bytes()
    }

    pub fn pty(&self) -> Option<&[u8]> {
        self.pty.as_ref().map(CredentialRedactedOutput::as_bytes)
    }

    pub fn stdout_metadata(&self) -> GovernedStreamMetadata {
        self.stdout_metadata
    }

    pub fn stderr_metadata(&self) -> GovernedStreamMetadata {
        self.stderr_metadata
    }

    pub fn pty_metadata(&self) -> Option<GovernedStreamMetadata> {
        self.pty_metadata
    }

    pub fn artifact_metadata(&self) -> GovernedArtifactMetadata {
        self.artifact_metadata
    }

    pub fn artifacts(&self) -> &[GovernedCollectedArtifact] {
        &self.artifacts
    }

    #[cfg(test)]
    pub(crate) fn retains_output_capacity(&self) -> bool {
        self._output_retention.is_some()
    }

    #[cfg(test)]
    pub(crate) fn retains_artifact_capacity(&self) -> bool {
        self._artifact_retention.is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GovernedExecutionResultError {
    pub code: GovernedArtifactErrorCode,
    pub field: &'static str,
    pub message: &'static str,
    dispatch: GovernedExecutionDispatch,
}

impl GovernedExecutionResultError {
    pub fn dispatch(self) -> GovernedExecutionDispatch {
        self.dispatch
    }
}

impl fmt::Display for GovernedExecutionResultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for GovernedExecutionResultError {}

pub(crate) struct GovernedExecutionResultSealer;

impl GovernedExecutionResultSealer {
    pub(crate) fn seal_batch(
        raw: GovernedRawBatchExecution,
        redactor: &CredentialValueRedactor,
        artifact_authority: Option<GovernedArtifactAuthority>,
    ) -> Result<GovernedExecutionResult, GovernedExecutionResultError> {
        let GovernedRawBatchExecutionParts {
            terminal,
            exit_code,
            elapsed,
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
            output_retention,
        } = raw.into_parts();
        let dispatch = terminal.dispatch();
        let declared_count = artifact_authority
            .as_ref()
            .map_or(0, GovernedArtifactAuthority::declaration_count);
        let raw_artifacts = if dispatch == GovernedExecutionDispatch::NotDispatched {
            None
        } else {
            artifact_authority.map(GovernedArtifactAuthority::collect_raw)
        }
        .transpose();

        let (collection, collection_error) = match raw_artifacts {
            Ok(Some(collection)) => (Some(collection), None),
            Ok(None) => (None, None),
            Err(error) => (None, Some(error.code)),
        };
        let mut segments = vec![stdout, stderr];
        let mut artifact_paths = Vec::new();
        let mut missing_count = 0usize;
        let mut raw_artifact_total = 0u64;
        let mut artifact_retention = None;
        if let Some(collection) = collection {
            let RawArtifactCollection {
                declared,
                missing,
                total_bytes,
                files,
                retention,
            } = collection;
            if declared != declared_count {
                return Err(result_redaction_failed(dispatch));
            }
            missing_count = missing;
            raw_artifact_total = total_bytes;
            artifact_retention = Some(retention);
            for artifact in files {
                artifact_paths.push(artifact.relative_path);
                segments.push(artifact.bytes);
            }
        } else if dispatch == GovernedExecutionDispatch::NotDispatched {
            missing_count = declared_count;
        }
        let max_total = MAX_RUNTIME_STREAM_BYTES
            .saturating_mul(2)
            .saturating_add(MAX_GOVERNED_ARTIFACT_TOTAL_BYTES);
        let max_total = usize::try_from(max_total).unwrap_or(usize::MAX);
        let (redacted, matched_segments) = redactor
            .redact_governed_segments_owned(segments, max_total)
            .map_err(|_| result_redaction_failed(dispatch))?;
        let mut redacted = redacted.into_iter();
        let stdout = redacted
            .next()
            .ok_or_else(|| result_redaction_failed(dispatch))?;
        let stderr = redacted
            .next()
            .ok_or_else(|| result_redaction_failed(dispatch))?;
        let artifact_credential_detected = matched_segments.iter().skip(2).any(|value| *value);
        if redacted.len() != artifact_paths.len() {
            return Err(result_redaction_failed(dispatch));
        }
        let rejection = collection_error.or_else(|| {
            artifact_credential_detected.then_some(GovernedArtifactErrorCode::CredentialDetected)
        });
        if rejection.is_some() {
            artifact_retention = None;
        }
        let mut artifacts = Vec::new();
        if rejection.is_none() {
            for (relative_path, content) in artifact_paths.into_iter().zip(redacted) {
                artifacts.push(GovernedCollectedArtifact {
                    relative_path,
                    content,
                });
            }
        }
        let artifact_metadata = if let Some(rejection) = rejection {
            GovernedArtifactMetadata {
                outcome: GovernedArtifactOutcome::Rejected,
                declared_count,
                collected_count: 0,
                missing_count,
                total_bytes: 0,
                rejection: Some(rejection),
            }
        } else {
            GovernedArtifactMetadata {
                outcome: if terminal.terminal() == GovernedExecutionTerminal::Success {
                    GovernedArtifactOutcome::Complete
                } else {
                    GovernedArtifactOutcome::Partial
                },
                declared_count,
                collected_count: artifacts.len(),
                missing_count,
                total_bytes: raw_artifact_total,
                rejection: None,
            }
        };
        let terminal = if terminal.terminal() == GovernedExecutionTerminal::Success
            && artifact_metadata.outcome == GovernedArtifactOutcome::Rejected
        {
            GovernedExecutionTerminalState::new(
                GovernedExecutionTerminal::ArtifactRejected,
                GovernedExecutionDispatch::Dispatched,
            )
            .map_err(|_| result_redaction_failed(dispatch))?
        } else {
            terminal
        };
        Ok(GovernedExecutionResult {
            schema_version: GOVERNED_EXECUTION_RESULT_V1,
            terminal,
            exit_code,
            elapsed,
            stdout_metadata: GovernedStreamMetadata {
                bytes: stdout.as_bytes().len(),
                truncated: stdout_truncated,
            },
            stderr_metadata: GovernedStreamMetadata {
                bytes: stderr.as_bytes().len(),
                truncated: stderr_truncated,
            },
            stdout,
            stderr,
            pty: None,
            artifact_metadata,
            artifacts,
            pty_metadata: None,
            _output_retention: output_retention,
            _artifact_retention: artifact_retention,
        })
    }

    pub(crate) fn seal_pty(
        raw: GovernedRawPtyExecution,
        redactor: &CredentialValueRedactor,
        artifact_authority: Option<GovernedArtifactAuthority>,
    ) -> Result<GovernedExecutionResult, GovernedExecutionResultError> {
        let GovernedRawPtyExecutionParts {
            terminal,
            exit_code,
            elapsed,
            stable_output,
            pending_output,
            output_truncated,
            output_retention,
        } = raw.into_parts();
        let dispatch = terminal.dispatch();
        let declared_count = artifact_authority
            .as_ref()
            .map_or(0, GovernedArtifactAuthority::declaration_count);
        let raw_artifacts = if dispatch == GovernedExecutionDispatch::NotDispatched {
            None
        } else {
            artifact_authority.map(GovernedArtifactAuthority::collect_raw)
        }
        .transpose();
        let (collection, collection_error) = match raw_artifacts {
            Ok(Some(collection)) => (Some(collection), None),
            Ok(None) => (None, None),
            Err(error) => (None, Some(error.code)),
        };
        let mut segments = vec![pending_output];
        let mut artifact_paths = Vec::new();
        let mut missing_count = 0usize;
        let mut raw_artifact_total = 0u64;
        let mut artifact_retention = None;
        if let Some(collection) = collection {
            let RawArtifactCollection {
                declared,
                missing,
                total_bytes,
                files,
                retention,
            } = collection;
            if declared != declared_count {
                return Err(result_redaction_failed(dispatch));
            }
            missing_count = missing;
            raw_artifact_total = total_bytes;
            artifact_retention = Some(retention);
            for artifact in files {
                artifact_paths.push(artifact.relative_path);
                segments.push(artifact.bytes);
            }
        } else if dispatch == GovernedExecutionDispatch::NotDispatched {
            missing_count = declared_count;
        }
        let max_total = MAX_RUNTIME_STREAM_BYTES
            .saturating_mul(2)
            .saturating_add(MAX_GOVERNED_ARTIFACT_TOTAL_BYTES);
        let max_total = usize::try_from(max_total).unwrap_or(usize::MAX);
        let (redacted, matched_segments) = redactor
            .redact_governed_segments_owned(segments, max_total)
            .map_err(|_| result_redaction_failed(dispatch))?;
        let mut redacted = redacted.into_iter();
        let pending_output = redacted
            .next()
            .ok_or_else(|| result_redaction_failed(dispatch))?;
        let artifact_credential_detected = matched_segments.iter().skip(1).any(|value| *value);
        if redacted.len() != artifact_paths.len() {
            return Err(result_redaction_failed(dispatch));
        }
        let rejection = collection_error.or_else(|| {
            artifact_credential_detected.then_some(GovernedArtifactErrorCode::CredentialDetected)
        });
        if rejection.is_some() {
            artifact_retention = None;
        }
        let mut artifacts = Vec::new();
        if rejection.is_none() {
            for (relative_path, content) in artifact_paths.into_iter().zip(redacted) {
                artifacts.push(GovernedCollectedArtifact {
                    relative_path,
                    content,
                });
            }
        }
        let artifact_metadata = if let Some(rejection) = rejection {
            GovernedArtifactMetadata {
                outcome: GovernedArtifactOutcome::Rejected,
                declared_count,
                collected_count: 0,
                missing_count,
                total_bytes: 0,
                rejection: Some(rejection),
            }
        } else {
            GovernedArtifactMetadata {
                outcome: if terminal.terminal() == GovernedExecutionTerminal::Success {
                    GovernedArtifactOutcome::Complete
                } else {
                    GovernedArtifactOutcome::Partial
                },
                declared_count,
                collected_count: artifacts.len(),
                missing_count,
                total_bytes: raw_artifact_total,
                rejection: None,
            }
        };
        let terminal = if terminal.terminal() == GovernedExecutionTerminal::Success
            && artifact_metadata.outcome == GovernedArtifactOutcome::Rejected
        {
            GovernedExecutionTerminalState::new(
                GovernedExecutionTerminal::ArtifactRejected,
                GovernedExecutionDispatch::Dispatched,
            )
            .map_err(|_| result_redaction_failed(dispatch))?
        } else {
            terminal
        };
        let mut pty_bytes = stable_output.into_bytes();
        let pty_total = pty_bytes
            .len()
            .checked_add(pending_output.as_bytes().len())
            .ok_or_else(|| result_redaction_failed(dispatch))?;
        let pty_capacity = pty_bytes.capacity();
        if pty_total > pty_capacity {
            pty_bytes.reserve_exact(pty_total - pty_capacity);
        }
        pty_bytes.extend_from_slice(pending_output.as_bytes());
        let pty = CredentialRedactedOutput(pty_bytes);
        let pty_metadata = GovernedStreamMetadata {
            bytes: pty.as_bytes().len(),
            truncated: output_truncated,
        };
        Ok(GovernedExecutionResult {
            schema_version: GOVERNED_EXECUTION_RESULT_V1,
            terminal,
            exit_code,
            elapsed,
            stdout: CredentialRedactedOutput(Vec::new()),
            stderr: CredentialRedactedOutput(Vec::new()),
            pty: Some(pty),
            stdout_metadata: GovernedStreamMetadata {
                bytes: 0,
                truncated: false,
            },
            stderr_metadata: GovernedStreamMetadata {
                bytes: 0,
                truncated: false,
            },
            pty_metadata: Some(pty_metadata),
            artifact_metadata,
            artifacts,
            _output_retention: output_retention,
            _artifact_retention: artifact_retention,
        })
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct ArtifactFileIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    links: u64,
    length: u64,
    change_time_secs: i64,
    change_time_nanos: i64,
}

#[cfg(unix)]
fn root_identity(metadata: &fs::Metadata) -> Result<RootIdentity, GovernedArtifactError> {
    if !metadata.is_dir() {
        return Err(unsafe_output_root());
    }
    Ok(RootIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.mode(),
    })
}

#[cfg(not(unix))]
fn root_identity(_metadata: &fs::Metadata) -> Result<RootIdentity, GovernedArtifactError> {
    Err(unsafe_output_root())
}

#[cfg(unix)]
fn artifact_identity(
    metadata: &fs::Metadata,
    root: RootIdentity,
) -> Result<ArtifactFileIdentity, GovernedArtifactError> {
    if !metadata.is_file() {
        return Err(non_regular_file());
    }
    if metadata.nlink() != 1 {
        return Err(hard_link_rejected());
    }
    if metadata.uid() != root.owner {
        return Err(wrong_owner());
    }
    if metadata.dev() != root.device {
        return Err(cross_filesystem());
    }
    Ok(ArtifactFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.mode(),
        links: metadata.nlink(),
        length: metadata.len(),
        change_time_secs: metadata.ctime(),
        change_time_nanos: metadata.ctime_nsec(),
    })
}

#[cfg(unix)]
fn declared_path_absent(
    root_fd: RawFd,
    root: RootIdentity,
    declaration: &DeclaredArtifactPath,
) -> Result<bool, GovernedArtifactError> {
    match walk_to_declared_file(root_fd, root, declaration)? {
        WalkedArtifact::Missing => Ok(true),
        WalkedArtifact::File(_) => Ok(false),
    }
}

#[cfg(unix)]
fn open_declared_file(
    root_fd: RawFd,
    root: RootIdentity,
    declaration: &DeclaredArtifactPath,
) -> Result<Option<File>, GovernedArtifactError> {
    match walk_to_declared_file(root_fd, root, declaration)? {
        WalkedArtifact::Missing => Ok(None),
        WalkedArtifact::File(file) => Ok(Some(file)),
    }
}

#[cfg(not(unix))]
fn open_declared_file(
    _root_fd: i32,
    _root: RootIdentity,
    _declaration: &DeclaredArtifactPath,
) -> Result<Option<File>, GovernedArtifactError> {
    Err(unsafe_output_root())
}

#[cfg(unix)]
enum WalkedArtifact {
    Missing,
    File(File),
}

#[cfg(unix)]
fn walk_to_declared_file(
    root_fd: RawFd,
    root: RootIdentity,
    declaration: &DeclaredArtifactPath,
) -> Result<WalkedArtifact, GovernedArtifactError> {
    let mut directories = Vec::new();
    let mut current_fd = root_fd;
    let Some((file_name, parent_components)) = declaration.components.split_last() else {
        return Err(invalid_declaration());
    };
    for component in parent_components {
        let metadata = match metadata_at(current_fd, component)? {
            Some(metadata) => metadata,
            None => return Ok(WalkedArtifact::Missing),
        };
        validate_directory_stat(&metadata, root)?;
        let directory = open_directory_at(current_fd, component)?;
        let opened = directory.metadata().map_err(|_| file_read_failed())?;
        if opened.dev() != metadata.st_dev as u64
            || opened.ino() != metadata.st_ino as u64
            || !opened.is_dir()
        {
            return Err(file_changed_during_collection());
        }
        current_fd = directory.as_raw_fd();
        directories.push(directory);
    }
    let Some(metadata) = metadata_at(current_fd, file_name)? else {
        return Ok(WalkedArtifact::Missing);
    };
    if file_type(metadata.st_mode) == libc::S_IFLNK {
        return Err(symlink_rejected());
    }
    if file_type(metadata.st_mode) != libc::S_IFREG {
        return Err(non_regular_file());
    }
    let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    // SAFETY: `current_fd` is root or a retained verified directory descriptor and the
    // component is a NUL-free single path segment.
    let fd = unsafe { libc::openat(current_fd, file_name.as_ptr(), flags) };
    if fd < 0 {
        return Err(file_read_failed());
    }
    // SAFETY: `openat` returned a fresh owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let opened = file.metadata().map_err(|_| file_read_failed())?;
    if opened.dev() != metadata.st_dev as u64
        || opened.ino() != metadata.st_ino
        || !opened.is_file()
    {
        return Err(file_changed_during_collection());
    }
    let _ = directories;
    Ok(WalkedArtifact::File(file))
}

#[cfg(unix)]
fn metadata_at(
    directory_fd: RawFd,
    component: &CString,
) -> Result<Option<libc::stat>, GovernedArtifactError> {
    // SAFETY: zero is a valid initial bit pattern for `stat`, and fstatat initializes it
    // on success. The component is one validated NUL-free segment.
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::fstatat(
            directory_fd,
            component.as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Ok(Some(metadata));
    }
    if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        return Ok(None);
    }
    Err(file_read_failed())
}

#[cfg(unix)]
fn validate_directory_stat(
    metadata: &libc::stat,
    root: RootIdentity,
) -> Result<(), GovernedArtifactError> {
    match file_type(metadata.st_mode) {
        libc::S_IFLNK => Err(symlink_rejected()),
        libc::S_IFDIR => {
            if metadata.st_dev as u64 != root.device {
                return Err(cross_filesystem());
            }
            if metadata.st_uid != root.owner {
                return Err(wrong_owner());
            }
            if metadata.st_mode & 0o022 != 0 {
                return Err(missing_parent_not_directory());
            }
            Ok(())
        },
        _ => Err(missing_parent_not_directory()),
    }
}

#[cfg(unix)]
fn open_directory_at(
    directory_fd: RawFd,
    component: &CString,
) -> Result<File, GovernedArtifactError> {
    let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY;
    // SAFETY: the parent descriptor and single validated component are controlled as
    // described by `walk_to_declared_file`.
    let fd = unsafe { libc::openat(directory_fd, component.as_ptr(), flags) };
    if fd < 0 {
        return Err(file_read_failed());
    }
    // SAFETY: `openat` returned a fresh owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn file_type(mode: libc::mode_t) -> libc::mode_t {
    mode & libc::S_IFMT
}

#[cfg(unix)]
fn artifact_root_fd(root: &File) -> Result<RawFd, GovernedArtifactError> {
    Ok(root.as_raw_fd())
}

#[cfg(not(unix))]
fn artifact_root_fd(_root: &File) -> Result<i32, GovernedArtifactError> {
    Err(unsafe_output_root())
}

fn result_redaction_failed(dispatch: GovernedExecutionDispatch) -> GovernedExecutionResultError {
    GovernedExecutionResultError {
        code: GovernedArtifactErrorCode::RedactionFailed,
        field: "execution_result",
        message: "the governed execution result could not be safely redacted",
        dispatch,
    }
}

const fn capacity_exceeded() -> GovernedArtifactError {
    GovernedArtifactError::new(
        GovernedArtifactErrorCode::CapacityExceeded,
        "artifact_capacity",
        "the process-wide governed result-retention capacity is exhausted",
    )
}

const fn invalid_policy() -> GovernedArtifactError {
    GovernedArtifactError::new(
        GovernedArtifactErrorCode::InvalidPolicy,
        "artifact_policy",
        "the artifact policy is empty or exceeds a hard runtime ceiling",
    )
}

const fn invalid_declaration() -> GovernedArtifactError {
    GovernedArtifactError::new(
        GovernedArtifactErrorCode::InvalidDeclaration,
        "artifact_declaration",
        "an artifact declaration is not a bounded portable relative file path",
    )
}

const fn duplicate_declaration() -> GovernedArtifactError {
    GovernedArtifactError::new(
        GovernedArtifactErrorCode::DuplicateDeclaration,
        "artifact_declaration",
        "artifact declarations contain the same exact relative file path",
    )
}

const fn conflicting_declaration() -> GovernedArtifactError {
    GovernedArtifactError::new(
        GovernedArtifactErrorCode::ConflictingDeclaration,
        "artifact_declaration",
        "an artifact file declaration is an ancestor of another declaration",
    )
}

const fn unsafe_output_root() -> GovernedArtifactError {
    GovernedArtifactError::new(
        GovernedArtifactErrorCode::UnsafeOutputRoot,
        "artifact_root",
        "the artifact output root is not an exact private owner-controlled directory",
    )
}

const fn existing_artifact() -> GovernedArtifactError {
    GovernedArtifactError::new(
        GovernedArtifactErrorCode::ExistingArtifact,
        "artifact_declaration",
        "a declared artifact already exists before governed execution",
    )
}

const fn output_authority_changed() -> GovernedArtifactError {
    GovernedArtifactError::new(
        GovernedArtifactErrorCode::OutputAuthorityChanged,
        "artifact_root",
        "the artifact output authority changed during governed execution",
    )
}

const fn missing_parent_not_directory() -> GovernedArtifactError {
    GovernedArtifactError::new(
        GovernedArtifactErrorCode::MissingParentIsNotDirectory,
        "artifact_path",
        "a declared artifact parent is not a private governed directory",
    )
}

const fn symlink_rejected() -> GovernedArtifactError {
    GovernedArtifactError::new(
        GovernedArtifactErrorCode::SymlinkRejected,
        "artifact_path",
        "a declared artifact path contains a symbolic link",
    )
}

const fn hard_link_rejected() -> GovernedArtifactError {
    GovernedArtifactError::new(
        GovernedArtifactErrorCode::HardLinkRejected,
        "artifact_path",
        "a declared artifact is hard-linked and cannot cross the result boundary",
    )
}

const fn non_regular_file() -> GovernedArtifactError {
    GovernedArtifactError::new(
        GovernedArtifactErrorCode::NonRegularFile,
        "artifact_path",
        "a declared artifact is not a regular file",
    )
}

const fn wrong_owner() -> GovernedArtifactError {
    GovernedArtifactError::new(
        GovernedArtifactErrorCode::WrongOwner,
        "artifact_path",
        "a declared artifact is not owned by the governed runtime user",
    )
}

const fn cross_filesystem() -> GovernedArtifactError {
    GovernedArtifactError::new(
        GovernedArtifactErrorCode::CrossFilesystem,
        "artifact_path",
        "a declared artifact crosses the governed output filesystem",
    )
}

const fn file_too_large() -> GovernedArtifactError {
    GovernedArtifactError::new(
        GovernedArtifactErrorCode::FileTooLarge,
        "artifact_file",
        "a declared artifact exceeds its per-file byte ceiling",
    )
}

const fn aggregate_too_large() -> GovernedArtifactError {
    GovernedArtifactError::new(
        GovernedArtifactErrorCode::AggregateTooLarge,
        "artifact_collection",
        "declared artifacts exceed the aggregate byte ceiling",
    )
}

const fn file_changed_during_collection() -> GovernedArtifactError {
    GovernedArtifactError::new(
        GovernedArtifactErrorCode::FileChangedDuringCollection,
        "artifact_file",
        "a declared artifact changed while it was being collected",
    )
}

const fn file_read_failed() -> GovernedArtifactError {
    GovernedArtifactError::new(
        GovernedArtifactErrorCode::FileReadFailed,
        "artifact_file",
        "a declared artifact could not be read through its pinned authority",
    )
}

#[cfg(test)]
mod tests {
    use std::{fmt, fs, sync::Arc};

    #[cfg(unix)]
    use std::os::unix::fs::{symlink, PermissionsExt};

    use serde::Serialize;
    use static_assertions::assert_not_impl_any;
    use zeroize::Zeroizing;

    use super::*;
    use crate::governed_batch_process::GovernedRawBatchExecution;

    fn policy() -> GovernedArtifactPolicy {
        GovernedArtifactPolicy::new(8, 4, 1024, 4096).unwrap()
    }

    fn private_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    #[test]
    fn declarations_reject_traversal_duplicates_and_file_ancestor_conflicts() {
        assert_eq!(
            GovernedArtifactDeclarations::compile(vec!["../escape".to_owned()], policy())
                .err()
                .unwrap()
                .code,
            GovernedArtifactErrorCode::InvalidDeclaration
        );
        assert_eq!(
            GovernedArtifactDeclarations::compile(
                vec!["result.txt".to_owned(), "result.txt".to_owned()],
                policy(),
            )
            .err()
            .unwrap()
            .code,
            GovernedArtifactErrorCode::DuplicateDeclaration
        );
        assert_eq!(
            GovernedArtifactDeclarations::compile(
                vec!["result".to_owned(), "result/detail.txt".to_owned()],
                policy(),
            )
            .err()
            .unwrap()
            .code,
            GovernedArtifactErrorCode::ConflictingDeclaration
        );
        assert_eq!(
            GovernedArtifactDeclarations::compile(
                vec![
                    "a".to_owned(),
                    "a-lexically-between".to_owned(),
                    "a/result.txt".to_owned(),
                ],
                policy(),
            )
            .err()
            .expect("an unrelated lexical neighbor must not hide an ancestor conflict")
            .code,
            GovernedArtifactErrorCode::ConflictingDeclaration
        );
    }

    #[test]
    fn collection_reads_only_exact_new_declared_files_and_counts_missing() {
        let root = private_root();
        let declarations = GovernedArtifactDeclarations::compile(
            vec!["nested/result.txt".to_owned(), "optional.txt".to_owned()],
            policy(),
        )
        .unwrap();
        let authority =
            GovernedArtifactAuthority::bind(root.path(), declarations, policy()).unwrap();
        fs::create_dir(root.path().join("nested")).unwrap();
        #[cfg(unix)]
        fs::set_permissions(
            root.path().join("nested"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::write(root.path().join("nested/result.txt"), b"safe").unwrap();
        fs::write(root.path().join("undeclared.txt"), b"ignored").unwrap();
        let collection = authority.collect_raw().unwrap();
        assert_eq!(collection.declared, 2);
        assert_eq!(collection.missing, 1);
        assert_eq!(collection.files.len(), 1);
        assert_eq!(collection.files[0].relative_path, "nested/result.txt");
        assert_eq!(collection.files[0].bytes.as_slice(), b"safe");
    }

    #[test]
    fn one_redaction_pass_covers_credentials_split_across_output_streams() {
        let redactor =
            CredentialValueRedactor::new(vec![Arc::new(Zeroizing::new(b"credential".to_vec()))])
                .unwrap();
        let raw = GovernedRawBatchExecution::for_test(
            GovernedExecutionTerminal::Success,
            GovernedExecutionDispatch::Dispatched,
            b"creden".to_vec(),
            b"tial".to_vec(),
        );
        let result = GovernedExecutionResultSealer::seal_batch(raw, &redactor, None).unwrap();
        assert_eq!(result.stdout(), b"******");
        assert_eq!(result.stderr(), b"****");
        assert_eq!(
            result.terminal().terminal(),
            GovernedExecutionTerminal::Success
        );
    }

    #[test]
    fn dispatched_failure_marks_collected_artifacts_partial_not_complete() {
        let root = private_root();
        let declarations =
            GovernedArtifactDeclarations::compile(vec!["partial.txt".to_owned()], policy())
                .unwrap();
        let authority =
            GovernedArtifactAuthority::bind(root.path(), declarations, policy()).unwrap();
        fs::write(root.path().join("partial.txt"), b"incomplete").unwrap();
        let redactor = CredentialValueRedactor::new(Vec::new()).unwrap();
        let raw = GovernedRawBatchExecution::for_test(
            GovernedExecutionTerminal::NonZeroExit,
            GovernedExecutionDispatch::Dispatched,
            Vec::new(),
            Vec::new(),
        );
        let result =
            GovernedExecutionResultSealer::seal_batch(raw, &redactor, Some(authority)).unwrap();
        assert_eq!(
            result.artifact_metadata().outcome,
            GovernedArtifactOutcome::Partial
        );
        assert_eq!(result.artifacts().len(), 1);
        assert!(result.retains_artifact_capacity());
        assert_eq!(
            result.terminal().terminal(),
            GovernedExecutionTerminal::NonZeroExit
        );
    }

    #[test]
    fn credential_touching_an_artifact_rejects_all_artifacts_but_keeps_safe_output() {
        let root = private_root();
        let declarations =
            GovernedArtifactDeclarations::compile(vec!["result.txt".to_owned()], policy()).unwrap();
        let authority =
            GovernedArtifactAuthority::bind(root.path(), declarations, policy()).unwrap();
        fs::write(root.path().join("result.txt"), b"tial").unwrap();
        let redactor =
            CredentialValueRedactor::new(vec![Arc::new(Zeroizing::new(b"credential".to_vec()))])
                .unwrap();
        let raw = GovernedRawBatchExecution::for_test(
            GovernedExecutionTerminal::Success,
            GovernedExecutionDispatch::Dispatched,
            b"creden".to_vec(),
            Vec::new(),
        );
        let result =
            GovernedExecutionResultSealer::seal_batch(raw, &redactor, Some(authority)).unwrap();
        assert!(result.artifacts().is_empty());
        assert_eq!(
            result.artifact_metadata().rejection,
            Some(GovernedArtifactErrorCode::CredentialDetected)
        );
        assert_eq!(
            result.terminal().terminal(),
            GovernedExecutionTerminal::ArtifactRejected
        );
        assert_eq!(result.stdout(), b"******");
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_and_hard_link_artifacts_fail_closed_without_path_diagnostics() {
        let outside = private_root();
        let root = private_root();
        let outside_file = outside.path().join("outside.txt");
        fs::write(&outside_file, b"secret").unwrap();
        let declarations =
            GovernedArtifactDeclarations::compile(vec!["result.txt".to_owned()], policy()).unwrap();
        let authority =
            GovernedArtifactAuthority::bind(root.path(), declarations, policy()).unwrap();
        symlink(&outside_file, root.path().join("result.txt")).unwrap();
        let error = authority.collect_raw().err().unwrap();
        assert_eq!(error.code, GovernedArtifactErrorCode::SymlinkRejected);
        assert!(!error
            .to_string()
            .contains(root.path().to_string_lossy().as_ref()));

        let root = private_root();
        let declarations =
            GovernedArtifactDeclarations::compile(vec!["result.txt".to_owned()], policy()).unwrap();
        let authority =
            GovernedArtifactAuthority::bind(root.path(), declarations, policy()).unwrap();
        fs::hard_link(&outside_file, root.path().join("result.txt")).unwrap();
        assert_eq!(
            authority.collect_raw().err().unwrap().code,
            GovernedArtifactErrorCode::HardLinkRejected
        );
    }

    assert_not_impl_any!(GovernedArtifactDeclarations: Clone, fmt::Debug, Serialize);
    assert_not_impl_any!(GovernedArtifactAuthority: Clone, fmt::Debug, Serialize);
    assert_not_impl_any!(GovernedCollectedArtifact: Clone, fmt::Debug, Serialize);
    assert_not_impl_any!(GovernedExecutionResult: Clone, fmt::Debug, Serialize);
}
