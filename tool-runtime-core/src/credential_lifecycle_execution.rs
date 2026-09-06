//! Sealed binding for governed CLI authentication lifecycle execution.
//!
//! Phase 4E joins the immutable lifecycle command authority from Phase 4A to the
//! metadata-only injection plan from Phase 3 and one exact scoped auth directory. The
//! resulting invocation is non-cloneable and non-serializable. Physical paths exist only
//! inside a higher-ranked callback, are revalidated before and after it, and are included
//! in value-aware output redaction. This module deliberately does not spawn a process;
//! Magician owns the process tree and must finish/reap it inside the callback.

use std::{
    collections::BTreeMap,
    error::Error,
    ffi::{OsStr, OsString},
    fmt, fs,
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(unix)]
use std::os::unix::{
    ffi::{OsStrExt, OsStringExt},
    fs::{FileExt, MetadataExt, PermissionsExt},
};

use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    credential_filesystem::CredentialProfileDirectory,
    credential_injection::{ChildEnvironmentBaseline, ChildEnvironmentVariable},
    credential_lifecycle::{CredentialLifecycleOperation, CredentialLifecyclePlan},
    credential_lifecycle_coordinator::CredentialLifecyclePendingKind,
    credential_materialization::{
        ChildEnvironmentValues, CredentialRedactedOutput, CredentialValueRedactor,
        MAX_CHILD_ENVIRONMENT_TOTAL_BYTES, MAX_CHILD_ENVIRONMENT_VALUE_BYTES,
    },
    manifest::{CliInteraction, InjectionSource, InjectionTarget},
    manifest_validation::ValidatedSkillRuntimeContract,
    scoped_paths::{
        CredentialProfilePathAuthority, ScopedPath, ScopedPathComponent, ScopedPathKind,
    },
};

pub const CREDENTIAL_LIFECYCLE_EXECUTION_V1: &str =
    "tool-runtime.credential-lifecycle-execution.v1";
pub const MAX_LIFECYCLE_EXECUTABLE_SEARCH_ENTRIES: usize = 128;
pub const MAX_LIFECYCLE_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_LIFECYCLE_INTERACTION_INPUT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialLifecycleExecutionBindingErrorCode {
    PlanMismatch,
    DirectoryTargetMismatch,
    DirectoryUnavailable,
    BaselineMismatch,
    EnvironmentLimitExceeded,
    UnsupportedInjection,
    ExecutableNotFound,
    ExecutableUnsafe,
    ExecutableChanged,
    OutputRedactionFailed,
    InteractionInputInvalid,
}

/// Stable path-, argv-, output-, and value-free binding diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CredentialLifecycleExecutionBindingError {
    pub code: CredentialLifecycleExecutionBindingErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl CredentialLifecycleExecutionBindingError {
    const fn new(
        code: CredentialLifecycleExecutionBindingErrorCode,
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

impl fmt::Display for CredentialLifecycleExecutionBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for CredentialLifecycleExecutionBindingError {}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ExecutableIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    change_time_secs: i64,
    #[cfg(unix)]
    change_time_nanos: i64,
    length: u64,
}

struct ResolvedLifecycleExecutable {
    path: PathBuf,
    identity: ExecutableIdentity,
    content_digest: [u8; 32],
    file: File,
}

impl ResolvedLifecycleExecutable {
    fn resolve(
        executable: &str,
        environment: &BTreeMap<String, Zeroizing<Vec<u8>>>,
    ) -> Result<Self, CredentialLifecycleExecutionBindingError> {
        if executable.is_empty()
            || executable.as_bytes().contains(&b'/')
            || executable.as_bytes().contains(&b'\\')
        {
            return Err(executable_unsafe());
        }
        let path = environment
            .get(ChildEnvironmentVariable::Path.as_str())
            .ok_or_else(executable_not_found)?;
        let path = bytes_to_os_string(path)?;
        for (index, directory) in std::env::split_paths(&path).enumerate() {
            if index >= MAX_LIFECYCLE_EXECUTABLE_SEARCH_ENTRIES {
                return Err(executable_unsafe());
            }
            if !directory.is_absolute() {
                return Err(executable_unsafe());
            }
            let candidate = directory.join(executable);
            let canonical = fs::canonicalize(&candidate).map_err(|_| executable_unsafe())?;
            if !canonical.is_absolute() {
                return Err(executable_unsafe());
            }
            let file = match File::open(&canonical) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(executable_unsafe()),
            };
            let metadata = file.metadata().map_err(|_| executable_unsafe())?;
            let identity = executable_identity(&metadata)?;
            let content_digest = digest_open_file(&file, identity.length)?;
            let resolved = Self {
                path: canonical,
                identity,
                content_digest,
                file,
            };
            resolved.revalidate()?;
            return Ok(resolved);
        }
        Err(executable_not_found())
    }

    fn revalidate(&self) -> Result<(), CredentialLifecycleExecutionBindingError> {
        let open = self.file.metadata().map_err(|_| executable_changed())?;
        if executable_identity(&open)? != self.identity {
            return Err(executable_changed());
        }
        let metadata = fs::metadata(&self.path).map_err(|_| executable_changed())?;
        let current = executable_identity(&metadata)?;
        if current != self.identity {
            return Err(executable_changed());
        }
        Ok(())
    }

    fn launch_handle(
        &self,
    ) -> Result<CredentialLifecycleExecutable, CredentialLifecycleExecutionBindingError> {
        let snapshot = tempfile::Builder::new()
            .prefix("magician-lifecycle-executable-")
            .tempdir()
            .map_err(|_| executable_changed())?;
        let file_name = self.path.file_name().ok_or_else(executable_changed)?;
        let path = snapshot.path().join(file_name);
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| executable_changed())?;
        let copied_digest =
            copy_and_digest_open_file(&self.file, self.identity.length, &mut output)?;
        if copied_digest != self.content_digest {
            return Err(executable_changed());
        }
        output.flush().map_err(|_| executable_changed())?;
        #[cfg(unix)]
        fs::set_permissions(
            &path,
            fs::Permissions::from_mode(self.identity.mode & 0o777),
        )
        .map_err(|_| executable_changed())?;
        drop(output);
        Ok(CredentialLifecycleExecutable {
            path,
            _snapshot: snapshot,
        })
    }
}

/// Move-only launch authority for an exact private snapshot of the executable bytes
/// validated at bind time.
pub struct CredentialLifecycleExecutable {
    path: PathBuf,
    _snapshot: TempDir,
}

impl CredentialLifecycleExecutable {
    pub fn as_path(&self) -> &Path {
        &self.path
    }
}

/// One lifecycle invocation bound to an exact plan, exact executable identity, and exact
/// auth directory. It intentionally has no `Clone`, `Debug`, or serialization surface.
pub struct CredentialLifecycleInvocation {
    schema_version: &'static str,
    plan: CredentialLifecyclePlan,
    executable: ResolvedLifecycleExecutable,
    directory: ScopedPath,
    environment: Vec<(String, Zeroizing<Vec<u8>>)>,
    profile_authority: Option<CredentialProfilePathAuthority>,
    profile_directories: Vec<CredentialProfileDirectory>,
    redactor: CredentialValueRedactor,
}

impl CredentialLifecycleInvocation {
    pub fn bind(
        validated: ValidatedSkillRuntimeContract<'_>,
        plan: CredentialLifecyclePlan,
        directory: ScopedPath,
        baseline: &ChildEnvironmentBaseline,
        baseline_values: ChildEnvironmentValues,
    ) -> Result<Self, CredentialLifecycleExecutionBindingError> {
        validate_plan_binding(validated, &plan, &directory)?;
        let (provided_baseline, baseline_values) = baseline_values.into_parts();
        if provided_baseline != *baseline.variables() {
            return Err(baseline_mismatch());
        }
        let executable = ResolvedLifecycleExecutable::resolve(plan.executable(), &baseline_values)?;

        let profile_authority = match (
            plan.selected_profile_key(),
            plan.selected_profile_revision(),
        ) {
            (Some(key), Some(revision)) => Some(
                directory
                    .authorize_lifecycle_profile(key, revision)
                    .map_err(|_| directory_unavailable())?,
            ),
            (None, None) => None,
            _ => return Err(plan_mismatch()),
        };

        let mut environment = baseline_values.into_iter().collect::<BTreeMap<_, _>>();
        let mut profile_directories = Vec::new();
        let mut sensitive_patterns = Vec::new();
        for binding in &validated.contract().auth.injections {
            let InjectionTarget::Environment { name } = &binding.target else {
                return Err(unsupported_injection());
            };
            let value = match &binding.source {
                InjectionSource::ProfileAuthRoot { path } => {
                    let path = path
                        .iter()
                        .cloned()
                        .map(ScopedPathComponent::new)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| plan_mismatch())?;
                    if let Some(authority) = profile_authority.as_ref() {
                        let bound = CredentialProfileDirectory::resolve(
                            authority,
                            plan.scope(),
                            plan.selected_profile_key().ok_or_else(plan_mismatch)?,
                            plan.selected_profile_revision().ok_or_else(plan_mismatch)?,
                            &path,
                        )
                        .map_err(|_| directory_unavailable())?;
                        let bytes = path_bytes(
                            bound
                                .revalidated_path()
                                .map_err(|_| directory_unavailable())?,
                        )?;
                        let value = Zeroizing::new(bytes);
                        sensitive_patterns.push(Arc::new(value.clone()));
                        profile_directories.push(bound);
                        value
                    } else {
                        if !path.is_empty() || directory.kind() != ScopedPathKind::Auth {
                            return Err(unsupported_injection());
                        }
                        let value = Zeroizing::new(path_bytes(
                            directory
                                .revalidated_path()
                                .map_err(|_| directory_unavailable())?,
                        )?);
                        sensitive_patterns.push(Arc::new(value.clone()));
                        value
                    }
                },
                InjectionSource::ProfileAlias => Zeroizing::new(
                    plan.selected_profile_key()
                        .ok_or_else(plan_mismatch)?
                        .alias
                        .as_str()
                        .as_bytes()
                        .to_vec(),
                ),
                InjectionSource::ExpectedIdentity => Zeroizing::new(
                    plan.expected_identity()
                        .ok_or_else(plan_mismatch)?
                        .as_str()
                        .as_bytes()
                        .to_vec(),
                ),
                InjectionSource::Secret { .. } => {
                    return Err(unsupported_injection());
                },
            };
            if environment.insert(name.clone(), value).is_some() {
                return Err(baseline_mismatch());
            }
        }
        validate_environment_limits(&environment)?;
        let redactor = CredentialValueRedactor::new(sensitive_patterns)
            .map_err(|_| output_redaction_failed())?;
        Ok(Self {
            schema_version: CREDENTIAL_LIFECYCLE_EXECUTION_V1,
            plan,
            executable,
            directory,
            environment: environment.into_iter().collect(),
            profile_authority,
            profile_directories,
            redactor,
        })
    }

    pub fn schema_version(&self) -> &'static str {
        self.schema_version
    }

    pub fn operation(&self) -> CredentialLifecycleOperation {
        self.plan.operation()
    }

    pub fn matches_plan(&self, plan: &CredentialLifecyclePlan) -> bool {
        &self.plan == plan
    }

    /// Revalidate every authority, lend a complete process specification to one trusted
    /// product callback, and revalidate again before releasing the sealed invocation.
    /// The callback must start, terminate, and reap the entire process tree before return.
    pub fn with_bound_process<T>(
        &self,
        consumer: impl for<'call> FnOnce(CredentialLifecycleBoundProcess<'call>) -> T,
    ) -> Result<T, CredentialLifecycleExecutionBindingError> {
        self.revalidate()?;
        let bound = CredentialLifecycleBoundProcess { invocation: self };
        let result = consumer(bound);
        self.revalidate()?;
        Ok(result)
    }

    fn revalidate(&self) -> Result<(), CredentialLifecycleExecutionBindingError> {
        self.executable.revalidate()?;
        self.directory
            .revalidate()
            .map_err(|_| directory_unavailable())?;
        if let Some(authority) = &self.profile_authority {
            authority
                .revalidate()
                .map_err(|_| directory_unavailable())?;
        }
        for directory in &self.profile_directories {
            directory
                .revalidated_path()
                .map_err(|_| directory_unavailable())?;
        }
        Ok(())
    }
}

/// Borrow-scoped process specification. Debugging and serialization are intentionally
/// absent because environment values may contain physical credential-directory paths.
pub struct CredentialLifecycleBoundProcess<'call> {
    invocation: &'call CredentialLifecycleInvocation,
}

impl CredentialLifecycleBoundProcess<'_> {
    pub fn launch_executable(
        &self,
    ) -> Result<CredentialLifecycleExecutable, CredentialLifecycleExecutionBindingError> {
        self.invocation.executable.launch_handle()
    }

    pub fn args(&self) -> &[String] {
        self.invocation.plan.args()
    }

    pub fn interaction(&self) -> CliInteraction {
        self.invocation.plan.interaction()
    }

    pub fn timeout_secs(&self) -> Option<u32> {
        self.invocation.plan.timeout_secs()
    }

    pub fn environment_len(&self) -> usize {
        self.invocation.environment.len()
    }

    pub fn with_environment_entry<T>(
        &self,
        index: usize,
        consumer: impl for<'value> FnOnce(&'value str, &'value OsStr) -> T,
    ) -> Result<Option<T>, CredentialLifecycleExecutionBindingError> {
        let Some((name, value)) = self.invocation.environment.get(index) else {
            return Ok(None);
        };
        Ok(Some(consumer(name, bytes_as_os_str(value)?)))
    }

    pub fn redact_output(
        &self,
        output: &[u8],
    ) -> Result<CredentialRedactedOutput, CredentialLifecycleExecutionBindingError> {
        self.invocation
            .redactor
            .redact(output)
            .map_err(|_| output_redaction_failed())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialLifecycleOutputChannel {
    Stdout,
    Stderr,
    Pty,
}

/// Borrowed sensitive process output presented only to the product interaction bridge.
/// It has no debug or serialization surface.
pub struct CredentialLifecycleSensitiveOutput<'a> {
    channel: CredentialLifecycleOutputChannel,
    bytes: &'a [u8],
}

impl<'a> CredentialLifecycleSensitiveOutput<'a> {
    pub fn new(channel: CredentialLifecycleOutputChannel, bytes: &'a [u8]) -> Self {
        Self { channel, bytes }
    }

    pub fn channel(&self) -> CredentialLifecycleOutputChannel {
        self.channel
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }
}

/// Owned user input that is zeroized on drop and can be borrowed only for the immediate
/// process write. It intentionally has no clone, debug, or serialization surface.
pub struct CredentialLifecycleSensitiveInput(Zeroizing<Vec<u8>>);

impl CredentialLifecycleSensitiveInput {
    pub fn new(value: Vec<u8>) -> Result<Self, CredentialLifecycleExecutionBindingError> {
        let value = Zeroizing::new(value);
        if value.is_empty()
            || value.len() > MAX_LIFECYCLE_INTERACTION_INPUT_BYTES
            || value.contains(&0)
        {
            return Err(interaction_input_invalid());
        }
        Ok(Self(value))
    }

    pub fn with_bytes<T>(&self, consumer: impl for<'value> FnOnce(&'value [u8]) -> T) -> T {
        consumer(&self.0)
    }
}

impl Drop for CredentialLifecycleSensitiveInput {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub enum CredentialLifecycleInteractionAction {
    Continue,
    Await {
        pending: CredentialLifecyclePendingKind,
    },
    ProvideInput {
        pending: CredentialLifecyclePendingKind,
        input: CredentialLifecycleSensitiveInput,
    },
    Cancel,
}

/// Product-owned bridge for browser callbacks, device codes, OTPs, QR flows, and other
/// operator interaction. Sensitive provider output/input never enters coordinator state.
pub trait CredentialLifecycleInteractionBridge: Send {
    fn on_output(
        &mut self,
        output: CredentialLifecycleSensitiveOutput<'_>,
    ) -> Result<CredentialLifecycleInteractionAction, CredentialLifecycleExecutionBindingError>;

    fn on_idle(
        &mut self,
    ) -> Result<CredentialLifecycleInteractionAction, CredentialLifecycleExecutionBindingError>
    {
        Ok(CredentialLifecycleInteractionAction::Continue)
    }
}

fn validate_plan_binding(
    validated: ValidatedSkillRuntimeContract<'_>,
    plan: &CredentialLifecyclePlan,
    directory: &ScopedPath,
) -> Result<(), CredentialLifecycleExecutionBindingError> {
    if !plan.matches_validated_contract(validated) {
        return Err(plan_mismatch());
    }
    let target_matches = match plan.selected_profile_key() {
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
    if !target_matches {
        return Err(directory_target_mismatch());
    }
    directory.revalidate().map_err(|_| directory_unavailable())
}

fn validate_environment_limits(
    environment: &BTreeMap<String, Zeroizing<Vec<u8>>>,
) -> Result<(), CredentialLifecycleExecutionBindingError> {
    let mut total = 0usize;
    for (name, value) in environment {
        if value.len() > MAX_CHILD_ENVIRONMENT_VALUE_BYTES {
            return Err(environment_limit_exceeded());
        }
        total = total
            .checked_add(name.len())
            .and_then(|current| current.checked_add(value.len()))
            .ok_or_else(environment_limit_exceeded)?;
        if total > MAX_CHILD_ENVIRONMENT_TOTAL_BYTES {
            return Err(environment_limit_exceeded());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn executable_identity(
    metadata: &fs::Metadata,
) -> Result<ExecutableIdentity, CredentialLifecycleExecutionBindingError> {
    let mode = metadata.permissions().mode();
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_LIFECYCLE_EXECUTABLE_BYTES
        || mode & 0o111 == 0
        || mode & 0o022 != 0
    {
        return Err(executable_unsafe());
    }
    Ok(ExecutableIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode,
        change_time_secs: metadata.ctime(),
        change_time_nanos: metadata.ctime_nsec(),
        length: metadata.len(),
    })
}

#[cfg(not(unix))]
fn executable_identity(
    metadata: &fs::Metadata,
) -> Result<ExecutableIdentity, CredentialLifecycleExecutionBindingError> {
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_LIFECYCLE_EXECUTABLE_BYTES
    {
        return Err(executable_unsafe());
    }
    Ok(ExecutableIdentity {
        length: metadata.len(),
    })
}

fn digest_open_file(
    file: &File,
    expected_length: u64,
) -> Result<[u8; 32], CredentialLifecycleExecutionBindingError> {
    let mut sink = std::io::sink();
    copy_and_digest_open_file(file, expected_length, &mut sink)
}

#[cfg(unix)]
fn copy_and_digest_open_file(
    file: &File,
    expected_length: u64,
    output: &mut impl Write,
) -> Result<[u8; 32], CredentialLifecycleExecutionBindingError> {
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut offset = 0u64;
    while offset < expected_length {
        let remaining = usize::try_from((expected_length - offset).min(buffer.len() as u64))
            .map_err(|_| executable_changed())?;
        let read = file
            .read_at(&mut buffer[..remaining], offset)
            .map_err(|_| executable_changed())?;
        if read == 0 {
            return Err(executable_changed());
        }
        output
            .write_all(&buffer[..read])
            .map_err(|_| executable_changed())?;
        digest.update(&buffer[..read]);
        offset = offset
            .checked_add(read as u64)
            .ok_or_else(executable_changed)?;
    }
    let mut extra = [0u8; 1];
    if file
        .read_at(&mut extra, expected_length)
        .map_err(|_| executable_changed())?
        != 0
    {
        return Err(executable_changed());
    }
    Ok(digest.finalize().into())
}

#[cfg(not(unix))]
fn copy_and_digest_open_file(
    file: &File,
    expected_length: u64,
    output: &mut impl Write,
) -> Result<[u8; 32], CredentialLifecycleExecutionBindingError> {
    use std::io::{Read, Seek, SeekFrom};

    let mut source = file.try_clone().map_err(|_| executable_changed())?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| executable_changed())?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut copied = 0u64;
    loop {
        let read = source.read(&mut buffer).map_err(|_| executable_changed())?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(read as u64)
            .ok_or_else(executable_changed)?;
        if copied > expected_length {
            return Err(executable_changed());
        }
        output
            .write_all(&buffer[..read])
            .map_err(|_| executable_changed())?;
        digest.update(&buffer[..read]);
    }
    if copied != expected_length {
        return Err(executable_changed());
    }
    Ok(digest.finalize().into())
}

#[cfg(unix)]
fn bytes_to_os_string(value: &[u8]) -> Result<OsString, CredentialLifecycleExecutionBindingError> {
    if value.contains(&0) {
        return Err(baseline_mismatch());
    }
    Ok(OsString::from_vec(value.to_vec()))
}

#[cfg(not(unix))]
fn bytes_to_os_string(value: &[u8]) -> Result<OsString, CredentialLifecycleExecutionBindingError> {
    String::from_utf8(value.to_vec())
        .map(OsString::from)
        .map_err(|_| baseline_mismatch())
}

#[cfg(unix)]
fn bytes_as_os_str(value: &[u8]) -> Result<&OsStr, CredentialLifecycleExecutionBindingError> {
    if value.contains(&0) {
        return Err(baseline_mismatch());
    }
    Ok(OsStr::from_bytes(value))
}

#[cfg(not(unix))]
fn bytes_as_os_str(value: &[u8]) -> Result<&OsStr, CredentialLifecycleExecutionBindingError> {
    std::str::from_utf8(value)
        .map(OsStr::new)
        .map_err(|_| baseline_mismatch())
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> Result<Vec<u8>, CredentialLifecycleExecutionBindingError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.contains(&0) {
        return Err(directory_unavailable());
    }
    Ok(bytes.to_vec())
}

#[cfg(not(unix))]
fn path_bytes(path: &Path) -> Result<Vec<u8>, CredentialLifecycleExecutionBindingError> {
    path.to_str()
        .filter(|value| !value.is_empty())
        .map(|value| value.as_bytes().to_vec())
        .ok_or_else(directory_unavailable)
}

const fn plan_mismatch() -> CredentialLifecycleExecutionBindingError {
    CredentialLifecycleExecutionBindingError::new(
        CredentialLifecycleExecutionBindingErrorCode::PlanMismatch,
        "lifecycle_execution.plan",
        "the lifecycle and injection plans do not describe the same exact target",
    )
}

const fn directory_target_mismatch() -> CredentialLifecycleExecutionBindingError {
    CredentialLifecycleExecutionBindingError::new(
        CredentialLifecycleExecutionBindingErrorCode::DirectoryTargetMismatch,
        "lifecycle_execution.directory",
        "the scoped authentication directory does not belong to the lifecycle target",
    )
}

const fn directory_unavailable() -> CredentialLifecycleExecutionBindingError {
    CredentialLifecycleExecutionBindingError::new(
        CredentialLifecycleExecutionBindingErrorCode::DirectoryUnavailable,
        "lifecycle_execution.directory",
        "the scoped authentication directory could not be revalidated",
    )
}

const fn baseline_mismatch() -> CredentialLifecycleExecutionBindingError {
    CredentialLifecycleExecutionBindingError::new(
        CredentialLifecycleExecutionBindingErrorCode::BaselineMismatch,
        "lifecycle_execution.environment",
        "the clean child environment does not match the compiled baseline",
    )
}

const fn environment_limit_exceeded() -> CredentialLifecycleExecutionBindingError {
    CredentialLifecycleExecutionBindingError::new(
        CredentialLifecycleExecutionBindingErrorCode::EnvironmentLimitExceeded,
        "lifecycle_execution.environment",
        "the clean lifecycle environment exceeded its fixed byte limit",
    )
}

const fn unsupported_injection() -> CredentialLifecycleExecutionBindingError {
    CredentialLifecycleExecutionBindingError::new(
        CredentialLifecycleExecutionBindingErrorCode::UnsupportedInjection,
        "lifecycle_execution.injection",
        "the lifecycle executor accepts only declared local environment projections",
    )
}

const fn executable_not_found() -> CredentialLifecycleExecutionBindingError {
    CredentialLifecycleExecutionBindingError::new(
        CredentialLifecycleExecutionBindingErrorCode::ExecutableNotFound,
        "lifecycle_execution.executable",
        "the declared executable was not found in the clean runtime PATH",
    )
}

const fn executable_unsafe() -> CredentialLifecycleExecutionBindingError {
    CredentialLifecycleExecutionBindingError::new(
        CredentialLifecycleExecutionBindingErrorCode::ExecutableUnsafe,
        "lifecycle_execution.executable",
        "the declared executable did not resolve to a safe fixed executable",
    )
}

const fn executable_changed() -> CredentialLifecycleExecutionBindingError {
    CredentialLifecycleExecutionBindingError::new(
        CredentialLifecycleExecutionBindingErrorCode::ExecutableChanged,
        "lifecycle_execution.executable",
        "the resolved executable changed before lifecycle execution completed",
    )
}

const fn output_redaction_failed() -> CredentialLifecycleExecutionBindingError {
    CredentialLifecycleExecutionBindingError::new(
        CredentialLifecycleExecutionBindingErrorCode::OutputRedactionFailed,
        "lifecycle_execution.output",
        "lifecycle process output could not be safely redacted",
    )
}

const fn interaction_input_invalid() -> CredentialLifecycleExecutionBindingError {
    CredentialLifecycleExecutionBindingError::new(
        CredentialLifecycleExecutionBindingErrorCode::InteractionInputInvalid,
        "lifecycle_execution.interaction_input",
        "interactive credential input must be non-empty, bounded, and contain no NUL byte",
    )
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        collections::BTreeSet,
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
    };

    use static_assertions::assert_not_impl_any;

    use super::*;
    use crate::{
        credential_injection::ChildEnvironmentBaseline,
        credential_lifecycle::{CredentialLifecycleOperation, CredentialLifecyclePlan},
        credential_profiles::{
            CreateCredentialProfileReference, CredentialProfileAvailability,
            CredentialProfileBinding, CredentialProfileError, CredentialProfileKey,
            CredentialProfileMetadata, CredentialProfileRegistry,
            CredentialProfileRegistrySnapshot, CredentialProfileRevision, CredentialProfileStatus,
            CredentialScope, ExpectedCredentialIdentity, SetCredentialProfileDisabled,
            UpdateCredentialProfileMetadata,
        },
        manifest::{
            AuthContract, AuthKind, AuthLifecycle, AuthRequirement, AuthState, AuthStorage,
            IdentityContract, IdentitySelector, InjectionBinding, LifecycleHook,
            LifecycleJsonPredicate, LifecycleJsonScalar, LifecycleObservedAuthState,
            LifecycleStatusObservation, LifecycleStatusOutputFormat, LifecycleStatusRule,
            ProfileSelection, RuntimeLimits, RuntimeProtocol, RuntimeRequirements,
            SkillRuntimeContract, SkillRuntimeContractVersion, StdinContract,
            WorkingDirectoryContract,
        },
        manifest_validation::validate_skill_runtime_contract,
        scoped_paths::{ScopedPathAuthority, ScopedPathComponent},
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct TestRegistry {
        profile: CredentialProfileStatus,
    }

    impl CredentialProfileRegistry for TestRegistry {
        fn snapshot(
            &self,
            scope: &CredentialScope,
        ) -> Result<CredentialProfileRegistrySnapshot, CredentialProfileError> {
            CredentialProfileRegistrySnapshot::new(scope.clone(), vec![self.profile.clone()])
        }

        fn status(
            &self,
            key: &CredentialProfileKey,
        ) -> Result<Option<CredentialProfileStatus>, CredentialProfileError> {
            Ok((self.profile.key() == key).then(|| self.profile.clone()))
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

    struct Fixture {
        root: PathBuf,
        scopes_root: PathBuf,
        bin_root: PathBuf,
        key: CredentialProfileKey,
    }

    impl Fixture {
        fn new() -> Self {
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = fs::canonicalize(std::env::temp_dir())
                .expect("temp root")
                .join(format!(
                    "tool-runtime-lifecycle-execution-{}-{sequence}",
                    std::process::id()
                ));
            let scopes_root = root.join("scopes");
            let bin_root = root.join("bin");
            let scope = CredentialScope::new("owner", "default").expect("scope");
            let key = CredentialProfileKey::new(
                scope.clone(),
                "google-workspace",
                "work",
                CredentialProfileBinding::Provider,
            )
            .expect("key");
            let workspace = scopes_root
                .join(scope.principal.as_str())
                .join(scope.workspace.as_str());
            fs::create_dir_all(workspace.join("auth").join("work").join("cloudsdk"))
                .expect("auth tree");
            fs::create_dir(&bin_root).expect("bin root");
            set_mode(&root, 0o700);
            set_mode(&scopes_root, 0o755);
            set_mode(&scopes_root.join(scope.principal.as_str()), 0o755);
            set_mode(&workspace, 0o755);
            set_mode(&workspace.join("auth"), 0o700);
            set_mode(&workspace.join("auth").join("work"), 0o700);
            set_mode(&workspace.join("auth").join("work").join("cloudsdk"), 0o700);
            set_mode(&bin_root, 0o700);
            let fixture = Self {
                root,
                scopes_root,
                bin_root,
                key,
            };
            fixture.write_executable("#!/bin/sh\nexit 0\n");
            fixture
        }

        fn write_executable(&self, body: &str) {
            let executable = self.bin_root.join("fake-cli");
            fs::write(&executable, body).expect("fake executable");
            set_mode(&executable, 0o755);
        }

        fn replace_executable(&self, body: &str) {
            let executable = self.bin_root.join("fake-cli");
            fs::remove_file(&executable).expect("remove executable");
            self.write_executable(body);
        }

        fn overwrite_executable(&self, body: &str) {
            let executable = self.bin_root.join("fake-cli");
            fs::write(&executable, body).expect("overwrite executable");
            set_mode(&executable, 0o755);
        }

        fn profile_status(&self, state: AuthState) -> CredentialProfileStatus {
            let metadata = CredentialProfileMetadata::new(
                self.key.clone(),
                Some(
                    ExpectedCredentialIdentity::new("work@example.com").expect("expected identity"),
                ),
                true,
                CredentialProfileAvailability::Enabled,
                CredentialProfileRevision::new(7).expect("revision"),
            )
            .expect("metadata");
            CredentialProfileStatus::new(metadata, state).expect("status")
        }

        fn profile_root(&self) -> ScopedPath {
            ScopedPathAuthority::open(&self.scopes_root)
                .expect("authority")
                .resolve_profile_root(
                    &self.key,
                    ScopedPathComponent::new("work").expect("component"),
                )
                .expect("profile root")
        }

        fn environment(&self, baseline: &ChildEnvironmentBaseline) -> ChildEnvironmentValues {
            let mut values = ChildEnvironmentValues::new(baseline);
            values
                .provide(
                    ChildEnvironmentVariable::Path,
                    self.bin_root.as_os_str().as_bytes().to_vec(),
                )
                .expect("PATH");
            values
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("mode");
    }

    fn contract(selection: ProfileSelection) -> SkillRuntimeContract {
        SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires: RuntimeRequirements {
                bins: BTreeSet::from(["fake-cli".to_owned()]),
                entrypoint: Default::default(),
                environment: Default::default(),
            },
            runtime: RuntimeProtocol::Cli {
                command_prefix: vec!["mail".to_owned()],
                interaction: CliInteraction::Batch,
                stdin: StdinContract::default(),
                working_directory: WorkingDirectoryContract::default(),
                limits: RuntimeLimits::default(),
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
                injections: vec![
                    InjectionBinding {
                        source: InjectionSource::ProfileAuthRoot { path: Vec::new() },
                        target: InjectionTarget::Environment {
                            name: "GWS_CONFIG_DIR".to_owned(),
                        },
                    },
                    InjectionBinding {
                        source: InjectionSource::ProfileAuthRoot {
                            path: vec!["cloudsdk".to_owned()],
                        },
                        target: InjectionTarget::Environment {
                            name: "CLOUDSDK_CONFIG".to_owned(),
                        },
                    },
                ],
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
                    refresh: None,
                },
                identity: IdentityContract::ProfileExpected {
                    selector: IdentitySelector::JsonPointer {
                        pointer: "/account/email".to_owned(),
                    },
                },
                ..AuthContract::default()
            },
            policy_floor: Default::default(),
        }
    }

    fn plan(
        contract: &SkillRuntimeContract,
        profile: CredentialProfileStatus,
        operation: CredentialLifecycleOperation,
    ) -> CredentialLifecyclePlan {
        let validated = validate_skill_runtime_contract(contract).expect("validated contract");
        let registry = TestRegistry {
            profile: profile.clone(),
        };
        CredentialLifecyclePlan::for_profile(&registry, validated, profile.key(), operation)
            .expect("lifecycle plan")
    }

    #[test]
    fn missing_profile_can_bind_status_without_weakening_ready_only_tool_authority() {
        let fixture = Fixture::new();
        let contract = contract(ProfileSelection::Selectable {
            default: Some("work".to_owned()),
        });
        let lifecycle = plan(
            &contract,
            fixture.profile_status(AuthState::Missing),
            CredentialLifecycleOperation::Status,
        );
        let validated = validate_skill_runtime_contract(&contract).expect("contract");
        let baseline = ChildEnvironmentBaseline::portable_cli();
        let invocation = CredentialLifecycleInvocation::bind(
            validated,
            lifecycle.clone(),
            fixture.profile_root(),
            &baseline,
            fixture.environment(&baseline),
        )
        .expect("missing-profile status binding");

        assert!(invocation.matches_plan(&lifecycle));
        invocation
            .with_bound_process(|bound| {
                assert_eq!(bound.args(), ["auth", "status", "--json"]);
                assert_eq!(bound.interaction(), CliInteraction::Batch);
                assert_eq!(bound.environment_len(), 3);
            })
            .expect("bound callback");
    }

    #[test]
    fn physical_profile_paths_are_redacted_before_leaving_the_bound_callback() {
        let fixture = Fixture::new();
        let contract = contract(ProfileSelection::Fixed {
            alias: "work".to_owned(),
        });
        let lifecycle = plan(
            &contract,
            fixture.profile_status(AuthState::Expired),
            CredentialLifecycleOperation::Status,
        );
        let validated = validate_skill_runtime_contract(&contract).expect("contract");
        let baseline = ChildEnvironmentBaseline::portable_cli();
        let profile = fixture.profile_root();
        let profile_path = profile
            .revalidated_path()
            .expect("profile path")
            .as_os_str()
            .as_bytes()
            .to_vec();
        let invocation = CredentialLifecycleInvocation::bind(
            validated,
            lifecycle,
            profile,
            &baseline,
            fixture.environment(&baseline),
        )
        .expect("binding");
        let redacted = invocation
            .with_bound_process(|bound| {
                let mut output = b"failure in ".to_vec();
                output.extend_from_slice(&profile_path);
                bound.redact_output(&output).expect("redaction")
            })
            .expect("callback");
        assert!(!redacted
            .as_bytes()
            .windows(profile_path.len())
            .any(|window| window == profile_path));
    }

    #[test]
    fn executable_replacement_is_detected_before_callback_entry() {
        let fixture = Fixture::new();
        let contract = contract(ProfileSelection::Fixed {
            alias: "work".to_owned(),
        });
        let lifecycle = plan(
            &contract,
            fixture.profile_status(AuthState::Missing),
            CredentialLifecycleOperation::Status,
        );
        let validated = validate_skill_runtime_contract(&contract).expect("contract");
        let baseline = ChildEnvironmentBaseline::portable_cli();
        let invocation = CredentialLifecycleInvocation::bind(
            validated,
            lifecycle,
            fixture.profile_root(),
            &baseline,
            fixture.environment(&baseline),
        )
        .expect("binding");
        fixture.replace_executable("#!/bin/sh\nexit 1\n");
        let error = invocation
            .with_bound_process(|_| ())
            .expect_err("replacement must fail");
        assert_eq!(
            error.code,
            CredentialLifecycleExecutionBindingErrorCode::ExecutableChanged
        );
    }

    #[test]
    fn launched_snapshot_cannot_be_redirected_by_a_path_replacement() {
        let fixture = Fixture::new();
        fixture.replace_executable("#!/bin/sh\nprintf 'validated-inode'\n");
        let contract = contract(ProfileSelection::Fixed {
            alias: "work".to_owned(),
        });
        let lifecycle = plan(
            &contract,
            fixture.profile_status(AuthState::Missing),
            CredentialLifecycleOperation::Status,
        );
        let validated = validate_skill_runtime_contract(&contract).expect("contract");
        let baseline = ChildEnvironmentBaseline::portable_cli();
        let invocation = CredentialLifecycleInvocation::bind(
            validated,
            lifecycle,
            fixture.profile_root(),
            &baseline,
            fixture.environment(&baseline),
        )
        .expect("binding");
        let mut observed = Vec::new();
        let error = invocation
            .with_bound_process(|bound| {
                let executable = bound.launch_executable().expect("launch handle");
                fixture.replace_executable("#!/bin/sh\nprintf 'replacement-path'\n");
                observed = Command::new(executable.as_path())
                    .output()
                    .expect("snapshot-bound launch")
                    .stdout;
            })
            .expect_err("path replacement must still be reported");

        assert_eq!(observed, b"validated-inode");
        assert_eq!(
            error.code,
            CredentialLifecycleExecutionBindingErrorCode::ExecutableChanged
        );
    }

    #[test]
    fn in_place_content_drift_is_rejected_before_a_snapshot_can_launch() {
        let fixture = Fixture::new();
        fixture.replace_executable("#!/bin/sh\nprintf 'validated-inode'\n");
        let contract = contract(ProfileSelection::Fixed {
            alias: "work".to_owned(),
        });
        let lifecycle = plan(
            &contract,
            fixture.profile_status(AuthState::Missing),
            CredentialLifecycleOperation::Status,
        );
        let validated = validate_skill_runtime_contract(&contract).expect("contract");
        let baseline = ChildEnvironmentBaseline::portable_cli();
        let invocation = CredentialLifecycleInvocation::bind(
            validated,
            lifecycle,
            fixture.profile_root(),
            &baseline,
            fixture.environment(&baseline),
        )
        .expect("binding");
        let mut launch_error = None;
        let completion = invocation.with_bound_process(|bound| {
            fixture.overwrite_executable("#!/bin/sh\nprintf 'tampered-inode!'\n");
            launch_error = match bound.launch_executable() {
                Ok(_) => panic!("changed bytes must not mint launch authority"),
                Err(error) => Some(error),
            };
        });

        assert_eq!(
            launch_error.expect("launch failure").code,
            CredentialLifecycleExecutionBindingErrorCode::ExecutableChanged
        );
        assert_eq!(
            completion
                .expect_err("post-callback revalidation must also fail")
                .code,
            CredentialLifecycleExecutionBindingErrorCode::ExecutableChanged
        );
    }

    #[test]
    fn changed_contract_cannot_reuse_an_existing_lifecycle_plan() {
        let fixture = Fixture::new();
        let contract = contract(ProfileSelection::Fixed {
            alias: "work".to_owned(),
        });
        let lifecycle = plan(
            &contract,
            fixture.profile_status(AuthState::Missing),
            CredentialLifecycleOperation::Status,
        );
        let mut changed = contract.clone();
        changed.auth.lifecycle.status.as_mut().expect("hook").args =
            vec!["auth".to_owned(), "whoami".to_owned()];
        let validated = validate_skill_runtime_contract(&changed).expect("changed contract");
        let baseline = ChildEnvironmentBaseline::portable_cli();
        let error = match CredentialLifecycleInvocation::bind(
            validated,
            lifecycle,
            fixture.profile_root(),
            &baseline,
            fixture.environment(&baseline),
        ) {
            Ok(_) => panic!("changed contract must fail"),
            Err(error) => error,
        };
        assert_eq!(
            error.code,
            CredentialLifecycleExecutionBindingErrorCode::PlanMismatch
        );
    }

    #[test]
    fn non_lifecycle_contract_drift_cannot_reuse_an_existing_plan() {
        let fixture = Fixture::new();
        let contract = contract(ProfileSelection::Fixed {
            alias: "work".to_owned(),
        });
        let lifecycle = plan(
            &contract,
            fixture.profile_status(AuthState::Missing),
            CredentialLifecycleOperation::Status,
        );
        let mut changed = contract;
        let crate::manifest::RuntimeProtocol::Cli { command_prefix, .. } = &mut changed.runtime
        else {
            panic!("fixture is CLI");
        };
        command_prefix.push("drift".to_owned());
        let validated = validate_skill_runtime_contract(&changed).expect("changed contract");
        let baseline = ChildEnvironmentBaseline::portable_cli();
        let error = match CredentialLifecycleInvocation::bind(
            validated,
            lifecycle,
            fixture.profile_root(),
            &baseline,
            fixture.environment(&baseline),
        ) {
            Ok(_) => panic!("non-lifecycle contract drift must fail"),
            Err(error) => error,
        };
        assert_eq!(
            error.code,
            CredentialLifecycleExecutionBindingErrorCode::PlanMismatch
        );
    }

    #[test]
    fn sensitive_interaction_values_have_no_clone_debug_or_serialization_surface() {
        assert_not_impl_any!(CredentialLifecycleSensitiveInput: Clone, fmt::Debug, Serialize);
        assert_not_impl_any!(CredentialLifecycleSensitiveOutput<'static>: Clone, fmt::Debug, Serialize);
        assert_not_impl_any!(CredentialLifecycleInteractionAction: Clone, fmt::Debug, Serialize);
        let empty = match CredentialLifecycleSensitiveInput::new(Vec::new()) {
            Ok(_) => panic!("empty input must fail"),
            Err(error) => error,
        };
        assert_eq!(
            empty.code,
            CredentialLifecycleExecutionBindingErrorCode::InteractionInputInvalid
        );
        let nul = match CredentialLifecycleSensitiveInput::new(vec![0]) {
            Ok(_) => panic!("NUL input must fail"),
            Err(error) => error,
        };
        assert_eq!(
            nul.code,
            CredentialLifecycleExecutionBindingErrorCode::InteractionInputInvalid
        );
    }
}
