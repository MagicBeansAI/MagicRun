//! Scoped credential-file and profile-directory authority.
//!
//! Phase 3C1 owns permission-safe per-call scratch sessions, deterministic drop
//! cleanup, bounded bootstrap recovery, and revalidatable existing profile-directory
//! projections. Physical paths remain crate-private. Nothing here spawns a process,
//! reads a credential source, persists an audit record, or enables a production route.

#![cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "sealed Phase 3 filesystem pipeline stays dormant until governed dispatch migration"
    )
)]

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
};

#[cfg(unix)]
use std::os::unix::{
    fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    io::AsRawFd,
};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    credential_injection::{CredentialCallId, CredentialExecutionFailure, CredentialRelativePath},
    credential_profiles::{CredentialProfileKey, CredentialProfileRevision, CredentialScope},
    manifest_validation::MAX_PROFILE_PATH_SEGMENTS,
    scoped_paths::{
        CredentialProfilePathAuthority, ScopedPath, ScopedPathComponent, ScopedPathKind,
    },
};

const SCRATCH_DIRECTORY_NAME: &str = "runtime-credential-material";
const SCRATCH_LEASE_FILE_NAME: &str = ".runtime-credential-material.lock";
const SESSION_PREFIX: &str = "session-";
const SESSION_DIGEST_HEX_BYTES: usize = 32;
pub const MAX_RECOVERABLE_SESSIONS: usize = 256;
pub const MAX_SESSION_ENTRIES: usize = 1024;
pub const MAX_SESSION_DEPTH: usize = MAX_PROFILE_PATH_SEGMENTS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialFilesystemErrorCode {
    UnsupportedPlatform,
    ScopeMismatch,
    WrongCapabilityKind,
    ScratchUnavailable,
    ScratchChanged,
    UnsafePermissions,
    AliasCollision,
    SessionAlreadyExists,
    SessionLimitExceeded,
    InvalidRelativePath,
    TargetAlreadyExists,
    WriteFailed,
    ProfileDirectoryUnavailable,
    RecoveryWhileActive,
    RecoveryLimitExceeded,
    CleanupFailed,
    InternalStateUnavailable,
}

/// Fixed, path-free and value-free filesystem failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CredentialFilesystemError {
    pub code: CredentialFilesystemErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl CredentialFilesystemError {
    const fn new(
        code: CredentialFilesystemErrorCode,
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
            CredentialFilesystemErrorCode::CleanupFailed => {
                CredentialExecutionFailure::CleanupFailed
            },
            CredentialFilesystemErrorCode::ProfileDirectoryUnavailable
            | CredentialFilesystemErrorCode::ScopeMismatch
            | CredentialFilesystemErrorCode::WrongCapabilityKind => {
                CredentialExecutionFailure::ScopedPathUnavailable
            },
            CredentialFilesystemErrorCode::UnsupportedPlatform
            | CredentialFilesystemErrorCode::ScratchUnavailable
            | CredentialFilesystemErrorCode::ScratchChanged
            | CredentialFilesystemErrorCode::UnsafePermissions
            | CredentialFilesystemErrorCode::AliasCollision
            | CredentialFilesystemErrorCode::SessionAlreadyExists
            | CredentialFilesystemErrorCode::SessionLimitExceeded
            | CredentialFilesystemErrorCode::InvalidRelativePath
            | CredentialFilesystemErrorCode::TargetAlreadyExists
            | CredentialFilesystemErrorCode::WriteFailed
            | CredentialFilesystemErrorCode::RecoveryWhileActive
            | CredentialFilesystemErrorCode::RecoveryLimitExceeded
            | CredentialFilesystemErrorCode::InternalStateUnavailable => {
                CredentialExecutionFailure::MaterializationFailed
            },
        }
    }
}

impl fmt::Display for CredentialFilesystemError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for CredentialFilesystemError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    owner: u32,
}

struct ScratchInner {
    scope_root: ScopedPath,
    scope: CredentialScope,
    path: PathBuf,
    identity: DirectoryIdentity,
    lease_path: PathBuf,
    lease_identity: DirectoryIdentity,
    _lease: File,
    active_sessions: Mutex<BTreeSet<String>>,
}

static SCRATCH_AUTHORITIES: OnceLock<Mutex<BTreeMap<PathBuf, Weak<ScratchInner>>>> =
    OnceLock::new();

/// Cloneable authority for one scope's fixed scratch container. Debug output contains
/// scope metadata only, never a physical path.
#[derive(Clone)]
pub struct CredentialScratchAuthority {
    inner: Arc<ScratchInner>,
}

impl fmt::Debug for CredentialScratchAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialScratchAuthority")
            .field("scope", &self.inner.scope)
            .field("path", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CredentialRecoveryReport {
    pub recovered_sessions: usize,
    pub removed_entries: usize,
}

impl CredentialScratchAuthority {
    pub fn open_or_create(scope_root: &ScopedPath) -> Result<Self, CredentialFilesystemError> {
        #[cfg(not(unix))]
        {
            let _ = scope_root;
            return Err(unsupported_platform());
        }
        #[cfg(unix)]
        {
            if scope_root.kind() != ScopedPathKind::Scope {
                return Err(wrong_capability_kind());
            }
            let root = scope_root
                .revalidated_path()
                .map_err(|_| scratch_unavailable())?;
            reject_case_alias(root, SCRATCH_DIRECTORY_NAME)?;
            let path = root.join(SCRATCH_DIRECTORY_NAME);
            match private_directory_builder().create(&path) {
                Ok(()) => {},
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {},
                Err(_) => return Err(scratch_unavailable()),
            }
            let identity = inspect_private_directory(&path, None)?;
            let canonical = fs::canonicalize(&path).map_err(|_| scratch_unavailable())?;
            if canonical != path {
                return Err(alias_collision());
            }
            scope_root.revalidate().map_err(|_| scratch_unavailable())?;
            reject_case_alias(root, SCRATCH_LEASE_FILE_NAME)?;

            let mut authorities = scratch_authorities()
                .lock()
                .map_err(|_| internal_state_unavailable())?;
            authorities.retain(|_, authority| authority.strong_count() > 0);
            if let Some(existing) = authorities.get(&path).and_then(Weak::upgrade) {
                if existing.scope != *scope_root.scope() || existing.identity != identity {
                    return Err(scratch_changed());
                }
                let authority = Self { inner: existing };
                authority.revalidate()?;
                return Ok(authority);
            }

            let lease_path = root.join(SCRATCH_LEASE_FILE_NAME);
            let (lease, lease_identity) = acquire_scratch_lease(&lease_path, identity.device)?;
            let inner = Arc::new(ScratchInner {
                scope_root: scope_root.clone(),
                scope: scope_root.scope().clone(),
                path: path.clone(),
                identity,
                lease_path,
                lease_identity,
                _lease: lease,
                active_sessions: Mutex::new(BTreeSet::new()),
            });
            authorities.insert(path, Arc::downgrade(&inner));
            Ok(Self { inner })
        }
    }

    pub fn scope(&self) -> &CredentialScope {
        &self.inner.scope
    }

    #[cfg(unix)]
    pub(crate) fn start_session(
        &self,
        call_id: &CredentialCallId,
        scope: &CredentialScope,
    ) -> Result<CredentialFileSession, CredentialFilesystemError> {
        if scope != &self.inner.scope {
            return Err(scope_mismatch());
        }
        self.revalidate()?;
        let name = session_name(call_id);
        {
            let mut active = self
                .inner
                .active_sessions
                .lock()
                .map_err(|_| internal_state_unavailable())?;
            if active.len() >= MAX_RECOVERABLE_SESSIONS {
                return Err(session_limit_exceeded());
            }
            if !active.insert(name.clone()) {
                return Err(session_already_exists());
            }
        }
        let path = self.inner.path.join(&name);
        let created = (|| {
            private_directory_builder().create(&path).map_err(|error| {
                if error.kind() == ErrorKind::AlreadyExists {
                    session_already_exists()
                } else {
                    scratch_unavailable()
                }
            })?;
            let identity = inspect_private_directory(&path, Some(self.inner.identity.device))?;
            sync_directory(&self.inner.path)?;
            Ok(CredentialFileSession {
                authority: self.clone(),
                name: name.clone(),
                path,
                identity,
                cleaned: false,
            })
        })();
        if created.is_err() {
            self.remove_active(&name);
        }
        created
    }

    #[cfg(not(unix))]
    pub(crate) fn start_session(
        &self,
        _call_id: &CredentialCallId,
        _scope: &CredentialScope,
    ) -> Result<CredentialFileSession, CredentialFilesystemError> {
        Err(unsupported_platform())
    }

    /// Bootstrap-only stale recovery. It refuses to run while this process owns any
    /// active session and removes only exact digest-derived session directories.
    pub fn recover_stale_sessions(
        &self,
    ) -> Result<CredentialRecoveryReport, CredentialFilesystemError> {
        self.revalidate()?;
        let active = self
            .inner
            .active_sessions
            .lock()
            .map_err(|_| internal_state_unavailable())?;
        if !active.is_empty() {
            return Err(recovery_while_active());
        }
        let mut candidates = Vec::new();
        let entries = fs::read_dir(&self.inner.path).map_err(|_| scratch_unavailable())?;
        for (index, entry) in entries.enumerate() {
            if index >= MAX_RECOVERABLE_SESSIONS {
                return Err(recovery_limit_exceeded());
            }
            let entry = entry.map_err(|_| scratch_unavailable())?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| recovery_limit_exceeded())?;
            if !valid_session_name(&name) {
                return Err(recovery_limit_exceeded());
            }
            candidates.push((name, entry.path()));
        }
        drop(active);

        let mut removed_entries = 0usize;
        for (_, path) in &candidates {
            inspect_private_directory(path, Some(self.inner.identity.device))?;
            removed_entries = removed_entries
                .checked_add(validate_cleanup_tree(path, 0)?)
                .ok_or_else(recovery_limit_exceeded)?;
        }
        for (_, path) in &candidates {
            fs::remove_dir_all(path).map_err(|_| cleanup_failed())?;
        }
        sync_directory(&self.inner.path).map_err(|_| cleanup_failed())?;
        Ok(CredentialRecoveryReport {
            recovered_sessions: candidates.len(),
            removed_entries,
        })
    }

    fn revalidate(&self) -> Result<(), CredentialFilesystemError> {
        self.inner
            .scope_root
            .revalidate()
            .map_err(|_| scratch_changed())?;
        let current = inspect_private_directory(&self.inner.path, None)?;
        if current != self.inner.identity {
            return Err(scratch_changed());
        }
        let lease = inspect_private_file(&self.inner.lease_path, Some(self.inner.identity.device))?;
        if lease != self.inner.lease_identity {
            return Err(scratch_changed());
        }
        Ok(())
    }

    fn remove_active(&self, name: &str) {
        if let Ok(mut active) = self.inner.active_sessions.lock() {
            active.remove(name);
        }
    }
}

/// One per-call secret-file owner. It is intentionally neither cloneable nor
/// debuggable. Drop attempts cleanup on success, error, cancellation, and unwind.
pub(crate) struct CredentialFileSession {
    authority: CredentialScratchAuthority,
    name: String,
    path: PathBuf,
    identity: DirectoryIdentity,
    cleaned: bool,
}

impl CredentialFileSession {
    pub(crate) fn revalidated_path(&self) -> Result<&Path, CredentialFilesystemError> {
        self.revalidate()?;
        Ok(&self.path)
    }

    #[cfg(unix)]
    pub(crate) fn write_file(
        &mut self,
        relative_path: &CredentialRelativePath,
        value: &[u8],
    ) -> Result<CredentialMaterializedFile, CredentialFilesystemError> {
        self.revalidate()?;
        let components = relative_components(relative_path.as_str())?;
        let (file_name, parents) = components.split_last().ok_or_else(invalid_relative_path)?;
        let mut directory = self.path.clone();
        for component in parents {
            reject_case_alias(&directory, component.as_str())?;
            directory.push(component.as_str());
            match private_directory_builder().create(&directory) {
                Ok(()) => {},
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {},
                Err(_) => return Err(scratch_unavailable()),
            }
            inspect_private_directory(&directory, Some(self.identity.device))?;
        }
        reject_case_alias(&directory, file_name.as_str())?;
        let path = directory.join(file_name.as_str());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|error| {
                if error.kind() == ErrorKind::AlreadyExists {
                    target_already_exists()
                } else {
                    write_failed()
                }
            })?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| write_failed())?;
        file.write_all(value).map_err(|_| write_failed())?;
        file.sync_all().map_err(|_| write_failed())?;
        let identity = inspect_private_file(&path, Some(self.identity.device))?;
        sync_directory(&directory)?;
        self.revalidate()?;
        Ok(CredentialMaterializedFile { path, identity })
    }

    #[cfg(unix)]
    pub(crate) fn create_config_directory(
        &mut self,
        name: &ScopedPathComponent,
    ) -> Result<CredentialMaterializedDirectory, CredentialFilesystemError> {
        self.revalidate()?;
        reject_case_alias(&self.path, name.as_str())?;
        let path = self.path.join(name.as_str());
        match private_directory_builder().create(&path) {
            Ok(()) => {},
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                return Err(target_already_exists());
            },
            Err(_) => return Err(scratch_unavailable()),
        }
        let identity = inspect_private_directory(&path, Some(self.identity.device))?;
        sync_directory(&self.path)?;
        self.revalidate()?;
        Ok(CredentialMaterializedDirectory { path, identity })
    }

    #[cfg(not(unix))]
    pub(crate) fn create_config_directory(
        &mut self,
        _name: &ScopedPathComponent,
    ) -> Result<CredentialMaterializedDirectory, CredentialFilesystemError> {
        Err(unsupported_platform())
    }

    #[cfg(not(unix))]
    pub(crate) fn write_file(
        &mut self,
        _relative_path: &CredentialRelativePath,
        _value: &[u8],
    ) -> Result<CredentialMaterializedFile, CredentialFilesystemError> {
        Err(unsupported_platform())
    }

    pub(crate) fn cleanup(&mut self) -> Result<(), CredentialFilesystemError> {
        if self.cleaned {
            return Ok(());
        }
        let result = (|| {
            self.authority.revalidate()?;
            let current = inspect_private_directory(&self.path, Some(self.identity.device))?;
            if current != self.identity {
                return Err(scratch_changed());
            }
            validate_cleanup_tree(&self.path, 0)?;
            fs::remove_dir_all(&self.path).map_err(|_| cleanup_failed())?;
            sync_directory(&self.authority.inner.path).map_err(|_| cleanup_failed())?;
            Ok(())
        })();
        if result.is_ok() {
            self.authority.remove_active(&self.name);
            self.cleaned = true;
        }
        result
    }

    fn revalidate(&self) -> Result<(), CredentialFilesystemError> {
        self.authority.revalidate()?;
        let current = inspect_private_directory(&self.path, Some(self.identity.device))?;
        if current != self.identity {
            return Err(scratch_changed());
        }
        Ok(())
    }
}

impl Drop for CredentialFileSession {
    fn drop(&mut self) {
        if self.cleanup().is_err() {
            // The owner is gone even when filesystem cleanup fails. Leave the directory for
            // bounded bootstrap recovery, but release the in-process ownership reservation.
            self.authority.remove_active(&self.name);
        }
    }
}

pub(crate) struct CredentialMaterializedFile {
    path: PathBuf,
    identity: DirectoryIdentity,
}

impl CredentialMaterializedFile {
    pub(crate) fn revalidated_path(&self) -> Result<&Path, CredentialFilesystemError> {
        let current = inspect_private_file(&self.path, Some(self.identity.device))?;
        if current != self.identity {
            return Err(scratch_changed());
        }
        Ok(&self.path)
    }
}

pub(crate) struct CredentialMaterializedDirectory {
    path: PathBuf,
    identity: DirectoryIdentity,
}

impl CredentialMaterializedDirectory {
    pub(crate) fn revalidated_path(&self) -> Result<&Path, CredentialFilesystemError> {
        let current = inspect_private_directory(&self.path, Some(self.identity.device))?;
        if current != self.identity {
            return Err(scratch_changed());
        }
        Ok(&self.path)
    }
}

/// Existing, private profile directory projected through a revalidated capability.
pub(crate) struct CredentialProfileDirectory {
    profile_root: ScopedPath,
    components: Vec<ScopedPathComponent>,
    path: PathBuf,
    identity: DirectoryIdentity,
}

impl CredentialProfileDirectory {
    pub(crate) fn resolve(
        profile_root: &CredentialProfilePathAuthority,
        scope: &CredentialScope,
        expected_key: &CredentialProfileKey,
        expected_revision: CredentialProfileRevision,
        components: &[ScopedPathComponent],
    ) -> Result<Self, CredentialFilesystemError> {
        if &expected_key.scope != scope
            || profile_root.key() != expected_key
            || profile_root.revision() != expected_revision
        {
            return Err(scope_mismatch());
        }
        profile_root
            .revalidate()
            .map_err(|_| profile_directory_unavailable())?;
        let profile_path = profile_root.path();
        if profile_path.kind() != ScopedPathKind::CredentialProfile
            || profile_path.scope() != scope
            || profile_path.profile_key() != Some(expected_key)
        {
            return Err(scope_mismatch());
        }
        if components.len() > MAX_SESSION_DEPTH {
            return Err(invalid_relative_path());
        }
        let root = profile_path
            .revalidated_path()
            .map_err(|_| profile_directory_unavailable())?;
        let root_identity = inspect_private_directory(root, None)?;
        let mut path = root.to_path_buf();
        for component in components {
            reject_case_alias(&path, component.as_str())?;
            path.push(component.as_str());
            inspect_private_directory(&path, Some(root_identity.device))?;
        }
        let identity = inspect_private_directory(&path, Some(root_identity.device))?;
        Ok(Self {
            profile_root: profile_path.clone(),
            components: components.to_vec(),
            path,
            identity,
        })
    }

    pub(crate) fn revalidated_path(&self) -> Result<&Path, CredentialFilesystemError> {
        self.profile_root
            .revalidate()
            .map_err(|_| profile_directory_unavailable())?;
        let current = inspect_private_directory(&self.path, Some(self.identity.device))?;
        if current != self.identity {
            return Err(profile_directory_unavailable());
        }
        let mut expected = self
            .profile_root
            .revalidated_path()
            .map_err(|_| profile_directory_unavailable())?
            .to_path_buf();
        for component in &self.components {
            reject_case_alias(&expected, component.as_str())?;
            expected.push(component.as_str());
        }
        if expected != self.path {
            return Err(profile_directory_unavailable());
        }
        Ok(&self.path)
    }
}

fn session_name(call_id: &CredentialCallId) -> String {
    let digest = Sha256::digest(call_id.as_str().as_bytes());
    let mut encoded = String::with_capacity(SESSION_PREFIX.len() + SESSION_DIGEST_HEX_BYTES);
    encoded.push_str(SESSION_PREFIX);
    for byte in digest.iter().take(SESSION_DIGEST_HEX_BYTES / 2) {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn valid_session_name(name: &str) -> bool {
    name.len() == SESSION_PREFIX.len() + SESSION_DIGEST_HEX_BYTES
        && name.starts_with(SESSION_PREFIX)
        && name[SESSION_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn relative_components(value: &str) -> Result<Vec<ScopedPathComponent>, CredentialFilesystemError> {
    let parts = value.split('/').collect::<Vec<_>>();
    if parts.is_empty() || parts.len() > MAX_SESSION_DEPTH {
        return Err(invalid_relative_path());
    }
    parts
        .into_iter()
        .map(|part| ScopedPathComponent::new(part.to_owned()).map_err(|_| invalid_relative_path()))
        .collect()
}

#[cfg(unix)]
fn private_directory_builder() -> fs::DirBuilder {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
}

fn scratch_authorities() -> &'static Mutex<BTreeMap<PathBuf, Weak<ScratchInner>>> {
    SCRATCH_AUTHORITIES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

#[cfg(unix)]
fn acquire_scratch_lease(
    path: &Path,
    expected_device: u64,
) -> Result<(File, DirectoryIdentity), CredentialFilesystemError> {
    let file = match open_scratch_lease(path, true) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            open_scratch_lease(path, false).map_err(|_| scratch_unavailable())?
        },
        Err(_) => return Err(scratch_unavailable()),
    };
    let path_identity = inspect_private_file(path, Some(expected_device))?;
    let descriptor_metadata = file.metadata().map_err(|_| scratch_unavailable())?;
    let descriptor_identity =
        inspect_private_metadata(&descriptor_metadata, Some(expected_device), false)?;
    if descriptor_identity != path_identity {
        return Err(scratch_changed());
    }

    // SAFETY: `flock` receives a valid, owned file descriptor and an operation with no
    // pointer arguments. The descriptor remains owned by `ScratchInner` for the lease.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(scratch_unavailable());
    }
    Ok((file, path_identity))
}

#[cfg(unix)]
fn open_scratch_lease(path: &Path, create_new: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    if create_new {
        options.create_new(true);
    }
    options.open(path)
}

#[cfg(unix)]
fn inspect_private_directory(
    path: &Path,
    expected_device: Option<u64>,
) -> Result<DirectoryIdentity, CredentialFilesystemError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| scratch_unavailable())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(scratch_changed());
    }
    inspect_private_metadata(&metadata, expected_device, true)
}

#[cfg(not(unix))]
fn inspect_private_directory(
    _path: &Path,
    _expected_device: Option<u64>,
) -> Result<DirectoryIdentity, CredentialFilesystemError> {
    Err(unsupported_platform())
}

#[cfg(unix)]
fn inspect_private_file(
    path: &Path,
    expected_device: Option<u64>,
) -> Result<DirectoryIdentity, CredentialFilesystemError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| scratch_unavailable())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
        return Err(scratch_changed());
    }
    inspect_private_metadata(&metadata, expected_device, false)
}

#[cfg(not(unix))]
fn inspect_private_file(
    _path: &Path,
    _expected_device: Option<u64>,
) -> Result<DirectoryIdentity, CredentialFilesystemError> {
    Err(unsupported_platform())
}

#[cfg(unix)]
fn inspect_private_metadata(
    metadata: &fs::Metadata,
    expected_device: Option<u64>,
    directory: bool,
) -> Result<DirectoryIdentity, CredentialFilesystemError> {
    // SAFETY: `geteuid` has no preconditions, returns no borrowed state, and cannot mutate Rust
    // memory. It is used only to compare filesystem ownership with the current process owner.
    let owner = unsafe { libc::geteuid() };
    let expected_mode = if directory { 0o700 } else { 0o600 };
    if metadata.uid() != owner
        || expected_device.is_some_and(|device| metadata.dev() != device)
        || metadata.mode() & 0o7777 != expected_mode
    {
        return Err(unsafe_permissions());
    }
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
    })
}

fn reject_case_alias(parent: &Path, expected: &str) -> Result<(), CredentialFilesystemError> {
    let entries = fs::read_dir(parent).map_err(|_| scratch_unavailable())?;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_SESSION_ENTRIES {
            return Err(recovery_limit_exceeded());
        }
        let name = entry
            .map_err(|_| scratch_unavailable())?
            .file_name()
            .into_string()
            .map_err(|_| alias_collision())?;
        if name != expected && name.eq_ignore_ascii_case(expected) {
            return Err(alias_collision());
        }
    }
    Ok(())
}

fn validate_cleanup_tree(path: &Path, depth: usize) -> Result<usize, CredentialFilesystemError> {
    let mut pending = vec![(path.to_path_buf(), depth)];
    let mut count = 0usize;

    while let Some((directory, current_depth)) = pending.pop() {
        if current_depth > MAX_SESSION_DEPTH {
            return Err(recovery_limit_exceeded());
        }

        let entries = fs::read_dir(directory).map_err(|_| cleanup_failed())?;
        for entry in entries {
            count = count.checked_add(1).ok_or_else(recovery_limit_exceeded)?;
            if count > MAX_SESSION_ENTRIES {
                return Err(recovery_limit_exceeded());
            }

            let entry = entry.map_err(|_| cleanup_failed())?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|_| cleanup_failed())?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                pending.push((path, current_depth.saturating_add(1)));
            }
        }
    }

    Ok(count)
}

fn sync_directory(path: &Path) -> Result<(), CredentialFilesystemError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| scratch_unavailable())
}

#[cfg(not(unix))]
const fn unsupported_platform() -> CredentialFilesystemError {
    CredentialFilesystemError::new(
        CredentialFilesystemErrorCode::UnsupportedPlatform,
        "credential_filesystem",
        "credential file authority requires Unix ownership and permission checks",
    )
}

const fn scope_mismatch() -> CredentialFilesystemError {
    CredentialFilesystemError::new(
        CredentialFilesystemErrorCode::ScopeMismatch,
        "credential_scope",
        "credential filesystem authority belongs to a different scope",
    )
}

const fn wrong_capability_kind() -> CredentialFilesystemError {
    CredentialFilesystemError::new(
        CredentialFilesystemErrorCode::WrongCapabilityKind,
        "scoped_path",
        "credential filesystem operation received the wrong scoped path capability",
    )
}

const fn scratch_unavailable() -> CredentialFilesystemError {
    CredentialFilesystemError::new(
        CredentialFilesystemErrorCode::ScratchUnavailable,
        "credential_scratch",
        "the scoped credential scratch directory is unavailable",
    )
}

const fn scratch_changed() -> CredentialFilesystemError {
    CredentialFilesystemError::new(
        CredentialFilesystemErrorCode::ScratchChanged,
        "credential_scratch",
        "scoped credential material changed after authority was issued",
    )
}

const fn unsafe_permissions() -> CredentialFilesystemError {
    CredentialFilesystemError::new(
        CredentialFilesystemErrorCode::UnsafePermissions,
        "credential_filesystem",
        "credential filesystem material has unsafe ownership, links, or permissions",
    )
}

const fn alias_collision() -> CredentialFilesystemError {
    CredentialFilesystemError::new(
        CredentialFilesystemErrorCode::AliasCollision,
        "credential_filesystem",
        "credential filesystem names collide on a case-insensitive platform",
    )
}

const fn session_already_exists() -> CredentialFilesystemError {
    CredentialFilesystemError::new(
        CredentialFilesystemErrorCode::SessionAlreadyExists,
        "credential_session",
        "a credential material session with this call identity already exists",
    )
}

const fn session_limit_exceeded() -> CredentialFilesystemError {
    CredentialFilesystemError::new(
        CredentialFilesystemErrorCode::SessionLimitExceeded,
        "credential_session",
        "the active credential material session limit is exhausted",
    )
}

const fn invalid_relative_path() -> CredentialFilesystemError {
    CredentialFilesystemError::new(
        CredentialFilesystemErrorCode::InvalidRelativePath,
        "credential_target",
        "the credential file target is not a bounded portable relative path",
    )
}

const fn target_already_exists() -> CredentialFilesystemError {
    CredentialFilesystemError::new(
        CredentialFilesystemErrorCode::TargetAlreadyExists,
        "credential_target",
        "credential file targets are create-once within a call",
    )
}

const fn write_failed() -> CredentialFilesystemError {
    CredentialFilesystemError::new(
        CredentialFilesystemErrorCode::WriteFailed,
        "credential_target",
        "credential file material could not be written durably",
    )
}

const fn profile_directory_unavailable() -> CredentialFilesystemError {
    CredentialFilesystemError::new(
        CredentialFilesystemErrorCode::ProfileDirectoryUnavailable,
        "profile_auth_root",
        "the selected profile directory is unavailable or changed",
    )
}

const fn recovery_while_active() -> CredentialFilesystemError {
    CredentialFilesystemError::new(
        CredentialFilesystemErrorCode::RecoveryWhileActive,
        "credential_recovery",
        "stale credential recovery cannot run while calls are active",
    )
}

const fn recovery_limit_exceeded() -> CredentialFilesystemError {
    CredentialFilesystemError::new(
        CredentialFilesystemErrorCode::RecoveryLimitExceeded,
        "credential_recovery",
        "credential recovery exceeded its bounded session, entry, or depth limit",
    )
}

const fn cleanup_failed() -> CredentialFilesystemError {
    CredentialFilesystemError::new(
        CredentialFilesystemErrorCode::CleanupFailed,
        "credential_cleanup",
        "credential material cleanup did not complete",
    )
}

const fn internal_state_unavailable() -> CredentialFilesystemError {
    CredentialFilesystemError::new(
        CredentialFilesystemErrorCode::InternalStateUnavailable,
        "credential_session",
        "credential filesystem session state is unavailable",
    )
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        collections::BTreeSet,
        os::unix::fs::{symlink, PermissionsExt},
        panic::{catch_unwind, AssertUnwindSafe},
        sync::atomic::{AtomicU64, Ordering},
        thread,
    };

    use static_assertions::assert_not_impl_any;

    use super::*;
    use crate::{
        credential_injection::{ChildEnvironmentBaseline, CredentialInjectionPlan},
        credential_preparation::{
            CredentialMaterialBindingName, CredentialMaterialKind, CredentialPreparationBinding,
            CredentialPreparationPlan,
        },
        credential_profiles::{
            CredentialProfileAvailability, CredentialProfileBinding, CredentialProfileKey,
            CredentialProfileMetadata, CredentialProfileRegistrySnapshot,
            CredentialProfileRevision, CredentialProfileStatus,
        },
        manifest::{
            AuthContract, AuthKind, AuthRequirement, AuthState, InjectionBinding, InjectionSource,
            InjectionTarget, PolicyFloor, ProfileSelection, RuntimeLimits, RuntimeProtocol,
            RuntimeRequirements, SecretBindingRef, SkillRuntimeContract,
            SkillRuntimeContractVersion, StdinContract, WorkingDirectoryContract,
        },
        manifest_validation::validate_skill_runtime_contract,
        profile_selection::{
            select_credential_profile_from_snapshot, CredentialProfileSelectionRequest,
        },
        scoped_paths::ScopedPathAuthority,
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        container: PathBuf,
        scopes_root: PathBuf,
        scope: CredentialScope,
    }

    impl Fixture {
        fn new() -> Self {
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let temp_root = fs::canonicalize(std::env::temp_dir()).expect("canonical temp root");
            let container = temp_root.join(format!(
                "tool-runtime-credential-fs-{}-{sequence}",
                std::process::id()
            ));
            let scopes_root = container.join("scopes");
            let scope = CredentialScope::new("owner", "default").expect("scope");
            let workspace = scopes_root
                .join(scope.principal.as_str())
                .join(scope.workspace.as_str());
            fs::create_dir_all(workspace.join("auth").join("work").join("cloudsdk"))
                .expect("fixture directories");
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
            ScopedPathAuthority::open(&self.scopes_root).expect("scoped authority")
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
            CredentialProfileKey::new(
                self.scope.clone(),
                "provider-cli",
                "work",
                CredentialProfileBinding::Provider,
            )
            .expect("profile key")
        }

        fn profile_status(&self) -> CredentialProfileStatus {
            let metadata = CredentialProfileMetadata::new(
                self.profile_key(),
                None,
                true,
                CredentialProfileAvailability::Enabled,
                CredentialProfileRevision::new(1).expect("revision"),
            )
            .expect("profile metadata");
            CredentialProfileStatus::new(metadata, AuthState::Ready).expect("ready profile")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.container);
        }
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set mode");
    }

    fn call_id(value: &str) -> CredentialCallId {
        CredentialCallId::new(value).expect("call id")
    }

    fn require_error<T>(result: Result<T, CredentialFilesystemError>) -> CredentialFilesystemError {
        match result {
            Err(error) => error,
            Ok(_) => panic!("expected credential filesystem failure"),
        }
    }

    fn scoped_file_target() -> CredentialRelativePath {
        let scope = CredentialScope::new("owner", "default").expect("scope");
        let contract = SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires: RuntimeRequirements {
                bins: BTreeSet::from(["fixture-cli".to_owned()]),
                entrypoint: Default::default(),
                environment: Default::default(),
            },
            runtime: RuntimeProtocol::Cli {
                command_prefix: Vec::new(),
                interaction: Default::default(),
                stdin: StdinContract::default(),
                working_directory: WorkingDirectoryContract::default(),
                limits: RuntimeLimits::default(),
            },
            auth: AuthContract {
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
                        relative_path: "nested/token.txt".to_owned(),
                    },
                }],
                ..AuthContract::default()
            },
            policy_floor: PolicyFloor::default(),
        };
        let request = CredentialProfileSelectionRequest::new(
            scope.clone(),
            None,
            CredentialProfileBinding::Provider,
            &ProfileSelection::None,
            None,
        )
        .expect("none request");
        let snapshot =
            CredentialProfileRegistrySnapshot::new(scope.clone(), Vec::new()).expect("snapshot");
        let selection =
            select_credential_profile_from_snapshot(&request, &snapshot).expect("selection");
        let preparation = CredentialPreparationPlan::new(
            scope,
            AuthKind::Secrets,
            &selection,
            vec![CredentialPreparationBinding::new(
                CredentialMaterialBindingName::new("token").expect("binding name"),
                CredentialMaterialKind::SecretBinding,
                1024,
            )
            .expect("binding")],
        )
        .expect("preparation");
        let injection = CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract).expect("validated contract"),
            &preparation,
            ChildEnvironmentBaseline::hermetic(),
        )
        .expect("injection");
        match injection.injections()[0].target() {
            crate::credential_injection::CredentialInjectionTarget::ScopedFile {
                relative_path,
            } => relative_path.clone(),
            _ => panic!("scoped file target"),
        }
    }

    #[test]
    fn scratch_and_session_paths_are_private_redacted_capabilities() {
        assert_not_impl_any!(CredentialFileSession: Clone, fmt::Debug, Serialize);
        assert_not_impl_any!(CredentialMaterializedFile: Clone, fmt::Debug, Serialize);
        assert_not_impl_any!(CredentialProfileDirectory: Clone, fmt::Debug, Serialize);

        let fixture = Fixture::new();
        let authority = CredentialScratchAuthority::open_or_create(&fixture.scope_root())
            .expect("scratch authority");
        let debug = format!("{authority:?}");
        assert!(debug.contains("owner"));
        assert!(!debug.contains(fixture.container.to_string_lossy().as_ref()));
        let metadata = fs::metadata(&authority.inner.path).expect("scratch metadata");
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);

        let id = call_id("exec_file_001");
        let expected_session = authority.inner.path.join(session_name(&id));
        let session = authority
            .start_session(&id, &fixture.scope)
            .expect("session");
        assert!(expected_session.is_dir());
        drop(session);
        assert!(!expected_session.exists());
    }

    #[test]
    fn nested_secret_file_is_create_once_private_and_removed_on_cleanup() {
        let fixture = Fixture::new();
        let authority = CredentialScratchAuthority::open_or_create(&fixture.scope_root())
            .expect("scratch authority");
        let id = call_id("exec_file_002");
        let session_path = authority.inner.path.join(session_name(&id));
        let mut session = authority
            .start_session(&id, &fixture.scope)
            .expect("session");
        let target = scoped_file_target();
        let file = session
            .write_file(&target, b"credential-file-canary")
            .expect("secret file");
        let path = file.revalidated_path().expect("file path").to_path_buf();
        assert_eq!(
            fs::read(&path).expect("read fixture"),
            b"credential-file-canary"
        );
        assert_eq!(
            fs::metadata(&path)
                .expect("file metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.parent().expect("parent"))
                .expect("directory metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        assert_eq!(
            require_error(session.write_file(&target, b"replacement-canary")).code,
            CredentialFilesystemErrorCode::TargetAlreadyExists
        );
        session.cleanup().expect("cleanup");
        assert!(!session_path.exists());
        assert!(!path.exists());
        session.cleanup().expect("idempotent cleanup");
    }

    #[test]
    fn unwind_and_active_recovery_paths_are_safe() {
        let fixture = Fixture::new();
        let authority = CredentialScratchAuthority::open_or_create(&fixture.scope_root())
            .expect("scratch authority");
        let id = call_id("exec_file_panic");
        let session_path = authority.inner.path.join(session_name(&id));
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let mut session = authority
                .start_session(&id, &fixture.scope)
                .expect("session");
            session
                .write_file(&scoped_file_target(), b"panic-canary")
                .expect("file");
            assert_eq!(
                authority
                    .recover_stale_sessions()
                    .expect_err("active recovery denied")
                    .code,
                CredentialFilesystemErrorCode::RecoveryWhileActive
            );
            panic!("fixture unwind");
        }));
        assert!(panic.is_err());
        assert!(!session_path.exists());
        assert_eq!(
            authority
                .recover_stale_sessions()
                .expect("post-unwind recovery")
                .recovered_sessions,
            0
        );
    }

    #[test]
    fn bootstrap_recovery_is_bounded_and_does_not_follow_symlinks() {
        let fixture = Fixture::new();
        let authority = CredentialScratchAuthority::open_or_create(&fixture.scope_root())
            .expect("scratch authority");
        let stale = authority
            .inner
            .path
            .join(session_name(&call_id("exec_stale_001")));
        fs::create_dir(&stale).expect("stale session");
        set_mode(&stale, 0o700);
        fs::write(stale.join("secret"), b"stale-canary").expect("stale file");
        set_mode(&stale.join("secret"), 0o600);
        let outside = fixture.container.join("outside");
        fs::create_dir(&outside).expect("outside");
        fs::write(outside.join("keep"), b"keep").expect("outside file");
        symlink(&outside, stale.join("outside-link")).expect("symlink fixture");

        let report = authority.recover_stale_sessions().expect("recovery");
        assert_eq!(report.recovered_sessions, 1);
        assert_eq!(report.removed_entries, 2);
        assert!(!stale.exists());
        assert_eq!(
            fs::read(outside.join("keep")).expect("outside retained"),
            b"keep"
        );

        fs::create_dir(authority.inner.path.join("unexpected")).expect("unexpected root entry");
        assert_eq!(
            authority
                .recover_stale_sessions()
                .expect_err("unknown root entry")
                .code,
            CredentialFilesystemErrorCode::RecoveryLimitExceeded
        );
    }

    #[test]
    fn bootstrap_recovery_rejects_overdeep_trees_without_recursion() {
        let fixture = Fixture::new();
        let authority = CredentialScratchAuthority::open_or_create(&fixture.scope_root())
            .expect("scratch authority");
        let stale = authority
            .inner
            .path
            .join(session_name(&call_id("exec_stale_overdeep")));
        fs::create_dir(&stale).expect("stale session");
        set_mode(&stale, 0o700);

        let mut current = stale.clone();
        for index in 0..=MAX_SESSION_DEPTH {
            current = current.join(format!("depth-{index:02}"));
            fs::create_dir(&current).expect("nested stale directory");
            set_mode(&current, 0o700);
        }

        let authority = authority.clone();
        let error = thread::Builder::new()
            .name("credential-recovery-small-stack".to_owned())
            .stack_size(64 * 1024)
            .spawn(move || {
                authority
                    .recover_stale_sessions()
                    .expect_err("overdeep recovery must fail closed")
            })
            .expect("recovery thread")
            .join()
            .expect("recovery thread result");
        assert_eq!(
            error.code,
            CredentialFilesystemErrorCode::RecoveryLimitExceeded
        );
        assert!(stale.exists());
    }

    #[test]
    fn bootstrap_recovery_prevalidates_every_session_before_removal() {
        let fixture = Fixture::new();
        let authority = CredentialScratchAuthority::open_or_create(&fixture.scope_root())
            .expect("scratch authority");
        let valid = authority
            .inner
            .path
            .join(session_name(&call_id("exec_stale_valid")));
        let unsafe_session = authority
            .inner
            .path
            .join(session_name(&call_id("exec_stale_unsafe")));
        for path in [&valid, &unsafe_session] {
            fs::create_dir(path).expect("stale session");
            set_mode(path, 0o700);
        }
        set_mode(&unsafe_session, 0o755);

        assert_eq!(
            authority
                .recover_stale_sessions()
                .expect_err("unsafe candidate")
                .code,
            CredentialFilesystemErrorCode::UnsafePermissions
        );
        assert!(valid.exists());
        assert!(unsafe_session.exists());

        set_mode(&unsafe_session, 0o700);
        assert_eq!(
            authority
                .recover_stale_sessions()
                .expect("recovery retry")
                .recovered_sessions,
            2
        );
    }

    #[test]
    fn cloned_authority_supports_distinct_concurrent_sessions() {
        let fixture = Fixture::new();
        let authority = CredentialScratchAuthority::open_or_create(&fixture.scope_root())
            .expect("scratch authority");
        let target = scoped_file_target();
        let threads = (0..16)
            .map(|index| {
                let authority = authority.clone();
                let scope = fixture.scope.clone();
                let target = target.clone();
                thread::spawn(move || {
                    let id = call_id(&format!("exec_parallel_{index:02}"));
                    let mut session = authority.start_session(&id, &scope).expect("session");
                    session
                        .write_file(&target, format!("value-{index:02}").as_bytes())
                        .expect("file");
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().expect("parallel session");
        }
        assert_eq!(
            fs::read_dir(&authority.inner.path)
                .expect("scratch entries")
                .count(),
            0
        );
    }

    #[test]
    fn independently_opened_authorities_share_active_session_ownership() {
        let fixture = Fixture::new();
        let scope_root = fixture.scope_root();
        let first = CredentialScratchAuthority::open_or_create(&scope_root)
            .expect("first scratch authority");
        let second = CredentialScratchAuthority::open_or_create(&scope_root)
            .expect("second scratch authority");
        assert!(Arc::ptr_eq(&first.inner, &second.inner));

        let session = first
            .start_session(&call_id("exec_shared_authority"), &fixture.scope)
            .expect("active session");
        assert_eq!(
            second
                .recover_stale_sessions()
                .expect_err("shared active session blocks recovery")
                .code,
            CredentialFilesystemErrorCode::RecoveryWhileActive
        );
        drop(session);
        assert_eq!(
            second
                .recover_stale_sessions()
                .expect("empty recovery")
                .recovered_sessions,
            0
        );
    }

    #[test]
    fn opening_an_authority_prunes_dead_scratch_cache_entries() {
        let first_fixture = Fixture::new();
        let first = CredentialScratchAuthority::open_or_create(&first_fixture.scope_root())
            .expect("first authority");
        let first_path = first.inner.path.clone();
        drop(first);

        let second_fixture = Fixture::new();
        let _second = CredentialScratchAuthority::open_or_create(&second_fixture.scope_root())
            .expect("second authority");

        let authorities = scratch_authorities().lock().expect("scratch cache");
        assert!(!authorities.contains_key(&first_path));
    }

    #[test]
    fn replacing_the_process_lease_fails_future_operations_closed() {
        let fixture = Fixture::new();
        let authority = CredentialScratchAuthority::open_or_create(&fixture.scope_root())
            .expect("scratch authority");
        let original = authority.inner.lease_path.with_extension("lock-old");
        fs::rename(&authority.inner.lease_path, &original).expect("move held lease");
        let replacement = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&authority.inner.lease_path)
            .expect("replacement lease");
        drop(replacement);

        assert_eq!(
            require_error(
                authority.start_session(&call_id("exec_replaced_lease"), &fixture.scope,)
            )
            .code,
            CredentialFilesystemErrorCode::ScratchChanged
        );
    }

    #[test]
    fn profile_directory_is_scope_exact_alias_safe_and_revalidatable() {
        let fixture = Fixture::new();
        let profile_root = fixture.profile_root();
        let profile_authority = profile_root
            .authorize_ready_profile(&fixture.profile_status())
            .expect("profile authority");
        let profile_key = fixture.profile_key();
        let profile_revision = CredentialProfileRevision::new(1).expect("revision");
        let component = ScopedPathComponent::new("cloudsdk").expect("component");
        let projected = CredentialProfileDirectory::resolve(
            &profile_authority,
            &fixture.scope,
            &profile_key,
            profile_revision,
            std::slice::from_ref(&component),
        )
        .expect("profile projection");
        let original = projected
            .revalidated_path()
            .expect("profile path")
            .to_path_buf();
        assert!(original.ends_with("cloudsdk"));

        let replacement = original.with_file_name("cloudsdk-old");
        fs::rename(&original, &replacement).expect("rename profile child");
        fs::create_dir(&original).expect("replacement child");
        set_mode(&original, 0o700);
        assert_eq!(
            projected
                .revalidated_path()
                .expect_err("identity replacement")
                .code,
            CredentialFilesystemErrorCode::ProfileDirectoryUnavailable
        );

        fs::remove_dir(&original).expect("remove replacement");
        fs::rename(&replacement, &original).expect("restore child");
        let case_alias = original.with_file_name("CloudSDK");
        fs::rename(&original, &case_alias).expect("case alias");
        assert_eq!(
            require_error(CredentialProfileDirectory::resolve(
                &profile_authority,
                &fixture.scope,
                &profile_key,
                profile_revision,
                std::slice::from_ref(&component),
            ))
            .code,
            CredentialFilesystemErrorCode::AliasCollision
        );
    }

    #[test]
    fn scope_permission_and_duplicate_session_drift_fail_closed() {
        let fixture = Fixture::new();
        let authority = CredentialScratchAuthority::open_or_create(&fixture.scope_root())
            .expect("scratch authority");
        let other = CredentialScope::new("other", "default").expect("other scope");
        assert_eq!(
            require_error(authority.start_session(&call_id("exec_wrong_scope"), &other)).code,
            CredentialFilesystemErrorCode::ScopeMismatch
        );

        let id = call_id("exec_duplicate");
        let session = authority
            .start_session(&id, &fixture.scope)
            .expect("first session");
        assert_eq!(
            require_error(authority.start_session(&id, &fixture.scope)).code,
            CredentialFilesystemErrorCode::SessionAlreadyExists
        );
        drop(session);

        set_mode(&authority.inner.path, 0o755);
        assert_eq!(
            require_error(authority.start_session(&call_id("exec_unsafe_mode"), &fixture.scope),)
                .code,
            CredentialFilesystemErrorCode::UnsafePermissions
        );
        set_mode(&authority.inner.path, 0o700);
    }

    #[test]
    fn failed_cleanup_keeps_a_live_session_reserved() {
        let fixture = Fixture::new();
        let authority = CredentialScratchAuthority::open_or_create(&fixture.scope_root())
            .expect("scratch authority");
        let id = call_id("exec_cleanup_retry");
        let mut session = authority
            .start_session(&id, &fixture.scope)
            .expect("session");
        set_mode(&session.path, 0o755);

        assert_eq!(
            session.cleanup().expect_err("unsafe cleanup").code,
            CredentialFilesystemErrorCode::UnsafePermissions
        );
        assert_eq!(
            authority
                .recover_stale_sessions()
                .expect_err("live owner must block recovery")
                .code,
            CredentialFilesystemErrorCode::RecoveryWhileActive
        );
        assert_eq!(
            require_error(authority.start_session(&id, &fixture.scope)).code,
            CredentialFilesystemErrorCode::SessionAlreadyExists
        );

        set_mode(&session.path, 0o700);
        session.cleanup().expect("retry cleanup");
        assert_eq!(
            authority
                .recover_stale_sessions()
                .expect("post-cleanup recovery")
                .recovered_sessions,
            0
        );
    }

    #[test]
    fn failures_never_echo_call_paths_or_secret_values() {
        let call_canary = "exec_sensitive_call_canary";
        let value_canary = "credential-value-canary";
        let error = target_already_exists();
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(call_canary));
        assert!(!rendered.contains(value_canary));
        assert_eq!(
            error.execution_failure(),
            CredentialExecutionFailure::MaterializationFailed
        );
    }
}
