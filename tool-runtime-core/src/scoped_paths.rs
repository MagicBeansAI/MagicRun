//! Typed filesystem authority for scope-owned authentication directories.
//!
//! A [`ScopedPath`] is issued only after exact-name, containment, symlink, device,
//! ownership, and permission checks. It is intentionally not serializable and does not
//! create directories or read credential contents. Consumers must call `revalidate`
//! immediately before opening a path; later phases attach storage and execution adapters.

use std::{
    error::Error,
    fmt,
    fs::File,
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(unix)]
use std::{
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::ErrorKind,
    os::unix::{ffi::OsStrExt, fs::MetadataExt, fs::OpenOptionsExt},
    path::Component,
};

use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    credential_profiles::{
        CredentialProfileAvailability, CredentialProfileKey, CredentialProfileRevision,
        CredentialProfileStatus, CredentialScope,
    },
    manifest::AuthState,
};

pub const MAX_SCOPED_PATH_COMPONENT_BYTES: usize = 255;
pub const MAX_SCOPED_PATH_BYTES: usize = 16 * 1024;
pub const MAX_SCOPED_DIRECTORY_ENTRIES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopedPathErrorCode {
    UnsupportedPlatform,
    InvalidRoot,
    InvalidComponent,
    Missing,
    NotDirectory,
    Symlink,
    Escape,
    Alias,
    CrossDevice,
    WrongOwner,
    UnsafePermissions,
    DirectoryTooLarge,
    FilesystemUnavailable,
    Changed,
    ProfileMismatch,
    ProfileNotReady,
}

/// Stable, bounded, path-value-free authority diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ScopedPathError {
    pub code: ScopedPathErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl ScopedPathError {
    const fn new(code: ScopedPathErrorCode, field: &'static str, message: &'static str) -> Self {
        Self {
            code,
            field,
            message,
        }
    }
}

impl fmt::Display for ScopedPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for ScopedPathError {}

/// One exact directory name below an already-authorized path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ScopedPathComponent(String);

impl ScopedPathComponent {
    pub fn new(value: impl Into<String>) -> Result<Self, ScopedPathError> {
        let value = value.into();
        if !portable_component(&value) {
            return Err(invalid_component());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ScopedPathComponent {
    type Error = ScopedPathError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for ScopedPathComponent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopedPathKind {
    Scope,
    Auth,
    CredentialProfile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    owner: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(unix)]
enum PermissionClass {
    Scope,
    CredentialPrivate,
}

#[derive(Debug)]
struct AuthorityInner {
    scopes_root: PathBuf,
    root_identity: DirectoryIdentity,
    owner: u32,
}

/// Issuer for verified scope/auth/profile directory capabilities.
#[derive(Clone)]
pub struct ScopedPathAuthority {
    inner: Arc<AuthorityInner>,
}

impl fmt::Debug for ScopedPathAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScopedPathAuthority")
            .field("scopes_root", &"<redacted>")
            .field("owner", &self.inner.owner)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ScopedPathLocator {
    Scope,
    Auth,
    Profile {
        key: CredentialProfileKey,
        directory: ScopedPathComponent,
    },
}

/// Non-serializable, revalidatable capability for one verified directory.
#[derive(Clone)]
pub struct ScopedPath {
    authority: ScopedPathAuthority,
    scope: CredentialScope,
    locator: ScopedPathLocator,
    canonical_path: PathBuf,
    identity: DirectoryIdentity,
}

impl fmt::Debug for ScopedPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScopedPath")
            .field("scope", &self.scope)
            .field("kind", &self.kind())
            .field("canonical_path", &"<redacted>")
            .finish()
    }
}

impl ScopedPathAuthority {
    /// Open an existing scope container owned by the effective process user.
    ///
    /// This performs no directory creation and accepts no relative or aliased root.
    pub fn open(scopes_root: impl AsRef<Path>) -> Result<Self, ScopedPathError> {
        #[cfg(unix)]
        {
            Self::open_for_owner(scopes_root.as_ref(), effective_user_id())
        }
        #[cfg(not(unix))]
        {
            let _ = scopes_root;
            Err(unsupported_platform())
        }
    }

    #[cfg(unix)]
    fn open_for_owner(scopes_root: &Path, owner: u32) -> Result<Self, ScopedPathError> {
        validate_absolute_root(scopes_root)?;
        let root = inspect_directory(
            scopes_root,
            owner,
            PermissionClass::Scope,
            None,
            "scopes_root",
        )?;
        let canonical = canonicalize(scopes_root, "scopes_root")?;
        if canonical != scopes_root {
            return Err(aliased_path("scopes_root"));
        }
        Ok(Self {
            inner: Arc::new(AuthorityInner {
                scopes_root: canonical,
                root_identity: root,
                owner,
            }),
        })
    }

    pub fn resolve_scope_root(
        &self,
        scope: &CredentialScope,
    ) -> Result<ScopedPath, ScopedPathError> {
        self.issue(scope, ScopedPathLocator::Scope)
    }

    pub fn resolve_auth_root(
        &self,
        scope: &CredentialScope,
    ) -> Result<ScopedPath, ScopedPathError> {
        self.issue(scope, ScopedPathLocator::Auth)
    }

    pub fn resolve_profile_root(
        &self,
        key: &CredentialProfileKey,
        directory: ScopedPathComponent,
    ) -> Result<ScopedPath, ScopedPathError> {
        self.issue(
            &key.scope,
            ScopedPathLocator::Profile {
                key: key.clone(),
                directory,
            },
        )
    }

    fn issue(
        &self,
        scope: &CredentialScope,
        locator: ScopedPathLocator,
    ) -> Result<ScopedPath, ScopedPathError> {
        self.revalidate_root()?;
        let resolved = self.resolve_locator(scope, &locator)?;
        Ok(ScopedPath {
            authority: self.clone(),
            scope: scope.clone(),
            locator,
            canonical_path: resolved.path,
            identity: resolved.identity,
        })
    }

    #[cfg(unix)]
    fn revalidate_root(&self) -> Result<(), ScopedPathError> {
        let current = inspect_directory(
            &self.inner.scopes_root,
            self.inner.owner,
            PermissionClass::Scope,
            None,
            "scopes_root",
        )?;
        let canonical = canonicalize(&self.inner.scopes_root, "scopes_root")?;
        if canonical != self.inner.scopes_root {
            return Err(aliased_path("scopes_root"));
        }
        if current != self.inner.root_identity {
            return Err(changed_path());
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn revalidate_root(&self) -> Result<(), ScopedPathError> {
        Err(unsupported_platform())
    }

    #[cfg(unix)]
    fn resolve_locator(
        &self,
        scope: &CredentialScope,
        locator: &ScopedPathLocator,
    ) -> Result<ResolvedDirectory, ScopedPathError> {
        validate_scope_component(scope.principal.as_str())?;
        validate_scope_component(scope.workspace.as_str())?;

        let principal = resolve_exact_child(
            &self.inner.scopes_root,
            scope.principal.as_str(),
            self.inner.owner,
            self.inner.root_identity.device,
            PermissionClass::Scope,
        )?;
        let workspace = resolve_exact_child(
            &principal.path,
            scope.workspace.as_str(),
            self.inner.owner,
            self.inner.root_identity.device,
            PermissionClass::Scope,
        )?;

        match locator {
            ScopedPathLocator::Scope => Ok(workspace),
            ScopedPathLocator::Auth => resolve_exact_child(
                &workspace.path,
                "auth",
                self.inner.owner,
                self.inner.root_identity.device,
                PermissionClass::CredentialPrivate,
            ),
            ScopedPathLocator::Profile { key, directory } => {
                if &key.scope != scope {
                    return Err(profile_mismatch());
                }
                let auth = resolve_exact_child(
                    &workspace.path,
                    "auth",
                    self.inner.owner,
                    self.inner.root_identity.device,
                    PermissionClass::CredentialPrivate,
                )?;
                resolve_exact_child(
                    &auth.path,
                    directory.as_str(),
                    self.inner.owner,
                    self.inner.root_identity.device,
                    PermissionClass::CredentialPrivate,
                )
            },
        }
        .and_then(|resolved| {
            if !resolved.path.starts_with(&self.inner.scopes_root) {
                return Err(escaped_path());
            }
            Ok(resolved)
        })
    }

    #[cfg(not(unix))]
    fn resolve_locator(
        &self,
        _scope: &CredentialScope,
        _locator: &ScopedPathLocator,
    ) -> Result<ResolvedDirectory, ScopedPathError> {
        Err(unsupported_platform())
    }
}

impl ScopedPath {
    pub fn scope(&self) -> &CredentialScope {
        &self.scope
    }

    pub fn kind(&self) -> ScopedPathKind {
        match self.locator {
            ScopedPathLocator::Scope => ScopedPathKind::Scope,
            ScopedPathLocator::Auth => ScopedPathKind::Auth,
            ScopedPathLocator::Profile { .. } => ScopedPathKind::CredentialProfile,
        }
    }

    /// Logical profile identity bound to a credential-profile directory capability.
    pub fn profile_key(&self) -> Option<&CredentialProfileKey> {
        match &self.locator {
            ScopedPathLocator::Profile { key, .. } => Some(key),
            ScopedPathLocator::Scope | ScopedPathLocator::Auth => None,
        }
    }

    /// Bind a freshly-read ready status to this exact profile path for one execution.
    ///
    /// The caller must obtain `status` from its trusted registry/lifecycle authority
    /// immediately before materialization. The returned guard is non-cloneable and
    /// carries the exact profile revision checked by the execution plan.
    #[allow(
        dead_code,
        reason = "reserved for the dormant Phase 3 credential materializer integration"
    )]
    pub(crate) fn authorize_ready_profile(
        &self,
        status: &CredentialProfileStatus,
    ) -> Result<CredentialProfilePathAuthority, ScopedPathError> {
        let Some(key) = self.profile_key() else {
            return Err(profile_mismatch());
        };
        if key != status.key() {
            return Err(profile_mismatch());
        }
        if status.metadata().availability() != CredentialProfileAvailability::Enabled
            || status.auth_state() != AuthState::Ready
        {
            return Err(profile_not_ready());
        }
        self.revalidate()?;
        Ok(CredentialProfilePathAuthority {
            path: self.clone(),
            key: key.clone(),
            revision: status.metadata().revision(),
        })
    }

    /// Bind an exact lifecycle plan to this profile directory without claiming that
    /// authentication is already ready. Status and login must be able to inspect or
    /// populate a profile that is missing, expired, or revoked; ordinary tool execution
    /// continues to require `authorize_ready_profile` above.
    pub(crate) fn authorize_lifecycle_profile(
        &self,
        key: &CredentialProfileKey,
        revision: CredentialProfileRevision,
    ) -> Result<CredentialProfilePathAuthority, ScopedPathError> {
        if self.profile_key() != Some(key) {
            return Err(profile_mismatch());
        }
        self.revalidate()?;
        Ok(CredentialProfilePathAuthority {
            path: self.clone(),
            key: key.clone(),
            revision,
        })
    }

    /// Revalidate and then borrow the verified path for immediate filesystem use.
    pub fn revalidated_path(&self) -> Result<&Path, ScopedPathError> {
        self.revalidate()?;
        Ok(&self.canonical_path)
    }

    /// Re-run root and target checks and reject replacement since issuance.
    pub fn revalidate(&self) -> Result<(), ScopedPathError> {
        self.authority.revalidate_root()?;
        let current = self.authority.resolve_locator(&self.scope, &self.locator)?;
        if current.path != self.canonical_path || current.identity != self.identity {
            return Err(changed_path());
        }
        Ok(())
    }

    /// Compare two already-issued capabilities without exposing either path or inode.
    /// Callers must still revalidate the selected capability immediately before use.
    pub(crate) fn has_same_directory_identity(&self, other: &Self) -> bool {
        self.scope == other.scope
            && self.locator == other.locator
            && self.canonical_path == other.canonical_path
            && self.identity == other.identity
            && self.authority.inner.scopes_root == other.authority.inner.scopes_root
            && self.authority.inner.root_identity == other.authority.inner.root_identity
            && self.authority.inner.owner == other.authority.inner.owner
    }

    /// Pin the verified directory identity for descriptor-relative crate-internal I/O.
    #[cfg(unix)]
    pub(crate) fn open_revalidated_directory(&self) -> Result<File, ScopedPathError> {
        self.revalidate()?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&self.canonical_path)
            .map_err(|_| filesystem_unavailable())?;
        let metadata = directory.metadata().map_err(|_| filesystem_unavailable())?;
        let permissions = match self.locator {
            ScopedPathLocator::Scope => PermissionClass::Scope,
            ScopedPathLocator::Auth | ScopedPathLocator::Profile { .. } => {
                PermissionClass::CredentialPrivate
            },
        };
        let mode = metadata.mode() & 0o7777;
        let unsafe_mode = mode & 0o700 != 0o700
            || match permissions {
                PermissionClass::Scope => mode & 0o7022 != 0,
                PermissionClass::CredentialPrivate => mode & 0o7077 != 0,
            };
        if !metadata.is_dir()
            || metadata.uid() != self.identity.owner
            || metadata.dev() != self.identity.device
            || metadata.ino() != self.identity.inode
            || unsafe_mode
        {
            return Err(changed_path());
        }
        self.revalidate()?;
        Ok(directory)
    }

    #[cfg(not(unix))]
    pub(crate) fn open_revalidated_directory(&self) -> Result<File, ScopedPathError> {
        Err(unsupported_platform())
    }
}

/// Non-cloneable execution authority binding one freshly-ready logical profile and
/// revision to one revalidatable physical profile directory.
pub(crate) struct CredentialProfilePathAuthority {
    path: ScopedPath,
    key: CredentialProfileKey,
    revision: CredentialProfileRevision,
}

impl fmt::Debug for CredentialProfilePathAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialProfilePathAuthority")
            .field("key", &self.key)
            .field("revision", &self.revision)
            .field("path", &"<redacted>")
            .finish()
    }
}

impl CredentialProfilePathAuthority {
    pub(crate) fn key(&self) -> &CredentialProfileKey {
        &self.key
    }

    pub(crate) fn revision(&self) -> CredentialProfileRevision {
        self.revision
    }

    pub(crate) fn path(&self) -> &ScopedPath {
        &self.path
    }

    pub(crate) fn revalidate(&self) -> Result<(), ScopedPathError> {
        if self.path.profile_key() != Some(&self.key) {
            return Err(profile_mismatch());
        }
        self.path.revalidate()
    }
}

#[derive(Debug)]
struct ResolvedDirectory {
    path: PathBuf,
    identity: DirectoryIdentity,
}

#[cfg(unix)]
fn resolve_exact_child(
    parent: &Path,
    expected_name: &str,
    owner: u32,
    expected_device: u64,
    permissions: PermissionClass,
) -> Result<ResolvedDirectory, ScopedPathError> {
    validate_scope_component(expected_name)?;
    let exact_name = OsStr::new(expected_name);
    let mut found_exact = false;
    let mut found_alias = false;
    let entries = fs::read_dir(parent).map_err(|_| filesystem_unavailable())?;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_SCOPED_DIRECTORY_ENTRIES {
            return Err(directory_too_large());
        }
        let entry = entry.map_err(|_| filesystem_unavailable())?;
        let name = entry.file_name();
        if name == exact_name {
            found_exact = true;
        } else if os_name_ascii_eq_ignore_case(&name, expected_name) {
            found_alias = true;
        }
    }
    if found_alias {
        return Err(aliased_path("scoped_path"));
    }
    if !found_exact {
        return Err(missing_path());
    }

    let path = parent.join(exact_name);
    if path_bytes(&path) > MAX_SCOPED_PATH_BYTES {
        return Err(invalid_root());
    }
    let identity = inspect_directory(
        &path,
        owner,
        permissions,
        Some(expected_device),
        "scoped_path",
    )?;
    let canonical = canonicalize(&path, "scoped_path")?;
    if canonical != path {
        return Err(aliased_path("scoped_path"));
    }
    Ok(ResolvedDirectory {
        path: canonical,
        identity,
    })
}

#[cfg(unix)]
fn inspect_directory(
    path: &Path,
    owner: u32,
    permissions: PermissionClass,
    expected_device: Option<u64>,
    field: &'static str,
) -> Result<DirectoryIdentity, ScopedPathError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Err(missing_path()),
        Err(_) => return Err(filesystem_unavailable()),
    };
    if metadata.file_type().is_symlink() {
        return Err(symlink_path(field));
    }
    if !metadata.is_dir() {
        return Err(not_directory(field));
    }
    if metadata.uid() != owner {
        return Err(wrong_owner(field));
    }
    if expected_device.is_some_and(|device| metadata.dev() != device) {
        return Err(cross_device_path());
    }

    let mode = metadata.mode() & 0o7777;
    let unsafe_mode = mode & 0o700 != 0o700
        || match permissions {
            PermissionClass::Scope => mode & 0o7022 != 0,
            PermissionClass::CredentialPrivate => mode & 0o7077 != 0,
        };
    if unsafe_mode {
        return Err(unsafe_permissions(field));
    }
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
    })
}

#[cfg(unix)]
fn canonicalize(path: &Path, field: &'static str) -> Result<PathBuf, ScopedPathError> {
    let canonical = match fs::canonicalize(path) {
        Ok(path) => path,
        Err(error) if error.kind() == ErrorKind::NotFound => return Err(missing_path()),
        Err(_) => return Err(filesystem_unavailable()),
    };
    if path_bytes(&canonical) > MAX_SCOPED_PATH_BYTES {
        return Err(ScopedPathError::new(
            ScopedPathErrorCode::InvalidRoot,
            field,
            "the canonical scoped path exceeds its byte limit",
        ));
    }
    Ok(canonical)
}

#[cfg(unix)]
fn validate_absolute_root(path: &Path) -> Result<(), ScopedPathError> {
    if !path.is_absolute() || path == Path::new("/") || path_bytes(path) > MAX_SCOPED_PATH_BYTES {
        return Err(invalid_root());
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(invalid_root());
    }
    Ok(())
}

fn validate_scope_component(value: &str) -> Result<(), ScopedPathError> {
    if !portable_component(value) {
        return Err(invalid_component());
    }
    Ok(())
}

fn portable_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SCOPED_PATH_COMPONENT_BYTES
        && value != "."
        && value != ".."
        && !value.contains("..")
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+' | b'@')
        })
}

#[cfg(unix)]
fn os_name_ascii_eq_ignore_case(actual: &OsString, expected: &str) -> bool {
    actual
        .as_os_str()
        .as_bytes()
        .eq_ignore_ascii_case(expected.as_bytes())
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> usize {
    path.as_os_str().as_bytes().len()
}

#[cfg(unix)]
fn effective_user_id() -> u32 {
    // SAFETY: `geteuid` has no preconditions and does not retain pointers.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
const fn unsupported_platform() -> ScopedPathError {
    ScopedPathError::new(
        ScopedPathErrorCode::UnsupportedPlatform,
        "scoped_path",
        "scoped path ownership checks require a Unix platform",
    )
}

const fn invalid_root() -> ScopedPathError {
    ScopedPathError::new(
        ScopedPathErrorCode::InvalidRoot,
        "scopes_root",
        "the scope container must be a bounded canonical absolute directory",
    )
}

const fn invalid_component() -> ScopedPathError {
    ScopedPathError::new(
        ScopedPathErrorCode::InvalidComponent,
        "scoped_path_component",
        "scoped path components must be bounded exact portable directory names",
    )
}

const fn missing_path() -> ScopedPathError {
    ScopedPathError::new(
        ScopedPathErrorCode::Missing,
        "scoped_path",
        "the required scoped directory does not exist",
    )
}

const fn not_directory(field: &'static str) -> ScopedPathError {
    ScopedPathError::new(
        ScopedPathErrorCode::NotDirectory,
        field,
        "the scoped path is not a directory",
    )
}

const fn symlink_path(field: &'static str) -> ScopedPathError {
    ScopedPathError::new(
        ScopedPathErrorCode::Symlink,
        field,
        "symlinks cannot carry scoped path authority",
    )
}

const fn escaped_path() -> ScopedPathError {
    ScopedPathError::new(
        ScopedPathErrorCode::Escape,
        "scoped_path",
        "the scoped directory escaped its scope container",
    )
}

const fn aliased_path(field: &'static str) -> ScopedPathError {
    ScopedPathError::new(
        ScopedPathErrorCode::Alias,
        field,
        "aliased or case-colliding directories cannot carry scoped path authority",
    )
}

const fn cross_device_path() -> ScopedPathError {
    ScopedPathError::new(
        ScopedPathErrorCode::CrossDevice,
        "scoped_path",
        "scoped directory authority cannot cross a filesystem boundary",
    )
}

const fn wrong_owner(field: &'static str) -> ScopedPathError {
    ScopedPathError::new(
        ScopedPathErrorCode::WrongOwner,
        field,
        "the scoped directory is not owned by the runtime user",
    )
}

const fn unsafe_permissions(field: &'static str) -> ScopedPathError {
    ScopedPathError::new(
        ScopedPathErrorCode::UnsafePermissions,
        field,
        "the scoped directory has unsafe permissions",
    )
}

const fn directory_too_large() -> ScopedPathError {
    ScopedPathError::new(
        ScopedPathErrorCode::DirectoryTooLarge,
        "scoped_path",
        "the scoped directory exceeds its entry limit",
    )
}

const fn filesystem_unavailable() -> ScopedPathError {
    ScopedPathError::new(
        ScopedPathErrorCode::FilesystemUnavailable,
        "scoped_path",
        "the scoped directory could not be inspected",
    )
}

const fn changed_path() -> ScopedPathError {
    ScopedPathError::new(
        ScopedPathErrorCode::Changed,
        "scoped_path",
        "the scoped directory changed after authority was issued",
    )
}

const fn profile_mismatch() -> ScopedPathError {
    ScopedPathError::new(
        ScopedPathErrorCode::ProfileMismatch,
        "credential_profile",
        "the profile path authority belongs to a different logical profile",
    )
}

#[allow(
    dead_code,
    reason = "reserved for the dormant Phase 3 credential materializer integration"
)]
const fn profile_not_ready() -> ScopedPathError {
    ScopedPathError::new(
        ScopedPathErrorCode::ProfileNotReady,
        "credential_profile",
        "the profile path cannot be authorized without a current ready status",
    )
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        os::unix::fs::{symlink, MetadataExt, PermissionsExt},
        sync::atomic::{AtomicU64, Ordering},
        thread,
    };

    use serde_json::json;

    use super::*;

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
                "tool-runtime-scoped-paths-{}-{sequence}",
                std::process::id()
            ));
            let scopes_root = container.join("scopes");
            let scope = CredentialScope::new("owner", "default").expect("valid scope");
            fs::create_dir_all(
                scopes_root
                    .join(scope.principal.as_str())
                    .join(scope.workspace.as_str())
                    .join("auth"),
            )
            .expect("create fixture");
            set_mode(&container, 0o700);
            set_mode(&scopes_root, 0o755);
            set_mode(&scopes_root.join(scope.principal.as_str()), 0o755);
            set_mode(
                &scopes_root
                    .join(scope.principal.as_str())
                    .join(scope.workspace.as_str()),
                0o755,
            );
            set_mode(
                &scopes_root
                    .join(scope.principal.as_str())
                    .join(scope.workspace.as_str())
                    .join("auth"),
                0o700,
            );
            Self {
                container,
                scopes_root,
                scope,
            }
        }

        fn auth_root(&self) -> PathBuf {
            self.scopes_root
                .join(self.scope.principal.as_str())
                .join(self.scope.workspace.as_str())
                .join("auth")
        }

        fn create_profile(&self, name: &str) -> PathBuf {
            let path = self.auth_root().join(name);
            fs::create_dir(&path).expect("create profile");
            set_mode(&path, 0o700);
            path
        }

        fn profile_key(&self, alias: &str) -> CredentialProfileKey {
            CredentialProfileKey::new(
                self.scope.clone(),
                "test-provider",
                alias,
                crate::credential_profiles::CredentialProfileBinding::Provider,
            )
            .expect("profile key")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.container);
        }
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set permissions");
    }

    #[test]
    fn valid_scope_auth_and_profile_paths_are_typed_and_revalidatable() {
        let fixture = Fixture::new();
        let profile_path = fixture.create_profile("gws-work");
        let authority = ScopedPathAuthority::open(&fixture.scopes_root).expect("authority");
        assert!(!format!("{authority:?}").contains(fixture.scopes_root.to_str().unwrap()));

        let scope = authority
            .resolve_scope_root(&fixture.scope)
            .expect("scope root");
        let auth = authority
            .resolve_auth_root(&fixture.scope)
            .expect("auth root");
        let profile = authority
            .resolve_profile_root(
                &fixture.profile_key("work"),
                ScopedPathComponent::new("gws-work").unwrap(),
            )
            .expect("profile root");

        assert_eq!(scope.kind(), ScopedPathKind::Scope);
        assert_eq!(auth.kind(), ScopedPathKind::Auth);
        assert_eq!(profile.kind(), ScopedPathKind::CredentialProfile);
        assert_eq!(profile.scope(), &fixture.scope);
        assert_eq!(profile.profile_key(), Some(&fixture.profile_key("work")));
        assert_eq!(profile.revalidated_path().unwrap(), profile_path);
        assert!(scope.revalidate().is_ok());
        assert!(auth.revalidate().is_ok());
        assert!(profile.revalidate().is_ok());
        assert!(!format!("{profile:?}").contains(profile_path.to_str().unwrap()));
    }

    #[test]
    fn ready_profile_authority_binds_exact_key_and_revision_and_is_not_cloneable() {
        static_assertions::assert_not_impl_any!(
            CredentialProfilePathAuthority: Clone,
            serde::Serialize
        );
        let fixture = Fixture::new();
        fixture.create_profile("gws-work");
        let profile = ScopedPathAuthority::open(&fixture.scopes_root)
            .unwrap()
            .resolve_profile_root(
                &fixture.profile_key("work"),
                ScopedPathComponent::new("gws-work").unwrap(),
            )
            .unwrap();
        let status = |alias: &str, revision: u64, state: AuthState| {
            CredentialProfileStatus::new(
                crate::credential_profiles::CredentialProfileMetadata::new(
                    fixture.profile_key(alias),
                    None,
                    true,
                    CredentialProfileAvailability::Enabled,
                    CredentialProfileRevision::new(revision).unwrap(),
                )
                .unwrap(),
                state,
            )
            .unwrap()
        };

        let authority = profile
            .authorize_ready_profile(&status("work", 7, AuthState::Ready))
            .unwrap();
        assert_eq!(authority.key(), &fixture.profile_key("work"));
        assert_eq!(authority.revision().get(), 7);
        assert!(authority.revalidate().is_ok());
        assert_eq!(
            profile
                .authorize_ready_profile(&status("personal", 7, AuthState::Ready))
                .expect_err("wrong profile")
                .code,
            ScopedPathErrorCode::ProfileMismatch
        );
        assert_eq!(
            profile
                .authorize_ready_profile(&status("work", 7, AuthState::Unknown))
                .expect_err("not ready")
                .code,
            ScopedPathErrorCode::ProfileNotReady
        );
    }

    #[test]
    fn components_and_errors_are_bounded_validated_and_value_free() {
        for invalid in [
            "",
            ".",
            "..",
            "../other",
            "safe..other",
            "/absolute",
            "nested/path",
            " leading",
            "unicode-₹",
        ] {
            assert!(ScopedPathComponent::new(invalid).is_err(), "{invalid:?}");
            assert!(serde_json::from_value::<ScopedPathComponent>(json!(invalid)).is_err());
        }
        assert!(ScopedPathComponent::new("gws-work_1").is_ok());
        assert!(ScopedPathComponent::new(format!(
            "p{}",
            "a".repeat(MAX_SCOPED_PATH_COMPONENT_BYTES)
        ))
        .is_err());

        let canary = "../../SCOPED_PATH_CANARY";
        let error = ScopedPathComponent::new(canary).expect_err("invalid component");
        assert!(!error.to_string().contains(canary));
        assert!(!serde_json::to_string(&error).unwrap().contains(canary));
    }

    #[test]
    fn relative_parent_and_symlinked_roots_fail_closed() {
        let fixture = Fixture::new();
        assert_eq!(
            ScopedPathAuthority::open(Path::new("relative/scopes"))
                .expect_err("relative root")
                .code,
            ScopedPathErrorCode::InvalidRoot
        );
        let oversized_root = PathBuf::from(format!("/{}", "a".repeat(MAX_SCOPED_PATH_BYTES)));
        assert_eq!(
            ScopedPathAuthority::open(&oversized_root)
                .expect_err("oversized root")
                .code,
            ScopedPathErrorCode::InvalidRoot
        );

        let root_link = fixture.container.join("scopes-link");
        symlink(&fixture.scopes_root, &root_link).expect("root symlink");
        assert_eq!(
            ScopedPathAuthority::open(&root_link)
                .expect_err("symlinked root")
                .code,
            ScopedPathErrorCode::Symlink
        );
    }

    #[test]
    fn symlinked_auth_and_profile_directories_cannot_escape() {
        let fixture = Fixture::new();
        let authority = ScopedPathAuthority::open(&fixture.scopes_root).expect("authority");
        let outside = fixture.container.join("outside");
        fs::create_dir(&outside).expect("outside");
        set_mode(&outside, 0o700);

        let profile_link = fixture.auth_root().join("gws-work");
        symlink(&outside, &profile_link).expect("profile symlink");
        assert_eq!(
            authority
                .resolve_profile_root(
                    &fixture.profile_key("work"),
                    ScopedPathComponent::new("gws-work").unwrap(),
                )
                .expect_err("symlinked profile")
                .code,
            ScopedPathErrorCode::Symlink
        );

        fs::remove_file(&profile_link).expect("remove profile link");
        fs::remove_dir(fixture.auth_root()).expect("remove auth root");
        symlink(&outside, fixture.auth_root()).expect("auth symlink");
        assert_eq!(
            authority
                .resolve_auth_root(&fixture.scope)
                .expect_err("symlinked auth")
                .code,
            ScopedPathErrorCode::Symlink
        );
    }

    #[test]
    fn case_aliases_fail_on_case_sensitive_and_case_insensitive_filesystems() {
        let fixture = Fixture::new();
        let original = fixture.scopes_root.join("owner");
        let aliased = fixture.scopes_root.join("Owner");
        fs::rename(&original, &aliased).expect("rename principal case");
        let authority = ScopedPathAuthority::open(&fixture.scopes_root).expect("authority");
        assert_eq!(
            authority
                .resolve_scope_root(&fixture.scope)
                .expect_err("case alias")
                .code,
            ScopedPathErrorCode::Alias
        );
    }

    #[test]
    fn ownership_and_permission_policies_fail_closed() {
        let fixture = Fixture::new();
        assert_eq!(
            ScopedPathAuthority::open_for_owner(
                &fixture.scopes_root,
                effective_user_id().wrapping_add(1),
            )
            .expect_err("wrong owner")
            .code,
            ScopedPathErrorCode::WrongOwner
        );
        let device = fs::symlink_metadata(&fixture.scopes_root)
            .expect("scope metadata")
            .dev();
        assert_eq!(
            inspect_directory(
                &fixture.scopes_root,
                effective_user_id(),
                PermissionClass::Scope,
                Some(device.wrapping_add(1)),
                "scopes_root",
            )
            .expect_err("cross-device authority")
            .code,
            ScopedPathErrorCode::CrossDevice
        );

        set_mode(&fixture.scopes_root, 0o775);
        assert_eq!(
            ScopedPathAuthority::open(&fixture.scopes_root)
                .expect_err("writable scope root")
                .code,
            ScopedPathErrorCode::UnsafePermissions
        );
        set_mode(&fixture.scopes_root, 0o755);

        let authority = ScopedPathAuthority::open(&fixture.scopes_root).expect("authority");
        set_mode(&fixture.auth_root(), 0o750);
        assert_eq!(
            authority
                .resolve_auth_root(&fixture.scope)
                .expect_err("shared auth root")
                .code,
            ScopedPathErrorCode::UnsafePermissions
        );
        set_mode(&fixture.auth_root(), 0o700);

        let profile = fixture.create_profile("gws-work");
        set_mode(&profile, 0o701);
        assert_eq!(
            authority
                .resolve_profile_root(
                    &fixture.profile_key("work"),
                    ScopedPathComponent::new("gws-work").unwrap(),
                )
                .expect_err("shared profile")
                .code,
            ScopedPathErrorCode::UnsafePermissions
        );
    }

    #[test]
    fn missing_and_non_directory_targets_are_distinct() {
        let fixture = Fixture::new();
        let authority = ScopedPathAuthority::open(&fixture.scopes_root).expect("authority");
        assert_eq!(
            authority
                .resolve_profile_root(
                    &fixture.profile_key("missing"),
                    ScopedPathComponent::new("missing-profile").unwrap(),
                )
                .expect_err("missing profile")
                .code,
            ScopedPathErrorCode::Missing
        );

        let file = fixture.auth_root().join("file-profile");
        fs::write(&file, b"not a directory").expect("create file profile");
        set_mode(&file, 0o600);
        assert_eq!(
            authority
                .resolve_profile_root(
                    &fixture.profile_key("file"),
                    ScopedPathComponent::new("file-profile").unwrap(),
                )
                .expect_err("file profile")
                .code,
            ScopedPathErrorCode::NotDirectory
        );
    }

    #[test]
    fn revalidation_detects_permission_change_and_inode_replacement() {
        let fixture = Fixture::new();
        let profile_path = fixture.create_profile("gws-work");
        let authority = ScopedPathAuthority::open(&fixture.scopes_root).expect("authority");
        let profile = authority
            .resolve_profile_root(
                &fixture.profile_key("work"),
                ScopedPathComponent::new("gws-work").unwrap(),
            )
            .expect("profile");

        set_mode(&profile_path, 0o750);
        assert_eq!(
            profile.expect_revalidation_error().code,
            ScopedPathErrorCode::UnsafePermissions
        );
        set_mode(&profile_path, 0o700);
        assert!(profile.revalidate().is_ok());

        let old = fixture.auth_root().join("gws-work-old");
        fs::rename(&profile_path, &old).expect("move old profile");
        fs::create_dir(&profile_path).expect("replace profile");
        set_mode(&profile_path, 0o700);
        assert_eq!(
            profile.expect_revalidation_error().code,
            ScopedPathErrorCode::Changed
        );
    }

    impl ScopedPath {
        fn expect_revalidation_error(&self) -> ScopedPathError {
            self.revalidate().expect_err("revalidation must fail")
        }
    }

    #[test]
    fn scope_component_and_directory_scan_limits_are_enforced() {
        let fixture = Fixture::new();
        let authority = ScopedPathAuthority::open(&fixture.scopes_root).expect("authority");
        let oversized_scope = CredentialScope::new(
            format!("p{}", "a".repeat(MAX_SCOPED_PATH_COMPONENT_BYTES)),
            "default",
        )
        .expect("logical scope permits its larger phase 2a bound");
        assert_eq!(
            authority
                .resolve_scope_root(&oversized_scope)
                .expect_err("filesystem component too large")
                .code,
            ScopedPathErrorCode::InvalidComponent
        );

        for index in 0..=MAX_SCOPED_DIRECTORY_ENTRIES {
            fs::write(fixture.scopes_root.join(format!("noise-{index:04}")), b"")
                .expect("create scan noise");
        }
        assert_eq!(
            authority
                .resolve_scope_root(&fixture.scope)
                .expect_err("directory scan limit")
                .code,
            ScopedPathErrorCode::DirectoryTooLarge
        );
    }

    #[test]
    fn maximum_valid_resolution_and_revalidation_fit_a_small_stack() {
        let result = thread::Builder::new()
            .name("scoped-path-small-stack".to_owned())
            .stack_size(128 * 1024)
            .spawn(|| {
                let fixture = Fixture::new();
                let profile_name = format!("p{}", "a".repeat(MAX_SCOPED_PATH_COMPONENT_BYTES - 1));
                fixture.create_profile(&profile_name);
                let authority = ScopedPathAuthority::open(&fixture.scopes_root).expect("authority");
                let profile = authority
                    .resolve_profile_root(
                        &fixture.profile_key("maximum"),
                        ScopedPathComponent::new(profile_name).unwrap(),
                    )
                    .expect("maximum profile");
                profile.revalidate()
            })
            .expect("spawn small-stack path test")
            .join()
            .expect("path resolution must not panic or overflow");
        assert!(result.is_ok());
    }
}
