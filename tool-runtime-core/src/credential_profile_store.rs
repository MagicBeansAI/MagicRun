//! Concurrent local storage and provider-neutral legacy references for credential profiles.
//!
//! The store persists validated metadata only. It never reads credential contents,
//! moves an existing profile directory, resolves a secret, invokes an authentication
//! lifecycle, mutates process-global state, or enables a production route. Product-owned
//! compatibility adapters can normalize legacy configuration into opaque path attachments;
//! directory presence is reported as `Unknown`, never as proof of readiness.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fmt,
    fs::File,
    io::{ErrorKind, Read, Write},
    sync::{atomic::AtomicU64, atomic::Ordering, Mutex},
    thread,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::{
    fs::MetadataExt,
    io::{AsRawFd, FromRawFd},
};

use serde::{Deserialize, Serialize};

use crate::{
    credential_profiles::{
        CreateCredentialProfileReference, CredentialProfileAvailability, CredentialProfileError,
        CredentialProfileErrorCode, CredentialProfileKey, CredentialProfileMetadata,
        CredentialProfileRegistry, CredentialProfileRegistrySnapshot, CredentialProfileRevision,
        CredentialProfileStatus, CredentialScope, DefaultProfileUpdate, ExpectedCredentialIdentity,
        ExpectedIdentityUpdate, SetCredentialProfileDisabled, UpdateCredentialProfileMetadata,
        MAX_PROFILES_PER_SCOPE,
    },
    manifest::AuthState,
    scoped_paths::{ScopedPath, ScopedPathKind},
};

pub const CREDENTIAL_PROFILE_STORE_V1: &str = "tool-runtime.credential-profile-store.v1";
pub const MAX_CREDENTIAL_PROFILE_STORE_BYTES: usize = 8 * 1024 * 1024;

const STORE_FILE_NAME: &str = ".credential-profiles.v1.json";
const LOCK_FILE_NAME: &str = ".credential-profiles.v1.lock";
const MAX_DOCUMENT_DEPTH: usize = 48;
const LOCK_RETRY_COUNT: usize = 100;
const LOCK_RETRY_DELAY: Duration = Duration::from_millis(5);
const STAGING_CREATE_ATTEMPTS: usize = 32;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct LegacyProfileEntry {
    metadata: CredentialProfileMetadata,
    profile_root: Option<ScopedPath>,
}

impl fmt::Debug for LegacyProfileEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyProfileEntry")
            .field("metadata", &self.metadata)
            .field(
                "profile_root",
                &self.profile_root.as_ref().map(|_| "<scoped-path>"),
            )
            .finish()
    }
}

/// Opaque, bounded projection of legacy account metadata and verified path authority.
///
/// It exposes no physical path and can only be consumed by the local registry.
#[derive(Clone)]
pub struct LegacyCredentialProfileSet {
    scope: CredentialScope,
    entries: BTreeMap<CredentialProfileKey, LegacyProfileEntry>,
}

impl fmt::Debug for LegacyCredentialProfileSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyCredentialProfileSet")
            .field("scope", &self.scope)
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

impl LegacyCredentialProfileSet {
    /// Build a bounded compatibility projection from product-normalized references.
    pub fn new(
        scope: CredentialScope,
        references: Vec<LegacyCredentialProfileReference>,
    ) -> Result<Self, CredentialProfileError> {
        if references.len() > MAX_PROFILES_PER_SCOPE {
            return Err(collection_too_large());
        }
        let mut entries = BTreeMap::new();
        for reference in references {
            if reference.metadata.key().scope != scope {
                return Err(scope_mismatch());
            }
            if entries
                .insert(
                    reference.metadata.key().clone(),
                    LegacyProfileEntry {
                        metadata: reference.metadata,
                        profile_root: reference.profile_root,
                    },
                )
                .is_some()
            {
                return Err(duplicate_profile());
            }
        }
        let set = Self { scope, entries };
        CredentialProfileRegistrySnapshot::new(
            set.scope.clone(),
            set.entries
                .values()
                .map(|entry| {
                    let state = if entry.metadata.availability()
                        == CredentialProfileAvailability::Disabled
                    {
                        AuthState::Denied
                    } else {
                        AuthState::Unknown
                    };
                    CredentialProfileStatus::new(entry.metadata.clone(), state)
                })
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        Ok(set)
    }

    pub fn empty(scope: CredentialScope) -> Self {
        Self {
            scope,
            entries: BTreeMap::new(),
        }
    }

    pub fn scope(&self) -> &CredentialScope {
        &self.scope
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// One product-normalized legacy metadata/path reference.
///
/// The constructor rejects a path capability for a different logical profile.
pub struct LegacyCredentialProfileReference {
    metadata: CredentialProfileMetadata,
    profile_root: Option<ScopedPath>,
}

impl LegacyCredentialProfileReference {
    pub fn new(
        metadata: CredentialProfileMetadata,
        profile_root: Option<ScopedPath>,
    ) -> Result<Self, CredentialProfileError> {
        if profile_root.as_ref().is_some_and(|path| {
            path.kind() != ScopedPathKind::CredentialProfile
                || path.profile_key() != Some(metadata.key())
        }) {
            return Err(scope_mismatch());
        }
        Ok(Self {
            metadata,
            profile_root,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCredentialProfile {
    key: CredentialProfileKey,
    expected_identity: Option<ExpectedCredentialIdentity>,
    is_default: bool,
    disabled: bool,
    revision: CredentialProfileRevision,
}

impl StoredCredentialProfile {
    fn from_metadata(metadata: &CredentialProfileMetadata) -> Self {
        Self {
            key: metadata.key().clone(),
            expected_identity: metadata.expected_identity().cloned(),
            is_default: metadata.is_default(),
            disabled: metadata.availability() == CredentialProfileAvailability::Disabled,
            revision: metadata.revision(),
        }
    }

    fn metadata(&self) -> Result<CredentialProfileMetadata, CredentialProfileError> {
        CredentialProfileMetadata::new(
            self.key.clone(),
            self.expected_identity.clone(),
            self.is_default,
            if self.disabled {
                CredentialProfileAvailability::Disabled
            } else {
                CredentialProfileAvailability::Enabled
            },
            self.revision,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRegistryFile {
    schema_version: String,
    scope: CredentialScope,
    generation: u64,
    profiles: Vec<StoredCredentialProfile>,
}

impl StoredRegistryFile {
    fn empty(scope: CredentialScope) -> Self {
        Self {
            schema_version: CREDENTIAL_PROFILE_STORE_V1.to_owned(),
            scope,
            generation: 0,
            profiles: Vec::new(),
        }
    }

    fn validate(&self, expected_scope: &CredentialScope) -> Result<(), CredentialProfileError> {
        if self.schema_version != CREDENTIAL_PROFILE_STORE_V1 || &self.scope != expected_scope {
            return Err(CredentialProfileError::registry_unavailable());
        }
        if self.profiles.len() > MAX_PROFILES_PER_SCOPE {
            return Err(collection_too_large());
        }
        let mut keys = BTreeSet::new();
        for profile in &self.profiles {
            if &profile.key.scope != expected_scope || !keys.insert(profile.key.clone()) {
                return Err(CredentialProfileError::registry_unavailable());
            }
            profile.metadata()?;
        }
        Ok(())
    }

    fn into_map(
        self,
    ) -> Result<BTreeMap<CredentialProfileKey, StoredCredentialProfile>, CredentialProfileError>
    {
        self.validate(&self.scope)?;
        Ok(self
            .profiles
            .into_iter()
            .map(|profile| (profile.key.clone(), profile))
            .collect())
    }

    fn replace_profiles(
        &mut self,
        profiles: BTreeMap<CredentialProfileKey, StoredCredentialProfile>,
    ) -> Result<(), CredentialProfileError> {
        if profiles.len() > MAX_PROFILES_PER_SCOPE {
            return Err(collection_too_large());
        }
        self.profiles = profiles.into_values().collect();
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(CredentialProfileError::registry_unavailable)?;
        Ok(())
    }
}

/// Scope-bound metadata registry backed by one atomically published local JSON file.
pub struct LocalCredentialProfileRegistry {
    scope: CredentialScope,
    auth_root: ScopedPath,
    legacy: LegacyCredentialProfileSet,
    local_write: Mutex<()>,
}

impl fmt::Debug for LocalCredentialProfileRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalCredentialProfileRegistry")
            .field("scope", &self.scope)
            .field("auth_root", &"<scoped-path>")
            .field("legacy", &self.legacy)
            .finish_non_exhaustive()
    }
}

impl LocalCredentialProfileRegistry {
    pub fn open(
        scope: CredentialScope,
        auth_root: ScopedPath,
        legacy: LegacyCredentialProfileSet,
    ) -> Result<Self, CredentialProfileError> {
        if auth_root.kind() != ScopedPathKind::Auth
            || auth_root.scope() != &scope
            || legacy.scope() != &scope
        {
            return Err(scope_mismatch());
        }
        auth_root
            .revalidate()
            .map_err(|_| CredentialProfileError::registry_unavailable())?;
        let registry = Self {
            scope,
            auth_root,
            legacy,
            local_write: Mutex::new(()),
        };
        let store = registry.read_store()?;
        registry.validate_candidate(&store)?;
        Ok(registry)
    }

    fn ensure_scope(&self, scope: &CredentialScope) -> Result<(), CredentialProfileError> {
        if scope != &self.scope {
            return Err(scope_mismatch());
        }
        Ok(())
    }

    fn read_store(&self) -> Result<StoredRegistryFile, CredentialProfileError> {
        #[cfg(unix)]
        let directory = self
            .auth_root
            .open_revalidated_directory()
            .map_err(|_| CredentialProfileError::registry_unavailable())?;
        #[cfg(not(unix))]
        return Err(CredentialProfileError::registry_unavailable());
        #[cfg(unix)]
        self.read_store_from(&directory)
    }

    #[cfg(unix)]
    fn read_store_from(
        &self,
        directory: &File,
    ) -> Result<StoredRegistryFile, CredentialProfileError> {
        let Some(bytes) = read_secure_bounded_file(directory, STORE_FILE_NAME)? else {
            return Ok(StoredRegistryFile::empty(self.scope.clone()));
        };
        validate_json_depth(&bytes)?;
        let store: StoredRegistryFile = serde_json::from_slice(&bytes)
            .map_err(|_| CredentialProfileError::registry_unavailable())?;
        store.validate(&self.scope)?;
        Ok(store)
    }

    fn merged_statuses(
        &self,
        stored: &StoredRegistryFile,
    ) -> Result<Vec<CredentialProfileStatus>, CredentialProfileError> {
        let mut merged = BTreeMap::<CredentialProfileKey, CredentialProfileMetadata>::new();
        for (key, entry) in &self.legacy.entries {
            merged.insert(key.clone(), entry.metadata.clone());
        }
        for profile in &stored.profiles {
            merged.insert(profile.key.clone(), profile.metadata()?);
        }
        merged
            .into_values()
            .map(|metadata| {
                let auth_state = self.auth_state_for(&metadata);
                CredentialProfileStatus::new(metadata, auth_state)
            })
            .collect()
    }

    fn auth_state_for(&self, metadata: &CredentialProfileMetadata) -> AuthState {
        if metadata.availability() == CredentialProfileAvailability::Disabled {
            return AuthState::Denied;
        }
        match self.legacy.entries.get(metadata.key()) {
            Some(entry) => match &entry.profile_root {
                Some(path) if path.revalidate().is_ok() => AuthState::Unknown,
                Some(_) => AuthState::Error,
                None => AuthState::Missing,
            },
            None => AuthState::Missing,
        }
    }

    fn validate_candidate(&self, store: &StoredRegistryFile) -> Result<(), CredentialProfileError> {
        CredentialProfileRegistrySnapshot::new(self.scope.clone(), self.merged_statuses(store)?)?;
        Ok(())
    }

    fn mutate<T>(
        &self,
        operation: impl FnOnce(
            &mut BTreeMap<CredentialProfileKey, StoredCredentialProfile>,
        ) -> Result<T, CredentialProfileError>,
    ) -> Result<T, CredentialProfileError> {
        #[cfg(not(unix))]
        {
            let _ = operation;
            return Err(CredentialProfileError::registry_unavailable());
        }
        #[cfg(unix)]
        {
            let _local = self
                .local_write
                .lock()
                .map_err(|_| CredentialProfileError::registry_unavailable())?;
            let directory = self
                .auth_root
                .open_revalidated_directory()
                .map_err(|_| CredentialProfileError::registry_unavailable())?;
            let file_lock = RegistryFileLock::acquire(&directory)?;
            self.auth_root
                .revalidate()
                .map_err(|_| CredentialProfileError::registry_unavailable())?;

            let mut store = self.read_store_from(&directory)?;
            file_lock.revalidate(&directory)?;
            let mut profiles = store.clone().into_map()?;
            let result = operation(&mut profiles)?;
            store.replace_profiles(profiles)?;
            self.validate_candidate(&store)?;
            write_store_atomic(&directory, &store, Some(&file_lock))?;
            Ok(result)
        }
    }

    fn current_metadata(
        &self,
        profiles: &BTreeMap<CredentialProfileKey, StoredCredentialProfile>,
        key: &CredentialProfileKey,
    ) -> Result<CredentialProfileMetadata, CredentialProfileError> {
        if let Some(profile) = profiles.get(key) {
            return profile.metadata();
        }
        self.legacy
            .entries
            .get(key)
            .map(|entry| entry.metadata.clone())
            .ok_or_else(CredentialProfileError::not_found)
    }

    fn status_from_metadata(
        &self,
        metadata: CredentialProfileMetadata,
    ) -> Result<CredentialProfileStatus, CredentialProfileError> {
        let auth_state = self.auth_state_for(&metadata);
        CredentialProfileStatus::new(metadata, auth_state)
    }
}

impl CredentialProfileRegistry for LocalCredentialProfileRegistry {
    fn snapshot(
        &self,
        scope: &CredentialScope,
    ) -> Result<CredentialProfileRegistrySnapshot, CredentialProfileError> {
        self.ensure_scope(scope)?;
        let store = self.read_store()?;
        CredentialProfileRegistrySnapshot::new(self.scope.clone(), self.merged_statuses(&store)?)
    }

    fn status(
        &self,
        key: &CredentialProfileKey,
    ) -> Result<Option<CredentialProfileStatus>, CredentialProfileError> {
        self.ensure_scope(&key.scope)?;
        let store = self.read_store()?;
        self.validate_candidate(&store)?;
        Ok(self
            .merged_statuses(&store)?
            .into_iter()
            .find(|status| status.key() == key))
    }

    fn create_reference(
        &self,
        request: CreateCredentialProfileReference,
    ) -> Result<CredentialProfileStatus, CredentialProfileError> {
        self.ensure_scope(&request.key().scope)?;
        let key = request.key().clone();
        let expected_identity = request.expected_identity().cloned();
        let is_default = request.make_default();
        let metadata = self.mutate(|profiles| {
            if profiles.contains_key(&key) || self.legacy.entries.contains_key(&key) {
                return Err(duplicate_profile());
            }
            let metadata = CredentialProfileMetadata::new(
                key.clone(),
                expected_identity,
                is_default,
                CredentialProfileAvailability::Enabled,
                revision(1)?,
            )?;
            profiles.insert(
                key.clone(),
                StoredCredentialProfile::from_metadata(&metadata),
            );
            Ok(metadata)
        })?;
        self.status_from_metadata(metadata)
    }

    fn update_metadata(
        &self,
        request: UpdateCredentialProfileMetadata,
    ) -> Result<CredentialProfileStatus, CredentialProfileError> {
        self.ensure_scope(&request.key().scope)?;
        let key = request.key().clone();
        let expected_revision = request.expected_revision();
        let expected_update = request.expected_identity().clone();
        let default_update = request.default_profile();
        let metadata = self.mutate(|profiles| {
            let current = self.current_metadata(profiles, &key)?;
            if current.revision() != expected_revision {
                return Err(CredentialProfileError::conflict());
            }
            let expected_identity = match expected_update {
                ExpectedIdentityUpdate::Preserve => current.expected_identity().cloned(),
                ExpectedIdentityUpdate::Clear => None,
                ExpectedIdentityUpdate::Set { value } => Some(value),
            };
            let is_default = match default_update {
                DefaultProfileUpdate::Preserve => current.is_default(),
                DefaultProfileUpdate::Set(value) => value,
            };
            let metadata = CredentialProfileMetadata::new(
                key.clone(),
                expected_identity,
                is_default,
                current.availability(),
                next_revision(current.revision())?,
            )?;
            profiles.insert(
                key.clone(),
                StoredCredentialProfile::from_metadata(&metadata),
            );
            Ok(metadata)
        })?;
        self.status_from_metadata(metadata)
    }

    fn set_disabled(
        &self,
        request: SetCredentialProfileDisabled,
    ) -> Result<CredentialProfileStatus, CredentialProfileError> {
        self.ensure_scope(&request.key().scope)?;
        let key = request.key().clone();
        let expected_revision = request.expected_revision();
        let disabled = request.disabled();
        let metadata = self.mutate(|profiles| {
            let current = self.current_metadata(profiles, &key)?;
            if current.revision() != expected_revision {
                return Err(CredentialProfileError::conflict());
            }
            let metadata = CredentialProfileMetadata::new(
                key.clone(),
                current.expected_identity().cloned(),
                current.is_default(),
                if disabled {
                    CredentialProfileAvailability::Disabled
                } else {
                    CredentialProfileAvailability::Enabled
                },
                next_revision(current.revision())?,
            )?;
            profiles.insert(
                key.clone(),
                StoredCredentialProfile::from_metadata(&metadata),
            );
            Ok(metadata)
        })?;
        self.status_from_metadata(metadata)
    }
}

#[cfg(unix)]
struct RegistryFileLock {
    file: File,
}

#[cfg(unix)]
impl RegistryFileLock {
    fn acquire(directory: &File) -> Result<Self, CredentialProfileError> {
        let file = open_file_at(
            directory,
            LOCK_FILE_NAME,
            libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
        .map_err(|_| CredentialProfileError::registry_unavailable())?;
        validate_private_regular_file(directory, &file, None)?;
        for _ in 0..LOCK_RETRY_COUNT {
            // SAFETY: `file` owns a valid descriptor for the lifetime of the guard.
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result == 0 {
                let guard = Self { file };
                guard.revalidate(directory)?;
                return Ok(guard);
            }
            let error = std::io::Error::last_os_error();
            if !matches!(error.kind(), ErrorKind::WouldBlock) {
                return Err(CredentialProfileError::registry_unavailable());
            }
            thread::sleep(LOCK_RETRY_DELAY);
        }
        Err(CredentialProfileError::registry_unavailable())
    }

    fn revalidate(&self, directory: &File) -> Result<(), CredentialProfileError> {
        validate_private_regular_file(directory, &self.file, None)?;
        let named = open_file_at(
            directory,
            LOCK_FILE_NAME,
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        )
        .map_err(|_| CredentialProfileError::registry_unavailable())?;
        validate_private_regular_file(directory, &named, None)?;
        let held = self
            .file
            .metadata()
            .map_err(|_| CredentialProfileError::registry_unavailable())?;
        let current = named
            .metadata()
            .map_err(|_| CredentialProfileError::registry_unavailable())?;
        if held.dev() != current.dev()
            || held.ino() != current.ino()
            || held.uid() != current.uid()
            || held.nlink() != current.nlink()
        {
            return Err(CredentialProfileError::registry_unavailable());
        }
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for RegistryFileLock {
    fn drop(&mut self) {
        // SAFETY: best-effort release on an owned valid descriptor; close also releases it.
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(not(unix))]
struct RegistryFileLock;

#[cfg(not(unix))]
impl RegistryFileLock {
    fn acquire(_auth_root: &()) -> Result<Self, CredentialProfileError> {
        Err(CredentialProfileError::registry_unavailable())
    }
}

fn validate_json_depth(bytes: &[u8]) -> Result<(), CredentialProfileError> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match *byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                if depth > MAX_DOCUMENT_DEPTH {
                    return Err(CredentialProfileError::registry_unavailable());
                }
            },
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {},
        }
    }
    Ok(())
}

fn read_secure_bounded_file(
    directory: &File,
    name: &str,
) -> Result<Option<Vec<u8>>, CredentialProfileError> {
    #[cfg(unix)]
    {
        let mut file = match open_file_at(
            directory,
            name,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(CredentialProfileError::registry_unavailable()),
        };
        let length = validate_private_regular_file(
            directory,
            &file,
            Some(MAX_CREDENTIAL_PROFILE_STORE_BYTES),
        )?;
        let bytes = read_bounded_exact(&mut file, length, MAX_CREDENTIAL_PROFILE_STORE_BYTES)?;
        Ok(Some(bytes))
    }
    #[cfg(not(unix))]
    {
        let _ = (directory, name);
        Err(CredentialProfileError::registry_unavailable())
    }
}

fn read_bounded_exact(
    reader: &mut impl Read,
    expected_bytes: usize,
    max_bytes: usize,
) -> Result<Vec<u8>, CredentialProfileError> {
    if expected_bytes > max_bytes {
        return Err(CredentialProfileError::registry_unavailable());
    }
    let mut bytes = Vec::with_capacity(expected_bytes);
    reader
        .take((max_bytes.saturating_add(1)) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| CredentialProfileError::registry_unavailable())?;
    if bytes.len() != expected_bytes || bytes.len() > max_bytes {
        return Err(CredentialProfileError::registry_unavailable());
    }
    Ok(bytes)
}

#[cfg(unix)]
fn validate_private_regular_file(
    directory: &File,
    file: &File,
    max_bytes: Option<usize>,
) -> Result<usize, CredentialProfileError> {
    let metadata = file
        .metadata()
        .map_err(|_| CredentialProfileError::registry_unavailable())?;
    let directory_metadata = directory
        .metadata()
        .map_err(|_| CredentialProfileError::registry_unavailable())?;
    if !metadata.is_file()
        || metadata.uid() != effective_user_id()
        || metadata.dev() != directory_metadata.dev()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || max_bytes.is_some_and(|max| metadata.len() > max as u64)
    {
        return Err(CredentialProfileError::registry_unavailable());
    }
    usize::try_from(metadata.len()).map_err(|_| CredentialProfileError::registry_unavailable())
}

fn write_store_atomic(
    directory: &File,
    store: &StoredRegistryFile,
    lock: Option<&RegistryFileLock>,
) -> Result<(), CredentialProfileError> {
    write_store_atomic_with_sync(directory, store, lock, File::sync_all)
}

fn write_store_atomic_with_sync(
    directory: &File,
    store: &StoredRegistryFile,
    lock: Option<&RegistryFileLock>,
    sync_directory: impl FnOnce(&File) -> std::io::Result<()>,
) -> Result<(), CredentialProfileError> {
    #[cfg(unix)]
    {
        store.validate(&store.scope)?;
        let bytes = serde_json::to_vec(store)
            .map_err(|_| CredentialProfileError::registry_unavailable())?;
        if bytes.len() > MAX_CREDENTIAL_PROFILE_STORE_BYTES {
            return Err(collection_too_large());
        }
        let (temp_name, mut temp) = create_staging_file(directory, &TEMP_SEQUENCE)?;
        let publish = (|| {
            temp.write_all(&bytes)
                .map_err(|_| CredentialProfileError::registry_unavailable())?;
            temp.sync_all()
                .map_err(|_| CredentialProfileError::registry_unavailable())?;
            if let Some(lock) = lock {
                lock.revalidate(directory)?;
            }
            match open_file_at(
                directory,
                STORE_FILE_NAME,
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0,
            ) {
                Ok(existing) => {
                    validate_private_regular_file(
                        directory,
                        &existing,
                        Some(MAX_CREDENTIAL_PROFILE_STORE_BYTES),
                    )?;
                },
                Err(error) if error.kind() == ErrorKind::NotFound => {},
                Err(_) => return Err(CredentialProfileError::registry_unavailable()),
            }
            rename_file_at(directory, &temp_name, STORE_FILE_NAME)
                .map_err(|_| CredentialProfileError::registry_unavailable())?;
            sync_directory(directory)
                .map_err(|_| CredentialProfileError::commit_state_unknown())?;
            Ok(())
        })();
        if publish.is_err() {
            let _ = unlink_file_at(directory, &temp_name);
        }
        publish
    }
    #[cfg(not(unix))]
    {
        let _ = (directory, store, lock, sync_directory);
        Err(CredentialProfileError::registry_unavailable())
    }
}

#[cfg(unix)]
fn create_staging_file(
    directory: &File,
    sequence: &AtomicU64,
) -> Result<(String, File), CredentialProfileError> {
    for _ in 0..STAGING_CREATE_ATTEMPTS {
        let value = sequence.fetch_add(1, Ordering::Relaxed);
        let name = format!(".credential-profiles.v1.tmp-{}-{value}", std::process::id());
        match open_file_at(
            directory,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        ) {
            Ok(file) => {
                validate_private_regular_file(directory, &file, None)?;
                return Ok((name, file));
            },
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(CredentialProfileError::registry_unavailable()),
        }
    }
    Err(CredentialProfileError::registry_unavailable())
}

#[cfg(unix)]
fn open_file_at(directory: &File, name: &str, flags: i32, mode: u32) -> std::io::Result<File> {
    let name = CString::new(name)
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidInput, "invalid relative file name"))?;
    // SAFETY: the directory descriptor and NUL-terminated name remain valid for the call.
    let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, mode) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `openat` returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn rename_file_at(directory: &File, from: &str, to: &str) -> std::io::Result<()> {
    let from = CString::new(from)
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidInput, "invalid relative file name"))?;
    let to = CString::new(to)
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidInput, "invalid relative file name"))?;
    // SAFETY: both names and the directory descriptor remain valid for the call.
    let result = unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            from.as_ptr(),
            directory.as_raw_fd(),
            to.as_ptr(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn unlink_file_at(directory: &File, name: &str) -> std::io::Result<()> {
    let name = CString::new(name)
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidInput, "invalid relative file name"))?;
    // SAFETY: the name and directory descriptor remain valid for the call.
    let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn effective_user_id() -> u32 {
    // SAFETY: `geteuid` has no preconditions and retains no pointers.
    unsafe { libc::geteuid() }
}

fn next_revision(
    current: CredentialProfileRevision,
) -> Result<CredentialProfileRevision, CredentialProfileError> {
    revision(
        current
            .get()
            .checked_add(1)
            .ok_or_else(CredentialProfileError::registry_unavailable)?,
    )
}

fn revision(value: u64) -> Result<CredentialProfileRevision, CredentialProfileError> {
    CredentialProfileRevision::new(value)
}

const fn collection_too_large() -> CredentialProfileError {
    CredentialProfileError::new(
        CredentialProfileErrorCode::CollectionTooLarge,
        "profiles",
        "the credential profile collection exceeds its size limit",
    )
}

const fn duplicate_profile() -> CredentialProfileError {
    CredentialProfileError::new(
        CredentialProfileErrorCode::DuplicateProfile,
        "profiles",
        "the credential profile collection contains a duplicate key",
    )
}

const fn scope_mismatch() -> CredentialProfileError {
    CredentialProfileError::new(
        CredentialProfileErrorCode::ScopeMismatch,
        "scope",
        "the credential profile request belongs to a different scope",
    )
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
        path::PathBuf,
        sync::{Arc, Barrier},
    };

    use serde_json::Value;

    use super::*;
    use crate::credential_profiles::CredentialProfileBinding;
    use crate::scoped_paths::{ScopedPathAuthority, ScopedPathComponent, ScopedPathErrorCode};

    static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        base: PathBuf,
        scope: CredentialScope,
        authority: ScopedPathAuthority,
        auth_root: ScopedPath,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let temp_root = fs::canonicalize(std::env::temp_dir()).expect("canonical temp root");
            let base = temp_root.join(format!(
                "tool-runtime-profile-store-{label}-{}-{sequence}",
                std::process::id()
            ));
            let scopes_root = base.join("scopes");
            let principal = scopes_root.join("owner");
            let workspace = principal.join("default");
            let auth = workspace.join("auth");
            for directory in [&base, &scopes_root, &principal, &workspace, &auth] {
                fs::create_dir_all(directory).expect("create fixture directory");
                fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                    .expect("set fixture permissions");
            }
            let scope = CredentialScope::new("owner", "default").expect("scope");
            let authority = ScopedPathAuthority::open(&scopes_root).expect("authority");
            let auth_root = authority.resolve_auth_root(&scope).expect("auth root");
            Self {
                base,
                scope,
                authority,
                auth_root,
            }
        }

        fn auth_path(&self) -> PathBuf {
            self.auth_root
                .revalidated_path()
                .expect("auth path")
                .to_path_buf()
        }

        fn add_profile(&self, alias: &str) -> PathBuf {
            let path = self.auth_path().join(format!("legacy-{alias}"));
            fs::create_dir(&path).expect("create profile");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("profile permissions");
            path
        }

        fn legacy(
            &self,
            profiles: &[(&str, Option<&str>, bool)],
        ) -> Result<LegacyCredentialProfileSet, CredentialProfileError> {
            let mut references = Vec::with_capacity(profiles.len());
            for (alias, expected_identity, is_default) in profiles {
                let key = key(&self.scope, alias);
                let metadata = CredentialProfileMetadata::new(
                    key.clone(),
                    expected_identity
                        .map(ExpectedCredentialIdentity::new)
                        .transpose()?,
                    *is_default,
                    CredentialProfileAvailability::Enabled,
                    revision(1)?,
                )?;
                let directory = ScopedPathComponent::new(format!("legacy-{alias}"))
                    .map_err(|_| CredentialProfileError::registry_unavailable())?;
                let profile_root = match self.authority.resolve_profile_root(&key, directory) {
                    Ok(path) => Some(path),
                    Err(error) if error.code == ScopedPathErrorCode::Missing => None,
                    Err(_) => return Err(CredentialProfileError::registry_unavailable()),
                };
                references.push(LegacyCredentialProfileReference::new(
                    metadata,
                    profile_root,
                )?);
            }
            LegacyCredentialProfileSet::new(self.scope.clone(), references)
        }

        fn registry(
            &self,
            legacy: LegacyCredentialProfileSet,
        ) -> Result<LocalCredentialProfileRegistry, CredentialProfileError> {
            LocalCredentialProfileRegistry::open(self.scope.clone(), self.auth_root.clone(), legacy)
        }

        fn empty_registry(&self) -> Result<LocalCredentialProfileRegistry, CredentialProfileError> {
            self.registry(LegacyCredentialProfileSet::empty(self.scope.clone()))
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    fn key(scope: &CredentialScope, alias: &str) -> CredentialProfileKey {
        CredentialProfileKey::new(
            scope.clone(),
            "legacy-provider",
            alias,
            CredentialProfileBinding::Provider,
        )
        .expect("key")
    }

    #[test]
    fn product_normalized_legacy_projection_is_read_only_and_never_claims_ready() {
        let fixture = Fixture::new("legacy");
        let work = fixture.add_profile("work");
        let credential_canary = "CLIENT_SECRET_CANARY_2C";
        fs::write(work.join("client_secret.json"), credential_canary).expect("credential fixture");
        let legacy = fixture
            .legacy(&[
                ("work", Some("owner@example.com"), true),
                ("personal", None, false),
            ])
            .expect("legacy projection");
        let registry = fixture.registry(legacy).expect("registry");
        let snapshot = registry.snapshot(&fixture.scope).expect("snapshot");
        assert_eq!(snapshot.profiles().len(), 2);
        let work = registry
            .status(&key(&fixture.scope, "work"))
            .expect("work status")
            .expect("work");
        let personal = registry
            .status(&key(&fixture.scope, "personal"))
            .expect("personal status")
            .expect("personal");
        assert_eq!(work.auth_state(), AuthState::Unknown);
        assert!(work.metadata().is_default());
        assert_eq!(personal.auth_state(), AuthState::Missing);

        let serialized = serde_json::to_string(&snapshot).expect("serialize snapshot");
        for forbidden in [
            credential_canary,
            "client_secret",
            "auth_root",
            fixture.base.to_string_lossy().as_ref(),
        ] {
            assert!(!serialized.contains(forbidden), "leaked {forbidden}");
        }
        assert!(!fixture.auth_path().join(STORE_FILE_NAME).exists());
        assert!(!fixture.auth_path().join(LOCK_FILE_NAME).exists());
    }

    #[test]
    fn legacy_projection_rejects_duplicate_cross_profile_and_unsafe_path_authority() {
        let fixture = Fixture::new("legacy-invalid");
        assert_eq!(
            fixture
                .legacy(&[("work", None, false), ("work", None, false)])
                .expect_err("duplicate profile")
                .code,
            CredentialProfileErrorCode::DuplicateProfile
        );

        fixture.add_profile("work");
        let work_key = key(&fixture.scope, "work");
        let work_path = fixture
            .authority
            .resolve_profile_root(&work_key, ScopedPathComponent::new("legacy-work").unwrap())
            .unwrap();
        let personal_metadata = CredentialProfileMetadata::new(
            key(&fixture.scope, "personal"),
            None,
            false,
            CredentialProfileAvailability::Enabled,
            revision(1).unwrap(),
        )
        .unwrap();
        let error = match LegacyCredentialProfileReference::new(personal_metadata, Some(work_path))
        {
            Err(error) => error,
            Ok(_) => panic!("cross-profile authority must fail"),
        };
        assert_eq!(error.code, CredentialProfileErrorCode::ScopeMismatch);

        let unsafe_profile = fixture.add_profile("unsafe");
        fs::set_permissions(&unsafe_profile, fs::Permissions::from_mode(0o755))
            .expect("unsafe mode");
        assert_eq!(
            fixture
                .legacy(&[("unsafe", None, false)])
                .expect_err("unsafe path")
                .code,
            CredentialProfileErrorCode::RegistryUnavailable
        );
    }

    #[test]
    fn local_registry_round_trips_metadata_with_atomic_private_storage() {
        let fixture = Fixture::new("roundtrip");
        let registry = fixture.empty_registry().expect("registry");
        let profile_key = key(&fixture.scope, "custom");
        let created = registry
            .create_reference(CreateCredentialProfileReference::new(
                profile_key.clone(),
                Some(ExpectedCredentialIdentity::new("first@example.com").unwrap()),
                false,
            ))
            .expect("create reference");
        assert_eq!(created.metadata().revision().get(), 1);
        assert_eq!(created.auth_state(), AuthState::Missing);

        let updated = registry
            .update_metadata(UpdateCredentialProfileMetadata::new(
                profile_key.clone(),
                ExpectedIdentityUpdate::Set {
                    value: ExpectedCredentialIdentity::new("second@example.com").unwrap(),
                },
                DefaultProfileUpdate::Preserve,
                revision(1).unwrap(),
            ))
            .expect("update metadata");
        assert_eq!(updated.metadata().revision().get(), 2);
        let disabled = registry
            .set_disabled(SetCredentialProfileDisabled::new(
                profile_key.clone(),
                true,
                revision(2).unwrap(),
            ))
            .expect("disable");
        assert_eq!(disabled.auth_state(), AuthState::Denied);
        assert_eq!(disabled.metadata().revision().get(), 3);

        let store_path = fixture.auth_path().join(STORE_FILE_NAME);
        let metadata = fs::metadata(&store_path).expect("store metadata");
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        let stored = fs::read_to_string(&store_path).expect("stored metadata");
        assert!(stored.contains("second@example.com"));
        for forbidden in ["auth_root", "secret_ref", "credential_token", "environment"] {
            assert!(!stored.contains(forbidden));
        }

        let reopened = fixture.empty_registry().expect("reopen");
        let current = reopened
            .status(&profile_key)
            .expect("status")
            .expect("profile");
        assert_eq!(current.metadata().revision().get(), 3);
        assert_eq!(current.auth_state(), AuthState::Denied);
    }

    #[test]
    fn legacy_metadata_can_be_overlaid_without_mutating_operator_config_or_credentials() {
        let fixture = Fixture::new("legacy-overlay");
        let profile = fixture.add_profile("work");
        let credential = profile.join("opaque-token");
        fs::write(&credential, "OPAQUE_CREDENTIAL_CANARY").expect("credential");
        let legacy = fixture
            .legacy(&[("work", Some("old@example.com"), false)])
            .expect("legacy");
        let registry = fixture.registry(legacy).expect("registry");
        let work_key = key(&fixture.scope, "work");
        let updated = registry
            .update_metadata(UpdateCredentialProfileMetadata::new(
                work_key.clone(),
                ExpectedIdentityUpdate::Set {
                    value: ExpectedCredentialIdentity::new("new@example.com").unwrap(),
                },
                DefaultProfileUpdate::Preserve,
                revision(1).unwrap(),
            ))
            .expect("overlay");
        assert_eq!(updated.auth_state(), AuthState::Unknown);
        assert_eq!(updated.metadata().revision().get(), 2);
        assert_eq!(
            fs::read_to_string(&credential).expect("credential unchanged"),
            "OPAQUE_CREDENTIAL_CANARY"
        );
        assert_eq!(
            registry
                .status(&work_key)
                .unwrap()
                .unwrap()
                .metadata()
                .expected_identity()
                .unwrap()
                .as_str(),
            "new@example.com"
        );
    }

    #[test]
    fn stale_revisions_duplicates_defaults_and_scope_crossing_fail_closed() {
        let fixture = Fixture::new("conflicts");
        fixture.add_profile("work");
        let legacy = fixture.legacy(&[("work", None, true)]).expect("legacy");
        let registry = fixture.registry(legacy).expect("registry");
        let work_key = key(&fixture.scope, "work");
        assert_eq!(
            registry
                .create_reference(CreateCredentialProfileReference::new(
                    work_key.clone(),
                    None,
                    false,
                ))
                .expect_err("duplicate")
                .code,
            CredentialProfileErrorCode::DuplicateProfile
        );
        assert_eq!(
            registry
                .update_metadata(UpdateCredentialProfileMetadata::new(
                    work_key.clone(),
                    ExpectedIdentityUpdate::Preserve,
                    DefaultProfileUpdate::Preserve,
                    revision(2).unwrap(),
                ))
                .expect_err("stale")
                .code,
            CredentialProfileErrorCode::Conflict
        );
        assert_eq!(
            registry
                .create_reference(CreateCredentialProfileReference::new(
                    key(&fixture.scope, "personal"),
                    None,
                    true,
                ))
                .expect_err("second default")
                .code,
            CredentialProfileErrorCode::MultipleDefaults
        );
        assert!(registry
            .status(&key(&fixture.scope, "personal"))
            .unwrap()
            .is_none());

        let other_scope = CredentialScope::new("other", "default").unwrap();
        assert_eq!(
            registry.snapshot(&other_scope).expect_err("scope").code,
            CredentialProfileErrorCode::ScopeMismatch
        );
        assert_eq!(
            registry
                .status(&key(&other_scope, "work"))
                .expect_err("cross-scope key")
                .code,
            CredentialProfileErrorCode::ScopeMismatch
        );
    }

    #[test]
    fn concurrent_registry_instances_serialize_and_reject_one_stale_writer() {
        let fixture = Fixture::new("concurrent");
        let seed = fixture.empty_registry().expect("seed");
        let profile_key = key(&fixture.scope, "shared");
        seed.create_reference(CreateCredentialProfileReference::new(
            profile_key.clone(),
            None,
            false,
        ))
        .expect("create");
        drop(seed);

        let left = Arc::new(fixture.empty_registry().expect("left"));
        let right = Arc::new(fixture.empty_registry().expect("right"));
        let barrier = Arc::new(Barrier::new(3));
        let mut joins = Vec::new();
        for (registry, identity) in [(left, "left@example.com"), (right, "right@example.com")] {
            let barrier = Arc::clone(&barrier);
            let profile_key = profile_key.clone();
            joins.push(thread::spawn(move || {
                barrier.wait();
                registry.update_metadata(UpdateCredentialProfileMetadata::new(
                    profile_key,
                    ExpectedIdentityUpdate::Set {
                        value: ExpectedCredentialIdentity::new(identity).unwrap(),
                    },
                    DefaultProfileUpdate::Preserve,
                    revision(1).unwrap(),
                ))
            }));
        }
        barrier.wait();
        let results: Vec<_> = joins
            .into_iter()
            .map(|join| join.join().expect("writer thread"))
            .collect();
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
        let final_status = fixture
            .empty_registry()
            .expect("final registry")
            .status(&profile_key)
            .unwrap()
            .unwrap();
        assert_eq!(final_status.metadata().revision().get(), 2);
    }

    #[test]
    fn incomplete_staging_is_ignored_but_corrupt_or_symlinked_store_is_rejected() {
        let fixture = Fixture::new("recovery");
        let auth = fixture.auth_path();
        let staging = auth.join(".credential-profiles.v1.tmp-abandoned");
        fs::write(&staging, b"partial").expect("staging");
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o600)).unwrap();
        fixture
            .empty_registry()
            .expect("abandoned staging is ignored");

        let store = auth.join(STORE_FILE_NAME);
        fs::write(&store, b"{not-json").expect("corrupt store");
        fs::set_permissions(&store, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            fixture.empty_registry().expect_err("corrupt store").code,
            CredentialProfileErrorCode::RegistryUnavailable
        );

        fs::remove_file(&store).unwrap();
        let outside = fixture.base.join("outside-store");
        fs::write(&outside, b"{}").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&outside, &store).unwrap();
        assert_eq!(
            fixture.empty_registry().expect_err("symlink store").code,
            CredentialProfileErrorCode::RegistryUnavailable
        );
    }

    #[test]
    fn staging_allocation_skips_a_crash_leftover_name_after_pid_reuse() {
        let fixture = Fixture::new("staging-collision");
        let directory = fixture
            .auth_root
            .open_revalidated_directory()
            .expect("pinned directory");
        let sequence = AtomicU64::new(41);
        let collision = format!(".credential-profiles.v1.tmp-{}-41", std::process::id());
        let existing = open_file_at(
            &directory,
            &collision,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
        .expect("crash leftover");
        drop(existing);

        let (allocated, file) = create_staging_file(&directory, &sequence).expect("retry");
        drop(file);
        assert!(allocated.ends_with("-42"));
        assert_ne!(allocated, collision);
        unlink_file_at(&directory, &allocated).expect("cleanup allocated staging");
    }

    #[test]
    fn bounded_reader_rejects_growth_and_shrink_without_unbounded_allocation() {
        let mut exact = std::io::Cursor::new(vec![7_u8; 64]);
        assert_eq!(read_bounded_exact(&mut exact, 64, 64).unwrap().len(), 64);

        let mut grew = std::io::Cursor::new(vec![7_u8; 65]);
        assert_eq!(
            read_bounded_exact(&mut grew, 1, 64).unwrap_err().code,
            CredentialProfileErrorCode::RegistryUnavailable
        );

        let mut shrank = std::io::Cursor::new(vec![7_u8; 63]);
        assert_eq!(
            read_bounded_exact(&mut shrank, 64, 64).unwrap_err().code,
            CredentialProfileErrorCode::RegistryUnavailable
        );
    }

    #[test]
    fn lock_path_replacement_invalidates_the_held_writer_authority() {
        let fixture = Fixture::new("lock-replacement");
        let directory = fixture
            .auth_root
            .open_revalidated_directory()
            .expect("pinned directory");
        let lock = RegistryFileLock::acquire(&directory).expect("writer lock");
        unlink_file_at(&directory, LOCK_FILE_NAME).expect("unlink held lock name");
        let replacement = open_file_at(
            &directory,
            LOCK_FILE_NAME,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
        .expect("replacement lock");
        drop(replacement);

        assert_eq!(
            lock.revalidate(&directory).unwrap_err().code,
            CredentialProfileErrorCode::RegistryUnavailable
        );
        assert!(!fixture.auth_path().join(STORE_FILE_NAME).exists());
    }

    #[test]
    fn descriptor_relative_publish_cannot_be_redirected_by_auth_root_replacement() {
        let fixture = Fixture::new("descriptor-pinning");
        let original = fixture.auth_path();
        let pinned = fixture
            .auth_root
            .open_revalidated_directory()
            .expect("pinned directory");
        let moved = original.with_file_name("auth-moved");
        fs::rename(&original, &moved).expect("move original auth root");
        fs::create_dir(&original).expect("replacement auth root");
        fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();

        write_store_atomic(
            &pinned,
            &StoredRegistryFile::empty(fixture.scope.clone()),
            None,
        )
        .expect("descriptor-relative publish");
        assert!(moved.join(STORE_FILE_NAME).is_file());
        assert!(!original.join(STORE_FILE_NAME).exists());
        assert_eq!(
            fixture
                .auth_root
                .revalidate()
                .expect_err("replacement")
                .code,
            crate::scoped_paths::ScopedPathErrorCode::Changed
        );
    }

    #[test]
    fn post_publish_sync_failure_reports_unknown_commit_and_requires_reconciliation() {
        let fixture = Fixture::new("commit-state-unknown");
        let directory = fixture
            .auth_root
            .open_revalidated_directory()
            .expect("pinned directory");
        let store = StoredRegistryFile::empty(fixture.scope.clone());

        let error = write_store_atomic_with_sync(&directory, &store, None, |_| {
            Err(std::io::Error::other("injected directory sync failure"))
        })
        .expect_err("durability confirmation must fail");
        assert_eq!(error.code, CredentialProfileErrorCode::CommitStateUnknown);

        // Rename happened before the injected failure, so a blind retry could duplicate
        // a higher-level operation. A fresh read is the required reconciliation step.
        let snapshot = fixture
            .empty_registry()
            .expect("reopen committed registry")
            .snapshot(&fixture.scope)
            .expect("reconcile committed state");
        assert!(snapshot.profiles().is_empty());
    }

    #[test]
    fn maximum_registry_and_legacy_projection_complete_on_a_small_stack() {
        let fixture = Fixture::new("small-stack");
        let scope = fixture.scope.clone();
        let auth_root = fixture.auth_root.clone();
        let count = thread::Builder::new()
            .name("credential-profile-store-small-stack".to_owned())
            .stack_size(128 * 1024)
            .spawn(move || {
                let references = (0..MAX_PROFILES_PER_SCOPE)
                    .map(|index| {
                        let metadata = CredentialProfileMetadata::new(
                            CredentialProfileKey::new(
                                scope.clone(),
                                "legacy-provider",
                                format!("p{index:03}"),
                                CredentialProfileBinding::Provider,
                            )
                            .unwrap(),
                            Some(
                                ExpectedCredentialIdentity::new(format!("p{index:03}@example.com"))
                                    .unwrap(),
                            ),
                            false,
                            CredentialProfileAvailability::Enabled,
                            revision(1).unwrap(),
                        )
                        .unwrap();
                        LegacyCredentialProfileReference::new(metadata, None).unwrap()
                    })
                    .collect();
                let legacy = LegacyCredentialProfileSet::new(scope.clone(), references)
                    .expect("maximum legacy projection");
                assert_eq!(legacy.len(), MAX_PROFILES_PER_SCOPE);
                drop(legacy);

                let profiles = (0..MAX_PROFILES_PER_SCOPE)
                    .map(|index| {
                        let metadata = CredentialProfileMetadata::new(
                            CredentialProfileKey::new(
                                scope.clone(),
                                "other-provider",
                                format!("p{index:03}"),
                                CredentialProfileBinding::Provider,
                            )
                            .unwrap(),
                            Some(
                                ExpectedCredentialIdentity::new(format!(
                                    "{}@example.com",
                                    "x".repeat(900)
                                ))
                                .unwrap(),
                            ),
                            false,
                            CredentialProfileAvailability::Enabled,
                            revision(1).unwrap(),
                        )
                        .unwrap();
                        StoredCredentialProfile::from_metadata(&metadata)
                    })
                    .collect();
                let store = StoredRegistryFile {
                    schema_version: CREDENTIAL_PROFILE_STORE_V1.to_owned(),
                    scope: scope.clone(),
                    generation: 1,
                    profiles,
                };
                let directory = auth_root
                    .open_revalidated_directory()
                    .expect("pinned auth directory");
                write_store_atomic(&directory, &store, None).expect("write maximum store");
                let registry = LocalCredentialProfileRegistry::open(
                    scope.clone(),
                    auth_root,
                    LegacyCredentialProfileSet::empty(scope.clone()),
                )
                .expect("open maximum store");
                registry
                    .snapshot(&scope)
                    .expect("maximum snapshot")
                    .profiles()
                    .len()
            })
            .expect("spawn small-stack test")
            .join()
            .expect("no panic or stack overflow");
        assert_eq!(count, MAX_PROFILES_PER_SCOPE);

        let stored: Value = serde_json::from_slice(
            &fs::read(fixture.auth_path().join(STORE_FILE_NAME)).expect("read store"),
        )
        .expect("parse store");
        assert_eq!(
            stored["profiles"].as_array().unwrap().len(),
            MAX_PROFILES_PER_SCOPE
        );
    }
}
