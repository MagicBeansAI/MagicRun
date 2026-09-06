//! Phase 6B executable and working-directory authority.
//!
//! This module consumes a pure Phase 6A intent, resolves only its fixed executable from
//! an explicit clean child environment, binds the requested cwd beneath a trusted root,
//! and retains exact filesystem identity. It still grants no authorization and exposes
//! no process specification; Phase 6F must join it to policy and credential authority.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::{OsStr, OsString},
    fmt, fs,
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::{
    ffi::OsStrExt,
    fs::{FileExt, MetadataExt, PermissionsExt},
};

use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use zeroize::Zeroizing;

use crate::{
    credential_injection::{ChildEnvironmentBaseline, ChildEnvironmentVariable},
    credential_materialization::ChildEnvironmentValues,
    governed_execution::{
        GovernedExecutionIntent, GovernedExecutionIntentParts,
        MAX_GOVERNED_WORKING_DIRECTORY_COMPONENTS,
    },
    manifest::{CliInteraction, WorkingDirectoryMode},
};

pub const GOVERNED_EXECUTION_AUTHORITY_V1: &str = "tool-runtime.governed-execution-authority.v1";
pub const MAX_GOVERNED_EXECUTABLE_SEARCH_ENTRIES: usize = 128;
pub const MAX_GOVERNED_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;

/// Total bytes admitted into one executable's adjacent-library bundle.
///
/// The live case is poppler: `pdftotext` needs `@rpath/libpoppler.159.dylib`,
/// and its keg's `lib/` yields roughly 8.4 MiB once each versioned alias is
/// materialized as its own copy. 64 MiB leaves that about sevenfold headroom
/// while staying a quarter of [`MAX_GOVERNED_EXECUTABLE_BYTES`], so a package
/// that points at an unexpectedly large tree is refused promptly rather than
/// copying for minutes.
pub const MAX_GOVERNED_EXECUTABLE_BUNDLE_BYTES: u64 = 64 * 1024 * 1024;

/// Entries admitted from one adjacent-library directory. Poppler's `lib/` has
/// fourteen; this bounds the loop well above any real layout.
pub const MAX_GOVERNED_EXECUTABLE_BUNDLE_ENTRIES: usize = 256;

/// Bytes searched for an `@rpath/` reference before concluding the executable
/// declares none. Mach-O keeps dylib install names in load commands near the
/// start of the image, so this covers real binaries many times over.
const MAX_GOVERNED_RPATH_SCAN_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedExecutionAuthorityErrorCode {
    BaselineMismatch,
    ExecutableNotFound,
    ExecutableUnsafe,
    ExecutableChanged,
    WorkingDirectoryModeMismatch,
    WorkingDirectoryUnsafe,
    WorkingDirectoryChanged,
    UnsupportedPlatform,
}

/// Stable path-, argv-, environment-, and value-free authority diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GovernedExecutionAuthorityError {
    pub code: GovernedExecutionAuthorityErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl GovernedExecutionAuthorityError {
    const fn new(
        code: GovernedExecutionAuthorityErrorCode,
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

impl fmt::Display for GovernedExecutionAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for GovernedExecutionAuthorityError {}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
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

#[derive(Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    owner: u32,
}

/// Trusted workspace or output-root authority. Opening a root accepts no relative path,
/// alias, or symlink. It is move-only and non-serializable.
pub struct GovernedWorkingDirectoryRoot {
    mode: WorkingDirectoryMode,
    path: PathBuf,
    identity: DirectoryIdentity,
}

impl GovernedWorkingDirectoryRoot {
    pub fn open(
        mode: WorkingDirectoryMode,
        path: impl AsRef<Path>,
    ) -> Result<Self, GovernedExecutionAuthorityError> {
        if mode == WorkingDirectoryMode::Denied {
            return Err(working_directory_mode_mismatch());
        }
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(working_directory_unsafe());
        }
        let metadata = fs::symlink_metadata(path).map_err(|_| working_directory_unsafe())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(working_directory_unsafe());
        }
        let canonical = fs::canonicalize(path).map_err(|_| working_directory_unsafe())?;
        let canonical_metadata =
            fs::symlink_metadata(&canonical).map_err(|_| working_directory_unsafe())?;
        if canonical_metadata.file_type().is_symlink()
            || !canonical_metadata.is_dir()
            || directory_identity(&canonical_metadata)? != directory_identity(&metadata)?
        {
            return Err(working_directory_unsafe());
        }
        let identity = directory_identity(&canonical_metadata)?;
        Ok(Self {
            mode,
            path: canonical,
            identity,
        })
    }

    pub fn mode(&self) -> WorkingDirectoryMode {
        self.mode
    }

    fn revalidate(&self) -> Result<(), GovernedExecutionAuthorityError> {
        let metadata = fs::symlink_metadata(&self.path).map_err(|_| working_directory_changed())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || directory_identity(&metadata)? != self.identity
            || fs::canonicalize(&self.path).map_err(|_| working_directory_changed())? != self.path
        {
            return Err(working_directory_changed());
        }
        Ok(())
    }
}

struct ResolvedWorkingDirectory {
    chain: Vec<(PathBuf, DirectoryIdentity)>,
}

impl ResolvedWorkingDirectory {
    fn bind(
        requested_mode: WorkingDirectoryMode,
        components: &[String],
        root: Option<GovernedWorkingDirectoryRoot>,
    ) -> Result<Option<Self>, GovernedExecutionAuthorityError> {
        if requested_mode == WorkingDirectoryMode::Denied {
            return if root.is_none() && components.is_empty() {
                Ok(None)
            } else {
                Err(working_directory_mode_mismatch())
            };
        }
        let root = root.ok_or_else(working_directory_mode_mismatch)?;
        if root.mode != requested_mode
            || components.len() > MAX_GOVERNED_WORKING_DIRECTORY_COMPONENTS
        {
            return Err(working_directory_mode_mismatch());
        }
        root.revalidate()?;
        let root_device = root.identity_device();
        let mut chain = vec![(root.path.clone(), root.identity)];
        let mut current = root.path;
        for component in components {
            current.push(component);
            let metadata =
                fs::symlink_metadata(&current).map_err(|_| working_directory_unsafe())?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(working_directory_unsafe());
            }
            let identity = directory_identity(&metadata)?;
            if identity_device(identity) != root_device {
                return Err(working_directory_unsafe());
            }
            let canonical = fs::canonicalize(&current).map_err(|_| working_directory_unsafe())?;
            if canonical != current || !canonical.starts_with(&chain[0].0) {
                return Err(working_directory_unsafe());
            }
            chain.push((current.clone(), identity));
        }
        Ok(Some(Self { chain }))
    }

    fn revalidate(&self) -> Result<(), GovernedExecutionAuthorityError> {
        let Some((root, root_identity)) = self.chain.first() else {
            return Err(working_directory_changed());
        };
        for (path, expected) in &self.chain {
            let metadata = fs::symlink_metadata(path).map_err(|_| working_directory_changed())?;
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || directory_identity(&metadata)? != *expected
            {
                return Err(working_directory_changed());
            }
            let canonical = fs::canonicalize(path).map_err(|_| working_directory_changed())?;
            if canonical != *path || !canonical.starts_with(root) {
                return Err(working_directory_changed());
            }
        }
        if self.chain.first().map(|entry| entry.1) != Some(*root_identity) {
            return Err(working_directory_changed());
        }
        Ok(())
    }

    fn path(&self) -> Result<&Path, GovernedExecutionAuthorityError> {
        self.revalidate()?;
        self.chain
            .last()
            .map(|entry| entry.0.as_path())
            .ok_or_else(working_directory_changed)
    }

    fn open_handle(
        &self,
    ) -> Result<GovernedWorkingDirectoryHandle, GovernedExecutionAuthorityError> {
        let path = self.path()?;
        let file = File::open(path).map_err(|_| working_directory_changed())?;
        let metadata = file.metadata().map_err(|_| working_directory_changed())?;
        let expected = self
            .chain
            .last()
            .map(|entry| entry.1)
            .ok_or_else(working_directory_changed)?;
        if directory_identity(&metadata)? != expected {
            return Err(working_directory_changed());
        }
        Ok(GovernedWorkingDirectoryHandle {
            file,
            path: path.to_path_buf(),
            identity: expected,
        })
    }
}

impl GovernedWorkingDirectoryRoot {
    #[cfg(unix)]
    fn identity_device(&self) -> u64 {
        self.identity.device
    }

    #[cfg(not(unix))]
    fn identity_device(&self) -> u64 {
        0
    }
}

#[cfg(unix)]
fn identity_device(identity: DirectoryIdentity) -> u64 {
    identity.device
}

#[cfg(not(unix))]
fn identity_device(_identity: DirectoryIdentity) -> u64 {
    0
}

struct ResolvedExecutable {
    path: PathBuf,
    identity: FileIdentity,
    sha256_digest: [u8; 32],
    blake3_digest: [u8; 32],
    file: File,
}

impl ResolvedExecutable {
    fn resolve(
        executable: &str,
        environment: &BTreeMap<String, Zeroizing<Vec<u8>>>,
    ) -> Result<Self, GovernedExecutionAuthorityError> {
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
            if index >= MAX_GOVERNED_EXECUTABLE_SEARCH_ENTRIES || !directory.is_absolute() {
                return Err(executable_unsafe());
            }
            let directory = fs::canonicalize(&directory).map_err(|_| executable_unsafe())?;
            let directory_metadata =
                fs::symlink_metadata(&directory).map_err(|_| executable_unsafe())?;
            if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
                return Err(executable_unsafe());
            }
            let candidate = directory.join(executable);
            let metadata = match fs::symlink_metadata(&candidate) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(executable_unsafe()),
            };
            if !metadata.is_file() && !metadata.file_type().is_symlink() {
                return Err(executable_unsafe());
            }
            // Installed CLIs commonly expose a PATH entry as a symlink (npm,
            // Homebrew, cargo aliases). Bind the resolved regular file, then
            // hash and privately snapshot those exact bytes. A later retarget
            // cannot affect this invocation because launch never uses the
            // public symlink again.
            let canonical = fs::canonicalize(&candidate).map_err(|_| executable_unsafe())?;
            let canonical_metadata =
                fs::symlink_metadata(&canonical).map_err(|_| executable_unsafe())?;
            if canonical_metadata.file_type().is_symlink() || !canonical_metadata.is_file() {
                return Err(executable_unsafe());
            }
            let file = File::open(&canonical).map_err(|_| executable_unsafe())?;
            let open_metadata = file.metadata().map_err(|_| executable_unsafe())?;
            let identity = executable_identity(&open_metadata)?;
            if identity != executable_identity(&canonical_metadata)? {
                return Err(executable_changed());
            }
            let content_digests = digest_open_file(&file, identity.length)?;
            let resolved = Self {
                path: canonical,
                identity,
                sha256_digest: content_digests.sha256,
                blake3_digest: content_digests.blake3,
                file,
            };
            resolved.revalidate()?;
            return Ok(resolved);
        }
        Err(executable_not_found())
    }

    fn revalidate(&self) -> Result<(), GovernedExecutionAuthorityError> {
        let open = self.file.metadata().map_err(|_| executable_changed())?;
        if executable_identity(&open)? != self.identity {
            return Err(executable_changed());
        }
        let metadata = fs::symlink_metadata(&self.path).map_err(|_| executable_changed())?;
        if metadata.file_type().is_symlink()
            || executable_identity(&metadata)? != self.identity
            || fs::canonicalize(&self.path).map_err(|_| executable_changed())? != self.path
        {
            return Err(executable_changed());
        }
        Ok(())
    }

    fn snapshot(&self) -> Result<GovernedExecutableSnapshot, GovernedExecutionAuthorityError> {
        self.revalidate()?;

        // SECURITY BOUNDARY, deliberately narrowed. See the module note on
        // `executes_in_place_on_sealed_system_volume` for the full argument and
        // the evidence behind it. Evaluated per launch, immediately after
        // revalidation, so a volume that stopped being sealed since the last
        // execution is caught.
        if executes_in_place_on_sealed_system_volume(&self.path) {
            return Ok(GovernedExecutableSnapshot {
                path: self.path.clone(),
                _directory: None,
                canonical_bundle_root: None,
            });
        }

        let directory = tempfile::Builder::new()
            .prefix("governed-executable-")
            .tempdir()
            .map_err(|_| executable_changed())?;
        // Keep the TempDir as the deletion owner, but use one canonical path
        // for every later copy, profile and mount operation. Platform temp
        // roots can contain stable aliases (notably `/var` -> `/private/var`
        // on macOS); retaining the non-canonical spelling would make strict
        // no-follow validation reject a directory we just created.
        let canonical_bundle_root =
            fs::canonicalize(directory.path()).map_err(|_| executable_changed())?;
        let root_metadata =
            fs::symlink_metadata(&canonical_bundle_root).map_err(|_| executable_changed())?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            return Err(executable_changed());
        }
        let file_name = self.path.file_name().ok_or_else(executable_changed)?;

        // A binary that resolves libraries through `@rpath` loses them the
        // moment it is copied away from its siblings, because `@loader_path`
        // follows the copy. When that is what this executable does, the
        // snapshot reproduces one level of its layout so the relative lookup
        // still lands inside the private directory. This *extends* the
        // snapshot: every byte the child loads is still a governed copy.
        let executable_directory = if self.needs_adjacent_library_bundle()? {
            let parent_name = self
                .path
                .parent()
                .and_then(Path::file_name)
                .ok_or_else(executable_changed)?;
            self.copy_adjacent_libraries(&canonical_bundle_root)?;
            let executable_directory = canonical_bundle_root.join(parent_name);
            // `create_dir_all` rather than `create_dir` because a binary that
            // already sits in its own `lib` directory resolves `../lib` back to
            // that same directory, which the library copy just created.
            fs::create_dir_all(&executable_directory).map_err(|_| executable_changed())?;
            executable_directory
        } else {
            canonical_bundle_root.clone()
        };

        let path = executable_directory.join(file_name);
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| executable_changed())?;
        let copied_digest =
            copy_and_digest_open_file(&self.file, self.identity.length, &mut output)?;
        if copied_digest != self.sha256_digest {
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
        Ok(GovernedExecutableSnapshot {
            path,
            _directory: Some(directory),
            canonical_bundle_root: Some(canonical_bundle_root),
        })
    }

    /// Whether this executable names a library through `@rpath`, and therefore
    /// cannot be relocated without its sibling directory.
    ///
    /// Mach-O stores dylib install names as plain strings inside load commands,
    /// so the reference is detectable without linking a Mach-O parser into this
    /// crate. The test is deliberately conservative in the safe direction: a
    /// binary that merely happens to contain the bytes is bundled needlessly,
    /// which costs a copy, while a binary that truly needs the bundle is never
    /// missed. Absence of the sibling directory answers no on its own.
    #[cfg(unix)]
    fn needs_adjacent_library_bundle(&self) -> Result<bool, GovernedExecutionAuthorityError> {
        let Some(library_directory) = self.adjacent_library_directory() else {
            return Ok(false);
        };
        if !library_directory.is_dir() {
            return Ok(false);
        }
        let scanned = self.identity.length.min(MAX_GOVERNED_RPATH_SCAN_BYTES);
        let scanned = usize::try_from(scanned).map_err(|_| executable_changed())?;
        let mut buffer = vec![0_u8; scanned];
        let mut offset = 0_usize;
        while offset < scanned {
            let read = self
                .file
                .read_at(&mut buffer[offset..], offset as u64)
                .map_err(|_| executable_changed())?;
            if read == 0 {
                break;
            }
            offset += read;
        }
        Ok(buffer[..offset]
            .windows(RPATH_MARKER.len())
            .any(|window| window == RPATH_MARKER))
    }

    /// The `lib` directory beside the executable's own directory -- the target
    /// of the near-universal `@loader_path/../lib` rpath that build systems
    /// emit. Only this exact shape is reproduced; nothing else is inferred.
    fn adjacent_library_directory(&self) -> Option<PathBuf> {
        let library_directory = self.path.parent()?.parent()?.join("lib");
        let metadata = fs::symlink_metadata(&library_directory).ok()?;
        (!metadata.file_type().is_symlink() && metadata.is_dir()).then_some(library_directory)
    }

    /// Copy the adjacent `lib` directory's loadable images into the snapshot.
    ///
    /// Only depth-one entries are considered, and only those whose bytes are a
    /// Mach-O image: that admits the `.dylib` files dyld will open and excludes
    /// static archives, `pkgconfig` text, and typelib subdirectories, none of
    /// which are loadable and which together are the bulk of a real keg.
    ///
    /// A symlink is materialized as a regular copy of its target's bytes under
    /// the link's own name, and only when that target canonicalizes to a file
    /// inside the same source directory. So a versioned alias such as
    /// `libpoppler.159.dylib -> libpoppler.159.0.0.dylib` still resolves, no
    /// symlink is ever created inside the bundle, and a link pointing outside
    /// the package's own tree copies nothing.
    #[cfg(unix)]
    fn copy_adjacent_libraries(
        &self,
        bundle_root: &Path,
    ) -> Result<(), GovernedExecutionAuthorityError> {
        let Some(source) = self.adjacent_library_directory() else {
            return Ok(());
        };
        let canonical_source = fs::canonicalize(&source).map_err(|_| executable_unsafe())?;
        let destination = bundle_root.join("lib");
        fs::create_dir(&destination).map_err(|_| executable_changed())?;

        let entries = fs::read_dir(&canonical_source).map_err(|_| executable_unsafe())?;
        let mut copied_entries = 0_usize;
        let mut copied_bytes = 0_u64;
        for entry in entries {
            let entry = entry.map_err(|_| executable_unsafe())?;
            let entry_path = entry.path();
            let Some(entry_name) = entry_path.file_name() else {
                continue;
            };
            // Resolving through the link is what makes a versioned alias work;
            // requiring the result to stay inside the source directory is what
            // stops the bundle reaching out of the package tree.
            let Ok(resolved) = fs::canonicalize(&entry_path) else {
                continue;
            };
            // The executable is copied separately, with its digest verified
            // against the bound provenance. Skipping it here keeps that the
            // only path by which it enters the snapshot, and avoids a collision
            // when a binary sits inside its own `lib` directory.
            if resolved == self.path || !resolved.starts_with(&canonical_source) {
                continue;
            }
            let Ok(metadata) = fs::symlink_metadata(&resolved) else {
                continue;
            };
            if !metadata.is_file() || metadata.len() == 0 {
                continue;
            }
            let Ok(mut input) = File::open(&resolved) else {
                continue;
            };
            let mut magic = [0_u8; 4];
            let Ok(read) = input.read_at(&mut magic, 0) else {
                continue;
            };
            if !is_mach_object(&magic[..read]) {
                continue;
            }

            copied_entries = copied_entries
                .checked_add(1)
                .ok_or_else(executable_changed)?;
            copied_bytes = copied_bytes
                .checked_add(metadata.len())
                .ok_or_else(executable_changed)?;
            if copied_entries > MAX_GOVERNED_EXECUTABLE_BUNDLE_ENTRIES
                || copied_bytes > MAX_GOVERNED_EXECUTABLE_BUNDLE_BYTES
            {
                return Err(executable_unsafe());
            }

            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination.join(entry_name))
                .map_err(|_| executable_changed())?;
            std::io::copy(&mut input, &mut output).map_err(|_| executable_changed())?;
            output.flush().map_err(|_| executable_changed())?;
        }
        Ok(())
    }
}

impl ResolvedExecutable {
    /// Adjacent-library bundling is a Mach-O/dyld concern reached through
    /// positional reads, so platforms without that surface never bundle. They
    /// already cannot bind an executable at all; this keeps them compiling.
    #[cfg(not(unix))]
    fn needs_adjacent_library_bundle(&self) -> Result<bool, GovernedExecutionAuthorityError> {
        Ok(false)
    }

    #[cfg(not(unix))]
    fn copy_adjacent_libraries(
        &self,
        _bundle_root: &Path,
    ) -> Result<(), GovernedExecutionAuthorityError> {
        Err(unsupported_platform())
    }
}

const RPATH_MARKER: &[u8] = b"@rpath/";

/// Mach-O thin and universal magics, in both byte orders.
fn is_mach_object(bytes: &[u8]) -> bool {
    matches!(
        bytes,
        [0xfe, 0xed, 0xfa, 0xce]
            | [0xce, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xcf, 0xfa, 0xed, 0xfe]
            | [0xca, 0xfe, 0xba, 0xbe]
            | [0xbe, 0xba, 0xfe, 0xca]
    )
}

/// Whether the resolved executable may be launched from its own path instead of
/// from a private copy.
///
/// **This narrows a security boundary, for exactly one filesystem shape.**
///
/// The snapshot exists to close a TOCTOU window: without it, the file proven
/// safe during binding is not provably the file the kernel later execs. Copying
/// the bytes into a private directory removes that window because nothing else
/// can reach the copy.
///
/// On macOS the copy also *breaks* the thing it protects. Every `/usr/bin` and
/// `/bin` tool ships as a universal image whose arm64e slice uses the pointer
/// authentication ABI, and that ABI is admissible only for platform binaries.
/// The kernel decides platform-binary status from where the file *lives*, not
/// from what it carries -- a copy keeps its Apple signature completely intact
/// (`codesign -v` passes on the copy, reporting the same CDHash and the same
/// platform identifier) and is still SIGKILLed at exec, yielding no exit code
/// and two empty streams. That counter-intuitive detail is the part worth
/// remembering: **residence, not signature, is the test.** The practical effect
/// was that no `/usr/bin` tool could run under this runtime at all -- `awk`,
/// `sed`, `tar`, `curl`, `sqlite3` and the rest die identically.
///
/// The trade is sound only because the alternative is stronger, not weaker. The
/// sealed system volume is mounted read-only and its immutability is enforced by
/// the kernel and verified against a sealed APFS snapshot; the file cannot be
/// swapped between binding and exec by anything that a private temp directory
/// would have stopped. So for this one volume the snapshot buys nothing and
/// costs everything.
///
/// The predicate is therefore on the *mount*, never on the path: a `/usr/bin`
/// prefix test would be defeated by a bind mount or a symlink, whereas the
/// volume flags are the actual property being relied on. It requires both
/// `MNT_RDONLY` and `MNT_ROOTFS`, which together hold only for the sealed root
/// volume -- measured true for `/usr/bin/awk`, `/bin/sh` and `/usr/bin/tar` on
/// `/dev/disk3s1s1`, and false for Homebrew and `/tmp` on `/dev/disk3s5`. It is
/// re-evaluated at every launch rather than cached, because a volume can in
/// principle be remounted. Any `statfs` failure, or either flag missing, falls
/// through to the ordinary snapshot: there is no path here that executes in
/// place on a doubt.
///
/// Non-macOS platforms are unaffected and always snapshot.
#[cfg(all(unix, target_os = "macos"))]
fn executes_in_place_on_sealed_system_volume(path: &Path) -> bool {
    use std::ffi::CString;

    const SEALED_SYSTEM_VOLUME_FLAGS: u32 = (libc::MNT_RDONLY as u32) | (libc::MNT_ROOTFS as u32);

    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `path` is a valid NUL-terminated C string that outlives the call,
    // and `mount` is a correctly sized, writable `statfs` this thread owns.
    let mut mount = std::mem::MaybeUninit::<libc::statfs>::uninit();
    let status = unsafe { libc::statfs(path.as_ptr(), mount.as_mut_ptr()) };
    if status != 0 {
        return false;
    }
    // SAFETY: `statfs` returned success, so it initialized the structure.
    let mount = unsafe { mount.assume_init() };
    mount.f_flags & SEALED_SYSTEM_VOLUME_FLAGS == SEALED_SYSTEM_VOLUME_FLAGS
}

#[cfg(not(all(unix, target_os = "macos")))]
fn executes_in_place_on_sealed_system_volume(_path: &Path) -> bool {
    false
}

/// Move-only exact executable snapshot. Only the later sealed process specification can
/// request it; it has no debug or serialization surface.
///
/// The snapshot is normally relocated into a private directory. Two shapes are
/// handled beyond that plain copy:
///
/// - A binary that resolves libraries through `@rpath` is copied together with
///   the loadable images from its adjacent `lib` directory, preserving one
///   level of layout so `@loader_path/../lib` still lands inside the private
///   directory. Everything the child loads remains a governed copy.
/// - A binary on the sealed, read-only macOS system volume is launched from its
///   own path, because a copy of a platform binary cannot be executed at all.
///   `_directory` is `None` in exactly that case. See
///   `executes_in_place_on_sealed_system_volume` for why this is safe there and
///   nowhere else.
///
/// Self-relative wrappers whose companion files are not a sibling `lib`
/// directory still need a separately declared bundle authority and must not be
/// migrated through this capability.
pub struct GovernedExecutableSnapshot {
    path: PathBuf,
    _directory: Option<TempDir>,
    canonical_bundle_root: Option<PathBuf>,
}

/// Move-only opened directory used for descriptor-bound `fchdir` by the batch runner.
/// The PTY runner can request a freshly revalidated canonical path because
/// `portable-pty` does not expose a pre-exec `fchdir` hook and macOS cannot use a
/// directory descriptor through `/dev/fd` as `Command::current_dir`.
pub struct GovernedWorkingDirectoryHandle {
    file: File,
    path: PathBuf,
    identity: DirectoryIdentity,
}

impl GovernedWorkingDirectoryHandle {
    #[cfg(unix)]
    pub(crate) fn raw_fd(&self) -> std::os::unix::io::RawFd {
        use std::os::unix::io::AsRawFd;
        self.file.as_raw_fd()
    }

    /// Returns the canonical path only after proving that both the opened descriptor
    /// and the current path still name the directory authorized earlier. This closes
    /// all detectable drift before PTY spawn; eliminating the final path-to-spawn race
    /// requires a PTY backend with a pre-exec `fchdir` capability.
    #[cfg(unix)]
    pub(crate) fn revalidated_child_cwd_path(
        &self,
    ) -> Result<PathBuf, GovernedExecutionAuthorityError> {
        let opened = self
            .file
            .metadata()
            .map_err(|_| working_directory_changed())?;
        if directory_identity(&opened)? != self.identity {
            return Err(working_directory_changed());
        }
        let current = fs::symlink_metadata(&self.path).map_err(|_| working_directory_changed())?;
        if current.file_type().is_symlink()
            || !current.is_dir()
            || directory_identity(&current)? != self.identity
            || fs::canonicalize(&self.path).map_err(|_| working_directory_changed())? != self.path
        {
            return Err(working_directory_changed());
        }
        Ok(self.path.clone())
    }
}

impl GovernedExecutableSnapshot {
    pub(crate) fn as_path(&self) -> &Path {
        &self.path
    }

    /// Private root retained by this snapshot, when launch uses governed
    /// copied bytes. `None` is reserved for an executable proven to reside on
    /// the sealed read-only macOS system volume. Containment owners use this
    /// distinction to avoid widening a literal system executable into read
    /// access over its whole host directory.
    pub(crate) fn private_bundle_root(&self) -> Option<&Path> {
        self.canonical_bundle_root.as_deref()
    }
}

/// Safe, value-free provenance projection. The digest identifies exact executable bytes
/// without exposing an installation path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GovernedExecutableProvenance {
    pub schema_version: &'static str,
    pub length: u64,
    pub sha256: [u8; 32],
}

/// Install-review content constraint for one governed executable. Constructing
/// this value grants nothing: it is consumed only as an additional equality
/// check against bytes read from the runtime's already-opened executable.
pub struct GovernedExpectedExecutableDigest {
    blake3: [u8; 32],
}

impl GovernedExpectedExecutableDigest {
    pub fn from_blake3(blake3: [u8; 32]) -> Self {
        Self { blake3 }
    }
}

/// Move-only union of the exact 6A intent, executable, cwd, and clean baseline. It is
/// still non-authorizing and cannot expose a process specification.
pub struct GovernedExecutionAuthority {
    schema_version: &'static str,
    intent: GovernedExecutionIntentParts,
    executable: ResolvedExecutable,
    working_directory: Option<ResolvedWorkingDirectory>,
    environment: BTreeMap<String, Zeroizing<Vec<u8>>>,
}

impl GovernedExecutionAuthority {
    pub fn bind(
        intent: GovernedExecutionIntent,
        baseline: &ChildEnvironmentBaseline,
        baseline_values: ChildEnvironmentValues,
        working_directory_root: Option<GovernedWorkingDirectoryRoot>,
    ) -> Result<Self, GovernedExecutionAuthorityError> {
        let intent = intent.into_parts();
        let (provided_baseline, environment) = baseline_values.into_parts();
        Self::bind_with_expected_executable_digest(
            intent,
            baseline,
            provided_baseline,
            environment,
            working_directory_root,
            None,
        )
    }

    /// Bind one exact executable and additionally require that the bytes read
    /// from its already-opened descriptor match install-review evidence. The
    /// digest can only narrow the ordinary governed resolution; it cannot
    /// select an executable, path or environment value.
    pub fn bind_expected_executable(
        intent: GovernedExecutionIntent,
        baseline: &ChildEnvironmentBaseline,
        baseline_values: ChildEnvironmentValues,
        working_directory_root: Option<GovernedWorkingDirectoryRoot>,
        expected: GovernedExpectedExecutableDigest,
    ) -> Result<Self, GovernedExecutionAuthorityError> {
        let intent = intent.into_parts();
        let (provided_baseline, environment) = baseline_values.into_parts();
        Self::bind_with_expected_executable_digest(
            intent,
            baseline,
            provided_baseline,
            environment,
            working_directory_root,
            Some(expected),
        )
    }

    fn bind_with_expected_executable_digest(
        intent: GovernedExecutionIntentParts,
        baseline: &ChildEnvironmentBaseline,
        provided_baseline: BTreeSet<ChildEnvironmentVariable>,
        environment: BTreeMap<String, Zeroizing<Vec<u8>>>,
        working_directory_root: Option<GovernedWorkingDirectoryRoot>,
        expected: Option<GovernedExpectedExecutableDigest>,
    ) -> Result<Self, GovernedExecutionAuthorityError> {
        if provided_baseline != *baseline.variables() {
            return Err(baseline_mismatch());
        }
        let executable = ResolvedExecutable::resolve(&intent.executable, &environment)?;
        if expected.is_some_and(|expected| expected.blake3 != executable.blake3_digest) {
            return Err(executable_changed());
        }
        let working_directory = ResolvedWorkingDirectory::bind(
            intent.working_directory_mode,
            &intent.working_directory,
            working_directory_root,
        )?;
        let authority = Self {
            schema_version: GOVERNED_EXECUTION_AUTHORITY_V1,
            intent,
            executable,
            working_directory,
            environment,
        };
        authority.revalidate()?;
        Ok(authority)
    }

    pub fn schema_version(&self) -> &'static str {
        self.schema_version
    }

    pub fn interaction(&self) -> CliInteraction {
        self.intent.interaction
    }

    pub fn argument_count(&self) -> usize {
        self.intent.arguments.len()
    }

    pub fn command_prefix_len(&self) -> usize {
        self.intent.command_prefix.len()
    }

    pub fn has_stdin(&self) -> bool {
        self.intent.stdin.is_some()
    }

    pub fn timeout_secs(&self) -> u32 {
        self.intent.timeout_secs
    }

    pub fn working_directory_mode(&self) -> WorkingDirectoryMode {
        self.intent.working_directory_mode
    }

    pub fn provenance(&self) -> GovernedExecutableProvenance {
        GovernedExecutableProvenance {
            schema_version: GOVERNED_EXECUTION_AUTHORITY_V1,
            length: self.executable.identity.length,
            sha256: self.executable.sha256_digest,
        }
    }

    pub fn revalidate(&self) -> Result<(), GovernedExecutionAuthorityError> {
        self.executable.revalidate()?;
        if let Some(working_directory) = &self.working_directory {
            working_directory.revalidate()?;
        }
        Ok(())
    }

    pub(crate) fn into_parts(self) -> GovernedExecutionAuthorityParts {
        GovernedExecutionAuthorityParts {
            intent: self.intent,
            executable: self.executable,
            working_directory: self.working_directory,
            environment: self.environment,
        }
    }
}

pub(crate) struct GovernedExecutionAuthorityParts {
    pub(crate) intent: GovernedExecutionIntentParts,
    executable: ResolvedExecutable,
    working_directory: Option<ResolvedWorkingDirectory>,
    pub(crate) environment: BTreeMap<String, Zeroizing<Vec<u8>>>,
}

impl GovernedExecutionAuthorityParts {
    pub(crate) fn revalidate(&self) -> Result<(), GovernedExecutionAuthorityError> {
        self.executable.revalidate()?;
        if let Some(working_directory) = &self.working_directory {
            working_directory.revalidate()?;
        }
        Ok(())
    }

    pub(crate) fn executable_snapshot(
        &self,
    ) -> Result<GovernedExecutableSnapshot, GovernedExecutionAuthorityError> {
        self.executable.snapshot()
    }

    pub(crate) fn working_directory_handle(
        &self,
    ) -> Result<Option<GovernedWorkingDirectoryHandle>, GovernedExecutionAuthorityError> {
        self.working_directory
            .as_ref()
            .map(ResolvedWorkingDirectory::open_handle)
            .transpose()
    }

    pub(crate) fn baseline_matches_environment(
        &self,
        environment: &[(String, Zeroizing<Vec<u8>>)],
    ) -> bool {
        self.environment.iter().all(|(variable, expected)| {
            environment
                .binary_search_by(|(name, _)| name.as_str().cmp(variable.as_str()))
                .ok()
                .and_then(|index| environment.get(index))
                .is_some_and(|(_, actual)| actual.as_slice() == expected.as_slice())
        })
    }
}

#[cfg(unix)]
fn executable_identity(
    metadata: &fs::Metadata,
) -> Result<FileIdentity, GovernedExecutionAuthorityError> {
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_GOVERNED_EXECUTABLE_BYTES
        || metadata.mode() & 0o111 == 0
    {
        return Err(executable_unsafe());
    }
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        change_time_secs: metadata.ctime(),
        change_time_nanos: metadata.ctime_nsec(),
        length: metadata.len(),
    })
}

#[cfg(not(unix))]
fn executable_identity(
    _metadata: &fs::Metadata,
) -> Result<FileIdentity, GovernedExecutionAuthorityError> {
    Err(unsupported_platform())
}

#[cfg(unix)]
fn directory_identity(
    metadata: &fs::Metadata,
) -> Result<DirectoryIdentity, GovernedExecutionAuthorityError> {
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        return Err(working_directory_unsafe());
    }
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
    })
}

#[cfg(not(unix))]
fn directory_identity(
    _metadata: &fs::Metadata,
) -> Result<DirectoryIdentity, GovernedExecutionAuthorityError> {
    Err(unsupported_platform())
}

struct OpenFileDigests {
    sha256: [u8; 32],
    blake3: [u8; 32],
}

#[cfg(unix)]
fn digest_open_file(
    file: &File,
    length: u64,
) -> Result<OpenFileDigests, GovernedExecutionAuthorityError> {
    let mut sha256 = Sha256::new();
    let mut blake3 = blake3::Hasher::new();
    let mut offset = 0u64;
    let mut buffer = vec![0u8; 64 * 1024];
    while offset < length {
        let remaining = usize::try_from((length - offset).min(buffer.len() as u64))
            .map_err(|_| executable_changed())?;
        let read = file
            .read_at(&mut buffer[..remaining], offset)
            .map_err(|_| executable_changed())?;
        if read == 0 {
            return Err(executable_changed());
        }
        sha256.update(&buffer[..read]);
        blake3.update(&buffer[..read]);
        offset = offset
            .checked_add(read as u64)
            .ok_or_else(executable_changed)?;
    }
    let extra = file
        .read_at(&mut buffer[..1], length)
        .map_err(|_| executable_changed())?;
    if extra != 0 {
        return Err(executable_changed());
    }
    Ok(OpenFileDigests {
        sha256: sha256.finalize().into(),
        blake3: blake3.finalize().into(),
    })
}

#[cfg(not(unix))]
fn digest_open_file(
    _file: &File,
    _length: u64,
) -> Result<OpenFileDigests, GovernedExecutionAuthorityError> {
    Err(unsupported_platform())
}

#[cfg(unix)]
fn copy_and_digest_open_file(
    file: &File,
    length: u64,
    output: &mut File,
) -> Result<[u8; 32], GovernedExecutionAuthorityError> {
    let mut digest = Sha256::new();
    let mut offset = 0u64;
    let mut buffer = vec![0u8; 64 * 1024];
    while offset < length {
        let remaining = usize::try_from((length - offset).min(buffer.len() as u64))
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
    Ok(digest.finalize().into())
}

#[cfg(not(unix))]
fn copy_and_digest_open_file(
    _file: &File,
    _length: u64,
    _output: &mut File,
) -> Result<[u8; 32], GovernedExecutionAuthorityError> {
    Err(unsupported_platform())
}

#[cfg(unix)]
fn bytes_to_os_string(value: &[u8]) -> Result<OsString, GovernedExecutionAuthorityError> {
    if value.contains(&0) {
        return Err(baseline_mismatch());
    }
    Ok(OsStr::from_bytes(value).to_os_string())
}

#[cfg(not(unix))]
fn bytes_to_os_string(_value: &[u8]) -> Result<OsString, GovernedExecutionAuthorityError> {
    Err(unsupported_platform())
}

const fn baseline_mismatch() -> GovernedExecutionAuthorityError {
    GovernedExecutionAuthorityError::new(
        GovernedExecutionAuthorityErrorCode::BaselineMismatch,
        "environment",
        "the explicit child environment does not match its baseline policy",
    )
}

const fn executable_not_found() -> GovernedExecutionAuthorityError {
    GovernedExecutionAuthorityError::new(
        GovernedExecutionAuthorityErrorCode::ExecutableNotFound,
        "executable",
        "the fixed executable is absent from the governed search path",
    )
}

const fn executable_unsafe() -> GovernedExecutionAuthorityError {
    GovernedExecutionAuthorityError::new(
        GovernedExecutionAuthorityErrorCode::ExecutableUnsafe,
        "executable",
        "the fixed executable does not satisfy provenance requirements",
    )
}

const fn executable_changed() -> GovernedExecutionAuthorityError {
    GovernedExecutionAuthorityError::new(
        GovernedExecutionAuthorityErrorCode::ExecutableChanged,
        "executable",
        "the fixed executable changed after provenance binding",
    )
}

const fn working_directory_mode_mismatch() -> GovernedExecutionAuthorityError {
    GovernedExecutionAuthorityError::new(
        GovernedExecutionAuthorityErrorCode::WorkingDirectoryModeMismatch,
        "working_dir",
        "the working-directory authority does not match the validated mode",
    )
}

const fn working_directory_unsafe() -> GovernedExecutionAuthorityError {
    GovernedExecutionAuthorityError::new(
        GovernedExecutionAuthorityErrorCode::WorkingDirectoryUnsafe,
        "working_dir",
        "the working directory is outside exact governed directory authority",
    )
}

const fn working_directory_changed() -> GovernedExecutionAuthorityError {
    GovernedExecutionAuthorityError::new(
        GovernedExecutionAuthorityErrorCode::WorkingDirectoryChanged,
        "working_dir",
        "the working-directory authority changed after binding",
    )
}

#[cfg(not(unix))]
const fn unsupported_platform() -> GovernedExecutionAuthorityError {
    GovernedExecutionAuthorityError::new(
        GovernedExecutionAuthorityErrorCode::UnsupportedPlatform,
        "platform",
        "the platform cannot provide exact executable and directory authority",
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fmt, fs};

    #[cfg(unix)]
    use std::os::unix::fs::{symlink, PermissionsExt};

    use serde::Serialize;
    use static_assertions::assert_not_impl_any;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        governed_execution::{
            GovernedExecutionContract, GovernedExecutionPolicy, GovernedExecutionRequest,
        },
        manifest::{
            AuthContract, CliInteraction, PolicyFloor, RuntimeLimits, RuntimeProtocol,
            RuntimeRequirements, SkillRuntimeContract, SkillRuntimeContractVersion, StdinContract,
            WorkingDirectoryContract,
        },
        manifest_validation::validate_skill_runtime_contract,
    };

    struct Fixture {
        _root: TempDir,
        bin: PathBuf,
        executable: PathBuf,
        workspace: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let bin = root.path().join("bin");
            let workspace = root.path().join("workspace");
            fs::create_dir(&bin).unwrap();
            fs::create_dir(&workspace).unwrap();
            let executable = bin.join("fixture-cli");
            write_executable(&executable, b"#!/bin/sh\nexit 0\n");
            Self {
                _root: root,
                bin,
                executable,
                workspace,
            }
        }

        fn environment(&self) -> (ChildEnvironmentBaseline, ChildEnvironmentValues) {
            let baseline = ChildEnvironmentBaseline::portable_cli();
            let mut values = ChildEnvironmentValues::new(&baseline);
            values
                .provide(
                    ChildEnvironmentVariable::Path,
                    self.bin.as_os_str().as_bytes().to_vec(),
                )
                .unwrap();
            (baseline, values)
        }
    }

    #[cfg(unix)]
    fn write_executable(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn contract(cwd: WorkingDirectoryMode) -> SkillRuntimeContract {
        contract_for("fixture-cli", cwd)
    }

    fn contract_for(executable: &str, cwd: WorkingDirectoryMode) -> SkillRuntimeContract {
        SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires: RuntimeRequirements {
                bins: BTreeSet::from([executable.to_owned()]),
                entrypoint: Default::default(),
                environment: Default::default(),
            },
            runtime: RuntimeProtocol::Cli {
                command_prefix: vec!["fixed".to_owned()],
                interaction: CliInteraction::Batch,
                stdin: StdinContract::default(),
                working_directory: WorkingDirectoryContract { mode: cwd },
                limits: RuntimeLimits::default(),
            },
            auth: AuthContract::default(),
            policy_floor: PolicyFloor::default(),
        }
    }

    fn intent(contract: &SkillRuntimeContract, cwd: Option<String>) -> GovernedExecutionIntent {
        GovernedExecutionContract::compile(
            validate_skill_runtime_contract(contract).unwrap(),
            GovernedExecutionPolicy::new(30, 60, 1024, 2048, 2048).unwrap(),
        )
        .unwrap()
        .admit(GovernedExecutionRequest::new(
            vec!["a b".to_owned(), "$(false)".to_owned()],
            None,
            cwd,
            None,
        ))
        .unwrap()
    }

    #[test]
    fn exact_executable_and_cwd_authority_bind_without_launching() {
        let fixture = Fixture::new();
        let child = fixture.workspace.join("子目录");
        fs::create_dir(&child).unwrap();
        let authored = contract(WorkingDirectoryMode::Workspace);
        let intent = intent(&authored, Some("子目录".to_owned()));
        let (baseline, values) = fixture.environment();
        let root =
            GovernedWorkingDirectoryRoot::open(WorkingDirectoryMode::Workspace, &fixture.workspace)
                .unwrap();
        let authority =
            GovernedExecutionAuthority::bind(intent, &baseline, values, Some(root)).unwrap();
        assert_eq!(authority.argument_count(), 2);
        assert_eq!(authority.command_prefix_len(), 1);
        assert_eq!(
            authority.working_directory_mode(),
            WorkingDirectoryMode::Workspace
        );
        assert_eq!(authority.provenance().length, 17);
        authority.revalidate().unwrap();
    }

    #[test]
    fn executable_content_substitution_is_detected_before_snapshot() {
        let fixture = Fixture::new();
        let authored = contract(WorkingDirectoryMode::Denied);
        let (baseline, values) = fixture.environment();
        let authority =
            GovernedExecutionAuthority::bind(intent(&authored, None), &baseline, values, None)
                .unwrap();
        write_executable(&fixture.executable, b"#!/bin/sh\nexit 1\n");
        assert_eq!(
            authority
                .revalidate()
                .expect_err("changed executable must fail")
                .code,
            GovernedExecutionAuthorityErrorCode::ExecutableChanged
        );
    }

    #[test]
    fn install_review_digest_must_match_the_final_opened_executable() {
        let fixture = Fixture::new();
        let authored = contract(WorkingDirectoryMode::Denied);
        let reviewed = GovernedExpectedExecutableDigest::from_blake3(
            *blake3::hash(b"#!/bin/sh\nexit 0\n").as_bytes(),
        );
        let (baseline, values) = fixture.environment();
        GovernedExecutionAuthority::bind_expected_executable(
            intent(&authored, None),
            &baseline,
            values,
            None,
            reviewed,
        )
        .expect("the exact install-reviewed bytes bind");

        let wrong_algorithm_bytes = GovernedExpectedExecutableDigest::from_blake3(
            Sha256::digest(b"#!/bin/sh\nexit 0\n").into(),
        );
        let (baseline, values) = fixture.environment();
        let error = GovernedExecutionAuthority::bind_expected_executable(
            intent(&authored, None),
            &baseline,
            values,
            None,
            wrong_algorithm_bytes,
        )
        .err()
        .expect("a SHA-256 payload cannot masquerade as the reviewed BLAKE3");
        assert_eq!(
            error.code,
            GovernedExecutionAuthorityErrorCode::ExecutableChanged
        );
    }

    #[test]
    fn private_snapshot_preserves_the_bound_bytes_and_mode() {
        let fixture = Fixture::new();
        let authored = contract(WorkingDirectoryMode::Denied);
        let (baseline, values) = fixture.environment();
        let authority =
            GovernedExecutionAuthority::bind(intent(&authored, None), &baseline, values, None)
                .unwrap();
        let parts = authority.into_parts();
        let snapshot = parts.executable_snapshot().unwrap();
        assert_ne!(snapshot.as_path().parent(), fixture.executable.parent());
        assert_eq!(
            fs::read(snapshot.as_path()).unwrap(),
            b"#!/bin/sh\nexit 0\n"
        );
        #[cfg(unix)]
        assert_ne!(
            fs::metadata(snapshot.as_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o111,
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn path_symlink_binds_and_snapshots_the_resolved_executable() {
        let fixture = Fixture::new();
        let target = fixture._root.path().join("installed-cli-real");
        write_executable(&target, b"#!/bin/sh\nexit 7\n");
        fs::remove_file(&fixture.executable).unwrap();
        symlink(&target, &fixture.executable).unwrap();

        let authored = contract(WorkingDirectoryMode::Denied);
        let (baseline, values) = fixture.environment();
        let authority =
            GovernedExecutionAuthority::bind(intent(&authored, None), &baseline, values, None)
                .expect("reviewed PATH symlink");
        let snapshot = authority.into_parts().executable_snapshot().unwrap();
        assert_eq!(
            fs::read(snapshot.as_path()).unwrap(),
            b"#!/bin/sh\nexit 7\n"
        );

        fs::remove_file(&fixture.executable).unwrap();
        symlink(fixture._root.path().join("other"), &fixture.executable).unwrap();
        assert_eq!(
            fs::read(snapshot.as_path()).unwrap(),
            b"#!/bin/sh\nexit 7\n"
        );
    }

    #[test]
    fn symlinked_cwd_and_mode_substitution_fail_closed() {
        let fixture = Fixture::new();
        let outside = fixture._root.path().join("outside");
        fs::create_dir(&outside).unwrap();
        #[cfg(unix)]
        symlink(&outside, fixture.workspace.join("escape")).unwrap();
        let authored = contract(WorkingDirectoryMode::Workspace);
        let (baseline, values) = fixture.environment();
        let root =
            GovernedWorkingDirectoryRoot::open(WorkingDirectoryMode::Workspace, &fixture.workspace)
                .unwrap();
        assert_eq!(
            GovernedExecutionAuthority::bind(
                intent(&authored, Some("escape".to_owned())),
                &baseline,
                values,
                Some(root),
            )
            .err()
            .expect("symlinked cwd must fail")
            .code,
            GovernedExecutionAuthorityErrorCode::WorkingDirectoryUnsafe
        );

        let (baseline, values) = fixture.environment();
        let wrong = GovernedWorkingDirectoryRoot::open(
            WorkingDirectoryMode::OutputRoot,
            &fixture.workspace,
        )
        .unwrap();
        assert_eq!(
            GovernedExecutionAuthority::bind(
                intent(&authored, None),
                &baseline,
                values,
                Some(wrong),
            )
            .err()
            .expect("cwd authority mode mismatch must fail")
            .code,
            GovernedExecutionAuthorityErrorCode::WorkingDirectoryModeMismatch
        );
    }

    #[test]
    fn replacing_a_bound_cwd_component_is_detected() {
        let fixture = Fixture::new();
        let child = fixture.workspace.join("child");
        fs::create_dir(&child).unwrap();
        let authored = contract(WorkingDirectoryMode::Workspace);
        let (baseline, values) = fixture.environment();
        let root =
            GovernedWorkingDirectoryRoot::open(WorkingDirectoryMode::Workspace, &fixture.workspace)
                .unwrap();
        let authority = GovernedExecutionAuthority::bind(
            intent(&authored, Some("child".to_owned())),
            &baseline,
            values,
            Some(root),
        )
        .unwrap();
        fs::remove_dir(&child).unwrap();
        fs::create_dir(&child).unwrap();
        assert_eq!(
            authority
                .revalidate()
                .expect_err("replaced cwd must fail")
                .code,
            GovernedExecutionAuthorityErrorCode::WorkingDirectoryChanged
        );
    }

    #[cfg(unix)]
    #[test]
    fn group_or_world_writable_cwd_authority_fails_closed() {
        let fixture = Fixture::new();
        fs::set_permissions(&fixture.workspace, fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(
            GovernedWorkingDirectoryRoot::open(
                WorkingDirectoryMode::Workspace,
                &fixture.workspace,
            )
            .err()
            .expect("mutable cwd authority must be rejected")
            .code,
            GovernedExecutionAuthorityErrorCode::WorkingDirectoryUnsafe
        );
    }

    #[test]
    fn diagnostics_and_public_authorities_expose_no_paths_or_values() {
        let fixture = Fixture::new();
        let authored = contract(WorkingDirectoryMode::Workspace);
        let (baseline, values) = fixture.environment();
        let error = GovernedExecutionAuthority::bind(
            intent(&authored, Some("missing-canary".to_owned())),
            &baseline,
            values,
            Some(
                GovernedWorkingDirectoryRoot::open(
                    WorkingDirectoryMode::Workspace,
                    &fixture.workspace,
                )
                .unwrap(),
            ),
        )
        .err()
        .expect("missing cwd must fail");
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains("missing-canary"));
        assert!(!diagnostic.contains(fixture.workspace.to_string_lossy().as_ref()));
    }

    /// Mach-O 64-bit magic, little-endian on disk. Enough for `is_mach_object`.
    const MACH_O_64: &[u8] = b"\xcf\xfa\xed\xfe";

    /// Lay a `bin/` + `lib/` package out around the fixture executable, giving
    /// the executable the `@rpath/` reference that makes it need the bundle.
    #[cfg(unix)]
    fn write_rpath_package(fixture: &Fixture, rpath_reference: bool) -> PathBuf {
        let library_directory = fixture._root.path().join("lib");
        fs::create_dir(&library_directory).unwrap();
        let mut library = MACH_O_64.to_vec();
        library.extend_from_slice(b" fixture library payload");
        fs::write(library_directory.join("libfixture.1.dylib"), &library).unwrap();
        let body: &[u8] = if rpath_reference {
            b"#!/bin/sh\n# needs @rpath/libfixture.1.dylib\nexit 0\n"
        } else {
            b"#!/bin/sh\n# self-contained, no adjacent libraries\nexit 0\n"
        };
        write_executable(&fixture.executable, body);
        library_directory
    }

    #[cfg(unix)]
    fn bound_authority(fixture: &Fixture) -> GovernedExecutionAuthority {
        let authored = contract(WorkingDirectoryMode::Denied);
        let (baseline, values) = fixture.environment();
        GovernedExecutionAuthority::bind(intent(&authored, None), &baseline, values, None).unwrap()
    }

    /// A binary that resolves libraries through `@rpath` is snapshotted with one
    /// level of its layout preserved, so `@loader_path/../lib` still lands
    /// inside the private directory instead of at a path that does not exist.
    #[cfg(unix)]
    #[test]
    fn rpath_executable_snapshots_with_its_adjacent_libraries() {
        let fixture = Fixture::new();
        write_rpath_package(&fixture, true);
        let snapshot = bound_authority(&fixture)
            .into_parts()
            .executable_snapshot()
            .unwrap();

        let executable_directory = snapshot.as_path().parent().expect("bundle bin directory");
        assert_eq!(
            executable_directory.file_name(),
            Some(OsStr::new("bin")),
            "the executable keeps its directory name so `../lib` resolves"
        );
        let bundled = executable_directory
            .parent()
            .expect("bundle root")
            .join("lib")
            .join("libfixture.1.dylib");
        let bundled = fs::read(&bundled).expect("bundled library");
        assert!(bundled.starts_with(MACH_O_64));
        assert_ne!(
            executable_directory, fixture.bin,
            "the bundle is a private copy, not the installed directory"
        );
    }

    /// The bundle is built only for binaries that actually need it. Without an
    /// `@rpath` reference the snapshot stays the plain single file it has
    /// always been, even when a sibling `lib` directory happens to exist.
    #[cfg(unix)]
    #[test]
    fn snapshot_without_an_rpath_reference_stays_a_single_file() {
        let fixture = Fixture::new();
        write_rpath_package(&fixture, false);
        let snapshot = bound_authority(&fixture)
            .into_parts()
            .executable_snapshot()
            .unwrap();

        let executable_directory = snapshot.as_path().parent().expect("snapshot directory");
        assert!(
            !executable_directory.join("lib").exists(),
            "no library directory is materialized for a self-contained binary"
        );
        assert_ne!(
            executable_directory.file_name(),
            Some(OsStr::new("bin")),
            "no layout level is reproduced for a self-contained binary"
        );
        assert_ne!(executable_directory, fixture.bin);
    }

    /// A library directory larger than the bundle ceiling is refused rather than
    /// copied. The file is sparse: the ceiling is checked from the entry's
    /// length before any bytes are read, which is the behaviour being pinned.
    #[cfg(unix)]
    #[test]
    fn adjacent_library_bundle_refuses_an_oversized_directory() {
        let fixture = Fixture::new();
        let library_directory = write_rpath_package(&fixture, true);
        let oversized = File::create(library_directory.join("liboversized.dylib")).unwrap();
        oversized.write_at(MACH_O_64, 0).unwrap();
        oversized
            .set_len(MAX_GOVERNED_EXECUTABLE_BUNDLE_BYTES + 1)
            .unwrap();
        drop(oversized);

        // `expect_err` would require `GovernedExecutableSnapshot: Debug`, which
        // the type deliberately does not implement — see the
        // `assert_not_impl_any!` below.
        match bound_authority(&fixture).into_parts().executable_snapshot() {
            Ok(_) => panic!("an oversized bundle must be refused"),
            Err(error) => assert_eq!(
                error.code,
                GovernedExecutionAuthorityErrorCode::ExecutableUnsafe
            ),
        }
    }

    /// More entries than the budget allows is refused on the same branch.
    #[cfg(unix)]
    #[test]
    fn adjacent_library_bundle_refuses_too_many_entries() {
        let fixture = Fixture::new();
        let library_directory = write_rpath_package(&fixture, true);
        for index in 0..=MAX_GOVERNED_EXECUTABLE_BUNDLE_ENTRIES {
            fs::write(
                library_directory.join(format!("libfixture-{index}.dylib")),
                MACH_O_64,
            )
            .unwrap();
        }

        match bound_authority(&fixture).into_parts().executable_snapshot() {
            Ok(_) => panic!("an over-budget bundle must be refused"),
            Err(error) => assert_eq!(
                error.code,
                GovernedExecutionAuthorityErrorCode::ExecutableUnsafe
            ),
        }
    }

    /// A versioned alias inside the directory is materialized as a real copy, so
    /// the bundle contains no symlink at all; a link that points out of the
    /// package tree copies nothing, so the bundle cannot reach outside it.
    #[cfg(unix)]
    #[test]
    fn adjacent_library_bundle_resolves_aliases_but_not_links_out_of_the_tree() {
        let fixture = Fixture::new();
        let library_directory = write_rpath_package(&fixture, true);
        symlink(
            library_directory.join("libfixture.1.dylib"),
            library_directory.join("libfixture.dylib"),
        )
        .unwrap();
        let outside = fixture._root.path().join("outside.dylib");
        let mut escaped = MACH_O_64.to_vec();
        escaped.extend_from_slice(b" outside the package tree");
        fs::write(&outside, &escaped).unwrap();
        symlink(&outside, library_directory.join("libescaped.dylib")).unwrap();

        let snapshot = bound_authority(&fixture)
            .into_parts()
            .executable_snapshot()
            .unwrap();
        let bundled_libraries = snapshot
            .as_path()
            .parent()
            .and_then(Path::parent)
            .expect("bundle root")
            .join("lib");

        let alias = bundled_libraries.join("libfixture.dylib");
        assert!(
            fs::symlink_metadata(&alias).unwrap().is_file()
                && !fs::symlink_metadata(&alias)
                    .unwrap()
                    .file_type()
                    .is_symlink(),
            "an alias is materialized as a regular copy, never as a link"
        );
        assert!(fs::read(&alias).unwrap().starts_with(MACH_O_64));
        assert!(
            !bundled_libraries.join("libescaped.dylib").exists(),
            "a link out of the package tree contributes nothing"
        );
    }

    /// The narrowed boundary. On the sealed, read-only system volume the
    /// executable is launched from its own path, because a copy of an arm64e
    /// platform binary is SIGKILLed at exec no matter how intact its signature
    /// is. Everywhere else the private copy is still what runs.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_sealed_system_volume_executable_launches_from_its_own_path() {
        let system_awk = Path::new("/usr/bin/awk");
        if !system_awk.is_file() {
            return;
        }
        let authored = contract_for("awk", WorkingDirectoryMode::Denied);
        let baseline = ChildEnvironmentBaseline::portable_cli();
        let mut values = ChildEnvironmentValues::new(&baseline);
        values
            .provide(ChildEnvironmentVariable::Path, b"/usr/bin".to_vec())
            .unwrap();
        let authority =
            GovernedExecutionAuthority::bind(intent(&authored, None), &baseline, values, None)
                .unwrap();
        let snapshot = authority.into_parts().executable_snapshot().unwrap();

        assert_eq!(
            snapshot.as_path(),
            system_awk,
            "a sealed-volume binary must run from its own path, not a copy"
        );
    }

    /// The predicate is on the mount, and it fails closed: a writable volume and
    /// an unreadable path both snapshot exactly as before.
    #[cfg(target_os = "macos")]
    #[test]
    fn in_place_execution_is_refused_off_the_sealed_volume_and_on_statfs_failure() {
        let fixture = Fixture::new();
        assert!(
            !executes_in_place_on_sealed_system_volume(&fixture.executable),
            "a writable volume must still be snapshotted"
        );
        assert!(
            !executes_in_place_on_sealed_system_volume(&fixture._root.path().join("absent-canary")),
            "a statfs failure must fall back to snapshotting"
        );
        assert!(
            executes_in_place_on_sealed_system_volume(Path::new("/usr/bin")),
            "the sealed system volume is recognized through its mount flags"
        );

        // And the writable case really does still produce a private copy.
        let snapshot = bound_authority(&fixture)
            .into_parts()
            .executable_snapshot()
            .unwrap();
        assert_ne!(snapshot.as_path(), fixture.executable.as_path());
    }

    assert_not_impl_any!(GovernedWorkingDirectoryRoot: Clone, fmt::Debug, Serialize);
    assert_not_impl_any!(GovernedExpectedExecutableDigest: Clone, fmt::Debug, Serialize);
    assert_not_impl_any!(GovernedExecutableSnapshot: Clone, fmt::Debug, Serialize);
    assert_not_impl_any!(GovernedExecutionAuthority: Clone, fmt::Debug, Serialize);
}
