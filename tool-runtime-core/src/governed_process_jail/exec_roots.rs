//! Declared exec roots: an opt-in jail mode that runs an installed program
//! in place, whatever its language or toolchain.
//!
//! Trust model. The code under a declared root (the skill, its runtime, its
//! packages) is trusted as installed; the untrusted party is the caller who
//! picks the arguments. The jail therefore confines the run's authority and
//! data flow, not the program's code: it may read and exec only the declared
//! roots (minus their excluded subpaths) and the fixed system exec paths,
//! write only its private workdir, and reach the network only through the
//! broker of a brokered jail (or not at all).

use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs,
    path::{Component, Path, PathBuf},
};

use serde::Serialize;

use super::{
    sbpl_escape, validate_real_absolute_directory, GovernedProcessJailDigest,
    GovernedProcessJailError, GovernedProcessJailErrorCode,
};

/// Schema of the exec-roots evidence in the jail audit. The jail's own schema
/// stays that of its network mode.
pub const GOVERNED_JAIL_EXEC_ROOTS_V1: &str = "tool-runtime.governed-process-jail.exec-roots.v1";
/// Most declared roots per jail.
pub const MAX_GOVERNED_JAIL_EXEC_ROOTS: usize = 16;
/// Most excluded subpaths per root.
pub const MAX_GOVERNED_JAIL_EXEC_ROOT_EXCLUSIONS: usize = 16;
/// Most `PATH` directories the consumer may list.
pub const MAX_GOVERNED_JAIL_EXEC_SEARCH_PATH: usize = 16;
/// Longest root, exclusion or `PATH` entry, in bytes (canonical, joined).
pub const MAX_GOVERNED_JAIL_EXEC_ROOT_PATH_BYTES: usize = 1024;
/// System directories appended to the child's `PATH`, in order. Their
/// programs are exec-allowed in this mode (macOS: `(subpath …)` exec and
/// read; Linux: read-only binds).
pub const GOVERNED_JAIL_EXEC_ROOTS_SYSTEM_PATH: [&str; 2] = ["/usr/bin", "/bin"];
/// Interpreter flags in exec-roots mode: `-s` no user site, `-B` no bytecode
/// writes. `-I` and `-S` are dropped on purpose: the script's directory must
/// be on `sys.path` and `site` must run, so a program can import packages
/// that live inside its roots.
pub const GOVERNED_JAIL_PYTHON3_EXEC_ROOTS_FLAGS: [&str; 2] = ["-s", "-B"];
/// Fixed child environment overlay of this mode, applied after every
/// contract value so that every Python the run starts (not only the one the
/// jail launches) skips the user site and writes no bytecode.
/// `OPENSSL_CONF=/dev/null` keeps OpenSSL (Python's `ssl`, Node, `curl`)
/// from reading a configuration file, which can load engines and providers,
/// from a prefix whose `etc/` is excluded or not a root at all.
pub const GOVERNED_JAIL_EXEC_ROOTS_ENVIRONMENT: [(&str, &str); 3] = [
    ("PYTHONNOUSERSITE", "1"),
    ("PYTHONDONTWRITEBYTECODE", "1"),
    ("OPENSSL_CONF", "/dev/null"),
];
/// Directory of the workdir that receives staged inputs in exec-roots mode;
/// `stage_input_file` returns `in/<name>`.
pub const GOVERNED_JAIL_EXEC_ROOTS_INPUT_DIRECTORY: &str = "in";
/// Linux: host system directories bound read-only in this mode, when they
/// exist, on top of the strict `/lib` and `/lib64`.
pub(super) const LINUX_EXEC_ROOTS_SYSTEM_MOUNTS: [&str; 4] = ["/bin", "/usr/bin", "/usr/lib", "/usr/lib64"];
/// macOS: system directories that are exec-allowed and readable in this mode.
pub(super) const MACOS_EXEC_ROOTS_SYSTEM_EXEC: [&str; 2] = ["/bin", "/usr/bin"];
/// In-jail paths of the jail's own machinery; a root may not be, contain or
/// sit inside one.
const RESERVED_JAIL_PATHS: [&str; 5] = ["/app", "/work", "/proc", "/dev", "/run/magicrun"];

/// One declared root: a directory whose whole tree the jailed run may read
/// and exec, less its excluded subpaths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernedJailExecRoot {
    path: PathBuf,
    excluded: Vec<PathBuf>,
}

impl GovernedJailExecRoot {
    /// An absolute existing directory. It is canonicalized when the
    /// declaration is validated; the canonical path is what the jail grants.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            excluded: Vec::new(),
        }
    }

    /// Keep `relative` (a directory below the root, plain components only)
    /// unreadable even though the root is granted. It must exist as a real
    /// directory when the declaration is validated and at every launch:
    /// exclude the directory that holds a secret (`config/`), not the file,
    /// and replace files inside it rather than the directory itself.
    pub fn excluding(mut self, relative: impl Into<PathBuf>) -> Self {
        self.excluded.push(relative.into());
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn excluded(&self) -> &[PathBuf] {
        &self.excluded
    }

    /// Absolute excluded paths.
    pub(super) fn excluded_paths(&self) -> impl Iterator<Item = PathBuf> + '_ {
        self.excluded.iter().map(|relative| self.path.join(relative))
    }
}

/// A validated exec-roots declaration: canonical roots, their exclusions and
/// the consumer's `PATH` directories (each inside a root). Build it with
/// [`Self::new`] and pass it to
/// [`GovernedProcessJail::with_exec_roots`](super::GovernedProcessJail::with_exec_roots).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernedJailExecRoots {
    roots: Vec<GovernedJailExecRoot>,
    search_path: Vec<PathBuf>,
}

impl GovernedJailExecRoots {
    /// Validate a declaration against this host.
    ///
    /// Roots must be runtime and skill directories only: an installed
    /// runtime's own tree (a keg, a venv, a Node install) and the skill
    /// itself, never a prefix that also holds data (`/opt/homebrew` holds
    /// `var/` databases and `etc/`), a data root or a home directory. The
    /// jail cannot know what a directory holds; the consumer must assert
    /// this, and should pass its data roots to [`Self::new_with_forbidden`].
    ///
    /// Each root is canonicalized and must be an existing directory, at most
    /// [`MAX_GOVERNED_JAIL_EXEC_ROOT_PATH_BYTES`] long; not `/`, not the home
    /// directory (`$HOME` or the password database's) or one of its
    /// ancestors, not overlapping another root or a path of the jail's own
    /// machinery. The root must be owned by root or this user and not
    /// group/other-writable; every ancestor must be owned by root or this
    /// user and not group/other-writable, except a root-owned sticky
    /// directory such as `/tmp`. Exclusions are relative, plain components,
    /// and must exist as real directories (not symlinks, not below one)
    /// whose regular files have a single link each; a file exclusion is
    /// refused (see [`GovernedJailExecRoot::excluding`]). `PATH` entries are
    /// canonicalized, must lie inside a root outside its exclusions, and may
    /// not contain `:`. Only the program's identity is pinned: the rest of
    /// each root's tree is not walked and is trusted as installed.
    pub fn new(
        roots: impl IntoIterator<Item = GovernedJailExecRoot>,
        search_path: impl IntoIterator<Item = PathBuf>,
    ) -> Result<Self, GovernedProcessJailError> {
        Self::new_with_forbidden(roots, search_path, std::iter::empty())
    }

    /// As [`Self::new`], additionally refusing a root that equals, contains
    /// or lies inside any of `forbidden` (the consumer's data root, sensitive
    /// directories of the home directory). A forbidden path is compared
    /// with its longest existing ancestor canonicalized and the rest
    /// appended, so a path not created yet still matches through a
    /// symlinked ancestor (`/tmp`, `/var` on macOS). It is a validation
    /// input only and does not change the declaration or its identity.
    pub fn new_with_forbidden(
        roots: impl IntoIterator<Item = GovernedJailExecRoot>,
        search_path: impl IntoIterator<Item = PathBuf>,
        forbidden: impl IntoIterator<Item = PathBuf>,
    ) -> Result<Self, GovernedProcessJailError> {
        let roots = roots.into_iter().collect::<Vec<_>>();
        let search_path = search_path.into_iter().collect::<Vec<_>>();
        if roots.is_empty()
            || roots.len() > MAX_GOVERNED_JAIL_EXEC_ROOTS
            || search_path.len() > MAX_GOVERNED_JAIL_EXEC_SEARCH_PATH
        {
            return Err(invalid_exec_roots());
        }
        let roots = roots
            .into_iter()
            .map(|root| {
                if !root.path.is_absolute() {
                    return Err(invalid_exec_roots());
                }
                Ok(GovernedJailExecRoot {
                    path: fs::canonicalize(&root.path).map_err(|_| invalid_exec_roots())?,
                    excluded: root.excluded,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let search_path = search_path
            .into_iter()
            .map(|entry| {
                if !entry.is_absolute() {
                    return Err(invalid_exec_roots());
                }
                fs::canonicalize(entry).map_err(|_| invalid_exec_roots())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let declaration = Self::declared(roots, search_path)?;
        for home in home_directories() {
            if declaration.roots.iter().any(|root| home.starts_with(&root.path)) {
                return Err(invalid_exec_roots());
            }
        }
        for forbidden in forbidden {
            if !forbidden.is_absolute() {
                return Err(invalid_exec_roots());
            }
            let forbidden = canonical_prefix(&forbidden);
            if declaration
                .roots
                .iter()
                .any(|root| root.path.starts_with(&forbidden) || forbidden.starts_with(&root.path))
            {
                return Err(invalid_exec_roots());
            }
        }
        declaration.revalidate()?;
        Ok(declaration)
    }

    /// The host-independent checks of a canonical declaration.
    pub(super) fn declared(
        roots: Vec<GovernedJailExecRoot>,
        search_path: Vec<PathBuf>,
    ) -> Result<Self, GovernedProcessJailError> {
        if roots.is_empty()
            || roots.len() > MAX_GOVERNED_JAIL_EXEC_ROOTS
            || search_path.len() > MAX_GOVERNED_JAIL_EXEC_SEARCH_PATH
        {
            return Err(invalid_exec_roots());
        }
        for (index, root) in roots.iter().enumerate() {
            declared_path(&root.path)?;
            if root.path.parent().is_none()
                || RESERVED_JAIL_PATHS.iter().any(|reserved| {
                    let reserved = Path::new(reserved);
                    root.path.starts_with(reserved) || reserved.starts_with(&root.path)
                })
                || roots[..index]
                    .iter()
                    .any(|other| other.path.starts_with(&root.path) || root.path.starts_with(&other.path))
                || root.excluded.len() > MAX_GOVERNED_JAIL_EXEC_ROOT_EXCLUSIONS
            {
                return Err(invalid_exec_roots());
            }
            let mut seen = BTreeSet::new();
            for relative in &root.excluded {
                if relative.as_os_str().is_empty()
                    || !relative
                        .components()
                        .all(|component| matches!(component, Component::Normal(_)))
                    || !seen.insert(relative.clone())
                {
                    return Err(invalid_exec_roots());
                }
                declared_path(&root.path.join(relative))?;
            }
        }
        for (index, entry) in search_path.iter().enumerate() {
            declared_path(entry)?;
            let inside = roots.iter().any(|root| {
                entry.starts_with(&root.path)
                    && !root.excluded_paths().any(|excluded| entry.starts_with(excluded))
            });
            if !inside
                || entry.as_os_str().as_encoded_bytes().contains(&b':')
                || search_path[..index].contains(entry)
            {
                return Err(invalid_exec_roots());
            }
        }
        Ok(Self { roots, search_path })
    }

    pub fn roots(&self) -> &[GovernedJailExecRoot] {
        &self.roots
    }

    pub fn search_path(&self) -> &[PathBuf] {
        &self.search_path
    }

    /// Domain-separated BLAKE3 of the canonical roots, their exclusions and
    /// the `PATH` entries, in order. Folded into the profile identity.
    pub fn declaration_digest(&self) -> GovernedProcessJailDigest {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tool-runtime.governed-process-jail.exec-roots-declaration.v1\0");
        let mut part = |bytes: &[u8]| {
            hasher.update(&(bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        };
        part(&(self.roots.len() as u64).to_be_bytes());
        for root in &self.roots {
            part(root.path.as_os_str().as_encoded_bytes());
            part(&(root.excluded.len() as u64).to_be_bytes());
            for excluded in &root.excluded {
                part(excluded.as_os_str().as_encoded_bytes());
            }
        }
        part(&(self.search_path.len() as u64).to_be_bytes());
        for entry in &self.search_path {
            part(entry.as_os_str().as_encoded_bytes());
        }
        GovernedProcessJailDigest(*hasher.finalize().as_bytes())
    }

    pub(super) fn excluded_count(&self) -> usize {
        self.roots.iter().map(|root| root.excluded.len()).sum()
    }

    /// Re-run the host checks: canonical real directories, ownership and
    /// mode of every root and its ancestors, exclusions that exist are
    /// canonical, `PATH` entries are still canonical directories.
    pub(super) fn revalidate(&self) -> Result<(), GovernedProcessJailError> {
        for root in &self.roots {
            validate_real_absolute_directory(&root.path).map_err(|_| invalid_exec_roots())?;
            trusted_root(&root.path)?;
            for excluded in root.excluded_paths() {
                // An exclusion must exist as a real directory. A file mask
                // does not survive the atomic temp-plus-rename writers use:
                // since Linux 3.18 a rename over a mount point in another
                // mount namespace detaches that mount, so the jail would
                // then read the new file. A directory mask survives writes
                // inside the directory. An exclusion absent at launch would
                // get no Linux mask at all.
                validate_real_absolute_directory(&excluded).map_err(|_| invalid_exec_roots())?;
                single_link_tree(&excluded)?;
            }
        }
        for entry in &self.search_path {
            validate_real_absolute_directory(entry).map_err(|_| invalid_exec_roots())?;
            // The entry and every directory between it and its root are
            // held to the root's own trust rule: nobody else may plant a
            // program the run would find by name.
            let root = self
                .roots
                .iter()
                .find(|root| entry.starts_with(&root.path))
                .ok_or_else(invalid_exec_roots)?;
            let mut current = Some(entry.as_path());
            while let Some(directory) = current.filter(|directory| *directory != root.path) {
                trusted_directory(directory)?;
                current = directory.parent();
            }
        }
        Ok(())
    }

    /// Whether a root and the workdir share a subtree.
    pub(super) fn overlaps(&self, workdir: &Path) -> bool {
        self.roots
            .iter()
            .any(|root| workdir.starts_with(&root.path) || root.path.starts_with(workdir))
    }

    /// Whether `path` lies inside a root and outside its exclusions.
    pub(super) fn admits(&self, path: &Path) -> bool {
        self.roots.iter().any(|root| {
            path.starts_with(&root.path)
                && path != root.path
                && !root.excluded_paths().any(|excluded| path.starts_with(excluded))
        })
    }

    /// The child's `PATH`: the consumer's entries, then the system paths.
    pub(super) fn child_path(&self) -> OsString {
        let mut path = OsString::new();
        for entry in self
            .search_path
            .iter()
            .map(|entry| entry.as_os_str())
            .chain(GOVERNED_JAIL_EXEC_ROOTS_SYSTEM_PATH.iter().map(|entry| entry.as_ref()))
        {
            if !path.is_empty() {
                path.push(":");
            }
            path.push(entry);
        }
        path
    }

    /// Linux: the excluded directories to mask, each with an empty tmpfs
    /// remounted read-only. [`Self::revalidate`] has just proved each one a
    /// real directory.
    pub(super) fn masks(&self) -> Vec<PathBuf> {
        self.roots
            .iter()
            .flat_map(GovernedJailExecRoot::excluded_paths)
            .collect()
    }

    /// macOS allowances of this mode, placed after the strict base profile:
    /// fork and signals inside the sandbox, `/dev/null` writes, the
    /// membership sentinel, the system
    /// exec paths, the roots (read, exec, map executable) and metadata of
    /// every ancestor of a root or the workdir (path resolution such as
    /// Node's `realpath` `lstat`s each component; no listing is granted).
    pub(super) fn macos_allow_rules(&self, workdir: &Path, sentinel: &Path) -> Result<String, GovernedProcessJailError> {
        let mut rules = String::from(
            "(allow process-fork)\n\
             (allow signal (target same-sandbox))\n\
             (allow file-write-data (literal \"/dev/null\"))\n",
        );
        // The membership sentinel: an empty directory only this jail's
        // profile may read (see `MacosJailMembers`).
        rules.push_str(&format!(
            "(allow file-read-data (literal \"{}\"))\n",
            sbpl_escape(sentinel)?,
        ));
        for system in MACOS_EXEC_ROOTS_SYSTEM_EXEC {
            rules.push_str(&format!(
                "(allow file-read* process-exec (subpath \"{system}\"))\n"
            ));
        }
        for root in &self.roots {
            rules.push_str(&format!(
                "(allow file-read* process-exec file-map-executable (subpath \"{}\"))\n",
                sbpl_escape(&root.path)?,
            ));
        }
        let ancestors = self
            .roots
            .iter()
            .map(|root| root.path.as_path())
            .chain(std::iter::once(workdir))
            .flat_map(|path| path.ancestors().skip(1))
            .collect::<BTreeSet<_>>();
        for ancestor in ancestors {
            rules.push_str(&format!(
                "(allow file-read-metadata (literal \"{}\"))\n",
                sbpl_escape(ancestor)?,
            ));
        }
        Ok(rules)
    }

    /// macOS denials of the excluded subpaths, placed after every allowance
    /// so they win. They apply whether or not the path exists yet.
    pub(super) fn macos_deny_rules(&self) -> Result<String, GovernedProcessJailError> {
        let mut rules = String::new();
        for excluded in self.roots.iter().flat_map(GovernedJailExecRoot::excluded_paths) {
            rules.push_str(&format!(
                "(deny file-read* process-exec file-map-executable (subpath \"{}\"))\n",
                sbpl_escape(&excluded)?,
            ));
        }
        Ok(rules)
    }
}

/// Most entries walked under one excluded directory.
const MAX_EXCLUDED_TREE_ENTRIES: usize = 4096;

/// Every regular file below an excluded directory has exactly one link, so
/// no other path (inside a root or not) reaches its bytes around the
/// exclusion. Symlinks are not followed. Bounded.
fn single_link_tree(directory: &Path) -> Result<(), GovernedProcessJailError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let mut pending = vec![directory.to_path_buf()];
        let mut entries = 0_usize;
        while let Some(current) = pending.pop() {
            for entry in fs::read_dir(&current).map_err(|_| invalid_exec_roots())? {
                entries += 1;
                if entries > MAX_EXCLUDED_TREE_ENTRIES {
                    return Err(invalid_exec_roots());
                }
                let path = entry.map_err(|_| invalid_exec_roots())?.path();
                let metadata = fs::symlink_metadata(&path).map_err(|_| invalid_exec_roots())?;
                if metadata.is_dir() {
                    pending.push(path);
                } else if metadata.is_file() && metadata.nlink() != 1 {
                    return Err(invalid_exec_roots());
                }
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        Err(super::unsupported_platform())
    }
}

#[cfg(test)]
pub(super) fn home_directories_for_test() -> Vec<PathBuf> {
    home_directories()
}

/// Canonical home directories: `$HOME` and this user's password-database
/// entry, when they resolve.
fn home_directories() -> Vec<PathBuf> {
    let mut homes = Vec::new();
    if let Some(home) = std::env::var_os("HOME").filter(|home| !home.is_empty()) {
        homes.push(PathBuf::from(home));
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        let mut buffer = vec![0 as libc::c_char; 16 * 1024];
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::zeroed();
        let mut result = std::ptr::null_mut::<libc::passwd>();
        // SAFETY: `getpwuid_r` writes only into `entry` and `buffer` (sized
        // as passed) and sets `result` to `entry` or null.
        let status = unsafe {
            libc::getpwuid_r(
                libc::getuid(),
                entry.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        if status == 0 && !result.is_null() {
            // SAFETY: on success `entry` is initialized and `pw_dir` points
            // into `buffer`, NUL-terminated, or is null.
            let directory = unsafe { entry.assume_init() }.pw_dir;
            if !directory.is_null() {
                // SAFETY: a NUL-terminated string inside the live `buffer`.
                let bytes = unsafe { std::ffi::CStr::from_ptr(directory) }.to_bytes();
                if !bytes.is_empty() {
                    homes.push(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)));
                }
            }
        }
    }
    homes
        .into_iter()
        .map(|home| fs::canonicalize(&home).unwrap_or(home))
        .collect()
}

/// Bounded, SBPL-safe spelling of a declared path.
fn declared_path(path: &Path) -> Result<(), GovernedProcessJailError> {
    if !path.is_absolute()
        || path.as_os_str().len() > MAX_GOVERNED_JAIL_EXEC_ROOT_PATH_BYTES
        || !path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(invalid_exec_roots());
    }
    sbpl_escape(path).map_err(|_| invalid_exec_roots())?;
    Ok(())
}

/// The longest existing ancestor of `path` canonicalized, the rest appended.
fn canonical_prefix(path: &Path) -> PathBuf {
    let mut existing = path;
    let mut rest = Vec::new();
    loop {
        if let Ok(canonical) = fs::canonicalize(existing) {
            return rest.iter().rev().fold(canonical, |joined, part| joined.join(part));
        }
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_owned());
                existing = parent;
            },
            _ => return path.to_path_buf(),
        }
    }
}

/// A real directory owned by root or this user, not group/other-writable.
fn trusted_directory(directory: &Path) -> Result<(), GovernedProcessJailError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        // SAFETY: `geteuid` has no preconditions and cannot fail.
        let euid = unsafe { libc::geteuid() };
        let metadata = fs::symlink_metadata(directory).map_err(|_| invalid_exec_roots())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != euid)
            || metadata.mode() & 0o022 != 0
        {
            return Err(invalid_exec_roots());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        Err(super::unsupported_platform())
    }
}

/// The root is owned by root or this user and not group/other-writable.
/// Every ancestor is owned by root or this user and not group/other-writable,
/// or is a root-owned sticky directory (`/tmp`), where nobody else can rename
/// or remove the entry below it.
fn trusted_root(root: &Path) -> Result<(), GovernedProcessJailError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        // SAFETY: `geteuid` has no preconditions and cannot fail.
        let euid = unsafe { libc::geteuid() };
        let metadata = fs::symlink_metadata(root).map_err(|_| invalid_exec_roots())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != euid)
            || metadata.mode() & 0o022 != 0
        {
            return Err(invalid_exec_roots());
        }
        for ancestor in root.ancestors().skip(1) {
            let metadata = fs::symlink_metadata(ancestor).map_err(|_| invalid_exec_roots())?;
            let owner_ok = metadata.uid() == 0 || metadata.uid() == euid;
            let mode_ok = metadata.mode() & 0o022 == 0
                || (metadata.mode() & 0o1000 != 0 && metadata.uid() == 0);
            if metadata.file_type().is_symlink() || !metadata.is_dir() || !owner_ok || !mode_ok {
                return Err(invalid_exec_roots());
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        Err(super::unsupported_platform())
    }
}

pub(super) const fn invalid_exec_roots() -> GovernedProcessJailError {
    GovernedProcessJailError::new(
        GovernedProcessJailErrorCode::InvalidExecRoots,
        "jail.exec_roots",
        "a declared exec root, exclusion, PATH entry or program is unsafe or outside the roots",
    )
}

/// What [`sweep_stale_jail_members`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct GovernedJailSweep {
    /// Stale member sentinels whose members were all killed and which were
    /// removed.
    pub sentinels_removed: u64,
    /// Stale sentinels kept because their members could not be proven dead.
    pub sentinels_kept: u64,
    /// Processes killed.
    pub members_killed: u64,
}

/// macOS: find member sentinels (`magicrun-jail-member-*` in the temp
/// directory, owned by this user) left by a host process that is gone (it
/// crashed or was killed before its jail's teardown finished), kill every
/// process still in those jails and remove the sentinels. A sentinel whose
/// recorded owner process is still running belongs to a live jail and is
/// left alone; one whose owner cannot be read is kept (counted in
/// `sentinels_kept`). Call it at startup and, if wanted, periodically.
/// Other hosts: nothing to do (a Linux jail's processes die with its pid
/// namespace); returns zeros.
///
/// Transitional limits: a legacy sentinel without an owner record (made
/// before owner records) is judged by age alone and swept once its mtime is
/// older than [`STALE_SENTINEL_WITHOUT_OWNER`] (600 s), live or not; and
/// only the current [`std::env::temp_dir`] is scanned, so a sentinel made
/// by a host with another `TMPDIR` is not found.
pub fn sweep_stale_jail_members() -> GovernedJailSweep {
    #[cfg(target_os = "macos")]
    {
        MacosJailMembers::sweep_stale()
    }
    #[cfg(not(target_os = "macos"))]
    {
        GovernedJailSweep::default()
    }
}

/// Age past which a member sentinel without an owner record is stale: more
/// than any run's wall ceiling.
pub const STALE_SENTINEL_WITHOUT_OWNER: std::time::Duration = std::time::Duration::from_secs(600);

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const MEMBER_SENTINEL_PREFIX: &str = "magicrun-jail-member-";
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const MEMBER_SENTINEL_OWNER: &str = "owner";

/// macOS: the processes of one exec-roots jail, wherever they are.
///
/// Exec roots allow fork, and macOS has no pid namespace: a jailed process
/// can `setsid`/`setpgid` out of the launcher's process group, which the
/// watchdog samples and teardown signals. Such a process keeps its sandbox,
/// so membership is decided by the sandbox itself with `sandbox_check`: a
/// process of this user is a member when it is sandboxed, may read this
/// jail's unique sentinel directory (granted by a literal in its profile
/// only), and may not read the sentinel's parent (which no jail profile
/// grants). An unsandboxed process, a process of another jail or an ordinary
/// app sandbox fails one of the three. The sentinel lives as long as this
/// value, records its owning host process, and is kept on disk if teardown
/// could not prove every member dead ([`sweep_stale_jail_members`] finishes
/// the job later). `sandbox_check` is exported by `libsystem_sandbox`
/// (listed in the SDK's stub) but has no public header; the watchdog fails
/// closed if it stops recognizing the jail's own leader.
#[cfg(target_os = "macos")]
pub(crate) struct MacosJailMembers {
    sentinel: std::sync::Mutex<Option<tempfile::TempDir>>,
    sentinel_path: PathBuf,
    inside: std::ffi::CString,
    outside: std::ffi::CString,
    uid: libc::uid_t,
    state: std::sync::Mutex<MemberState>,
}

/// A process identity: pid and start time (microseconds), so a reused pid
/// is never mistaken for the process first seen under it. An exec keeps
/// both.
#[cfg(target_os = "macos")]
type ProcessKey = (libc::pid_t, u64);

#[cfg(target_os = "macos")]
#[derive(Default)]
struct MemberState {
    /// Same-user processes proven unsandboxed: the only negative answer that
    /// is cached. Only the leader joins a sandbox after it starts, and it is
    /// never cached; a sandboxed non-member is asked again on every scan,
    /// and confirmation scans ignore this cache altogether.
    unsandboxed: std::collections::HashSet<ProcessKey>,
    /// Pids of `unsandboxed`, to examine unseen pids first.
    known_pids: std::collections::HashSet<libc::pid_t>,
    /// Highest CPU time seen per member, including members since gone.
    cpu: std::collections::HashMap<ProcessKey, u64>,
    /// Teardown could not prove every member dead.
    survived: bool,
}

#[cfg(target_os = "macos")]
mod sandbox_ffi {
    use std::ffi::{c_char, c_int};

    pub(super) const SANDBOX_FILTER_NONE: c_int = 0;
    pub(super) const SANDBOX_FILTER_PATH: c_int = 1;

    extern "C" {
        /// 0: allowed (or not sandboxed); 1: denied (or sandboxed, for a
        /// null operation); -1: error.
        pub(super) fn sandbox_check(pid: libc::pid_t, operation: *const c_char, filter: c_int, ...) -> c_int;
        pub(super) static SANDBOX_CHECK_NO_REPORT: c_int;
    }
}

/// What one look at a pid established.
#[cfg(target_os = "macos")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Probe {
    /// A live, non-zombie process of this user.
    Ours(ProcessKey),
    /// Gone, a zombie, or another user's (`EPERM`): never a member.
    NotOurs,
    /// Could not be read: never taken as proof of absence.
    Unknown,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Membership {
    Member,
    Unsandboxed,
    /// Sandboxed, but another sandbox.
    OtherSandbox,
    /// `sandbox_check` failed.
    Unknown,
}

/// How a scan uses the unsandboxed cache and whether it stops members.
#[cfg(target_os = "macos")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanMode {
    /// Watchdog sample: cached, no signals.
    Sample,
    /// Teardown: cached, SIGSTOP each member as found.
    Stop,
    /// Final confirmation: every pid asked afresh, SIGSTOP members.
    Confirm,
}

#[cfg(target_os = "macos")]
struct ScanResult {
    members: Vec<ProcessKey>,
    /// Some same-user process could not be classified.
    uncertain: bool,
}

/// Resource sample of a set of members.
#[cfg(target_os = "macos")]
pub(crate) struct MacosMemberUsage {
    pub(crate) processes: u64,
    pub(crate) tasks: u64,
    /// Sum of the highest CPU time seen for every member identity so far,
    /// including members that have exited since (sampled, so a member that
    /// lived between two samples is missed).
    pub(crate) cpu_nanos: u64,
    pub(crate) memory_bytes: u64,
}

/// pid and start time of `pid` if it is a live process of `uid`.
#[cfg(target_os = "macos")]
fn probe(uid: libc::uid_t, pid: libc::pid_t) -> Probe {
    const SZOMB: u32 = 5;
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: PROC_PIDTBSDINFO writes at most `size` bytes into `info`.
    let written = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, info.as_mut_ptr().cast(), size) };
    if written != size {
        return match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EPERM | libc::ESRCH) => Probe::NotOurs,
            _ => Probe::Unknown,
        };
    }
    // SAFETY: the kernel filled the whole structure.
    let info = unsafe { info.assume_init() };
    if info.pbi_uid != uid || info.pbi_status == SZOMB {
        return Probe::NotOurs;
    }
    Probe::Ours((pid, info.pbi_start_tvsec.saturating_mul(1_000_000).saturating_add(info.pbi_start_tvusec)))
}

#[cfg(target_os = "macos")]
impl MacosJailMembers {
    /// Teardown ends after this many consecutive confirmation scans find no
    /// member and no unclassified process...
    const QUIET_SCANS: usize = 3;
    /// ...spaced this far apart.
    const QUIET_SPACING: std::time::Duration = std::time::Duration::from_millis(10);
    /// Teardown gives up (and reports survivors) after this long.
    const TEARDOWN_BOUND: std::time::Duration = std::time::Duration::from_secs(3);
    /// The unsandboxed cache is cleared beyond this many entries.
    const MAX_CACHED: usize = 1 << 16;

    pub(crate) fn new() -> Option<Self> {
        let sentinel = tempfile::Builder::new()
            .prefix(MEMBER_SENTINEL_PREFIX)
            .tempdir()
            .ok()?;
        // SAFETY: `geteuid`/`getpid` have no preconditions and cannot fail.
        let (uid, pid) = unsafe { (libc::geteuid(), libc::getpid()) };
        let Probe::Ours((_, started)) = probe(uid, pid) else {
            return None;
        };
        fs::write(sentinel.path().join(MEMBER_SENTINEL_OWNER), format!("{pid} {started}\n")).ok()?;
        let path = fs::canonicalize(sentinel.path()).ok()?;
        let mut members = Self::for_sentinel(path)?;
        members.sentinel = std::sync::Mutex::new(Some(sentinel));
        Some(members)
    }

    /// A checker for an existing sentinel it does not own.
    fn for_sentinel(path: PathBuf) -> Option<Self> {
        use std::os::unix::ffi::OsStrExt;

        let parent = path.parent()?;
        Some(Self {
            inside: std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?,
            outside: std::ffi::CString::new(parent.as_os_str().as_bytes()).ok()?,
            sentinel_path: path,
            sentinel: std::sync::Mutex::new(None),
            // SAFETY: `geteuid` has no preconditions and cannot fail.
            uid: unsafe { libc::geteuid() },
            state: std::sync::Mutex::new(MemberState::default()),
        })
    }

    /// The directory the jail's profile grants by literal.
    pub(crate) fn sentinel(&self) -> &Path {
        &self.sentinel_path
    }

    fn state(&self) -> std::sync::MutexGuard<'_, MemberState> {
        self.state.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    fn membership(&self, pid: libc::pid_t) -> Membership {
        use sandbox_ffi::*;

        // SAFETY: `sandbox_check` reads the NUL-terminated operation and
        // path (live `CString`s) and the pid; it writes nothing of ours.
        unsafe {
            match sandbox_check(pid, std::ptr::null(), SANDBOX_FILTER_NONE) {
                0 => return Membership::Unsandboxed,
                1 => {},
                _ => return Membership::Unknown,
            }
            let flags = SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT;
            let operation = c"file-read-data".as_ptr();
            let inside = sandbox_check(pid, operation, flags, self.inside.as_ptr());
            let outside = sandbox_check(pid, operation, flags, self.outside.as_ptr());
            match (inside, outside) {
                (0, 1) => Membership::Member,
                (-1, _) | (_, -1) => Membership::Unknown,
                _ => Membership::OtherSandbox,
            }
        }
    }

    /// Whether `key` is still that live process and a member.
    fn still_member(&self, key: ProcessKey) -> bool {
        probe(self.uid, key.0) == Probe::Ours(key) && self.membership(key.0) == Membership::Member
    }

    fn all_pids() -> Option<Vec<libc::pid_t>> {
        // SAFETY: a null buffer asks only for the current count.
        let estimate = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
        let capacity = usize::try_from(estimate).ok()?.checked_add(256)?;
        let mut pids = vec![0 as libc::pid_t; capacity];
        let bytes = libc::c_int::try_from(capacity.checked_mul(std::mem::size_of::<libc::pid_t>())?).ok()?;
        // SAFETY: `pids` is a live writable buffer of `bytes` bytes.
        let listed = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
        let listed = usize::try_from(listed).ok()?.min(capacity);
        pids.truncate(listed);
        Some(pids)
    }

    /// One scan. Unseen pids are examined first, right after the listing: a
    /// fork-and-exit chain keeps only a short-lived member alive at a time.
    /// Stopping modes send SIGSTOP to each member the moment it is found, so
    /// it can neither fork nor exit before it is killed. `leader` is never
    /// cached: it is the one process that joins the sandbox after it starts.
    fn scan(&self, leader: Option<libc::pid_t>, mode: ScanMode) -> Option<ScanResult> {
        let pids = Self::all_pids()?;
        let mut state = self.state();
        if state.unsandboxed.len() > Self::MAX_CACHED {
            state.unsandboxed.clear();
            state.known_pids.clear();
        }
        let (fresh, known): (Vec<_>, Vec<_>) = pids
            .into_iter()
            .filter(|pid| *pid > 1)
            .partition(|pid| !state.known_pids.contains(pid));
        let mut result = ScanResult {
            members: Vec::new(),
            uncertain: false,
        };
        for pid in fresh.into_iter().chain(known) {
            let key = match probe(self.uid, pid) {
                Probe::Ours(key) => key,
                Probe::NotOurs => continue,
                Probe::Unknown => {
                    result.uncertain = true;
                    continue;
                },
            };
            if mode != ScanMode::Confirm && state.unsandboxed.contains(&key) {
                continue;
            }
            match self.membership(pid) {
                Membership::Member => {
                    if mode != ScanMode::Sample {
                        // SAFETY: a signal to a same-user process just
                        // proven a member; SIGSTOP cannot be caught.
                        unsafe { libc::kill(pid, libc::SIGSTOP) };
                    }
                    result.members.push(key);
                },
                Membership::Unsandboxed if Some(pid) != leader => {
                    state.unsandboxed.insert(key);
                    state.known_pids.insert(pid);
                },
                Membership::Unsandboxed | Membership::OtherSandbox => {},
                Membership::Unknown => result.uncertain = true,
            }
        }
        Some(result)
    }

    /// Whether the leader is recognized as a member. `None` while that
    /// cannot be decided: the leader is gone, `sandbox_check` failed, or it
    /// is still `sandbox-exec` itself, before the profile applies and the
    /// program is exec'd. The watchdog fails closed on `Some(false)`:
    /// `sandbox_check` would otherwise fail open.
    pub(crate) fn recognizes_leader(&self, leader: libc::pid_t) -> Option<bool> {
        let mut path = [0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: `proc_pidpath` writes at most the given size into `path`.
        let written = unsafe { libc::proc_pidpath(leader, path.as_mut_ptr().cast(), path.len() as u32) };
        let written = usize::try_from(written).ok().filter(|written| *written > 0)?;
        if &path[..written] == b"/usr/bin/sandbox-exec" {
            return None;
        }
        let Probe::Ours(_) = probe(self.uid, leader) else {
            return None;
        };
        match self.membership(leader) {
            Membership::Member => Some(true),
            Membership::Unknown => None,
            Membership::Unsandboxed | Membership::OtherSandbox => Some(false),
        }
    }

    /// Live members (and the group members given) with their usage; CPU
    /// time accumulates per member identity across samples.
    pub(crate) fn usage(&self, leader: Option<libc::pid_t>, group: &[libc::pid_t]) -> Option<MacosMemberUsage> {
        let mut keys = self.scan(leader, ScanMode::Sample)?.members;
        for pid in group.iter().copied().filter(|pid| *pid > 0) {
            if let Probe::Ours(key) = probe(self.uid, pid) {
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
        }
        let mut usage = MacosMemberUsage {
            processes: 0,
            tasks: 0,
            cpu_nanos: 0,
            memory_bytes: 0,
        };
        let mut state = self.state();
        for key in keys {
            let mut info = std::mem::MaybeUninit::<libc::rusage_info_v2>::zeroed();
            // SAFETY: RUSAGE_INFO_V2 selects exactly this output type.
            if unsafe { libc::proc_pid_rusage(key.0, libc::RUSAGE_INFO_V2, info.as_mut_ptr().cast()) } != 0 {
                continue;
            }
            // SAFETY: the successful kernel call initialized `info`.
            let info = unsafe { info.assume_init() };
            let cpu = info.ri_user_time.saturating_add(info.ri_system_time);
            let peak = state.cpu.entry(key).or_insert(0);
            *peak = (*peak).max(cpu);
            usage.processes += 1;
            usage.memory_bytes = usage.memory_bytes.saturating_add(info.ri_phys_footprint);
            let mut task = std::mem::MaybeUninit::<libc::proc_taskinfo>::zeroed();
            let task_bytes = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
            // SAFETY: PROC_PIDTASKINFO writes at most `task_bytes` into `task`.
            let written =
                unsafe { libc::proc_pidinfo(key.0, libc::PROC_PIDTASKINFO, 0, task.as_mut_ptr().cast(), task_bytes) };
            let threads = if written == task_bytes {
                // SAFETY: the kernel filled the whole structure.
                u64::try_from(unsafe { task.assume_init() }.pti_threadnum).unwrap_or(1)
            } else {
                1
            };
            usage.tasks = usage.tasks.saturating_add(threads.max(1));
        }
        usage.cpu_nanos = state.cpu.values().fold(0_u64, |total, cpu| total.saturating_add(*cpu));
        (usage.processes > 0).then_some(usage)
    }

    /// Kill every member. Stopping scans (cached) repeat while they find
    /// members; each stopped member's identity and membership is rechecked
    /// and it is SIGKILLed. The end needs [`Self::QUIET_SCANS`] consecutive
    /// confirmation scans, which ask every same-user process afresh, spaced
    /// by [`Self::QUIET_SPACING`], that find no member and no process they
    /// could not classify. Returns `false` (and keeps the sentinel on disk)
    /// when that does not happen within [`Self::TEARDOWN_BOUND`] or the
    /// process list cannot be read: the caller must then fail closed.
    pub(crate) fn kill_all(&self) -> bool {
        self.kill_all_counted().0
    }

    fn kill_all_counted(&self) -> (bool, u64) {
        let deadline = std::time::Instant::now() + Self::TEARDOWN_BOUND;
        let mut quiet = 0_usize;
        let mut killed = 0_u64;
        let clean = loop {
            let mode = if quiet == 0 { ScanMode::Stop } else { ScanMode::Confirm };
            let Some(result) = self.scan(None, mode) else {
                break false;
            };
            if result.members.is_empty() {
                if result.uncertain {
                    quiet = 1;
                } else {
                    quiet += 1;
                    // The first empty stopping scan starts the count; the
                    // rest are confirmation scans.
                    if quiet > Self::QUIET_SCANS {
                        break true;
                    }
                }
                std::thread::sleep(Self::QUIET_SPACING);
            } else {
                quiet = 0;
                for key in result.members {
                    if self.still_member(key) {
                        // SAFETY: a stopped member whose identity was just
                        // rechecked; a stopped process cannot exit, so its
                        // pid cannot have been reused meanwhile.
                        unsafe { libc::kill(key.0, libc::SIGKILL) };
                        killed += 1;
                    }
                }
            }
            if std::time::Instant::now() >= deadline {
                break false;
            }
        };
        if !clean {
            self.state().survived = true;
        }
        (clean, killed)
    }

    /// Tests: a checker keyed on any directory the jail's profile may read
    /// and its parent may not (a root), to find a jail's processes after
    /// the jail and its sentinel are gone.
    #[cfg(test)]
    pub(crate) fn for_directory(directory: PathBuf) -> Option<Self> {
        Self::for_sentinel(directory)
    }

    /// Tests: every live member now, asking each same-user process afresh.
    #[cfg(test)]
    pub(crate) fn census(&self) -> Vec<libc::pid_t> {
        Self::all_pids()
            .unwrap_or_default()
            .into_iter()
            .filter(|pid| {
                *pid > 1
                    && matches!(probe(self.uid, *pid), Probe::Ours(_))
                    && self.membership(*pid) == Membership::Member
            })
            .collect()
    }

    /// Whether any teardown reported survivors.
    pub(crate) fn survived(&self) -> bool {
        self.state().survived
    }

    fn sweep_stale() -> GovernedJailSweep {
        use std::os::unix::fs::MetadataExt;

        let mut sweep = GovernedJailSweep::default();
        let Ok(directory) = fs::canonicalize(std::env::temp_dir()) else {
            return sweep;
        };
        let Ok(entries) = fs::read_dir(&directory) else {
            return sweep;
        };
        // SAFETY: `geteuid` has no preconditions and cannot fail.
        let uid = unsafe { libc::geteuid() };
        for entry in entries.flatten() {
            let path = entry.path();
            let named = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(MEMBER_SENTINEL_PREFIX));
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                continue;
            };
            if !named || !metadata.is_dir() || metadata.uid() != uid {
                continue;
            }
            let owner = fs::read_to_string(path.join(MEMBER_SENTINEL_OWNER)).ok().and_then(|text| {
                let mut parts = text.split_whitespace();
                Some((parts.next()?.parse::<libc::pid_t>().ok()?, parts.next()?.parse::<u64>().ok()?))
            });
            let stale = match owner {
                Some(owner) => match owner_is_gone(owner, probe(uid, owner.0)) {
                    Some(gone) => gone,
                    None => {
                        // The owner could not be read: it may be alive, so
                        // its jail is left alone.
                        sweep.sentinels_kept += 1;
                        continue;
                    },
                },
                None => metadata
                    .modified()
                    .ok()
                    .and_then(|modified| modified.elapsed().ok())
                    .is_some_and(|age| age > STALE_SENTINEL_WITHOUT_OWNER),
            };
            if !stale {
                continue;
            }
            let Some(members) = Self::for_sentinel(path.clone()) else {
                continue;
            };
            let (clean, killed) = members.kill_all_counted();
            sweep.members_killed += killed;
            if clean && fs::remove_dir_all(&path).is_ok() {
                sweep.sentinels_removed += 1;
            } else {
                sweep.sentinels_kept += 1;
            }
        }
        sweep
    }
}

/// Whether a sentinel's recorded owner is gone, given a probe of its pid:
/// `Some(true)` when that pid is gone, another user's or a zombie, or now a
/// different process (another start time); `Some(false)` when it is the
/// owner, alive; `None` when the probe failed, so nothing can be concluded.
#[cfg(target_os = "macos")]
fn owner_is_gone(owner: ProcessKey, probed: Probe) -> Option<bool> {
    match probed {
        Probe::NotOurs => Some(true),
        Probe::Ours(key) => Some(key != owner),
        Probe::Unknown => None,
    }
}

#[cfg(all(test, target_os = "macos"))]
pub(super) fn owner_is_gone_for_test(owner: (libc::pid_t, u64), probed: Option<Option<(libc::pid_t, u64)>>) -> Option<bool> {
    owner_is_gone(
        owner,
        match probed {
            None => Probe::Unknown,
            Some(None) => Probe::NotOurs,
            Some(Some(key)) => Probe::Ours(key),
        },
    )
}

#[cfg(target_os = "macos")]
impl Drop for MacosJailMembers {
    fn drop(&mut self) {
        if self.survived() {
            // Keep membership decidable: survivors stay recognizable by the
            // sentinel, and `sweep_stale_jail_members` can finish the job.
            if let Some(sentinel) = self.sentinel.lock().unwrap_or_else(|poison| poison.into_inner()).take() {
                let _ = sentinel.keep();
            }
        }
    }
}
