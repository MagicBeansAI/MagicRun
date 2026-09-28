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
pub const GOVERNED_JAIL_EXEC_ROOTS_ENVIRONMENT: [(&str, &str); 2] =
    [("PYTHONNOUSERSITE", "1"), ("PYTHONDONTWRITEBYTECODE", "1")];
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

    /// Keep `relative` (a path below the root, plain components only)
    /// unreadable even though the root is granted. It need not exist.
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

/// How an excluded path is masked in a Linux jail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LinuxMask {
    /// A read-only empty tmpfs over the directory.
    Directory,
    /// `/dev/null` bound read-only over the file.
    File,
}

impl GovernedJailExecRoots {
    /// Validate a declaration against this host.
    ///
    /// Each root is canonicalized and must be an existing directory, at most
    /// [`MAX_GOVERNED_JAIL_EXEC_ROOT_PATH_BYTES`] long; not `/`, not the home
    /// directory or one of its ancestors, not overlapping another root or a
    /// path of the jail's own machinery. The root must be owned by root or
    /// this user and not group/other-writable; every ancestor must be owned
    /// by root or this user and not group/other-writable, except a
    /// root-owned sticky directory such as `/tmp`. Exclusions are relative,
    /// plain components; one that exists must not be a symlink or sit below
    /// one. `PATH` entries are canonicalized, must lie inside a root outside
    /// its exclusions, and may not contain `:`. The tree under a root is
    /// not walked: its contents are trusted as installed.
    pub fn new(
        roots: impl IntoIterator<Item = GovernedJailExecRoot>,
        search_path: impl IntoIterator<Item = PathBuf>,
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
        if let Some(home) = std::env::var_os("HOME")
            .filter(|home| !home.is_empty())
            .and_then(|home| fs::canonicalize(home).ok())
        {
            if declaration.roots.iter().any(|root| home.starts_with(&root.path)) {
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
                match fs::symlink_metadata(&excluded) {
                    Ok(_) => {
                        if fs::canonicalize(&excluded).map_err(|_| invalid_exec_roots())? != excluded {
                            return Err(invalid_exec_roots());
                        }
                    },
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        // Absent now. Below a symlinked component it could
                        // still resolve elsewhere: every existing ancestor up
                        // to the root must be a real directory.
                        let mut current = excluded.parent();
                        while let Some(ancestor) = current {
                            if ancestor == root.path {
                                break;
                            }
                            if let Ok(metadata) = fs::symlink_metadata(ancestor) {
                                if !metadata.is_dir() {
                                    return Err(invalid_exec_roots());
                                }
                            }
                            current = ancestor.parent();
                        }
                    },
                    Err(_) => return Err(invalid_exec_roots()),
                }
            }
        }
        for entry in &self.search_path {
            validate_real_absolute_directory(entry).map_err(|_| invalid_exec_roots())?;
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

    /// Linux: how each excluded path that exists at launch is masked. An
    /// absent one is skipped (there is nothing to read; the jail cannot
    /// create it, the roots being read-only).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(super) fn linux_masks(&self) -> Result<Vec<(PathBuf, LinuxMask)>, GovernedProcessJailError> {
        let mut masks = Vec::new();
        for root in &self.roots {
            for excluded in root.excluded_paths() {
                let metadata = match fs::symlink_metadata(&excluded) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(_) => return Err(invalid_exec_roots()),
                };
                let kind = if metadata.file_type().is_dir() {
                    LinuxMask::Directory
                } else if metadata.file_type().is_file() {
                    LinuxMask::File
                } else {
                    return Err(invalid_exec_roots());
                };
                masks.push((excluded, kind));
            }
        }
        Ok(masks)
    }

    /// The template masks of the profile identity: every exclusion rendered
    /// as a directory, independent of what exists on a host.
    pub(super) fn template_masks(&self) -> Vec<(PathBuf, LinuxMask)> {
        self.roots
            .iter()
            .flat_map(GovernedJailExecRoot::excluded_paths)
            .map(|excluded| (excluded, LinuxMask::Directory))
            .collect()
    }

    /// macOS allowances of this mode, placed after the strict base profile:
    /// fork and signals inside the sandbox, `/dev/null` writes, the system
    /// exec paths, the roots (read, exec, map executable) and metadata of
    /// every ancestor of a root or the workdir (path resolution such as
    /// Node's `realpath` `lstat`s each component; no listing is granted).
    pub(super) fn macos_allow_rules(&self, workdir: &Path) -> Result<String, GovernedProcessJailError> {
        let mut rules = String::from(
            "(allow process-fork)\n\
             (allow signal (target same-sandbox))\n\
             (allow file-write-data (literal \"/dev/null\"))\n",
        );
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

/// macOS: the processes of one exec-roots jail, wherever they are.
///
/// Exec roots allow fork, and macOS has no pid namespace: a jailed process
/// can `setsid`/`setpgid` out of the launcher's process group, which the
/// watchdog samples and teardown signals. Such a process keeps its sandbox,
/// so membership is decided by the sandbox itself with `sandbox_check`: a
/// process of this user is a member when it is sandboxed, may read its
/// jail's unique workdir, and may not read that workdir's parent (which no
/// jail profile grants). An unsandboxed process, a process of another jail
/// or an ordinary app sandbox fails one of the three. `sandbox_check` is
/// exported by `libsystem_sandbox` (listed in the SDK's stub) but has no
/// public header.
#[cfg(target_os = "macos")]
pub(crate) struct MacosJailMembers {
    inside: std::ffi::CString,
    outside: std::ffi::CString,
    uid: libc::uid_t,
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

#[cfg(target_os = "macos")]
impl MacosJailMembers {
    /// Most kill rounds at teardown; a member forking while it is killed
    /// needs another round.
    const KILL_ROUNDS: usize = 64;

    pub(crate) fn new(workdir: &Path) -> Option<Self> {
        use std::os::unix::ffi::OsStrExt;

        let parent = workdir.parent()?;
        Some(Self {
            inside: std::ffi::CString::new(workdir.as_os_str().as_bytes()).ok()?,
            outside: std::ffi::CString::new(parent.as_os_str().as_bytes()).ok()?,
            // SAFETY: `geteuid` has no preconditions and cannot fail.
            uid: unsafe { libc::geteuid() },
        })
    }

    /// Every live member. `None` when the process list cannot be read.
    pub(crate) fn pids(&self) -> Option<Vec<libc::pid_t>> {
        // SAFETY: a null buffer asks only for the current count.
        let estimate = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
        let capacity = usize::try_from(estimate).ok()?.checked_add(256)?;
        let mut pids = vec![0 as libc::pid_t; capacity];
        let bytes = libc::c_int::try_from(capacity.checked_mul(std::mem::size_of::<libc::pid_t>())?).ok()?;
        // SAFETY: `pids` is a live writable buffer of `bytes` bytes.
        let listed = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
        let listed = usize::try_from(listed).ok()?.min(capacity);
        Some(
            pids[..listed]
                .iter()
                .copied()
                .filter(|pid| *pid > 1 && self.is_member(*pid))
                .collect(),
        )
    }

    fn is_member(&self, pid: libc::pid_t) -> bool {
        use sandbox_ffi::*;

        let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: PROC_PIDTBSDINFO writes at most `size` bytes into `info`.
        let written = unsafe {
            libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, info.as_mut_ptr().cast(), size)
        };
        // SAFETY: the kernel filled the whole structure when it wrote `size`.
        if written != size || unsafe { info.assume_init() }.pbi_uid != self.uid {
            return false;
        }
        // SAFETY: `sandbox_check` reads the NUL-terminated operation and
        // path (live `CString`s) and the pid; it writes nothing of ours.
        unsafe {
            let flags = SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT;
            let operation = c"file-read-data".as_ptr();
            sandbox_check(pid, std::ptr::null(), SANDBOX_FILTER_NONE) == 1
                && sandbox_check(pid, operation, flags, self.inside.as_ptr()) == 0
                && sandbox_check(pid, operation, flags, self.outside.as_ptr()) == 1
        }
    }

    /// SIGKILL every member until none is left (bounded).
    pub(crate) fn kill_all(&self) {
        for _ in 0..Self::KILL_ROUNDS {
            let Some(pids) = self.pids() else {
                return;
            };
            if pids.is_empty() {
                return;
            }
            for pid in pids {
                // SAFETY: a signal to a live member of this user's jail.
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
}
