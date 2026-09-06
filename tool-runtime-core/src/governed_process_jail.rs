//! Fail-closed OS containment for governed non-interactive child processes.
//!
//! This module deliberately does not resolve executables, lower model input,
//! prepare credentials, authorize an effect, or retain output.  Those jobs
//! remain with the existing governed execution pipeline.  A jail is a
//! move-only launch profile which can only wrap the exact governed executable
//! snapshot (private copy or proven sealed-system bytes) produced by
//! `governed_execution_authority` and the private
//! invocation directory it owns.

use std::{
    error::Error,
    fmt, fs,
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use serde::Serialize;
use tempfile::{Builder, TempDir};

use crate::{
    governed_execution_authority::{
        GovernedExecutableSnapshot, GovernedWorkingDirectoryHandle, GovernedWorkingDirectoryRoot,
    },
    manifest::WorkingDirectoryMode,
};

pub const GOVERNED_PROCESS_JAIL_V1: &str = "tool-runtime.governed-process-jail.v1";
pub const MAX_GOVERNED_JAIL_PROFILE_BYTES: usize = 32 * 1024;
pub const MAX_GOVERNED_JAIL_FILES: u64 = 256;
pub const MAX_GOVERNED_JAIL_FILE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_GOVERNED_JAIL_TOTAL_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_GOVERNED_JAIL_PROCESSES: u64 = 16;
pub const MAX_GOVERNED_JAIL_OPEN_FILES: u64 = 64;
pub const MAX_GOVERNED_JAIL_WALL_SECONDS: u64 = 300;
pub const MAX_GOVERNED_JAIL_CPU_SECONDS: u64 = 300;
pub const MAX_GOVERNED_JAIL_MEMORY_BYTES: u64 = 1024 * 1024 * 1024;
pub const DEFAULT_GOVERNED_JAIL_MEMORY_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedProcessJailErrorCode {
    UnsupportedPlatform,
    LauncherUnavailable,
    PrivateWorkdirUnavailable,
    InvalidLimits,
    ProfileTooLarge,
    UnsafeHostPath,
}

/// Stable and value-free. Host paths and launcher diagnostics never cross the
/// product boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GovernedProcessJailError {
    pub code: GovernedProcessJailErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl GovernedProcessJailError {
    const fn new(
        code: GovernedProcessJailErrorCode,
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

impl fmt::Display for GovernedProcessJailError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for GovernedProcessJailError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedProcessJailPlatform {
    MacosSandboxExec,
    LinuxBubblewrap,
}

/// Resource ceilings which are additional to the governed runtime's existing
/// wall, stdout, stderr and RSS/address-space ceilings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GovernedProcessJailLimits {
    pub wall_seconds: u64,
    pub cpu_seconds: u64,
    pub max_memory_bytes: u64,
    pub max_processes: u64,
    pub max_open_files: u64,
    pub max_files: u64,
    pub max_file_bytes: u64,
    pub max_total_file_bytes: u64,
}

impl Default for GovernedProcessJailLimits {
    fn default() -> Self {
        Self {
            wall_seconds: 30,
            cpu_seconds: 30,
            max_memory_bytes: DEFAULT_GOVERNED_JAIL_MEMORY_BYTES,
            max_processes: MAX_GOVERNED_JAIL_PROCESSES,
            max_open_files: MAX_GOVERNED_JAIL_OPEN_FILES,
            max_files: MAX_GOVERNED_JAIL_FILES,
            max_file_bytes: MAX_GOVERNED_JAIL_FILE_BYTES,
            max_total_file_bytes: MAX_GOVERNED_JAIL_TOTAL_FILE_BYTES,
        }
    }
}

impl GovernedProcessJailLimits {
    fn validate(self) -> Result<Self, GovernedProcessJailError> {
        if self.wall_seconds == 0
            || self.cpu_seconds == 0
            || self.max_memory_bytes == 0
            || self.max_processes == 0
            || self.max_open_files < 3
            || self.max_files == 0
            || self.max_file_bytes == 0
            || self.max_total_file_bytes == 0
            || self.max_processes > MAX_GOVERNED_JAIL_PROCESSES
            || self.wall_seconds > MAX_GOVERNED_JAIL_WALL_SECONDS
            || self.cpu_seconds > MAX_GOVERNED_JAIL_CPU_SECONDS
            || self.max_memory_bytes > MAX_GOVERNED_JAIL_MEMORY_BYTES
            || self.max_open_files > MAX_GOVERNED_JAIL_OPEN_FILES
            || self.max_files > MAX_GOVERNED_JAIL_FILES
            || self.max_file_bytes > MAX_GOVERNED_JAIL_FILE_BYTES
            || self.max_total_file_bytes > MAX_GOVERNED_JAIL_TOTAL_FILE_BYTES
            || self.max_file_bytes > self.max_total_file_bytes
        {
            return Err(invalid_limits());
        }
        Ok(self)
    }
}

/// Safe capability projection for audit and admission. It intentionally says
/// exactly what is enforced and does not use a generic "sandboxed" boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GovernedProcessJailGuarantees {
    pub schema_version: &'static str,
    pub platform: GovernedProcessJailPlatform,
    pub direct_network_denied: bool,
    pub ambient_environment_denied: bool,
    pub host_writes_denied: bool,
    pub private_workdir: bool,
    pub exact_executable_snapshot: bool,
    pub wall_ceiling: bool,
    pub cpu_ceiling: bool,
    pub memory_ceiling: bool,
    pub process_ceiling: bool,
    pub file_ceiling: bool,
    pub output_ceiling: bool,
}

/// Value-free evidence attached to the existing governed execution receipt.
/// It identifies the actual host isolation class and all enforced ceilings,
/// without exposing launcher or workdir paths and without minting authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GovernedProcessJailAudit {
    pub guarantees: GovernedProcessJailGuarantees,
    pub limits: GovernedProcessJailLimits,
}

/// Move-only strict app profile. There is no constructor accepting a caller
/// path, executable, environment map, launcher argv, or sandbox profile.
pub struct GovernedProcessJail {
    platform: GovernedProcessJailPlatform,
    launcher: PathBuf,
    _workdir: TempDir,
    canonical_workdir: PathBuf,
    limits: GovernedProcessJailLimits,
}

impl GovernedProcessJail {
    /// Create a private invocation root and bind a supported OS launcher.
    /// Missing or unsupported containment is a pre-dispatch refusal; there is
    /// intentionally no pass-through command.
    pub fn strict_app(limits: GovernedProcessJailLimits) -> Result<Self, GovernedProcessJailError> {
        let limits = limits.validate()?;
        let (platform, launcher) = platform_launcher()?;
        let workdir = Builder::new()
            .prefix("magician-app-jail-")
            .tempdir()
            .map_err(|_| private_workdir_unavailable())?;
        #[cfg(unix)]
        fs::set_permissions(workdir.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| private_workdir_unavailable())?;
        let canonical_workdir = canonical_real_directory(workdir.path())?;
        Ok(Self {
            platform,
            launcher,
            _workdir: workdir,
            canonical_workdir,
            limits,
        })
    }

    pub fn schema_version(&self) -> &'static str {
        GOVERNED_PROCESS_JAIL_V1
    }

    pub fn guarantees(&self) -> GovernedProcessJailGuarantees {
        GovernedProcessJailGuarantees {
            schema_version: GOVERNED_PROCESS_JAIL_V1,
            platform: self.platform,
            direct_network_denied: true,
            ambient_environment_denied: true,
            host_writes_denied: true,
            private_workdir: true,
            exact_executable_snapshot: true,
            wall_ceiling: true,
            cpu_ceiling: true,
            memory_ceiling: true,
            // Linux combines the PID/user namespace with inherited
            // RLIMIT_NPROC. macOS has no per-invocation process namespace and
            // its RLIMIT_NPROC is user-wide, so that platform intentionally
            // reports only the sampled process watchdog rather than claiming
            // an exact hard ceiling.
            process_ceiling: matches!(self.platform, GovernedProcessJailPlatform::LinuxBubblewrap),
            file_ceiling: true,
            output_ceiling: true,
        }
    }

    pub fn limits(&self) -> GovernedProcessJailLimits {
        self.limits
    }

    pub fn audit(&self) -> GovernedProcessJailAudit {
        GovernedProcessJailAudit {
            guarantees: self.guarantees(),
            limits: self.limits,
        }
    }

    /// The caller receives only the existing move-only directory authority,
    /// never the host path. The jail retains the TempDir owner through process
    /// execution and removes it on every terminal/drop path.
    pub fn working_directory_root(
        &self,
        mode: WorkingDirectoryMode,
    ) -> Result<GovernedWorkingDirectoryRoot, GovernedProcessJailError> {
        GovernedWorkingDirectoryRoot::open(mode, &self.canonical_workdir)
            .map_err(|_| private_workdir_unavailable())
    }

    pub(crate) fn watch(&self) -> GovernedProcessJailWatch {
        GovernedProcessJailWatch {
            workdir: self.canonical_workdir.clone(),
            limits: self.limits,
        }
    }

    /// Require the governed invocation to be bound to the exact directory
    /// owned by this jail. This prevents a caller from pairing a strict launch
    /// profile with some other authorized-but-host-visible cwd, and prevents
    /// the launcher from silently ignoring rewritten cwd components.
    pub(crate) fn owns_workdir(
        &self,
        handle: &GovernedWorkingDirectoryHandle,
    ) -> Result<bool, GovernedProcessJailError> {
        #[cfg(unix)]
        {
            let path = handle
                .revalidated_child_cwd_path()
                .map_err(|_| private_workdir_unavailable())?;
            return Ok(path == self.canonical_workdir);
        }
        #[cfg(not(unix))]
        {
            let _ = handle;
            Ok(false)
        }
    }

    pub(crate) fn command(
        &self,
        executable: &GovernedExecutableSnapshot,
    ) -> Result<Command, GovernedProcessJailError> {
        validate_trusted_launcher(&self.launcher)?;
        validate_real_absolute_file(executable.as_path())?;
        validate_real_absolute_directory(&self.canonical_workdir)?;
        match self.platform {
            GovernedProcessJailPlatform::MacosSandboxExec => self.macos_command(executable),
            GovernedProcessJailPlatform::LinuxBubblewrap => self.linux_command(executable),
        }
    }

    pub(crate) fn harden_environment(&self, command: &mut Command) {
        // The governed coordinator has already called `env_clear` and inserted
        // only its compiled baseline plus authorized injections. These fixed
        // overlays remove ambient home/temp discovery without admitting a
        // caller-provided path. On Linux the same values are set inside bwrap;
        // setting them here also keeps the trusted launcher deterministic.
        command
            .env("HOME", &self.canonical_workdir)
            .env("PATH", &self.canonical_workdir)
            .env("TMPDIR", &self.canonical_workdir)
            .env("TMP", &self.canonical_workdir)
            .env("TEMP", &self.canonical_workdir)
            // Direct network is unavailable in this profile, so a portable
            // host trust-store path is unnecessary ambient host topology.
            .env_remove("SSL_CERT_FILE");
    }

    #[cfg(target_os = "macos")]
    fn macos_command(
        &self,
        snapshot: &GovernedExecutableSnapshot,
    ) -> Result<Command, GovernedProcessJailError> {
        let executable = sbpl_path(snapshot.as_path())?;
        let private_bundle_root = snapshot.private_bundle_root().map(sbpl_path).transpose()?;
        let workdir = sbpl_path(&self.canonical_workdir)?;
        let profile = macos_profile(&executable, private_bundle_root.as_deref(), &workdir)?;
        let mut command = Command::new(&self.launcher);
        command.arg("-p").arg(profile).arg(executable);
        Ok(command)
    }

    #[cfg(not(target_os = "macos"))]
    fn macos_command(
        &self,
        _snapshot: &GovernedExecutableSnapshot,
    ) -> Result<Command, GovernedProcessJailError> {
        Err(unsupported_platform())
    }

    #[cfg(target_os = "linux")]
    fn linux_command(
        &self,
        snapshot: &GovernedExecutableSnapshot,
    ) -> Result<Command, GovernedProcessJailError> {
        // Linux snapshots are always broker-owned copies. Never mount the
        // resolved executable's original parent: for `/usr/bin/tool` that
        // would expose and make executable every sibling host command. The
        // capability-bearing snapshot is the only source of a private bundle
        // root, and contains only the exact copied executable plus any
        // explicitly retained private adjacent runtime images.
        let private_bundle_root = snapshot
            .private_bundle_root()
            .ok_or_else(unsafe_host_path)?;
        self.linux_command_for_private_snapshot(snapshot.as_path(), private_bundle_root)
    }

    #[cfg(target_os = "linux")]
    fn linux_command_for_private_snapshot(
        &self,
        executable: &Path,
        private_bundle_root: &Path,
    ) -> Result<Command, GovernedProcessJailError> {
        validate_real_absolute_directory(private_bundle_root)?;
        validate_real_absolute_file(executable)?;
        let relative_executable =
            private_snapshot_relative_executable(executable, private_bundle_root)?;
        let name = executable.file_name().ok_or_else(unsafe_host_path)?;
        if name.is_empty() {
            return Err(unsafe_host_path());
        }
        let mut command = Command::new(&self.launcher);
        command.args([
            "--die-with-parent",
            "--unshare-all",
            "--tmpfs",
            "/",
            "--dir",
            "/app",
            "--dir",
            "/work",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
        ]);
        // Deliberately do not expose `/bin`, `/usr/bin` or `/usr/lib`: the exact
        // admitted executable is the only ordinary program mounted into the
        // jail. Only the base loader/library roots remain read-only because a
        // dynamically linked snapshot cannot start without them. A binary with
        // undeclared non-base adjacent resources fails closed.
        for root in ["/lib", "/lib64"] {
            if Path::new(root).exists() {
                command.arg("--ro-bind").arg(root).arg(root);
            }
        }
        command
            .arg("--ro-bind")
            .arg(private_bundle_root)
            .arg("/app")
            .arg("--bind")
            .arg(&self.canonical_workdir)
            .arg("/work")
            // The tmpfs root exists only to assemble the mount namespace. Make
            // it read-only after all mounts are installed so `/work` is the
            // sole writable host-visible or in-memory subtree.
            .arg("--remount-ro")
            .arg("/")
            .arg("--remount-ro")
            .arg("/proc")
            .arg("--remount-ro")
            .arg("/dev")
            .args([
                "--chdir", "/work", "--setenv", "HOME", "/work", "--setenv", "TMPDIR", "/work",
                "--setenv", "TMP", "/work", "--setenv", "TEMP", "/work", "--setenv", "PATH",
                "/app", "--",
            ]);
        let mut jailed_executable = PathBuf::from("/app");
        jailed_executable.push(relative_executable);
        command.arg(jailed_executable);
        Ok(command)
    }

    #[cfg(not(target_os = "linux"))]
    fn linux_command(
        &self,
        _snapshot: &GovernedExecutableSnapshot,
    ) -> Result<Command, GovernedProcessJailError> {
        Err(unsupported_platform())
    }
}

#[cfg(target_os = "macos")]
fn macos_profile(
    executable: &Path,
    private_bundle_root: Option<&Path>,
    workdir: &Path,
) -> Result<String, GovernedProcessJailError> {
    // Darwin's libc resolves the inherited working directory by reading the
    // root directory entry once during process startup. Denying that exact read
    // makes even `/usr/bin/true` abort before main. Keep this a literal data read
    // of `/`: it does not grant traversal, metadata, or any root subtree.
    let mut profile = format!(
        "(version 1)\n\
         (deny default)\n\
         (deny process-fork)\n\
         (allow process-exec (literal \"{}\"))\n\
         (allow file-read* (literal \"{}\"))\n\
         (allow file-read-data (literal \"/\"))\n\
         (allow sysctl-read)\n\
         (allow file-read* (subpath \"/System\"))\n\
         (allow file-read* (subpath \"/usr/lib\"))\n\
         (allow file-read* (subpath \"/Library/Apple/System\"))\n\
         (allow file-read* (subpath \"/private/var/db/dyld\"))\n\
         (allow file-read* (literal \"/dev/null\"))\n\
         (allow file-read* (literal \"/dev/random\"))\n\
         (allow file-read* (literal \"/dev/urandom\"))\n",
        sbpl_escape(executable)?,
        sbpl_escape(executable)?,
    );
    if let Some(root) = private_bundle_root {
        profile.push_str(&format!(
            "(allow file-read* (subpath \"{}\"))\n",
            sbpl_escape(root)?,
        ));
    }
    profile.push_str(&format!(
        "(allow file-read* (subpath \"{}\"))\n\
         (allow file-write* (subpath \"{}\"))\n",
        sbpl_escape(workdir)?,
        sbpl_escape(workdir)?,
    ));
    if profile.len() > MAX_GOVERNED_JAIL_PROFILE_BYTES {
        return Err(profile_too_large());
    }
    Ok(profile)
}

/// Bounded, cloneable observation state retained only while the jail owner is
/// alive. The path is never serializable and never leaves tool-runtime-core.
pub(crate) struct GovernedProcessJailWatch {
    workdir: PathBuf,
    limits: GovernedProcessJailLimits,
}

impl GovernedProcessJailWatch {
    pub(crate) fn limits(&self) -> GovernedProcessJailLimits {
        self.limits
    }

    pub(crate) fn workdir_within_limits(&self) -> Result<bool, ()> {
        let mut pending = vec![self.workdir.clone()];
        let mut files = 0_u64;
        let mut total = 0_u64;
        while let Some(directory) = pending.pop() {
            let entries = fs::read_dir(&directory).map_err(|_| ())?;
            for entry in entries {
                let entry = entry.map_err(|_| ())?;
                files = files.checked_add(1).ok_or(())?;
                if files > self.limits.max_files {
                    return Ok(false);
                }
                let metadata = fs::symlink_metadata(entry.path()).map_err(|_| ())?;
                if metadata.file_type().is_symlink() {
                    return Ok(false);
                }
                if metadata.is_dir() {
                    pending.push(entry.path());
                    continue;
                }
                if !metadata.is_file() || metadata.len() > self.limits.max_file_bytes {
                    return Ok(false);
                }
                total = total.checked_add(metadata.len()).ok_or(())?;
                if total > self.limits.max_total_file_bytes {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

#[cfg(target_os = "macos")]
fn platform_launcher() -> Result<(GovernedProcessJailPlatform, PathBuf), GovernedProcessJailError> {
    let launcher = PathBuf::from("/usr/bin/sandbox-exec");
    validate_trusted_launcher(&launcher)
        .map(|_| (GovernedProcessJailPlatform::MacosSandboxExec, launcher))
        .map_err(|_| launcher_unavailable())
}

#[cfg(target_os = "linux")]
fn platform_launcher() -> Result<(GovernedProcessJailPlatform, PathBuf), GovernedProcessJailError> {
    for candidate in ["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"] {
        let path = PathBuf::from(candidate);
        if validate_trusted_launcher(&path).is_ok() {
            return Ok((GovernedProcessJailPlatform::LinuxBubblewrap, path));
        }
    }
    Err(launcher_unavailable())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn platform_launcher() -> Result<(GovernedProcessJailPlatform, PathBuf), GovernedProcessJailError> {
    Err(unsupported_platform())
}

fn validate_real_absolute_file(path: &Path) -> Result<(), GovernedProcessJailError> {
    if !path.is_absolute() {
        return Err(unsafe_host_path());
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| unsafe_host_path())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(unsafe_host_path());
    }
    let canonical = fs::canonicalize(path).map_err(|_| unsafe_host_path())?;
    if canonical != path {
        return Err(unsafe_host_path());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn private_snapshot_relative_executable<'a>(
    executable: &'a Path,
    private_bundle_root: &Path,
) -> Result<&'a Path, GovernedProcessJailError> {
    let relative = executable
        .strip_prefix(private_bundle_root)
        .map_err(|_| unsafe_host_path())?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(unsafe_host_path());
    }
    Ok(relative)
}

fn validate_trusted_launcher(path: &Path) -> Result<(), GovernedProcessJailError> {
    validate_real_absolute_file(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let mut current = Some(path);
        while let Some(component) = current {
            let metadata = fs::symlink_metadata(component).map_err(|_| unsafe_host_path())?;
            if metadata.file_type().is_symlink()
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
            {
                return Err(unsafe_host_path());
            }
            current = component.parent();
        }
    }
    Ok(())
}

fn validate_real_absolute_directory(path: &Path) -> Result<(), GovernedProcessJailError> {
    if !path.is_absolute() {
        return Err(unsafe_host_path());
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| unsafe_host_path())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(unsafe_host_path());
    }
    let canonical = fs::canonicalize(path).map_err(|_| unsafe_host_path())?;
    if canonical != path {
        return Err(unsafe_host_path());
    }
    Ok(())
}

fn canonical_real_directory(path: &Path) -> Result<PathBuf, GovernedProcessJailError> {
    if !path.is_absolute() {
        return Err(unsafe_host_path());
    }
    let before = fs::symlink_metadata(path).map_err(|_| unsafe_host_path())?;
    if before.file_type().is_symlink() || !before.is_dir() {
        return Err(unsafe_host_path());
    }
    let canonical = fs::canonicalize(path).map_err(|_| unsafe_host_path())?;
    let after = fs::symlink_metadata(&canonical).map_err(|_| unsafe_host_path())?;
    if after.file_type().is_symlink() || !after.is_dir() {
        return Err(unsafe_host_path());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(unsafe_host_path());
        }
    }
    Ok(canonical)
}

#[cfg(target_os = "macos")]
fn sbpl_path(path: &Path) -> Result<PathBuf, GovernedProcessJailError> {
    let canonical = fs::canonicalize(path).map_err(|_| unsafe_host_path())?;
    sbpl_escape(&canonical)?;
    Ok(canonical)
}

#[cfg(target_os = "macos")]
fn sbpl_escape(path: &Path) -> Result<String, GovernedProcessJailError> {
    let value = path.to_str().ok_or_else(unsafe_host_path)?;
    if value.as_bytes().contains(&0) || value.contains('\n') || value.contains('\r') {
        return Err(unsafe_host_path());
    }
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            other => escaped.push(other),
        }
    }
    Ok(escaped)
}

const fn unsupported_platform() -> GovernedProcessJailError {
    GovernedProcessJailError::new(
        GovernedProcessJailErrorCode::UnsupportedPlatform,
        "jail.platform",
        "this host has no supported strict process jail",
    )
}

const fn launcher_unavailable() -> GovernedProcessJailError {
    GovernedProcessJailError::new(
        GovernedProcessJailErrorCode::LauncherUnavailable,
        "jail.launcher",
        "the strict process-jail launcher is unavailable",
    )
}

const fn private_workdir_unavailable() -> GovernedProcessJailError {
    GovernedProcessJailError::new(
        GovernedProcessJailErrorCode::PrivateWorkdirUnavailable,
        "jail.workdir",
        "a private invocation workdir could not be created",
    )
}

const fn invalid_limits() -> GovernedProcessJailError {
    GovernedProcessJailError::new(
        GovernedProcessJailErrorCode::InvalidLimits,
        "jail.limits",
        "the process-jail resource ceilings are invalid",
    )
}

const fn profile_too_large() -> GovernedProcessJailError {
    GovernedProcessJailError::new(
        GovernedProcessJailErrorCode::ProfileTooLarge,
        "jail.profile",
        "the host-built process-jail profile exceeds its byte ceiling",
    )
}

const fn unsafe_host_path() -> GovernedProcessJailError {
    GovernedProcessJailError::new(
        GovernedProcessJailErrorCode::UnsafeHostPath,
        "jail.host_path",
        "a broker-owned process-jail path is unsafe or changed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_not_impl_any;

    #[test]
    fn limits_refuse_zero_and_widening() {
        let mut limits = GovernedProcessJailLimits::default();
        limits.max_processes = MAX_GOVERNED_JAIL_PROCESSES + 1;
        assert_eq!(
            limits.validate().unwrap_err().code,
            GovernedProcessJailErrorCode::InvalidLimits
        );
        limits = GovernedProcessJailLimits::default();
        limits.max_memory_bytes = MAX_GOVERNED_JAIL_MEMORY_BYTES + 1;
        assert_eq!(
            limits.validate().unwrap_err().code,
            GovernedProcessJailErrorCode::InvalidLimits
        );
        limits = GovernedProcessJailLimits::default();
        limits.wall_seconds = MAX_GOVERNED_JAIL_WALL_SECONDS + 1;
        assert_eq!(
            limits.validate().unwrap_err().code,
            GovernedProcessJailErrorCode::InvalidLimits
        );
        limits = GovernedProcessJailLimits::default();
        limits.cpu_seconds = 0;
        assert_eq!(
            limits.validate().unwrap_err().code,
            GovernedProcessJailErrorCode::InvalidLimits
        );
    }

    #[test]
    fn workdir_scanner_refuses_symlinks_and_file_overflow() {
        let directory = tempfile::tempdir().unwrap();
        let watch = GovernedProcessJailWatch {
            workdir: directory.path().to_path_buf(),
            limits: GovernedProcessJailLimits {
                max_files: 1,
                max_file_bytes: 2,
                max_total_file_bytes: 2,
                ..GovernedProcessJailLimits::default()
            },
        };
        fs::write(directory.path().join("one"), b"12").unwrap();
        assert_eq!(watch.workdir_within_limits(), Ok(true));
        fs::write(directory.path().join("two"), b"x").unwrap();
        assert_eq!(watch.workdir_within_limits(), Ok(false));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_profile_is_deny_default_and_exec_literal_only() {
        let executable = Path::new("/private/tmp/exact-tool");
        let workdir = Path::new("/private/tmp/private-work");
        let profile = macos_profile(executable, None, workdir).unwrap();
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(deny process-fork)"));
        assert!(profile.contains("(allow process-exec (literal \"/private/tmp/exact-tool\"))"));
        assert!(!profile.contains("(allow default)"));
        assert!(!profile.contains("mach-lookup"));
        assert!(!profile.contains("(subpath \"/usr/bin\")"));
        assert!(profile.contains("(allow file-read-data (literal \"/\"))"));
        assert!(!profile.contains("(allow file-read* (subpath \"/\"))"));
        assert_eq!(profile.matches("(allow process-exec").count(), 1);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_reused_system_executable_does_not_grant_its_parent() {
        let profile = macos_profile(
            Path::new("/usr/bin/tool"),
            None,
            Path::new("/private/tmp/private-work"),
        )
        .unwrap();
        assert!(profile.contains("(allow process-exec (literal \"/usr/bin/tool\"))"));
        assert!(profile.contains("(allow file-read* (literal \"/usr/bin/tool\"))"));
        assert!(!profile.contains("(subpath \"/usr/bin\")"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_profile_escapes_hostile_executable_literals() {
        let profile = macos_profile(
            Path::new("/private/tmp/evil\") (allow default) (\""),
            None,
            Path::new("/private/tmp/private-work"),
        )
        .unwrap();
        assert!(!profile.lines().any(|line| line.trim() == "(allow default)"));
        assert!(profile.contains("evil\\\") (allow default) (\\\""));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_profile_reads_only_a_proven_private_snapshot_bundle() {
        let profile = macos_profile(
            Path::new("/private/tmp/governed-bundle/bin/tool"),
            Some(Path::new("/private/tmp/governed-bundle")),
            Path::new("/private/tmp/private-work"),
        )
        .unwrap();
        assert!(profile.contains("(allow file-read* (subpath \"/private/tmp/governed-bundle\"))"));
        assert!(!profile.contains("(subpath \"/usr/bin\")"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_profile_does_not_mount_host_command_directories() {
        use std::ffi::OsStr;
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let canonical_workdir = fs::canonicalize(directory.path()).unwrap();
        let jail = GovernedProcessJail {
            platform: GovernedProcessJailPlatform::LinuxBubblewrap,
            launcher: PathBuf::from("/usr/bin/bwrap"),
            canonical_workdir,
            _workdir: directory,
            limits: GovernedProcessJailLimits::default(),
        };
        let snapshot = tempfile::tempdir().unwrap();
        let snapshot_root = fs::canonicalize(snapshot.path()).unwrap();
        let executable = snapshot_root.join("tool");
        fs::write(&executable, b"exact executable bytes").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let command = jail
            .linux_command_for_private_snapshot(&executable, &snapshot_root)
            .unwrap();
        let args = command.get_args().collect::<Vec<_>>();
        assert!(args
            .windows(2)
            .any(|pair| { pair == [OsStr::new("--ro-bind"), snapshot_root.as_os_str()] }));
        assert!(!args.windows(2).any(|pair| {
            pair == [OsStr::new("--ro-bind"), OsStr::new("/usr")]
                || pair == [OsStr::new("--ro-bind"), OsStr::new("/usr/bin")]
                || pair == [OsStr::new("--ro-bind"), OsStr::new("/bin")]
        }));
        assert!(!args.iter().any(|argument| *argument == OsStr::new("/tmp")));
        assert!(args
            .windows(2)
            .any(|pair| { pair == [OsStr::new("--remount-ro"), OsStr::new("/")] }));
        assert_eq!(args.last().copied(), Some(OsStr::new("/app/tool")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_rejects_reused_system_executable_without_a_private_snapshot() {
        assert!(private_snapshot_relative_executable(
            Path::new("/usr/bin/tool"),
            Path::new("/private/governed-executable")
        )
        .is_err());
    }

    assert_not_impl_any!(GovernedProcessJail: Clone, fmt::Debug, Serialize);
}
