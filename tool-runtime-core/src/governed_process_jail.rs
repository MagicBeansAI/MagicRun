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
    ffi::OsString,
    fmt, fs,
    num::NonZeroU16,
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

/// Schema of the opt-in brokered-egress mode. The strict profile keeps
/// [`GOVERNED_PROCESS_JAIL_V1`]; a jail built with
/// [`GovernedProcessJail::strict_app_with_brokered_egress`] reports this one.
pub const GOVERNED_PROCESS_JAIL_BROKERED_EGRESS_V1: &str =
    "tool-runtime.governed-process-jail.brokered-egress.v1";
/// Loopback port the Linux in-jail forwarder listens on inside the jail's own
/// network namespace. It is unreachable from the host and needs no allocation.
pub const GOVERNED_JAIL_EGRESS_LINUX_PROXY_PORT: u16 = 3128;
/// Fixed, root-owned install locations searched for the Linux in-jail egress
/// forwarder (`magicrun-jail-egress-forwarder`). There is no caller path.
pub const GOVERNED_JAIL_EGRESS_FORWARDER_PATHS: [&str; 2] = [
    "/usr/libexec/magicrun/magicrun-jail-egress-forwarder",
    "/usr/local/libexec/magicrun/magicrun-jail-egress-forwarder",
];
/// Proxy variables set in the jailed child environment, upper and lower case,
/// so that ordinary HTTP clients route through the broker. `NO_PROXY` and
/// `no_proxy` are set empty so no destination bypasses it.
pub const GOVERNED_JAIL_EGRESS_PROXY_VARIABLES: [&str; 6] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
];
pub const GOVERNED_JAIL_EGRESS_NO_PROXY_VARIABLES: [&str; 2] = ["NO_PROXY", "no_proxy"];
/// argv marker of the in-jail forwarder protocol. Bumped with any change to
/// its argument layout.
pub const GOVERNED_JAIL_EGRESS_FORWARDER_PROTOCOL_V1: &str = "--magicrun-jail-egress-forwarder-v1";
const MAX_GOVERNED_JAIL_FORWARDER_BYTES: u64 = 64 * 1024 * 1024;
const LINUX_JAIL_EGRESS_FORWARDER: &str = "/run/magicrun/egress-forwarder";
const LINUX_JAIL_EGRESS_SOCKET: &str = "/run/magicrun/egress.sock";
const LINUX_JAIL_TRUST_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";
const LINUX_HOST_TRUST_BUNDLES: [&str; 3] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
];
const MACOS_TRUST_DIRECTORY: &str = "/private/etc/ssl";
const MACOS_TRUST_BUNDLE: &str = "/private/etc/ssl/cert.pem";

/// Schema of the interpreter evidence in [`GovernedProcessJailAudit`]. The
/// jail's own schema stays that of its network mode.
pub const GOVERNED_JAIL_INTERPRETER_V1: &str = "tool-runtime.governed-process-jail.interpreter.v1";
/// Fixed interpreter flags placed before the script snapshot: `-I` isolated
/// mode (no `PYTHON*` environment, no user site, no script directory or cwd
/// on `sys.path`), `-S` no `site` import, `-B` no bytecode writes.
pub const GOVERNED_JAIL_PYTHON3_FLAGS: [&str; 3] = ["-I", "-S", "-B"];
/// Fixed macOS discovery candidates, in order. `/usr/bin/python3` is
/// deliberately absent: it is an `xcrun` shim that needs fork and exec. The
/// Xcode.app framework is absent too: `/Applications` is `root:admin` 0775 on
/// stock macOS, so it can never pass the trust checks. A python.org framework
/// passes only once it is root-owned and not group/other-writable
/// (`chown -R root:wheel` and `chmod -R go-w` its `Python.framework`); the
/// installer leaves it admin-writable.
pub const GOVERNED_JAIL_MACOS_PYTHON3_CANDIDATES: [&str; 2] = [
    "/Library/Frameworks/Python.framework/Versions/Current/bin/python3",
    "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/Current/bin/python3",
];
/// Fixed Linux discovery candidate.
pub const GOVERNED_JAIL_LINUX_PYTHON3_CANDIDATES: [&str; 1] = ["/usr/bin/python3"];
const MAX_GOVERNED_JAIL_INTERPRETER_IMAGE_BYTES: u64 = 256 * 1024 * 1024;
/// Linux: the smallest `max_open_files` a brokered jail accepts, so the
/// in-jail forwarder can hold stdio, its listener, one relay and the spawn
/// pipe. The forwarder clamps its concurrent relays to what the limit allows.
pub const MIN_GOVERNED_JAIL_BROKERED_OPEN_FILES: u64 =
    egress_forwarder::FORWARDER_MIN_OPEN_FILES;
#[cfg_attr(not(unix), allow(dead_code))]
const MAX_GOVERNED_JAIL_INTERPRETER_TREE_ENTRIES: usize = 200_000;

pub mod egress_forwarder;
#[cfg(test)]
mod egress_tests;
#[cfg(all(test, unix))]
mod interpreter_tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedProcessJailErrorCode {
    UnsupportedPlatform,
    LauncherUnavailable,
    PrivateWorkdirUnavailable,
    InvalidLimits,
    ProfileTooLarge,
    UnsafeHostPath,
    /// The requested broker endpoint kind cannot be reached from this host's
    /// jail (macOS takes only loopback TCP; Linux only a unix socket).
    UnsupportedEgressBroker,
    /// The broker endpoint is missing, not a socket, or not owned by this user.
    EgressBrokerUnavailable,
    /// Linux only: no trusted in-jail egress forwarder is installed.
    EgressForwarderUnavailable,
    /// No trusted interpreter is installed, a pinned interpreter changed, or
    /// the jail cannot take one.
    InterpreterUnavailable,
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

/// Network policy of a jail. `Denied` is the strict profile. `BrokeredEgress`
/// admits exactly one host-owned HTTP CONNECT broker and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedProcessJailNetwork {
    Denied,
    BrokeredEgress,
}

/// The host-owned egress broker a brokered jail may reach. The broker is an
/// HTTP CONNECT proxy owned by the caller; it — not the jail — enforces the
/// destination allowlist, resolves names, refuses private addresses and
/// meters bytes. The jail only guarantees it is the sole reachable endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernedEgressBrokerEndpoint {
    /// macOS: a TCP listener on the host loopback interface. The sandbox
    /// profile admits outbound IPv4 TCP to `localhost:<port>` only.
    LoopbackTcp { port: NonZeroU16 },
    /// Linux: a unix stream socket owned by the calling user. It is
    /// bind-mounted read-only into the jail and relayed from
    /// `127.0.0.1:GOVERNED_JAIL_EGRESS_LINUX_PROXY_PORT` inside the jail's
    /// isolated network namespace by the trusted in-jail forwarder.
    UnixSocket { path: PathBuf },
}

impl GovernedEgressBrokerEndpoint {
    pub fn kind(&self) -> GovernedEgressBrokerKind {
        match self {
            Self::LoopbackTcp { .. } => GovernedEgressBrokerKind::LoopbackTcp,
            Self::UnixSocket { .. } => GovernedEgressBrokerKind::UnixSocket,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedEgressBrokerKind {
    LoopbackTcp,
    UnixSocket,
}

/// A BLAKE3 digest, serialized as `blake3:<hex>`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct GovernedProcessJailDigest([u8; 32]);

impl GovernedProcessJailDigest {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for GovernedProcessJailDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "blake3:{}", blake3::Hash::from(self.0).to_hex())
    }
}

impl fmt::Debug for GovernedProcessJailDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Serialize for GovernedProcessJailDigest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Value-free evidence of the brokered-egress mode. Present in
/// [`GovernedProcessJailAudit`] only for a brokered jail, so the strict audit
/// serializes exactly as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GovernedProcessJailEgressAudit {
    pub schema_version: &'static str,
    pub broker: GovernedEgressBrokerKind,
    /// Host loopback port of a `LoopbackTcp` broker; `None` for a unix socket.
    pub broker_port: Option<u16>,
    /// Port the child's proxy variables name on `127.0.0.1`.
    pub proxy_port: u16,
    pub proxy_environment: bool,
    pub dns_denied: bool,
    pub non_broker_network_denied: bool,
    pub trust_bundle_exposed: bool,
    /// Linux: BLAKE3 of the installed forwarder executable bound into the jail.
    pub forwarder_digest: Option<GovernedProcessJailDigest>,
    /// Endpoint-independent launch-template identity; equal to
    /// [`governed_process_jail_profile_identity`] for this platform and mode.
    pub profile_identity: GovernedProcessJailDigest,
    /// Identity of this concrete binding: profile identity, broker kind and
    /// port, a digest of the socket path, forwarder digest and trust exposure.
    pub binding_identity: GovernedProcessJailDigest,
}

/// Interpreter family a jail can pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedJailInterpreterKind {
    Python3,
}

/// `major.minor` of a pinned interpreter, serialized as `"3.9"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GovernedJailInterpreterVersion {
    pub major: u16,
    pub minor: u16,
}

impl fmt::Display for GovernedJailInterpreterVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}", self.major, self.minor)
    }
}

impl Serialize for GovernedJailInterpreterVersion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Value-free evidence of the interpreter mode. Present in
/// [`GovernedProcessJailAudit`] only for a jail built
/// [`GovernedProcessJail::with_interpreter`], so other audits serialize
/// exactly as before. Host paths are never included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GovernedJailInterpreterAudit {
    pub schema_version: &'static str,
    pub kind: GovernedJailInterpreterKind,
    pub version: GovernedJailInterpreterVersion,
    /// BLAKE3 over the interpreter executable and its pinned images (macOS:
    /// the framework library; Linux: a shared `libpython3.N.so`); rechecked
    /// immediately before every launch.
    pub digest: GovernedProcessJailDigest,
    /// Launch hygiene, not containment: the fixed flags placed between the
    /// interpreter and the script snapshot. A script can re-exec the
    /// interpreter without them; it stays inside the same profile.
    pub launch_flags: [&'static str; 3],
    /// Launch hygiene, not containment: `-I` disables the user site at
    /// launch. The host user site is never readable (the jail's `HOME` is its
    /// private workdir), but a re-exec without `-I` can import from a user
    /// site the script itself writes into that workdir.
    pub launch_user_site_disabled: bool,
    /// Enforced by the profile. macOS: only the interpreter literal may be
    /// exec'd, and workdir files cannot be `dlopen`ed or mapped `PROT_EXEC`
    /// (in-process code via `mprotect`/`ctypes` is not prevented). Linux:
    /// `false`; bubblewrap has no exec control and `/work` is not `noexec`.
    pub script_exec_denied: bool,
    /// Enforced by the profile. macOS: the stdlib `site-packages` subtree is
    /// denied. Linux: `false`; it is off `sys.path` (`-S`) but readable.
    pub site_packages_read_denied: bool,
    /// Identity of this platform, network and interpreter kind/version;
    /// equal to [`governed_process_jail_interpreter_profile_identity`].
    pub profile_identity: GovernedProcessJailDigest,
}

/// A validated, pinned interpreter. It can only be produced by fixed host
/// discovery ([`Self::python3_for_host`]); there is no constructor taking a
/// caller path. The executable, its pinned images and every library root are
/// root-owned, not group/other-writable, canonical and free of symlink swaps,
/// like a trusted launcher; library trees are walked entry by entry. Paths
/// stay private to tool-runtime-core.
pub struct GovernedJailInterpreter {
    platform: GovernedProcessJailPlatform,
    kind: GovernedJailInterpreterKind,
    version: GovernedJailInterpreterVersion,
    /// Canonical real executable the jail execs (macOS: the framework's
    /// `Resources/Python.app/Contents/MacOS/Python`, not the `bin` stub that
    /// would re-exec it).
    executable: PathBuf,
    /// Further pinned binaries covered by the digest, read-only literals.
    images: Vec<PathBuf>,
    /// Read-only subtrees (stdlib, extension modules, bundled libraries).
    library_roots: Vec<PathBuf>,
    /// Subtrees of the library roots denied again (macOS `site-packages`).
    denied_roots: Vec<PathBuf>,
    digest: GovernedProcessJailDigest,
}

impl GovernedJailInterpreter {
    /// Discover the host's trusted Python 3 at fixed locations.
    ///
    /// macOS tries [`GOVERNED_JAIL_MACOS_PYTHON3_CANDIDATES`] in order and
    /// takes the first that passes every trust check; Linux takes
    /// [`GOVERNED_JAIL_LINUX_PYTHON3_CANDIDATES`]. Other hosts are refused.
    pub fn python3_for_host() -> Result<Self, GovernedProcessJailError> {
        #[cfg(target_os = "macos")]
        {
            python3_from_candidates(
                GovernedProcessJailPlatform::MacosSandboxExec,
                &GOVERNED_JAIL_MACOS_PYTHON3_CANDIDATES.map(Path::new),
            )
        }
        #[cfg(target_os = "linux")]
        {
            python3_from_candidates(
                GovernedProcessJailPlatform::LinuxBubblewrap,
                &GOVERNED_JAIL_LINUX_PYTHON3_CANDIDATES.map(Path::new),
            )
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Err(unsupported_platform())
        }
    }

    pub fn kind(&self) -> GovernedJailInterpreterKind {
        self.kind
    }

    pub fn version(&self) -> GovernedJailInterpreterVersion {
        self.version
    }

    pub fn digest(&self) -> GovernedProcessJailDigest {
        self.digest
    }

    /// Re-run every trust check and recompute the digest. Called when a jail
    /// takes the interpreter and again immediately before each launch.
    fn revalidate(&self) -> Result<(), GovernedProcessJailError> {
        validate_trusted_launcher(&self.executable).map_err(|_| interpreter_unavailable())?;
        for image in &self.images {
            validate_trusted_launcher(image).map_err(|_| interpreter_unavailable())?;
        }
        for root in &self.library_roots {
            validate_trusted_tree(root, &self.denied_roots)?;
        }
        if interpreter_digest(&self.executable, &self.images)? != self.digest {
            return Err(interpreter_unavailable());
        }
        Ok(())
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress: Option<GovernedProcessJailEgressAudit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<GovernedJailInterpreterAudit>,
}

/// Move-only strict app profile. There is no constructor accepting a caller
/// executable, environment map, launcher argv, or sandbox profile. The only
/// caller-supplied host resources are the explicitly opted-in egress broker
/// and a discovered, pinned interpreter.
pub struct GovernedProcessJail {
    platform: GovernedProcessJailPlatform,
    launcher: PathBuf,
    _workdir: TempDir,
    canonical_workdir: PathBuf,
    limits: GovernedProcessJailLimits,
    egress: Option<BrokeredEgress>,
    interpreter: Option<GovernedJailInterpreter>,
}

/// Host-validated binding of the brokered-egress mode.
struct BrokeredEgress {
    endpoint: GovernedEgressBrokerEndpoint,
    /// Linux: the trusted forwarder executable and its digest.
    forwarder: Option<(PathBuf, GovernedProcessJailDigest)>,
    /// Canonical host trust bundle exposed read-only, if one was found.
    trust_bundle: Option<PathBuf>,
}

impl BrokeredEgress {
    fn proxy_port(&self) -> u16 {
        match &self.endpoint {
            GovernedEgressBrokerEndpoint::LoopbackTcp { port } => port.get(),
            GovernedEgressBrokerEndpoint::UnixSocket { .. } => GOVERNED_JAIL_EGRESS_LINUX_PROXY_PORT,
        }
    }

    fn proxy_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.proxy_port())
    }

    /// The trust-bundle path as the child sees it.
    fn jailed_trust_bundle(&self, platform: GovernedProcessJailPlatform) -> Option<&Path> {
        self.trust_bundle.as_ref().map(|host| match platform {
            GovernedProcessJailPlatform::MacosSandboxExec => host.as_path(),
            GovernedProcessJailPlatform::LinuxBubblewrap => Path::new(LINUX_JAIL_TRUST_BUNDLE),
        })
    }
}

impl GovernedProcessJail {
    /// Create a private invocation root and bind a supported OS launcher.
    /// Missing or unsupported containment is a pre-dispatch refusal; there is
    /// intentionally no pass-through command.
    pub fn strict_app(limits: GovernedProcessJailLimits) -> Result<Self, GovernedProcessJailError> {
        Self::build(limits, None)
    }

    /// Opt-in variant of [`Self::strict_app`] whose only reachable network is
    /// the supplied host-owned HTTP CONNECT broker. Everything else in the
    /// strict profile is unchanged: deny-default, no DNS (the broker
    /// resolves), no other remote or loopback endpoint, no listening socket
    /// on the host, and the same limits. The child's proxy variables name the
    /// broker, `NO_PROXY` is empty, and a host trust bundle is exposed
    /// read-only as `SSL_CERT_FILE` when one is installed. A child that
    /// ignores the proxy variables cannot connect anywhere.
    ///
    /// macOS accepts only [`GovernedEgressBrokerEndpoint::LoopbackTcp`];
    /// Linux accepts only [`GovernedEgressBrokerEndpoint::UnixSocket`] and
    /// requires the trusted forwarder at one of
    /// [`GOVERNED_JAIL_EGRESS_FORWARDER_PATHS`].
    pub fn strict_app_with_brokered_egress(
        limits: GovernedProcessJailLimits,
        broker: GovernedEgressBrokerEndpoint,
    ) -> Result<Self, GovernedProcessJailError> {
        Self::build(limits, Some(broker))
    }

    fn build(
        limits: GovernedProcessJailLimits,
        broker: Option<GovernedEgressBrokerEndpoint>,
    ) -> Result<Self, GovernedProcessJailError> {
        let limits = limits.validate()?;
        let (platform, launcher) = platform_launcher()?;
        let egress = broker
            .map(|endpoint| brokered_egress_for(platform, endpoint))
            .transpose()?;
        if egress.as_ref().is_some_and(|egress| egress.forwarder.is_some())
            && limits.max_open_files < MIN_GOVERNED_JAIL_BROKERED_OPEN_FILES
        {
            return Err(invalid_limits());
        }
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
            egress,
            interpreter: None,
        })
    }

    /// Opt in to interpreter mode, on top of [`Self::strict_app`] or
    /// [`Self::strict_app_with_brokered_egress`]. The launched program becomes
    /// the pinned interpreter and the governed executable snapshot becomes its
    /// script: argv is `<interpreter> -I -S -B <script-snapshot> <args...>`.
    /// The profile allows exec of the interpreter literal only (never the
    /// script), reads the script snapshot, and reads the interpreter's library
    /// roots read-only; fork stays denied and nothing else changes. The
    /// governed executor still hashes and snapshots the script, so an expected
    /// executable digest binds the script bytes; the interpreter's own digest
    /// is rechecked before every launch. A jail takes one interpreter.
    pub fn with_interpreter(
        mut self,
        interpreter: GovernedJailInterpreter,
    ) -> Result<Self, GovernedProcessJailError> {
        if cfg!(not(any(target_os = "macos", target_os = "linux"))) {
            return Err(unsupported_platform());
        }
        if self.interpreter.is_some() || interpreter.platform != self.platform {
            return Err(interpreter_unavailable());
        }
        interpreter.revalidate()?;
        self.interpreter = Some(interpreter);
        Ok(self)
    }

    pub fn schema_version(&self) -> &'static str {
        schema_for(self.network())
    }

    pub fn network(&self) -> GovernedProcessJailNetwork {
        if self.egress.is_some() {
            GovernedProcessJailNetwork::BrokeredEgress
        } else {
            GovernedProcessJailNetwork::Denied
        }
    }

    pub fn platform(&self) -> GovernedProcessJailPlatform {
        self.platform
    }

    /// Endpoint-independent identity of this jail's launch template: schema,
    /// platform, network mode, the rendered sandbox profile or bubblewrap argv
    /// with placeholder paths, and the fixed child environment overlay.
    /// Consumers fold it into lock digests so a profile change invalidates
    /// them. Equal to [`governed_process_jail_profile_identity`].
    pub fn profile_identity(&self) -> GovernedProcessJailDigest {
        match self.interpreter.as_ref() {
            None => governed_process_jail_profile_identity(self.platform, self.network()),
            Some(interpreter) => governed_process_jail_interpreter_profile_identity(
                self.platform,
                self.network(),
                interpreter.kind,
                interpreter.version,
            ),
        }
    }

    pub fn guarantees(&self) -> GovernedProcessJailGuarantees {
        GovernedProcessJailGuarantees {
            schema_version: self.schema_version(),
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
            egress: self.egress_audit(),
            interpreter: self.interpreter_audit(),
        }
    }

    fn interpreter_audit(&self) -> Option<GovernedJailInterpreterAudit> {
        let interpreter = self.interpreter.as_ref()?;
        Some(GovernedJailInterpreterAudit {
            schema_version: GOVERNED_JAIL_INTERPRETER_V1,
            kind: interpreter.kind,
            version: interpreter.version,
            digest: interpreter.digest,
            launch_flags: GOVERNED_JAIL_PYTHON3_FLAGS,
            launch_user_site_disabled: true,
            script_exec_denied: self.platform == GovernedProcessJailPlatform::MacosSandboxExec,
            site_packages_read_denied: !interpreter.denied_roots.is_empty(),
            profile_identity: self.profile_identity(),
        })
    }

    fn egress_audit(&self) -> Option<GovernedProcessJailEgressAudit> {
        let egress = self.egress.as_ref()?;
        let profile_identity = self.profile_identity();
        let broker_port = match &egress.endpoint {
            GovernedEgressBrokerEndpoint::LoopbackTcp { port } => Some(port.get()),
            GovernedEgressBrokerEndpoint::UnixSocket { .. } => None,
        };
        let forwarder_digest = egress.forwarder.as_ref().map(|(_, digest)| *digest);
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tool-runtime.governed-process-jail.egress-binding.v1\0");
        hasher.update(profile_identity.as_bytes());
        match &egress.endpoint {
            GovernedEgressBrokerEndpoint::LoopbackTcp { port } => {
                hasher.update(b"loopback_tcp\0");
                hasher.update(&port.get().to_be_bytes());
            },
            GovernedEgressBrokerEndpoint::UnixSocket { path } => {
                hasher.update(b"unix_socket\0");
                hasher.update(blake3::hash(path.as_os_str().as_encoded_bytes()).as_bytes());
            },
        }
        match forwarder_digest {
            Some(digest) => {
                hasher.update(b"\x01");
                hasher.update(digest.as_bytes());
            },
            None => {
                hasher.update(b"\x00");
            },
        }
        hasher.update(&[u8::from(egress.trust_bundle.is_some())]);
        Some(GovernedProcessJailEgressAudit {
            schema_version: GOVERNED_PROCESS_JAIL_BROKERED_EGRESS_V1,
            broker: egress.endpoint.kind(),
            broker_port,
            proxy_port: egress.proxy_port(),
            proxy_environment: true,
            dns_denied: true,
            non_broker_network_denied: true,
            trust_bundle_exposed: egress.trust_bundle.is_some(),
            forwarder_digest,
            profile_identity,
            binding_identity: GovernedProcessJailDigest(*hasher.finalize().as_bytes()),
        })
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
        if let Some(interpreter) = self.interpreter.as_ref() {
            // Bind the interpreter bytes at launch, not only at discovery.
            interpreter.revalidate()?;
        }
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
            .env("TEMP", &self.canonical_workdir);
        // Loader injection (dyld `DYLD_*`, glibc ld.so `LD_*` and
        // `GLIBC_TUNABLES`) and the macOS framework launcher's executable
        // override are never part of a jailed launch. On Linux the launcher
        // (bwrap) runs on the host before any sandbox exists, so this matters
        // there too. Manifest validation already refuses most of these; this
        // is the jail's own backstop.
        let removed = command
            .get_envs()
            .map(|(name, _)| name.to_owned())
            .filter(|name| {
                let name = name.as_encoded_bytes();
                name.len() >= 5 && name[..5].eq_ignore_ascii_case(b"DYLD_")
                    || name.starts_with(b"LD_")
                    || name == b"GLIBC_TUNABLES"
                    || name == b"__PYVENV_LAUNCHER__"
            })
            .collect::<Vec<_>>();
        for name in removed {
            command.env_remove(name);
        }
        let Some(egress) = self.egress.as_ref() else {
            // Direct network is unavailable in this profile, so a portable
            // host trust-store path is unnecessary ambient host topology.
            command.env_remove("SSL_CERT_FILE");
            return;
        };
        // Brokered egress: these fixed overlays are applied after every
        // contract-provided value, so no manifest can bypass or re-point the
        // broker. The same values are set inside bwrap on Linux.
        for (name, value) in egress_environment(egress, self.platform) {
            command.env(name, value);
        }
        if egress.trust_bundle.is_none() {
            command.env_remove("SSL_CERT_FILE");
        }
    }

    #[cfg(target_os = "macos")]
    fn macos_command(
        &self,
        snapshot: &GovernedExecutableSnapshot,
    ) -> Result<Command, GovernedProcessJailError> {
        let executable = sbpl_path(snapshot.as_path())?;
        let private_bundle_root = snapshot.private_bundle_root().map(sbpl_path).transpose()?;
        let workdir = sbpl_path(&self.canonical_workdir)?;
        if let Some(interpreter) = self.interpreter.as_ref() {
            let program = sbpl_path(&interpreter.executable)?;
            let broker_port = self.egress.as_ref().map(|egress| egress.proxy_port().to_string());
            let profile = macos_interpreter_profile(
                &interpreter.grants(),
                &executable,
                private_bundle_root.as_deref(),
                &workdir,
                self.egress
                    .as_ref()
                    .zip(broker_port.as_deref())
                    .map(|(egress, port)| (port, egress.trust_bundle.is_some())),
            )?;
            let mut command = Command::new(&self.launcher);
            command
                .arg("-p")
                .arg(profile)
                .arg(program)
                .args(GOVERNED_JAIL_PYTHON3_FLAGS)
                .arg(executable);
            return Ok(command);
        }
        let profile = match self.egress.as_ref() {
            None => macos_profile(&executable, private_bundle_root.as_deref(), &workdir)?,
            Some(egress) => macos_egress_profile(
                &executable,
                private_bundle_root.as_deref(),
                &workdir,
                &egress.proxy_port().to_string(),
                egress.trust_bundle.is_some(),
            )?,
        };
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
        let lib_roots = ["/lib", "/lib64"]
            .into_iter()
            .map(Path::new)
            .filter(|root| root.exists())
            .collect::<Vec<_>>();
        let egress = match self.egress.as_ref() {
            None => None,
            Some(egress) => {
                let GovernedEgressBrokerEndpoint::UnixSocket { path: socket } = &egress.endpoint
                else {
                    return Err(unsupported_egress_broker());
                };
                let (forwarder, _) = egress
                    .forwarder
                    .as_ref()
                    .ok_or_else(egress_forwarder_unavailable)?;
                validate_trusted_launcher(forwarder)
                    .map_err(|_| egress_forwarder_unavailable())?;
                validate_broker_socket(socket)?;
                if let Some(bundle) = egress.trust_bundle.as_deref() {
                    validate_trusted_launcher(bundle)?;
                }
                Some(LinuxEgressMounts {
                    forwarder,
                    socket,
                    trust_bundle: egress.trust_bundle.as_deref(),
                    environment: egress_environment(egress, self.platform),
                })
            },
        };
        let mut command = Command::new(&self.launcher);
        match self.interpreter.as_ref() {
            None => command.args(linux_bwrap_args(
                &lib_roots,
                private_bundle_root,
                &self.canonical_workdir,
                relative_executable,
                egress.as_ref(),
            )),
            Some(interpreter) => command.args(linux_bwrap_args_with_interpreter(
                &lib_roots,
                private_bundle_root,
                &self.canonical_workdir,
                relative_executable,
                egress.as_ref(),
                Some(&interpreter.grants()),
            )),
        };
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

fn schema_for(network: GovernedProcessJailNetwork) -> &'static str {
    match network {
        GovernedProcessJailNetwork::Denied => GOVERNED_PROCESS_JAIL_V1,
        GovernedProcessJailNetwork::BrokeredEgress => GOVERNED_PROCESS_JAIL_BROKERED_EGRESS_V1,
    }
}

/// Validate a caller broker endpoint against this platform and bind the fixed
/// host resources (forwarder, trust bundle) the mode needs.
fn brokered_egress_for(
    platform: GovernedProcessJailPlatform,
    endpoint: GovernedEgressBrokerEndpoint,
) -> Result<BrokeredEgress, GovernedProcessJailError> {
    match (platform, &endpoint) {
        (
            GovernedProcessJailPlatform::MacosSandboxExec,
            GovernedEgressBrokerEndpoint::LoopbackTcp { .. },
        ) => {
            let trust_bundle = (Path::new(MACOS_TRUST_DIRECTORY).is_dir()
                && validate_trusted_launcher(Path::new(MACOS_TRUST_BUNDLE)).is_ok())
            .then(|| PathBuf::from(MACOS_TRUST_BUNDLE));
            Ok(BrokeredEgress {
                endpoint,
                forwarder: None,
                trust_bundle,
            })
        },
        (
            GovernedProcessJailPlatform::LinuxBubblewrap,
            GovernedEgressBrokerEndpoint::UnixSocket { path },
        ) => {
            validate_broker_socket(path)?;
            let forwarder = trusted_egress_forwarder()?;
            let trust_bundle = LINUX_HOST_TRUST_BUNDLES.iter().find_map(|candidate| {
                let canonical = fs::canonicalize(candidate).ok()?;
                validate_trusted_launcher(&canonical).ok()?;
                Some(canonical)
            });
            Ok(BrokeredEgress {
                endpoint,
                forwarder: Some(forwarder),
                trust_bundle,
            })
        },
        _ => Err(unsupported_egress_broker()),
    }
}

/// Host paths an interpreter-mode jail grants, borrowed from a pinned
/// interpreter or rendered as placeholders for the profile identity.
struct InterpreterGrants<'a> {
    executable: &'a Path,
    images: Vec<&'a Path>,
    library_roots: Vec<&'a Path>,
    denied_roots: Vec<&'a Path>,
}

impl GovernedJailInterpreter {
    #[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
    fn grants(&self) -> InterpreterGrants<'_> {
        InterpreterGrants {
            executable: &self.executable,
            images: self.images.iter().map(PathBuf::as_path).collect(),
            library_roots: self.library_roots.iter().map(PathBuf::as_path).collect(),
            denied_roots: self.denied_roots.iter().map(PathBuf::as_path).collect(),
        }
    }
}

/// Paths of one interpreter installation, before trust validation.
struct InterpreterLayout {
    executable: PathBuf,
    images: Vec<PathBuf>,
    library_roots: Vec<PathBuf>,
    denied_roots: Vec<PathBuf>,
}

/// First candidate that passes every trust check, in order.
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
fn python3_from_candidates(
    platform: GovernedProcessJailPlatform,
    candidates: &[&Path],
) -> Result<GovernedJailInterpreter, GovernedProcessJailError> {
    candidates
        .iter()
        .find_map(|candidate| python3_candidate(platform, candidate).ok())
        .ok_or_else(interpreter_unavailable)
}

/// Validate one fixed candidate. Every component of the candidate spelling
/// (symlinks included) must be root-owned and every non-symlink component
/// must not be group/other-writable, so nobody but root can re-point it. It
/// is then resolved to its real `python3.N` binary and the layout derived
/// from that canonical location is validated in full. No interpreter is run.
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
fn python3_candidate(
    platform: GovernedProcessJailPlatform,
    candidate: &Path,
) -> Result<GovernedJailInterpreter, GovernedProcessJailError> {
    validate_root_owned_spelling(candidate)?;
    let real = fs::canonicalize(candidate).map_err(|_| interpreter_unavailable())?;
    validate_trusted_launcher(&real).map_err(|_| interpreter_unavailable())?;
    let version = real
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(python3_version)
        .ok_or_else(interpreter_unavailable)?;
    let layout = match platform {
        GovernedProcessJailPlatform::MacosSandboxExec => macos_python3_layout(&real, version),
        GovernedProcessJailPlatform::LinuxBubblewrap => linux_python3_layout(&real, version),
    }
    .ok_or_else(interpreter_unavailable)?;
    let digest = interpreter_digest(&layout.executable, &layout.images)?;
    let interpreter = GovernedJailInterpreter {
        platform,
        kind: GovernedJailInterpreterKind::Python3,
        version,
        executable: layout.executable,
        images: layout.images,
        library_roots: layout.library_roots,
        denied_roots: layout.denied_roots,
        digest,
    };
    interpreter.revalidate()?;
    Ok(interpreter)
}

/// `python3.N` → `3.N`. Anything else (`python3`, `python3.14t`,
/// `python3.9-intel64`) is refused.
fn python3_version(name: &str) -> Option<GovernedJailInterpreterVersion> {
    let minor = name.strip_prefix("python3.")?;
    if minor.is_empty() || minor.len() > 3 || !minor.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(GovernedJailInterpreterVersion {
        major: 3,
        minor: minor.parse().ok()?,
    })
}

/// macOS framework layout of `<Name>.framework/Versions/X.Y/bin/pythonX.Y`.
/// The `bin` binary is a stub that re-execs
/// `Resources/Python.app/Contents/MacOS/Python`, so that app binary is the
/// executable (one exec, no second exec grant). It loads the framework
/// library `Versions/X.Y/<Name>`. `Versions/X.Y/lib` holds the stdlib,
/// `lib-dynload` and bundled libraries (python.org ships OpenSSL there);
/// `lib/pythonX.Y/site-packages` is denied again.
fn macos_python3_layout(
    real: &Path,
    version: GovernedJailInterpreterVersion,
) -> Option<InterpreterLayout> {
    let bin = real.parent()?;
    let version_directory = bin.parent()?;
    let versions = version_directory.parent()?;
    let framework = versions.parent()?.file_name()?.to_str()?;
    let framework_name = framework.strip_suffix(".framework")?;
    if bin.file_name()? != "bin"
        || version_directory.file_name()?.to_str()? != version.to_string()
        || versions.file_name()? != "Versions"
        || framework_name.is_empty()
    {
        return None;
    }
    let library = version_directory.join("lib");
    let stdlib = library.join(format!("python{version}"));
    if !stdlib.join("os.py").is_file() {
        return None;
    }
    Some(InterpreterLayout {
        executable: version_directory.join("Resources/Python.app/Contents/MacOS/Python"),
        images: vec![version_directory.join(framework_name)],
        library_roots: vec![library],
        denied_roots: vec![stdlib.join("site-packages")],
    })
}

/// Linux layout of `<prefix>/bin/python3.N`: the stdlib roots
/// `<prefix>/lib/python3.N` and, where present, `<prefix>/lib64/python3.N`.
/// The base loader/library roots are already bound by the strict profile.
fn linux_python3_layout(
    real: &Path,
    version: GovernedJailInterpreterVersion,
) -> Option<InterpreterLayout> {
    let bin = real.parent()?;
    if bin.file_name()? != "bin" {
        return None;
    }
    let prefix = bin.parent()?;
    let library_roots = canonical_unique_directories(
        ["lib", "lib64"]
            .into_iter()
            .map(|directory| prefix.join(directory).join(format!("python{version}"))),
    );
    if !library_roots.iter().any(|root| root.join("os.py").is_file()) {
        return None;
    }
    Some(InterpreterLayout {
        executable: real.to_path_buf(),
        images: linux_python3_images(real, prefix, version)?,
        library_roots,
        denied_roots: Vec::new(),
    })
}

/// Canonicalize candidate directories and keep each real directory once, in
/// order. Arch links `/usr/lib64` to `lib`, so `lib64/python3.N` resolves to
/// the same root as `lib/python3.N`; only canonical paths are kept.
fn canonical_unique_directories(candidates: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut directories = Vec::new();
    for candidate in candidates {
        let Ok(canonical) = fs::canonicalize(&candidate) else {
            continue;
        };
        if fs::symlink_metadata(&canonical).is_ok_and(|metadata| metadata.is_dir())
            && !directories.contains(&canonical)
        {
            directories.push(canonical);
        }
    }
    directories
}

/// A shared-libpython build (Fedora, RHEL, Arch) keeps the interpreter in
/// `libpython3.N.so.*`; the executable is a small launcher. Its `DT_NEEDED`
/// entries are read from the ELF dynamic section and the library is pinned
/// as an image. `None` (refuse) when the executable is not a readable
/// little-endian ELF64, names another `libpython`, or a needed libpython is
/// not a regular file in a trusted library directory.
fn linux_python3_images(
    real: &Path,
    prefix: &Path,
    version: GovernedJailInterpreterVersion,
) -> Option<Vec<PathBuf>> {
    let length = fs::symlink_metadata(real).ok()?.len();
    if length > MAX_GOVERNED_JAIL_INTERPRETER_IMAGE_BYTES {
        return None;
    }
    let bytes = fs::read(real).ok()?;
    let needed = elf64_needed(&bytes)?;
    let mut directories = vec![prefix.join("lib64")];
    if let Some(multiarch) = elf64_multiarch(&bytes) {
        directories.push(prefix.join("lib").join(multiarch));
    }
    directories.push(prefix.join("lib"));
    linux_libpython_images(&needed, version, &canonical_unique_directories(directories))
}

/// Resolve every needed `libpython*` in the first canonical directory that
/// holds it as a regular (non-symlink) file. Any other libpython name refuses.
fn linux_libpython_images(
    needed: &[String],
    version: GovernedJailInterpreterVersion,
    directories: &[PathBuf],
) -> Option<Vec<PathBuf>> {
    let expected = format!("libpython{version}.so");
    let mut images = Vec::new();
    for name in needed.iter().filter(|name| name.starts_with("libpython")) {
        if !name.starts_with(&expected) || name.contains('/') {
            return None;
        }
        let found = directories.iter().map(|directory| directory.join(name)).find(|path| {
            fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
        })?;
        if !images.contains(&found) {
            images.push(found);
        }
    }
    Some(images)
}

/// `DT_NEEDED` names of a little-endian ELF64 image. `None` when the bytes are
/// not one or are malformed; an image without a dynamic section needs
/// nothing. Bounded: the headers index the given bytes only, at most 4096
/// dynamic entries are read and names are at most 4096 bytes.
fn elf64_needed(bytes: &[u8]) -> Option<Vec<String>> {
    let u16_at = |offset: usize| -> Option<u16> {
        Some(u16::from_le_bytes(bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?))
    };
    let u32_at = |offset: usize| -> Option<u32> {
        Some(u32::from_le_bytes(bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?))
    };
    let u64_at = |offset: usize| -> Option<u64> {
        Some(u64::from_le_bytes(bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?))
    };
    if bytes.get(..6)? != b"\x7fELF\x02\x01" {
        return None;
    }
    let program_headers = usize::try_from(u64_at(0x20)?).ok()?;
    let entry_size = usize::from(u16_at(0x36)?);
    let entries = usize::from(u16_at(0x38)?);
    if entry_size < 56 {
        return None;
    }
    let mut loads = Vec::new();
    let mut dynamic = None;
    for index in 0..entries {
        let header = program_headers.checked_add(index.checked_mul(entry_size)?)?;
        let offset = u64_at(header.checked_add(8)?)?;
        let address = u64_at(header.checked_add(16)?)?;
        let size = u64_at(header.checked_add(32)?)?;
        match u32_at(header)? {
            1 => loads.push((address, offset, size)),
            2 => dynamic = Some((offset, size)),
            _ => {},
        }
    }
    let Some((dynamic_offset, dynamic_size)) = dynamic else {
        return Some(Vec::new());
    };
    let dynamic_offset = usize::try_from(dynamic_offset).ok()?;
    let mut names = Vec::new();
    let mut string_table = None;
    for index in 0..usize::try_from(dynamic_size / 16).ok()?.min(4096) {
        let entry = dynamic_offset.checked_add(index * 16)?;
        let value = u64_at(entry.checked_add(8)?)?;
        match u64_at(entry)? {
            0 => break,
            1 => names.push(value),
            5 => string_table = Some(value),
            _ => {},
        }
    }
    if names.is_empty() {
        return Some(Vec::new());
    }
    let string_table = string_table?;
    let (address, offset, _) = loads.iter().find(|(address, _, size)| {
        string_table >= *address && string_table - address < *size
    })?;
    let string_table = usize::try_from(string_table - address).ok()?
        .checked_add(usize::try_from(*offset).ok()?)?;
    names
        .into_iter()
        .map(|name| {
            let start = string_table.checked_add(usize::try_from(name).ok()?)?;
            let rest = bytes.get(start..)?;
            let end = rest.iter().take(4096).position(|byte| *byte == 0)?;
            String::from_utf8(rest[..end].to_vec()).ok()
        })
        .collect()
}

/// Debian multiarch library directory for the ELF machine, if any.
fn elf64_multiarch(bytes: &[u8]) -> Option<&'static str> {
    match u16::from_le_bytes(bytes.get(0x12..0x14)?.try_into().ok()?) {
        62 => Some("x86_64-linux-gnu"),
        183 => Some("aarch64-linux-gnu"),
        _ => None,
    }
}

/// BLAKE3 over a domain tag and, for the executable then each image, its
/// length and bytes. Domain-separated, so it is not a plain file digest.
fn interpreter_digest(
    executable: &Path,
    images: &[PathBuf],
) -> Result<GovernedProcessJailDigest, GovernedProcessJailError> {
    use std::io::Read;

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"tool-runtime.governed-process-jail.interpreter-image.v1\0");
    for path in std::iter::once(executable).chain(images.iter().map(PathBuf::as_path)) {
        let file = fs::File::open(path).map_err(|_| interpreter_unavailable())?;
        let length = file.metadata().map_err(|_| interpreter_unavailable())?.len();
        if length > MAX_GOVERNED_JAIL_INTERPRETER_IMAGE_BYTES {
            return Err(interpreter_unavailable());
        }
        // Length-prefixed and streamed: the bytes are never buffered whole,
        // and a file that grows or shrinks while hashed is refused.
        hasher.update(&length.to_be_bytes());
        let hashed = std::io::copy(&mut file.take(length + 1), &mut hasher)
            .map_err(|_| interpreter_unavailable())?;
        if hashed != length {
            return Err(interpreter_unavailable());
        }
    }
    Ok(GovernedProcessJailDigest(*hasher.finalize().as_bytes()))
}

/// Every component of `path` as spelled, symlinks included, is root-owned;
/// every non-symlink component is also not group/other-writable. A symlink's
/// own mode is not a write permission (Linux reports 0777 for all of them).
fn validate_root_owned_spelling(path: &Path) -> Result<(), GovernedProcessJailError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if !path.is_absolute() {
            return Err(interpreter_unavailable());
        }
        let mut current = Some(path);
        while let Some(component) = current {
            let metadata = fs::symlink_metadata(component).map_err(|_| interpreter_unavailable())?;
            if metadata.uid() != 0
                || (!metadata.file_type().is_symlink() && metadata.mode() & 0o022 != 0)
            {
                return Err(interpreter_unavailable());
            }
            current = component.parent();
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(unsupported_platform())
    }
}

/// A library root must be a canonical real directory whose ancestors pass the
/// trusted-launcher checks, and every entry below it (not following
/// symlinks, not descending into `denied` subtrees) must be root-owned and,
/// unless a symlink, not group/other-writable. Bounded by
/// `MAX_GOVERNED_JAIL_INTERPRETER_TREE_ENTRIES`.
fn validate_trusted_tree(root: &Path, denied: &[PathBuf]) -> Result<(), GovernedProcessJailError> {
    validate_real_absolute_directory(root).map_err(|_| interpreter_unavailable())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let mut current = Some(root);
        while let Some(component) = current {
            let metadata = fs::symlink_metadata(component).map_err(|_| interpreter_unavailable())?;
            if metadata.file_type().is_symlink()
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
            {
                return Err(interpreter_unavailable());
            }
            current = component.parent();
        }
        walk_tree(root, denied, MAX_GOVERNED_JAIL_INTERPRETER_TREE_ENTRIES, |_, metadata| {
            trusted_tree_entry(metadata)
        })
    }
    #[cfg(not(unix))]
    {
        let _ = denied;
        Err(unsupported_platform())
    }
}

/// Per-entry predicate of a trusted library tree: root-owned and, unless a
/// symlink (whose own mode is not a write permission), not
/// group/other-writable.
#[cfg(unix)]
fn trusted_tree_entry(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    metadata.uid() == 0 && (metadata.file_type().is_symlink() || metadata.mode() & 0o022 == 0)
}

/// Walk `root` without following symlinks, requiring `trusted` of every
/// entry, not descending into `denied` subtrees (their own entry is still
/// checked), and refusing more than `max_entries` entries.
#[cfg(unix)]
fn walk_tree(
    root: &Path,
    denied: &[PathBuf],
    max_entries: usize,
    trusted: impl Fn(&Path, &fs::Metadata) -> bool,
) -> Result<(), GovernedProcessJailError> {
    let mut pending = vec![root.to_path_buf()];
    let mut entries = 0_usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|_| interpreter_unavailable())? {
            let path = entry.map_err(|_| interpreter_unavailable())?.path();
            entries += 1;
            if entries > max_entries {
                return Err(interpreter_unavailable());
            }
            let metadata = fs::symlink_metadata(&path).map_err(|_| interpreter_unavailable())?;
            if !trusted(&path, &metadata) {
                return Err(interpreter_unavailable());
            }
            if metadata.is_dir() && !denied.contains(&path) {
                pending.push(path);
            }
        }
    }
    Ok(())
}

fn trusted_egress_forwarder() -> Result<(PathBuf, GovernedProcessJailDigest), GovernedProcessJailError>
{
    for candidate in GOVERNED_JAIL_EGRESS_FORWARDER_PATHS {
        let path = PathBuf::from(candidate);
        if validate_trusted_launcher(&path).is_err() {
            continue;
        }
        // A candidate that cannot be sized or read is skipped like an
        // untrusted one; the next fixed location may still hold a good copy.
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        if metadata.len() > MAX_GOVERNED_JAIL_FORWARDER_BYTES {
            continue;
        }
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let digest = GovernedProcessJailDigest(*blake3::hash(&bytes).as_bytes());
        return Ok((path, digest));
    }
    Err(egress_forwarder_unavailable())
}

/// The broker socket must be an existing, canonical unix socket owned by the
/// calling user inside a directory nobody else can write.
fn validate_broker_socket(path: &Path) -> Result<(), GovernedProcessJailError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};

        if !path.is_absolute() {
            return Err(egress_broker_unavailable());
        }
        let metadata = fs::symlink_metadata(path).map_err(|_| egress_broker_unavailable())?;
        // SAFETY: `geteuid` has no preconditions and cannot fail.
        let euid = unsafe { libc::geteuid() };
        if !metadata.file_type().is_socket() || metadata.uid() != euid {
            return Err(egress_broker_unavailable());
        }
        let canonical = fs::canonicalize(path).map_err(|_| egress_broker_unavailable())?;
        if canonical != path {
            return Err(egress_broker_unavailable());
        }
        let parent = path.parent().ok_or_else(egress_broker_unavailable)?;
        let parent_metadata =
            fs::symlink_metadata(parent).map_err(|_| egress_broker_unavailable())?;
        if !parent_metadata.is_dir()
            || (parent_metadata.uid() != euid && parent_metadata.uid() != 0)
            || parent_metadata.mode() & 0o022 != 0
        {
            return Err(egress_broker_unavailable());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(unsupported_egress_broker())
    }
}

/// Fixed child environment overlay of the brokered mode, in a stable order.
fn egress_environment(
    egress: &BrokeredEgress,
    platform: GovernedProcessJailPlatform,
) -> Vec<(&'static str, OsString)> {
    egress_environment_template(
        &egress.proxy_url(),
        egress.jailed_trust_bundle(platform),
    )
}

fn egress_environment_template(
    proxy_url: &str,
    trust_bundle: Option<&Path>,
) -> Vec<(&'static str, OsString)> {
    let mut environment = GOVERNED_JAIL_EGRESS_PROXY_VARIABLES
        .iter()
        .map(|name| (*name, OsString::from(proxy_url)))
        .chain(
            GOVERNED_JAIL_EGRESS_NO_PROXY_VARIABLES
                .iter()
                .map(|name| (*name, OsString::new())),
        )
        .collect::<Vec<_>>();
    if let Some(bundle) = trust_bundle {
        environment.push(("SSL_CERT_FILE", bundle.as_os_str().to_owned()));
    }
    environment
}

/// Endpoint-independent identity of a jail launch template for `platform` and
/// `network`. It renders the real profile builders with placeholder paths and
/// port, so any change to the rendered profile, bubblewrap argv, forwarder
/// protocol or environment overlay changes the digest. Available on every
/// host so a reviewer can compute lock identity without building a jail.
pub fn governed_process_jail_profile_identity(
    platform: GovernedProcessJailPlatform,
    network: GovernedProcessJailNetwork,
) -> GovernedProcessJailDigest {
    profile_identity(platform, network, None)
}

/// As [`governed_process_jail_profile_identity`], for a jail in interpreter
/// mode. It renders the interpreter profile/argv with placeholder paths and
/// additionally binds the interpreter kind, `major.minor` and fixed flags, so
/// it is portable across hosts yet changes with the interpreter line. It is
/// never equal to the identity without an interpreter.
pub fn governed_process_jail_interpreter_profile_identity(
    platform: GovernedProcessJailPlatform,
    network: GovernedProcessJailNetwork,
    kind: GovernedJailInterpreterKind,
    version: GovernedJailInterpreterVersion,
) -> GovernedProcessJailDigest {
    profile_identity(platform, network, Some((kind, version)))
}

fn profile_identity(
    platform: GovernedProcessJailPlatform,
    network: GovernedProcessJailNetwork,
    interpreter: Option<(GovernedJailInterpreterKind, GovernedJailInterpreterVersion)>,
) -> GovernedProcessJailDigest {
    let brokered = network == GovernedProcessJailNetwork::BrokeredEgress;
    let placeholder_grants = InterpreterGrants {
        executable: Path::new("/<interpreter>"),
        images: match platform {
            GovernedProcessJailPlatform::MacosSandboxExec => vec![Path::new("/<interpreter-image>")],
            GovernedProcessJailPlatform::LinuxBubblewrap => Vec::new(),
        },
        library_roots: vec![Path::new("/<interpreter-library>")],
        denied_roots: match platform {
            GovernedProcessJailPlatform::MacosSandboxExec => {
                vec![Path::new("/<interpreter-library>/<site-packages>")]
            },
            GovernedProcessJailPlatform::LinuxBubblewrap => Vec::new(),
        },
    };
    let grants = interpreter.map(|_| &placeholder_grants);
    let (template, environment): (Vec<OsString>, Vec<(&'static str, OsString)>) = match platform {
        GovernedProcessJailPlatform::MacosSandboxExec => {
            let executable = Path::new("/<executable>");
            let bundle = Path::new("/<bundle>");
            let workdir = Path::new("/<workdir>");
            let profile = match grants {
                Some(grants) => macos_interpreter_profile(
                    grants,
                    executable,
                    Some(bundle),
                    workdir,
                    brokered.then_some(("<broker-port>", true)),
                ),
                None if brokered => {
                    macos_egress_profile(executable, Some(bundle), workdir, "<broker-port>", true)
                },
                None => macos_profile(executable, Some(bundle), workdir),
            }
            // Fixed placeholder paths and port contain no quote, NUL or
            // newline and stay far below the byte ceiling, so rendering
            // cannot fail; a failure is a bug in this function.
            .expect("placeholder profile renders");
            let environment = if brokered {
                egress_environment_template(
                    "http://127.0.0.1:<broker-port>",
                    Some(Path::new(MACOS_TRUST_BUNDLE)),
                )
            } else {
                Vec::new()
            };
            (vec![OsString::from(profile)], environment)
        },
        GovernedProcessJailPlatform::LinuxBubblewrap => {
            let proxy_url = format!("http://127.0.0.1:{GOVERNED_JAIL_EGRESS_LINUX_PROXY_PORT}");
            let environment = if brokered {
                egress_environment_template(&proxy_url, Some(Path::new(LINUX_JAIL_TRUST_BUNDLE)))
            } else {
                Vec::new()
            };
            let egress = brokered.then(|| LinuxEgressMounts {
                forwarder: Path::new("/<forwarder>"),
                socket: Path::new("/<broker-socket>"),
                trust_bundle: Some(Path::new("/<trust-bundle>")),
                environment: environment.clone(),
            });
            let args = linux_bwrap_args_with_interpreter(
                &[Path::new("/lib"), Path::new("/lib64")],
                Path::new("/<bundle>"),
                Path::new("/<workdir>"),
                Path::new("<executable>"),
                egress.as_ref(),
                grants,
            );
            (args, environment)
        },
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"tool-runtime.governed-process-jail.profile-identity.v1\0");
    for part in [
        schema_for(network),
        match platform {
            GovernedProcessJailPlatform::MacosSandboxExec => "macos_sandbox_exec",
            GovernedProcessJailPlatform::LinuxBubblewrap => "linux_bubblewrap",
        },
        match network {
            GovernedProcessJailNetwork::Denied => "denied",
            GovernedProcessJailNetwork::BrokeredEgress => "brokered_egress",
        },
    ] {
        hasher.update(part.as_bytes());
        hasher.update(b"\0");
    }
    hasher.update(b"template\0");
    for part in &template {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part.as_encoded_bytes());
    }
    hasher.update(b"environment\0");
    for (name, value) in &environment {
        hasher.update(name.as_bytes());
        hasher.update(b"=");
        hasher.update(&(value.len() as u64).to_be_bytes());
        hasher.update(value.as_encoded_bytes());
    }
    if brokered {
        hasher.update(b"forwarder-protocol\0");
        hasher.update(GOVERNED_JAIL_EGRESS_FORWARDER_PROTOCOL_V1.as_bytes());
    }
    if let Some((kind, version)) = interpreter {
        hasher.update(b"interpreter\0");
        hasher.update(GOVERNED_JAIL_INTERPRETER_V1.as_bytes());
        hasher.update(b"\0");
        hasher.update(match kind {
            GovernedJailInterpreterKind::Python3 => b"python3\0",
        });
        hasher.update(version.to_string().as_bytes());
        hasher.update(b"\0");
        for flag in GOVERNED_JAIL_PYTHON3_FLAGS {
            hasher.update(flag.as_bytes());
            hasher.update(b"\0");
        }
    }
    GovernedProcessJailDigest(*hasher.finalize().as_bytes())
}

/// Host resources and fixed overlay of the Linux brokered mode.
struct LinuxEgressMounts<'a> {
    forwarder: &'a Path,
    socket: &'a Path,
    trust_bundle: Option<&'a Path>,
    environment: Vec<(&'static str, OsString)>,
}

/// Pure bubblewrap argv builder. The strict (`egress == None`) argv is
/// byte-identical to the reviewed strict profile. The brokered argv adds only
/// read-only binds of the forwarder, the broker socket and the trust bundle,
/// the fixed environment overlay, and runs the exact executable under the
/// forwarder. The network namespace stays unshared: only `lo` exists and no
/// resolver configuration is mounted, so DNS and every other address fail.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_bwrap_args(
    lib_roots: &[&Path],
    private_bundle_root: &Path,
    workdir: &Path,
    relative_executable: &Path,
    egress: Option<&LinuxEgressMounts<'_>>,
) -> Vec<OsString> {
    linux_bwrap_args_with_interpreter(
        lib_roots,
        private_bundle_root,
        workdir,
        relative_executable,
        egress,
        None,
    )
}

/// [`linux_bwrap_args`] plus interpreter mode: the interpreter executable
/// and its library roots are bound read-only at their own host paths (so the
/// interpreter finds its stdlib from its location), and the command becomes
/// `<interpreter> -I -S -B /app/<script>`. `None` yields exactly the argv of
/// [`linux_bwrap_args`].
fn linux_bwrap_args_with_interpreter(
    lib_roots: &[&Path],
    private_bundle_root: &Path,
    workdir: &Path,
    relative_executable: &Path,
    egress: Option<&LinuxEgressMounts<'_>>,
    interpreter: Option<&InterpreterGrants<'_>>,
) -> Vec<OsString> {
    let mut args: Vec<OsString> = [
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
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    // Deliberately do not expose `/bin`, `/usr/bin` or `/usr/lib`: the exact
    // admitted executable is the only ordinary program mounted into the
    // jail. Only the base loader/library roots remain read-only because a
    // dynamically linked snapshot cannot start without them. A binary with
    // undeclared non-base adjacent resources fails closed.
    for root in lib_roots {
        args.extend([OsString::from("--ro-bind"), root.into(), root.into()]);
    }
    args.extend([
        OsString::from("--ro-bind"),
        private_bundle_root.into(),
        OsString::from("/app"),
        OsString::from("--bind"),
        workdir.into(),
        OsString::from("/work"),
    ]);
    if let Some(egress) = egress {
        args.extend([
            OsString::from("--ro-bind"),
            egress.forwarder.into(),
            OsString::from(LINUX_JAIL_EGRESS_FORWARDER),
            // A read-only bind still admits `connect(2)`: Linux exempts
            // sockets from the read-only-filesystem write check, while chmod
            // or replacement of the host socket stays impossible.
            OsString::from("--ro-bind"),
            egress.socket.into(),
            OsString::from(LINUX_JAIL_EGRESS_SOCKET),
        ]);
        if let Some(bundle) = egress.trust_bundle {
            args.extend([
                OsString::from("--ro-bind"),
                bundle.into(),
                OsString::from(LINUX_JAIL_TRUST_BUNDLE),
            ]);
        }
    }
    if let Some(interpreter) = interpreter {
        for path in std::iter::once(interpreter.executable)
            .chain(interpreter.images.iter().copied())
            .chain(interpreter.library_roots.iter().copied())
        {
            args.extend([OsString::from("--ro-bind"), path.into(), path.into()]);
        }
    }
    // The tmpfs root exists only to assemble the mount namespace. Make it
    // read-only after all mounts are installed so `/work` is the sole
    // writable host-visible or in-memory subtree.
    args.extend(
        [
            "--remount-ro", "/", "--remount-ro", "/proc", "--remount-ro", "/dev", "--chdir",
            "/work", "--setenv", "HOME", "/work", "--setenv", "TMPDIR", "/work", "--setenv",
            "TMP", "/work", "--setenv", "TEMP", "/work", "--setenv", "PATH", "/app",
        ]
        .into_iter()
        .map(OsString::from),
    );
    if let Some(egress) = egress {
        for (name, value) in &egress.environment {
            args.extend([OsString::from("--setenv"), OsString::from(name), value.clone()]);
        }
    }
    args.push(OsString::from("--"));
    if egress.is_some() {
        args.extend([
            OsString::from(LINUX_JAIL_EGRESS_FORWARDER),
            OsString::from(GOVERNED_JAIL_EGRESS_FORWARDER_PROTOCOL_V1),
            OsString::from(GOVERNED_JAIL_EGRESS_LINUX_PROXY_PORT.to_string()),
            OsString::from(LINUX_JAIL_EGRESS_SOCKET),
            OsString::from("--"),
        ]);
    }
    if let Some(interpreter) = interpreter {
        args.push(interpreter.executable.into());
        args.extend(GOVERNED_JAIL_PYTHON3_FLAGS.map(OsString::from));
    }
    let mut jailed_executable = PathBuf::from("/app");
    jailed_executable.push(relative_executable);
    args.push(jailed_executable.into_os_string());
    args
}

/// Strict profile plus exactly the brokered-egress allowances: outbound TCP
/// to the broker's loopback port and read-only access to the system trust
/// store. No `mach-lookup` is granted, so mDNSResponder (DNS) and trustd stay
/// unreachable; no bind/inbound rule is granted, so the child cannot listen.
fn macos_egress_profile(
    executable: &Path,
    private_bundle_root: Option<&Path>,
    workdir: &Path,
    broker_port: &str,
    trust_bundle: bool,
) -> Result<String, GovernedProcessJailError> {
    let mut profile = macos_profile(executable, private_bundle_root, workdir)?;
    profile.push_str(&macos_egress_rules(broker_port, trust_bundle)?);
    if profile.len() > MAX_GOVERNED_JAIL_PROFILE_BYTES {
        return Err(profile_too_large());
    }
    Ok(profile)
}

/// The brokered-egress allowances appended to a base profile.
fn macos_egress_rules(broker_port: &str, trust_bundle: bool) -> Result<String, GovernedProcessJailError> {
    if broker_port.is_empty()
        || !broker_port
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'<' | b'>' | b'-'))
    {
        return Err(unsafe_host_path());
    }
    let mut rules = String::new();
    if trust_bundle {
        // `/etc` is a symlink to `/private/etc`; clients that open
        // `/etc/ssl/cert.pem` need its metadata to resolve it.
        rules.push_str(&format!(
            "(allow file-read-metadata (literal \"/etc\"))\n\
             (allow file-read* (subpath \"{MACOS_TRUST_DIRECTORY}\"))\n"
        ));
    }
    rules.push_str(&format!(
        "(allow network-outbound (remote tcp4 \"localhost:{broker_port}\"))\n"
    ));
    Ok(rules)
}

/// Interpreter mode: the strict profile rendered for the interpreter as the
/// only exec'able program, plus a read-only literal of the script snapshot,
/// read-only literals of the pinned images, read-only library subtrees and,
/// last so they win, denials of the `site-packages` subtrees. The optional
/// brokered-egress allowances follow unchanged. `process-fork` stays denied
/// and the script is never exec-allowed.
fn macos_interpreter_profile(
    interpreter: &InterpreterGrants<'_>,
    script: &Path,
    private_bundle_root: Option<&Path>,
    workdir: &Path,
    egress: Option<(&str, bool)>,
) -> Result<String, GovernedProcessJailError> {
    if interpreter.executable == script {
        return Err(unsafe_host_path());
    }
    let mut profile = macos_profile(interpreter.executable, private_bundle_root, workdir)?;
    profile.push_str(&format!("(allow file-read* (literal \"{}\"))\n", sbpl_escape(script)?));
    for image in &interpreter.images {
        profile.push_str(&format!("(allow file-read* (literal \"{}\"))\n", sbpl_escape(image)?));
    }
    for root in &interpreter.library_roots {
        profile.push_str(&format!("(allow file-read* (subpath \"{}\"))\n", sbpl_escape(root)?));
    }
    for denied in &interpreter.denied_roots {
        profile.push_str(&format!("(deny file-read* (subpath \"{}\"))\n", sbpl_escape(denied)?));
    }
    if let Some((broker_port, trust_bundle)) = egress {
        profile.push_str(&macos_egress_rules(broker_port, trust_bundle)?);
    }
    if profile.len() > MAX_GOVERNED_JAIL_PROFILE_BYTES {
        return Err(profile_too_large());
    }
    Ok(profile)
}

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
    // The workdir is the only writable subtree. Files written there cannot be
    // `dlopen`ed or mapped `PROT_EXEC` (nor injected by
    // `DYLD_INSERT_LIBRARIES` on a re-exec). This is defense in depth: a
    // process can still create native code in memory (`mprotect`, `ctypes`),
    // and that code stays inside this same profile.
    profile.push_str(&format!(
        "(allow file-read* (subpath \"{}\"))\n\
         (allow file-write* (subpath \"{}\"))\n\
         (deny file-map-executable (subpath \"{}\"))\n",
        sbpl_escape(workdir)?,
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

const fn unsupported_egress_broker() -> GovernedProcessJailError {
    GovernedProcessJailError::new(
        GovernedProcessJailErrorCode::UnsupportedEgressBroker,
        "jail.egress.broker",
        "this host's process jail cannot reach that egress broker kind",
    )
}

#[cfg_attr(not(unix), allow(dead_code))]
const fn egress_broker_unavailable() -> GovernedProcessJailError {
    GovernedProcessJailError::new(
        GovernedProcessJailErrorCode::EgressBrokerUnavailable,
        "jail.egress.broker",
        "the egress broker endpoint is missing, unsafe or not owned by this user",
    )
}

const fn egress_forwarder_unavailable() -> GovernedProcessJailError {
    GovernedProcessJailError::new(
        GovernedProcessJailErrorCode::EgressForwarderUnavailable,
        "jail.egress.forwarder",
        "no trusted in-jail egress forwarder is installed",
    )
}

const fn interpreter_unavailable() -> GovernedProcessJailError {
    GovernedProcessJailError::new(
        GovernedProcessJailErrorCode::InterpreterUnavailable,
        "jail.interpreter",
        "no trusted interpreter is available, or the pinned interpreter changed",
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

    /// Golden: the reviewed strict profile. The brokered-egress and
    /// interpreter modes must not move a single byte of it. `0.1.77` added the
    /// final `file-map-executable` denial of the workdir deliberately, which
    /// rotates the strict profile identity.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_strict_profile_is_byte_identical_to_the_reviewed_golden() {
        let profile = macos_profile(
            Path::new("/private/tmp/governed-bundle/bin/tool"),
            Some(Path::new("/private/tmp/governed-bundle")),
            Path::new("/private/tmp/private-work"),
        )
        .unwrap();
        assert_eq!(
            profile,
            "(version 1)\n\
             (deny default)\n\
             (deny process-fork)\n\
             (allow process-exec (literal \"/private/tmp/governed-bundle/bin/tool\"))\n\
             (allow file-read* (literal \"/private/tmp/governed-bundle/bin/tool\"))\n\
             (allow file-read-data (literal \"/\"))\n\
             (allow sysctl-read)\n\
             (allow file-read* (subpath \"/System\"))\n\
             (allow file-read* (subpath \"/usr/lib\"))\n\
             (allow file-read* (subpath \"/Library/Apple/System\"))\n\
             (allow file-read* (subpath \"/private/var/db/dyld\"))\n\
             (allow file-read* (literal \"/dev/null\"))\n\
             (allow file-read* (literal \"/dev/random\"))\n\
             (allow file-read* (literal \"/dev/urandom\"))\n\
             (allow file-read* (subpath \"/private/tmp/governed-bundle\"))\n\
             (allow file-read* (subpath \"/private/tmp/private-work\"))\n\
             (allow file-write* (subpath \"/private/tmp/private-work\"))\n\
             (deny file-map-executable (subpath \"/private/tmp/private-work\"))\n"
        );
    }

    /// Golden: the strict audit projection is embedded in governed receipts
    /// and consumer digests. It must serialize exactly as before.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn strict_audit_serialization_is_unchanged() {
        let jail = match GovernedProcessJail::strict_app(GovernedProcessJailLimits::default()) {
            Ok(jail) => jail,
            Err(error) if error.code == GovernedProcessJailErrorCode::LauncherUnavailable => return,
            Err(error) => panic!("unexpected strict jail setup failure: {error}"),
        };
        assert_eq!(jail.schema_version(), GOVERNED_PROCESS_JAIL_V1);
        let platform = if cfg!(target_os = "macos") {
            ("macos_sandbox_exec", false)
        } else {
            ("linux_bubblewrap", true)
        };
        assert_eq!(
            serde_json::to_string(&jail.audit()).unwrap(),
            format!(
                "{{\"guarantees\":{{\"schema_version\":\"tool-runtime.governed-process-jail.v1\",\
                 \"platform\":\"{}\",\"direct_network_denied\":true,\
                 \"ambient_environment_denied\":true,\"host_writes_denied\":true,\
                 \"private_workdir\":true,\"exact_executable_snapshot\":true,\
                 \"wall_ceiling\":true,\"cpu_ceiling\":true,\"memory_ceiling\":true,\
                 \"process_ceiling\":{},\"file_ceiling\":true,\"output_ceiling\":true}},\
                 \"limits\":{{\"wall_seconds\":30,\"cpu_seconds\":30,\
                 \"max_memory_bytes\":536870912,\"max_processes\":16,\
                 \"max_open_files\":64,\"max_files\":256,\"max_file_bytes\":16777216,\
                 \"max_total_file_bytes\":67108864}}}}",
                platform.0, platform.1
            )
        );
    }

    fn strings(args: &[OsString]) -> Vec<&str> {
        args.iter().map(|argument| argument.to_str().unwrap()).collect()
    }

    /// Golden: the strict bubblewrap argv is unchanged by the refactor into
    /// the pure builder. Runs on every host; the builder is platform-free.
    #[test]
    fn linux_strict_argv_is_identical_to_the_reviewed_golden() {
        let args = linux_bwrap_args(
            &[Path::new("/lib"), Path::new("/lib64")],
            Path::new("/private/bundle"),
            Path::new("/private/work"),
            Path::new("bin/tool"),
            None,
        );
        assert_eq!(
            strings(&args),
            [
                "--die-with-parent", "--unshare-all", "--tmpfs", "/", "--dir", "/app", "--dir",
                "/work", "--proc", "/proc", "--dev", "/dev", "--ro-bind", "/lib", "/lib",
                "--ro-bind", "/lib64", "/lib64", "--ro-bind", "/private/bundle", "/app",
                "--bind", "/private/work", "/work", "--remount-ro", "/", "--remount-ro",
                "/proc", "--remount-ro", "/dev", "--chdir", "/work", "--setenv", "HOME",
                "/work", "--setenv", "TMPDIR", "/work", "--setenv", "TMP", "/work",
                "--setenv", "TEMP", "/work", "--setenv", "PATH", "/app", "--",
                "/app/bin/tool",
            ]
        );
    }

    #[test]
    fn linux_brokered_argv_keeps_the_netns_unshared_and_runs_under_the_forwarder() {
        let environment = egress_environment_template(
            "http://127.0.0.1:3128",
            Some(Path::new(LINUX_JAIL_TRUST_BUNDLE)),
        );
        let mounts = LinuxEgressMounts {
            forwarder: Path::new("/usr/libexec/magicrun/magicrun-jail-egress-forwarder"),
            socket: Path::new("/run/magician/egress/broker.sock"),
            trust_bundle: Some(Path::new("/etc/ssl/certs/ca-certificates.crt")),
            environment,
        };
        let args = linux_bwrap_args(
            &[Path::new("/lib")],
            Path::new("/private/bundle"),
            Path::new("/private/work"),
            Path::new("tool"),
            Some(&mounts),
        );
        let args = strings(&args);
        assert!(args.contains(&"--unshare-all"));
        for widening in ["--share-net", "--unshare-net-try", "/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf"] {
            assert!(!args.contains(&widening), "{widening}");
        }
        let has = |window: &[&str]| args.windows(window.len()).any(|pair| pair == window);
        assert!(has(&[
            "--ro-bind",
            "/usr/libexec/magicrun/magicrun-jail-egress-forwarder",
            LINUX_JAIL_EGRESS_FORWARDER
        ]));
        assert!(has(&["--ro-bind", "/run/magician/egress/broker.sock", LINUX_JAIL_EGRESS_SOCKET]));
        assert!(has(&["--ro-bind", "/etc/ssl/certs/ca-certificates.crt", LINUX_JAIL_TRUST_BUNDLE]));
        assert!(!args.windows(2).any(|pair| pair[0] == "--bind" && pair[1].contains("sock")));
        for name in GOVERNED_JAIL_EGRESS_PROXY_VARIABLES {
            assert!(has(&["--setenv", name, "http://127.0.0.1:3128"]), "{name}");
        }
        for name in GOVERNED_JAIL_EGRESS_NO_PROXY_VARIABLES {
            assert!(has(&["--setenv", name, ""]), "{name}");
        }
        assert!(has(&["--setenv", "SSL_CERT_FILE", LINUX_JAIL_TRUST_BUNDLE]));
        // Every mount precedes the read-only remount of the assembled root.
        let remount = args.iter().position(|arg| *arg == "--remount-ro").unwrap();
        assert!(args.iter().rposition(|arg| *arg == "--ro-bind").unwrap() < remount);
        let separator = args.iter().position(|arg| *arg == "--").unwrap();
        assert_eq!(
            &args[separator..],
            [
                "--",
                LINUX_JAIL_EGRESS_FORWARDER,
                GOVERNED_JAIL_EGRESS_FORWARDER_PROTOCOL_V1,
                "3128",
                LINUX_JAIL_EGRESS_SOCKET,
                "--",
                "/app/tool",
            ]
        );
        assert!(egress_forwarder::parse_forwarder_arguments(
            args[separator + 2..].iter().map(OsString::from)
        )
        .is_some());
    }

    #[test]
    fn macos_brokered_profile_adds_only_the_broker_and_trust_store() {
        let executable = Path::new("/private/tmp/exact-tool");
        let workdir = Path::new("/private/tmp/private-work");
        let strict = macos_profile(executable, None, workdir).unwrap();
        let brokered = macos_egress_profile(executable, None, workdir, "49152", true).unwrap();
        let added = brokered.strip_prefix(&strict).expect("strict profile is a prefix");
        assert_eq!(
            added,
            "(allow file-read-metadata (literal \"/etc\"))\n\
             (allow file-read* (subpath \"/private/etc/ssl\"))\n\
             (allow network-outbound (remote tcp4 \"localhost:49152\"))\n"
        );
        for absent in ["mach-lookup", "network-bind", "network-inbound", "(remote ip \"*", "system-socket", "(allow default)"] {
            assert!(!brokered.contains(absent), "{absent}");
        }
        let without_trust = macos_egress_profile(executable, None, workdir, "49152", false).unwrap();
        assert_eq!(
            without_trust.strip_prefix(&strict).unwrap(),
            "(allow network-outbound (remote tcp4 \"localhost:49152\"))\n"
        );
        for hostile in ["", "1) (allow default", "80\"", "*"] {
            assert!(macos_egress_profile(executable, None, workdir, hostile, true).is_err());
        }
    }

    #[test]
    fn profile_identity_separates_modes_and_platforms_and_is_stable() {
        let platforms = [
            GovernedProcessJailPlatform::MacosSandboxExec,
            GovernedProcessJailPlatform::LinuxBubblewrap,
        ];
        let networks = [
            GovernedProcessJailNetwork::Denied,
            GovernedProcessJailNetwork::BrokeredEgress,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for platform in platforms {
            for network in networks {
                let identity = governed_process_jail_profile_identity(platform, network);
                assert_eq!(identity, governed_process_jail_profile_identity(platform, network));
                assert!(seen.insert(identity.to_string()));
                assert!(identity.to_string().starts_with("blake3:"));
                assert_eq!(
                    serde_json::to_value(identity).unwrap(),
                    serde_json::Value::String(identity.to_string())
                );
            }
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn strict_jail_reports_denied_network_and_its_profile_identity() {
        let jail = match GovernedProcessJail::strict_app(GovernedProcessJailLimits::default()) {
            Ok(jail) => jail,
            Err(error) if error.code == GovernedProcessJailErrorCode::LauncherUnavailable => return,
            Err(error) => panic!("unexpected strict jail setup failure: {error}"),
        };
        assert_eq!(jail.network(), GovernedProcessJailNetwork::Denied);
        assert!(jail.audit().egress.is_none());
        assert_eq!(
            jail.profile_identity(),
            governed_process_jail_profile_identity(jail.platform(), GovernedProcessJailNetwork::Denied)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_brokered_jail_audit_and_environment_overlay() {
        let jail = match GovernedProcessJail::strict_app_with_brokered_egress(
            GovernedProcessJailLimits::default(),
            GovernedEgressBrokerEndpoint::LoopbackTcp {
                port: NonZeroU16::new(49152).unwrap(),
            },
        ) {
            Ok(jail) => jail,
            Err(error) if error.code == GovernedProcessJailErrorCode::LauncherUnavailable => return,
            Err(error) => panic!("unexpected brokered jail setup failure: {error}"),
        };
        assert_eq!(jail.schema_version(), GOVERNED_PROCESS_JAIL_BROKERED_EGRESS_V1);
        assert_eq!(jail.network(), GovernedProcessJailNetwork::BrokeredEgress);
        let audit = jail.audit();
        assert_eq!(audit.guarantees.schema_version, GOVERNED_PROCESS_JAIL_BROKERED_EGRESS_V1);
        assert!(audit.guarantees.direct_network_denied);
        let egress = audit.egress.unwrap();
        assert_eq!(egress.broker, GovernedEgressBrokerKind::LoopbackTcp);
        assert_eq!((egress.broker_port, egress.proxy_port), (Some(49152), 49152));
        assert!(egress.dns_denied && egress.non_broker_network_denied && egress.proxy_environment);
        assert!(egress.forwarder_digest.is_none());
        assert_eq!(
            egress.profile_identity,
            governed_process_jail_profile_identity(
                GovernedProcessJailPlatform::MacosSandboxExec,
                GovernedProcessJailNetwork::BrokeredEgress
            )
        );
        let other = GovernedProcessJail::strict_app_with_brokered_egress(
            GovernedProcessJailLimits::default(),
            GovernedEgressBrokerEndpoint::LoopbackTcp {
                port: NonZeroU16::new(49153).unwrap(),
            },
        )
        .unwrap();
        let other = other.audit().egress.unwrap();
        assert_eq!(other.profile_identity, egress.profile_identity);
        assert_ne!(other.binding_identity, egress.binding_identity);
        let json = serde_json::to_value(audit).unwrap();
        assert_eq!(json["egress"]["broker"], "loopback_tcp");
        assert!(json["egress"]["binding_identity"].as_str().unwrap().starts_with("blake3:"));

        let mut command = Command::new("/usr/bin/true");
        command.env("HTTPS_PROXY", "http://attacker.invalid:1").env("NO_PROXY", "*");
        jail.harden_environment(&mut command);
        let environment = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_str().unwrap().to_owned(),
                    value.map(|value| value.to_str().unwrap().to_owned()),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        for name in GOVERNED_JAIL_EGRESS_PROXY_VARIABLES {
            assert_eq!(environment[name].as_deref(), Some("http://127.0.0.1:49152"), "{name}");
        }
        for name in GOVERNED_JAIL_EGRESS_NO_PROXY_VARIABLES {
            assert_eq!(environment[name].as_deref(), Some(""), "{name}");
        }
        if egress.trust_bundle_exposed {
            assert_eq!(environment["SSL_CERT_FILE"].as_deref(), Some(MACOS_TRUST_BUNDLE));
        }
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
            egress: None,
            interpreter: None,
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
