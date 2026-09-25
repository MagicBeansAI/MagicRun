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

pub mod egress_forwarder;
#[cfg(test)]
mod egress_tests;

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
}

/// Move-only strict app profile. There is no constructor accepting a caller
/// executable, environment map, launcher argv, or sandbox profile. The only
/// caller-supplied host resource is the explicitly opted-in egress broker.
pub struct GovernedProcessJail {
    platform: GovernedProcessJailPlatform,
    launcher: PathBuf,
    _workdir: TempDir,
    canonical_workdir: PathBuf,
    limits: GovernedProcessJailLimits,
    egress: Option<BrokeredEgress>,
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
        })
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
        governed_process_jail_profile_identity(self.platform, self.network())
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
        }
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
        command.args(linux_bwrap_args(
            &lib_roots,
            private_bundle_root,
            &self.canonical_workdir,
            relative_executable,
            egress.as_ref(),
        ));
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

fn trusted_egress_forwarder() -> Result<(PathBuf, GovernedProcessJailDigest), GovernedProcessJailError>
{
    for candidate in GOVERNED_JAIL_EGRESS_FORWARDER_PATHS {
        let path = PathBuf::from(candidate);
        if validate_trusted_launcher(&path).is_err() {
            continue;
        }
        let metadata = fs::metadata(&path).map_err(|_| egress_forwarder_unavailable())?;
        if metadata.len() > MAX_GOVERNED_JAIL_FORWARDER_BYTES {
            return Err(egress_forwarder_unavailable());
        }
        let bytes = fs::read(&path).map_err(|_| egress_forwarder_unavailable())?;
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
    let brokered = network == GovernedProcessJailNetwork::BrokeredEgress;
    let (template, environment): (Vec<OsString>, Vec<(&'static str, OsString)>) = match platform {
        GovernedProcessJailPlatform::MacosSandboxExec => {
            let executable = Path::new("/<executable>");
            let bundle = Path::new("/<bundle>");
            let workdir = Path::new("/<workdir>");
            let profile = if brokered {
                macos_egress_profile(executable, Some(bundle), workdir, "<broker-port>", true)
            } else {
                macos_profile(executable, Some(bundle), workdir)
            }
            .unwrap_or_default();
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
            let args = linux_bwrap_args(
                &[Path::new("/lib"), Path::new("/lib64")],
                Path::new("/<bundle>"),
                Path::new("/<workdir>"),
                Path::new("<executable>"),
                egress.as_ref(),
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
    if broker_port.is_empty()
        || !broker_port
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'<' | b'>' | b'-'))
    {
        return Err(unsafe_host_path());
    }
    let mut profile = macos_profile(executable, private_bundle_root, workdir)?;
    if trust_bundle {
        // `/etc` is a symlink to `/private/etc`; clients that open
        // `/etc/ssl/cert.pem` need its metadata to resolve it.
        profile.push_str(&format!(
            "(allow file-read-metadata (literal \"/etc\"))\n\
             (allow file-read* (subpath \"{MACOS_TRUST_DIRECTORY}\"))\n"
        ));
    }
    profile.push_str(&format!(
        "(allow network-outbound (remote tcp4 \"localhost:{broker_port}\"))\n"
    ));
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

    /// Golden: the strict profile existing locks were reviewed against. The
    /// brokered-egress mode must not move a single byte of it.
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
             (allow file-write* (subpath \"/private/tmp/private-work\"))\n"
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
