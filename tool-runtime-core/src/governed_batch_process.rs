//! Phase 6C bounded non-interactive process owner.
//!
//! Construction is crate-private: only the later Phase 6F authorization/auth join may
//! turn dormant Phase 6B authority into this executable capability. Raw stdout/stderr
//! remain crate-private for Phase 6D redaction and result sealing.

use std::{
    error::Error,
    ffi::OsStr,
    fmt,
    io::{Read, Write},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::{
    ffi::OsStrExt,
    io::{AsRawFd, RawFd},
    process::{CommandExt, ExitStatusExt},
};

use serde::Serialize;
use zeroize::Zeroizing;

use crate::{
    governed_execution::{
        GovernedExecutionDispatch, GovernedExecutionTerminal, GovernedExecutionTerminalState,
    },
    governed_execution_authority::{
        GovernedExecutableSnapshot, GovernedExecutionAuthorityError,
        GovernedExecutionAuthorityParts,
    },
    governed_process_jail::{
        GovernedProcessJail, GovernedProcessJailLimits, GovernedProcessJailWatch,
        MAX_GOVERNED_JAIL_PROCESSES,
    },
    manifest::CliInteraction,
};

pub const GOVERNED_BATCH_PROCESS_V1: &str = "tool-runtime.governed-batch-process.v1";
pub const MAX_CONCURRENT_GOVERNED_PROCESSES: usize = 32;
pub const MAX_RESERVED_GOVERNED_OUTPUT_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_RESERVED_GOVERNED_RESULT_BYTES: u64 = 640 * 1024 * 1024;
pub const MAX_RESERVED_GOVERNED_MEMORY_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const STREAM_CHUNK_BYTES: usize = 16 * 1024;
const STREAM_CHANNEL_DEPTH: usize = 32;
const GOVERNED_IO_THREAD_STACK_BYTES: usize = 256 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const JAIL_WATCH_INTERVAL: Duration = Duration::from_millis(200);
const TERMINATION_GRACE: Duration = Duration::from_millis(200);

/// How this target holds a spawned child to a declared `runtime.limits.memory_bytes`.
///
/// The two mechanisms are not equivalent and callers that record why a child died
/// should say which one applied, so this reports the mechanism rather than a bare
/// yes/no.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryLimitEnforcement {
    /// `setrlimit(RLIMIT_AS)` in the post-fork child. The kernel refuses the
    /// allocation itself, so the ceiling cannot be passed even momentarily.
    KernelAddressSpace,
    /// The executor samples the owned process group's physical footprint every
    /// `POLL_INTERVAL` and terminates the group on breach.
    ///
    /// This is a detection bound, not an allocation bound. A child may hold more
    /// than its ceiling for up to one sampling interval, and a single allocation
    /// large enough to be serviced and released between two samples is never
    /// observed at all. It is strictly weaker than `KernelAddressSpace` and is
    /// used only where the kernel offers nothing better.
    ParentFootprintWatchdog,
    /// No mechanism. A declared ceiling is refused rather than dropped.
    None,
}

impl MemoryLimitEnforcement {
    pub const fn is_enforceable(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Darwin aliases `RLIMIT_AS` onto `RLIMIT_RSS` and its kernel answers every finite
/// value with `EINVAL`; only `RLIM_INFINITY` is accepted. That is measured, not
/// assumed, and the test at the foot of this module re-measures it rather than
/// restating this constant. `RLIMIT_DATA` is no substitute: it bounds only the
/// `brk` segment, which a modern allocator's `mmap` arenas never occupy, so
/// honouring the declaration through it would be enforcement in name only.
///
/// So Darwin holds the ceiling from the parent instead, against the physical
/// footprint the platform's own jetsam accounting uses. That is weaker than the
/// kernel bound and says so in `ParentFootprintWatchdog`, but it is real
/// enforcement: the group is terminated and the caller is told why.
#[cfg(all(unix, not(target_vendor = "apple")))]
pub const fn memory_limit_enforcement() -> MemoryLimitEnforcement {
    MemoryLimitEnforcement::KernelAddressSpace
}

#[cfg(all(unix, target_vendor = "apple"))]
pub const fn memory_limit_enforcement() -> MemoryLimitEnforcement {
    MemoryLimitEnforcement::ParentFootprintWatchdog
}

/// Targets without `setrlimit` and without a way to observe a foreign process's
/// footprint have neither mechanism available.
#[cfg(not(unix))]
pub const fn memory_limit_enforcement() -> MemoryLimitEnforcement {
    MemoryLimitEnforcement::None
}

/// Whether a declared `runtime.limits.memory_bytes` can be held at all here.
///
/// A declared bound this predicate reports as unenforceable is refused in
/// `GovernedBatchProcess::from_authorized_parts` rather than dropped, so a manifest
/// can never claim a ceiling the child is not actually held to.
pub const fn process_memory_limits_are_enforceable() -> bool {
    memory_limit_enforcement().is_enforceable()
}

static ACTIVE_BATCH_PROCESSES: AtomicUsize = AtomicUsize::new(0);
static RESERVED_GOVERNED_OUTPUT_BYTES: AtomicU64 = AtomicU64::new(0);
static RESERVED_GOVERNED_RESULT_BYTES: AtomicU64 = AtomicU64::new(0);
static RESERVED_GOVERNED_MEMORY_BYTES: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedBatchProcessErrorCode {
    AuthorizationRequired,
    WrongInteraction,
    AuthorityChanged,
    CapacityExceeded,
    InvalidEnvironment,
    SpawnFailed,
    UnenforceableMemoryLimit,
    JailUnavailable,
    StreamUnavailable,
    StreamWriteFailed,
    StreamReadFailed,
    ProcessWaitFailed,
    ReaderShutdownFailed,
}

/// Fixed value-free executor error with explicit dispatch certainty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GovernedBatchProcessError {
    pub code: GovernedBatchProcessErrorCode,
    pub field: &'static str,
    pub message: &'static str,
    dispatch: GovernedExecutionDispatch,
}

impl GovernedBatchProcessError {
    const fn new(
        code: GovernedBatchProcessErrorCode,
        field: &'static str,
        message: &'static str,
        dispatch: GovernedExecutionDispatch,
    ) -> Self {
        Self {
            code,
            field,
            message,
            dispatch,
        }
    }

    pub fn dispatch(self) -> GovernedExecutionDispatch {
        self.dispatch
    }
}

impl fmt::Display for GovernedBatchProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for GovernedBatchProcessError {}

/// Sticky cancellation authority. It contains no invocation or provider payload.
#[derive(Clone, Default)]
pub struct GovernedBatchCancellation {
    cancelled: Arc<AtomicBool>,
}

impl fmt::Debug for GovernedBatchCancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernedBatchCancellation")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl GovernedBatchCancellation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Sealed authorized batch capability. The constructor is unavailable outside this
/// crate and is called only by Phase 6F after policy admission and auth preparation.
pub struct GovernedBatchProcess {
    schema_version: &'static str,
    authority: GovernedExecutionAuthorityParts,
    environment: Vec<(String, Zeroizing<Vec<u8>>)>,
    jail: Option<GovernedProcessJail>,
}

impl GovernedBatchProcess {
    pub(crate) fn from_authorized_parts(
        authority: GovernedExecutionAuthorityParts,
        environment: Vec<(String, Zeroizing<Vec<u8>>)>,
    ) -> Result<Self, GovernedBatchProcessError> {
        authority.revalidate().map_err(authority_changed)?;
        if authority.intent.interaction != CliInteraction::Batch {
            return Err(wrong_interaction());
        }
        // A memory ceiling is a promise about the child, so it is refused here —
        // before any permit, any reservation, and any process — on a host that
        // cannot keep it. Applying `setrlimit` and swallowing the platform's
        // rejection would leave the child running while the manifest still
        // advertised a bound nothing enforces, which is a worse failure than not
        // running it: it is invisible. The declaration itself stays valid and
        // portable; only this host refuses to act on it.
        if authority.intent.max_memory_bytes.is_some() && !process_memory_limits_are_enforceable() {
            return Err(unenforceable_memory_limit());
        }
        validate_environment(&environment)?;
        if !authority.baseline_matches_environment(&environment) {
            return Err(invalid_environment());
        }
        Ok(Self {
            schema_version: GOVERNED_BATCH_PROCESS_V1,
            authority,
            environment,
            jail: None,
        })
    }

    pub(crate) fn from_authorized_parts_in_jail(
        mut authority: GovernedExecutionAuthorityParts,
        environment: Vec<(String, Zeroizing<Vec<u8>>)>,
        jail: GovernedProcessJail,
    ) -> Result<Self, GovernedBatchProcessError> {
        // A strict app execution always has an RSS/address-space ceiling even
        // when an older manifest omitted one. A manifest may narrow this
        // profile, never widen it.
        authority.intent.max_memory_bytes = Some(
            authority
                .intent
                .max_memory_bytes
                .map_or(jail.limits().max_memory_bytes, |declared| {
                    declared.min(jail.limits().max_memory_bytes)
                }),
        );
        let mut process = Self::from_authorized_parts(authority, environment)?;
        process.jail = Some(jail);
        Ok(process)
    }

    pub fn schema_version(&self) -> &'static str {
        self.schema_version
    }
}

/// Raw bounded execution result. It exposes only value-free metadata publicly; Phase 6D
/// consumes it inside this crate to redact and seal output.
pub struct GovernedRawBatchExecution {
    terminal: GovernedExecutionTerminalState,
    exit_code: Option<i32>,
    elapsed: Duration,
    stdout: Zeroizing<Vec<u8>>,
    stderr: Zeroizing<Vec<u8>>,
    stdout_truncated: bool,
    stderr_truncated: bool,
    output_retention: Option<GovernedOutputRetention>,
}

impl GovernedRawBatchExecution {
    pub fn terminal(&self) -> GovernedExecutionTerminalState {
        self.terminal
    }

    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    pub fn stdout_bytes(&self) -> usize {
        self.stdout.len()
    }

    pub fn stderr_bytes(&self) -> usize {
        self.stderr.len()
    }

    pub fn stdout_truncated(&self) -> bool {
        self.stdout_truncated
    }

    pub fn stderr_truncated(&self) -> bool {
        self.stderr_truncated
    }

    pub(crate) fn into_parts(self) -> GovernedRawBatchExecutionParts {
        GovernedRawBatchExecutionParts {
            terminal: self.terminal,
            exit_code: self.exit_code,
            elapsed: self.elapsed,
            stdout: self.stdout,
            stderr: self.stderr,
            stdout_truncated: self.stdout_truncated,
            stderr_truncated: self.stderr_truncated,
            output_retention: self.output_retention,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        terminal: GovernedExecutionTerminal,
        dispatch: GovernedExecutionDispatch,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    ) -> Self {
        raw_terminal(
            terminal,
            dispatch,
            (terminal == GovernedExecutionTerminal::Success).then_some(0),
            Duration::from_millis(1),
            Zeroizing::new(stdout),
            Zeroizing::new(stderr),
        )
    }
}

pub(crate) struct GovernedRawBatchExecutionParts {
    pub(crate) terminal: GovernedExecutionTerminalState,
    pub(crate) exit_code: Option<i32>,
    pub(crate) elapsed: Duration,
    pub(crate) stdout: Zeroizing<Vec<u8>>,
    pub(crate) stderr: Zeroizing<Vec<u8>>,
    pub(crate) stdout_truncated: bool,
    pub(crate) stderr_truncated: bool,
    pub(crate) output_retention: Option<GovernedOutputRetention>,
}

pub struct GovernedBatchExecutor;

impl GovernedBatchExecutor {
    pub fn execute(
        process: GovernedBatchProcess,
        cancellation: &GovernedBatchCancellation,
    ) -> Result<GovernedRawBatchExecution, GovernedBatchProcessError> {
        let started = Instant::now();
        let intent_wall_seconds = u64::from(process.authority.intent.timeout_secs);
        let wall_seconds = process.jail.as_ref().map_or(intent_wall_seconds, |jail| {
            intent_wall_seconds.min(jail.limits().wall_seconds)
        });
        let deadline = started
            .checked_add(Duration::from_secs(wall_seconds))
            .ok_or_else(process_wait_failed)?;
        Self::execute_until(process, cancellation, deadline)
    }

    pub(crate) fn execute_until(
        process: GovernedBatchProcess,
        cancellation: &GovernedBatchCancellation,
        deadline: Instant,
    ) -> Result<GovernedRawBatchExecution, GovernedBatchProcessError> {
        let started = Instant::now();
        if cancellation.is_cancelled() || Instant::now() >= deadline {
            return Ok(raw_terminal(
                if cancellation.is_cancelled() {
                    GovernedExecutionTerminal::Cancelled
                } else {
                    GovernedExecutionTerminal::TimedOut
                },
                GovernedExecutionDispatch::NotDispatched,
                None,
                started.elapsed(),
                Zeroizing::new(Vec::new()),
                Zeroizing::new(Vec::new()),
            ));
        }
        let reserved_output = process
            .authority
            .intent
            .max_stdout_bytes
            .checked_add(process.authority.intent.max_stderr_bytes)
            .ok_or_else(capacity_exceeded)?;
        let permit = GovernedProcessPermit::acquire(
            reserved_output,
            process.authority.intent.max_memory_bytes.unwrap_or(0),
        )?;
        process.authority.revalidate().map_err(authority_changed)?;
        let executable = process
            .authority
            .executable_snapshot()
            .map_err(authority_changed)?;
        let cwd = process
            .authority
            .working_directory_handle()
            .map_err(authority_changed)?;
        if cancellation.is_cancelled() || Instant::now() >= deadline {
            return Ok(raw_terminal(
                if cancellation.is_cancelled() {
                    GovernedExecutionTerminal::Cancelled
                } else {
                    GovernedExecutionTerminal::TimedOut
                },
                GovernedExecutionDispatch::NotDispatched,
                None,
                started.elapsed(),
                Zeroizing::new(Vec::new()),
                Zeroizing::new(Vec::new()),
            ));
        }
        let mut raw = execute_spawned(process, executable, cwd, cancellation, started, deadline)?;
        if raw.terminal.dispatch() == GovernedExecutionDispatch::NotDispatched {
            drop(permit);
        } else {
            raw.output_retention = Some(permit.into_output_retention());
        }
        Ok(raw)
    }
}

fn execute_spawned(
    mut process: GovernedBatchProcess,
    executable: GovernedExecutableSnapshot,
    cwd: Option<crate::governed_execution_authority::GovernedWorkingDirectoryHandle>,
    cancellation: &GovernedBatchCancellation,
    started: Instant,
    deadline: Instant,
) -> Result<GovernedRawBatchExecution, GovernedBatchProcessError> {
    let jail_watch = process.jail.as_ref().map(GovernedProcessJail::watch);
    if let Some(jail) = process.jail.as_ref() {
        let owned_workdir = cwd.as_ref().ok_or_else(jail_unavailable)?;
        if !jail
            .owns_workdir(owned_workdir)
            .map_err(|_| jail_unavailable())?
        {
            return Err(jail_unavailable());
        }
    }
    let mut command = match process.jail.as_ref() {
        Some(jail) => jail.command(&executable).map_err(|_| jail_unavailable())?,
        None => Command::new(executable.as_path()),
    };
    command
        .env_clear()
        .stdin(if process.authority.intent.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for argument in &process.authority.intent.command_prefix {
        command.arg(argument);
    }
    for argument in process.authority.intent.arguments.iter() {
        command.arg(argument);
    }
    for (name, value) in &process.environment {
        command.env(name, bytes_as_os_str(value)?);
    }
    if let Some(jail) = process.jail.as_ref() {
        jail.harden_environment(&mut command);
    }
    #[cfg(unix)]
    {
        // Only the kernel mechanism is applied here. Under
        // `ParentFootprintWatchdog` the ceiling is held by the collection loop
        // instead, and calling `setrlimit` would fail the spawn outright on the
        // very platform the watchdog exists to serve.
        let max_memory_bytes = match memory_limit_enforcement() {
            MemoryLimitEnforcement::KernelAddressSpace => process.authority.intent.max_memory_bytes,
            MemoryLimitEnforcement::ParentFootprintWatchdog | MemoryLimitEnforcement::None => None,
        };
        command.process_group(0);
        let directory_fd = cwd.as_ref().map(|cwd| cwd.raw_fd());
        let jail_limits = process.jail.as_ref().map(GovernedProcessJail::limits);
        // SAFETY: `setrlimit` and `fchdir` are async-signal-safe. The optional
        // descriptor belongs to the identity-checked handle retained across
        // `spawn` and is used only in the post-fork, pre-exec child.
        unsafe {
            command.pre_exec(move || {
                // This branch is reached with `Some` only under
                // `KernelAddressSpace`, where the target is known to accept a
                // finite `RLIMIT_AS`. It therefore stays exactly as written: a
                // platform rejection here is a genuine anomaly and must still
                // fail the spawn rather than let the child escape the ceiling
                // its manifest declares.
                if let Some(bytes) = max_memory_bytes {
                    let limit = libc::rlimit {
                        rlim_cur: bytes as libc::rlim_t,
                        rlim_max: bytes as libc::rlim_t,
                    };
                    if libc::setrlimit(libc::RLIMIT_AS, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                if let Some(limits) = jail_limits {
                    apply_jail_rlimits(limits)?;
                }
                if let Some(directory_fd) = directory_fd {
                    if libc::fchdir(directory_fd) == 0 {
                        return Ok(());
                    } else {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }

    if cancellation.is_cancelled() || Instant::now() >= deadline {
        return Ok(raw_terminal(
            if cancellation.is_cancelled() {
                GovernedExecutionTerminal::Cancelled
            } else {
                GovernedExecutionTerminal::TimedOut
            },
            GovernedExecutionDispatch::NotDispatched,
            None,
            started.elapsed(),
            Zeroizing::new(Vec::new()),
            Zeroizing::new(Vec::new()),
        ));
    }

    process.authority.revalidate().map_err(authority_changed)?;
    let child = command.spawn().map_err(|_| spawn_failed())?;
    let mut tree = ProcessTreeGuard::new(child);
    let stdout = tree
        .child_mut()?
        .stdout
        .take()
        .ok_or_else(stream_unavailable)?;
    let stderr = tree
        .child_mut()?
        .stderr
        .take()
        .ok_or_else(stream_unavailable)?;
    let stdin_writer = match process.authority.intent.stdin.take() {
        Some(value) => {
            let stdin = tree
                .child_mut()?
                .stdin
                .take()
                .ok_or_else(stream_unavailable)?;
            #[cfg(unix)]
            let stdin_fd = Some(stdin.as_raw_fd());
            #[cfg(not(unix))]
            let stdin_fd = None;
            Some((stdin, stdin_fd, value))
        },
        None => None,
    };
    let (sender, receiver) = mpsc::sync_channel(STREAM_CHANNEL_DEPTH);
    #[cfg(unix)]
    let stdout_fd = Some(stdout.as_raw_fd());
    #[cfg(not(unix))]
    let stdout_fd = None;
    #[cfg(unix)]
    let stderr_fd = Some(stderr.as_raw_fd());
    #[cfg(not(unix))]
    let stderr_fd = None;
    let stdout_reader = spawn_reader(stdout, stdout_fd, OutputChannel::Stdout, sender.clone())?;
    let stderr_reader = match spawn_reader(stderr, stderr_fd, OutputChannel::Stderr, sender) {
        Ok(reader) => reader,
        Err(error) => {
            tree.terminate_and_reap();
            drop(receiver);
            let _ = stop_and_join_readers([stdout_reader]);
            return Err(error);
        },
    };
    let stdin_writer = match stdin_writer {
        Some((stdin, stdin_fd, value)) => match spawn_stdin_writer(stdin, stdin_fd, value) {
            Ok(writer) => Some(writer),
            Err(error) => {
                tree.terminate_and_reap();
                drop(receiver);
                let _ = stop_and_join_readers([stdout_reader, stderr_reader]);
                return Err(error);
            },
        },
        None => None,
    };
    collect(
        &mut tree,
        receiver,
        [stdout_reader, stderr_reader],
        stdin_writer,
        cancellation,
        BatchCollectionPolicy {
            deadline,
            max_stdout: process.authority.intent.max_stdout_bytes,
            max_stderr: process.authority.intent.max_stderr_bytes,
            // Carried only where the parent is the enforcing party. Under
            // `KernelAddressSpace` the child is already held by `setrlimit`, and
            // sampling it every tick would burn syscalls to re-derive a bound the
            // kernel is enforcing.
            watched_memory_bytes: match memory_limit_enforcement() {
                MemoryLimitEnforcement::ParentFootprintWatchdog => {
                    process.authority.intent.max_memory_bytes
                },
                MemoryLimitEnforcement::KernelAddressSpace | MemoryLimitEnforcement::None => None,
            },
            jail_watch,
            started,
        },
    )
}

struct BatchCollectionPolicy {
    deadline: Instant,
    max_stdout: u64,
    max_stderr: u64,
    /// Present only when this host holds the ceiling from the parent. `None`
    /// means either no ceiling was declared or the kernel is already holding it.
    watched_memory_bytes: Option<u64>,
    jail_watch: Option<GovernedProcessJailWatch>,
    started: Instant,
}

fn collect(
    tree: &mut ProcessTreeGuard,
    receiver: Receiver<StreamEvent>,
    readers: [ReaderHandle; 2],
    stdin_writer: Option<StdinWriterHandle>,
    cancellation: &GovernedBatchCancellation,
    policy: BatchCollectionPolicy,
) -> Result<GovernedRawBatchExecution, GovernedBatchProcessError> {
    let mut stdout = Zeroizing::new(Vec::new());
    let mut stderr = Zeroizing::new(Vec::new());
    let mut done_readers = 0usize;
    let mut status = None;
    let mut terminal_override = None;
    let mut stdout_truncated = false;
    let mut stderr_truncated = false;
    let mut first_error = None;
    // Let the owned child receive one bounded scheduler interval before the
    // first sampled jail check. Hard kernel limits apply from exec; this
    // parent-side sampler covers the remaining platform gaps. Reaping at the
    // top of every loop then makes a genuinely fast terminal authoritative
    // instead of misclassifying a transient launcher process tree.
    let mut last_jail_watch = Instant::now();

    loop {
        // Reap before sampling or honoring a newly observed cancellation. A
        // fast child may already have completed the effect and disappeared
        // from process accounting; treating that as a watchdog failure (or as
        // a pre-completion cancellation) would be both incorrect and likely to
        // retry an effect that already happened.
        if status.is_none() {
            status = tree.try_wait()?;
            if status.is_some() {
                tree.mark_reaped();
            }
        }
        if status.is_none() && cancellation.is_cancelled() {
            terminal_override = Some(GovernedExecutionTerminal::Cancelled);
            tree.terminate_and_reap();
            break;
        }
        if status.is_none() && Instant::now() >= policy.deadline {
            terminal_override = Some(GovernedExecutionTerminal::TimedOut);
            tree.terminate_and_reap();
            break;
        }
        // Sampled only while the child is still unreaped. The loop keeps running
        // after a child exits, to drain its readers, and a reaped pid is free for
        // reuse — so a later tick could measure a stranger that inherited the
        // group id and terminate it for a ceiling it never agreed to. An exited
        // child also holds nothing, so there is nothing to enforce.
        //
        // A tick that cannot sample yields `None` and is skipped rather than read
        // as compliant.
        if status.is_none() {
            if let Some(ceiling) = policy.watched_memory_bytes {
                if owned_group_footprint_bytes(tree.pid).is_some_and(|held| held > ceiling) {
                    terminal_override = Some(GovernedExecutionTerminal::MemoryLimitExceeded);
                    tree.terminate_and_reap();
                    break;
                }
            }
        }
        if status.is_none() && last_jail_watch.elapsed() >= JAIL_WATCH_INTERVAL {
            if let Some(watch) = policy.jail_watch.as_ref() {
                match observe_jail_limits(tree.pid, watch) {
                    Ok(Some(terminal)) => {
                        // The child may exit after the loop's initial reap but
                        // before this resource sample completes. Its real exit
                        // is authoritative; do not replace it with a sampled
                        // limit terminal after the process has already ended.
                        if let Some(exited) = tree.try_wait()? {
                            status = Some(exited);
                            tree.mark_reaped();
                        } else {
                            terminal_override = Some(terminal);
                            tree.terminate_and_reap();
                            break;
                        }
                    },
                    Ok(None) => {},
                    Err(()) => {
                        // Close the exit-between-poll-and-sample race. If the
                        // owned child is now waitable, its terminal status is
                        // authoritative and there is no live effect left to
                        // observe. Only a still-running child with lost
                        // observation becomes effect-uncertain.
                        if let Some(exited) = tree.try_wait()? {
                            status = Some(exited);
                            tree.mark_reaped();
                        } else {
                            first_error.get_or_insert_with(jail_watch_failed);
                            tree.terminate_and_reap();
                            break;
                        }
                    },
                }
            }
            last_jail_watch = Instant::now();
        }
        match receiver.recv_timeout(POLL_INTERVAL) {
            Ok(StreamEvent::Chunk(channel, bytes)) => {
                if let Err(exceeded) = append_bounded(
                    channel,
                    &bytes,
                    &mut stdout,
                    &mut stderr,
                    policy.max_stdout,
                    policy.max_stderr,
                ) {
                    match exceeded {
                        OutputChannel::Stdout => stdout_truncated = true,
                        OutputChannel::Stderr => stderr_truncated = true,
                    }
                    terminal_override = Some(GovernedExecutionTerminal::OutputLimitExceeded);
                    tree.terminate_and_reap();
                    break;
                }
            },
            Ok(StreamEvent::Done) => done_readers += 1,
            Ok(StreamEvent::Failed) => {
                first_error.get_or_insert_with(stream_read_failed);
                tree.terminate_and_reap();
                break;
            },
            Err(mpsc::RecvTimeoutError::Timeout) => {},
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if done_readers < 2 {
                    first_error.get_or_insert_with(stream_read_failed);
                    break;
                }
                // Both output owners can observe EOF a few scheduler ticks before
                // `try_wait` reports the child's status. Keep polling the owned child
                // under the same cancellation/deadline bounds instead of converting
                // that valid ordering into a synthetic reaping failure.
                thread::sleep(POLL_INTERVAL);
            },
        }
        if status.is_some() && done_readers >= 2 {
            break;
        }
    }

    drop(receiver);
    let reader_result = stop_and_join_readers(readers);
    let mut writer_error = None;
    if let Some(writer) = stdin_writer {
        match stop_and_join_stdin_writer(writer) {
            Ok(Ok(())) => {},
            Ok(Err(error)) => {
                if status.is_none() && terminal_override.is_none() {
                    writer_error = Some(error);
                }
            },
            Err(()) => {
                writer_error = Some(stream_write_failed());
            },
        }
    }
    if reader_result.is_err() {
        first_error.get_or_insert_with(reader_shutdown_failed);
    }
    if let Some(error) = writer_error {
        first_error.get_or_insert(error);
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    let (terminal, exit_code) = match terminal_override {
        Some(terminal) => (terminal, None),
        None => {
            let status = status.ok_or_else(process_wait_failed)?;
            terminal_from_exit_status(status)
        },
    };
    Ok(raw_terminal_with_truncation(
        terminal,
        GovernedExecutionDispatch::Dispatched,
        exit_code,
        policy.started.elapsed(),
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    ))
}

fn terminal_from_exit_status(status: ExitStatus) -> (GovernedExecutionTerminal, Option<i32>) {
    match status.code() {
        Some(0) => (GovernedExecutionTerminal::Success, Some(0)),
        Some(code) => (GovernedExecutionTerminal::NonZeroExit, Some(code)),
        #[cfg(unix)]
        None if status.signal() == Some(libc::SIGXCPU) => {
            (GovernedExecutionTerminal::CpuLimitExceeded, None)
        },
        #[cfg(unix)]
        None if status.signal() == Some(libc::SIGXFSZ) => {
            (GovernedExecutionTerminal::FileLimitExceeded, None)
        },
        None => (GovernedExecutionTerminal::RuntimeFailure, None),
    }
}

#[derive(Clone, Copy)]
enum OutputChannel {
    Stdout,
    Stderr,
}

enum StreamEvent {
    Chunk(OutputChannel, Vec<u8>),
    Done,
    Failed,
}

struct ReaderHandle {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

fn spawn_reader(
    mut reader: impl Read + Send + 'static,
    #[cfg(unix)] raw_fd: Option<RawFd>,
    #[cfg(not(unix))] _raw_fd: Option<i32>,
    channel: OutputChannel,
    sender: SyncSender<StreamEvent>,
) -> Result<ReaderHandle, GovernedBatchProcessError> {
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = thread::Builder::new()
        .name("governed-batch-reader".to_owned())
        .stack_size(GOVERNED_IO_THREAD_STACK_BYTES)
        .spawn(move || {
            let mut buffer = [0u8; STREAM_CHUNK_BYTES];
            while !thread_stop.load(Ordering::Acquire) {
                #[cfg(unix)]
                if let Some(raw_fd) = raw_fd {
                    let mut descriptor = libc::pollfd {
                        fd: raw_fd,
                        events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                        revents: 0,
                    };
                    // SAFETY: the reader owns this descriptor for the thread lifetime.
                    let ready = unsafe {
                        libc::poll(
                            &mut descriptor,
                            1,
                            i32::try_from(POLL_INTERVAL.as_millis()).unwrap_or(20),
                        )
                    };
                    if ready == 0 {
                        continue;
                    }
                    if ready < 0 {
                        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                        {
                            continue;
                        }
                        let _ = sender.send(StreamEvent::Failed);
                        break;
                    }
                }
                match reader.read(&mut buffer) {
                    Ok(0) => {
                        let _ = sender.send(StreamEvent::Done);
                        break;
                    },
                    Ok(count) => {
                        if sender
                            .send(StreamEvent::Chunk(channel, buffer[..count].to_vec()))
                            .is_err()
                        {
                            break;
                        }
                    },
                    Err(error) => {
                        #[cfg(unix)]
                        if error.raw_os_error() == Some(libc::EIO) {
                            let _ = sender.send(StreamEvent::Done);
                            break;
                        }
                        let _ = sender.send(StreamEvent::Failed);
                        break;
                    },
                }
            }
        })
        .map_err(|_| stream_unavailable())?;
    Ok(ReaderHandle { stop, thread })
}

fn stop_and_join_readers<const N: usize>(
    readers: [ReaderHandle; N],
) -> Result<(), GovernedBatchProcessError> {
    for reader in &readers {
        reader.stop.store(true, Ordering::Release);
    }
    let mut failed = false;
    for reader in readers {
        if reader.thread.join().is_err() {
            failed = true;
        }
    }
    if failed {
        Err(reader_shutdown_failed())
    } else {
        Ok(())
    }
}

struct StdinWriterHandle {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<Result<(), GovernedBatchProcessError>>,
}

fn spawn_stdin_writer(
    mut stdin: impl Write + Send + 'static,
    #[cfg(unix)] raw_fd: Option<RawFd>,
    #[cfg(not(unix))] _raw_fd: Option<i32>,
    bytes: Zeroizing<Vec<u8>>,
) -> Result<StdinWriterHandle, GovernedBatchProcessError> {
    #[cfg(unix)]
    if let Some(raw_fd) = raw_fd {
        set_nonblocking(raw_fd).map_err(|_| stream_unavailable())?;
    }
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = thread::Builder::new()
        .name("governed-batch-stdin".to_owned())
        .stack_size(GOVERNED_IO_THREAD_STACK_BYTES)
        .spawn(move || {
            write_all_cancellable(&mut stdin, &bytes, &thread_stop)?;
            flush_cancellable(&mut stdin, &thread_stop)
        })
        .map_err(|_| stream_unavailable())?;
    Ok(StdinWriterHandle { stop, thread })
}

fn stop_and_join_stdin_writer(
    writer: StdinWriterHandle,
) -> Result<Result<(), GovernedBatchProcessError>, ()> {
    writer.stop.store(true, Ordering::Release);
    writer.thread.join().map_err(|_| ())
}

fn write_all_cancellable(
    writer: &mut dyn Write,
    bytes: &[u8],
    stop: &AtomicBool,
) -> Result<(), GovernedBatchProcessError> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        match writer.write(&bytes[offset..]) {
            Ok(0) => return Err(stream_write_failed()),
            Ok(written) => {
                offset = offset
                    .checked_add(written)
                    .ok_or_else(stream_write_failed)?;
            },
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) =>
            {
                thread::sleep(POLL_INTERVAL);
            },
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => return Ok(()),
            Err(_) => return Err(stream_write_failed()),
        }
    }
    Ok(())
}

fn flush_cancellable(
    writer: &mut dyn Write,
    stop: &AtomicBool,
) -> Result<(), GovernedBatchProcessError> {
    while !stop.load(Ordering::Acquire) {
        match writer.flush() {
            Ok(()) => return Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) =>
            {
                thread::sleep(POLL_INTERVAL);
            },
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => return Ok(()),
            Err(_) => return Err(stream_write_failed()),
        }
    }
    Ok(())
}

fn append_bounded(
    channel: OutputChannel,
    bytes: &[u8],
    stdout: &mut Zeroizing<Vec<u8>>,
    stderr: &mut Zeroizing<Vec<u8>>,
    max_stdout: u64,
    max_stderr: u64,
) -> Result<(), OutputChannel> {
    let (target, maximum) = match channel {
        OutputChannel::Stdout => (stdout, max_stdout),
        OutputChannel::Stderr => (stderr, max_stderr),
    };
    let next = target.len().checked_add(bytes.len()).ok_or(channel)?;
    if next as u64 > maximum {
        return Err(channel);
    }
    let capacity = target.capacity();
    if next > capacity {
        target.reserve_exact(next - capacity);
    }
    target.extend_from_slice(bytes);
    Ok(())
}

struct ProcessTreeGuard {
    child: Option<Child>,
    pid: Option<u32>,
}

impl ProcessTreeGuard {
    fn new(child: Child) -> Self {
        let pid = Some(child.id());
        Self {
            child: Some(child),
            pid,
        }
    }

    fn child_mut(&mut self) -> Result<&mut Child, GovernedBatchProcessError> {
        self.child.as_mut().ok_or_else(process_wait_failed)
    }

    fn try_wait(&mut self) -> Result<Option<ExitStatus>, GovernedBatchProcessError> {
        #[cfg(unix)]
        {
            if !observe_owned_child_exit(self.pid).map_err(|_| process_wait_failed())? {
                return Ok(None);
            }
            terminate_exited_process_group_before_reap(self.pid);
            self.child_mut()?
                .wait()
                .map(Some)
                .map_err(|_| process_wait_failed())
        }
        #[cfg(not(unix))]
        self.child_mut()?
            .try_wait()
            .map_err(|_| process_wait_failed())
    }

    fn mark_reaped(&mut self) {
        self.child = None;
    }

    fn terminate_and_reap(&mut self) {
        terminate_process_group(self.pid);
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;
    }
}

impl Drop for ProcessTreeGuard {
    fn drop(&mut self) {
        if self.child.is_some() {
            self.terminate_and_reap();
        }
    }
}

pub(crate) struct GovernedProcessPermit {
    reserved_output: u64,
    reserved_memory: u64,
}

impl GovernedProcessPermit {
    pub(crate) fn acquire(
        reserved_output: u64,
        reserved_memory: u64,
    ) -> Result<Self, GovernedBatchProcessError> {
        if reserved_output == 0 || reserved_output > MAX_RESERVED_GOVERNED_OUTPUT_BYTES {
            return Err(capacity_exceeded());
        }
        ACTIVE_BATCH_PROCESSES
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < MAX_CONCURRENT_GOVERNED_PROCESSES).then_some(active + 1)
            })
            .map_err(|_| capacity_exceeded())?;
        let output_reserved = RESERVED_GOVERNED_OUTPUT_BYTES
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(reserved_output)
                    .filter(|next| *next <= MAX_RESERVED_GOVERNED_OUTPUT_BYTES)
            })
            .is_ok();
        if !output_reserved {
            ACTIVE_BATCH_PROCESSES.fetch_sub(1, Ordering::AcqRel);
            return Err(capacity_exceeded());
        }
        if !try_reserve_governed_result_bytes(reserved_output) {
            RESERVED_GOVERNED_OUTPUT_BYTES.fetch_sub(reserved_output, Ordering::AcqRel);
            ACTIVE_BATCH_PROCESSES.fetch_sub(1, Ordering::AcqRel);
            return Err(capacity_exceeded());
        }
        let memory_reserved = reserved_memory == 0
            || RESERVED_GOVERNED_MEMORY_BYTES
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current
                        .checked_add(reserved_memory)
                        .filter(|next| *next <= MAX_RESERVED_GOVERNED_MEMORY_BYTES)
                })
                .is_ok();
        if !memory_reserved {
            release_governed_result_bytes(reserved_output);
            RESERVED_GOVERNED_OUTPUT_BYTES.fetch_sub(reserved_output, Ordering::AcqRel);
            ACTIVE_BATCH_PROCESSES.fetch_sub(1, Ordering::AcqRel);
            return Err(capacity_exceeded());
        }
        Ok(Self {
            reserved_output,
            reserved_memory,
        })
    }

    pub(crate) fn into_output_retention(mut self) -> GovernedOutputRetention {
        ACTIVE_BATCH_PROCESSES.fetch_sub(1, Ordering::AcqRel);
        let reserved_output = self.reserved_output;
        if self.reserved_memory != 0 {
            RESERVED_GOVERNED_MEMORY_BYTES.fetch_sub(self.reserved_memory, Ordering::AcqRel);
            self.reserved_memory = 0;
        }
        self.reserved_output = 0;
        GovernedOutputRetention { reserved_output }
    }
}

impl Drop for GovernedProcessPermit {
    fn drop(&mut self) {
        if self.reserved_output != 0 {
            release_governed_result_bytes(self.reserved_output);
            RESERVED_GOVERNED_OUTPUT_BYTES.fetch_sub(self.reserved_output, Ordering::AcqRel);
            ACTIVE_BATCH_PROCESSES.fetch_sub(1, Ordering::AcqRel);
        }
        if self.reserved_memory != 0 {
            RESERVED_GOVERNED_MEMORY_BYTES.fetch_sub(self.reserved_memory, Ordering::AcqRel);
        }
    }
}

/// Keeps the raw-output reservation alive until result redaction and artifact sealing
/// have completed. It carries no process slot, invocation value, or output bytes.
pub(crate) struct GovernedOutputRetention {
    reserved_output: u64,
}

impl Drop for GovernedOutputRetention {
    fn drop(&mut self) {
        release_governed_result_bytes(self.reserved_output);
        RESERVED_GOVERNED_OUTPUT_BYTES.fetch_sub(self.reserved_output, Ordering::AcqRel);
    }
}

pub(crate) fn try_reserve_governed_result_bytes(bytes: u64) -> bool {
    bytes != 0
        && RESERVED_GOVERNED_RESULT_BYTES
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(bytes)
                    .filter(|next| *next <= MAX_RESERVED_GOVERNED_RESULT_BYTES)
            })
            .is_ok()
}

pub(crate) fn release_governed_result_bytes(bytes: u64) {
    if bytes != 0 {
        RESERVED_GOVERNED_RESULT_BYTES.fetch_sub(bytes, Ordering::AcqRel);
    }
}

#[cfg(unix)]
pub(crate) fn set_nonblocking(fd: RawFd) -> Result<(), ()> {
    // SAFETY: `fd` belongs to a live process/PTY stream. `F_GETFL` is read-only.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(());
    }
    // SAFETY: preserve every existing descriptor status flag and add O_NONBLOCK.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(());
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn set_nonblocking(_fd: i32) -> Result<(), ()> {
    Err(())
}

/// Physical footprint, in bytes, of every live process in the owned group.
///
/// The group is the unit of measurement because the executor owns a process
/// group, not a single pid. A converter that forks a helper must not be able to
/// place its allocation outside the ceiling its manifest declared, and the group
/// is exactly the set the executor already terminates.
///
/// `ri_phys_footprint` is the accounting macOS uses for its own jetsam
/// decisions: resident pages plus compressed pages plus IOKit mappings.
/// `ri_resident_size` alone would under-count a child whose pages the compressor
/// has already taken, which is precisely the state a process approaching a
/// ceiling is in.
///
/// Returns `None` when the group could not be sampled at all. The caller must
/// treat that as "no observation this tick" and never as zero, or an unsampleable
/// group would read as compliant.
#[cfg(all(unix, target_vendor = "apple"))]
pub(crate) fn owned_group_footprint_bytes(pid: Option<u32>) -> Option<u64> {
    // <sys/proc_info.h>. Not re-exported by `libc`, so it is restated here with
    // its header as the citation; `PROC_TTY_ONLY` is the adjacent value and
    // would silently enumerate a different set.
    const PROC_PGRP_ONLY: u32 = 2;
    const PID_BYTES: usize = std::mem::size_of::<libc::pid_t>();
    // The group may gain a member between sizing and filling; ask for a little
    // more than the kernel just reported so a fork mid-sample is still counted.
    const GROWTH_HEADROOM: usize = 8;

    let leader = pid.and_then(|value| i32::try_from(value).ok())?;
    let group = u32::try_from(leader).ok()?;

    // SAFETY: a null buffer with zero size is the documented way to ask
    // `proc_listpids` for the byte count it would write, and writes nothing.
    let needed = unsafe { libc::proc_listpids(PROC_PGRP_ONLY, group, std::ptr::null_mut(), 0) };
    if needed <= 0 {
        return None;
    }

    let capacity = usize::try_from(needed).ok()? / PID_BYTES + GROWTH_HEADROOM;
    let mut members = vec![0 as libc::pid_t; capacity];
    let buffer_bytes = libc::c_int::try_from(members.len() * PID_BYTES).ok()?;
    // SAFETY: the buffer is owned, live for the call, and its capacity is passed
    // in bytes exactly as the buffer was sized.
    let written = unsafe {
        libc::proc_listpids(
            PROC_PGRP_ONLY,
            group,
            members.as_mut_ptr().cast::<libc::c_void>(),
            buffer_bytes,
        )
    };
    if written <= 0 {
        return None;
    }
    let live = (usize::try_from(written).ok()? / PID_BYTES).min(members.len());

    let mut total: u64 = 0;
    let mut sampled = false;
    for member in members[..live].iter().copied().filter(|value| *value > 0) {
        let mut info = std::mem::MaybeUninit::<libc::rusage_info_v2>::zeroed();
        // SAFETY: `RUSAGE_INFO_V2` selects exactly `rusage_info_v2`, and the
        // buffer is a live owned allocation of that type. The C signature takes
        // `rusage_info_t *`, which is `void **`, so the cast is the documented
        // calling convention rather than a reinterpretation.
        let rc = unsafe {
            libc::proc_pid_rusage(
                member,
                libc::RUSAGE_INFO_V2,
                info.as_mut_ptr().cast::<libc::rusage_info_t>(),
            )
        };
        if rc != 0 {
            // A member that exited between listing and sampling is not an error;
            // it holds nothing. Skipping it keeps the sample valid for the rest.
            continue;
        }
        // SAFETY: `proc_pid_rusage` returned 0, so it initialised the buffer.
        let info = unsafe { info.assume_init() };
        total = total.saturating_add(info.ri_phys_footprint);
        sampled = true;
    }

    sampled.then_some(total)
}

#[cfg(not(all(unix, target_vendor = "apple")))]
pub(crate) fn owned_group_footprint_bytes(_pid: Option<u32>) -> Option<u64> {
    None
}

#[cfg(unix)]
pub(crate) fn terminate_process_group(pid: Option<u32>) {
    let Some(pid) = pid.and_then(|value| i32::try_from(value).ok()) else {
        return;
    };
    let group = -pid;
    // SAFETY: the child was placed in a new process group whose leader is owned by the
    // guard. A negative pid addresses that exact group only.
    let delivered = unsafe { libc::kill(group, libc::SIGTERM) } == 0;
    if delivered {
        thread::sleep(TERMINATION_GRACE);
        // SAFETY: same exact owned process group; SIGKILL is the bounded backstop.
        unsafe {
            libc::kill(group, libc::SIGKILL);
        }
    }
}

/// Observe an owned child without reaping it. Keeping the exited leader waitable pins
/// its pid/process-group identity until descendant cleanup has been issued.
#[cfg(unix)]
pub(crate) fn observe_owned_child_exit(pid: Option<u32>) -> Result<bool, ()> {
    let Some(pid) = pid.and_then(|value| libc::id_t::try_from(value).ok()) else {
        return Err(());
    };
    let mut information = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    loop {
        // SAFETY: `information` points to writable storage for one siginfo record. The
        // owned child is observed with WNOWAIT so this call cannot release its identity.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid,
                information.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == 0 {
            // SAFETY: successful waitid initialized the siginfo record. POSIX specifies
            // si_pid == 0 when WNOHANG finds no waitable state change.
            return Ok(unsafe { information.assume_init().si_pid() } != 0);
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(());
        }
    }
}

/// Clean descendants while the exited process-group leader is still waitable. The
/// unreaped leader pins the exact pid/group id, eliminating signal delivery to a reused
/// unrelated process group.
#[cfg(unix)]
pub(crate) fn terminate_exited_process_group_before_reap(pid: Option<u32>) {
    let Some(pid) = pid.and_then(|value| i32::try_from(value).ok()) else {
        return;
    };
    // SAFETY: the waitable owned leader still pins this exact process-group identity.
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
}

#[cfg(not(unix))]
pub(crate) fn observe_owned_child_exit(_pid: Option<u32>) -> Result<bool, ()> {
    Err(())
}

#[cfg(not(unix))]
pub(crate) fn terminate_exited_process_group_before_reap(_pid: Option<u32>) {}

#[cfg(not(unix))]
pub(crate) fn terminate_process_group(_pid: Option<u32>) {}

fn raw_terminal(
    terminal: GovernedExecutionTerminal,
    dispatch: GovernedExecutionDispatch,
    exit_code: Option<i32>,
    elapsed: Duration,
    stdout: Zeroizing<Vec<u8>>,
    stderr: Zeroizing<Vec<u8>>,
) -> GovernedRawBatchExecution {
    raw_terminal_with_truncation(
        terminal, dispatch, exit_code, elapsed, stdout, stderr, false, false,
    )
}

#[allow(clippy::too_many_arguments)]
fn raw_terminal_with_truncation(
    terminal: GovernedExecutionTerminal,
    dispatch: GovernedExecutionDispatch,
    exit_code: Option<i32>,
    elapsed: Duration,
    stdout: Zeroizing<Vec<u8>>,
    stderr: Zeroizing<Vec<u8>>,
    stdout_truncated: bool,
    stderr_truncated: bool,
) -> GovernedRawBatchExecution {
    let terminal = GovernedExecutionTerminalState::executor_owned(terminal, dispatch);
    GovernedRawBatchExecution {
        terminal,
        exit_code,
        elapsed,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        output_retention: None,
    }
}

fn validate_environment(
    environment: &[(String, Zeroizing<Vec<u8>>)],
) -> Result<(), GovernedBatchProcessError> {
    let mut previous: Option<&str> = None;
    let mut total = 0usize;
    for (name, value) in environment {
        if name.is_empty()
            || name.contains('=')
            || name.as_bytes().contains(&0)
            || value.contains(&0)
            || previous.is_some_and(|prior| prior >= name.as_str())
        {
            return Err(invalid_environment());
        }
        total = total
            .checked_add(name.len())
            .and_then(|value_size| value_size.checked_add(value.len()))
            .ok_or_else(invalid_environment)?;
        if total > crate::credential_materialization::MAX_CHILD_ENVIRONMENT_TOTAL_BYTES {
            return Err(invalid_environment());
        }
        previous = Some(name);
    }
    Ok(())
}

#[cfg(unix)]
fn apply_jail_rlimits(limits: GovernedProcessJailLimits) -> std::io::Result<()> {
    macro_rules! apply {
        ($resource:expr, $value:expr) => {{
            let value = libc::rlim_t::try_from($value)
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
            let limit = libc::rlimit {
                rlim_cur: value,
                rlim_max: value,
            };
            // SAFETY: the resource is a fixed RLIMIT constant and `limit` is
            // a live initialized structure for the duration of the call.
            if unsafe { libc::setrlimit($resource, &limit) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }};
    }

    apply!(libc::RLIMIT_CPU, limits.cpu_seconds);
    apply!(libc::RLIMIT_NOFILE, limits.max_open_files);
    apply!(libc::RLIMIT_FSIZE, limits.max_file_bytes);
    // Linux enforces this against the real UID. Existing same-UID processes
    // can only make the bound stricter (new forks fail sooner), never allow the
    // jailed group to exceed it. macOS denies process-fork in SBPL instead;
    // its RLIMIT_NPROC is also user-wide and adds no useful precision there.
    #[cfg(target_os = "linux")]
    apply!(libc::RLIMIT_NPROC, limits.max_processes);
    Ok(())
}

fn observe_jail_limits(
    pid: Option<u32>,
    watch: &GovernedProcessJailWatch,
) -> Result<Option<GovernedExecutionTerminal>, ()> {
    if !watch.workdir_within_limits()? {
        return Ok(Some(GovernedExecutionTerminal::FileLimitExceeded));
    }
    let usage = owned_group_usage(pid).ok_or(())?;
    let limits = watch.limits();
    if usage.processes > limits.max_processes {
        return Ok(Some(GovernedExecutionTerminal::ProcessLimitExceeded));
    }
    if usage.cpu_micros > limits.cpu_seconds.saturating_mul(1_000_000) {
        return Ok(Some(GovernedExecutionTerminal::CpuLimitExceeded));
    }
    if usage.memory_bytes > limits.max_memory_bytes {
        return Ok(Some(GovernedExecutionTerminal::MemoryLimitExceeded));
    }
    Ok(None)
}

struct OwnedGroupUsage {
    processes: u64,
    cpu_micros: u64,
    memory_bytes: u64,
}

#[cfg(target_os = "macos")]
fn owned_group_usage(pid: Option<u32>) -> Option<OwnedGroupUsage> {
    const PROC_PGRP_ONLY: u32 = 2;
    const PID_BYTES: usize = std::mem::size_of::<libc::pid_t>();
    const GROWTH_HEADROOM: usize = 8;
    const MAX_OBSERVED_GROUP_MEMBERS: usize = MAX_GOVERNED_JAIL_PROCESSES as usize + 1;

    let leader = pid.and_then(|value| i32::try_from(value).ok())?;
    let group = u32::try_from(leader).ok()?;
    // SAFETY: a null buffer and zero size is the documented sizing query.
    let needed = unsafe { libc::proc_listpids(PROC_PGRP_ONLY, group, std::ptr::null_mut(), 0) };
    if needed <= 0 {
        return None;
    }
    let reported = usize::try_from(needed).ok()? / PID_BYTES;
    if reported > MAX_OBSERVED_GROUP_MEMBERS {
        return Some(OwnedGroupUsage {
            processes: reported as u64,
            cpu_micros: 0,
            memory_bytes: 0,
        });
    }
    let capacity = reported.saturating_add(GROWTH_HEADROOM);
    let mut members = vec![0 as libc::pid_t; capacity];
    let buffer_bytes = libc::c_int::try_from(members.len().checked_mul(PID_BYTES)?).ok()?;
    // SAFETY: `members` is a live writable pid buffer sized in bytes.
    let written = unsafe {
        libc::proc_listpids(
            PROC_PGRP_ONLY,
            group,
            members.as_mut_ptr().cast::<libc::c_void>(),
            buffer_bytes,
        )
    };
    if written <= 0 {
        return None;
    }
    let live = (usize::try_from(written).ok()? / PID_BYTES).min(members.len());
    let mut processes = 0_u64;
    let mut cpu_nanos = 0_u64;
    let mut memory_bytes = 0_u64;
    for member in members[..live].iter().copied().filter(|value| *value > 0) {
        let mut info = std::mem::MaybeUninit::<libc::rusage_info_v2>::zeroed();
        // SAFETY: RUSAGE_INFO_V2 selects exactly this initialized output type.
        let rc = unsafe {
            libc::proc_pid_rusage(
                member,
                libc::RUSAGE_INFO_V2,
                info.as_mut_ptr().cast::<libc::rusage_info_t>(),
            )
        };
        if rc != 0 {
            continue;
        }
        // SAFETY: the successful kernel call initialized `info`.
        let info = unsafe { info.assume_init() };
        processes = processes.saturating_add(1);
        cpu_nanos = cpu_nanos
            .saturating_add(info.ri_user_time)
            .saturating_add(info.ri_system_time);
        memory_bytes = memory_bytes.saturating_add(info.ri_phys_footprint);
    }
    (processes > 0).then_some(OwnedGroupUsage {
        processes,
        cpu_micros: cpu_nanos / 1_000,
        memory_bytes,
    })
}

#[cfg(target_os = "linux")]
fn owned_group_usage(pid: Option<u32>) -> Option<OwnedGroupUsage> {
    const MAX_PROC_ENTRIES: usize = 65_536;
    let group = i64::from(pid?);
    // SAFETY: sysconf is read-only and `_SC_CLK_TCK` has no pointer argument.
    let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    // SAFETY: sysconf is read-only and `_SC_PAGESIZE` has no pointer argument.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if ticks_per_second <= 0 || page_size <= 0 {
        return None;
    }
    let mut processes = 0_u64;
    let mut cpu_ticks = 0_u64;
    let mut resident_pages = 0_u64;
    let mut visited = 0_usize;
    for entry in std::fs::read_dir("/proc").ok()? {
        let entry = entry.ok()?;
        if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        visited = visited.checked_add(1)?;
        if visited > MAX_PROC_ENTRIES {
            return None;
        }
        let stat = match std::fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(_) => continue,
        };
        let tail = match stat.rsplit_once(')') {
            Some((_, tail)) => tail.trim(),
            None => continue,
        };
        let fields = tail.split_whitespace().collect::<Vec<_>>();
        if fields.len() <= 12 || fields[2].parse::<i64>().ok() != Some(group) {
            continue;
        }
        let user = fields[11].parse::<u64>().ok()?;
        let system = fields[12].parse::<u64>().ok()?;
        processes = processes.saturating_add(1);
        cpu_ticks = cpu_ticks.saturating_add(user).saturating_add(system);
        // A process that exits after its stat sample holds no resident pages;
        // otherwise a malformed statm loses the required observation.
        match std::fs::read_to_string(entry.path().join("statm")) {
            Ok(statm) => {
                let resident = statm.split_whitespace().nth(1)?.parse::<u64>().ok()?;
                resident_pages = resident_pages.saturating_add(resident);
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(_) => return None,
        }
    }
    (processes > 0).then_some(OwnedGroupUsage {
        processes,
        cpu_micros: cpu_ticks.saturating_mul(1_000_000) / ticks_per_second as u64,
        memory_bytes: resident_pages.saturating_mul(page_size as u64),
    })
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn owned_group_usage(_pid: Option<u32>) -> Option<OwnedGroupUsage> {
    None
}

#[cfg(unix)]
fn bytes_as_os_str(value: &[u8]) -> Result<&OsStr, GovernedBatchProcessError> {
    if value.contains(&0) {
        return Err(invalid_environment());
    }
    Ok(OsStr::from_bytes(value))
}

#[cfg(not(unix))]
fn bytes_as_os_str(_value: &[u8]) -> Result<&OsStr, GovernedBatchProcessError> {
    Err(invalid_environment())
}

fn authority_changed(_error: GovernedExecutionAuthorityError) -> GovernedBatchProcessError {
    GovernedBatchProcessError::new(
        GovernedBatchProcessErrorCode::AuthorityChanged,
        "authority",
        "executable or working-directory authority changed before execution",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn wrong_interaction() -> GovernedBatchProcessError {
    GovernedBatchProcessError::new(
        GovernedBatchProcessErrorCode::WrongInteraction,
        "interaction",
        "the batch executor cannot accept an interactive PTY contract",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn capacity_exceeded() -> GovernedBatchProcessError {
    GovernedBatchProcessError::new(
        GovernedBatchProcessErrorCode::CapacityExceeded,
        "process_capacity",
        "the process-wide governed execution capacity is exhausted",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn invalid_environment() -> GovernedBatchProcessError {
    GovernedBatchProcessError::new(
        GovernedBatchProcessErrorCode::InvalidEnvironment,
        "environment",
        "the sealed child environment is invalid or exceeds its aggregate ceiling",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn spawn_failed() -> GovernedBatchProcessError {
    GovernedBatchProcessError::new(
        GovernedBatchProcessErrorCode::SpawnFailed,
        "process",
        "the governed child process could not be started",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn unenforceable_memory_limit() -> GovernedBatchProcessError {
    GovernedBatchProcessError::new(
        GovernedBatchProcessErrorCode::UnenforceableMemoryLimit,
        "runtime.limits.memory_bytes",
        "this host cannot enforce the declared process memory limit",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn stream_unavailable() -> GovernedBatchProcessError {
    GovernedBatchProcessError::new(
        GovernedBatchProcessErrorCode::StreamUnavailable,
        "process_stream",
        "a required governed process stream is unavailable",
        GovernedExecutionDispatch::UnknownAfterDispatch,
    )
}

const fn stream_write_failed() -> GovernedBatchProcessError {
    GovernedBatchProcessError::new(
        GovernedBatchProcessErrorCode::StreamWriteFailed,
        "stdin",
        "the bounded process input stream failed",
        GovernedExecutionDispatch::Dispatched,
    )
}

const fn stream_read_failed() -> GovernedBatchProcessError {
    GovernedBatchProcessError::new(
        GovernedBatchProcessErrorCode::StreamReadFailed,
        "process_output",
        "a bounded process output stream failed",
        GovernedExecutionDispatch::UnknownAfterDispatch,
    )
}

const fn process_wait_failed() -> GovernedBatchProcessError {
    GovernedBatchProcessError::new(
        GovernedBatchProcessErrorCode::ProcessWaitFailed,
        "process",
        "the governed child process could not be reaped deterministically",
        GovernedExecutionDispatch::UnknownAfterDispatch,
    )
}

const fn reader_shutdown_failed() -> GovernedBatchProcessError {
    GovernedBatchProcessError::new(
        GovernedBatchProcessErrorCode::ReaderShutdownFailed,
        "process_output",
        "a bounded process reader could not be joined",
        GovernedExecutionDispatch::UnknownAfterDispatch,
    )
}

const fn jail_unavailable() -> GovernedBatchProcessError {
    GovernedBatchProcessError::new(
        GovernedBatchProcessErrorCode::JailUnavailable,
        "jail",
        "the strict process jail could not build a safe host command",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn jail_watch_failed() -> GovernedBatchProcessError {
    GovernedBatchProcessError::new(
        GovernedBatchProcessErrorCode::JailUnavailable,
        "jail.watchdog",
        "the strict process jail lost a required resource observation",
        GovernedExecutionDispatch::UnknownAfterDispatch,
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fmt, fs, path::PathBuf, sync::Mutex};

    #[cfg(unix)]
    use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt, io::AsRawFd, net::UnixStream};

    use serde::Serialize;
    use static_assertions::assert_not_impl_any;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        credential_injection::{ChildEnvironmentBaseline, ChildEnvironmentVariable},
        credential_materialization::ChildEnvironmentValues,
        governed_execution::{
            GovernedExecutionContract, GovernedExecutionPolicy, GovernedExecutionRequest,
        },
        governed_execution_authority::{GovernedExecutionAuthority, GovernedWorkingDirectoryRoot},
        manifest::{
            AuthContract, CliInteraction, PolicyFloor, RuntimeLimits, RuntimeProtocol,
            RuntimeRequirements, SkillRuntimeContract, SkillRuntimeContractVersion, StdinContract,
            StdinMode, WorkingDirectoryContract, WorkingDirectoryMode,
        },
        manifest_validation::validate_skill_runtime_contract,
    };

    static TEST_PROCESS_BUDGET: Mutex<()> = Mutex::new(());

    struct Fixture {
        _root: TempDir,
        bin: PathBuf,
        workspace: PathBuf,
    }

    impl Fixture {
        fn new(script: &[u8]) -> Self {
            let root = tempfile::tempdir().unwrap();
            let bin = root.path().join("bin");
            let workspace = root.path().join("workspace");
            fs::create_dir(&bin).unwrap();
            fs::create_dir(&workspace).unwrap();
            let executable = bin.join("fixture-cli");
            fs::write(&executable, script).unwrap();
            #[cfg(unix)]
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
            Self {
                _root: root,
                bin,
                workspace,
            }
        }

        fn process(
            &self,
            args: Vec<String>,
            stdin: Option<Vec<u8>>,
            timeout_secs: u32,
            stdout_bytes: u64,
            stderr_bytes: u64,
        ) -> GovernedBatchProcess {
            self.process_with_memory(args, stdin, timeout_secs, stdout_bytes, stderr_bytes, None)
                .unwrap()
        }

        /// The same fixture with a declared `runtime.limits.memory_bytes`.
        ///
        /// The result is deliberately returned rather than unwrapped: whether a
        /// declared ceiling can be accepted at all is the platform's answer, and
        /// the caller has to be able to see both of them.
        #[allow(clippy::too_many_arguments)]
        fn process_with_memory(
            &self,
            args: Vec<String>,
            stdin: Option<Vec<u8>>,
            timeout_secs: u32,
            stdout_bytes: u64,
            stderr_bytes: u64,
            memory_bytes: Option<u64>,
        ) -> Result<GovernedBatchProcess, GovernedBatchProcessError> {
            let authored = SkillRuntimeContract {
                schema_version: SkillRuntimeContractVersion::v1(),
                requires: RuntimeRequirements {
                    bins: BTreeSet::from(["fixture-cli".to_owned()]),
                    entrypoint: Default::default(),
                    environment: Default::default(),
                },
                runtime: RuntimeProtocol::Cli {
                    command_prefix: vec!["fixed token".to_owned()],
                    interaction: CliInteraction::Batch,
                    stdin: StdinContract {
                        mode: StdinMode::Optional,
                        sensitivity: Default::default(),
                    },
                    working_directory: WorkingDirectoryContract {
                        mode: WorkingDirectoryMode::Workspace,
                    },
                    limits: RuntimeLimits {
                        timeout_secs: Some(timeout_secs),
                        stdin_bytes: Some(64 * 1024),
                        stdout_bytes: Some(stdout_bytes),
                        stderr_bytes: Some(stderr_bytes),
                        memory_bytes,
                    },
                },
                auth: AuthContract::default(),
                policy_floor: PolicyFloor::default(),
            };
            let contract = GovernedExecutionContract::compile(
                validate_skill_runtime_contract(&authored).unwrap(),
                GovernedExecutionPolicy::new(
                    timeout_secs,
                    timeout_secs,
                    64 * 1024,
                    stdout_bytes,
                    stderr_bytes,
                )
                .unwrap(),
            )
            .unwrap();
            let intent = contract
                .admit(GovernedExecutionRequest::new(
                    args,
                    stdin,
                    None,
                    Some(timeout_secs),
                ))
                .unwrap();
            let baseline = ChildEnvironmentBaseline::portable_cli();
            let mut values = ChildEnvironmentValues::new(&baseline);
            values
                .provide(
                    ChildEnvironmentVariable::Path,
                    self.bin.as_os_str().as_bytes().to_vec(),
                )
                .unwrap();
            values
                .provide(ChildEnvironmentVariable::Lang, b"C.UTF-8".to_vec())
                .unwrap();
            let root = GovernedWorkingDirectoryRoot::open(
                WorkingDirectoryMode::Workspace,
                &self.workspace,
            )
            .unwrap();
            let authority =
                GovernedExecutionAuthority::bind(intent, &baseline, values, Some(root)).unwrap();
            let parts = authority.into_parts();
            let mut environment = parts
                .environment
                .iter()
                .map(|(name, value)| (name.as_str().to_owned(), value.clone()))
                .collect::<Vec<_>>();
            environment.sort_by(|left, right| left.0.cmp(&right.0));
            GovernedBatchProcess::from_authorized_parts(parts, environment)
        }
    }

    #[test]
    fn exact_args_cwd_stdin_and_clean_environment_reach_the_child_inertly() {
        let _budget = TEST_PROCESS_BUDGET.lock().unwrap();
        let fixture = Fixture::new(
            b"#!/bin/sh\nprintf 'ARG=<%s>\\n' \"$@\"\nprintf 'PWD=<%s>\\n' \"$PWD\"\nprintf 'HOME=<%s>\\n' \"${HOME-unset}\"\n/bin/cat\n",
        );
        let process = fixture.process(
            vec![
                "two words".to_owned(),
                "हैलो".to_owned(),
                "$(touch should-not-exist);|&<>".to_owned(),
                String::new(),
            ],
            Some(b"stdin-value".to_vec()),
            5,
            64 * 1024,
            64 * 1024,
        );
        let result =
            GovernedBatchExecutor::execute(process, &GovernedBatchCancellation::new()).unwrap();
        assert_eq!(
            result.terminal().terminal(),
            GovernedExecutionTerminal::Success
        );
        let parts = result.into_parts();
        let (stdout, stderr) = (parts.stdout, parts.stderr);
        let text = String::from_utf8(stdout.to_vec()).unwrap();
        assert!(text.contains("ARG=<fixed token>"));
        assert!(text.contains("ARG=<two words>"));
        assert!(text.contains("ARG=<हैलो>"));
        assert!(text.contains("ARG=<$(touch should-not-exist);|&<>>"));
        assert!(text.contains("ARG=<>"));
        assert!(text.contains(fixture.workspace.to_string_lossy().as_ref()));
        assert!(text.contains("HOME=<unset>"));
        assert!(text.ends_with("stdin-value"));
        assert!(stderr.is_empty());
        assert!(!fixture.workspace.join("should-not-exist").exists());
    }

    #[test]
    fn pre_cancelled_execution_never_spawns() {
        let _budget = TEST_PROCESS_BUDGET.lock().unwrap();
        let fixture = Fixture::new(b"#!/bin/sh\n/usr/bin/touch marker\n");
        let process = fixture.process(vec![], None, 5, 1024, 1024);
        let cancellation = GovernedBatchCancellation::new();
        cancellation.cancel();
        let result = GovernedBatchExecutor::execute(process, &cancellation).unwrap();
        assert_eq!(
            result.terminal().dispatch(),
            GovernedExecutionDispatch::NotDispatched
        );
        assert!(!fixture.workspace.join("marker").exists());
    }

    #[test]
    fn fast_exit_is_reaped_after_both_output_readers_close() {
        let _budget = TEST_PROCESS_BUDGET.lock().unwrap();
        let fixture = Fixture::new(b"#!/bin/sh\nprintf ok\n");
        let process = fixture.process(vec![], None, 5, 1024, 1024);
        let result =
            GovernedBatchExecutor::execute(process, &GovernedBatchCancellation::new()).unwrap();
        assert_eq!(
            result.terminal().terminal(),
            GovernedExecutionTerminal::Success
        );
        assert_eq!(result.stdout.as_slice(), b"ok");
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn jailed_fast_exit_is_reaped_before_first_resource_sample() {
        let _budget = TEST_PROCESS_BUDGET.lock().unwrap();
        let jail = match GovernedProcessJail::strict_app(GovernedProcessJailLimits::default()) {
            Ok(jail) => jail,
            Err(error)
                if matches!(
                    error.code,
                    crate::governed_process_jail::GovernedProcessJailErrorCode::LauncherUnavailable
                        | crate::governed_process_jail::GovernedProcessJailErrorCode::UnsupportedPlatform
                ) =>
            {
                return;
            },
            Err(error) => panic!("unexpected strict jail setup failure: {error}"),
        };
        let authored = SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires: RuntimeRequirements {
                bins: BTreeSet::from(["true".to_owned()]),
                entrypoint: Default::default(),
                environment: Default::default(),
            },
            runtime: RuntimeProtocol::Cli {
                command_prefix: Vec::new(),
                interaction: CliInteraction::Batch,
                stdin: StdinContract {
                    mode: StdinMode::Denied,
                    sensitivity: Default::default(),
                },
                working_directory: WorkingDirectoryContract {
                    mode: WorkingDirectoryMode::Workspace,
                },
                limits: RuntimeLimits {
                    timeout_secs: Some(5),
                    stdin_bytes: None,
                    stdout_bytes: Some(1024),
                    stderr_bytes: Some(1024),
                    memory_bytes: None,
                },
            },
            auth: AuthContract::default(),
            policy_floor: PolicyFloor::default(),
        };
        let contract = GovernedExecutionContract::compile(
            validate_skill_runtime_contract(&authored).unwrap(),
            GovernedExecutionPolicy::new(5, 5, 1024, 1024, 1024).unwrap(),
        )
        .unwrap();
        let intent = contract
            .admit(GovernedExecutionRequest::new(
                Vec::new(),
                None,
                None,
                Some(5),
            ))
            .unwrap();
        let baseline = ChildEnvironmentBaseline::portable_cli();
        let mut values = ChildEnvironmentValues::new(&baseline);
        values
            .provide(ChildEnvironmentVariable::Path, b"/usr/bin:/bin".to_vec())
            .unwrap();
        values
            .provide(ChildEnvironmentVariable::Lang, b"C.UTF-8".to_vec())
            .unwrap();
        let root = jail
            .working_directory_root(WorkingDirectoryMode::Workspace)
            .unwrap();
        let authority =
            GovernedExecutionAuthority::bind(intent, &baseline, values, Some(root)).unwrap();
        let parts = authority.into_parts();
        let mut environment = parts
            .environment
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect::<Vec<_>>();
        environment.sort_by(|left, right| left.0.cmp(&right.0));
        let process =
            GovernedBatchProcess::from_authorized_parts_in_jail(parts, environment, jail).unwrap();
        let result =
            GovernedBatchExecutor::execute(process, &GovernedBatchCancellation::new()).unwrap();
        assert_eq!(
            result.terminal().terminal(),
            GovernedExecutionTerminal::Success,
            "stderr={}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    #[test]
    fn sealed_process_rejects_environment_drift_from_executable_authority() {
        let fixture = Fixture::new(b"#!/bin/sh\nexit 0\n");
        let process = fixture.process(vec![], None, 5, 1024, 1024);
        let GovernedBatchProcess {
            authority,
            mut environment,
            ..
        } = process;
        let (_, path) = environment
            .iter_mut()
            .find(|(name, _)| name == "PATH")
            .expect("fixture PATH");
        **path = b"/unrelated".to_vec();
        assert_eq!(
            GovernedBatchProcess::from_authorized_parts(authority, environment)
                .err()
                .expect("baseline drift must fail")
                .code,
            GovernedBatchProcessErrorCode::InvalidEnvironment
        );
    }

    #[test]
    fn timeout_terminates_the_owned_process_group() {
        let _budget = TEST_PROCESS_BUDGET.lock().unwrap();
        let fixture = Fixture::new(b"#!/bin/sh\n/bin/sleep 60 &\necho $! > child.pid\nwait\n");
        // Leave enough launch budget for a heavily loaded CI host to schedule the
        // shell through creation of the descendant PID marker. The assertion still
        // exercises executor-owned timeout termination rather than test cancellation.
        let process = fixture.process(vec![], None, 3, 1024, 1024);
        let result =
            GovernedBatchExecutor::execute(process, &GovernedBatchCancellation::new()).unwrap();
        assert_eq!(
            result.terminal().terminal(),
            GovernedExecutionTerminal::TimedOut
        );
        #[cfg(unix)]
        {
            let pid = fs::read_to_string(fixture.workspace.join("child.pid"))
                .unwrap()
                .trim()
                .parse::<i32>()
                .unwrap();
            let gone = (0..50).any(|_| {
                // SAFETY: signal zero performs no mutation and only checks liveness.
                if unsafe { libc::kill(pid, 0) } != 0 {
                    true
                } else {
                    std::thread::sleep(Duration::from_millis(20));
                    false
                }
            });
            assert!(gone, "owned descendant survived bounded termination");
        }
    }

    #[test]
    fn cancellation_after_spawn_terminates_and_reaps_the_owned_group() {
        let _budget = TEST_PROCESS_BUDGET.lock().unwrap();
        let fixture = Fixture::new(b"#!/bin/sh\n/usr/bin/touch started\n/bin/sleep 60\n");
        let process = fixture.process(vec![], None, 5, 1024, 1024);
        let cancellation = GovernedBatchCancellation::new();
        let trigger = cancellation.clone();
        let workspace = fixture.workspace.clone();
        let canceller = std::thread::Builder::new()
            .name("governed-batch-test-canceller".to_owned())
            .spawn(move || {
                for _ in 0..100 {
                    if workspace.join("started").exists() {
                        trigger.cancel();
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                trigger.cancel();
            })
            .unwrap();
        let result = GovernedBatchExecutor::execute(process, &cancellation).unwrap();
        canceller.join().unwrap();
        assert_eq!(
            result.terminal().terminal(),
            GovernedExecutionTerminal::Cancelled
        );
        assert_eq!(
            result.terminal().dispatch(),
            GovernedExecutionDispatch::Dispatched
        );
    }

    #[test]
    fn output_bomb_is_bounded_and_terminates_the_tree() {
        let _budget = TEST_PROCESS_BUDGET.lock().unwrap();
        let fixture = Fixture::new(b"#!/bin/sh\nwhile :; do printf '0123456789'; done\n");
        let process = fixture.process(vec![], None, 5, 1024, 1024);
        let result =
            GovernedBatchExecutor::execute(process, &GovernedBatchCancellation::new()).unwrap();
        assert_eq!(
            result.terminal().terminal(),
            GovernedExecutionTerminal::OutputLimitExceeded
        );
        assert!(result.stdout_bytes() <= 1024);
    }

    #[test]
    fn an_expired_total_deadline_prevents_dispatch() {
        let _budget = TEST_PROCESS_BUDGET.lock().unwrap();
        let fixture = Fixture::new(b"#!/bin/sh\nprintf should-not-run\n");
        let process = fixture.process(vec![], None, 5, 1024, 1024);
        let result = GovernedBatchExecutor::execute_until(
            process,
            &GovernedBatchCancellation::new(),
            Instant::now() - Duration::from_millis(1),
        )
        .unwrap();
        assert_eq!(
            result.terminal().terminal(),
            GovernedExecutionTerminal::TimedOut
        );
        assert_eq!(
            result.terminal().dispatch(),
            GovernedExecutionDispatch::NotDispatched
        );
    }

    #[test]
    fn process_and_output_reservations_are_exact_and_released() {
        const ISOLATED_CAPACITY_ENV: &str = "TOOL_RUNTIME_CORE_ISOLATED_CAPACITY_TEST";
        if std::env::var_os(ISOLATED_CAPACITY_ENV).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("governed_batch_process::tests::process_and_output_reservations_are_exact_and_released")
                .arg("--exact")
                .env(ISOLATED_CAPACITY_ENV, "1")
                .status()
                .unwrap();
            assert!(status.success(), "isolated governed-capacity proof failed");
            return;
        }
        let _budget = TEST_PROCESS_BUDGET.lock().unwrap();
        let mut permits = Vec::new();
        for _ in 0..MAX_CONCURRENT_GOVERNED_PROCESSES {
            permits.push(GovernedProcessPermit::acquire(1, 0).unwrap());
        }
        assert_eq!(
            GovernedProcessPermit::acquire(1, 0)
                .err()
                .expect("process capacity must fail")
                .code,
            GovernedBatchProcessErrorCode::CapacityExceeded
        );
        drop(permits);
        let full = GovernedProcessPermit::acquire(MAX_RESERVED_GOVERNED_OUTPUT_BYTES, 0).unwrap();
        assert_eq!(
            GovernedProcessPermit::acquire(1, 0)
                .err()
                .expect("output reservation capacity must fail")
                .code,
            GovernedBatchProcessErrorCode::CapacityExceeded
        );
        let retained = full.into_output_retention();
        assert_eq!(
            GovernedProcessPermit::acquire(1, 0)
                .err()
                .expect("retained raw output must continue consuming the output budget")
                .code,
            GovernedBatchProcessErrorCode::CapacityExceeded
        );
        drop(retained);
        assert!(GovernedProcessPermit::acquire(1, 0).is_ok());

        let half_memory = MAX_RESERVED_GOVERNED_MEMORY_BYTES / 2;
        let first = GovernedProcessPermit::acquire(1, half_memory).unwrap();
        let second = GovernedProcessPermit::acquire(1, half_memory).unwrap();
        assert_eq!(
            GovernedProcessPermit::acquire(1, 1)
                .err()
                .expect("memory reservation capacity must fail")
                .code,
            GovernedBatchProcessErrorCode::CapacityExceeded
        );
        drop((first, second));
        assert!(GovernedProcessPermit::acquire(1, half_memory).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn stopped_batch_stdin_writer_cannot_block_on_a_saturated_peer() {
        let (writer, _non_reading_peer) = UnixStream::pair().unwrap();
        let raw_fd = writer.as_raw_fd();
        let writer = spawn_stdin_writer(
            writer,
            Some(raw_fd),
            Zeroizing::new(vec![b'x'; 8 * 1024 * 1024]),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(40));
        let started = Instant::now();
        let result = stop_and_join_stdin_writer(writer).expect("writer thread must join");
        assert!(result.is_ok());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// A declared memory ceiling is either applied to the child or refused. It is
    /// never quietly dropped.
    ///
    /// Both outcomes below are correct and the platform picks which: a host whose
    /// `RLIMIT_AS` is a real address-space limit accepts the contract and holds the
    /// child to it, and a host whose kernel cannot express the bound refuses to
    /// build an executable capability at all. The outcome this rejects is the
    /// third one — a child that runs happily while the ceiling its manifest
    /// declares does not exist anywhere.
    ///
    /// The result is matched rather than unwrapped on purpose.
    /// `GovernedBatchProcess` implements neither `Clone`, `Debug`, nor `Serialize`
    /// (asserted at the foot of this module), so `unwrap_err`/`expect_err` — which
    /// need `T: Debug` — do not compile against it.
    #[test]
    fn a_declared_memory_limit_is_either_enforced_or_refused_never_dropped() {
        let _budget = TEST_PROCESS_BUDGET.lock().unwrap();
        let fixture = Fixture::new(b"#!/bin/sh\nprintf ok\n");
        match fixture.process_with_memory(vec![], None, 5, 1024, 1024, Some(256 * 1024 * 1024)) {
            Ok(process) => {
                assert!(
                    process_memory_limits_are_enforceable(),
                    "a host that cannot apply the bound must refuse the contract, not \
                     accept it and run without one"
                );
                let result =
                    GovernedBatchExecutor::execute(process, &GovernedBatchCancellation::new())
                        .unwrap();
                assert_eq!(
                    result.terminal().terminal(),
                    GovernedExecutionTerminal::Success
                );
                assert_eq!(result.stdout.as_slice(), b"ok");
            },
            Err(error) => {
                assert!(
                    !process_memory_limits_are_enforceable(),
                    "a host that can apply the bound must accept the contract"
                );
                assert_eq!(
                    error.code,
                    GovernedBatchProcessErrorCode::UnenforceableMemoryLimit
                );
                // Refused before any child exists, so the caller may retry or
                // report without wondering what ran.
                assert_eq!(error.dispatch(), GovernedExecutionDispatch::NotDispatched);
            },
        }
    }

    /// An undeclared memory limit is unaffected on every platform: the refusal
    /// above is keyed on the declaration, not on the host alone.
    #[test]
    fn a_contract_without_a_memory_limit_runs_on_every_platform() {
        let _budget = TEST_PROCESS_BUDGET.lock().unwrap();
        let fixture = Fixture::new(b"#!/bin/sh\nprintf ok\n");
        match fixture.process_with_memory(vec![], None, 5, 1024, 1024, None) {
            Ok(process) => {
                let result =
                    GovernedBatchExecutor::execute(process, &GovernedBatchCancellation::new())
                        .unwrap();
                assert_eq!(
                    result.terminal().terminal(),
                    GovernedExecutionTerminal::Success
                );
            },
            Err(error) => panic!("a contract declaring no memory limit must build: {error}"),
        }
    }

    /// The platform predicate is measured against the kernel, not asserted against
    /// itself. A `cfg` that merely restated its own definition would keep agreeing
    /// after the underlying fact changed.
    #[cfg(unix)]
    #[test]
    fn the_memory_limit_capability_matches_what_the_kernel_accepts() {
        #[cfg(target_vendor = "apple")]
        {
            assert_eq!(
                memory_limit_enforcement(),
                MemoryLimitEnforcement::ParentFootprintWatchdog,
                "Darwin cannot bound a child's address space, so the ceiling is held \
                 from the parent instead of being refused"
            );
            assert_eq!(
                libc::RLIMIT_AS,
                libc::RLIMIT_RSS,
                "Darwin aliases the address-space resource onto the resident-set one"
            );
            let limit = libc::rlimit {
                rlim_cur: 4 * 1024 * 1024 * 1024,
                rlim_max: 4 * 1024 * 1024 * 1024,
            };
            // SAFETY: `limit` is a fully initialized `rlimit` and the pointer is
            // valid for the call. The call is expected to fail, and a failed
            // `setrlimit` changes nothing about this process.
            let outcome = unsafe { libc::setrlimit(libc::RLIMIT_AS, &limit) };
            assert_eq!(
                outcome, -1,
                "a finite address-space ceiling must be refused"
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINVAL)
            );
        }
        #[cfg(not(target_vendor = "apple"))]
        {
            assert_eq!(
                memory_limit_enforcement(),
                MemoryLimitEnforcement::KernelAddressSpace
            );
            assert_ne!(
                libc::RLIMIT_AS,
                libc::RLIMIT_RSS,
                "a target that aliases the address-space resource onto the resident-set \
                 one cannot bound a child's address space and must not claim to"
            );
        }
    }

    /// A group over its declared ceiling is terminated and reported as such.
    ///
    /// The child has to allocate for real: `manifest_validation` refuses any
    /// `memory_bytes` below 64 MiB, so a token ceiling that every process
    /// trivially exceeds is not expressible. The ceiling is therefore the
    /// contract floor and the child doubles a shell variable to roughly twice
    /// it, in POSIX shell so the test adds no interpreter dependency.
    ///
    /// The breach is caught either mid-doubling or during the sleep that holds
    /// the result, so it does not depend on winning a race with the sampler.
    /// `/bin/sleep 30` against a 10s timeout is deliberate: a watchdog that
    /// never fires surfaces as `TimedOut` after ten seconds rather than as a
    /// pass, which names the failure instead of hiding it.
    ///
    /// The distinct terminal is the point. A breach reported as `TimedOut` would
    /// tell an operator to raise the timeout on a process that was killed for
    /// what it held.
    #[cfg(all(unix, target_vendor = "apple"))]
    #[test]
    fn the_watchdog_terminates_a_group_past_its_declared_ceiling() {
        let _budget = TEST_PROCESS_BUDGET.lock().unwrap();
        // 2^27 bytes ≈ 128 MiB held in the shell's own heap, against a 64 MiB
        // ceiling.
        let fixture = Fixture::new(
            b"#!/bin/sh\ns=x\ni=0\nwhile [ $i -lt 27 ]; do\n  s=\"$s$s\"\n  i=$((i + 1))\ndone\n/bin/sleep 30\n",
        );
        let process = fixture
            .process_with_memory(vec![], None, 10, 1024, 1024, Some(64 * 1024 * 1024))
            .expect("Darwin holds the ceiling from the parent, so the contract must build");
        let result =
            GovernedBatchExecutor::execute(process, &GovernedBatchCancellation::new()).unwrap();
        assert_eq!(
            result.terminal().terminal(),
            GovernedExecutionTerminal::MemoryLimitExceeded,
            "a group over its ceiling must be reported for what it held, not as a timeout"
        );
    }

    /// The watchdog is not trigger-happy: a child comfortably inside its ceiling
    /// runs to completion and keeps its output.
    ///
    /// Without this, a watchdog that terminated unconditionally would still pass
    /// the breach test above.
    #[cfg(all(unix, target_vendor = "apple"))]
    #[test]
    fn the_watchdog_leaves_a_group_inside_its_ceiling_alone() {
        let _budget = TEST_PROCESS_BUDGET.lock().unwrap();
        let fixture = Fixture::new(b"#!/bin/sh\nprintf ok\n");
        let process = fixture
            .process_with_memory(vec![], None, 10, 1024, 1024, Some(4 * 1024 * 1024 * 1024))
            .expect("a generous ceiling must build");
        let result =
            GovernedBatchExecutor::execute(process, &GovernedBatchCancellation::new()).unwrap();
        assert_eq!(
            result.terminal().terminal(),
            GovernedExecutionTerminal::Success
        );
        assert_eq!(result.stdout.as_slice(), b"ok");
    }

    /// An unsampleable group yields no observation, never a compliant one.
    ///
    /// This is the direction that fails silently if inverted: were the reader to
    /// answer `Some(0)` for a group it could not see, every ceiling would read as
    /// satisfied and the watchdog would never fire again.
    #[cfg(all(unix, target_vendor = "apple"))]
    #[test]
    fn an_unsampleable_group_yields_no_observation_rather_than_zero() {
        assert_eq!(owned_group_footprint_bytes(None), None);
    }

    /// The enforceable path is unchanged: a declared ceiling still reaches the
    /// child before it execs its program.
    ///
    /// Compiled only where `RLIMIT_AS` is a real address-space resource, which is
    /// precisely the platform set the refusal above must leave alone. `ulimit -v`
    /// reports the inherited soft ceiling in KiB, so the child itself answers
    /// whether the bound arrived.
    #[cfg(all(unix, not(target_vendor = "apple")))]
    #[test]
    fn an_enforceable_memory_limit_reaches_the_child() {
        let _budget = TEST_PROCESS_BUDGET.lock().unwrap();
        let fixture = Fixture::new(b"#!/bin/sh\nulimit -v\n");
        let process =
            match fixture.process_with_memory(vec![], None, 5, 1024, 1024, Some(256 * 1024 * 1024))
            {
                Ok(process) => process,
                Err(error) => {
                    panic!("an enforceable target must accept a declared memory limit: {error}")
                },
            };
        let result =
            GovernedBatchExecutor::execute(process, &GovernedBatchCancellation::new()).unwrap();
        assert_eq!(
            result.terminal().terminal(),
            GovernedExecutionTerminal::Success
        );
        let parts = result.into_parts();
        let observed = String::from_utf8(parts.stdout.to_vec()).unwrap();
        assert_eq!(
            observed.trim(),
            (256 * 1024).to_string(),
            "the child must observe the declared address-space ceiling in KiB"
        );
    }

    assert_not_impl_any!(GovernedBatchProcess: Clone, fmt::Debug, Serialize);
    assert_not_impl_any!(GovernedRawBatchExecution: Clone, fmt::Debug, Serialize);
}
