//! Phase 6E bounded interactive PTY owner.
//!
//! PTY execution is a separate sealed capability. It cannot be constructed for a batch
//! contract and never falls back to the batch runner. Product bridges receive only
//! incrementally credential-redacted output.

use std::{
    error::Error,
    ffi::OsStr,
    fmt,
    io::{Read, Write},
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::{
    credential_materialization::{
        CredentialRedactedOutput, CredentialStreamingRedactor, CredentialValueRedactor,
    },
    governed_batch_process::{
        observe_owned_child_exit, set_nonblocking, terminate_exited_process_group_before_reap,
        terminate_process_group, GovernedBatchCancellation, GovernedOutputRetention,
        GovernedProcessPermit,
    },
    governed_execution::{
        GovernedExecutionDispatch, GovernedExecutionTerminal, GovernedExecutionTerminalState,
    },
    governed_execution_authority::{
        GovernedExecutableSnapshot, GovernedExecutionAuthorityError,
        GovernedExecutionAuthorityParts, GovernedWorkingDirectoryHandle,
    },
    manifest::CliInteraction,
};

pub const GOVERNED_PTY_PROCESS_V1: &str = "tool-runtime.governed-pty-process.v1";
pub const MAX_GOVERNED_PTY_INPUT_EVENT_BYTES: usize = 64 * 1024;
pub const MAX_GOVERNED_PTY_TOTAL_INPUT_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_GOVERNED_PTY_IDLE_DECISIONS: u32 = 128;
pub const MAX_GOVERNED_PTY_ROWS: u16 = 500;
pub const MAX_GOVERNED_PTY_COLUMNS: u16 = 1000;
const PTY_STREAM_CHUNK_BYTES: usize = 16 * 1024;
const PTY_STREAM_CHANNEL_DEPTH: usize = 32;
const PTY_INPUT_CHANNEL_DEPTH: usize = 8;
const PTY_IO_THREAD_STACK_BYTES: usize = 256 * 1024;
const PTY_POLL_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedPtyErrorCode {
    WrongInteraction,
    InvalidPolicy,
    InvalidSize,
    InvalidInput,
    InputLimitExceeded,
    AuthorityChanged,
    CapacityExceeded,
    InvalidEnvironment,
    OpenFailed,
    SpawnFailed,
    StreamUnavailable,
    StreamReadFailed,
    StreamWriteFailed,
    ResizeFailed,
    BridgeRejected,
    RedactionFailed,
    ProcessWaitFailed,
    ReaderShutdownFailed,
    WriterShutdownFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GovernedPtyError {
    pub code: GovernedPtyErrorCode,
    pub field: &'static str,
    pub message: &'static str,
    dispatch: GovernedExecutionDispatch,
}

impl GovernedPtyError {
    const fn new(
        code: GovernedPtyErrorCode,
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

impl fmt::Display for GovernedPtyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for GovernedPtyError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GovernedPtyPolicy {
    idle_timeout: Duration,
    max_idle_decisions: u32,
    max_input_event_bytes: usize,
    max_total_input_bytes: usize,
}

impl GovernedPtyPolicy {
    pub fn new(
        idle_timeout_secs: u32,
        max_idle_decisions: u32,
        max_input_event_bytes: usize,
        max_total_input_bytes: usize,
    ) -> Result<Self, GovernedPtyError> {
        if idle_timeout_secs == 0
            || max_idle_decisions == 0
            || max_idle_decisions > MAX_GOVERNED_PTY_IDLE_DECISIONS
            || max_input_event_bytes == 0
            || max_input_event_bytes > MAX_GOVERNED_PTY_INPUT_EVENT_BYTES
            || max_total_input_bytes == 0
            || max_total_input_bytes > MAX_GOVERNED_PTY_TOTAL_INPUT_BYTES
            || max_input_event_bytes > max_total_input_bytes
        {
            return Err(invalid_policy());
        }
        Ok(Self {
            idle_timeout: Duration::from_secs(u64::from(idle_timeout_secs)),
            max_idle_decisions,
            max_input_event_bytes,
            max_total_input_bytes,
        })
    }

    pub fn idle_timeout(self) -> Duration {
        self.idle_timeout
    }

    pub fn max_idle_decisions(self) -> u32 {
        self.max_idle_decisions
    }

    pub fn max_input_event_bytes(self) -> usize {
        self.max_input_event_bytes
    }

    pub fn max_total_input_bytes(self) -> usize {
        self.max_total_input_bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GovernedPtySize {
    pub rows: u16,
    pub columns: u16,
    pub pixel_width: u16,
    pub pixel_height: u16,
}

impl GovernedPtySize {
    pub fn new(
        rows: u16,
        columns: u16,
        pixel_width: u16,
        pixel_height: u16,
    ) -> Result<Self, GovernedPtyError> {
        if rows == 0
            || rows > MAX_GOVERNED_PTY_ROWS
            || columns == 0
            || columns > MAX_GOVERNED_PTY_COLUMNS
        {
            return Err(invalid_size());
        }
        Ok(Self {
            rows,
            columns,
            pixel_width,
            pixel_height,
        })
    }

    fn portable(self) -> PtySize {
        PtySize {
            rows: self.rows,
            cols: self.columns,
            pixel_width: self.pixel_width,
            pixel_height: self.pixel_height,
        }
    }
}

/// Move-only, zeroizing operator/agent input for one PTY write.
pub struct GovernedPtyInput(Zeroizing<Vec<u8>>);

impl GovernedPtyInput {
    pub fn new(bytes: Vec<u8>) -> Result<Self, GovernedPtyError> {
        if bytes.is_empty() || bytes.len() > MAX_GOVERNED_PTY_INPUT_EVENT_BYTES {
            return Err(invalid_input());
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    fn into_inner(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(std::mem::take(&mut *self.0))
    }
}

pub enum GovernedPtyAction {
    Continue,
    Write(GovernedPtyInput),
    Resize(GovernedPtySize),
    CloseInput,
    /// The trusted controller observed its declared completion signal. The
    /// runtime terminates and reaps the still-interactive child, retaining a
    /// successful dispatched terminal instead of misclassifying normal TUI
    /// completion as cancellation.
    Complete,
    Cancel,
}

/// Safe event delivered to the product bridge. Bytes have already passed through the
/// streaming credential redactor and may be retained by the UI if desired.
pub struct GovernedPtyOutputEvent {
    output: CredentialRedactedOutput,
    total_output_bytes: u64,
}

impl GovernedPtyOutputEvent {
    pub fn output(&self) -> &CredentialRedactedOutput {
        &self.output
    }

    pub fn total_output_bytes(&self) -> u64 {
        self.total_output_bytes
    }
}

pub trait GovernedPtyBridge {
    fn on_output(
        &mut self,
        output: GovernedPtyOutputEvent,
    ) -> Result<GovernedPtyAction, GovernedPtyError>;

    fn on_idle(&mut self) -> Result<GovernedPtyAction, GovernedPtyError> {
        Ok(GovernedPtyAction::Continue)
    }

    /// Deadline-aware hook used by the governed coordinator. Bridges backed by external
    /// I/O should override this and apply the absolute deadline to that transport.
    fn on_output_before(
        &mut self,
        output: GovernedPtyOutputEvent,
        _deadline: Instant,
    ) -> Result<GovernedPtyAction, GovernedPtyError> {
        self.on_output(output)
    }

    fn on_idle_before(
        &mut self,
        _deadline: Instant,
    ) -> Result<GovernedPtyAction, GovernedPtyError> {
        self.on_idle()
    }
}

/// Sealed authorized PTY capability. Phase 6F is the only production constructor.
pub struct GovernedPtyProcess {
    schema_version: &'static str,
    authority: GovernedExecutionAuthorityParts,
    environment: Vec<(String, Zeroizing<Vec<u8>>)>,
    redactor: CredentialValueRedactor,
    policy: GovernedPtyPolicy,
    initial_size: GovernedPtySize,
}

impl GovernedPtyProcess {
    pub(crate) fn from_authorized_parts(
        authority: GovernedExecutionAuthorityParts,
        environment: Vec<(String, Zeroizing<Vec<u8>>)>,
        redactor: CredentialValueRedactor,
        policy: GovernedPtyPolicy,
        initial_size: GovernedPtySize,
    ) -> Result<Self, GovernedPtyError> {
        authority.revalidate().map_err(authority_changed)?;
        if authority.intent.interaction != CliInteraction::Pty {
            return Err(wrong_interaction());
        }
        if policy.idle_timeout >= Duration::from_secs(u64::from(authority.intent.timeout_secs))
            || authority
                .intent
                .stdin
                .as_ref()
                .is_some_and(|value| value.len() > policy.max_total_input_bytes)
        {
            return Err(invalid_policy());
        }
        validate_environment(&environment)?;
        if !authority.baseline_matches_environment(&environment) {
            return Err(invalid_environment());
        }
        Ok(Self {
            schema_version: GOVERNED_PTY_PROCESS_V1,
            authority,
            environment,
            redactor,
            policy,
            initial_size,
        })
    }

    pub fn schema_version(&self) -> &'static str {
        self.schema_version
    }
}

/// Crate-private raw PTY result. Stable output is already redacted; only the bounded
/// suffix that could still be a credential prefix remains zeroizing for Phase 6D.
pub struct GovernedRawPtyExecution {
    terminal: GovernedExecutionTerminalState,
    exit_code: Option<i32>,
    elapsed: Duration,
    stable_output: CredentialRedactedOutput,
    pending_output: Zeroizing<Vec<u8>>,
    output_truncated: bool,
    output_retention: Option<GovernedOutputRetention>,
}

impl GovernedRawPtyExecution {
    pub fn terminal(&self) -> GovernedExecutionTerminalState {
        self.terminal
    }

    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    pub fn stable_output_bytes(&self) -> usize {
        self.stable_output.as_bytes().len()
    }

    pub fn pending_output_bytes(&self) -> usize {
        self.pending_output.len()
    }

    pub fn output_truncated(&self) -> bool {
        self.output_truncated
    }

    pub(crate) fn into_parts(self) -> GovernedRawPtyExecutionParts {
        GovernedRawPtyExecutionParts {
            terminal: self.terminal,
            exit_code: self.exit_code,
            elapsed: self.elapsed,
            stable_output: self.stable_output,
            pending_output: self.pending_output,
            output_truncated: self.output_truncated,
            output_retention: self.output_retention,
        }
    }
}

pub(crate) struct GovernedRawPtyExecutionParts {
    pub(crate) terminal: GovernedExecutionTerminalState,
    pub(crate) exit_code: Option<i32>,
    pub(crate) elapsed: Duration,
    pub(crate) stable_output: CredentialRedactedOutput,
    pub(crate) pending_output: Zeroizing<Vec<u8>>,
    pub(crate) output_truncated: bool,
    pub(crate) output_retention: Option<GovernedOutputRetention>,
}

pub struct GovernedPtyExecutor;

impl GovernedPtyExecutor {
    pub fn execute(
        process: GovernedPtyProcess,
        cancellation: &GovernedBatchCancellation,
        bridge: &mut dyn GovernedPtyBridge,
    ) -> Result<GovernedRawPtyExecution, GovernedPtyError> {
        let started = Instant::now();
        let deadline = started
            .checked_add(Duration::from_secs(u64::from(
                process.authority.intent.timeout_secs,
            )))
            .ok_or_else(process_wait_failed)?;
        Self::execute_until(process, cancellation, bridge, deadline)
    }

    pub(crate) fn execute_until(
        process: GovernedPtyProcess,
        cancellation: &GovernedBatchCancellation,
        bridge: &mut dyn GovernedPtyBridge,
        deadline: Instant,
    ) -> Result<GovernedRawPtyExecution, GovernedPtyError> {
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
                CredentialRedactedOutput(Vec::new()),
                Zeroizing::new(Vec::new()),
                false,
            ));
        }
        let max_output = process
            .authority
            .intent
            .max_stdout_bytes
            .checked_add(process.authority.intent.max_stderr_bytes)
            .ok_or_else(capacity_exceeded)?;
        let permit =
            GovernedProcessPermit::acquire(max_output, 0).map_err(|_| capacity_exceeded())?;
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
                CredentialRedactedOutput(Vec::new()),
                Zeroizing::new(Vec::new()),
                false,
            ));
        }
        let mut raw = execute_spawned(
            process,
            executable,
            cwd,
            cancellation,
            bridge,
            started,
            deadline,
            max_output,
        )?;
        if raw.terminal.dispatch() == GovernedExecutionDispatch::NotDispatched {
            drop(permit);
        } else {
            raw.output_retention = Some(permit.into_output_retention());
        }
        Ok(raw)
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_spawned(
    mut process: GovernedPtyProcess,
    executable: GovernedExecutableSnapshot,
    cwd: Option<GovernedWorkingDirectoryHandle>,
    cancellation: &GovernedBatchCancellation,
    bridge: &mut dyn GovernedPtyBridge,
    started: Instant,
    deadline: Instant,
    max_output: u64,
) -> Result<GovernedRawPtyExecution, GovernedPtyError> {
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(process.initial_size.portable())
        .map_err(|_| open_failed())?;
    configure_pty_streams(pair.master.as_ref())?;
    // The governed bridge already owns presentation of typed input. Terminal-driver
    // echo adds no protocol value and could reflect model, user, or credential bytes
    // back across the output boundary before their sensitivity is known.
    disable_pty_echo(pair.master.as_ref())?;
    let initial_input = process.authority.intent.stdin.take();
    let mut command = CommandBuilder::new(executable.as_path());
    command.env_clear();
    for argument in &process.authority.intent.command_prefix {
        command.arg(argument);
    }
    for argument in process.authority.intent.arguments.iter() {
        command.arg(argument);
    }
    for (name, value) in &process.environment {
        command.env(name, bytes_as_os_str(value)?);
    }
    if let Some(cwd) = &cwd {
        command.cwd(pty_cwd_path(cwd)?);
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
            CredentialRedactedOutput(Vec::new()),
            Zeroizing::new(Vec::new()),
            false,
        ));
    }
    let reader = pair
        .master
        .try_clone_reader()
        .map_err(|_| stream_unavailable_before_dispatch())?;
    let writer = pair
        .master
        .take_writer()
        .map_err(|_| stream_unavailable_before_dispatch())?;
    process.authority.revalidate().map_err(authority_changed)?;
    let child = pair
        .slave
        .spawn_command(command)
        .map_err(|_| spawn_failed())?;
    drop(pair.slave);
    let group_leader = pty_group_leader(pair.master.as_ref()).or_else(|| child.process_id());
    let mut guard = PtyProcessGuard::new(child, pair.master, group_leader);
    let (sender, receiver) = mpsc::sync_channel(PTY_STREAM_CHANNEL_DEPTH);
    let mut writer = spawn_writer(writer, sender.clone())?;
    let reader = match spawn_reader(reader, sender) {
        Ok(reader) => reader,
        Err(error) => {
            guard.terminate_and_reap();
            drop(receiver);
            writer.close();
            let _ = join_writer(writer);
            return Err(error);
        },
    };
    let mut total_input = 0usize;
    if let Some(input) = initial_input {
        if let Err(error) = queue_input(
            &mut writer,
            input,
            &mut total_input,
            process.policy.max_total_input_bytes,
        ) {
            guard.terminate_and_reap();
            drop(receiver);
            writer.close();
            let reader_result = join_reader(reader);
            let writer_result = join_writer(writer);
            reader_result?;
            writer_result?;
            return Err(error);
        }
    }
    collect(
        &mut guard,
        writer,
        receiver,
        reader,
        process.redactor.streaming(),
        process.policy,
        cancellation,
        bridge,
        started,
        deadline,
        max_output,
        total_input,
    )
}

#[allow(clippy::too_many_arguments)]
fn collect(
    guard: &mut PtyProcessGuard,
    mut writer: PtyWriterHandle,
    receiver: Receiver<PtyStreamEvent>,
    reader: PtyReaderHandle,
    mut streaming: CredentialStreamingRedactor<'_>,
    policy: GovernedPtyPolicy,
    cancellation: &GovernedBatchCancellation,
    bridge: &mut dyn GovernedPtyBridge,
    started: Instant,
    deadline: Instant,
    max_output: u64,
    mut total_input: usize,
) -> Result<GovernedRawPtyExecution, GovernedPtyError> {
    let mut stable_output = Vec::new();
    let mut captured_output = 0u64;
    let mut output_truncated = false;
    let mut terminal_override = None;
    let mut status = None;
    let mut reader_done = false;
    let mut first_error = None;
    let mut last_activity = Instant::now();
    let mut idle_decisions = 0u32;

    loop {
        if cancellation.is_cancelled() {
            terminal_override = Some(GovernedExecutionTerminal::Cancelled);
            break;
        }
        let now = Instant::now();
        if now >= deadline {
            terminal_override = Some(GovernedExecutionTerminal::TimedOut);
            break;
        }
        if status.is_none() {
            match guard.try_wait() {
                Ok(Some(exit)) => {
                    status = Some(exit);
                    guard.mark_reaped();
                },
                Ok(None) => {},
                Err(error) => {
                    first_error = Some(error);
                    break;
                },
            }
        }
        if status.is_some() && reader_done {
            break;
        }
        if now.duration_since(last_activity) >= policy.idle_timeout {
            idle_decisions = idle_decisions.saturating_add(1);
            if idle_decisions > policy.max_idle_decisions {
                terminal_override = Some(GovernedExecutionTerminal::TimedOut);
                break;
            }
            match call_bridge_idle(bridge, deadline) {
                Ok(action) => {
                    let controller_activity = matches!(
                        &action,
                        GovernedPtyAction::Write(_) | GovernedPtyAction::Resize(_)
                    );
                    if let Err(error) = apply_action(
                        action,
                        guard,
                        &mut writer,
                        &mut total_input,
                        policy,
                        &mut terminal_override,
                    ) {
                        first_error = Some(error);
                        break;
                    }
                    if controller_activity {
                        idle_decisions = 0;
                    }
                },
                Err(_) => {
                    first_error = Some(bridge_rejected());
                    break;
                },
            }
            last_activity = Instant::now();
            if terminal_override.is_some() {
                break;
            }
        }
        match receiver.recv_timeout(PTY_POLL_INTERVAL) {
            Ok(PtyStreamEvent::Chunk(bytes)) => {
                idle_decisions = 0;
                let next = captured_output.saturating_add(bytes.len() as u64);
                if next > max_output {
                    output_truncated = true;
                    terminal_override = Some(GovernedExecutionTerminal::OutputLimitExceeded);
                    break;
                }
                captured_output = next;
                match streaming.push(&bytes) {
                    Ok(safe) => {
                        if !safe.as_bytes().is_empty() {
                            let Some(stable_next) =
                                stable_output.len().checked_add(safe.as_bytes().len())
                            else {
                                first_error = Some(redaction_failed());
                                break;
                            };
                            if stable_next as u64 > max_output {
                                first_error = Some(redaction_failed());
                                break;
                            }
                            let stable_capacity = stable_output.capacity();
                            if stable_next > stable_capacity {
                                stable_output.reserve_exact(stable_next - stable_capacity);
                            }
                            stable_output.extend_from_slice(safe.as_bytes());
                            let event = GovernedPtyOutputEvent {
                                output: safe,
                                total_output_bytes: captured_output,
                            };
                            match call_bridge_output(bridge, event, deadline) {
                                Ok(action) => {
                                    if let Err(error) = apply_action(
                                        action,
                                        guard,
                                        &mut writer,
                                        &mut total_input,
                                        policy,
                                        &mut terminal_override,
                                    ) {
                                        first_error = Some(error);
                                        break;
                                    }
                                },
                                Err(_) => {
                                    first_error = Some(bridge_rejected());
                                    break;
                                },
                            }
                        }
                    },
                    Err(_) => {
                        first_error = Some(redaction_failed());
                        break;
                    },
                }
                last_activity = Instant::now();
                if terminal_override.is_some() {
                    break;
                }
            },
            Ok(PtyStreamEvent::Done) => reader_done = true,
            Ok(PtyStreamEvent::Failed) => {
                first_error = Some(stream_read_failed());
                break;
            },
            Ok(PtyStreamEvent::WriteFailed) => {
                first_error = Some(stream_write_failed());
                break;
            },
            Err(mpsc::RecvTimeoutError::Timeout) => {},
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if !reader_done {
                    first_error = Some(stream_read_failed());
                    break;
                }
                // PTY EOF can become observable immediately before the child status.
                // Continue bounded polling rather than treating that legal ordering as
                // an unreapable process.
                thread::sleep(PTY_POLL_INTERVAL);
            },
        }
    }

    writer.close();
    if status.is_none() || terminal_override.is_some() || first_error.is_some() {
        guard.terminate_and_reap();
    }
    drop(receiver);
    let reader_result = join_reader(reader);
    let writer_result = join_writer(writer);
    if reader_result.is_err() {
        first_error.get_or_insert_with(reader_shutdown_failed);
    }
    if writer_result.is_err() {
        first_error.get_or_insert_with(writer_shutdown_failed);
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    let pending_output = streaming.into_pending();
    if stable_output.len().saturating_add(pending_output.len()) as u64 > max_output {
        return Err(redaction_failed());
    }
    let (terminal, exit_code) = match terminal_override {
        Some(terminal) => (terminal, None),
        None => {
            let status = status.ok_or_else(process_wait_failed)?;
            let exit_code = i32::try_from(status.exit_code()).ok();
            if status.success() {
                (GovernedExecutionTerminal::Success, exit_code)
            } else {
                (GovernedExecutionTerminal::NonZeroExit, exit_code)
            }
        },
    };
    Ok(raw_terminal(
        terminal,
        GovernedExecutionDispatch::Dispatched,
        exit_code,
        started.elapsed(),
        CredentialRedactedOutput(stable_output),
        pending_output,
        output_truncated,
    ))
}

fn apply_action(
    action: GovernedPtyAction,
    guard: &PtyProcessGuard,
    writer: &mut PtyWriterHandle,
    total_input: &mut usize,
    policy: GovernedPtyPolicy,
    terminal_override: &mut Option<GovernedExecutionTerminal>,
) -> Result<(), GovernedPtyError> {
    match action {
        GovernedPtyAction::Continue => Ok(()),
        GovernedPtyAction::Write(input) => {
            let input = input.into_inner();
            if input.len() > policy.max_input_event_bytes {
                return Err(input_limit_exceeded());
            }
            queue_input(writer, input, total_input, policy.max_total_input_bytes)
        },
        GovernedPtyAction::Resize(size) => guard.resize(size),
        GovernedPtyAction::CloseInput => {
            writer.close();
            Ok(())
        },
        GovernedPtyAction::Complete => {
            *terminal_override = Some(GovernedExecutionTerminal::Success);
            Ok(())
        },
        GovernedPtyAction::Cancel => {
            *terminal_override = Some(GovernedExecutionTerminal::Cancelled);
            Ok(())
        },
    }
}

fn call_bridge_output(
    bridge: &mut dyn GovernedPtyBridge,
    event: GovernedPtyOutputEvent,
    deadline: Instant,
) -> Result<GovernedPtyAction, GovernedPtyError> {
    catch_unwind(AssertUnwindSafe(|| {
        bridge.on_output_before(event, deadline)
    }))
    .map_err(|_| bridge_rejected())?
    .map_err(|_| bridge_rejected())
}

fn call_bridge_idle(
    bridge: &mut dyn GovernedPtyBridge,
    deadline: Instant,
) -> Result<GovernedPtyAction, GovernedPtyError> {
    catch_unwind(AssertUnwindSafe(|| bridge.on_idle_before(deadline)))
        .map_err(|_| bridge_rejected())?
        .map_err(|_| bridge_rejected())
}

fn queue_input(
    writer: &mut PtyWriterHandle,
    input: Zeroizing<Vec<u8>>,
    total_input: &mut usize,
    maximum: usize,
) -> Result<(), GovernedPtyError> {
    let next = total_input
        .checked_add(input.len())
        .ok_or_else(input_limit_exceeded)?;
    if next > maximum {
        return Err(input_limit_exceeded());
    }
    writer.enqueue(input)?;
    *total_input = next;
    Ok(())
}

enum PtyStreamEvent {
    Chunk(Vec<u8>),
    Done,
    Failed,
    WriteFailed,
}

struct PtyWriterHandle {
    sender: Option<SyncSender<Zeroizing<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

impl PtyWriterHandle {
    fn enqueue(&mut self, input: Zeroizing<Vec<u8>>) -> Result<(), GovernedPtyError> {
        self.sender
            .as_ref()
            .ok_or_else(stream_write_failed)?
            .try_send(input)
            .map_err(|_| stream_write_failed())
    }

    fn close(&mut self) {
        self.sender = None;
        self.stop.store(true, Ordering::Release);
    }
}

struct PtyReaderHandle {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

fn spawn_writer(
    mut writer: Box<dyn Write + Send>,
    event_sender: SyncSender<PtyStreamEvent>,
) -> Result<PtyWriterHandle, GovernedPtyError> {
    let (sender, receiver) = mpsc::sync_channel::<Zeroizing<Vec<u8>>>(PTY_INPUT_CHANNEL_DEPTH);
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = thread::Builder::new()
        .name("governed-pty-writer".to_owned())
        .stack_size(PTY_IO_THREAD_STACK_BYTES)
        .spawn(move || {
            while let Ok(input) = receiver.recv() {
                if write_pty_input(&mut *writer, &input, &thread_stop).is_err() {
                    let _ = event_sender.send(PtyStreamEvent::WriteFailed);
                    break;
                }
                if thread_stop.load(Ordering::Acquire) {
                    break;
                }
            }
        })
        .map_err(|_| stream_unavailable_after_dispatch())?;
    Ok(PtyWriterHandle {
        sender: Some(sender),
        stop,
        thread,
    })
}

fn write_pty_input(
    writer: &mut dyn Write,
    input: &[u8],
    stop: &AtomicBool,
) -> Result<(), GovernedPtyError> {
    let mut offset = 0usize;
    while offset < input.len() {
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        match writer.write(&input[offset..]) {
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
                thread::sleep(PTY_POLL_INTERVAL);
            },
            Err(_) => return Err(stream_write_failed()),
        }
    }
    while !stop.load(Ordering::Acquire) {
        match writer.flush() {
            Ok(()) => return Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) =>
            {
                thread::sleep(PTY_POLL_INTERVAL);
            },
            Err(_) => return Err(stream_write_failed()),
        }
    }
    Ok(())
}

fn spawn_reader(
    mut reader: Box<dyn Read + Send>,
    sender: SyncSender<PtyStreamEvent>,
) -> Result<PtyReaderHandle, GovernedPtyError> {
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = thread::Builder::new()
        .name("governed-pty-reader".to_owned())
        .stack_size(PTY_IO_THREAD_STACK_BYTES)
        .spawn(move || {
            let mut chunk = [0u8; PTY_STREAM_CHUNK_BYTES];
            while !thread_stop.load(Ordering::Acquire) {
                match reader.read(&mut chunk) {
                    Ok(0) => {
                        let _ = sender.send(PtyStreamEvent::Done);
                        break;
                    },
                    Ok(count) => {
                        if sender
                            .send(PtyStreamEvent::Chunk(chunk[..count].to_vec()))
                            .is_err()
                        {
                            break;
                        }
                    },
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {},
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(PTY_POLL_INTERVAL);
                    },
                    Err(error) => {
                        #[cfg(unix)]
                        if error.raw_os_error() == Some(libc::EIO) {
                            let _ = sender.send(PtyStreamEvent::Done);
                            break;
                        }
                        let _ = sender.send(PtyStreamEvent::Failed);
                        break;
                    },
                }
            }
        })
        .map_err(|_| stream_unavailable_after_dispatch())?;
    Ok(PtyReaderHandle { stop, thread })
}

fn join_reader(reader: PtyReaderHandle) -> Result<(), GovernedPtyError> {
    reader.stop.store(true, Ordering::Release);
    reader.thread.join().map_err(|_| reader_shutdown_failed())
}

fn join_writer(writer: PtyWriterHandle) -> Result<(), GovernedPtyError> {
    writer.thread.join().map_err(|_| writer_shutdown_failed())
}

struct PtyProcessGuard {
    child: Option<Box<dyn Child + Send + Sync>>,
    master: Option<Box<dyn MasterPty + Send>>,
    group_leader: Option<u32>,
}

impl PtyProcessGuard {
    fn new(
        child: Box<dyn Child + Send + Sync>,
        master: Box<dyn MasterPty + Send>,
        group_leader: Option<u32>,
    ) -> Self {
        Self {
            child: Some(child),
            master: Some(master),
            group_leader,
        }
    }

    fn try_wait(&mut self) -> Result<Option<portable_pty::ExitStatus>, GovernedPtyError> {
        #[cfg(unix)]
        {
            if !observe_owned_child_exit(self.group_leader).map_err(|_| process_wait_failed())? {
                return Ok(None);
            }
            terminate_exited_process_group_before_reap(self.group_leader);
            self.child
                .as_mut()
                .ok_or_else(process_wait_failed)?
                .wait()
                .map(Some)
                .map_err(|_| process_wait_failed())
        }
        #[cfg(not(unix))]
        self.child
            .as_mut()
            .ok_or_else(process_wait_failed)?
            .try_wait()
            .map_err(|_| process_wait_failed())
    }

    fn resize(&self, size: GovernedPtySize) -> Result<(), GovernedPtyError> {
        self.master
            .as_ref()
            .ok_or_else(resize_failed)?
            .resize(size.portable())
            .map_err(|_| resize_failed())
    }

    fn mark_reaped(&mut self) {
        self.child = None;
    }

    fn terminate_and_reap(&mut self) {
        terminate_process_group(self.group_leader);
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;
        self.master = None;
    }
}

impl Drop for PtyProcessGuard {
    fn drop(&mut self) {
        if self.child.is_some() {
            self.terminate_and_reap();
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn raw_terminal(
    terminal: GovernedExecutionTerminal,
    dispatch: GovernedExecutionDispatch,
    exit_code: Option<i32>,
    elapsed: Duration,
    stable_output: CredentialRedactedOutput,
    pending_output: Zeroizing<Vec<u8>>,
    output_truncated: bool,
) -> GovernedRawPtyExecution {
    let terminal = GovernedExecutionTerminalState::executor_owned(terminal, dispatch);
    GovernedRawPtyExecution {
        terminal,
        exit_code,
        elapsed,
        stable_output,
        pending_output,
        output_truncated,
        output_retention: None,
    }
}

fn validate_environment(
    environment: &[(String, Zeroizing<Vec<u8>>)],
) -> Result<(), GovernedPtyError> {
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
            .and_then(|size| size.checked_add(value.len()))
            .ok_or_else(invalid_environment)?;
        if total > crate::credential_materialization::MAX_CHILD_ENVIRONMENT_TOTAL_BYTES {
            return Err(invalid_environment());
        }
        previous = Some(name);
    }
    Ok(())
}

#[cfg(unix)]
fn bytes_as_os_str(value: &[u8]) -> Result<&OsStr, GovernedPtyError> {
    if value.contains(&0) {
        return Err(invalid_environment());
    }
    Ok(OsStr::from_bytes(value))
}

#[cfg(not(unix))]
fn bytes_as_os_str(_value: &[u8]) -> Result<&OsStr, GovernedPtyError> {
    Err(invalid_environment())
}

#[cfg(unix)]
fn pty_cwd_path(
    cwd: &GovernedWorkingDirectoryHandle,
) -> Result<std::path::PathBuf, GovernedPtyError> {
    cwd.revalidated_child_cwd_path().map_err(authority_changed)
}

#[cfg(not(unix))]
fn pty_cwd_path(
    _cwd: &GovernedWorkingDirectoryHandle,
) -> Result<std::path::PathBuf, GovernedPtyError> {
    Err(unsupported_pty_cwd())
}

#[cfg(unix)]
fn pty_group_leader(master: &dyn MasterPty) -> Option<u32> {
    master
        .process_group_leader()
        .and_then(|pid| u32::try_from(pid).ok())
}

#[cfg(unix)]
fn configure_pty_streams(master: &dyn MasterPty) -> Result<(), GovernedPtyError> {
    let fd = master
        .as_raw_fd()
        .ok_or_else(stream_unavailable_before_dispatch)?;
    set_nonblocking(fd).map_err(|_| stream_unavailable_before_dispatch())
}

#[cfg(not(unix))]
fn configure_pty_streams(_master: &dyn MasterPty) -> Result<(), GovernedPtyError> {
    Err(stream_unavailable_before_dispatch())
}

#[cfg(unix)]
fn disable_pty_echo(master: &dyn MasterPty) -> Result<(), GovernedPtyError> {
    let fd = master
        .as_raw_fd()
        .ok_or_else(stream_unavailable_before_dispatch)?;
    // SAFETY: this is the retained live PTY master. Termios state is shared with the
    // slave, and only terminal-driver echo is removed before any sensitive input is
    // queued.
    let mut attributes: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut attributes) } != 0 {
        return Err(stream_unavailable_before_dispatch());
    }
    attributes.c_lflag &= !(libc::ECHO | libc::ECHONL);
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &attributes) } != 0 {
        return Err(stream_unavailable_before_dispatch());
    }
    Ok(())
}

#[cfg(not(unix))]
fn disable_pty_echo(_master: &dyn MasterPty) -> Result<(), GovernedPtyError> {
    Err(stream_unavailable_before_dispatch())
}

#[cfg(not(unix))]
fn pty_group_leader(_master: &dyn MasterPty) -> Option<u32> {
    None
}

fn authority_changed(_error: GovernedExecutionAuthorityError) -> GovernedPtyError {
    GovernedPtyError::new(
        GovernedPtyErrorCode::AuthorityChanged,
        "authority",
        "executable or working-directory authority changed before PTY execution",
        GovernedExecutionDispatch::NotDispatched,
    )
}

#[cfg(not(unix))]
const fn unsupported_pty_cwd() -> GovernedPtyError {
    GovernedPtyError::new(
        GovernedPtyErrorCode::AuthorityChanged,
        "working_directory",
        "descriptor-bound PTY working directories are unavailable on this platform",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn wrong_interaction() -> GovernedPtyError {
    GovernedPtyError::new(
        GovernedPtyErrorCode::WrongInteraction,
        "interaction",
        "the PTY executor requires an explicitly interactive runtime contract",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn invalid_policy() -> GovernedPtyError {
    GovernedPtyError::new(
        GovernedPtyErrorCode::InvalidPolicy,
        "pty_policy",
        "the PTY policy is empty, inconsistent, or exceeds a hard runtime ceiling",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn invalid_size() -> GovernedPtyError {
    GovernedPtyError::new(
        GovernedPtyErrorCode::InvalidSize,
        "pty_size",
        "the PTY dimensions are empty or exceed a hard runtime ceiling",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn invalid_input() -> GovernedPtyError {
    GovernedPtyError::new(
        GovernedPtyErrorCode::InvalidInput,
        "pty_input",
        "a PTY input event is empty or exceeds its hard byte ceiling",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn input_limit_exceeded() -> GovernedPtyError {
    GovernedPtyError::new(
        GovernedPtyErrorCode::InputLimitExceeded,
        "pty_input",
        "PTY input exceeds the per-event or aggregate byte ceiling",
        GovernedExecutionDispatch::Dispatched,
    )
}

const fn capacity_exceeded() -> GovernedPtyError {
    GovernedPtyError::new(
        GovernedPtyErrorCode::CapacityExceeded,
        "process_capacity",
        "the process-wide governed execution capacity is exhausted",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn invalid_environment() -> GovernedPtyError {
    GovernedPtyError::new(
        GovernedPtyErrorCode::InvalidEnvironment,
        "environment",
        "the sealed PTY child environment is invalid or exceeds its aggregate ceiling",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn open_failed() -> GovernedPtyError {
    GovernedPtyError::new(
        GovernedPtyErrorCode::OpenFailed,
        "pty",
        "a bounded pseudo-terminal could not be allocated",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn spawn_failed() -> GovernedPtyError {
    GovernedPtyError::new(
        GovernedPtyErrorCode::SpawnFailed,
        "process",
        "the governed PTY child process could not be started",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn stream_unavailable_before_dispatch() -> GovernedPtyError {
    GovernedPtyError::new(
        GovernedPtyErrorCode::StreamUnavailable,
        "pty_stream",
        "a required governed PTY stream is unavailable",
        GovernedExecutionDispatch::NotDispatched,
    )
}

const fn stream_unavailable_after_dispatch() -> GovernedPtyError {
    GovernedPtyError::new(
        GovernedPtyErrorCode::StreamUnavailable,
        "pty_stream",
        "a bounded PTY reader could not be started",
        GovernedExecutionDispatch::UnknownAfterDispatch,
    )
}

const fn stream_read_failed() -> GovernedPtyError {
    GovernedPtyError::new(
        GovernedPtyErrorCode::StreamReadFailed,
        "pty_output",
        "the bounded PTY output stream failed",
        GovernedExecutionDispatch::UnknownAfterDispatch,
    )
}

const fn stream_write_failed() -> GovernedPtyError {
    GovernedPtyError::new(
        GovernedPtyErrorCode::StreamWriteFailed,
        "pty_input",
        "the bounded PTY input stream failed",
        GovernedExecutionDispatch::Dispatched,
    )
}

const fn resize_failed() -> GovernedPtyError {
    GovernedPtyError::new(
        GovernedPtyErrorCode::ResizeFailed,
        "pty_size",
        "the governed pseudo-terminal could not be resized",
        GovernedExecutionDispatch::Dispatched,
    )
}

const fn bridge_rejected() -> GovernedPtyError {
    GovernedPtyError::new(
        GovernedPtyErrorCode::BridgeRejected,
        "pty_bridge",
        "the trusted PTY interaction bridge rejected the current event",
        GovernedExecutionDispatch::Dispatched,
    )
}

const fn redaction_failed() -> GovernedPtyError {
    GovernedPtyError::new(
        GovernedPtyErrorCode::RedactionFailed,
        "pty_output",
        "PTY output could not be safely redacted within its work ceiling",
        GovernedExecutionDispatch::Dispatched,
    )
}

const fn process_wait_failed() -> GovernedPtyError {
    GovernedPtyError::new(
        GovernedPtyErrorCode::ProcessWaitFailed,
        "process",
        "the governed PTY child could not be reaped deterministically",
        GovernedExecutionDispatch::UnknownAfterDispatch,
    )
}

const fn reader_shutdown_failed() -> GovernedPtyError {
    GovernedPtyError::new(
        GovernedPtyErrorCode::ReaderShutdownFailed,
        "pty_output",
        "the bounded PTY output reader could not be joined",
        GovernedExecutionDispatch::UnknownAfterDispatch,
    )
}

const fn writer_shutdown_failed() -> GovernedPtyError {
    GovernedPtyError::new(
        GovernedPtyErrorCode::WriterShutdownFailed,
        "pty_input",
        "the bounded PTY input writer could not be joined",
        GovernedExecutionDispatch::UnknownAfterDispatch,
    )
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        fmt, fs,
        path::PathBuf,
        sync::{Arc, Mutex, OnceLock},
    };

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
            AuthContract, DataSensitivity, PolicyFloor, RuntimeLimits, RuntimeProtocol,
            RuntimeRequirements, SkillRuntimeContract, SkillRuntimeContractVersion, StdinContract,
            StdinMode, WorkingDirectoryContract, WorkingDirectoryMode,
        },
        manifest_validation::validate_skill_runtime_contract,
    };

    struct Fixture {
        _root: TempDir,
        bin: PathBuf,
        workspace: PathBuf,
    }

    fn pty_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    impl Fixture {
        fn new(script: &[u8]) -> Self {
            let root = tempfile::tempdir().unwrap();
            let bin = root.path().join("bin");
            let workspace = root.path().join("workspace");
            fs::create_dir(&bin).unwrap();
            fs::create_dir(&workspace).unwrap();
            let executable = bin.join("fixture-pty");
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
            interaction: CliInteraction,
            redaction_patterns: Vec<Arc<Zeroizing<Vec<u8>>>>,
        ) -> Result<GovernedPtyProcess, GovernedPtyError> {
            let authored = SkillRuntimeContract {
                schema_version: SkillRuntimeContractVersion::v1(),
                requires: RuntimeRequirements {
                    bins: BTreeSet::from(["fixture-pty".to_owned()]),
                    entrypoint: Default::default(),
                    environment: Default::default(),
                },
                runtime: RuntimeProtocol::Cli {
                    command_prefix: vec![],
                    interaction,
                    stdin: StdinContract {
                        mode: StdinMode::Optional,
                        sensitivity: DataSensitivity::Public,
                    },
                    working_directory: WorkingDirectoryContract {
                        mode: WorkingDirectoryMode::Workspace,
                    },
                    limits: RuntimeLimits {
                        timeout_secs: Some(3),
                        stdin_bytes: Some(1024),
                        stdout_bytes: Some(64 * 1024),
                        stderr_bytes: Some(64 * 1024),
                        memory_bytes: None,
                    },
                },
                auth: AuthContract::default(),
                policy_floor: PolicyFloor::default(),
            };
            let contract = GovernedExecutionContract::compile(
                validate_skill_runtime_contract(&authored).unwrap(),
                GovernedExecutionPolicy::new(3, 3, 1024, 64 * 1024, 64 * 1024).unwrap(),
            )
            .unwrap();
            let intent = contract
                .admit(GovernedExecutionRequest::new(vec![], None, None, Some(3)))
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
            GovernedPtyProcess::from_authorized_parts(
                parts,
                environment,
                CredentialValueRedactor::new(redaction_patterns).unwrap(),
                GovernedPtyPolicy::new(1, 2, 1024, 4096).unwrap(),
                GovernedPtySize::new(24, 80, 0, 0).unwrap(),
            )
        }
    }

    #[derive(Default)]
    struct CapturingBridge {
        output: Vec<u8>,
    }

    struct OneLargeWriteBridge {
        wrote: bool,
    }

    struct CompleteOnOutputBridge;

    impl GovernedPtyBridge for OneLargeWriteBridge {
        fn on_output(
            &mut self,
            _output: GovernedPtyOutputEvent,
        ) -> Result<GovernedPtyAction, GovernedPtyError> {
            if self.wrote {
                Ok(GovernedPtyAction::Continue)
            } else {
                self.wrote = true;
                Ok(GovernedPtyAction::Write(GovernedPtyInput::new(
                    vec![b'x'; MAX_GOVERNED_PTY_INPUT_EVENT_BYTES],
                )?))
            }
        }
    }

    impl GovernedPtyBridge for CapturingBridge {
        fn on_output(
            &mut self,
            output: GovernedPtyOutputEvent,
        ) -> Result<GovernedPtyAction, GovernedPtyError> {
            self.output.extend_from_slice(output.output().as_bytes());
            Ok(GovernedPtyAction::Continue)
        }
    }

    impl GovernedPtyBridge for CompleteOnOutputBridge {
        fn on_output(
            &mut self,
            _output: GovernedPtyOutputEvent,
        ) -> Result<GovernedPtyAction, GovernedPtyError> {
            Ok(GovernedPtyAction::Complete)
        }
    }

    #[test]
    fn batch_contract_cannot_construct_a_pty_capability() {
        let _guard = pty_test_lock();
        let fixture = Fixture::new(b"#!/bin/sh\nexit 0\n");
        assert_eq!(
            fixture
                .process(CliInteraction::Batch, vec![])
                .err()
                .unwrap()
                .code,
            GovernedPtyErrorCode::WrongInteraction
        );
    }

    #[test]
    fn streaming_bridge_never_observes_a_credential_split_across_pty_reads() {
        let _guard = pty_test_lock();
        let fixture = Fixture::new(b"#!/bin/sh\nprintf cred\n/bin/sleep 0.05\nprintf ential\n");
        let process = fixture
            .process(
                CliInteraction::Pty,
                vec![Arc::new(Zeroizing::new(b"credential".to_vec()))],
            )
            .unwrap();
        let mut bridge = CapturingBridge::default();
        let result =
            GovernedPtyExecutor::execute(process, &GovernedBatchCancellation::new(), &mut bridge)
                .unwrap();
        assert!(!bridge
            .output
            .windows(10)
            .any(|value| value == b"credential"));
        assert_eq!(
            result.terminal().terminal(),
            GovernedExecutionTerminal::Success
        );
    }

    #[test]
    fn fast_pty_exit_is_reaped_after_output_eof() {
        let _guard = pty_test_lock();
        let fixture = Fixture::new(b"#!/bin/sh\nprintf ok\n");
        let process = fixture.process(CliInteraction::Pty, vec![]).unwrap();
        let mut bridge = CapturingBridge::default();
        let result =
            GovernedPtyExecutor::execute(process, &GovernedBatchCancellation::new(), &mut bridge)
                .unwrap();
        assert_eq!(
            result.terminal().terminal(),
            GovernedExecutionTerminal::Success
        );
        assert_eq!(bridge.output, b"ok");
    }

    #[test]
    fn trusted_completion_signal_terminates_a_live_tui_as_success() {
        let _guard = pty_test_lock();
        let fixture = Fixture::new(b"#!/bin/sh\nprintf ready\n/bin/sleep 60\n");
        let process = fixture.process(CliInteraction::Pty, vec![]).unwrap();
        let mut bridge = CompleteOnOutputBridge;
        let result =
            GovernedPtyExecutor::execute(process, &GovernedBatchCancellation::new(), &mut bridge)
                .unwrap();
        assert_eq!(
            result.terminal().terminal(),
            GovernedExecutionTerminal::Success
        );
        assert_eq!(
            result.terminal().dispatch(),
            GovernedExecutionDispatch::Dispatched
        );
    }

    #[test]
    fn pty_dimensions_and_input_are_bounded_before_dispatch() {
        let _guard = pty_test_lock();
        assert_eq!(
            GovernedPtySize::new(0, 80, 0, 0).err().unwrap().code,
            GovernedPtyErrorCode::InvalidSize
        );
        assert_eq!(
            GovernedPtyInput::new(vec![0; MAX_GOVERNED_PTY_INPUT_EVENT_BYTES + 1])
                .err()
                .unwrap()
                .code,
            GovernedPtyErrorCode::InvalidInput
        );
    }

    #[test]
    fn child_that_does_not_read_input_cannot_block_wall_timeout() {
        let _guard = pty_test_lock();
        let fixture = Fixture::new(b"#!/bin/sh\nprintf ready\n/bin/sleep 60\n");
        let mut process = fixture.process(CliInteraction::Pty, vec![]).unwrap();
        process.policy = GovernedPtyPolicy::new(
            1,
            2,
            MAX_GOVERNED_PTY_INPUT_EVENT_BYTES,
            MAX_GOVERNED_PTY_INPUT_EVENT_BYTES * 2,
        )
        .unwrap();
        let mut bridge = OneLargeWriteBridge { wrote: false };
        let result =
            GovernedPtyExecutor::execute(process, &GovernedBatchCancellation::new(), &mut bridge)
                .unwrap();
        assert!(bridge.wrote);
        assert_eq!(
            result.terminal().terminal(),
            GovernedExecutionTerminal::TimedOut
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_pty_stdin_disables_terminal_driver_echo() {
        let _guard = pty_test_lock();
        let pair = native_pty_system()
            .openpty(GovernedPtySize::new(24, 80, 0, 0).unwrap().portable())
            .unwrap();
        disable_pty_echo(pair.master.as_ref()).unwrap();
        let fd = pair.master.as_raw_fd().unwrap();
        let mut attributes: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(fd, &mut attributes) }, 0);
        assert_eq!(attributes.c_lflag & (libc::ECHO | libc::ECHONL), 0);
    }

    #[cfg(unix)]
    #[test]
    fn stopped_pty_writer_cannot_block_on_a_saturated_peer() {
        let _guard = pty_test_lock();
        let (writer, _non_reading_peer) = UnixStream::pair().unwrap();
        set_nonblocking(writer.as_raw_fd()).unwrap();
        let (event_sender, _event_receiver) = mpsc::sync_channel(1);
        let mut writer = spawn_writer(Box::new(writer), event_sender).unwrap();
        writer
            .enqueue(Zeroizing::new(vec![b'x'; 8 * 1024 * 1024]))
            .unwrap();
        std::thread::sleep(Duration::from_millis(40));
        writer.close();
        let started = Instant::now();
        join_writer(writer).expect("writer thread must join");
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    assert_not_impl_any!(GovernedPtyInput: Clone, fmt::Debug, Serialize);
    assert_not_impl_any!(GovernedPtyProcess: Clone, fmt::Debug, Serialize);
    assert_not_impl_any!(GovernedRawPtyExecution: Clone, fmt::Debug, Serialize);
}
