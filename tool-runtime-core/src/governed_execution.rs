//! Pure Phase 6A contract for governed CLI execution.
//!
//! This module validates one invocation against a semantically validated CLI contract
//! and a trusted local resource policy. It performs no executable lookup, filesystem
//! access, credential preparation, authorization, process creation, or output handling.
//! A successful [`GovernedExecutionIntent`] is therefore not launch authority.

use std::{error::Error, fmt, num::NonZeroU32};

use serde::Serialize;
use zeroize::Zeroizing;

use crate::{
    manifest::{
        CliInteraction, DataSensitivity, InjectionTarget, RuntimeProtocol, StdinMode,
        WorkingDirectoryMode,
    },
    manifest_synthesis::MAX_SYNTHESIZED_WORKING_DIRECTORY_BYTES,
    manifest_validation::{
        ValidatedSkillRuntimeContract, MAX_ARGUMENT_BYTES, MAX_FIXED_ARGUMENTS,
        MAX_FIXED_ARGUMENT_BYTES, MAX_RUNTIME_STREAM_BYTES, MAX_RUNTIME_TIMEOUT_SECS,
    },
};

pub const GOVERNED_EXECUTION_CONTRACT_V1: &str = "tool-runtime.governed-execution.v1";
pub const MAX_GOVERNED_WORKING_DIRECTORY_COMPONENT_BYTES: usize = 255;
pub const MAX_GOVERNED_WORKING_DIRECTORY_COMPONENTS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedExecutionContractErrorCode {
    UnsupportedProtocol,
    InvalidLocalPolicy,
    TooManyArguments,
    InvalidArgument,
    ArgumentsTooLarge,
    StdinDenied,
    StdinReservedForCredential,
    StdinRequired,
    StdinTooLarge,
    MaterializedStdinMissing,
    MaterializedStdinUnexpected,
    WorkingDirectoryDenied,
    InvalidWorkingDirectory,
    InvalidTimeout,
}

/// Stable value-free failure. Request, path, stdin, executable, and prefix values never
/// enter this surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GovernedExecutionContractError {
    pub code: GovernedExecutionContractErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl GovernedExecutionContractError {
    const fn new(
        code: GovernedExecutionContractErrorCode,
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

impl fmt::Display for GovernedExecutionContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for GovernedExecutionContractError {}

/// Trusted product resource policy. Authored manifest limits can only lower these
/// ceilings. The caller must choose this policy explicitly; Phase 6A has no hidden
/// timeout or output-size defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GovernedExecutionPolicy {
    default_timeout_secs: NonZeroU32,
    max_timeout_secs: NonZeroU32,
    max_stdin_bytes: u64,
    max_stdout_bytes: u64,
    max_stderr_bytes: u64,
}

impl GovernedExecutionPolicy {
    pub fn new(
        default_timeout_secs: u32,
        max_timeout_secs: u32,
        max_stdin_bytes: u64,
        max_stdout_bytes: u64,
        max_stderr_bytes: u64,
    ) -> Result<Self, GovernedExecutionContractError> {
        let Some(default_timeout_secs) = NonZeroU32::new(default_timeout_secs) else {
            return Err(invalid_local_policy());
        };
        let Some(max_timeout_secs) = NonZeroU32::new(max_timeout_secs) else {
            return Err(invalid_local_policy());
        };
        if default_timeout_secs > max_timeout_secs
            || max_timeout_secs.get() > MAX_RUNTIME_TIMEOUT_SECS
            || max_stdin_bytes == 0
            || max_stdout_bytes == 0
            || max_stderr_bytes == 0
            || max_stdin_bytes > MAX_RUNTIME_STREAM_BYTES
            || max_stdout_bytes > MAX_RUNTIME_STREAM_BYTES
            || max_stderr_bytes > MAX_RUNTIME_STREAM_BYTES
        {
            return Err(invalid_local_policy());
        }
        Ok(Self {
            default_timeout_secs,
            max_timeout_secs,
            max_stdin_bytes,
            max_stdout_bytes,
            max_stderr_bytes,
        })
    }

    pub fn default_timeout_secs(self) -> u32 {
        self.default_timeout_secs.get()
    }

    pub fn max_timeout_secs(self) -> u32 {
        self.max_timeout_secs.get()
    }

    pub fn max_stdin_bytes(self) -> u64 {
        self.max_stdin_bytes
    }

    pub fn max_stdout_bytes(self) -> u64 {
        self.max_stdout_bytes
    }

    pub fn max_stderr_bytes(self) -> u64 {
        self.max_stderr_bytes
    }
}

/// Reusable, non-serializable contract compiled only from a Phase 1C validation proof.
/// It carries no profile, credential, approval receipt, filesystem authority, or resolved
/// executable.
pub struct GovernedExecutionContract {
    schema_version: &'static str,
    executable: String,
    command_prefix: Vec<String>,
    interaction: CliInteraction,
    stdin_mode: StdinMode,
    stdin_sensitivity: DataSensitivity,
    credential_stdin_reserved: bool,
    working_directory: WorkingDirectoryMode,
    max_timeout_secs: u32,
    default_timeout_secs: u32,
    max_stdin_bytes: u64,
    max_stdout_bytes: u64,
    max_stderr_bytes: u64,
    max_memory_bytes: Option<u64>,
}

impl GovernedExecutionContract {
    pub fn compile(
        validated: ValidatedSkillRuntimeContract<'_>,
        policy: GovernedExecutionPolicy,
    ) -> Result<Self, GovernedExecutionContractError> {
        let contract = validated.contract();
        let RuntimeProtocol::Cli {
            command_prefix,
            interaction,
            stdin,
            working_directory,
            limits,
        } = &contract.runtime
        else {
            return Err(unsupported_protocol());
        };
        let executable = contract
            .requires
            .bins
            .first()
            .ok_or_else(unsupported_protocol)?;
        let credential_stdin_reserved = contract
            .auth
            .injections
            .iter()
            .any(|binding| binding.target == InjectionTarget::Stdin);
        let max_timeout_secs = limits
            .timeout_secs
            .unwrap_or(MAX_RUNTIME_TIMEOUT_SECS)
            .min(policy.max_timeout_secs());
        let default_timeout_secs = policy.default_timeout_secs().min(max_timeout_secs);
        let max_stdin_bytes = limits
            .stdin_bytes
            .unwrap_or(MAX_RUNTIME_STREAM_BYTES)
            .min(policy.max_stdin_bytes());
        let max_stdout_bytes = limits
            .stdout_bytes
            .unwrap_or(MAX_RUNTIME_STREAM_BYTES)
            .min(policy.max_stdout_bytes());
        let max_stderr_bytes = limits
            .stderr_bytes
            .unwrap_or(MAX_RUNTIME_STREAM_BYTES)
            .min(policy.max_stderr_bytes());
        let max_memory_bytes = limits.memory_bytes;
        Ok(Self {
            schema_version: GOVERNED_EXECUTION_CONTRACT_V1,
            executable: executable.clone(),
            command_prefix: command_prefix.clone(),
            interaction: *interaction,
            stdin_mode: stdin.mode,
            stdin_sensitivity: stdin.sensitivity,
            credential_stdin_reserved,
            working_directory: working_directory.mode,
            max_timeout_secs,
            default_timeout_secs,
            max_stdin_bytes,
            max_stdout_bytes,
            max_stderr_bytes,
            max_memory_bytes,
        })
    }

    pub fn schema_version(&self) -> &'static str {
        self.schema_version
    }

    pub fn interaction(&self) -> CliInteraction {
        self.interaction
    }

    pub fn stdin_mode(&self) -> StdinMode {
        self.stdin_mode
    }

    pub fn stdin_sensitivity(&self) -> DataSensitivity {
        self.stdin_sensitivity
    }

    pub fn working_directory_mode(&self) -> WorkingDirectoryMode {
        self.working_directory
    }

    pub fn command_prefix_len(&self) -> usize {
        self.command_prefix.len()
    }

    pub fn max_timeout_secs(&self) -> u32 {
        self.max_timeout_secs
    }

    pub fn max_stdin_bytes(&self) -> u64 {
        self.max_stdin_bytes
    }

    pub fn max_stdout_bytes(&self) -> u64 {
        self.max_stdout_bytes
    }

    pub fn max_stderr_bytes(&self) -> u64 {
        self.max_stderr_bytes
    }

    pub fn max_memory_bytes(&self) -> Option<u64> {
        self.max_memory_bytes
    }

    /// Validate and retain one value-bearing request. Success still grants no permission
    /// to resolve or launch a process.
    pub fn admit(
        &self,
        request: GovernedExecutionRequest,
    ) -> Result<GovernedExecutionIntent, GovernedExecutionContractError> {
        let GovernedExecutionRequest {
            arguments,
            argument_item_limit,
            stdin,
            working_directory,
            timeout_secs,
        } = request;
        let argument_bytes = validate_arguments(&arguments, argument_item_limit)?;
        if self.credential_stdin_reserved {
            if stdin.is_some() {
                return Err(stdin_reserved_for_credential());
            }
        } else {
            validate_stdin(
                self.stdin_mode,
                self.max_stdin_bytes,
                stdin.as_ref().map(|value| value.as_slice()),
            )?;
        }
        let working_directory = validate_working_directory(
            self.working_directory,
            working_directory.as_ref().map(|value| value.as_str()),
        )?;
        let timeout_secs = match timeout_secs {
            Some(value) if value != 0 && value <= self.max_timeout_secs => value,
            Some(_) => return Err(invalid_timeout()),
            None => self.default_timeout_secs,
        };
        Ok(GovernedExecutionIntent {
            schema_version: GOVERNED_EXECUTION_CONTRACT_V1,
            executable: self.executable.clone(),
            command_prefix: self.command_prefix.clone(),
            interaction: self.interaction,
            stdin_mode: self.stdin_mode,
            stdin_sensitivity: self.stdin_sensitivity,
            credential_stdin_reserved: self.credential_stdin_reserved,
            working_directory_mode: self.working_directory,
            arguments,
            argument_bytes,
            stdin,
            working_directory,
            timeout_secs,
            max_stdin_bytes: self.max_stdin_bytes,
            max_stdout_bytes: self.max_stdout_bytes,
            max_stderr_bytes: self.max_stderr_bytes,
            max_memory_bytes: self.max_memory_bytes,
        })
    }
}

/// Owned request values. It is deliberately move-only, non-debuggable, and
/// non-serializable. Argument, stdin, and working-directory buffers zeroize on drop.
pub struct GovernedExecutionRequest {
    arguments: Zeroizing<Vec<String>>,
    argument_item_limit: usize,
    stdin: Option<Zeroizing<Vec<u8>>>,
    working_directory: Option<Zeroizing<String>>,
    timeout_secs: Option<u32>,
}

impl GovernedExecutionRequest {
    pub fn new(
        arguments: Vec<String>,
        stdin: Option<Vec<u8>>,
        working_directory: Option<String>,
        timeout_secs: Option<u32>,
    ) -> Self {
        Self {
            arguments: Zeroizing::new(arguments),
            argument_item_limit: MAX_ARGUMENT_BYTES,
            stdin: stdin.map(Zeroizing::new),
            working_directory: working_directory.map(Zeroizing::new),
            timeout_secs,
        }
    }

    /// Construct a request for a trusted specialized controller that has
    /// already validated its runtime-only values. Individual inert argv tokens
    /// may consume the existing aggregate 64 KiB ceiling; token count,
    /// aggregate bytes, and control-character rejection remain unchanged.
    pub fn new_with_specialized_runtime_arguments(
        arguments: Vec<String>,
        stdin: Option<Vec<u8>>,
        working_directory: Option<String>,
        timeout_secs: Option<u32>,
    ) -> Self {
        Self {
            arguments: Zeroizing::new(arguments),
            argument_item_limit: MAX_FIXED_ARGUMENT_BYTES,
            stdin: stdin.map(Zeroizing::new),
            working_directory: working_directory.map(Zeroizing::new),
            timeout_secs,
        }
    }
}

/// Pure, move-only invocation intent. Phase 6B must consume this into exact executable
/// and filesystem authority before any runner can observe its value-bearing fields.
pub struct GovernedExecutionIntent {
    schema_version: &'static str,
    executable: String,
    command_prefix: Vec<String>,
    interaction: CliInteraction,
    stdin_mode: StdinMode,
    stdin_sensitivity: DataSensitivity,
    credential_stdin_reserved: bool,
    working_directory_mode: WorkingDirectoryMode,
    arguments: Zeroizing<Vec<String>>,
    argument_bytes: usize,
    stdin: Option<Zeroizing<Vec<u8>>>,
    working_directory: Vec<String>,
    timeout_secs: u32,
    max_stdin_bytes: u64,
    max_stdout_bytes: u64,
    max_stderr_bytes: u64,
    max_memory_bytes: Option<u64>,
}

impl GovernedExecutionIntent {
    pub fn schema_version(&self) -> &'static str {
        self.schema_version
    }

    pub fn interaction(&self) -> CliInteraction {
        self.interaction
    }

    pub fn argument_count(&self) -> usize {
        self.arguments.len()
    }

    pub fn argument_bytes(&self) -> usize {
        self.argument_bytes
    }

    pub fn command_prefix_len(&self) -> usize {
        self.command_prefix.len()
    }

    pub fn has_stdin(&self) -> bool {
        self.stdin.is_some()
    }

    pub fn stdin_bytes(&self) -> usize {
        self.stdin.as_ref().map_or(0, |value| value.len())
    }

    pub fn stdin_mode(&self) -> StdinMode {
        self.stdin_mode
    }

    pub fn stdin_sensitivity(&self) -> DataSensitivity {
        self.stdin_sensitivity
    }

    pub fn credential_stdin_reserved(&self) -> bool {
        self.credential_stdin_reserved
    }

    pub fn working_directory_mode(&self) -> WorkingDirectoryMode {
        self.working_directory_mode
    }

    pub fn working_directory_components(&self) -> usize {
        self.working_directory.len()
    }

    pub fn timeout_secs(&self) -> u32 {
        self.timeout_secs
    }

    pub fn max_stdout_bytes(&self) -> u64 {
        self.max_stdout_bytes
    }

    pub fn max_stderr_bytes(&self) -> u64 {
        self.max_stderr_bytes
    }

    pub fn max_memory_bytes(&self) -> Option<u64> {
        self.max_memory_bytes
    }

    pub(crate) fn max_stdin_bytes(&self) -> u64 {
        self.max_stdin_bytes
    }

    pub(crate) fn executable(&self) -> &str {
        &self.executable
    }

    pub(crate) fn command_prefix(&self) -> &[String] {
        &self.command_prefix
    }

    pub(crate) fn arguments(&self) -> &[String] {
        &self.arguments
    }

    pub(crate) fn stdin(&self) -> Option<&[u8]> {
        self.stdin.as_ref().map(|value| value.as_slice())
    }

    pub(crate) fn working_directory(&self) -> &[String] {
        &self.working_directory
    }

    pub(crate) fn matches_validated_contract(
        &self,
        validated: ValidatedSkillRuntimeContract<'_>,
    ) -> bool {
        let contract = validated.contract();
        let RuntimeProtocol::Cli {
            command_prefix,
            interaction,
            stdin,
            working_directory,
            limits,
        } = &contract.runtime
        else {
            return false;
        };
        let credential_stdin_reserved = contract
            .auth
            .injections
            .iter()
            .any(|binding| binding.target == InjectionTarget::Stdin);
        contract.requires.bins.first().map(String::as_str) == Some(self.executable.as_str())
            && command_prefix == &self.command_prefix
            && *interaction == self.interaction
            && stdin.mode == self.stdin_mode
            && stdin.sensitivity == self.stdin_sensitivity
            && working_directory.mode == self.working_directory_mode
            && credential_stdin_reserved == self.credential_stdin_reserved
            && self.timeout_secs <= limits.timeout_secs.unwrap_or(MAX_RUNTIME_TIMEOUT_SECS)
            && self.max_stdin_bytes <= limits.stdin_bytes.unwrap_or(MAX_RUNTIME_STREAM_BYTES)
            && self.max_stdout_bytes <= limits.stdout_bytes.unwrap_or(MAX_RUNTIME_STREAM_BYTES)
            && self.max_stderr_bytes <= limits.stderr_bytes.unwrap_or(MAX_RUNTIME_STREAM_BYTES)
            && self.max_memory_bytes == limits.memory_bytes
    }

    pub(crate) fn bind_materialized_stdin(
        mut self,
        materialized: Option<&[u8]>,
    ) -> Result<Self, GovernedExecutionContractError> {
        match (self.credential_stdin_reserved, materialized) {
            (true, Some(value))
                if !value.is_empty() && value.len() as u64 <= self.max_stdin_bytes =>
            {
                self.stdin = Some(Zeroizing::new(value.to_vec()));
                Ok(self)
            },
            (true, Some(_)) => Err(stdin_too_large()),
            (true, None) => Err(materialized_stdin_missing()),
            (false, Some(_)) => Err(materialized_stdin_unexpected()),
            (false, None) => Ok(self),
        }
    }

    pub(crate) fn into_parts(self) -> GovernedExecutionIntentParts {
        GovernedExecutionIntentParts {
            executable: self.executable,
            command_prefix: self.command_prefix,
            interaction: self.interaction,
            working_directory_mode: self.working_directory_mode,
            arguments: self.arguments,
            stdin: self.stdin,
            working_directory: self.working_directory,
            timeout_secs: self.timeout_secs,
            max_stdout_bytes: self.max_stdout_bytes,
            max_stderr_bytes: self.max_stderr_bytes,
            max_memory_bytes: self.max_memory_bytes,
        }
    }
}

pub(crate) struct GovernedExecutionIntentParts {
    pub(crate) executable: String,
    pub(crate) command_prefix: Vec<String>,
    pub(crate) interaction: CliInteraction,
    pub(crate) working_directory_mode: WorkingDirectoryMode,
    pub(crate) arguments: Zeroizing<Vec<String>>,
    pub(crate) stdin: Option<Zeroizing<Vec<u8>>>,
    pub(crate) working_directory: Vec<String>,
    pub(crate) timeout_secs: u32,
    pub(crate) max_stdout_bytes: u64,
    pub(crate) max_stderr_bytes: u64,
    pub(crate) max_memory_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedExecutionTerminal {
    Success,
    NonZeroExit,
    Cancelled,
    TimedOut,
    OutputLimitExceeded,
    /// The owned process group's memory footprint passed the declared
    /// `max_memory_bytes` and the executor terminated it. Distinct from
    /// `TimedOut`: the child was killed for what it held, not how long it ran.
    MemoryLimitExceeded,
    /// Aggregate CPU time across the owned process group crossed the strict
    /// jail ceiling.
    CpuLimitExceeded,
    /// The strict jail's owned process group crossed its process-count ceiling.
    ProcessLimitExceeded,
    /// The strict jail workdir crossed its file-count or byte ceiling.
    FileLimitExceeded,
    ArtifactRejected,
    LaunchRejected,
    RuntimeFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedExecutionDispatch {
    NotDispatched,
    Dispatched,
    UnknownAfterDispatch,
}

/// Value-free terminal classification. Output and artifacts remain in the sealed result
/// boundary introduced by Phase 6D.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct GovernedExecutionTerminalState {
    pub schema_version: &'static str,
    terminal: GovernedExecutionTerminal,
    dispatch: GovernedExecutionDispatch,
}

impl GovernedExecutionTerminalState {
    pub fn new(
        terminal: GovernedExecutionTerminal,
        dispatch: GovernedExecutionDispatch,
    ) -> Result<Self, GovernedExecutionContractError> {
        if !terminal_dispatch_is_valid(terminal, dispatch) {
            return Err(invalid_terminal_state());
        }
        Ok(Self {
            schema_version: GOVERNED_EXECUTION_CONTRACT_V1,
            terminal,
            dispatch,
        })
    }

    pub(crate) fn executor_owned(
        terminal: GovernedExecutionTerminal,
        dispatch: GovernedExecutionDispatch,
    ) -> Self {
        if terminal_dispatch_is_valid(terminal, dispatch) {
            Self {
                schema_version: GOVERNED_EXECUTION_CONTRACT_V1,
                terminal,
                dispatch,
            }
        } else {
            Self {
                schema_version: GOVERNED_EXECUTION_CONTRACT_V1,
                terminal: GovernedExecutionTerminal::RuntimeFailure,
                dispatch: GovernedExecutionDispatch::UnknownAfterDispatch,
            }
        }
    }

    pub(crate) fn launch_rejected() -> Self {
        Self::executor_owned(
            GovernedExecutionTerminal::LaunchRejected,
            GovernedExecutionDispatch::NotDispatched,
        )
    }

    pub(crate) fn cancelled(dispatch: GovernedExecutionDispatch) -> Self {
        Self::executor_owned(GovernedExecutionTerminal::Cancelled, dispatch)
    }

    pub(crate) fn timed_out(dispatch: GovernedExecutionDispatch) -> Self {
        Self::executor_owned(GovernedExecutionTerminal::TimedOut, dispatch)
    }

    pub(crate) fn runtime_failure(dispatch: GovernedExecutionDispatch) -> Self {
        Self::executor_owned(GovernedExecutionTerminal::RuntimeFailure, dispatch)
    }

    pub fn terminal(self) -> GovernedExecutionTerminal {
        self.terminal
    }

    pub fn dispatch(self) -> GovernedExecutionDispatch {
        self.dispatch
    }
}

fn terminal_dispatch_is_valid(
    terminal: GovernedExecutionTerminal,
    dispatch: GovernedExecutionDispatch,
) -> bool {
    match terminal {
        GovernedExecutionTerminal::Success
        | GovernedExecutionTerminal::NonZeroExit
        | GovernedExecutionTerminal::OutputLimitExceeded
        | GovernedExecutionTerminal::MemoryLimitExceeded
        | GovernedExecutionTerminal::CpuLimitExceeded
        | GovernedExecutionTerminal::ProcessLimitExceeded
        | GovernedExecutionTerminal::FileLimitExceeded
        | GovernedExecutionTerminal::ArtifactRejected => {
            dispatch == GovernedExecutionDispatch::Dispatched
        },
        GovernedExecutionTerminal::LaunchRejected => {
            dispatch == GovernedExecutionDispatch::NotDispatched
        },
        GovernedExecutionTerminal::Cancelled
        | GovernedExecutionTerminal::TimedOut
        | GovernedExecutionTerminal::RuntimeFailure => true,
    }
}

fn validate_arguments(
    arguments: &[String],
    argument_item_limit: usize,
) -> Result<usize, GovernedExecutionContractError> {
    if arguments.len() > MAX_FIXED_ARGUMENTS {
        return Err(too_many_arguments());
    }
    let mut total = 0usize;
    for argument in arguments {
        if argument.len() > argument_item_limit || argument.chars().any(char::is_control) {
            return Err(invalid_argument());
        }
        total = total
            .checked_add(argument.len())
            .ok_or_else(arguments_too_large)?;
        if total > MAX_FIXED_ARGUMENT_BYTES {
            return Err(arguments_too_large());
        }
    }
    Ok(total)
}

fn validate_stdin(
    mode: StdinMode,
    max_bytes: u64,
    stdin: Option<&[u8]>,
) -> Result<(), GovernedExecutionContractError> {
    match (mode, stdin) {
        (StdinMode::Denied, Some(_)) => Err(stdin_denied()),
        (StdinMode::Required, None) => Err(stdin_required()),
        (_, Some(value)) if value.len() as u64 > max_bytes => Err(stdin_too_large()),
        _ => Ok(()),
    }
}

fn validate_working_directory(
    mode: WorkingDirectoryMode,
    value: Option<&str>,
) -> Result<Vec<String>, GovernedExecutionContractError> {
    if mode == WorkingDirectoryMode::Denied {
        return match value {
            Some(_) => Err(working_directory_denied()),
            None => Ok(Vec::new()),
        };
    }
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if value.is_empty()
        || value.len() > MAX_SYNTHESIZED_WORKING_DIRECTORY_BYTES as usize
        || value.starts_with('/')
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        return Err(invalid_working_directory());
    }
    let mut components = Vec::new();
    for component in value.split('/') {
        if components.len() >= MAX_GOVERNED_WORKING_DIRECTORY_COMPONENTS
            || component.is_empty()
            || component.len() > MAX_GOVERNED_WORKING_DIRECTORY_COMPONENT_BYTES
            || matches!(component, "." | "..")
        {
            return Err(invalid_working_directory());
        }
        components.push(component.to_owned());
    }
    Ok(components)
}

const fn unsupported_protocol() -> GovernedExecutionContractError {
    GovernedExecutionContractError::new(
        GovernedExecutionContractErrorCode::UnsupportedProtocol,
        "runtime.protocol",
        "governed executable execution requires a validated CLI contract",
    )
}

const fn invalid_local_policy() -> GovernedExecutionContractError {
    GovernedExecutionContractError::new(
        GovernedExecutionContractErrorCode::InvalidLocalPolicy,
        "local_policy",
        "the local execution policy is outside immutable resource ceilings",
    )
}

const fn too_many_arguments() -> GovernedExecutionContractError {
    GovernedExecutionContractError::new(
        GovernedExecutionContractErrorCode::TooManyArguments,
        "args",
        "the invocation has too many argument tokens",
    )
}

const fn invalid_argument() -> GovernedExecutionContractError {
    GovernedExecutionContractError::new(
        GovernedExecutionContractErrorCode::InvalidArgument,
        "args",
        "an argument exceeds its byte limit or contains a control character",
    )
}

const fn arguments_too_large() -> GovernedExecutionContractError {
    GovernedExecutionContractError::new(
        GovernedExecutionContractErrorCode::ArgumentsTooLarge,
        "args",
        "the aggregate argument bytes exceed the invocation ceiling",
    )
}

const fn stdin_denied() -> GovernedExecutionContractError {
    GovernedExecutionContractError::new(
        GovernedExecutionContractErrorCode::StdinDenied,
        "stdin",
        "standard input is not permitted by this execution contract",
    )
}

const fn stdin_reserved_for_credential() -> GovernedExecutionContractError {
    GovernedExecutionContractError::new(
        GovernedExecutionContractErrorCode::StdinReservedForCredential,
        "stdin",
        "standard input is reserved for a declared credential injection",
    )
}

const fn stdin_required() -> GovernedExecutionContractError {
    GovernedExecutionContractError::new(
        GovernedExecutionContractErrorCode::StdinRequired,
        "stdin",
        "standard input is required by this execution contract",
    )
}

const fn stdin_too_large() -> GovernedExecutionContractError {
    GovernedExecutionContractError::new(
        GovernedExecutionContractErrorCode::StdinTooLarge,
        "stdin",
        "standard input exceeds the effective byte ceiling",
    )
}

const fn materialized_stdin_missing() -> GovernedExecutionContractError {
    GovernedExecutionContractError::new(
        GovernedExecutionContractErrorCode::MaterializedStdinMissing,
        "stdin",
        "the declared credential stdin value was not materialized",
    )
}

const fn materialized_stdin_unexpected() -> GovernedExecutionContractError {
    GovernedExecutionContractError::new(
        GovernedExecutionContractErrorCode::MaterializedStdinUnexpected,
        "stdin",
        "credential material attempted to inject undeclared standard input",
    )
}

const fn working_directory_denied() -> GovernedExecutionContractError {
    GovernedExecutionContractError::new(
        GovernedExecutionContractErrorCode::WorkingDirectoryDenied,
        "working_dir",
        "a working directory is not permitted by this execution contract",
    )
}

const fn invalid_working_directory() -> GovernedExecutionContractError {
    GovernedExecutionContractError::new(
        GovernedExecutionContractErrorCode::InvalidWorkingDirectory,
        "working_dir",
        "the working directory is not a bounded portable relative path",
    )
}

const fn invalid_timeout() -> GovernedExecutionContractError {
    GovernedExecutionContractError::new(
        GovernedExecutionContractErrorCode::InvalidTimeout,
        "timeout_secs",
        "the requested timeout is outside the effective non-zero ceiling",
    )
}

const fn invalid_terminal_state() -> GovernedExecutionContractError {
    GovernedExecutionContractError::new(
        GovernedExecutionContractErrorCode::InvalidLocalPolicy,
        "terminal_state",
        "the terminal classification is incompatible with dispatch certainty",
    )
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use serde::Serialize;
    use static_assertions::assert_not_impl_any;

    use super::*;
    use crate::{
        manifest::{
            AuthContract, AuthKind, AuthRequirement, InjectionBinding, InjectionSource,
            InjectionTarget, PolicyFloor, RuntimeLimits, RuntimeRequirements, SecretBindingRef,
            SkillRuntimeContract, SkillRuntimeContractVersion, StdinContract,
            WorkingDirectoryContract,
        },
        manifest_validation::validate_skill_runtime_contract,
    };

    fn policy() -> GovernedExecutionPolicy {
        GovernedExecutionPolicy::new(30, 120, 1024, 2048, 4096).unwrap()
    }

    fn cli_contract() -> SkillRuntimeContract {
        SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires: RuntimeRequirements {
                bins: ["fixture-cli".to_owned()].into_iter().collect(),
                entrypoint: Default::default(),
                environment: Default::default(),
            },
            runtime: RuntimeProtocol::Cli {
                command_prefix: vec!["fixed".to_owned(), "--json".to_owned()],
                interaction: CliInteraction::Batch,
                stdin: StdinContract::default(),
                working_directory: WorkingDirectoryContract::default(),
                limits: RuntimeLimits::default(),
            },
            auth: AuthContract::default(),
            policy_floor: PolicyFloor::default(),
        }
    }

    fn compile(contract: &SkillRuntimeContract) -> GovernedExecutionContract {
        GovernedExecutionContract::compile(
            validate_skill_runtime_contract(contract).unwrap(),
            policy(),
        )
        .unwrap()
    }

    #[test]
    fn exact_inert_argument_forms_round_trip_without_shell_interpretation() {
        let contract = cli_contract();
        let compiled = compile(&contract);
        let values = vec![
            "two words".to_owned(),
            "हैलो-世界".to_owned(),
            r#"{"key":"value"}"#.to_owned(),
            "https://example.test/a?q=x&next=y".to_owned(),
            String::new(),
            "$(touch /tmp/nope);`false`|&<>*?[]{}$HOME".to_owned(),
        ];
        let intent = compiled
            .admit(GovernedExecutionRequest::new(
                values.clone(),
                None,
                None,
                None,
            ))
            .unwrap();
        assert_eq!(&*intent.arguments, &values);
        assert_eq!(intent.command_prefix, vec!["fixed", "--json"]);
        assert_eq!(intent.timeout_secs(), 30);
    }

    #[test]
    fn argument_count_item_and_aggregate_limits_fail_closed() {
        let contract = cli_contract();
        let compiled = compile(&contract);
        let too_many = vec![String::new(); MAX_FIXED_ARGUMENTS + 1];
        assert_eq!(
            compiled
                .admit(GovernedExecutionRequest::new(too_many, None, None, None))
                .err()
                .expect("too many arguments must fail")
                .code,
            GovernedExecutionContractErrorCode::TooManyArguments
        );
        assert_eq!(
            compiled
                .admit(GovernedExecutionRequest::new(
                    vec!["\n".to_owned()],
                    None,
                    None,
                    None,
                ))
                .err()
                .expect("control characters must fail")
                .code,
            GovernedExecutionContractErrorCode::InvalidArgument
        );
        let aggregate = vec!["x".repeat(MAX_ARGUMENT_BYTES); MAX_FIXED_ARGUMENTS];
        assert_eq!(
            compiled
                .admit(GovernedExecutionRequest::new(aggregate, None, None, None))
                .err()
                .expect("aggregate argument overflow must fail")
                .code,
            GovernedExecutionContractErrorCode::ArgumentsTooLarge
        );
    }

    #[test]
    fn specialized_runtime_arguments_allow_one_bounded_prompt_without_weakening_defaults() {
        let contract = cli_contract();
        let compiled = compile(&contract);
        let prompt = "x".repeat(32 * 1024);
        assert_eq!(
            compiled
                .admit(GovernedExecutionRequest::new(
                    vec![prompt.clone()],
                    None,
                    None,
                    None,
                ))
                .err()
                .expect("the generic per-item ceiling must remain unchanged")
                .code,
            GovernedExecutionContractErrorCode::InvalidArgument
        );
        let intent = compiled
            .admit(
                GovernedExecutionRequest::new_with_specialized_runtime_arguments(
                    vec![prompt],
                    None,
                    None,
                    None,
                ),
            )
            .expect("a trusted specialized controller may use the aggregate ceiling");
        assert_eq!(intent.argument_bytes(), 32 * 1024);
        for rejected in ["\n".to_owned(), "x".repeat(MAX_FIXED_ARGUMENT_BYTES + 1)] {
            assert_eq!(
                compiled
                    .admit(
                        GovernedExecutionRequest::new_with_specialized_runtime_arguments(
                            vec![rejected],
                            None,
                            None,
                            None,
                        ),
                    )
                    .err()
                    .expect("specialized arguments remain bounded and control-free")
                    .code,
                GovernedExecutionContractErrorCode::InvalidArgument
            );
        }
    }

    #[test]
    fn stdin_mode_and_effective_manifest_policy_ceiling_are_exact() {
        let mut contract = cli_contract();
        let RuntimeProtocol::Cli { stdin, limits, .. } = &mut contract.runtime else {
            unreachable!()
        };
        stdin.mode = StdinMode::Required;
        stdin.sensitivity = DataSensitivity::Secret;
        limits.stdin_bytes = Some(4);
        let compiled = compile(&contract);
        assert_eq!(compiled.max_stdin_bytes(), 4);
        assert_eq!(compiled.stdin_sensitivity(), DataSensitivity::Secret);
        assert_eq!(
            compiled
                .admit(GovernedExecutionRequest::new(vec![], None, None, None))
                .err()
                .expect("missing required stdin must fail")
                .code,
            GovernedExecutionContractErrorCode::StdinRequired
        );
        assert_eq!(
            compiled
                .admit(GovernedExecutionRequest::new(
                    vec![],
                    Some(vec![0; 5]),
                    None,
                    None,
                ))
                .err()
                .expect("oversized stdin must fail")
                .code,
            GovernedExecutionContractErrorCode::StdinTooLarge
        );
        let intent = compiled
            .admit(GovernedExecutionRequest::new(
                vec![],
                Some(Vec::new()),
                None,
                None,
            ))
            .unwrap();
        assert!(intent.has_stdin());
        assert_eq!(intent.stdin_bytes(), 0);
    }

    #[test]
    fn excessive_working_directory_depth_fails_during_pure_admission() {
        let mut contract = cli_contract();
        let RuntimeProtocol::Cli {
            working_directory, ..
        } = &mut contract.runtime
        else {
            unreachable!();
        };
        working_directory.mode = WorkingDirectoryMode::Workspace;
        let value = std::iter::repeat_n("a", MAX_GOVERNED_WORKING_DIRECTORY_COMPONENTS + 1)
            .collect::<Vec<_>>()
            .join("/");
        assert_eq!(
            compile(&contract)
                .admit(GovernedExecutionRequest::new(
                    vec![],
                    None,
                    Some(value),
                    None,
                ))
                .err()
                .expect("over-deep cwd must fail before authorization")
                .code,
            GovernedExecutionContractErrorCode::InvalidWorkingDirectory
        );
    }

    #[test]
    fn credential_reserved_stdin_rejects_model_bytes_and_binds_once_after_materialization() {
        let mut contract = cli_contract();
        contract.auth = AuthContract {
            kind: AuthKind::Secrets,
            requirement: AuthRequirement::Required,
            secret_bindings: vec![SecretBindingRef {
                name: "token".to_owned(),
                secret_ref: "VAULT_TEST_TOKEN".to_owned(),
            }],
            injections: vec![InjectionBinding {
                source: InjectionSource::Secret {
                    binding: "token".to_owned(),
                },
                target: InjectionTarget::Stdin,
            }],
            ..AuthContract::default()
        };
        let compiled = compile(&contract);
        assert_eq!(
            compiled
                .admit(GovernedExecutionRequest::new(
                    vec![],
                    Some(b"model-data".to_vec()),
                    None,
                    None,
                ))
                .err()
                .expect("model stdin must not collide with a credential target")
                .code,
            GovernedExecutionContractErrorCode::StdinReservedForCredential
        );
        let intent = compiled
            .admit(GovernedExecutionRequest::new(vec![], None, None, None))
            .unwrap();
        assert!(intent.credential_stdin_reserved());
        assert_eq!(
            intent
                .bind_materialized_stdin(None)
                .err()
                .expect("declared credential stdin must materialize")
                .code,
            GovernedExecutionContractErrorCode::MaterializedStdinMissing
        );
        let intent = compiled
            .admit(GovernedExecutionRequest::new(vec![], None, None, None))
            .unwrap()
            .bind_materialized_stdin(Some(b"credential"))
            .unwrap();
        assert_eq!(intent.stdin(), Some(&b"credential"[..]));
    }

    #[test]
    fn working_directory_is_mode_bound_and_lexically_relative() {
        let mut contract = cli_contract();
        let RuntimeProtocol::Cli {
            working_directory, ..
        } = &mut contract.runtime
        else {
            unreachable!()
        };
        working_directory.mode = WorkingDirectoryMode::Workspace;
        let compiled = compile(&contract);
        let intent = compiled
            .admit(GovernedExecutionRequest::new(
                vec![],
                None,
                Some("रिपोर्ट/2026".to_owned()),
                None,
            ))
            .unwrap();
        assert_eq!(intent.working_directory, vec!["रिपोर्ट", "2026"]);
        for invalid in ["/tmp", "../escape", "a/../b", "a//b", "a\\b", "."] {
            assert_eq!(
                compiled
                    .admit(GovernedExecutionRequest::new(
                        vec![],
                        None,
                        Some(invalid.to_owned()),
                        None,
                    ))
                    .err()
                    .expect("invalid working directory must fail")
                    .code,
                GovernedExecutionContractErrorCode::InvalidWorkingDirectory
            );
        }
        assert_eq!(
            compiled
                .admit(GovernedExecutionRequest::new(
                    vec![],
                    None,
                    Some("x".repeat(MAX_GOVERNED_WORKING_DIRECTORY_COMPONENT_BYTES + 1)),
                    None,
                ))
                .err()
                .expect("oversized path component must fail")
                .code,
            GovernedExecutionContractErrorCode::InvalidWorkingDirectory
        );
    }

    #[test]
    fn timeout_and_output_limits_are_intersections_not_manifest_expansions() {
        let mut contract = cli_contract();
        let RuntimeProtocol::Cli { limits, .. } = &mut contract.runtime else {
            unreachable!()
        };
        limits.timeout_secs = Some(10);
        limits.stdout_bytes = Some(99);
        let compiled = compile(&contract);
        assert_eq!(compiled.max_timeout_secs(), 10);
        assert_eq!(compiled.max_stdout_bytes(), 99);
        assert_eq!(compiled.max_stderr_bytes(), 4096);
        assert_eq!(
            compiled
                .admit(GovernedExecutionRequest::new(vec![], None, None, Some(11),))
                .err()
                .expect("timeout above the ceiling must fail")
                .code,
            GovernedExecutionContractErrorCode::InvalidTimeout
        );
        assert_eq!(
            compiled
                .admit(GovernedExecutionRequest::new(vec![], None, None, None))
                .unwrap()
                .timeout_secs(),
            10
        );
    }

    #[test]
    fn batch_and_pty_contracts_remain_explicitly_separate() {
        let mut contract = cli_contract();
        let RuntimeProtocol::Cli { interaction, .. } = &mut contract.runtime else {
            unreachable!()
        };
        *interaction = CliInteraction::Pty;
        let compiled = compile(&contract);
        assert_eq!(compiled.interaction(), CliInteraction::Pty);
        assert_eq!(
            compiled
                .admit(GovernedExecutionRequest::new(vec![], None, None, None))
                .unwrap()
                .interaction(),
            CliInteraction::Pty
        );
    }

    #[test]
    fn mcp_contract_cannot_be_reinterpreted_as_executable_authority() {
        let mut contract = cli_contract();
        contract.runtime = RuntimeProtocol::Mcp {
            transport: crate::manifest::McpTransport::StreamableHttp {
                endpoint: "https://example.test/mcp".to_owned(),
            },
            discovery: Default::default(),
            limits: RuntimeLimits::default(),
        };
        contract.requires.bins.clear();
        assert_eq!(
            GovernedExecutionContract::compile(
                validate_skill_runtime_contract(&contract).unwrap(),
                policy(),
            )
            .err()
            .expect("MCP contract must not compile as CLI execution")
            .code,
            GovernedExecutionContractErrorCode::UnsupportedProtocol
        );
    }

    #[test]
    fn errors_are_fixed_and_terminal_dispatch_combinations_are_checked() {
        let canary = "do-not-copy-this-request";
        let contract = cli_contract();
        let compiled = compile(&contract);
        let error = compiled
            .admit(GovernedExecutionRequest::new(
                vec![format!("{canary}\n")],
                None,
                None,
                None,
            ))
            .err()
            .expect("control-bearing argument must fail");
        assert!(!format!("{error:?} {error}").contains(canary));
        assert!(GovernedExecutionTerminalState::new(
            GovernedExecutionTerminal::Success,
            GovernedExecutionDispatch::Dispatched,
        )
        .is_ok());
        assert!(GovernedExecutionTerminalState::new(
            GovernedExecutionTerminal::TimedOut,
            GovernedExecutionDispatch::NotDispatched,
        )
        .is_ok());
        assert_eq!(
            GovernedExecutionTerminalState::new(
                GovernedExecutionTerminal::Success,
                GovernedExecutionDispatch::NotDispatched,
            )
            .expect_err("invalid terminal state must fail")
            .code,
            GovernedExecutionContractErrorCode::InvalidLocalPolicy
        );
    }

    #[test]
    fn maximum_intent_validation_is_iterative_on_a_small_stack() {
        let contract = cli_contract();
        let handle = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(move || {
                let compiled = compile(&contract);
                let arguments = vec![
                    "x".repeat(MAX_FIXED_ARGUMENT_BYTES / MAX_FIXED_ARGUMENTS);
                    MAX_FIXED_ARGUMENTS
                ];
                let intent = compiled
                    .admit(GovernedExecutionRequest::new(arguments, None, None, None))
                    .unwrap();
                assert_eq!(intent.argument_count(), MAX_FIXED_ARGUMENTS);
            })
            .unwrap();
        handle.join().unwrap();
    }

    assert_not_impl_any!(GovernedExecutionContract: Clone, fmt::Debug, Serialize);
    assert_not_impl_any!(GovernedExecutionRequest: Clone, fmt::Debug, Serialize);
    assert_not_impl_any!(GovernedExecutionIntent: Clone, fmt::Debug, Serialize);
}
