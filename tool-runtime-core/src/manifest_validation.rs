//! Pure semantic validation for versioned skill runtime contracts.
//!
//! Parsing proves that authored YAML matches the v1 vocabulary. This module
//! proves that the resulting fields form one unambiguous, internally
//! consistent runtime/authentication contract. Validation performs no I/O,
//! execution, environment access, credential resolution, or network work.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    net::IpAddr,
};

use serde::Serialize;
use url::{Host, Url};

use crate::manifest::{
    AuthContract, AuthKind, AuthRequirement, AuthStorage, CliInteraction, DataSensitivity,
    IdentityContract, IdentitySelector, InjectionBinding, InjectionSource, InjectionTarget,
    LifecycleHook, LifecycleJsonPredicate, LifecycleJsonScalar, LifecycleObservedAuthState,
    LifecycleStatusObservation, LifecycleStatusOutputFormat, McpDiscoveryPolicy, McpToolRiskClass,
    McpTransport, PolicyFloor, ProfileSelection, RuntimeLimits, RuntimeProtocol,
    SkillRuntimeContract, StdinMode, MINIMAX_PROVIDER, MMX_CONFIG_DIR, SKILL_RUNTIME_CONTRACT_V1,
};

pub const MAX_EXECUTABLE_REQUIREMENTS: usize = 32;
pub const MAX_FIXED_ARGUMENTS: usize = 128;
pub const MAX_ARGUMENT_BYTES: usize = 4 * 1024;
pub const MAX_FIXED_ENVIRONMENT_VARIABLES: usize = 64;
pub const MAX_FIXED_ENVIRONMENT_NAME_BYTES: usize = 128;
pub const MAX_FIXED_ENVIRONMENT_VALUE_BYTES: usize = 4 * 1024;
pub const MAX_FIXED_ENVIRONMENT_TOTAL_BYTES: usize = 64 * 1024;
pub const MAX_FIXED_ARGUMENT_BYTES: usize = 64 * 1024;
pub const MAX_AUTH_BINDINGS: usize = 64;
pub const MAX_AUTH_INJECTIONS: usize = 64;
pub const MAX_DISCOVERY_RULES: usize = 512;
pub const MAX_POLICY_ENTRIES: usize = 256;
pub const MAX_TRUSTED_MCP_DESCRIPTION_BYTES: usize = 8 * 1024;
pub const MAX_MCP_TOOL_POLICY_REFERENCES: usize = 4 * 1024;
pub const MAX_MCP_TRUSTED_DESCRIPTION_BYTES: usize = 256 * 1024;
pub const MAX_MCP_ENDPOINT_ALIASES: usize = 16;
pub const MAX_MCP_OAUTH_SCOPES: usize = 64;
pub const MAX_MCP_COMMERCE_RULES: usize = 128;
pub const MAX_MCP_COMMERCE_TOTAL_FIELDS: usize = 32;
pub const MAX_PROFILE_PATH_SEGMENTS: usize = 32;
pub const MAX_RUNTIME_TIMEOUT_SECS: u32 = 24 * 60 * 60;
pub const MAX_LIFECYCLE_TIMEOUT_SECS: u32 = 15 * 60;
pub const MAX_LIFECYCLE_STATUS_RULES: usize = 32;
pub const MAX_LIFECYCLE_STATUS_PREDICATES: usize = 32;
pub const MAX_LIFECYCLE_STATUS_EXIT_CODES: usize = 16;
pub const MAX_LIFECYCLE_STATUS_ARRAY_VALUES: usize = 64;
pub const MAX_RUNTIME_STREAM_BYTES: u64 = 256 * 1024 * 1024;
// Keep the authored per-process ceiling at or below the executor's global
// reservation budget. A contract that validates must never be impossible to
// schedule solely because its declared limit exceeds the process pool ceiling.
pub const MAX_RUNTIME_MEMORY_BYTES: u64 = 8 * 1024 * 1024 * 1024;

const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_REFERENCE_BYTES: usize = 512;
const MAX_ENDPOINT_BYTES: usize = 2 * 1024;
const MAX_RELATIVE_PATH_BYTES: usize = 1024;
const MAX_IDENTITY_REASON_BYTES: usize = 512;
const MAX_JSON_POINTER_BYTES: usize = 1024;
const MAX_LIFECYCLE_STATUS_VALUE_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestValidationErrorCode {
    UnsupportedSchemaVersion,
    CollectionTooLarge,
    AmbiguousExecutable,
    InvalidExecutable,
    ExecutableRequirementMismatch,
    InvalidEnvironment,
    InvalidArgument,
    IllegalCommandPrefix,
    InvalidIdentifier,
    InvalidRuntimeLimit,
    InvalidStdinContract,
    InvalidMcpEndpoint,
    InvalidMcpDiscovery,
    InvalidAuthRequirement,
    InvalidAuthProvider,
    MissingAuthProvider,
    InvalidProfileSelection,
    InvalidAuthStorage,
    InvalidSecretBinding,
    InvalidInjection,
    DuplicateInjectionTarget,
    InvalidLifecycle,
    InvalidIdentity,
    IncompatibleProtocolAuth,
    InvalidPolicyFloor,
}

/// A stable, secret-safe semantic diagnostic.
///
/// `field` and `message` are selected from fixed validator-owned strings. The
/// authored value is deliberately never copied into an error, its `Display`
/// form, or its serialized representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ManifestValidationError {
    pub code: ManifestValidationErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl ManifestValidationError {
    const fn new(
        code: ManifestValidationErrorCode,
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

impl fmt::Display for ManifestValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for ManifestValidationError {}

/// Proof that a borrowed v1 contract passed every Phase 1C invariant.
///
/// The private field prevents later compiler slices from accidentally treating
/// a merely-deserialized contract as executable input.
#[derive(Debug, Clone, Copy)]
pub struct ValidatedSkillRuntimeContract<'a> {
    contract: &'a SkillRuntimeContract,
}

impl<'a> ValidatedSkillRuntimeContract<'a> {
    pub fn contract(self) -> &'a SkillRuntimeContract {
        self.contract
    }
}

/// Validate one already-parsed runtime contract without resolving anything.
pub fn validate_skill_runtime_contract(
    contract: &SkillRuntimeContract,
) -> Result<ValidatedSkillRuntimeContract<'_>, ManifestValidationError> {
    if contract.schema_version.as_str() != SKILL_RUNTIME_CONTRACT_V1 {
        return Err(error(
            ManifestValidationErrorCode::UnsupportedSchemaVersion,
            "schema_version",
            "the semantic validator supports only the v1 runtime contract",
        ));
    }

    validate_collection_bounds(contract)?;
    validate_requirements(contract)?;
    validate_runtime(contract)?;
    validate_policy_floor(&contract.policy_floor)?;
    validate_auth(
        &contract.auth,
        &contract.runtime,
        contract
            .requires
            .entrypoint
            .as_ref()
            .or_else(|| contract.requires.bins.first())
            .map(String::as_str),
    )?;

    Ok(ValidatedSkillRuntimeContract { contract })
}

const fn error(
    code: ManifestValidationErrorCode,
    field: &'static str,
    message: &'static str,
) -> ManifestValidationError {
    ManifestValidationError::new(code, field, message)
}

fn validate_collection_bounds(
    contract: &SkillRuntimeContract,
) -> Result<(), ManifestValidationError> {
    if contract.requires.bins.len() > MAX_EXECUTABLE_REQUIREMENTS {
        return Err(error(
            ManifestValidationErrorCode::CollectionTooLarge,
            "requires.bins",
            "too many executable requirements are declared",
        ));
    }
    bounded_len(
        contract.requires.environment.len(),
        MAX_FIXED_ENVIRONMENT_VARIABLES,
        "requires.environment",
    )?;
    match &contract.runtime {
        RuntimeProtocol::Cli { command_prefix, .. } => {
            bounded_len(
                command_prefix.len(),
                MAX_FIXED_ARGUMENTS,
                "runtime.command_prefix",
            )?;
        },
        RuntimeProtocol::Mcp {
            transport,
            discovery,
            ..
        } => {
            if let McpTransport::Stdio { args, .. } = transport {
                bounded_len(args.len(), MAX_FIXED_ARGUMENTS, "runtime.transport.args")?;
            }
            bounded_len(
                discovery.allow_tools.len(),
                MAX_DISCOVERY_RULES,
                "runtime.discovery.allow_tools",
            )?;
            bounded_len(
                discovery.deny_tools.len(),
                MAX_DISCOVERY_RULES,
                "runtime.discovery.deny_tools",
            )?;
            bounded_len(
                discovery.tool_policies.len(),
                MAX_DISCOVERY_RULES,
                "runtime.discovery.tool_policies",
            )?;
            bounded_len(
                discovery.endpoint_aliases.len(),
                MAX_MCP_ENDPOINT_ALIASES,
                "runtime.discovery.endpoint_aliases",
            )?;
            if let Some(oauth) = &discovery.oauth {
                bounded_len(
                    oauth.scopes.len(),
                    MAX_MCP_OAUTH_SCOPES,
                    "runtime.discovery.oauth.scopes",
                )?;
            }
            if let Some(commerce) = &discovery.commerce {
                for (count, field) in [
                    (
                        commerce.final_tools.len(),
                        "runtime.discovery.commerce.final_tools",
                    ),
                    (
                        commerce.conditional_final_tools.len(),
                        "runtime.discovery.commerce.conditional_final_tools",
                    ),
                    (
                        commerce.checkout_name_terms.len(),
                        "runtime.discovery.commerce.checkout_name_terms",
                    ),
                    (
                        commerce.cart_name_terms.len(),
                        "runtime.discovery.commerce.cart_name_terms",
                    ),
                    (
                        commerce.cart_read_verb_terms.len(),
                        "runtime.discovery.commerce.cart_read_verb_terms",
                    ),
                    (
                        commerce.cartless_endpoint_aliases.len(),
                        "runtime.discovery.commerce.cartless_endpoint_aliases",
                    ),
                ] {
                    bounded_len(count, MAX_MCP_COMMERCE_RULES, field)?;
                }
                bounded_len(
                    commerce.total_field_priority.len(),
                    MAX_MCP_COMMERCE_TOTAL_FIELDS,
                    "runtime.discovery.commerce.total_field_priority",
                )?;
            }
            for policy in discovery.tool_policies.values() {
                bounded_len(
                    policy.additional_approvals.len(),
                    MAX_POLICY_ENTRIES,
                    "runtime.discovery.tool_policies.additional_approvals",
                )?;
                bounded_len(
                    policy.additional_required_grants.len(),
                    MAX_POLICY_ENTRIES,
                    "runtime.discovery.tool_policies.additional_required_grants",
                )?;
                bounded_len(
                    policy.additional_resource_scopes.len(),
                    MAX_POLICY_ENTRIES,
                    "runtime.discovery.tool_policies.additional_resource_scopes",
                )?;
                bounded_len(
                    policy.additional_required_resource_authorities.len(),
                    MAX_POLICY_ENTRIES,
                    "runtime.discovery.tool_policies.additional_required_resource_authorities",
                )?;
            }
            let policy_references =
                discovery
                    .tool_policies
                    .values()
                    .try_fold(0usize, |total, policy| {
                        total.checked_add(
                            policy.additional_approvals.len()
                                + policy.additional_required_grants.len()
                                + policy.additional_resource_scopes.len()
                                + policy.additional_required_resource_authorities.len(),
                        )
                    });
            if policy_references.is_none_or(|count| count > MAX_MCP_TOOL_POLICY_REFERENCES) {
                return Err(error(
                    ManifestValidationErrorCode::CollectionTooLarge,
                    "runtime.discovery.tool_policies",
                    "the aggregate MCP tool policy reference count exceeds its limit",
                ));
            }
            let trusted_description_bytes =
                discovery
                    .tool_policies
                    .values()
                    .try_fold(0usize, |total, policy| {
                        total
                            .checked_add(policy.trusted_description.as_ref().map_or(0, String::len))
                    });
            if trusted_description_bytes
                .is_none_or(|count| count > MAX_MCP_TRUSTED_DESCRIPTION_BYTES)
            {
                return Err(error(
                    ManifestValidationErrorCode::CollectionTooLarge,
                    "runtime.discovery.tool_policies.trusted_description",
                    "the aggregate trusted MCP description size exceeds its limit",
                ));
            }
        },
    }
    bounded_len(
        contract.auth.secret_bindings.len(),
        MAX_AUTH_BINDINGS,
        "auth.secret_bindings",
    )?;
    bounded_len(
        contract.auth.injections.len(),
        MAX_AUTH_INJECTIONS,
        "auth.injections",
    )?;
    bounded_len(
        contract.policy_floor.required_grants.len(),
        MAX_POLICY_ENTRIES,
        "policy_floor.required_grants",
    )?;
    bounded_len(
        contract.policy_floor.resource_scopes.len(),
        MAX_POLICY_ENTRIES,
        "policy_floor.resource_scopes",
    )?;
    bounded_len(
        contract.policy_floor.required_resource_authorities.len(),
        MAX_POLICY_ENTRIES,
        "policy_floor.required_resource_authorities",
    )?;
    Ok(())
}

fn bounded_len(
    actual: usize,
    maximum: usize,
    field: &'static str,
) -> Result<(), ManifestValidationError> {
    if actual > maximum {
        return Err(error(
            ManifestValidationErrorCode::CollectionTooLarge,
            field,
            "the collection exceeds its semantic limit",
        ));
    }
    Ok(())
}

fn validate_requirements(contract: &SkillRuntimeContract) -> Result<(), ManifestValidationError> {
    for executable in &contract.requires.bins {
        if !is_executable_name(executable) {
            return Err(error(
                ManifestValidationErrorCode::InvalidExecutable,
                "requires.bins",
                "executable requirements must be portable names, not paths",
            ));
        }
    }
    validate_fixed_environment(contract)?;

    match &contract.runtime {
        RuntimeProtocol::Cli { .. }
            if contract.requires.bins.is_empty()
                || contract.requires.bins.len() > 1 && contract.requires.entrypoint.is_none() =>
        {
            Err(error(
                ManifestValidationErrorCode::AmbiguousExecutable,
                "requires.entrypoint",
                "a multi-binary CLI contract must declare one exact entrypoint",
            ))
        },
        RuntimeProtocol::Cli { .. }
            if contract
                .requires
                .entrypoint
                .as_ref()
                .is_some_and(|entrypoint| !contract.requires.bins.contains(entrypoint)) =>
        {
            Err(error(
                ManifestValidationErrorCode::ExecutableRequirementMismatch,
                "requires.entrypoint",
                "the CLI entrypoint must appear in requires.bins",
            ))
        },
        RuntimeProtocol::Mcp {
            transport: McpTransport::Stdio { executable, .. },
            ..
        } if !contract.requires.bins.contains(executable) => Err(error(
            ManifestValidationErrorCode::ExecutableRequirementMismatch,
            "runtime.transport.executable",
            "the stdio executable must also appear in requires.bins",
        )),
        RuntimeProtocol::Mcp {
            transport: McpTransport::StreamableHttp { .. },
            ..
        } if !contract.requires.bins.is_empty()
            || contract.requires.entrypoint.is_some()
            || !contract.requires.environment.is_empty() =>
        {
            Err(error(
                ManifestValidationErrorCode::AmbiguousExecutable,
                "requires.bins",
                "a remote Streamable HTTP contract cannot declare local process requirements",
            ))
        },
        RuntimeProtocol::Mcp { .. }
            if contract.requires.entrypoint.is_some()
                || !contract.requires.environment.is_empty() =>
        {
            Err(error(
                ManifestValidationErrorCode::InvalidEnvironment,
                "requires.environment",
                "MCP transports cannot inherit CLI fixed environment configuration",
            ))
        },
        _ => Ok(()),
    }
}

fn validate_fixed_environment(
    contract: &SkillRuntimeContract,
) -> Result<(), ManifestValidationError> {
    let mut total_bytes = 0usize;
    for (name, value) in &contract.requires.environment {
        let valid_name = !name.is_empty()
            && name.len() <= MAX_FIXED_ENVIRONMENT_NAME_BYTES
            && name.bytes().enumerate().all(|(index, byte)| {
                byte == b'_' || byte.is_ascii_uppercase() || index > 0 && byte.is_ascii_digit()
            });
        let process_sensitive = matches!(
            name.as_str(),
            "PATH"
                | "HOME"
                | "LANG"
                | "LC_ALL"
                | "LC_CTYPE"
                | "TERM"
                | "TZ"
                | "ENV"
                | "BASH_ENV"
                | "SHELLOPTS"
                | "PYTHONHOME"
                | "PYTHONPATH"
                | "NODE_OPTIONS"
                | "RUBYOPT"
                | "PERL5LIB"
                | "PERL5OPT"
                | "GIT_CONFIG_GLOBAL"
                | "GIT_CONFIG_SYSTEM"
        ) || name.starts_with("LD_")
            || name.starts_with("DYLD_");
        let injection_collision = contract.auth.injections.iter().any(|injection| {
            matches!(
                &injection.target,
                InjectionTarget::Environment { name: target }
                    if target.eq_ignore_ascii_case(name)
            )
        });
        if !valid_name
            || process_sensitive
            || injection_collision
            || value.len() > MAX_FIXED_ENVIRONMENT_VALUE_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(error(
                ManifestValidationErrorCode::InvalidEnvironment,
                "requires.environment",
                "fixed public environment must be bounded and process-safe",
            ));
        }
        total_bytes = total_bytes
            .checked_add(name.len())
            .and_then(|total| total.checked_add(value.len()))
            .ok_or_else(|| {
                error(
                    ManifestValidationErrorCode::InvalidEnvironment,
                    "requires.environment",
                    "fixed environment exceeds its aggregate byte limit",
                )
            })?;
        if total_bytes > MAX_FIXED_ENVIRONMENT_TOTAL_BYTES {
            return Err(error(
                ManifestValidationErrorCode::InvalidEnvironment,
                "requires.environment",
                "fixed environment exceeds its aggregate byte limit",
            ));
        }
    }
    Ok(())
}

fn validate_runtime(contract: &SkillRuntimeContract) -> Result<(), ManifestValidationError> {
    match &contract.runtime {
        RuntimeProtocol::Cli {
            command_prefix,
            interaction,
            stdin,
            limits,
            ..
        } => {
            let Some(executable) = contract
                .requires
                .entrypoint
                .as_ref()
                .or_else(|| contract.requires.bins.first())
            else {
                return Err(error(
                    ManifestValidationErrorCode::AmbiguousExecutable,
                    "requires.bins",
                    "a CLI contract must declare exactly one executable identity",
                ));
            };
            validate_fixed_arguments(command_prefix, "runtime.command_prefix")?;
            reject_inline_code_prefix(executable, command_prefix, "runtime.command_prefix")?;
            validate_stdin(stdin.mode, stdin.sensitivity, limits)?;
            validate_limits(limits)?;
            if limits.memory_bytes.is_some() && *interaction != CliInteraction::Batch {
                return Err(error(
                    ManifestValidationErrorCode::InvalidRuntimeLimit,
                    "runtime.limits.memory_bytes",
                    "process memory limits require batch CLI interaction",
                ));
            }
            Ok(())
        },
        RuntimeProtocol::Mcp {
            transport,
            discovery,
            limits,
        } => {
            match transport {
                McpTransport::Stdio { executable, args } => {
                    if !is_executable_name(executable) {
                        return Err(error(
                            ManifestValidationErrorCode::InvalidExecutable,
                            "runtime.transport.executable",
                            "the stdio executable must be a portable name, not a path",
                        ));
                    }
                    validate_fixed_arguments(args, "runtime.transport.args")?;
                    reject_inline_code_prefix(executable, args, "runtime.transport.args")?;
                },
                McpTransport::StreamableHttp { endpoint } => validate_mcp_endpoint(endpoint)?,
            }
            validate_mcp_discovery(discovery, transport)?;
            validate_limits(limits)?;
            if limits.memory_bytes.is_some() {
                return Err(error(
                    ManifestValidationErrorCode::InvalidRuntimeLimit,
                    "runtime.limits.memory_bytes",
                    "process memory limits are supported only for batch CLI runtimes",
                ));
            }
            Ok(())
        },
    }
}

pub(crate) fn validate_fixed_arguments(
    arguments: &[String],
    field: &'static str,
) -> Result<(), ManifestValidationError> {
    let mut total_bytes = 0usize;
    for argument in arguments {
        if argument.is_empty()
            || argument.len() > MAX_ARGUMENT_BYTES
            || argument.chars().any(char::is_control)
        {
            return Err(error(
                ManifestValidationErrorCode::InvalidArgument,
                field,
                "fixed arguments must be non-empty, bounded, control-free tokens",
            ));
        }
        total_bytes = total_bytes.checked_add(argument.len()).ok_or_else(|| {
            error(
                ManifestValidationErrorCode::InvalidArgument,
                field,
                "fixed argument bytes overflowed their semantic limit",
            )
        })?;
        if total_bytes > MAX_FIXED_ARGUMENT_BYTES {
            return Err(error(
                ManifestValidationErrorCode::InvalidArgument,
                field,
                "fixed arguments exceed the combined byte limit",
            ));
        }
    }
    Ok(())
}

pub(crate) fn reject_inline_code_prefix(
    executable: &str,
    arguments: &[String],
    field: &'static str,
) -> Result<(), ManifestValidationError> {
    let executable = executable.to_ascii_lowercase();
    let interpreter_target_is_safe = match executable.as_str() {
        "cmd" | "cmd.exe" => false,
        "python" | "python3" => match arguments.first().map(String::as_str) {
            Some("-m") => arguments
                .get(1)
                .is_some_and(|target| safe_code_target(target)),
            Some("--") => arguments
                .get(1)
                .is_some_and(|target| safe_code_target(target)),
            Some(target) => safe_code_target(target),
            None => false,
        },
        "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe" => {
            match arguments
                .first()
                .map(|argument| argument.to_ascii_lowercase())
            {
                Some(flag) if flag == "-file" => arguments
                    .get(1)
                    .is_some_and(|target| safe_code_target(target)),
                Some(flag) if flag == "--" => arguments
                    .get(1)
                    .is_some_and(|target| safe_code_target(target)),
                Some(target) => safe_code_target(&target),
                None => false,
            }
        },
        "sh" | "bash" | "dash" | "ksh" | "zsh" | "fish" | "ruby" | "perl" | "node" | "nodejs"
        | "osascript" => match arguments.first().map(String::as_str) {
            Some("--") => arguments
                .get(1)
                .is_some_and(|target| safe_code_target(target)),
            Some(target) => safe_code_target(target),
            None => false,
        },
        _ => true,
    };
    if !interpreter_target_is_safe {
        return Err(error(
            ManifestValidationErrorCode::IllegalCommandPrefix,
            field,
            "an interpreter prefix must select a fixed script or module without inline source",
        ));
    }
    Ok(())
}

fn safe_code_target(target: &str) -> bool {
    !target.is_empty() && target != "-" && !target.starts_with('-')
}

fn validate_stdin(
    mode: StdinMode,
    sensitivity: DataSensitivity,
    limits: &RuntimeLimits,
) -> Result<(), ManifestValidationError> {
    if mode == StdinMode::Denied
        && (sensitivity != DataSensitivity::Public || limits.stdin_bytes.is_some())
    {
        return Err(error(
            ManifestValidationErrorCode::InvalidStdinContract,
            "runtime.stdin",
            "denied model stdin cannot declare sensitivity or a byte allowance",
        ));
    }
    Ok(())
}

fn validate_limits(limits: &RuntimeLimits) -> Result<(), ManifestValidationError> {
    if limits
        .timeout_secs
        .is_some_and(|value| value == 0 || value > MAX_RUNTIME_TIMEOUT_SECS)
    {
        return Err(error(
            ManifestValidationErrorCode::InvalidRuntimeLimit,
            "runtime.limits.timeout_secs",
            "the runtime timeout must be within the supported non-zero ceiling",
        ));
    }
    for (field, value) in [
        ("runtime.limits.stdin_bytes", limits.stdin_bytes),
        ("runtime.limits.stdout_bytes", limits.stdout_bytes),
        ("runtime.limits.stderr_bytes", limits.stderr_bytes),
    ] {
        if value.is_some_and(|value| value == 0 || value > MAX_RUNTIME_STREAM_BYTES) {
            return Err(error(
                ManifestValidationErrorCode::InvalidRuntimeLimit,
                field,
                "the stream limit must be within the supported non-zero ceiling",
            ));
        }
    }
    if limits
        .memory_bytes
        .is_some_and(|value| value < 64 * 1024 * 1024 || value > MAX_RUNTIME_MEMORY_BYTES)
    {
        return Err(error(
            ManifestValidationErrorCode::InvalidRuntimeLimit,
            "runtime.limits.memory_bytes",
            "the process memory limit must be between 64 MiB and the supported ceiling",
        ));
    }
    Ok(())
}

fn validate_mcp_endpoint(endpoint: &str) -> Result<(), ManifestValidationError> {
    if endpoint.is_empty()
        || endpoint.len() > MAX_ENDPOINT_BYTES
        || endpoint.chars().any(char::is_control)
    {
        return Err(invalid_mcp_endpoint());
    }
    let parsed = Url::parse(endpoint).map_err(|_| invalid_mcp_endpoint())?;
    if parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || parsed.cannot_be_a_base()
    {
        return Err(invalid_mcp_endpoint());
    }
    let secure = parsed.scheme() == "https";
    let loopback_http = parsed.scheme() == "http" && is_loopback_host(parsed.host());
    if !secure && !loopback_http {
        return Err(invalid_mcp_endpoint());
    }
    Ok(())
}

fn invalid_mcp_endpoint() -> ManifestValidationError {
    error(
        ManifestValidationErrorCode::InvalidMcpEndpoint,
        "runtime.transport.endpoint",
        "Streamable HTTP requires HTTPS or loopback HTTP without credentials or fragments",
    )
}

fn is_loopback_host(host: Option<Host<&str>>) -> bool {
    match host {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => IpAddr::V4(address).is_loopback(),
        Some(Host::Ipv6(address)) => IpAddr::V6(address).is_loopback(),
        None => false,
    }
}

fn validate_mcp_discovery(
    discovery: &McpDiscoveryPolicy,
    transport: &McpTransport,
) -> Result<(), ManifestValidationError> {
    if discovery
        .namespace
        .as_deref()
        .is_some_and(|value| !is_identifier(value))
    {
        return Err(error(
            ManifestValidationErrorCode::InvalidMcpDiscovery,
            "runtime.discovery.namespace",
            "the discovery namespace must be a portable identifier",
        ));
    }
    for tool in discovery
        .allow_tools
        .iter()
        .chain(discovery.deny_tools.iter())
    {
        if !is_mcp_tool_name(tool) {
            return Err(error(
                ManifestValidationErrorCode::InvalidMcpDiscovery,
                "runtime.discovery",
                "discovery rules must contain bounded portable MCP tool names",
            ));
        }
    }
    for (tool, policy) in &discovery.tool_policies {
        if !is_mcp_tool_name(tool)
            || discovery.deny_tools.contains(tool)
            || (!discovery.allow_tools.is_empty() && !discovery.allow_tools.contains(tool))
        {
            return Err(error(
                ManifestValidationErrorCode::InvalidMcpDiscovery,
                "runtime.discovery.tool_policies",
                "tool policies must target an exact locally eligible MCP tool name",
            ));
        }
        if policy.trusted_description.as_deref().is_some_and(|value| {
            value.is_empty()
                || value.len() > MAX_TRUSTED_MCP_DESCRIPTION_BYTES
                || value.chars().any(|character| {
                    character.is_control() && !matches!(character, '\n' | '\r' | '\t')
                })
        }) {
            return Err(error(
                ManifestValidationErrorCode::InvalidMcpDiscovery,
                "runtime.discovery.tool_policies.trusted_description",
                "trusted MCP descriptions must be nonempty, bounded, and free of unsafe controls",
            ));
        }
        for reference in policy
            .additional_required_grants
            .iter()
            .chain(policy.additional_resource_scopes.iter())
            .chain(policy.additional_required_resource_authorities.iter())
        {
            if !is_reference(reference) {
                return Err(error(
                    ManifestValidationErrorCode::InvalidMcpDiscovery,
                    "runtime.discovery.tool_policies",
                    "tool policy additions must be portable reference identifiers",
                ));
            }
        }
    }
    if !discovery.endpoint_aliases.is_empty()
        && !matches!(transport, McpTransport::StreamableHttp { .. })
    {
        return Err(invalid_mcp_discovery());
    }
    for (alias, endpoint) in &discovery.endpoint_aliases {
        if !is_identifier(alias) || validate_mcp_endpoint(endpoint).is_err() {
            return Err(invalid_mcp_discovery());
        }
    }
    if discovery
        .default_endpoint_alias
        .as_ref()
        .is_some_and(|alias| !discovery.endpoint_aliases.contains_key(alias))
        || (!discovery.endpoint_aliases.is_empty() && discovery.default_endpoint_alias.is_none())
    {
        return Err(invalid_mcp_discovery());
    }
    if let Some(oauth) = &discovery.oauth {
        if !matches!(transport, McpTransport::StreamableHttp { .. })
            || !is_canonical_mcp_oauth_url(&oauth.authorization_issuer)
            || oauth.scopes.iter().any(|scope| !is_reference(scope))
        {
            return Err(invalid_mcp_discovery());
        }
        let McpTransport::StreamableHttp { endpoint } = transport else {
            return Err(invalid_mcp_discovery());
        };
        if !is_canonical_mcp_oauth_url(endpoint)
            || discovery
                .endpoint_aliases
                .values()
                .any(|endpoint| !is_canonical_mcp_oauth_url(endpoint))
        {
            return Err(invalid_mcp_discovery());
        }
    }
    if let Some(commerce) = &discovery.commerce {
        if !is_reference(&commerce.commodity)
            || !is_reference(&commerce.resource_scope)
            || !is_reference(&commerce.required_resource_authority)
            || !is_identifier(&commerce.amount_parameter)
            || commerce.percentage_tolerance_bps > 10_000
            || commerce.total_field_priority.is_empty()
            || commerce.cart_name_terms.is_empty()
            || commerce.cart_read_verb_terms.is_empty()
            || commerce
                .final_tools
                .iter()
                .chain(commerce.conditional_final_tools.keys())
                .any(|tool| {
                    !is_mcp_tool_name(tool)
                        || discovery
                            .tool_policies
                            .get(tool)
                            .is_none_or(|policy| policy.risk != McpToolRiskClass::Commerce)
                })
            || commerce.final_tools.iter().any(|tool| {
                discovery.tool_policies.get(tool).is_none_or(|policy| {
                    !policy
                        .additional_resource_scopes
                        .contains(&commerce.resource_scope)
                        || !policy
                            .additional_required_resource_authorities
                            .contains(&commerce.required_resource_authority)
                })
            })
            || commerce.conditional_final_tools.keys().any(|tool| {
                discovery.tool_policies.get(tool).is_some_and(|policy| {
                    policy
                        .additional_resource_scopes
                        .contains(&commerce.resource_scope)
                        || policy
                            .additional_required_resource_authorities
                            .contains(&commerce.required_resource_authority)
                })
            })
            || commerce
                .conditional_final_tools
                .values()
                .any(|condition| !is_json_pointer(&condition.pointer))
            || commerce
                .checkout_name_terms
                .iter()
                .chain(commerce.cart_name_terms.iter())
                .chain(commerce.cart_read_verb_terms.iter())
                .any(|term| !is_mcp_policy_term(term))
            || commerce
                .total_field_priority
                .iter()
                .any(|term| !is_normalized_mcp_field(term))
            || commerce
                .cartless_endpoint_aliases
                .iter()
                .any(|alias| !discovery.endpoint_aliases.contains_key(alias))
            || (commerce.allow_cartless_checkout && !commerce.cartless_endpoint_aliases.is_empty())
            || (commerce.final_tools.is_empty()
                && commerce.conditional_final_tools.is_empty()
                && commerce.checkout_name_terms.is_empty())
        {
            return Err(invalid_mcp_discovery());
        }
    }
    Ok(())
}

fn is_canonical_mcp_oauth_url(value: &str) -> bool {
    validate_mcp_endpoint(value).is_ok()
        && Url::parse(value)
            .ok()
            .is_some_and(|url| url.query().is_none())
}

fn invalid_mcp_discovery() -> ManifestValidationError {
    error(
        ManifestValidationErrorCode::InvalidMcpDiscovery,
        "runtime.discovery",
        "the local MCP endpoint, OAuth, or commerce policy is invalid",
    )
}

fn is_mcp_policy_term(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn is_normalized_mcp_field(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn validate_policy_floor(policy: &PolicyFloor) -> Result<(), ManifestValidationError> {
    for grant in &policy.required_grants {
        if !is_reference(grant) {
            return Err(error(
                ManifestValidationErrorCode::InvalidPolicyFloor,
                "policy_floor.required_grants",
                "required grants must be portable reference identifiers",
            ));
        }
    }
    for scope in &policy.resource_scopes {
        if !is_reference(scope) {
            return Err(error(
                ManifestValidationErrorCode::InvalidPolicyFloor,
                "policy_floor.resource_scopes",
                "resource scopes must be portable reference identifiers",
            ));
        }
    }
    for authority in &policy.required_resource_authorities {
        if !is_reference(authority) {
            return Err(error(
                ManifestValidationErrorCode::InvalidPolicyFloor,
                "policy_floor.required_resource_authorities",
                "resource authorities must be portable reference identifiers",
            ));
        }
    }
    Ok(())
}

fn validate_auth(
    auth: &AuthContract,
    runtime: &RuntimeProtocol,
    executable: Option<&str>,
) -> Result<(), ManifestValidationError> {
    validate_auth_requirement(auth.kind, auth.requirement)?;
    validate_auth_provider(auth)?;
    validate_profile_selection(auth)?;
    validate_auth_storage(auth, runtime)?;
    let secret_names = validate_secret_bindings(auth)?;
    if auth.requirement == AuthRequirement::AtLeastOne
        && (auth.kind != AuthKind::Secrets || auth.secret_bindings.len() < 2)
    {
        return Err(error(
            ManifestValidationErrorCode::InvalidAuthRequirement,
            "auth.requirement",
            "at_least_one auth requires two or more alternative secret bindings",
        ));
    }
    validate_lifecycle(auth, runtime, executable)?;
    validate_identity(auth, runtime)?;
    validate_injections(auth, runtime, &secret_names)?;
    validate_protocol_auth_compatibility(auth, runtime)
}

fn validate_auth_requirement(
    kind: AuthKind,
    requirement: AuthRequirement,
) -> Result<(), ManifestValidationError> {
    let valid = if kind == AuthKind::None {
        requirement == AuthRequirement::None
    } else {
        requirement != AuthRequirement::None
    };
    if !valid {
        return Err(error(
            ManifestValidationErrorCode::InvalidAuthRequirement,
            "auth.requirement",
            "the auth requirement contradicts the selected auth kind",
        ));
    }
    Ok(())
}

fn validate_auth_provider(auth: &AuthContract) -> Result<(), ManifestValidationError> {
    if auth
        .provider
        .as_deref()
        .is_some_and(|provider| !is_identifier(provider))
    {
        return Err(error(
            ManifestValidationErrorCode::InvalidIdentifier,
            "auth.provider",
            "the auth provider must be a portable identifier",
        ));
    }
    if auth.kind == AuthKind::None && auth.provider.is_some() {
        return Err(error(
            ManifestValidationErrorCode::InvalidAuthProvider,
            "auth.provider",
            "an unauthenticated contract cannot declare an auth provider",
        ));
    }
    if matches!(
        auth.kind,
        AuthKind::CliProfile
            | AuthKind::OAuthSession
            | AuthKind::BrowserProfile
            | AuthKind::DelegatedCredential
    ) && auth.provider.is_none()
    {
        return Err(error(
            ManifestValidationErrorCode::MissingAuthProvider,
            "auth.provider",
            "the selected auth kind requires a provider identifier",
        ));
    }
    Ok(())
}

fn validate_profile_selection(auth: &AuthContract) -> Result<(), ManifestValidationError> {
    match &auth.profile_selection {
        ProfileSelection::Selectable { default } => {
            if default
                .as_deref()
                .is_some_and(|value| !is_profile_alias(value))
            {
                return Err(invalid_profile_selection());
            }
        },
        ProfileSelection::Fixed { alias } if !is_profile_alias(alias) => {
            return Err(invalid_profile_selection());
        },
        _ => {},
    }

    let supports_profiles = matches!(
        auth.kind,
        AuthKind::CliProfile | AuthKind::OAuthSession | AuthKind::BrowserProfile
    );
    if supports_profiles == matches!(&auth.profile_selection, ProfileSelection::None) {
        return Err(invalid_profile_selection());
    }
    Ok(())
}

fn invalid_profile_selection() -> ManifestValidationError {
    error(
        ManifestValidationErrorCode::InvalidProfileSelection,
        "auth.profile_selection",
        "profile selection is missing, unsupported, or contains an invalid alias",
    )
}

fn validate_auth_storage(
    auth: &AuthContract,
    runtime: &RuntimeProtocol,
) -> Result<(), ManifestValidationError> {
    if let AuthStorage::ScopedDirectory {
        namespace,
        partition_by_profile,
    } = &auth.storage
    {
        if !is_identifier(namespace) {
            return Err(invalid_auth_storage());
        }
        if !matches!(
            &auth.profile_selection,
            ProfileSelection::None | ProfileSelection::Implicit
        ) && !partition_by_profile
        {
            return Err(invalid_auth_storage());
        }
    }

    let valid = match auth.kind {
        AuthKind::None | AuthKind::Secrets => matches!(&auth.storage, AuthStorage::None),
        AuthKind::CliProfile => matches!(
            &auth.storage,
            AuthStorage::ScopedDirectory { .. } | AuthStorage::CliOwned
        ),
        AuthKind::OAuthSession => match runtime {
            RuntimeProtocol::Cli { .. } => matches!(
                &auth.storage,
                AuthStorage::ScopedDirectory { .. } | AuthStorage::CliOwned
            ),
            RuntimeProtocol::Mcp { .. } => matches!(&auth.storage, AuthStorage::None),
        },
        AuthKind::BrowserProfile => matches!(&auth.storage, AuthStorage::BrowserProfile),
        AuthKind::NativePermission => matches!(&auth.storage, AuthStorage::OperatingSystem),
        AuthKind::DelegatedCredential => matches!(&auth.storage, AuthStorage::EphemeralGrant),
    };
    if !valid {
        return Err(invalid_auth_storage());
    }
    Ok(())
}

fn invalid_auth_storage() -> ManifestValidationError {
    error(
        ManifestValidationErrorCode::InvalidAuthStorage,
        "auth.storage",
        "auth storage contradicts the auth kind, protocol, or profile partition policy",
    )
}

fn validate_secret_bindings(
    auth: &AuthContract,
) -> Result<BTreeSet<&str>, ManifestValidationError> {
    let supports_secrets = matches!(
        auth.kind,
        AuthKind::Secrets | AuthKind::CliProfile | AuthKind::OAuthSession
    );
    if !supports_secrets && !auth.secret_bindings.is_empty() {
        return Err(invalid_secret_binding());
    }
    if auth.kind == AuthKind::Secrets && auth.secret_bindings.is_empty() {
        return Err(invalid_secret_binding());
    }

    let mut names = BTreeSet::new();
    for binding in &auth.secret_bindings {
        if !is_identifier(&binding.name)
            || !is_reference(&binding.secret_ref)
            || !names.insert(binding.name.as_str())
        {
            return Err(invalid_secret_binding());
        }
    }
    Ok(names)
}

fn invalid_secret_binding() -> ManifestValidationError {
    error(
        ManifestValidationErrorCode::InvalidSecretBinding,
        "auth.secret_bindings",
        "secret bindings must be supported, unique, referenced, and use safe identifiers",
    )
}

fn validate_lifecycle(
    auth: &AuthContract,
    runtime: &RuntimeProtocol,
    executable: Option<&str>,
) -> Result<(), ManifestValidationError> {
    let lifecycle = &auth.lifecycle;
    let has_hooks = lifecycle.status.is_some()
        || lifecycle.status_observation.is_some()
        || lifecycle.login.is_some()
        || lifecycle.logout.is_some()
        || lifecycle.refresh.is_some();
    if !has_hooks {
        return Ok(());
    }
    let RuntimeProtocol::Cli { .. } = runtime else {
        return Err(invalid_lifecycle());
    };
    if !matches!(auth.kind, AuthKind::CliProfile | AuthKind::OAuthSession) {
        return Err(invalid_lifecycle());
    }
    if lifecycle.status.is_some() != lifecycle.status_observation.is_some() {
        return Err(invalid_lifecycle());
    }
    validate_lifecycle_hook(lifecycle.status.as_ref(), false, executable)?;
    if let Some(observation) = &lifecycle.status_observation {
        validate_lifecycle_status_observation(observation, &auth.identity)?;
    }
    validate_lifecycle_hook(lifecycle.login.as_ref(), true, executable)?;
    validate_lifecycle_hook(lifecycle.logout.as_ref(), false, executable)?;
    validate_lifecycle_hook(lifecycle.refresh.as_ref(), false, executable)
}

fn validate_lifecycle_status_observation(
    observation: &LifecycleStatusObservation,
    identity: &IdentityContract,
) -> Result<(), ManifestValidationError> {
    if observation.rules.is_empty() || observation.rules.len() > MAX_LIFECYCLE_STATUS_RULES {
        return Err(invalid_lifecycle());
    }
    if observation.format == LifecycleStatusOutputFormat::ExitCode
        && matches!(identity, IdentityContract::ProfileExpected { .. })
    {
        return Err(invalid_lifecycle());
    }

    let mut rules = BTreeSet::new();
    let mut exit_states = BTreeMap::new();
    let mut has_ready = false;
    let mut total_json_predicates = 0usize;
    for rule in &observation.rules {
        if rule.exit_codes.is_empty()
            || rule.exit_codes.len() > MAX_LIFECYCLE_STATUS_EXIT_CODES
            || rule.all.len() > MAX_LIFECYCLE_STATUS_PREDICATES
            || !rules.insert(rule)
        {
            return Err(invalid_lifecycle());
        }
        has_ready |= rule.state == LifecycleObservedAuthState::Ready;
        for exit_code in &rule.exit_codes {
            if !(0..=255).contains(exit_code) {
                return Err(invalid_lifecycle());
            }
            if observation.format == LifecycleStatusOutputFormat::ExitCode
                && exit_states.insert(*exit_code, rule.state).is_some()
            {
                return Err(invalid_lifecycle());
            }
        }
        if observation.format == LifecycleStatusOutputFormat::ExitCode && !rule.all.is_empty() {
            return Err(invalid_lifecycle());
        }
        if observation.format == LifecycleStatusOutputFormat::Json
            && rule.all.is_empty()
            && !(rule.state == LifecycleObservedAuthState::Ready
                && matches!(identity, IdentityContract::ProfileExpected { .. }))
        {
            return Err(invalid_lifecycle());
        }
        total_json_predicates = total_json_predicates
            .checked_add(rule.all.len())
            .ok_or_else(invalid_lifecycle)?;
        if total_json_predicates > MAX_LIFECYCLE_STATUS_PREDICATES {
            return Err(invalid_lifecycle());
        }
        let mut predicates = BTreeSet::new();
        for predicate in &rule.all {
            if !predicates.insert(predicate) {
                return Err(invalid_lifecycle());
            }
            validate_lifecycle_json_predicate(predicate)?;
        }
    }
    if !has_ready {
        return Err(invalid_lifecycle());
    }
    Ok(())
}

fn validate_lifecycle_json_predicate(
    predicate: &LifecycleJsonPredicate,
) -> Result<(), ManifestValidationError> {
    match predicate {
        LifecycleJsonPredicate::Equals { pointer, value } => {
            if !is_json_pointer(pointer) || !valid_lifecycle_json_scalar(value) {
                return Err(invalid_lifecycle());
            }
        },
        LifecycleJsonPredicate::Exists { pointer }
        | LifecycleJsonPredicate::Missing { pointer } => {
            if !is_json_pointer(pointer) {
                return Err(invalid_lifecycle());
            }
        },
        LifecycleJsonPredicate::ArrayContainsAllStrings { pointer, values } => {
            if !is_json_pointer(pointer)
                || values.is_empty()
                || values.len() > MAX_LIFECYCLE_STATUS_ARRAY_VALUES
                || values.iter().any(|value| {
                    value.len() > MAX_LIFECYCLE_STATUS_VALUE_BYTES
                        || value.chars().any(char::is_control)
                })
            {
                return Err(invalid_lifecycle());
            }
        },
    }
    Ok(())
}

fn valid_lifecycle_json_scalar(value: &LifecycleJsonScalar) -> bool {
    match value {
        LifecycleJsonScalar::String { value } => {
            value.len() <= MAX_LIFECYCLE_STATUS_VALUE_BYTES && !value.chars().any(char::is_control)
        },
        LifecycleJsonScalar::Boolean { .. }
        | LifecycleJsonScalar::Integer { .. }
        | LifecycleJsonScalar::Null => true,
    }
}

fn validate_lifecycle_hook(
    hook: Option<&LifecycleHook>,
    interaction_allowed: bool,
    inline_code_executable: Option<&str>,
) -> Result<(), ManifestValidationError> {
    let Some(hook) = hook else {
        return Ok(());
    };
    if hook.args.is_empty() || hook.args.len() > MAX_FIXED_ARGUMENTS {
        return Err(invalid_lifecycle());
    }
    validate_fixed_arguments(&hook.args, "auth.lifecycle").map_err(|_| invalid_lifecycle())?;
    if let Some(executable) = inline_code_executable {
        reject_inline_code_prefix(executable, &hook.args, "auth.lifecycle")
            .map_err(|_| invalid_lifecycle())?;
    }
    if hook.interaction == CliInteraction::Pty && !interaction_allowed {
        return Err(invalid_lifecycle());
    }
    if hook
        .timeout_secs
        .is_some_and(|value| value == 0 || value > MAX_LIFECYCLE_TIMEOUT_SECS)
    {
        return Err(invalid_lifecycle());
    }
    Ok(())
}

fn invalid_lifecycle() -> ManifestValidationError {
    error(
        ManifestValidationErrorCode::InvalidLifecycle,
        "auth.lifecycle",
        "lifecycle hooks are incompatible, empty, oversized, or unexpectedly interactive",
    )
}

fn validate_identity(
    auth: &AuthContract,
    runtime: &RuntimeProtocol,
) -> Result<(), ManifestValidationError> {
    match &auth.identity {
        IdentityContract::None => Ok(()),
        IdentityContract::ProfileExpected { selector } => {
            if !matches!(auth.kind, AuthKind::CliProfile | AuthKind::OAuthSession)
                || !matches!(
                    &auth.profile_selection,
                    ProfileSelection::Selectable { .. } | ProfileSelection::Fixed { .. }
                )
                || !matches!(runtime, RuntimeProtocol::Cli { .. })
                || auth.lifecycle.status.is_none()
                || !auth
                    .lifecycle
                    .status_observation
                    .as_ref()
                    .is_some_and(|observation| {
                        observation.format == LifecycleStatusOutputFormat::Json
                    })
            {
                return Err(invalid_identity());
            }
            match selector {
                IdentitySelector::JsonPointer { pointer }
                | IdentitySelector::JsonPointerAsciiCaseInsensitive { pointer }
                    if is_json_pointer(pointer) =>
                {
                    Ok(())
                },
                _ => Err(invalid_identity()),
            }
        },
        IdentityContract::Unverified { reason } => {
            if auth.kind == AuthKind::None
                || reason.is_empty()
                || reason.len() > MAX_IDENTITY_REASON_BYTES
                || reason.chars().any(char::is_control)
            {
                return Err(invalid_identity());
            }
            Ok(())
        },
    }
}

fn invalid_identity() -> ManifestValidationError {
    error(
        ManifestValidationErrorCode::InvalidIdentity,
        "auth.identity",
        "identity verification lacks a compatible profile, status hook, selector, or reason",
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum InjectionTargetKey<'a> {
    Environment(&'a str),
    Stdin,
    ScopedFile(&'a str),
    ConfigDirectory(&'a str),
}

fn validate_injections(
    auth: &AuthContract,
    runtime: &RuntimeProtocol,
    secret_names: &BTreeSet<&str>,
) -> Result<(), ManifestValidationError> {
    if matches!(
        runtime,
        RuntimeProtocol::Mcp {
            transport: McpTransport::StreamableHttp { .. },
            ..
        }
    ) && !auth.injections.is_empty()
    {
        return Err(error(
            ManifestValidationErrorCode::IncompatibleProtocolAuth,
            "auth.injections",
            "a remote MCP transport cannot inject material into a local process",
        ));
    }

    let mut targets = BTreeSet::new();
    let mut used_secrets = BTreeSet::new();
    for injection in &auth.injections {
        validate_injection_source(auth, &injection.source, secret_names, &mut used_secrets)?;
        let target = validate_injection_target(auth, runtime, injection)?;
        if !targets.insert(target) {
            return Err(error(
                ManifestValidationErrorCode::DuplicateInjectionTarget,
                "auth.injections",
                "multiple injections cannot write to the same target",
            ));
        }
    }
    if secret_names.iter().any(|name| !used_secrets.contains(name)) {
        return Err(invalid_secret_binding());
    }
    Ok(())
}

fn validate_injection_source<'a>(
    auth: &AuthContract,
    source: &'a InjectionSource,
    secret_names: &BTreeSet<&'a str>,
    used_secrets: &mut BTreeSet<&'a str>,
) -> Result<(), ManifestValidationError> {
    match source {
        InjectionSource::Secret { binding } => {
            if !matches!(
                auth.kind,
                AuthKind::Secrets | AuthKind::CliProfile | AuthKind::OAuthSession
            ) || !secret_names.contains(binding.as_str())
            {
                return Err(invalid_injection());
            }
            used_secrets.insert(binding.as_str());
        },
        InjectionSource::ProfileAuthRoot { path } => {
            if !matches!(auth.kind, AuthKind::CliProfile | AuthKind::OAuthSession)
                || !matches!(
                    &auth.storage,
                    AuthStorage::ScopedDirectory { .. } | AuthStorage::CliOwned
                )
                || path.len() > MAX_PROFILE_PATH_SEGMENTS
                || path.iter().any(|segment| !is_path_segment(segment))
            {
                return Err(invalid_injection());
            }
        },
        InjectionSource::ProfileAlias => {
            if !matches!(
                &auth.profile_selection,
                ProfileSelection::Selectable { .. } | ProfileSelection::Fixed { .. }
            ) {
                return Err(invalid_injection());
            }
        },
        InjectionSource::ExpectedIdentity => {
            if !matches!(&auth.identity, IdentityContract::ProfileExpected { .. }) {
                return Err(invalid_injection());
            }
        },
    }
    Ok(())
}

fn validate_injection_target<'a>(
    auth: &AuthContract,
    runtime: &RuntimeProtocol,
    injection: &'a InjectionBinding,
) -> Result<InjectionTargetKey<'a>, ManifestValidationError> {
    match &injection.target {
        InjectionTarget::Environment { name } if is_safe_injection_environment_name(name) => {
            Ok(InjectionTargetKey::Environment(name))
        },
        InjectionTarget::Stdin => {
            let RuntimeProtocol::Cli { stdin, .. } = runtime else {
                return Err(invalid_injection());
            };
            if stdin.mode != StdinMode::Denied
                || !matches!(&injection.source, InjectionSource::Secret { .. })
            {
                return Err(invalid_injection());
            }
            Ok(InjectionTargetKey::Stdin)
        },
        InjectionTarget::ScopedFile { relative_path }
            if matches!(&injection.source, InjectionSource::Secret { .. })
                && is_relative_path(relative_path) =>
        {
            if !cfg!(unix) {
                return Err(invalid_injection());
            }
            Ok(InjectionTargetKey::ScopedFile(relative_path))
        },
        InjectionTarget::ConfigDirectory { name } if is_identifier(name) => {
            if !cfg!(unix) {
                return Err(invalid_injection());
            }
            match &injection.source {
                InjectionSource::ProfileAuthRoot { .. } => {
                    Ok(InjectionTargetKey::ConfigDirectory(name))
                },
                InjectionSource::Secret { .. }
                    if auth.provider.as_deref() == Some(MINIMAX_PROVIDER)
                        && name == MMX_CONFIG_DIR =>
                {
                    Ok(InjectionTargetKey::ConfigDirectory(name))
                },
                InjectionSource::Secret { .. } => Err(invalid_injection()),
                _ => Err(invalid_injection()),
            }
        },
        _ => Err(invalid_injection()),
    }
}

fn invalid_injection() -> ManifestValidationError {
    error(
        ManifestValidationErrorCode::InvalidInjection,
        "auth.injections",
        "an injection source, target, binding, path, or protocol combination is invalid",
    )
}

fn validate_protocol_auth_compatibility(
    auth: &AuthContract,
    runtime: &RuntimeProtocol,
) -> Result<(), ManifestValidationError> {
    let compatible = match runtime {
        RuntimeProtocol::Cli { .. } => true,
        RuntimeProtocol::Mcp {
            transport: McpTransport::Stdio { .. },
            ..
        } => auth.kind != AuthKind::BrowserProfile,
        RuntimeProtocol::Mcp {
            transport: McpTransport::StreamableHttp { .. },
            discovery,
            ..
        } => {
            matches!(
                auth.kind,
                AuthKind::None | AuthKind::OAuthSession | AuthKind::DelegatedCredential
            ) && (auth.kind == AuthKind::OAuthSession) == discovery.oauth.is_some()
        },
    };
    if !compatible {
        return Err(error(
            ManifestValidationErrorCode::IncompatibleProtocolAuth,
            "auth.kind",
            "the selected auth kind is not supported by this runtime transport",
        ));
    }
    Ok(())
}

pub(crate) fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+'))
}

fn is_profile_alias(value: &str) -> bool {
    is_identifier(value) && !value.contains('@')
}

fn is_executable_name(value: &str) -> bool {
    is_identifier(value) && !value.contains('/') && !value.contains('\\')
}

pub(crate) fn is_reference(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_REFERENCE_BYTES
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
    {
        return false;
    }
    value
        .split('/')
        .all(|segment| !matches!(segment, "" | "." | "..") && is_reference_segment(segment))
}

fn is_reference_segment(value: &str) -> bool {
    value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+' | b':')
    })
}

fn is_path_segment(value: &str) -> bool {
    is_identifier(value) && !value.contains('/') && !value.contains('\\')
}

fn is_environment_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn is_safe_injection_environment_name(value: &str) -> bool {
    if !is_environment_name(value) {
        return false;
    }
    let upper = value.to_ascii_uppercase();
    !matches!(
        upper.as_str(),
        "PATH"
            | "HOME"
            | "USER"
            | "LOGNAME"
            | "SHELL"
            | "PWD"
            | "OLDPWD"
            | "TMPDIR"
            | "TMP"
            | "TEMP"
            | "LD_PRELOAD"
            | "LD_LIBRARY_PATH"
            | "BASH_ENV"
            | "ENV"
            | "PYTHONPATH"
            | "PYTHONHOME"
            | "NODE_OPTIONS"
            | "RUBYOPT"
            | "PERL5OPT"
            | "SSLKEYLOGFILE"
    ) && !upper.starts_with("DYLD_")
        && !upper.starts_with("GIT_CONFIG_")
}

fn is_relative_path(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_RELATIVE_PATH_BYTES
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        return false;
    }
    let mut components = 0usize;
    for component in value.split('/') {
        if !is_path_segment(component) {
            return false;
        }
        components += 1;
        if components > MAX_PROFILE_PATH_SEGMENTS {
            return false;
        }
    }
    components > 0
}

fn is_json_pointer(pointer: &str) -> bool {
    if pointer.is_empty()
        || pointer.len() > MAX_JSON_POINTER_BYTES
        || !pointer.starts_with('/')
        || pointer.chars().any(char::is_control)
        || pointer.split('/').skip(1).count() > MAX_PROFILE_PATH_SEGMENTS
    {
        return false;
    }
    let bytes = pointer.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'~' {
            if index + 1 >= bytes.len() || !matches!(bytes[index + 1], b'0' | b'1') {
                return false;
            }
            index += 2;
        } else {
            index += 1;
        }
    }
    true
}

pub(crate) fn is_mcp_tool_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/')
        })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        thread,
    };

    use super::*;
    use crate::manifest::{
        ApprovalClass, LifecycleStatusRule, McpToolPolicy, McpToolRiskClass, RuntimeRequirements,
        SkillRuntimeContractVersion, StdinContract, WorkingDirectoryContract,
    };

    fn cli_contract(executable: &str) -> SkillRuntimeContract {
        SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires: RuntimeRequirements {
                bins: BTreeSet::from([executable.to_owned()]),
                entrypoint: Default::default(),
                environment: Default::default(),
            },
            runtime: RuntimeProtocol::Cli {
                command_prefix: Vec::new(),
                interaction: CliInteraction::Batch,
                stdin: StdinContract::default(),
                working_directory: WorkingDirectoryContract::default(),
                limits: RuntimeLimits::default(),
            },
            auth: AuthContract::default(),
            policy_floor: PolicyFloor::default(),
        }
    }

    fn required_auth(kind: AuthKind) -> AuthContract {
        AuthContract {
            kind,
            requirement: AuthRequirement::Required,
            ..AuthContract::default()
        }
    }

    fn json_status_observation() -> LifecycleStatusObservation {
        LifecycleStatusObservation {
            format: LifecycleStatusOutputFormat::Json,
            rules: vec![LifecycleStatusRule {
                state: LifecycleObservedAuthState::Ready,
                exit_codes: BTreeSet::from([0]),
                all: vec![LifecycleJsonPredicate::Equals {
                    pointer: "/ready".to_owned(),
                    value: LifecycleJsonScalar::Boolean { value: true },
                }],
            }],
        }
    }

    fn validation_error(contract: &SkillRuntimeContract) -> ManifestValidationError {
        validate_skill_runtime_contract(contract).expect_err("contract must be rejected")
    }

    #[test]
    fn accepts_representative_contracts_for_all_auth_strategies() {
        let none = cli_contract("jq");

        let mut secrets = cli_contract("provider-cli");
        secrets.auth = required_auth(AuthKind::Secrets);
        secrets
            .auth
            .secret_bindings
            .push(crate::manifest::SecretBindingRef {
                name: "provider_api_key".to_owned(),
                secret_ref: "PROVIDER_API_KEY".to_owned(),
            });
        secrets.auth.injections.push(InjectionBinding {
            source: InjectionSource::Secret {
                binding: "provider_api_key".to_owned(),
            },
            target: InjectionTarget::Environment {
                name: "PROVIDER_API_KEY".to_owned(),
            },
        });

        let mut cli_profile = cli_contract("gws");
        cli_profile.auth = required_auth(AuthKind::CliProfile);
        cli_profile.auth.provider = Some("google-workspace".to_owned());
        cli_profile.auth.profile_selection = ProfileSelection::Selectable {
            default: Some("work".to_owned()),
        };
        cli_profile.auth.storage = AuthStorage::ScopedDirectory {
            namespace: "gws".to_owned(),
            partition_by_profile: true,
        };
        cli_profile.auth.lifecycle.status = Some(LifecycleHook {
            args: vec!["auth".to_owned(), "status".to_owned(), "--json".to_owned()],
            interaction: CliInteraction::Batch,
            timeout_secs: Some(30),
        });
        cli_profile.auth.lifecycle.status_observation = Some(json_status_observation());
        cli_profile.auth.identity = IdentityContract::ProfileExpected {
            selector: IdentitySelector::JsonPointer {
                pointer: "/account/email".to_owned(),
            },
        };
        cli_profile.auth.injections.push(InjectionBinding {
            source: InjectionSource::ProfileAuthRoot {
                path: vec!["cloudsdk".to_owned()],
            },
            target: InjectionTarget::Environment {
                name: "CLOUDSDK_CONFIG".to_owned(),
            },
        });

        let mut oauth = SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires: RuntimeRequirements::default(),
            runtime: RuntimeProtocol::Mcp {
                transport: McpTransport::StreamableHttp {
                    endpoint: "https://provider.example/mcp".to_owned(),
                },
                discovery: McpDiscoveryPolicy {
                    oauth: Some(crate::manifest::McpOAuthConnectionPolicy {
                        authorization_issuer: "https://issuer.example".to_owned(),
                        scopes: BTreeSet::new(),
                    }),
                    ..McpDiscoveryPolicy::default()
                },
                limits: RuntimeLimits::default(),
            },
            auth: required_auth(AuthKind::OAuthSession),
            policy_floor: PolicyFloor::default(),
        };
        oauth.auth.provider = Some("provider-mcp".to_owned());
        oauth.auth.profile_selection = ProfileSelection::Selectable {
            default: Some("personal".to_owned()),
        };

        let mut browser = cli_contract("agent-browser");
        browser.auth = required_auth(AuthKind::BrowserProfile);
        browser.auth.provider = Some("browser-controller".to_owned());
        browser.auth.profile_selection = ProfileSelection::Implicit;
        browser.auth.storage = AuthStorage::BrowserProfile;

        let mut native = cli_contract("screencapture");
        native.auth = required_auth(AuthKind::NativePermission);
        native.auth.provider = Some("macos".to_owned());
        native.auth.storage = AuthStorage::OperatingSystem;

        let mut delegated = cli_contract("provider-cli");
        delegated.auth = required_auth(AuthKind::DelegatedCredential);
        delegated.auth.provider = Some("provider".to_owned());
        delegated.auth.storage = AuthStorage::EphemeralGrant;

        for contract in [
            none,
            secrets,
            cli_profile,
            oauth,
            browser,
            native,
            delegated,
        ] {
            let validated = validate_skill_runtime_contract(&contract).expect("valid contract");
            assert!(std::ptr::eq(validated.contract(), &contract));
        }
    }

    #[test]
    fn executable_identity_is_exact_and_unambiguous() {
        let mut forward = cli_contract("jq");
        forward.schema_version =
            SkillRuntimeContractVersion("tool-runtime.skill-runtime.v2".to_owned());
        assert_eq!(
            validation_error(&forward).code,
            ManifestValidationErrorCode::UnsupportedSchemaVersion
        );

        let mut missing = cli_contract("jq");
        missing.requires.bins.clear();
        assert_eq!(
            validation_error(&missing).code,
            ManifestValidationErrorCode::AmbiguousExecutable
        );

        let mut multiple = cli_contract("jq");
        multiple.requires.bins.insert("yq".to_owned());
        assert_eq!(
            validation_error(&multiple).code,
            ManifestValidationErrorCode::AmbiguousExecutable
        );

        let mut path = cli_contract("jq");
        path.requires.bins = BTreeSet::from(["/usr/bin/jq".to_owned()]);
        assert_eq!(
            validation_error(&path).code,
            ManifestValidationErrorCode::InvalidExecutable
        );

        let mut stdio = cli_contract("provider-mcp");
        stdio.runtime = RuntimeProtocol::Mcp {
            transport: McpTransport::Stdio {
                executable: "other-mcp".to_owned(),
                args: Vec::new(),
            },
            discovery: McpDiscoveryPolicy::default(),
            limits: RuntimeLimits::default(),
        };
        assert_eq!(
            validation_error(&stdio).code,
            ManifestValidationErrorCode::ExecutableRequirementMismatch
        );

        let mut remote = cli_contract("unused-local-bin");
        remote.runtime = RuntimeProtocol::Mcp {
            transport: McpTransport::StreamableHttp {
                endpoint: "https://provider.example/mcp".to_owned(),
            },
            discovery: McpDiscoveryPolicy::default(),
            limits: RuntimeLimits::default(),
        };
        assert_eq!(
            validation_error(&remote).code,
            ManifestValidationErrorCode::AmbiguousExecutable
        );
    }

    #[test]
    fn fixed_arguments_are_bounded_and_inline_code_is_rejected() {
        let mut inline = cli_contract("bash");
        let RuntimeProtocol::Cli { command_prefix, .. } = &mut inline.runtime else {
            unreachable!();
        };
        *command_prefix = vec!["-c".to_owned(), "run something".to_owned()];
        assert_eq!(
            validation_error(&inline).code,
            ManifestValidationErrorCode::IllegalCommandPrefix
        );

        let targetless = cli_contract("bash");
        assert_eq!(
            validation_error(&targetless).code,
            ManifestValidationErrorCode::IllegalCommandPrefix
        );

        let mut delayed_inline = cli_contract("bash");
        let RuntimeProtocol::Cli { command_prefix, .. } = &mut delayed_inline.runtime else {
            unreachable!();
        };
        *command_prefix = vec![
            "--noprofile".to_owned(),
            "-c".to_owned(),
            "run something".to_owned(),
        ];
        assert_eq!(
            validation_error(&delayed_inline).code,
            ManifestValidationErrorCode::IllegalCommandPrefix
        );

        let mut fixed_script = cli_contract("bash");
        let RuntimeProtocol::Cli { command_prefix, .. } = &mut fixed_script.runtime else {
            unreachable!();
        };
        command_prefix.push("scripts/run.sh".to_owned());
        validate_skill_runtime_contract(&fixed_script).expect("fixed script target is safe");

        let mut empty = cli_contract("provider-cli");
        let RuntimeProtocol::Cli { command_prefix, .. } = &mut empty.runtime else {
            unreachable!();
        };
        command_prefix.push(String::new());
        assert_eq!(
            validation_error(&empty).code,
            ManifestValidationErrorCode::InvalidArgument
        );

        let mut too_many = cli_contract("provider-cli");
        let RuntimeProtocol::Cli { command_prefix, .. } = &mut too_many.runtime else {
            unreachable!();
        };
        *command_prefix = vec!["fixed".to_owned(); MAX_FIXED_ARGUMENTS + 1];
        assert_eq!(
            validation_error(&too_many).code,
            ManifestValidationErrorCode::CollectionTooLarge
        );
    }

    #[test]
    fn streamable_http_endpoints_are_secure_and_canonical_enough_to_bind() {
        for endpoint in [
            "https://provider.example/mcp?tenant=personal",
            "http://localhost:8765/mcp",
            "http://127.0.0.1:8765/mcp",
            "http://[::1]:8765/mcp",
        ] {
            let mut contract = cli_contract("placeholder");
            contract.requires.bins.clear();
            contract.runtime = RuntimeProtocol::Mcp {
                transport: McpTransport::StreamableHttp {
                    endpoint: endpoint.to_owned(),
                },
                discovery: McpDiscoveryPolicy::default(),
                limits: RuntimeLimits::default(),
            };
            validate_skill_runtime_contract(&contract).expect("valid endpoint");
        }

        for endpoint in [
            "http://provider.example/mcp",
            "https://user:password@provider.example/mcp",
            "https://provider.example/mcp#fragment",
            "file:///tmp/mcp.sock",
            "not a URL",
        ] {
            let mut contract = cli_contract("placeholder");
            contract.requires.bins.clear();
            contract.runtime = RuntimeProtocol::Mcp {
                transport: McpTransport::StreamableHttp {
                    endpoint: endpoint.to_owned(),
                },
                discovery: McpDiscoveryPolicy::default(),
                limits: RuntimeLimits::default(),
            };
            assert_eq!(
                validation_error(&contract).code,
                ManifestValidationErrorCode::InvalidMcpEndpoint
            );
        }
    }

    #[test]
    fn discovery_rules_validate_names_while_preserving_deny_wins_overlap() {
        let mut contract = cli_contract("provider-mcp");
        contract.runtime = RuntimeProtocol::Mcp {
            transport: McpTransport::Stdio {
                executable: "provider-mcp".to_owned(),
                args: Vec::new(),
            },
            discovery: McpDiscoveryPolicy {
                namespace: Some("provider".to_owned()),
                allow_tools: BTreeSet::from(["mail/read".to_owned()]),
                deny_tools: BTreeSet::from(["mail/read".to_owned()]),
                tool_policies: Default::default(),
                ..McpDiscoveryPolicy::default()
            },
            limits: RuntimeLimits::default(),
        };
        validate_skill_runtime_contract(&contract)
            .expect("allow/deny overlap is deterministic because deny wins");

        if let RuntimeProtocol::Mcp { discovery, .. } = &mut contract.runtime {
            discovery.deny_tools.clear();
            discovery.allow_tools = BTreeSet::from(["tool with spaces".to_owned()]);
        }
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidMcpDiscovery
        );
    }

    #[test]
    fn mcp_tool_policies_are_exact_bounded_and_locally_authored() {
        let mut contract = cli_contract("provider-mcp");
        contract.runtime = RuntimeProtocol::Mcp {
            transport: McpTransport::Stdio {
                executable: "provider-mcp".to_owned(),
                args: Vec::new(),
            },
            discovery: McpDiscoveryPolicy {
                namespace: Some("provider".to_owned()),
                allow_tools: BTreeSet::from(["mail/read".to_owned()]),
                deny_tools: BTreeSet::new(),
                tool_policies: BTreeMap::from([(
                    "mail/read".to_owned(),
                    McpToolPolicy {
                        risk: McpToolRiskClass::ReadOnly,
                        trusted_description: Some(
                            "Read mail through the trusted account.".to_owned(),
                        ),
                        additional_required_resource_authorities: BTreeSet::from([
                            "mail-read".to_owned()
                        ]),
                        ..McpToolPolicy::default()
                    },
                )]),
                ..McpDiscoveryPolicy::default()
            },
            limits: RuntimeLimits::default(),
        };
        validate_skill_runtime_contract(&contract).expect("valid exact local tool policy");

        if let RuntimeProtocol::Mcp { discovery, .. } = &mut contract.runtime {
            discovery.deny_tools.insert("mail/read".to_owned());
        }
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidMcpDiscovery
        );
        if let RuntimeProtocol::Mcp { discovery, .. } = &mut contract.runtime {
            discovery.deny_tools.clear();
            discovery.allow_tools = BTreeSet::from(["mail/search".to_owned()]);
        }
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidMcpDiscovery
        );
        if let RuntimeProtocol::Mcp { discovery, .. } = &mut contract.runtime {
            discovery.allow_tools = BTreeSet::from(["mail/read".to_owned()]);
            discovery
                .tool_policies
                .get_mut("mail/read")
                .expect("policy")
                .trusted_description = Some("unsafe\u{0007}description".to_owned());
        }
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidMcpDiscovery
        );
        if let RuntimeProtocol::Mcp { discovery, .. } = &mut contract.runtime {
            let policy = discovery
                .tool_policies
                .get_mut("mail/read")
                .expect("policy");
            policy.trusted_description = None;
            policy.additional_required_grants = BTreeSet::from(["not portable".to_owned()]);
        }
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidMcpDiscovery
        );
    }

    #[test]
    fn aggregate_mcp_tool_policy_references_have_one_hard_ceiling() {
        let references = (0..MAX_POLICY_ENTRIES)
            .map(|index| format!("grant-{index}"))
            .collect::<BTreeSet<_>>();
        let tool_policies = (0..(MAX_MCP_TOOL_POLICY_REFERENCES / MAX_POLICY_ENTRIES + 1))
            .map(|index| {
                (
                    format!("tool-{index}"),
                    McpToolPolicy {
                        additional_required_grants: references.clone(),
                        ..McpToolPolicy::default()
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut contract = cli_contract("provider-mcp");
        contract.runtime = RuntimeProtocol::Mcp {
            transport: McpTransport::Stdio {
                executable: "provider-mcp".to_owned(),
                args: Vec::new(),
            },
            discovery: McpDiscoveryPolicy {
                tool_policies,
                ..McpDiscoveryPolicy::default()
            },
            limits: RuntimeLimits::default(),
        };
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::CollectionTooLarge
        );
    }

    #[test]
    fn auth_requirement_provider_profile_and_storage_must_agree() {
        let mut no_auth = cli_contract("jq");
        no_auth.auth.requirement = AuthRequirement::Required;
        assert_eq!(
            validation_error(&no_auth).code,
            ManifestValidationErrorCode::InvalidAuthRequirement
        );

        let mut profile = cli_contract("gws");
        profile.auth = required_auth(AuthKind::CliProfile);
        profile.auth.profile_selection = ProfileSelection::Selectable { default: None };
        profile.auth.storage = AuthStorage::ScopedDirectory {
            namespace: "gws".to_owned(),
            partition_by_profile: true,
        };
        assert_eq!(
            validation_error(&profile).code,
            ManifestValidationErrorCode::MissingAuthProvider
        );

        profile.auth.provider = Some("google-workspace".to_owned());
        profile.auth.profile_selection = ProfileSelection::None;
        assert_eq!(
            validation_error(&profile).code,
            ManifestValidationErrorCode::InvalidProfileSelection
        );

        profile.auth.profile_selection = ProfileSelection::Fixed {
            alias: "work".to_owned(),
        };
        profile.auth.storage = AuthStorage::ScopedDirectory {
            namespace: "gws".to_owned(),
            partition_by_profile: false,
        };
        assert_eq!(
            validation_error(&profile).code,
            ManifestValidationErrorCode::InvalidAuthStorage
        );

        let mut native = cli_contract("screencapture");
        native.auth = required_auth(AuthKind::NativePermission);
        native.auth.storage = AuthStorage::ScopedDirectory {
            namespace: "native".to_owned(),
            partition_by_profile: false,
        };
        assert_eq!(
            validation_error(&native).code,
            ManifestValidationErrorCode::InvalidAuthStorage
        );
    }

    #[test]
    fn remote_mcp_rejects_local_only_auth_strategies() {
        let mut contract = SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires: RuntimeRequirements::default(),
            runtime: RuntimeProtocol::Mcp {
                transport: McpTransport::StreamableHttp {
                    endpoint: "https://provider.example/mcp".to_owned(),
                },
                discovery: McpDiscoveryPolicy::default(),
                limits: RuntimeLimits::default(),
            },
            auth: required_auth(AuthKind::BrowserProfile),
            policy_floor: PolicyFloor::default(),
        };
        contract.auth.provider = Some("browser-controller".to_owned());
        contract.auth.profile_selection = ProfileSelection::Implicit;
        contract.auth.storage = AuthStorage::BrowserProfile;

        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::IncompatibleProtocolAuth
        );
    }

    #[test]
    fn secret_bindings_are_unique_known_and_fully_consumed() {
        let mut contract = cli_contract("provider-cli");
        contract.auth = required_auth(AuthKind::Secrets);
        contract.auth.secret_bindings = vec![
            crate::manifest::SecretBindingRef {
                name: "api_key".to_owned(),
                secret_ref: "PROVIDER_API_KEY".to_owned(),
            },
            crate::manifest::SecretBindingRef {
                name: "api_key".to_owned(),
                secret_ref: "SECOND_KEY".to_owned(),
            },
        ];
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidSecretBinding
        );

        contract.auth.secret_bindings.truncate(1);
        contract.auth.injections.push(InjectionBinding {
            source: InjectionSource::Secret {
                binding: "unknown".to_owned(),
            },
            target: InjectionTarget::Environment {
                name: "PROVIDER_API_KEY".to_owned(),
            },
        });
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidInjection
        );

        contract.auth.injections.clear();
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidSecretBinding
        );
    }

    #[test]
    fn injections_are_typed_collision_free_and_local_process_only() {
        let mut contract = cli_contract("provider-cli");
        contract.auth = required_auth(AuthKind::Secrets);
        contract.auth.secret_bindings = vec![crate::manifest::SecretBindingRef {
            name: "api_key".to_owned(),
            secret_ref: "PROVIDER_API_KEY".to_owned(),
        }];
        for _ in 0..2 {
            contract.auth.injections.push(InjectionBinding {
                source: InjectionSource::Secret {
                    binding: "api_key".to_owned(),
                },
                target: InjectionTarget::Environment {
                    name: "PROVIDER_API_KEY".to_owned(),
                },
            });
        }
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::DuplicateInjectionTarget
        );

        contract.auth.injections.truncate(1);
        contract.auth.provider = Some(crate::manifest::MINIMAX_PROVIDER.to_owned());
        contract.auth.injections[0].target = InjectionTarget::ConfigDirectory {
            name: crate::manifest::MMX_CONFIG_DIR.to_owned(),
        };
        assert!(validate_skill_runtime_contract(&contract).is_ok());

        contract.auth.provider = Some("provider-cli".to_owned());
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidInjection
        );

        contract.auth.injections[0].target = InjectionTarget::Environment {
            name: "DYLD_INSERT_LIBRARIES".to_owned(),
        };
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidInjection
        );

        let mut remote = SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires: RuntimeRequirements::default(),
            runtime: RuntimeProtocol::Mcp {
                transport: McpTransport::StreamableHttp {
                    endpoint: "https://provider.example/mcp".to_owned(),
                },
                discovery: McpDiscoveryPolicy {
                    oauth: Some(crate::manifest::McpOAuthConnectionPolicy {
                        authorization_issuer: "https://issuer.example".to_owned(),
                        scopes: BTreeSet::new(),
                    }),
                    ..McpDiscoveryPolicy::default()
                },
                limits: RuntimeLimits::default(),
            },
            auth: required_auth(AuthKind::OAuthSession),
            policy_floor: PolicyFloor::default(),
        };
        remote.auth.provider = Some("provider".to_owned());
        remote.auth.profile_selection = ProfileSelection::Fixed {
            alias: "personal".to_owned(),
        };
        remote.auth.injections.push(InjectionBinding {
            source: InjectionSource::ProfileAlias,
            target: InjectionTarget::Environment {
                name: "PROFILE".to_owned(),
            },
        });
        assert_eq!(
            validation_error(&remote).code,
            ManifestValidationErrorCode::IncompatibleProtocolAuth
        );
    }

    #[test]
    fn lifecycle_hooks_are_cli_auth_only_bounded_and_batch_except_login() {
        let mut inline = cli_contract("bash");
        let RuntimeProtocol::Cli { command_prefix, .. } = &mut inline.runtime else {
            unreachable!();
        };
        command_prefix.push("scripts/runtime.sh".to_owned());
        inline.auth = required_auth(AuthKind::CliProfile);
        inline.auth.provider = Some("provider".to_owned());
        inline.auth.profile_selection = ProfileSelection::Implicit;
        inline.auth.storage = AuthStorage::CliOwned;
        inline.auth.lifecycle.status = Some(LifecycleHook {
            args: vec!["-c".to_owned(), "read state".to_owned()],
            interaction: CliInteraction::Batch,
            timeout_secs: Some(30),
        });
        inline.auth.lifecycle.status_observation = Some(json_status_observation());
        assert_eq!(
            validation_error(&inline).code,
            ManifestValidationErrorCode::InvalidLifecycle
        );

        let mut contract = cli_contract("gws");
        contract.auth = required_auth(AuthKind::CliProfile);
        contract.auth.provider = Some("google-workspace".to_owned());
        contract.auth.profile_selection = ProfileSelection::Implicit;
        contract.auth.storage = AuthStorage::CliOwned;
        contract.auth.lifecycle.status = Some(LifecycleHook {
            args: vec!["auth".to_owned(), "status".to_owned()],
            interaction: CliInteraction::Pty,
            timeout_secs: Some(30),
        });
        contract.auth.lifecycle.status_observation = Some(json_status_observation());
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidLifecycle
        );

        contract.auth.lifecycle.status.as_mut().unwrap().interaction = CliInteraction::Batch;
        contract.auth.lifecycle.login = Some(LifecycleHook {
            args: vec!["auth".to_owned(), "login".to_owned()],
            interaction: CliInteraction::Pty,
            timeout_secs: Some(300),
        });
        validate_skill_runtime_contract(&contract).expect("interactive login is valid");

        contract.auth.lifecycle.login.as_mut().unwrap().timeout_secs = Some(0);
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidLifecycle
        );

        contract.auth.lifecycle.login.as_mut().unwrap().timeout_secs = Some(30);
        contract.runtime = RuntimeProtocol::Mcp {
            transport: McpTransport::Stdio {
                executable: "gws".to_owned(),
                args: Vec::new(),
            },
            discovery: McpDiscoveryPolicy::default(),
            limits: RuntimeLimits::default(),
        };
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidLifecycle
        );
    }

    #[test]
    fn status_observation_is_required_bounded_and_unambiguous_for_exit_codes() {
        let mut contract = cli_contract("provider-cli");
        contract.auth = required_auth(AuthKind::CliProfile);
        contract.auth.provider = Some("provider".to_owned());
        contract.auth.profile_selection = ProfileSelection::Implicit;
        contract.auth.storage = AuthStorage::CliOwned;
        contract.auth.lifecycle.status = Some(LifecycleHook {
            args: vec!["auth".to_owned(), "status".to_owned()],
            interaction: CliInteraction::Batch,
            timeout_secs: Some(30),
        });
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidLifecycle
        );

        contract.auth.lifecycle.status_observation = Some(LifecycleStatusObservation {
            format: LifecycleStatusOutputFormat::ExitCode,
            rules: vec![
                LifecycleStatusRule {
                    state: LifecycleObservedAuthState::Ready,
                    exit_codes: BTreeSet::from([0]),
                    all: Vec::new(),
                },
                LifecycleStatusRule {
                    state: LifecycleObservedAuthState::Missing,
                    exit_codes: BTreeSet::from([5]),
                    all: Vec::new(),
                },
            ],
        });
        validate_skill_runtime_contract(&contract).expect("exact exit-code mapping");

        contract
            .auth
            .lifecycle
            .status_observation
            .as_mut()
            .expect("observation")
            .rules[1]
            .exit_codes = BTreeSet::from([0]);
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidLifecycle
        );
        contract
            .auth
            .lifecycle
            .status_observation
            .as_mut()
            .expect("observation")
            .rules[1]
            .exit_codes = BTreeSet::from([256]);
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidLifecycle
        );
        {
            let observation = contract
                .auth
                .lifecycle
                .status_observation
                .as_mut()
                .expect("observation");
            observation.rules[1].exit_codes = BTreeSet::from([5]);
            observation.rules[0].all = vec![LifecycleJsonPredicate::Exists {
                pointer: "/ready".to_owned(),
            }];
        }
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidLifecycle
        );
    }

    #[test]
    fn json_status_rules_require_ready_exact_pointers_and_bounded_values() {
        let mut contract = cli_contract("provider-cli");
        contract.auth = required_auth(AuthKind::CliProfile);
        contract.auth.provider = Some("provider".to_owned());
        contract.auth.profile_selection = ProfileSelection::Implicit;
        contract.auth.storage = AuthStorage::CliOwned;
        contract.auth.lifecycle.status = Some(LifecycleHook {
            args: vec!["auth".to_owned(), "status".to_owned(), "--json".to_owned()],
            interaction: CliInteraction::Batch,
            timeout_secs: Some(30),
        });
        contract.auth.lifecycle.status_observation = Some(json_status_observation());
        validate_skill_runtime_contract(&contract).expect("json observation");

        contract
            .auth
            .lifecycle
            .status_observation
            .as_mut()
            .expect("observation")
            .rules[0]
            .state = LifecycleObservedAuthState::Missing;
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidLifecycle
        );
        {
            let rule = &mut contract
                .auth
                .lifecycle
                .status_observation
                .as_mut()
                .expect("observation")
                .rules[0];
            rule.state = LifecycleObservedAuthState::Ready;
            rule.all = vec![LifecycleJsonPredicate::Exists {
                pointer: "not-a-pointer".to_owned(),
            }];
        }
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidLifecycle
        );
        contract
            .auth
            .lifecycle
            .status_observation
            .as_mut()
            .expect("observation")
            .rules[0]
            .all = vec![LifecycleJsonPredicate::ArrayContainsAllStrings {
            pointer: "/scopes".to_owned(),
            values: BTreeSet::new(),
        }];
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidLifecycle
        );
        contract
            .auth
            .lifecycle
            .status_observation
            .as_mut()
            .expect("observation")
            .rules[0]
            .all = vec![LifecycleJsonPredicate::Equals {
            pointer: "/state".to_owned(),
            value: LifecycleJsonScalar::String {
                value: "x".repeat(MAX_LIFECYCLE_STATUS_VALUE_BYTES + 1),
            },
        }];
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidLifecycle
        );

        let observation = contract
            .auth
            .lifecycle
            .status_observation
            .as_mut()
            .expect("observation");
        observation.rules[0].all.clear();
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidLifecycle
        );

        contract.auth.lifecycle.status_observation = Some(LifecycleStatusObservation {
            format: LifecycleStatusOutputFormat::Json,
            rules: vec![
                LifecycleStatusRule {
                    state: LifecycleObservedAuthState::Ready,
                    exit_codes: BTreeSet::from([0]),
                    all: (0..16)
                        .map(|index| LifecycleJsonPredicate::Exists {
                            pointer: format!("/ready/{index}"),
                        })
                        .collect(),
                },
                LifecycleStatusRule {
                    state: LifecycleObservedAuthState::Missing,
                    exit_codes: BTreeSet::from([0]),
                    all: (0..17)
                        .map(|index| LifecycleJsonPredicate::Exists {
                            pointer: format!("/missing/{index}"),
                        })
                        .collect(),
                },
            ],
        });
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidLifecycle
        );
    }

    #[test]
    fn expected_identity_requires_selected_profile_status_and_valid_json_pointer() {
        let mut contract = cli_contract("gws");
        contract.auth = required_auth(AuthKind::CliProfile);
        contract.auth.provider = Some("google-workspace".to_owned());
        contract.auth.profile_selection = ProfileSelection::Selectable {
            default: Some("work".to_owned()),
        };
        contract.auth.storage = AuthStorage::ScopedDirectory {
            namespace: "gws".to_owned(),
            partition_by_profile: true,
        };
        contract.auth.identity = IdentityContract::ProfileExpected {
            selector: IdentitySelector::JsonPointer {
                pointer: "/account/~2email".to_owned(),
            },
        };
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidIdentity
        );

        contract.auth.lifecycle.status = Some(LifecycleHook {
            args: vec!["auth".to_owned(), "status".to_owned(), "--json".to_owned()],
            interaction: CliInteraction::Batch,
            timeout_secs: Some(30),
        });
        contract.auth.lifecycle.status_observation = Some(json_status_observation());
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidIdentity
        );

        let IdentityContract::ProfileExpected {
            selector: IdentitySelector::JsonPointer { pointer },
        } = &mut contract.auth.identity
        else {
            unreachable!();
        };
        *pointer = "/account/email".to_owned();
        validate_skill_runtime_contract(&contract).expect("valid expected identity");
    }

    #[test]
    fn runtime_limits_stdin_and_policy_references_fail_closed() {
        let mut contract = cli_contract("provider-cli");
        let RuntimeProtocol::Cli { stdin, .. } = &mut contract.runtime else {
            unreachable!();
        };
        stdin.sensitivity = DataSensitivity::Secret;
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidStdinContract
        );

        let RuntimeProtocol::Cli { stdin, limits, .. } = &mut contract.runtime else {
            unreachable!();
        };
        stdin.mode = StdinMode::Optional;
        limits.stdout_bytes = Some(MAX_RUNTIME_STREAM_BYTES + 1);
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidRuntimeLimit
        );

        let RuntimeProtocol::Cli { limits, .. } = &mut contract.runtime else {
            unreachable!();
        };
        limits.stdout_bytes = None;
        contract.policy_floor.approval = ApprovalClass::DelegatedWorkspaceWrite;
        contract
            .policy_floor
            .resource_scopes
            .insert("../outside".to_owned());
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidPolicyFloor
        );
    }

    #[test]
    fn process_memory_limit_is_bounded_and_only_valid_for_batch_cli() {
        let mut contract = cli_contract("provider-cli");
        let RuntimeProtocol::Cli { limits, .. } = &mut contract.runtime else {
            unreachable!();
        };
        limits.memory_bytes = Some(64 * 1024 * 1024 - 1);
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidRuntimeLimit
        );

        let RuntimeProtocol::Cli { limits, .. } = &mut contract.runtime else {
            unreachable!();
        };
        limits.memory_bytes = Some(MAX_RUNTIME_MEMORY_BYTES);
        validate_skill_runtime_contract(&contract).expect("maximum batch memory limit is valid");

        if let RuntimeProtocol::Cli { interaction, .. } = &mut contract.runtime {
            *interaction = CliInteraction::Pty;
        }
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidRuntimeLimit
        );

        if let RuntimeProtocol::Cli {
            interaction,
            limits,
            ..
        } = &mut contract.runtime
        {
            *interaction = CliInteraction::Batch;
            limits.memory_bytes = Some(MAX_RUNTIME_MEMORY_BYTES + 1);
        }
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidRuntimeLimit
        );
    }

    #[test]
    fn fixed_environment_is_structural_public_configuration_not_name_guessing() {
        let mut contract = cli_contract("provider-cli");
        contract.requires.environment = BTreeMap::from([
            ("APIKEY_DISPLAY_MODE".to_owned(), "masked".to_owned()),
            ("PROVIDER_TOKEN_STYLE".to_owned(), "compact".to_owned()),
        ]);
        validate_skill_runtime_contract(&contract)
            .expect("public package configuration may use provider-defined names");

        contract.auth.injections = vec![InjectionBinding {
            source: InjectionSource::ProfileAlias,
            target: InjectionTarget::Environment {
                name: "APIKEY_DISPLAY_MODE".to_owned(),
            },
        }];
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidEnvironment
        );

        contract.auth.injections.clear();
        contract.requires.environment =
            BTreeMap::from([("DYLD_INSERT_LIBRARIES".to_owned(), "anything".to_owned())]);
        assert_eq!(
            validation_error(&contract).code,
            ManifestValidationErrorCode::InvalidEnvironment
        );
    }

    #[test]
    fn diagnostics_are_stable_serializable_and_never_echo_authored_values() {
        let secret_canary = "SECRET-CANARY-do-not-copy";
        let mut contract = cli_contract("provider-cli");
        contract.auth = required_auth(AuthKind::Secrets);
        contract.auth.secret_bindings = vec![crate::manifest::SecretBindingRef {
            name: "api_key".to_owned(),
            secret_ref: format!("{secret_canary} with whitespace"),
        }];
        let diagnostic = validation_error(&contract);
        let display = diagnostic.to_string();
        let json = serde_json::to_string(&diagnostic).expect("serialize diagnostic");

        assert_eq!(
            diagnostic.code,
            ManifestValidationErrorCode::InvalidSecretBinding
        );
        assert!(!display.contains(secret_canary));
        assert!(!json.contains(secret_canary));
        assert!(json.contains("invalid_secret_binding"));
    }

    #[test]
    fn oversized_typed_collections_fail_on_a_small_stack_before_iteration() {
        let result = thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| {
                let mut contract = cli_contract("provider-cli");
                contract.requires.bins = (0..=MAX_EXECUTABLE_REQUIREMENTS)
                    .map(|index| format!("bin-{index}"))
                    .collect();
                validation_error(&contract).code
            })
            .expect("spawn small-stack validator")
            .join()
            .expect("validator must not overflow");

        assert_eq!(result, ManifestValidationErrorCode::CollectionTooLarge);
    }
}
