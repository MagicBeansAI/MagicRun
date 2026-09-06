//! Deterministic catalog synthesis from a Phase 1C validation proof.
//!
//! The compiler emits a bounded model-facing CLI `run` schema or a stable MCP
//! discovery seed. It performs no package lookup, process execution, credential
//! resolution, MCP connection, server discovery, or catalog publication.

use std::{collections::BTreeMap, error::Error, fmt};

use serde::Serialize;

use crate::{
    manifest::{
        AuthKind, AuthRequirement, CliInteraction, DataSensitivity, McpDiscoveryPolicy,
        McpTransport, PolicyFloor, ProfileSelection, RuntimeLimits, RuntimeProtocol, StdinMode,
        WorkingDirectoryMode,
    },
    manifest_validation::{
        ValidatedSkillRuntimeContract, MAX_ARGUMENT_BYTES, MAX_FIXED_ARGUMENTS,
        MAX_FIXED_ARGUMENT_BYTES, MAX_RUNTIME_STREAM_BYTES, MAX_RUNTIME_TIMEOUT_SECS,
    },
};

pub const SYNTHESIZED_RUNTIME_CATALOG_V1: &str = "tool-runtime.synthesized-catalog.v1";
pub const MAX_SYNTHESIZED_SKILL_ID_BYTES: usize = 128;
pub const MAX_SYNTHESIZED_TOOL_NAME_BYTES: usize = 512;
pub const MAX_SYNTHESIZED_PROFILE_ALIAS_BYTES: u64 = 256;
pub const MAX_SYNTHESIZED_WORKING_DIRECTORY_BYTES: u64 = 1024;
pub const MAX_DISCOVERED_MCP_TOOLS: usize = 512;
pub const MAX_DISCOVERED_MCP_TOOL_NAME_BYTES: usize = 256;
pub const MAX_DISCOVERED_MCP_DESCRIPTION_BYTES: usize = 8 * 1024;
pub const MAX_DISCOVERED_MCP_SCHEMA_BYTES: usize = 256 * 1024;
pub const MAX_DISCOVERED_MCP_CATALOG_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_DISCOVERED_MCP_SCHEMA_DEPTH: usize = 32;
pub const MAX_DISCOVERED_MCP_SCHEMA_NODES: usize = 10_000;

const CONTROL_FREE_PATTERN: &str = r"^[^\u0000-\u001F\u007F]*$";
const PROFILE_ALIAS_PATTERN: &str = r"^[A-Za-z0-9_.+-]+$";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestSynthesisErrorCode {
    InvalidSkillId,
    OutputNameTooLong,
    ValidatedContractInvariantViolation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ManifestSynthesisError {
    pub code: ManifestSynthesisErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl ManifestSynthesisError {
    const fn new(
        code: ManifestSynthesisErrorCode,
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

impl fmt::Display for ManifestSynthesisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for ManifestSynthesisError {}

/// Complete provider-neutral output of Phase 1D.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SynthesizedRuntimeCatalog {
    pub schema_version: &'static str,
    pub skill_id: String,
    pub runtime: SynthesizedRuntime,
    pub security_floor: SynthesizedSecurityFloor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum SynthesizedRuntime {
    Cli {
        action: SynthesizedActionDefinition,
        execution: SynthesizedCliExecution,
    },
    Mcp {
        discovery: SynthesizedMcpDiscoverySeed,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SynthesizedActionDefinition {
    pub name: String,
    pub description: &'static str,
    pub input_schema: SynthesizedInputSchema,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SynthesizedInputSchema {
    #[serde(rename = "type")]
    pub schema_type: &'static str,
    pub properties: BTreeMap<String, SynthesizedPropertySchema>,
    pub required: Vec<String>,
    #[serde(rename = "additionalProperties")]
    pub additional_properties: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SynthesizedPropertySchema {
    Array {
        description: &'static str,
        items: SynthesizedStringItemSchema,
        #[serde(rename = "minItems")]
        min_items: u64,
        #[serde(rename = "maxItems")]
        max_items: u64,
        #[serde(rename = "x-max-combined-utf8-bytes")]
        max_combined_utf8_bytes: u64,
    },
    String {
        description: &'static str,
        #[serde(rename = "minLength")]
        min_length: u64,
        #[serde(rename = "maxLength")]
        max_length: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        pattern: Option<&'static str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        format: Option<&'static str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        default: Option<String>,
        #[serde(rename = "x-max-utf8-bytes", skip_serializing_if = "Option::is_none")]
        max_utf8_bytes: Option<u64>,
        #[serde(rename = "x-data-sensitivity", skip_serializing_if = "Option::is_none")]
        data_sensitivity: Option<DataSensitivity>,
        #[serde(rename = "x-path-authority", skip_serializing_if = "Option::is_none")]
        path_authority: Option<WorkingDirectoryMode>,
    },
    Integer {
        description: &'static str,
        minimum: u64,
        maximum: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SynthesizedStringItemSchema {
    #[serde(rename = "type")]
    pub schema_type: &'static str,
    #[serde(rename = "minLength")]
    pub min_length: u64,
    #[serde(rename = "maxLength")]
    pub max_length: u64,
    pub pattern: &'static str,
}

/// Non-secret process binding. Auth material remains in the validated source
/// contract for later Auth Broker phases and is never projected into the model
/// schema or this execution shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SynthesizedCliExecution {
    pub executable: String,
    pub command_prefix: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub interaction: CliInteraction,
    pub stdin_mode: StdinMode,
    pub stdin_sensitivity: DataSensitivity,
    pub working_directory: WorkingDirectoryMode,
    pub limits: RuntimeLimits,
    pub model_argument_limits: SynthesizedArgumentLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SynthesizedArgumentLimits {
    pub max_items: usize,
    pub max_item_bytes: usize,
    pub max_combined_bytes: usize,
    pub reject_control_characters: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SynthesizedMcpDiscoverySeed {
    /// Every eventually discovered name is rooted beneath this skill-owned
    /// namespace before collision handling.
    pub local_namespace: String,
    pub naming_strategy: &'static str,
    pub transport: McpTransport,
    pub runtime_limits: RuntimeLimits,
    pub policy: McpDiscoveryPolicy,
    pub catalog_limits: SynthesizedMcpCatalogLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SynthesizedMcpCatalogLimits {
    pub max_tools: usize,
    pub max_tool_name_bytes: usize,
    pub max_description_bytes: usize,
    pub max_schema_bytes: usize,
    /// Aggregate raw schema/name/trusted-description budget for one projected
    /// snapshot. It is runtime policy rather than legacy catalog wire metadata.
    #[serde(skip_serializing)]
    pub max_catalog_bytes: usize,
    pub max_schema_depth: usize,
    pub max_schema_nodes: usize,
}

/// Minimum security identity carried beside either synthesized runtime shape.
/// It contains no secret references, lifecycle argv, injection target, expected
/// identity, or credential material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SynthesizedSecurityFloor {
    pub auth_kind: AuthKind,
    pub auth_requirement: AuthRequirement,
    pub provider: Option<String>,
    pub profile_selection: ProfileSelection,
    pub policy: PolicyFloor,
}

/// Compile a validated contract into a deterministic local catalog shape.
pub fn synthesize_runtime_catalog(
    skill_id: &str,
    validated: ValidatedSkillRuntimeContract<'_>,
) -> Result<SynthesizedRuntimeCatalog, ManifestSynthesisError> {
    if !is_skill_id(skill_id) {
        return Err(ManifestSynthesisError::new(
            ManifestSynthesisErrorCode::InvalidSkillId,
            "skill_id",
            "the skill identifier is not portable or exceeds its size limit",
        ));
    }

    let contract = validated.contract();
    let security_floor = SynthesizedSecurityFloor {
        auth_kind: contract.auth.kind,
        auth_requirement: contract.auth.requirement,
        provider: contract.auth.provider.clone(),
        profile_selection: contract.auth.profile_selection.clone(),
        policy: contract.policy_floor.clone(),
    };
    let runtime = match &contract.runtime {
        RuntimeProtocol::Cli {
            command_prefix,
            interaction,
            stdin,
            working_directory,
            limits,
        } => {
            let executable = contract
                .requires
                .entrypoint
                .as_ref()
                .or_else(|| contract.requires.bins.first())
                .ok_or_else(|| {
                    ManifestSynthesisError::new(
                        ManifestSynthesisErrorCode::ValidatedContractInvariantViolation,
                        "requires.bins",
                        "the validation proof did not retain a CLI executable",
                    )
                })?;
            let action_name = bounded_join(skill_id, ".run")?;
            SynthesizedRuntime::Cli {
                action: SynthesizedActionDefinition {
                    name: action_name,
                    description: "Run the installed skill with exact argument tokens.",
                    input_schema: synthesize_cli_input_schema(
                        &contract.auth.profile_selection,
                        stdin.mode,
                        stdin.sensitivity,
                        working_directory.mode,
                        limits,
                    ),
                },
                execution: SynthesizedCliExecution {
                    executable: executable.clone(),
                    command_prefix: command_prefix.clone(),
                    environment: contract.requires.environment.clone(),
                    interaction: *interaction,
                    stdin_mode: stdin.mode,
                    stdin_sensitivity: stdin.sensitivity,
                    working_directory: working_directory.mode,
                    limits: limits.clone(),
                    model_argument_limits: SynthesizedArgumentLimits {
                        max_items: MAX_FIXED_ARGUMENTS,
                        max_item_bytes: MAX_ARGUMENT_BYTES,
                        max_combined_bytes: MAX_FIXED_ARGUMENT_BYTES,
                        reject_control_characters: true,
                    },
                },
            }
        },
        RuntimeProtocol::Mcp {
            transport,
            discovery,
            limits,
        } => {
            let local_namespace = match discovery.namespace.as_deref() {
                Some(namespace) => bounded_join(skill_id, &format!(".{namespace}"))?,
                None => skill_id.to_owned(),
            };
            let max_tools = if discovery.allow_tools.is_empty() {
                MAX_DISCOVERED_MCP_TOOLS
            } else {
                discovery
                    .allow_tools
                    .difference(&discovery.deny_tools)
                    .count()
                    .min(MAX_DISCOVERED_MCP_TOOLS)
            };
            SynthesizedRuntime::Mcp {
                discovery: SynthesizedMcpDiscoverySeed {
                    local_namespace,
                    naming_strategy: "skill_namespace_dot_v1",
                    transport: transport.clone(),
                    runtime_limits: limits.clone(),
                    policy: discovery.clone(),
                    catalog_limits: SynthesizedMcpCatalogLimits {
                        max_tools,
                        max_tool_name_bytes: MAX_DISCOVERED_MCP_TOOL_NAME_BYTES,
                        max_description_bytes: MAX_DISCOVERED_MCP_DESCRIPTION_BYTES,
                        max_schema_bytes: MAX_DISCOVERED_MCP_SCHEMA_BYTES,
                        max_catalog_bytes: MAX_DISCOVERED_MCP_CATALOG_BYTES,
                        max_schema_depth: MAX_DISCOVERED_MCP_SCHEMA_DEPTH,
                        max_schema_nodes: MAX_DISCOVERED_MCP_SCHEMA_NODES,
                    },
                },
            }
        },
    };

    Ok(SynthesizedRuntimeCatalog {
        schema_version: SYNTHESIZED_RUNTIME_CATALOG_V1,
        skill_id: skill_id.to_owned(),
        runtime,
        security_floor,
    })
}

fn synthesize_cli_input_schema(
    profile_selection: &ProfileSelection,
    stdin_mode: StdinMode,
    stdin_sensitivity: DataSensitivity,
    working_directory: WorkingDirectoryMode,
    limits: &RuntimeLimits,
) -> SynthesizedInputSchema {
    let mut properties = BTreeMap::new();
    let mut required = vec!["args".to_owned()];
    properties.insert(
        "args".to_owned(),
        SynthesizedPropertySchema::Array {
            description: "Exact argument tokens appended after the fixed command prefix.",
            items: SynthesizedStringItemSchema {
                schema_type: "string",
                min_length: 0,
                max_length: MAX_ARGUMENT_BYTES as u64,
                pattern: CONTROL_FREE_PATTERN,
            },
            min_items: 0,
            max_items: MAX_FIXED_ARGUMENTS as u64,
            max_combined_utf8_bytes: MAX_FIXED_ARGUMENT_BYTES as u64,
        },
    );

    if let ProfileSelection::Selectable { default } = profile_selection {
        properties.insert(
            "profile".to_owned(),
            SynthesizedPropertySchema::String {
                description: "Configured local profile alias; never an email or credential.",
                min_length: 1,
                max_length: MAX_SYNTHESIZED_PROFILE_ALIAS_BYTES,
                pattern: Some(PROFILE_ALIAS_PATTERN),
                format: None,
                default: default.clone(),
                max_utf8_bytes: Some(MAX_SYNTHESIZED_PROFILE_ALIAS_BYTES),
                data_sensitivity: None,
                path_authority: None,
            },
        );
        if default.is_none() {
            required.push("profile".to_owned());
        }
    }

    if stdin_mode != StdinMode::Denied {
        let max_bytes = limits.stdin_bytes.unwrap_or(MAX_RUNTIME_STREAM_BYTES);
        properties.insert(
            "stdin".to_owned(),
            SynthesizedPropertySchema::String {
                description: "Bounded standard input for the child process.",
                min_length: 0,
                max_length: max_bytes,
                pattern: None,
                format: None,
                default: None,
                max_utf8_bytes: Some(max_bytes),
                data_sensitivity: Some(stdin_sensitivity),
                path_authority: None,
            },
        );
        if stdin_mode == StdinMode::Required {
            required.push("stdin".to_owned());
        }
    }

    let working_directory_schema = match working_directory {
        WorkingDirectoryMode::Denied => None,
        WorkingDirectoryMode::Workspace => Some((
            "Workspace-relative working directory authorized by the runtime.",
            "workspace-relative-path",
        )),
        WorkingDirectoryMode::OutputRoot => Some((
            "Output-root-relative working directory authorized by the runtime.",
            "output-root-relative-path",
        )),
    };
    if let Some((description, format)) = working_directory_schema {
        properties.insert(
            "working_dir".to_owned(),
            SynthesizedPropertySchema::String {
                description,
                min_length: 1,
                max_length: MAX_SYNTHESIZED_WORKING_DIRECTORY_BYTES,
                pattern: None,
                format: Some(format),
                default: None,
                max_utf8_bytes: Some(MAX_SYNTHESIZED_WORKING_DIRECTORY_BYTES),
                data_sensitivity: None,
                path_authority: Some(working_directory),
            },
        );
    }

    properties.insert(
        "timeout_secs".to_owned(),
        SynthesizedPropertySchema::Integer {
            description: "Requested wall-clock ceiling; local policy may lower it.",
            minimum: 1,
            maximum: limits.timeout_secs.unwrap_or(MAX_RUNTIME_TIMEOUT_SECS) as u64,
        },
    );

    required.sort();
    SynthesizedInputSchema {
        schema_type: "object",
        properties,
        required,
        additional_properties: false,
    }
}

fn bounded_join(skill_id: &str, suffix: &str) -> Result<String, ManifestSynthesisError> {
    let length = skill_id.len().checked_add(suffix.len()).ok_or_else(|| {
        ManifestSynthesisError::new(
            ManifestSynthesisErrorCode::OutputNameTooLong,
            "skill_id",
            "the synthesized output name overflowed its size limit",
        )
    })?;
    if length > MAX_SYNTHESIZED_TOOL_NAME_BYTES {
        return Err(ManifestSynthesisError::new(
            ManifestSynthesisErrorCode::OutputNameTooLong,
            "skill_id",
            "the synthesized output name exceeds its size limit",
        ));
    }
    let mut output = String::with_capacity(length);
    output.push_str(skill_id);
    output.push_str(suffix);
    Ok(output)
}

fn is_skill_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SYNTHESIZED_SKILL_ID_BYTES
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+'))
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, thread};

    use super::*;
    use crate::{
        manifest::{
            ApprovalClass, AuthContract, AuthStorage, InjectionBinding, InjectionSource,
            InjectionTarget, RuntimeRequirements, SkillRuntimeContract,
            SkillRuntimeContractVersion, StdinContract, WorkingDirectoryContract,
        },
        manifest_parser::parse_skill_runtime_contract,
        manifest_validation::validate_skill_runtime_contract,
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
                command_prefix: vec!["fixed".to_owned()],
                interaction: CliInteraction::Batch,
                stdin: StdinContract::default(),
                working_directory: WorkingDirectoryContract::default(),
                limits: RuntimeLimits::default(),
            },
            auth: AuthContract::default(),
            policy_floor: PolicyFloor::default(),
        }
    }

    fn compile(skill_id: &str, contract: &SkillRuntimeContract) -> SynthesizedRuntimeCatalog {
        let validated = validate_skill_runtime_contract(contract).expect("valid contract");
        synthesize_runtime_catalog(skill_id, validated).expect("synthesize catalog")
    }

    fn properties(
        catalog: &SynthesizedRuntimeCatalog,
    ) -> &BTreeMap<String, SynthesizedPropertySchema> {
        let SynthesizedRuntime::Cli { action, .. } = &catalog.runtime else {
            panic!("expected CLI catalog");
        };
        &action.input_schema.properties
    }

    #[test]
    fn unauthenticated_cli_synthesizes_one_bounded_run_action() {
        let contract = cli_contract("jq");
        let catalog = compile("jq", &contract);
        let SynthesizedRuntime::Cli { action, execution } = &catalog.runtime else {
            panic!("expected CLI catalog");
        };

        assert_eq!(catalog.schema_version, SYNTHESIZED_RUNTIME_CATALOG_V1);
        assert_eq!(action.name, "jq.run");
        assert_eq!(action.input_schema.required, vec!["args"]);
        assert!(!action.input_schema.additional_properties);
        assert_eq!(
            action
                .input_schema
                .properties
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["args", "timeout_secs"]
        );
        assert_eq!(execution.executable, "jq");
        assert_eq!(execution.command_prefix, vec!["fixed"]);
        assert_eq!(
            execution.model_argument_limits,
            SynthesizedArgumentLimits {
                max_items: MAX_FIXED_ARGUMENTS,
                max_item_bytes: MAX_ARGUMENT_BYTES,
                max_combined_bytes: MAX_FIXED_ARGUMENT_BYTES,
                reject_control_characters: true,
            }
        );
    }

    #[test]
    fn profile_parameter_appears_only_for_selectable_profiles() {
        let mut selectable = cli_contract("gws");
        selectable.auth.kind = AuthKind::CliProfile;
        selectable.auth.requirement = AuthRequirement::Required;
        selectable.auth.provider = Some("google-workspace".to_owned());
        selectable.auth.profile_selection = ProfileSelection::Selectable { default: None };
        selectable.auth.storage = AuthStorage::ScopedDirectory {
            namespace: "gws".to_owned(),
            partition_by_profile: true,
        };
        let catalog = compile("gws", &selectable);
        let SynthesizedRuntime::Cli { action, .. } = &catalog.runtime else {
            panic!("expected CLI catalog");
        };
        assert!(action.input_schema.properties.contains_key("profile"));
        assert_eq!(action.input_schema.required, vec!["args", "profile"]);

        selectable.auth.profile_selection = ProfileSelection::Selectable {
            default: Some("work".to_owned()),
        };
        let catalog = compile("gws", &selectable);
        let SynthesizedRuntime::Cli { action, .. } = &catalog.runtime else {
            panic!("expected CLI catalog");
        };
        assert_eq!(action.input_schema.required, vec!["args"]);
        assert!(matches!(
            action.input_schema.properties.get("profile"),
            Some(SynthesizedPropertySchema::String {
                default: Some(value),
                ..
            }) if value == "work"
        ));

        selectable.auth.profile_selection = ProfileSelection::Fixed {
            alias: "work".to_owned(),
        };
        let catalog = compile("gws", &selectable);
        assert!(!properties(&catalog).contains_key("profile"));

        selectable.auth.profile_selection = ProfileSelection::Implicit;
        selectable.auth.storage = AuthStorage::CliOwned;
        let catalog = compile("gws", &selectable);
        assert!(!properties(&catalog).contains_key("profile"));
    }

    #[test]
    fn stdin_working_directory_and_timeout_follow_validated_contract_ceilings() {
        let mut contract = cli_contract("provider-cli");
        let RuntimeProtocol::Cli {
            stdin,
            working_directory,
            limits,
            ..
        } = &mut contract.runtime
        else {
            unreachable!();
        };
        stdin.mode = StdinMode::Required;
        stdin.sensitivity = DataSensitivity::Private;
        working_directory.mode = WorkingDirectoryMode::Workspace;
        limits.stdin_bytes = Some(4096);
        limits.timeout_secs = Some(45);

        let catalog = compile("provider-cli", &contract);
        let SynthesizedRuntime::Cli { action, .. } = &catalog.runtime else {
            panic!("expected CLI catalog");
        };
        assert_eq!(action.input_schema.required, vec!["args", "stdin"]);
        assert!(matches!(
            action.input_schema.properties.get("stdin"),
            Some(SynthesizedPropertySchema::String {
                max_length: 4096,
                max_utf8_bytes: Some(4096),
                data_sensitivity: Some(DataSensitivity::Private),
                ..
            })
        ));
        assert!(matches!(
            action.input_schema.properties.get("working_dir"),
            Some(SynthesizedPropertySchema::String {
                path_authority: Some(WorkingDirectoryMode::Workspace),
                ..
            })
        ));
        assert!(matches!(
            action.input_schema.properties.get("timeout_secs"),
            Some(SynthesizedPropertySchema::Integer { maximum: 45, .. })
        ));
    }

    #[test]
    fn key_order_and_markdown_body_do_not_change_synthesized_bytes() {
        fn skill(contract: &str, body: &str) -> String {
            format!(
                "---\nname: fixture\nmetadata:\n  magician:\n    runtime_contract:\n{}---\n{body}\n",
                contract
                    .lines()
                    .map(|line| format!("      {line}\n"))
                    .collect::<String>()
            )
        }
        let first = skill(
            "schema_version: tool-runtime.skill-runtime.v1\nrequires:\n  bins: [jq]\nruntime:\n  protocol: cli\n  command_prefix: [fixed]\npolicy_floor:\n  required_grants: [write, read]\n",
            "# First prose body",
        );
        let second = skill(
            "policy_floor:\n  required_grants: [read, write]\nruntime:\n  command_prefix: [fixed]\n  protocol: cli\nrequires:\n  bins: [jq]\nschema_version: tool-runtime.skill-runtime.v1\n",
            "Completely unrelated prose and examples.",
        );
        let first = parse_skill_runtime_contract(&first)
            .expect("parse first")
            .expect("contract present");
        let second = parse_skill_runtime_contract(&second)
            .expect("parse second")
            .expect("contract present");
        let first = compile("jq", &first);
        let second = compile("jq", &second);

        assert_eq!(first, second);
        assert_eq!(
            serde_json::to_vec(&first).expect("serialize first"),
            serde_json::to_vec(&second).expect("serialize second")
        );
    }

    #[test]
    fn stdio_mcp_synthesizes_skill_owned_namespace_and_deny_wins_limit() {
        let contract = SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires: RuntimeRequirements {
                bins: BTreeSet::from(["provider-mcp".to_owned()]),
                entrypoint: Default::default(),
                environment: Default::default(),
            },
            runtime: RuntimeProtocol::Mcp {
                transport: McpTransport::Stdio {
                    executable: "provider-mcp".to_owned(),
                    args: vec!["--stdio".to_owned()],
                },
                discovery: McpDiscoveryPolicy {
                    namespace: Some("mail".to_owned()),
                    allow_tools: BTreeSet::from(["read".to_owned(), "search".to_owned()]),
                    deny_tools: BTreeSet::from(["search".to_owned()]),
                    tool_policies: Default::default(),
                    ..McpDiscoveryPolicy::default()
                },
                limits: RuntimeLimits::default(),
            },
            auth: AuthContract::default(),
            policy_floor: PolicyFloor::default(),
        };
        let catalog = compile("provider", &contract);
        let SynthesizedRuntime::Mcp { discovery } = &catalog.runtime else {
            panic!("expected MCP catalog seed");
        };

        assert_eq!(discovery.local_namespace, "provider.mail");
        assert_eq!(discovery.naming_strategy, "skill_namespace_dot_v1");
        assert_eq!(discovery.catalog_limits.max_tools, 1);
        assert!(matches!(
            discovery.transport,
            McpTransport::Stdio { ref executable, .. } if executable == "provider-mcp"
        ));
    }

    #[test]
    fn remote_mcp_seed_preserves_transport_without_connecting_or_discovering() {
        let mut contract = cli_contract("placeholder");
        contract.requires.bins.clear();
        contract.runtime = RuntimeProtocol::Mcp {
            transport: McpTransport::StreamableHttp {
                endpoint: "https://provider.example/mcp".to_owned(),
            },
            discovery: McpDiscoveryPolicy::default(),
            limits: RuntimeLimits {
                timeout_secs: Some(30),
                ..RuntimeLimits::default()
            },
        };
        let catalog = compile("remote-provider", &contract);
        let SynthesizedRuntime::Mcp { discovery } = &catalog.runtime else {
            panic!("expected MCP catalog seed");
        };

        assert_eq!(discovery.local_namespace, "remote-provider");
        assert_eq!(discovery.catalog_limits.max_tools, MAX_DISCOVERED_MCP_TOOLS);
        assert!(matches!(
            discovery.transport,
            McpTransport::StreamableHttp { ref endpoint }
                if endpoint == "https://provider.example/mcp"
        ));
    }

    #[test]
    fn synthesized_output_carries_policy_but_not_secret_or_injection_references() {
        let secret_canary = "SECRET_REFERENCE_CANARY";
        let injection_canary = "SECRET_ENV_CANARY";
        let mut contract = cli_contract("provider-cli");
        contract.auth.kind = AuthKind::Secrets;
        contract.auth.requirement = AuthRequirement::Required;
        contract.auth.secret_bindings = vec![crate::manifest::SecretBindingRef {
            name: "api_key".to_owned(),
            secret_ref: secret_canary.to_owned(),
        }];
        contract.auth.injections = vec![InjectionBinding {
            source: InjectionSource::Secret {
                binding: "api_key".to_owned(),
            },
            target: InjectionTarget::Environment {
                name: injection_canary.to_owned(),
            },
        }];
        contract.policy_floor.approval = ApprovalClass::ConditionalExternalSideEffect;
        contract
            .policy_floor
            .required_grants
            .insert("provider-write".to_owned());

        let catalog = compile("provider", &contract);
        let serialized = serde_json::to_string(&catalog).expect("serialize catalog");
        assert_eq!(
            catalog.security_floor.policy.approval,
            ApprovalClass::ConditionalExternalSideEffect
        );
        assert!(!serialized.contains(secret_canary));
        assert!(!serialized.contains(injection_canary));
        assert!(!serialized.contains("api_key"));
    }

    #[test]
    fn invalid_skill_id_diagnostic_is_fixed_and_value_free() {
        let canary = "../../SECRET-SKILL-CANARY";
        let contract = cli_contract("jq");
        let validated = validate_skill_runtime_contract(&contract).expect("valid contract");
        let diagnostic = synthesize_runtime_catalog(canary, validated).expect_err("invalid id");
        let serialized = serde_json::to_string(&diagnostic).expect("serialize diagnostic");

        assert_eq!(diagnostic.code, ManifestSynthesisErrorCode::InvalidSkillId);
        assert!(!diagnostic.to_string().contains(canary));
        assert!(!serialized.contains(canary));
    }

    #[test]
    fn maximum_fixed_prefix_synthesizes_on_a_small_stack() {
        let result = thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| {
                let mut contract = cli_contract("provider-cli");
                let RuntimeProtocol::Cli { command_prefix, .. } = &mut contract.runtime else {
                    unreachable!();
                };
                *command_prefix = vec!["x".repeat(500); MAX_FIXED_ARGUMENTS];
                let catalog = compile("provider", &contract);
                serde_json::to_vec(&catalog)
                    .expect("serialize bounded catalog")
                    .len()
            })
            .expect("spawn small-stack synthesis")
            .join()
            .expect("synthesis must not overflow");

        assert!(result > 60_000);
    }

    #[test]
    fn model_schema_is_closed_and_uses_standard_json_schema_keywords() {
        let catalog = compile("jq", &cli_contract("jq"));
        let serialized = serde_json::to_value(&catalog).expect("serialize catalog");
        let schema = &serialized["runtime"]["action"]["input_schema"];

        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["args"]["type"], "array");
        assert_eq!(schema["properties"]["args"]["items"]["type"], "string");
        assert_eq!(schema["properties"]["timeout_secs"]["type"], "integer");
    }
}
