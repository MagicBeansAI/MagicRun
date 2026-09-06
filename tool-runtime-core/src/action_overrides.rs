//! Monotonic typed-action composition over a validated CLI runtime contract.
//!
//! An explicit override may replace the generic model-facing `run` shape with
//! narrower typed actions. It cannot replace executable identity, auth/profile
//! selection, stdin or path authority, runtime ceilings, grants, approvals, or
//! resource authority. A v2 action may consume manifest-owned stdin as its
//! canonical input transport; it cannot create or widen that authority. Policy
//! refinements are additive and compilation performs no I/O, execution,
//! credential work, or production catalog publication.

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};

use crate::{
    manifest::{ApprovalClass, AuthLifecycle},
    manifest_synthesis::{
        synthesize_runtime_catalog, SynthesizedArgumentLimits, SynthesizedCliExecution,
        SynthesizedRuntime, SynthesizedSecurityFloor, MAX_SYNTHESIZED_TOOL_NAME_BYTES,
    },
    manifest_validation::{
        is_identifier, is_reference, reject_inline_code_prefix, validate_fixed_arguments,
        ValidatedSkillRuntimeContract, MAX_ARGUMENT_BYTES, MAX_FIXED_ARGUMENTS,
        MAX_FIXED_ARGUMENT_BYTES, MAX_POLICY_ENTRIES, MAX_RUNTIME_TIMEOUT_SECS,
    },
};

pub const TYPED_ACTION_OVERRIDES_V1: &str = "tool-runtime.typed-action-overrides.v1";
pub const TYPED_ACTION_OVERRIDES_V2: &str = "tool-runtime.typed-action-overrides.v2";
pub const COMPILED_ACTION_CATALOG_V1: &str = "tool-runtime.compiled-action-catalog.v1";
pub const MAX_TYPED_ACTIONS: usize = 512;
pub const MAX_TYPED_PARAMETERS: usize = 512;
pub const MAX_TYPED_MAPPINGS: usize = 512;
pub const MAX_TYPED_ACTION_ID_BYTES: usize = 128;
pub const MAX_TYPED_PARAMETER_ID_BYTES: usize = 128;
pub const MAX_TYPED_DESCRIPTION_BYTES: usize = 8 * 1024;
pub const MAX_TYPED_RUNTIME_CONTROL_STRING_BYTES: u64 = 64 * 1024;
pub const MAX_TYPED_ENUM_VALUES: usize = 256;
pub const MAX_TYPED_JSON_DEPTH: usize = 16;
pub const MAX_TYPED_JSON_NODES: usize = 2_048;
pub const MAX_TYPED_ARGUMENT_RULES: usize = 64;
pub const MAX_TYPED_ARGUMENT_RULE_PREFIX_TOKENS: usize = 16;
pub const MAX_TYPED_ARGUMENT_RULE_ALLOWED_TOKENS: usize = 64;
pub const MAX_TYPED_ARGUMENT_RULE_TOTAL_TOKENS: usize = 8_192;
pub const MAX_TYPED_ARGUMENT_RULE_TOTAL_BYTES: usize = 1024 * 1024;

const RESERVED_RUNTIME_PARAMETERS: [&str; 4] = ["profile", "stdin", "working_dir", "timeout_secs"];

/// Versioned, provider-neutral typed action refinement.
///
/// The type intentionally has no executable, auth, profile, storage, injection,
/// lifecycle, scope-replacement, or policy-replacement field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedActionOverrideSet {
    pub schema_version: String,
    /// How validated action parameters cross the executable boundary. Ordinary
    /// CLIs retain exact inert argv. Protocol adapters can instead receive one
    /// canonical JSON object on stdin, avoiding a second hand-authored flag
    /// schema in the adapter executable.
    #[serde(default)]
    pub input_delivery: TypedActionInputDelivery,
    pub actions: BTreeMap<String, TypedActionOverride>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypedActionInputDelivery {
    #[default]
    Argv,
    CanonicalJsonStdin,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedActionOverride {
    pub description: String,
    /// Optional exact executable for multi-binary packages. It must be one of
    /// the manifest's reviewed requirements and is never model-controlled.
    #[serde(default)]
    pub executable: Option<String>,
    #[serde(default)]
    pub route: TypedActionRoute,
    #[serde(default)]
    pub fixed_args: Vec<String>,
    /// Inert arguments appended after all parameter mappings. This preserves
    /// CLIs whose global flags must follow a subcommand without admitting a
    /// shell template or model-authored raw suffix.
    #[serde(default)]
    pub suffix_args: Vec<String>,
    /// Action-local exposure of manifest-owned stdin. The default preserves
    /// the validated runtime contract; refinements can only remove authority
    /// or change optionality within an already-declared stdin lane.
    #[serde(default)]
    pub stdin: TypedActionStdin,
    #[serde(default)]
    pub parameters: BTreeMap<String, TypedActionParameter>,
    #[serde(default)]
    pub mappings: Vec<TypedArgumentMapping>,
    /// Bounded, declarative restrictions over the final inert argv. This is
    /// intended for native CLIs whose former wrappers enforced a small amount
    /// of real local command policy. It cannot add, rewrite, or execute tokens.
    #[serde(default)]
    pub argument_rules: TypedArgumentRules,
    /// May lower the manifest/runtime ceiling, never raise it.
    #[serde(default)]
    pub timeout_secs: Option<u32>,
    #[serde(default)]
    pub policy: ActionPolicyRefinement,
}

/// Additive restrictions over an action's final argv.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TypedArgumentRules {
    /// Reject an invocation whose argv starts with any declared prefix.
    pub denied_prefixes: Vec<Vec<String>>,
    /// When argv starts with `prefix`, the immediately following token must be
    /// present and belong to `allowed_next_tokens`. Remaining tokens stay inert.
    pub constrained_prefixes: Vec<TypedConstrainedArgumentPrefix>,
}

impl TypedArgumentRules {
    pub fn is_empty(&self) -> bool {
        self.denied_prefixes.is_empty() && self.constrained_prefixes.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedConstrainedArgumentPrefix {
    pub prefix: Vec<String>,
    pub allowed_next_tokens: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypedActionStdin {
    #[default]
    Inherit,
    Denied,
    Optional,
    Required,
}

/// Finite execution lane for a typed action. Auth actions must be a nonempty
/// prefix of their broker-owned lifecycle hook; the route cannot replace auth
/// policy or select an unrelated lifecycle path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypedActionRoute {
    #[default]
    Execute,
    AuthStatus,
    AuthLogin,
}

/// Finite, nonrecursive parameter vocabulary. JSON object values are opaque and
/// size/depth/node bounded; arbitrary recursive authored schemas are not accepted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TypedActionParameter {
    String {
        description: String,
        #[serde(default)]
        required: bool,
        #[serde(default)]
        default: Option<String>,
        #[serde(default)]
        enum_values: BTreeSet<String>,
        #[serde(default)]
        min_length: Option<u64>,
        #[serde(default)]
        max_length: Option<u64>,
    },
    /// A filesystem path whose authority is resolved by the product runtime,
    /// never by the model-authored argv contract. The core validates only the
    /// bounded string shape; the dispatcher binds it beneath the admitted
    /// workspace root (or to an exact broker-owned path) before execution.
    WorkspacePath {
        description: String,
        access: WorkspacePathAccess,
        #[serde(default)]
        required: bool,
        #[serde(default)]
        max_length: Option<u64>,
    },
    Integer {
        description: String,
        #[serde(default)]
        required: bool,
        #[serde(default)]
        default: Option<i64>,
        #[serde(default)]
        enum_values: BTreeSet<i64>,
        #[serde(default)]
        minimum: Option<i64>,
        #[serde(default)]
        maximum: Option<i64>,
    },
    Number {
        description: String,
        #[serde(default)]
        required: bool,
        #[serde(default)]
        default: Option<Number>,
        #[serde(default)]
        minimum: Option<Number>,
        #[serde(default)]
        maximum: Option<Number>,
    },
    Boolean {
        description: String,
        #[serde(default)]
        required: bool,
        #[serde(default)]
        default: Option<bool>,
    },
    StringArray {
        description: String,
        #[serde(default)]
        required: bool,
        #[serde(default)]
        min_items: Option<u64>,
        #[serde(default)]
        max_items: Option<u64>,
        #[serde(default)]
        max_item_bytes: Option<u64>,
    },
    JsonObject {
        description: String,
        #[serde(default)]
        required: bool,
        #[serde(default)]
        max_json_bytes: Option<u64>,
        #[serde(default)]
        max_depth: Option<u64>,
        #[serde(default)]
        max_nodes: Option<u64>,
    },
    JsonArray {
        description: String,
        #[serde(default)]
        required: bool,
        #[serde(default)]
        max_json_bytes: Option<u64>,
        #[serde(default)]
        max_depth: Option<u64>,
        #[serde(default)]
        max_nodes: Option<u64>,
        #[serde(default)]
        max_items: Option<u64>,
    },
}

/// Finite filesystem authority carried by a typed workspace path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspacePathAccess {
    ReadFile,
    CreateFile,
    CreateDirectory,
}

impl TypedActionParameter {
    fn description(&self) -> &str {
        match self {
            Self::String { description, .. }
            | Self::WorkspacePath { description, .. }
            | Self::Integer { description, .. }
            | Self::Number { description, .. }
            | Self::Boolean { description, .. }
            | Self::StringArray { description, .. }
            | Self::JsonObject { description, .. }
            | Self::JsonArray { description, .. } => description,
        }
    }

    fn required(&self) -> bool {
        match self {
            Self::String { required, .. }
            | Self::WorkspacePath { required, .. }
            | Self::Integer { required, .. }
            | Self::Number { required, .. }
            | Self::Boolean { required, .. }
            | Self::StringArray { required, .. }
            | Self::JsonObject { required, .. }
            | Self::JsonArray { required, .. } => *required,
        }
    }
}

/// Exact non-shell argv lowering. Environment mutation is deliberately absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TypedArgumentMapping {
    Positional {
        parameter: String,
    },
    Flag {
        flag: String,
        parameter: String,
        /// Preserve native CLIs whose optional value flag must disappear when
        /// the compatibility default is an empty string.
        #[serde(default)]
        omit_if_empty: bool,
    },
    BoolFlag {
        flag: String,
        parameter: String,
    },
    RepeatedFlag {
        flag: String,
        parameter: String,
    },
    Passthrough {
        parameter: String,
    },
    JsonFlag {
        flag: String,
        parameter: String,
    },
    /// Insert a finite trusted token sequence at this exact point in the
    /// action mapping order. These tokens are authored in the package and are
    /// never model-controlled.
    Literal {
        arguments: Vec<String>,
    },
    /// Lexically split one bounded string into inert argv tokens. This has no
    /// variable expansion, globbing, redirection, pipes, or command execution.
    SplitPositional {
        parameter: String,
        max_items: u64,
        max_item_bytes: u64,
    },
    /// Deliver one already-validated, bounded action value to a trusted
    /// specialized runtime controller instead of placing it in child argv.
    /// Generic CLI dispatch must reject unconsumed controls.
    RuntimeControl {
        parameter: String,
    },
}

impl TypedArgumentMapping {
    fn parameter(&self) -> Option<&str> {
        match self {
            Self::Positional { parameter }
            | Self::Flag { parameter, .. }
            | Self::BoolFlag { parameter, .. }
            | Self::RepeatedFlag { parameter, .. }
            | Self::Passthrough { parameter }
            | Self::JsonFlag { parameter, .. }
            | Self::SplitPositional { parameter, .. }
            | Self::RuntimeControl { parameter } => Some(parameter),
            Self::Literal { .. } => None,
        }
    }

    fn flag(&self) -> Option<&str> {
        match self {
            Self::Flag { flag, .. }
            | Self::BoolFlag { flag, .. }
            | Self::RepeatedFlag { flag, .. }
            | Self::JsonFlag { flag, .. } => Some(flag),
            Self::Positional { .. }
            | Self::Passthrough { .. }
            | Self::Literal { .. }
            | Self::SplitPositional { .. }
            | Self::RuntimeControl { .. } => None,
        }
    }
}

/// Additive-only action policy. There is no replacement form.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ActionPolicyRefinement {
    pub additional_approvals: BTreeSet<ApprovalClass>,
    pub additional_required_grants: BTreeSet<String>,
    pub additional_resource_scopes: BTreeSet<String>,
    pub additional_required_resource_authorities: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompiledActionCatalog {
    pub schema_version: &'static str,
    pub skill_id: String,
    pub execution: SynthesizedCliExecution,
    pub security_floor: SynthesizedSecurityFloor,
    pub actions: BTreeMap<String, CompiledTypedAction>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompiledTypedAction {
    pub definition: CompiledActionDefinition,
    pub invocation: CompiledActionInvocation,
    pub effective_policy: EffectiveActionPolicy,
    /// Trusted authored parameter vocabulary retained for runtime lowering.
    /// The public compiled catalog already exposes the corresponding JSON
    /// schema; retaining this private-to-the-process copy avoids interpreting
    /// that presentation schema during execution.
    #[serde(skip)]
    pub parameters: BTreeMap<String, TypedActionParameter>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompiledActionDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompiledActionInvocation {
    pub executable: String,
    pub fixed_args: Vec<String>,
    pub suffix_args: Vec<String>,
    pub route: TypedActionRoute,
    pub stdin: TypedActionStdin,
    pub mappings: Vec<TypedArgumentMapping>,
    #[serde(skip_serializing_if = "TypedArgumentRules::is_empty")]
    pub argument_rules: TypedArgumentRules,
    pub input_delivery: TypedActionInputDelivery,
    pub max_generated_stdin_bytes: Option<u64>,
    pub timeout_ceiling_secs: u32,
    pub argument_limits: SynthesizedArgumentLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EffectiveActionPolicy {
    pub required_approvals: BTreeSet<ApprovalClass>,
    pub required_grants: BTreeSet<String>,
    pub resource_scopes: BTreeSet<String>,
    pub required_resource_authorities: BTreeSet<String>,
}

/// Inert process arguments plus runtime-owned controls produced from one
/// already-compiled typed action. No shell parsing or environment mutation is
/// performed by this boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweredTypedActionInvocation {
    pub arguments: Vec<String>,
    pub runtime_controls: BTreeMap<String, Value>,
    pub profile: Option<String>,
    pub stdin: Option<String>,
    pub working_directory: Option<String>,
    pub timeout_secs: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TypedActionInvocationErrorCode {
    InvalidInput,
    MissingRequiredParameter,
    UnknownParameter,
    InvalidParameter,
    InvocationTooLarge,
}

/// Stable, value-free runtime diagnostic. Model arguments never enter the
/// message or serialized error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TypedActionInvocationError {
    pub code: TypedActionInvocationErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl TypedActionInvocationError {
    const fn new(
        code: TypedActionInvocationErrorCode,
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

impl fmt::Display for TypedActionInvocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for TypedActionInvocationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionOverrideErrorCode {
    UnsupportedSchemaVersion,
    EmptyOverride,
    CollectionTooLarge,
    UnsupportedRuntime,
    InvalidAction,
    InvalidDescription,
    InvalidFixedArguments,
    AuthPathConflict,
    InvalidParameter,
    InvalidMapping,
    InvalidArgumentRules,
    InvalidTimeout,
    InvalidPolicyRefinement,
    ProjectedInvocationTooLarge,
    BaseContractInvariantViolation,
}

/// Stable, value-free diagnostic. Authored identifiers, descriptions, defaults,
/// flags, and policy references never enter the message or serialized error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ActionOverrideError {
    pub code: ActionOverrideErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl ActionOverrideError {
    const fn new(
        code: ActionOverrideErrorCode,
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

impl fmt::Display for ActionOverrideError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for ActionOverrideError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParameterShape {
    Scalar {
        max_bytes: usize,
    },
    Boolean,
    StringArray {
        max_items: usize,
        max_item_bytes: usize,
    },
    JsonObject {
        max_bytes: usize,
    },
    JsonArray {
        max_bytes: usize,
    },
}

/// Compile a typed override against an unforgeable Phase 1C validation proof.
pub fn compile_typed_action_overrides(
    skill_id: &str,
    validated: ValidatedSkillRuntimeContract<'_>,
    overrides: &TypedActionOverrideSet,
) -> Result<CompiledActionCatalog, ActionOverrideError> {
    if !matches!(
        overrides.schema_version.as_str(),
        TYPED_ACTION_OVERRIDES_V1 | TYPED_ACTION_OVERRIDES_V2
    ) {
        return Err(ActionOverrideError::new(
            ActionOverrideErrorCode::UnsupportedSchemaVersion,
            "schema_version",
            "the action override compiler supports only the v1 or v2 contract",
        ));
    }
    if overrides.input_delivery != TypedActionInputDelivery::Argv
        && overrides.schema_version != TYPED_ACTION_OVERRIDES_V2
    {
        return Err(ActionOverrideError::new(
            ActionOverrideErrorCode::UnsupportedSchemaVersion,
            "schema_version",
            "non-argv input delivery requires the v2 action contract",
        ));
    }
    if overrides.actions.is_empty() {
        return Err(ActionOverrideError::new(
            ActionOverrideErrorCode::EmptyOverride,
            "actions",
            "an explicit override must declare at least one action",
        ));
    }
    bounded_len(overrides.actions.len(), MAX_TYPED_ACTIONS, "actions")?;

    let contract = validated.contract();
    let base = synthesize_runtime_catalog(skill_id, validated).map_err(|_| {
        ActionOverrideError::new(
            ActionOverrideErrorCode::BaseContractInvariantViolation,
            "skill_id",
            "the validated base contract could not be synthesized",
        )
    })?;
    let SynthesizedRuntime::Cli {
        action: base_action,
        execution,
    } = &base.runtime
    else {
        return Err(ActionOverrideError::new(
            ActionOverrideErrorCode::UnsupportedRuntime,
            "runtime.protocol",
            "typed action overrides require a validated CLI runtime",
        ));
    };

    let base_controls = base_runtime_controls(base_action)?;
    let base_timeout = execution
        .limits
        .timeout_secs
        .unwrap_or(MAX_RUNTIME_TIMEOUT_SECS);
    let mut compiled = BTreeMap::new();
    for (action_id, action) in &overrides.actions {
        validate_action_id(action_id, skill_id)?;
        validate_description(&action.description, "actions.description")?;
        let action_executable = action.executable.as_ref().unwrap_or(&execution.executable);
        if !contract.requires.bins.contains(action_executable)
            || action.executable.is_some() && overrides.schema_version != TYPED_ACTION_OVERRIDES_V2
        {
            return Err(ActionOverrideError::new(
                ActionOverrideErrorCode::InvalidFixedArguments,
                "actions.executable",
                "an action executable must be a reviewed v2 package requirement",
            ));
        }
        validate_action_prefix(execution, action_executable, &action.fixed_args)?;
        validate_action_suffix(
            execution,
            action_executable,
            &action.fixed_args,
            &action.suffix_args,
        )?;
        validate_auth_path_separation(
            execution,
            action_executable,
            &action.fixed_args,
            action.route,
            &contract.auth.lifecycle,
        )?;
        bounded_len(
            action.parameters.len(),
            MAX_TYPED_PARAMETERS,
            "actions.parameters",
        )?;
        bounded_len(
            action.mappings.len(),
            MAX_TYPED_MAPPINGS,
            "actions.mappings",
        )?;
        validate_argument_rules(&action.argument_rules)?;

        let timeout_ceiling_secs = match action.timeout_secs {
            Some(timeout) if timeout == 0 || timeout > base_timeout => {
                return Err(ActionOverrideError::new(
                    ActionOverrideErrorCode::InvalidTimeout,
                    "actions.timeout_secs",
                    "an action timeout must be nonzero and no higher than the base ceiling",
                ));
            },
            Some(timeout) => timeout,
            None => base_timeout,
        };

        let mut properties = base_controls.properties.clone();
        let mut required = base_controls.required.clone();
        if overrides.input_delivery == TypedActionInputDelivery::Argv {
            refine_action_stdin(
                execution.stdin_mode,
                action.stdin,
                &mut properties,
                &mut required,
            )?;
        }
        let max_generated_stdin_bytes = match overrides.input_delivery {
            TypedActionInputDelivery::Argv => None,
            TypedActionInputDelivery::CanonicalJsonStdin => {
                if matches!(
                    action.stdin,
                    TypedActionStdin::Optional | TypedActionStdin::Required
                ) {
                    return Err(ActionOverrideError::new(
                        ActionOverrideErrorCode::InvalidParameter,
                        "actions.stdin",
                        "canonical JSON delivery exclusively owns the declared stdin lane",
                    ));
                }
                if execution.stdin_mode != crate::manifest::StdinMode::Required
                    || contract.auth.injections.iter().any(|binding| {
                        matches!(&binding.target, crate::manifest::InjectionTarget::Stdin)
                    })
                    || properties.remove("stdin").is_none()
                {
                    return Err(ActionOverrideError::new(
                        ActionOverrideErrorCode::BaseContractInvariantViolation,
                        "runtime.stdin",
                        "canonical JSON delivery requires dedicated required stdin authority",
                    ));
                }
                required.remove("stdin");
                Some(
                    execution
                        .limits
                        .stdin_bytes
                        .unwrap_or(crate::manifest_validation::MAX_RUNTIME_STREAM_BYTES),
                )
            },
        };
        lower_timeout_ceiling(&mut properties, timeout_ceiling_secs)?;
        let runtime_control_parameters = action
            .mappings
            .iter()
            .filter_map(|mapping| match mapping {
                TypedArgumentMapping::RuntimeControl { parameter } => Some(parameter.as_str()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let mut shapes = BTreeMap::new();
        for (parameter_name, parameter) in &action.parameters {
            validate_parameter_id(parameter_name)?;
            validate_description(parameter.description(), "actions.parameters.description")?;
            let maximum_parameter_bytes =
                if runtime_control_parameters.contains(parameter_name.as_str()) {
                    MAX_TYPED_RUNTIME_CONTROL_STRING_BYTES
                } else if overrides.input_delivery == TypedActionInputDelivery::CanonicalJsonStdin {
                    max_generated_stdin_bytes.ok_or_else(|| {
                        ActionOverrideError::new(
                            ActionOverrideErrorCode::BaseContractInvariantViolation,
                            "runtime.stdin",
                            "canonical JSON delivery lost its validated stdin ceiling",
                        )
                    })?
                } else {
                    MAX_ARGUMENT_BYTES as u64
                };
            let (schema, shape) = compile_parameter(parameter, maximum_parameter_bytes)?;
            if properties.insert(parameter_name.clone(), schema).is_some() {
                return Err(ActionOverrideError::new(
                    ActionOverrideErrorCode::InvalidParameter,
                    "actions.parameters",
                    "an action parameter collides with a runtime-owned control",
                ));
            }
            if parameter.required() {
                required.insert(parameter_name.clone());
            }
            shapes.insert(parameter_name.clone(), shape);
        }

        match overrides.input_delivery {
            TypedActionInputDelivery::Argv => {
                validate_mappings(&action.mappings, &shapes, execution.model_argument_limits)?;
            },
            TypedActionInputDelivery::CanonicalJsonStdin => {
                if !action.mappings.is_empty() || action.route != TypedActionRoute::Execute {
                    return Err(ActionOverrideError::new(
                        ActionOverrideErrorCode::InvalidMapping,
                        "actions.mappings",
                        "canonical JSON delivery owns parameter lowering and accepts no argv mappings",
                    ));
                }
            },
        }
        let mut compiled_parameters = action.parameters.clone();
        for (parameter_name, parameter) in &mut compiled_parameters {
            let maximum_parameter_bytes =
                if runtime_control_parameters.contains(parameter_name.as_str()) {
                    MAX_TYPED_RUNTIME_CONTROL_STRING_BYTES
                } else if overrides.input_delivery == TypedActionInputDelivery::CanonicalJsonStdin {
                    max_generated_stdin_bytes.ok_or_else(|| {
                        ActionOverrideError::new(
                            ActionOverrideErrorCode::BaseContractInvariantViolation,
                            "runtime.stdin",
                            "canonical JSON delivery lost its validated stdin ceiling",
                        )
                    })?
                } else {
                    MAX_ARGUMENT_BYTES as u64
                };
            match parameter {
                TypedActionParameter::String { max_length, .. }
                | TypedActionParameter::WorkspacePath { max_length, .. }
                    if max_length.is_none() =>
                {
                    *max_length = Some(maximum_parameter_bytes);
                },
                TypedActionParameter::JsonObject { max_json_bytes, .. }
                | TypedActionParameter::JsonArray { max_json_bytes, .. }
                    if max_json_bytes.is_none() =>
                {
                    *max_json_bytes = Some(maximum_parameter_bytes);
                },
                _ => {},
            }
        }
        let mut effective_policy = compose_policy(&base.security_floor, &action.policy)?;
        let has_workspace_path = compiled_parameters
            .values()
            .any(|parameter| matches!(parameter, TypedActionParameter::WorkspacePath { .. }));
        if has_workspace_path {
            effective_policy
                .resource_scopes
                .insert("workspace".to_owned());
            if effective_policy.resource_scopes.len() > MAX_POLICY_ENTRIES {
                return Err(ActionOverrideError::new(
                    ActionOverrideErrorCode::InvalidPolicyRefinement,
                    "actions.policy",
                    "the effective policy exceeds its bounded entry limit",
                ));
            }
        }
        if compiled_parameters.values().any(|parameter| {
            matches!(
                parameter,
                TypedActionParameter::WorkspacePath {
                    access: WorkspacePathAccess::CreateFile | WorkspacePathAccess::CreateDirectory,
                    ..
                }
            )
        }) {
            // Authored action policy can strengthen this floor, never omit it.
            // A create-only typed path is still a workspace mutation even when
            // the wrapped CLI describes itself as an ordinary local utility.
            effective_policy
                .required_approvals
                .insert(ApprovalClass::DelegatedWorkspaceWrite);
        }
        let name = action_name(skill_id, action_id)?;
        let input_schema = object_schema(properties, required);
        compiled.insert(
            action_id.clone(),
            CompiledTypedAction {
                definition: CompiledActionDefinition {
                    name,
                    description: action.description.clone(),
                    input_schema,
                },
                invocation: CompiledActionInvocation {
                    executable: action_executable.clone(),
                    fixed_args: action.fixed_args.clone(),
                    suffix_args: action.suffix_args.clone(),
                    route: action.route,
                    stdin: action.stdin,
                    mappings: action.mappings.clone(),
                    argument_rules: action.argument_rules.clone(),
                    input_delivery: overrides.input_delivery,
                    max_generated_stdin_bytes,
                    timeout_ceiling_secs,
                    argument_limits: execution.model_argument_limits,
                },
                effective_policy,
                parameters: compiled_parameters,
            },
        );
    }

    Ok(CompiledActionCatalog {
        schema_version: COMPILED_ACTION_CATALOG_V1,
        skill_id: base.skill_id,
        execution: execution.clone(),
        security_floor: base.security_floor,
        actions: compiled,
    })
}

/// Validate and lower one model invocation against its trusted compiled action.
///
/// Values are either appended as individual argv tokens or encoded as one
/// bounded canonical JSON object on manifest-owned stdin. Metacharacters remain
/// inert data in both forms and cannot introduce a shell boundary. Runtime-owned
/// controls are returned separately and are never included in either payload.
pub fn lower_typed_action_invocation(
    action: &CompiledTypedAction,
    input: &Value,
) -> Result<LoweredTypedActionInvocation, TypedActionInvocationError> {
    let object = input.as_object().ok_or_else(invalid_invocation_input)?;
    let schema_properties = action
        .definition
        .input_schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(invalid_invocation_input)?;
    if object
        .keys()
        .any(|name| !schema_properties.contains_key(name))
    {
        return Err(TypedActionInvocationError::new(
            TypedActionInvocationErrorCode::UnknownParameter,
            "input",
            "the invocation contains an unknown parameter",
        ));
    }

    let required = action
        .definition
        .input_schema
        .get("required")
        .and_then(Value::as_array)
        .ok_or_else(invalid_invocation_input)?;
    if required
        .iter()
        .filter_map(Value::as_str)
        .any(|name| !object.contains_key(name) && parameter_default(action, name).is_none())
    {
        return Err(TypedActionInvocationError::new(
            TypedActionInvocationErrorCode::MissingRequiredParameter,
            "input",
            "the invocation is missing a required parameter",
        ));
    }

    let mut arguments = action.invocation.fixed_args.clone();
    let mut runtime_controls = BTreeMap::new();
    let generated_stdin = match action.invocation.input_delivery {
        TypedActionInputDelivery::Argv => {
            for mapping in &action.invocation.mappings {
                if let TypedArgumentMapping::Literal { arguments: literal } = mapping {
                    arguments.extend(literal.iter().cloned());
                    continue;
                }
                let name = mapping.parameter().ok_or_else(invalid_invocation_input)?;
                let Some(parameter) = action.parameters.get(name) else {
                    return Err(invalid_invocation_input());
                };
                let value = match object.get(name) {
                    Some(value) => Some(Cow::Borrowed(value)),
                    None => typed_parameter_default(parameter).map(Cow::Owned),
                };
                let Some(value) = value else { continue };
                validate_runtime_parameter(parameter, value.as_ref())?;
                if matches!(mapping, TypedArgumentMapping::RuntimeControl { .. }) {
                    runtime_controls.insert(name.to_owned(), value.into_owned());
                } else {
                    lower_mapping(mapping, value.as_ref(), &mut arguments)?;
                }
            }
            None
        },
        TypedActionInputDelivery::CanonicalJsonStdin => {
            let mut payload = BTreeMap::new();
            for (name, parameter) in &action.parameters {
                let value = match object.get(name) {
                    Some(value) => Some(Cow::Borrowed(value)),
                    None => typed_parameter_default(parameter).map(Cow::Owned),
                };
                let Some(value) = value else { continue };
                validate_runtime_parameter(parameter, value.as_ref())?;
                payload.insert(name.clone(), value.into_owned());
            }
            let encoded =
                serde_json::to_string(&payload).map_err(|_| invalid_runtime_parameter())?;
            if encoded.len()
                > action
                    .invocation
                    .max_generated_stdin_bytes
                    .and_then(|value| usize::try_from(value).ok())
                    .ok_or_else(invocation_too_large)?
            {
                return Err(invocation_too_large());
            }
            Some(encoded)
        },
    };
    arguments.extend(action.invocation.suffix_args.iter().cloned());
    validate_lowered_arguments(&arguments, action.invocation.argument_limits)?;
    enforce_argument_rules(&arguments, &action.invocation.argument_rules)?;

    let profile = lower_optional_control(object, "profile", Value::as_str)?.map(str::to_owned);
    let stdin = match action.invocation.input_delivery {
        TypedActionInputDelivery::Argv => {
            lower_optional_control(object, "stdin", Value::as_str)?.map(str::to_owned)
        },
        TypedActionInputDelivery::CanonicalJsonStdin => generated_stdin,
    };
    let working_directory =
        lower_optional_control(object, "working_dir", Value::as_str)?.map(str::to_owned);
    let timeout_secs = match object.get("timeout_secs") {
        Some(Value::Number(value)) => value
            .as_u64()
            .filter(|value| {
                *value > 0 && *value <= u64::from(action.invocation.timeout_ceiling_secs)
            })
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(invalid_runtime_parameter)?,
        Some(_) => return Err(invalid_runtime_parameter()),
        None => action.invocation.timeout_ceiling_secs,
    };

    Ok(LoweredTypedActionInvocation {
        arguments,
        runtime_controls,
        profile,
        stdin,
        working_directory,
        timeout_secs,
    })
}

fn validate_argument_rules(rules: &TypedArgumentRules) -> Result<(), ActionOverrideError> {
    bounded_len(
        rules.denied_prefixes.len(),
        MAX_TYPED_ARGUMENT_RULES,
        "actions.argument_rules.denied_prefixes",
    )?;
    bounded_len(
        rules.constrained_prefixes.len(),
        MAX_TYPED_ARGUMENT_RULES,
        "actions.argument_rules.constrained_prefixes",
    )?;

    let mut prefixes = BTreeSet::new();
    let mut total_tokens = 0_usize;
    let mut total_bytes = 0_usize;
    for prefix in &rules.denied_prefixes {
        validate_argument_rule_prefix(prefix)?;
        account_argument_rule_tokens(prefix, &mut total_tokens, &mut total_bytes)?;
        if !prefixes.insert(prefix.clone()) {
            return Err(invalid_argument_rules());
        }
    }
    for constraint in &rules.constrained_prefixes {
        validate_argument_rule_prefix(&constraint.prefix)?;
        if !prefixes.insert(constraint.prefix.clone())
            || constraint.allowed_next_tokens.is_empty()
            || constraint.allowed_next_tokens.len() > MAX_TYPED_ARGUMENT_RULE_ALLOWED_TOKENS
        {
            return Err(invalid_argument_rules());
        }
        account_argument_rule_tokens(&constraint.prefix, &mut total_tokens, &mut total_bytes)?;
        for token in &constraint.allowed_next_tokens {
            validate_fixed_arguments(
                std::slice::from_ref(token),
                "actions.argument_rules.allowed_next_tokens",
            )
            .map_err(|_| invalid_argument_rules())?;
            account_argument_rule_tokens(
                std::slice::from_ref(token),
                &mut total_tokens,
                &mut total_bytes,
            )?;
        }
    }

    // Overlapping constrained prefixes make author intent ambiguous because a
    // single argv could be subjected to two different "next token" positions.
    for (index, left) in rules.constrained_prefixes.iter().enumerate() {
        if rules
            .constrained_prefixes
            .iter()
            .skip(index + 1)
            .any(|right| {
                left.prefix.starts_with(&right.prefix) || right.prefix.starts_with(&left.prefix)
            })
        {
            return Err(invalid_argument_rules());
        }
    }
    Ok(())
}

fn account_argument_rule_tokens(
    tokens: &[String],
    total_tokens: &mut usize,
    total_bytes: &mut usize,
) -> Result<(), ActionOverrideError> {
    *total_tokens = total_tokens
        .checked_add(tokens.len())
        .ok_or_else(invalid_argument_rules)?;
    *total_bytes = tokens
        .iter()
        .try_fold(*total_bytes, |total, token| total.checked_add(token.len()))
        .ok_or_else(invalid_argument_rules)?;
    if *total_tokens > MAX_TYPED_ARGUMENT_RULE_TOTAL_TOKENS
        || *total_bytes > MAX_TYPED_ARGUMENT_RULE_TOTAL_BYTES
    {
        return Err(invalid_argument_rules());
    }
    Ok(())
}

fn validate_argument_rule_prefix(prefix: &[String]) -> Result<(), ActionOverrideError> {
    if prefix.is_empty() || prefix.len() > MAX_TYPED_ARGUMENT_RULE_PREFIX_TOKENS {
        return Err(invalid_argument_rules());
    }
    validate_fixed_arguments(prefix, "actions.argument_rules.prefix")
        .map_err(|_| invalid_argument_rules())
}

fn enforce_argument_rules(
    arguments: &[String],
    rules: &TypedArgumentRules,
) -> Result<(), TypedActionInvocationError> {
    if rules
        .denied_prefixes
        .iter()
        .any(|prefix| arguments.starts_with(prefix))
    {
        return Err(invalid_runtime_parameter());
    }
    for constraint in &rules.constrained_prefixes {
        if arguments.starts_with(&constraint.prefix)
            && !arguments
                .get(constraint.prefix.len())
                .is_some_and(|token| constraint.allowed_next_tokens.contains(token))
        {
            return Err(invalid_runtime_parameter());
        }
    }
    Ok(())
}

fn parameter_default<'a>(action: &'a CompiledTypedAction, name: &str) -> Option<Value> {
    action
        .parameters
        .get(name)
        .and_then(typed_parameter_default)
        .or_else(|| {
            action
                .definition
                .input_schema
                .get("properties")?
                .get(name)?
                .get("default")
                .cloned()
        })
}

fn typed_parameter_default(parameter: &TypedActionParameter) -> Option<Value> {
    match parameter {
        TypedActionParameter::String { default, .. } => {
            default.as_ref().map(|value| Value::String(value.clone()))
        },
        TypedActionParameter::WorkspacePath { .. } => None,
        TypedActionParameter::Integer { default, .. } => default.map(Value::from),
        TypedActionParameter::Number { default, .. } => {
            default.as_ref().map(|value| Value::Number(value.clone()))
        },
        TypedActionParameter::Boolean { default, .. } => default.map(Value::Bool),
        TypedActionParameter::StringArray { .. }
        | TypedActionParameter::JsonObject { .. }
        | TypedActionParameter::JsonArray { .. } => None,
    }
}

fn validate_runtime_parameter(
    parameter: &TypedActionParameter,
    value: &Value,
) -> Result<(), TypedActionInvocationError> {
    let valid = match parameter {
        TypedActionParameter::String {
            default,
            enum_values,
            min_length,
            max_length,
            ..
        } => value.as_str().is_some_and(|value| {
            let length = value.chars().count() as u64;
            length >= min_length.unwrap_or(0)
                && length <= max_length.unwrap_or(MAX_ARGUMENT_BYTES as u64)
                && value.len() <= max_length.unwrap_or(MAX_ARGUMENT_BYTES as u64) as usize
                && !value.chars().any(char::is_control)
                && (enum_values.is_empty()
                    || enum_values.contains(value)
                    || default.as_deref() == Some(value))
        }),
        TypedActionParameter::WorkspacePath { max_length, .. } => {
            value.as_str().is_some_and(|value| {
                !value.is_empty()
                    && value.len() <= max_length.unwrap_or(MAX_ARGUMENT_BYTES as u64) as usize
                    && !value.chars().any(char::is_control)
            })
        },
        TypedActionParameter::Integer {
            enum_values,
            minimum,
            maximum,
            ..
        } => value.as_i64().is_some_and(|value| {
            minimum.is_none_or(|minimum| value >= minimum)
                && maximum.is_none_or(|maximum| value <= maximum)
                && (enum_values.is_empty() || enum_values.contains(&value))
        }),
        TypedActionParameter::Number {
            minimum, maximum, ..
        } => value.as_f64().is_some_and(|value| {
            value.is_finite()
                && minimum
                    .as_ref()
                    .and_then(Number::as_f64)
                    .is_none_or(|minimum| value >= minimum)
                && maximum
                    .as_ref()
                    .and_then(Number::as_f64)
                    .is_none_or(|maximum| value <= maximum)
        }),
        TypedActionParameter::Boolean { .. } => value.is_boolean(),
        TypedActionParameter::StringArray {
            min_items,
            max_items,
            max_item_bytes,
            ..
        } => value.as_array().is_some_and(|values| {
            let count = values.len() as u64;
            count >= min_items.unwrap_or(0)
                && count <= max_items.unwrap_or(MAX_FIXED_ARGUMENTS as u64)
                && values.iter().all(|value| {
                    value.as_str().is_some_and(|value| {
                        value.len() <= max_item_bytes.unwrap_or(MAX_ARGUMENT_BYTES as u64) as usize
                            && !value.chars().any(char::is_control)
                    })
                })
        }),
        TypedActionParameter::JsonObject {
            max_json_bytes,
            max_depth,
            max_nodes,
            ..
        } => {
            value.is_object()
                && bounded_json_shape(
                    value,
                    max_depth.unwrap_or(MAX_TYPED_JSON_DEPTH as u64) as usize,
                    max_nodes.unwrap_or(MAX_TYPED_JSON_NODES as u64) as usize,
                )
                && stable_json(value).is_some_and(|encoded| {
                    encoded.len() <= max_json_bytes.unwrap_or(MAX_ARGUMENT_BYTES as u64) as usize
                })
        },
        TypedActionParameter::JsonArray {
            max_json_bytes,
            max_depth,
            max_nodes,
            max_items,
            ..
        } => value.as_array().is_some_and(|items| {
            items.len() <= max_items.unwrap_or(MAX_FIXED_ARGUMENTS as u64) as usize
                && bounded_json_shape(
                    value,
                    max_depth.unwrap_or(MAX_TYPED_JSON_DEPTH as u64) as usize,
                    max_nodes.unwrap_or(MAX_TYPED_JSON_NODES as u64) as usize,
                )
                && stable_json(value).is_some_and(|encoded| {
                    encoded.len() <= max_json_bytes.unwrap_or(MAX_ARGUMENT_BYTES as u64) as usize
                })
        }),
    };
    if valid {
        Ok(())
    } else {
        Err(invalid_runtime_parameter())
    }
}

fn bounded_json_shape(value: &Value, max_depth: usize, max_nodes: usize) -> bool {
    let mut stack = vec![(value, 1usize)];
    let mut nodes = 0usize;
    while let Some((value, depth)) = stack.pop() {
        nodes = nodes.saturating_add(1);
        if nodes > max_nodes || depth > max_depth {
            return false;
        }
        match value {
            Value::Array(values) => {
                stack.extend(values.iter().map(|value| (value, depth.saturating_add(1))));
            },
            Value::Object(values) => {
                stack.extend(
                    values
                        .values()
                        .map(|value| (value, depth.saturating_add(1))),
                );
            },
            _ => {},
        }
    }
    true
}

fn stable_json(value: &Value) -> Option<String> {
    // serde_json's default map is key ordered. Authored JSON is capped at a
    // shallow depth before serialization, preventing unbounded recursion.
    serde_json::to_string(value).ok()
}

fn lower_mapping(
    mapping: &TypedArgumentMapping,
    value: &Value,
    arguments: &mut Vec<String>,
) -> Result<(), TypedActionInvocationError> {
    match mapping {
        TypedArgumentMapping::Positional { .. } => {
            arguments.push(scalar_argument(value)?);
        },
        TypedArgumentMapping::Flag {
            flag,
            omit_if_empty,
            ..
        } => {
            if *omit_if_empty && value.as_str().is_some_and(str::is_empty) {
                return Ok(());
            }
            arguments.push(flag.clone());
            arguments.push(scalar_argument(value)?);
        },
        TypedArgumentMapping::BoolFlag { flag, .. } => {
            if value.as_bool().ok_or_else(invalid_runtime_parameter)? {
                arguments.push(flag.clone());
            }
        },
        TypedArgumentMapping::RepeatedFlag { flag, .. } => {
            for value in value.as_array().ok_or_else(invalid_runtime_parameter)? {
                arguments.push(flag.clone());
                arguments.push(
                    value
                        .as_str()
                        .ok_or_else(invalid_runtime_parameter)?
                        .to_owned(),
                );
            }
        },
        TypedArgumentMapping::Passthrough { .. } => {
            for value in value.as_array().ok_or_else(invalid_runtime_parameter)? {
                arguments.push(
                    value
                        .as_str()
                        .ok_or_else(invalid_runtime_parameter)?
                        .to_owned(),
                );
            }
        },
        TypedArgumentMapping::JsonFlag { flag, .. } => {
            arguments.push(flag.clone());
            arguments.push(stable_json(value).ok_or_else(invalid_runtime_parameter)?);
        },
        TypedArgumentMapping::Literal { arguments: literal } => {
            arguments.extend(literal.iter().cloned());
        },
        TypedArgumentMapping::SplitPositional {
            max_items,
            max_item_bytes,
            ..
        } => {
            let source = value.as_str().ok_or_else(invalid_runtime_parameter)?;
            let split = split_inert_words(source)?;
            let maximum_items = usize::try_from(*max_items).map_err(|_| invocation_too_large())?;
            let maximum_item_bytes =
                usize::try_from(*max_item_bytes).map_err(|_| invocation_too_large())?;
            if split.len() > maximum_items
                || split.iter().any(|item| item.len() > maximum_item_bytes)
            {
                return Err(invocation_too_large());
            }
            arguments.extend(split);
        },
        TypedArgumentMapping::RuntimeControl { .. } => {
            return Err(invalid_runtime_parameter());
        },
    }
    Ok(())
}

/// Split shell-like quoting into inert argv only. The scanner is iterative and
/// deliberately implements no shell evaluation semantics.
fn split_inert_words(source: &str) -> Result<Vec<String>, TypedActionInvocationError> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut characters = source.chars().peekable();
    let mut in_word = false;
    while let Some(character) = characters.next() {
        match character {
            ' ' | '\t' | '\n' if !in_word || current.is_empty() => {
                if in_word {
                    words.push(std::mem::take(&mut current));
                    in_word = false;
                }
            },
            ' ' | '\t' | '\n' => {
                words.push(std::mem::take(&mut current));
                in_word = false;
            },
            '\'' => {
                in_word = true;
                loop {
                    match characters.next() {
                        Some('\'') => break,
                        Some(value) => current.push(value),
                        None => return Err(invalid_runtime_parameter()),
                    }
                }
            },
            '"' => {
                in_word = true;
                loop {
                    match characters.next() {
                        Some('"') => break,
                        Some('\\') => match characters.next() {
                            Some('"') => current.push('"'),
                            Some('\\') => current.push('\\'),
                            Some(value) => {
                                current.push('\\');
                                current.push(value);
                            },
                            None => current.push('\\'),
                        },
                        Some(value) => current.push(value),
                        None => return Err(invalid_runtime_parameter()),
                    }
                }
            },
            value => {
                in_word = true;
                current.push(value);
            },
        }
    }
    if in_word {
        words.push(current);
    }
    Ok(words)
}

fn scalar_argument(value: &Value) -> Result<String, TypedActionInvocationError> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        _ => Err(invalid_runtime_parameter()),
    }
}

fn validate_lowered_arguments(
    arguments: &[String],
    limits: SynthesizedArgumentLimits,
) -> Result<(), TypedActionInvocationError> {
    let mut bytes = 0usize;
    if arguments.len() > limits.max_items {
        return Err(invocation_too_large());
    }
    for argument in arguments {
        bytes = bytes
            .checked_add(argument.len())
            .ok_or_else(invocation_too_large)?;
        if argument.len() > limits.max_item_bytes
            || bytes > limits.max_combined_bytes
            || (limits.reject_control_characters && argument.chars().any(char::is_control))
        {
            return Err(invocation_too_large());
        }
    }
    Ok(())
}

fn lower_optional_control<'a, T>(
    object: &'a Map<String, Value>,
    name: &str,
    parse: impl FnOnce(&'a Value) -> Option<T>,
) -> Result<Option<T>, TypedActionInvocationError> {
    object
        .get(name)
        .map(|value| parse(value).ok_or_else(invalid_runtime_parameter))
        .transpose()
}

const fn invalid_invocation_input() -> TypedActionInvocationError {
    TypedActionInvocationError::new(
        TypedActionInvocationErrorCode::InvalidInput,
        "input",
        "the invocation input does not match the compiled action contract",
    )
}

const fn invalid_runtime_parameter() -> TypedActionInvocationError {
    TypedActionInvocationError::new(
        TypedActionInvocationErrorCode::InvalidParameter,
        "input",
        "an invocation parameter does not match its bounded typed contract",
    )
}

const fn invocation_too_large() -> TypedActionInvocationError {
    TypedActionInvocationError::new(
        TypedActionInvocationErrorCode::InvocationTooLarge,
        "input",
        "the lowered invocation exceeds its bounded argument limits",
    )
}

#[derive(Debug, Clone)]
struct BaseRuntimeControls {
    properties: Map<String, Value>,
    required: BTreeSet<String>,
}

fn base_runtime_controls(
    action: &crate::manifest_synthesis::SynthesizedActionDefinition,
) -> Result<BaseRuntimeControls, ActionOverrideError> {
    let value = serde_json::to_value(&action.input_schema).map_err(|_| {
        ActionOverrideError::new(
            ActionOverrideErrorCode::BaseContractInvariantViolation,
            "runtime.action.input_schema",
            "the validated base schema could not be projected",
        )
    })?;
    let mut properties = value
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| {
            ActionOverrideError::new(
                ActionOverrideErrorCode::BaseContractInvariantViolation,
                "runtime.action.input_schema",
                "the validated base schema has no property map",
            )
        })?;
    if properties.remove("args").is_none() {
        return Err(ActionOverrideError::new(
            ActionOverrideErrorCode::BaseContractInvariantViolation,
            "runtime.action.input_schema",
            "the validated base schema lost its generic argument control",
        ));
    }
    let required = action
        .input_schema
        .required
        .iter()
        .filter(|name| name.as_str() != "args")
        .cloned()
        .collect();
    Ok(BaseRuntimeControls {
        properties,
        required,
    })
}

fn lower_timeout_ceiling(
    properties: &mut Map<String, Value>,
    timeout: u32,
) -> Result<(), ActionOverrideError> {
    let maximum = properties
        .get_mut("timeout_secs")
        .and_then(Value::as_object_mut)
        .and_then(|schema| schema.get_mut("maximum"))
        .ok_or_else(|| {
            ActionOverrideError::new(
                ActionOverrideErrorCode::BaseContractInvariantViolation,
                "runtime.action.input_schema.timeout_secs",
                "the validated base schema lost its timeout ceiling",
            )
        })?;
    *maximum = Value::from(timeout);
    Ok(())
}

fn validate_action_id(action_id: &str, skill_id: &str) -> Result<(), ActionOverrideError> {
    if !portable_model_id(action_id, MAX_TYPED_ACTION_ID_BYTES) {
        return Err(ActionOverrideError::new(
            ActionOverrideErrorCode::InvalidAction,
            "actions",
            "action identifiers must be bounded portable names",
        ));
    }
    let name_len = skill_id
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(action_id.len()))
        .ok_or_else(|| {
            ActionOverrideError::new(
                ActionOverrideErrorCode::InvalidAction,
                "actions",
                "the compiled action name overflowed its size limit",
            )
        })?;
    if name_len > MAX_SYNTHESIZED_TOOL_NAME_BYTES {
        return Err(ActionOverrideError::new(
            ActionOverrideErrorCode::InvalidAction,
            "actions",
            "the compiled action name exceeds its size limit",
        ));
    }
    Ok(())
}

fn action_name(skill_id: &str, action_id: &str) -> Result<String, ActionOverrideError> {
    validate_action_id(action_id, skill_id)?;
    let mut name = String::with_capacity(skill_id.len() + action_id.len() + 1);
    name.push_str(skill_id);
    name.push('.');
    name.push_str(action_id);
    Ok(name)
}

fn validate_parameter_id(parameter: &str) -> Result<(), ActionOverrideError> {
    if !portable_model_id(parameter, MAX_TYPED_PARAMETER_ID_BYTES)
        || RESERVED_RUNTIME_PARAMETERS.contains(&parameter)
    {
        return Err(ActionOverrideError::new(
            ActionOverrideErrorCode::InvalidParameter,
            "actions.parameters",
            "parameter identifiers must be bounded, portable, and nonreserved",
        ));
    }
    Ok(())
}

fn portable_model_id(value: &str, max_bytes: usize) -> bool {
    value.len() <= max_bytes
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && is_identifier(value)
}

fn validate_description(description: &str, field: &'static str) -> Result<(), ActionOverrideError> {
    if description.is_empty()
        || description.len() > MAX_TYPED_DESCRIPTION_BYTES
        || description
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(ActionOverrideError::new(
            ActionOverrideErrorCode::InvalidDescription,
            field,
            "descriptions must be nonempty, bounded, and free of unsafe controls",
        ));
    }
    Ok(())
}

fn validate_action_prefix(
    execution: &SynthesizedCliExecution,
    executable: &str,
    fixed_args: &[String],
) -> Result<(), ActionOverrideError> {
    let total_items = execution
        .command_prefix
        .len()
        .checked_add(fixed_args.len())
        .ok_or_else(invalid_fixed_args)?;
    if total_items > MAX_FIXED_ARGUMENTS {
        return Err(invalid_fixed_args());
    }
    let mut combined = Vec::with_capacity(total_items);
    combined.extend(execution.command_prefix.iter().cloned());
    combined.extend(fixed_args.iter().cloned());
    validate_fixed_arguments(&combined, "actions.fixed_args").map_err(|_| invalid_fixed_args())?;
    reject_inline_code_prefix(executable, &combined, "actions.fixed_args")
        .map_err(|_| invalid_fixed_args())
}

fn validate_action_suffix(
    execution: &SynthesizedCliExecution,
    executable: &str,
    fixed_args: &[String],
    suffix_args: &[String],
) -> Result<(), ActionOverrideError> {
    if suffix_args.is_empty() {
        return Ok(());
    }
    // A suffix is never allowed to become the command's effective namespace;
    // it may only refine an already-fixed action path.
    if fixed_args.is_empty() {
        return Err(invalid_fixed_args());
    }
    let total_items = execution
        .command_prefix
        .len()
        .checked_add(fixed_args.len())
        .and_then(|count| count.checked_add(suffix_args.len()))
        .ok_or_else(invalid_fixed_args)?;
    if total_items > MAX_FIXED_ARGUMENTS {
        return Err(invalid_fixed_args());
    }
    let mut combined = Vec::with_capacity(total_items);
    combined.extend(execution.command_prefix.iter().cloned());
    combined.extend(fixed_args.iter().cloned());
    combined.extend(suffix_args.iter().cloned());
    validate_fixed_arguments(&combined, "actions.suffix_args").map_err(|_| invalid_fixed_args())?;
    reject_inline_code_prefix(executable, &combined, "actions.suffix_args")
        .map_err(|_| invalid_fixed_args())
}

fn refine_action_stdin(
    base: crate::manifest::StdinMode,
    refinement: TypedActionStdin,
    properties: &mut Map<String, Value>,
    required: &mut BTreeSet<String>,
) -> Result<(), ActionOverrideError> {
    use crate::manifest::StdinMode;

    match refinement {
        TypedActionStdin::Inherit => Ok(()),
        TypedActionStdin::Denied => {
            properties.remove("stdin");
            required.remove("stdin");
            Ok(())
        },
        TypedActionStdin::Optional | TypedActionStdin::Required => {
            if base == StdinMode::Denied || !properties.contains_key("stdin") {
                return Err(ActionOverrideError::new(
                    ActionOverrideErrorCode::InvalidParameter,
                    "actions.stdin",
                    "an action cannot create stdin authority absent from the base runtime",
                ));
            }
            if refinement == TypedActionStdin::Required {
                required.insert("stdin".to_owned());
            } else {
                required.remove("stdin");
            }
            Ok(())
        },
    }
}

fn validate_auth_path_separation(
    execution: &SynthesizedCliExecution,
    action_executable: &str,
    fixed_args: &[String],
    route: TypedActionRoute,
    lifecycle: &AuthLifecycle,
) -> Result<(), ActionOverrideError> {
    if action_executable != execution.executable {
        return if matches!(route, TypedActionRoute::Execute) {
            Ok(())
        } else {
            Err(ActionOverrideError::new(
                ActionOverrideErrorCode::AuthPathConflict,
                "actions.executable",
                "Auth Broker lifecycle routes must use the package entrypoint",
            ))
        };
    }
    let mut action_prefix = Vec::with_capacity(execution.command_prefix.len() + fixed_args.len());
    action_prefix.extend(execution.command_prefix.iter().map(String::as_str));
    action_prefix.extend(fixed_args.iter().map(String::as_str));

    let routed_hook = match route {
        TypedActionRoute::Execute => None,
        TypedActionRoute::AuthStatus => lifecycle.status.as_ref(),
        TypedActionRoute::AuthLogin => lifecycle.login.as_ref(),
    };
    if !matches!(route, TypedActionRoute::Execute) {
        let Some(hook) = routed_hook else {
            return Err(ActionOverrideError::new(
                ActionOverrideErrorCode::AuthPathConflict,
                "actions.route",
                "an auth action route requires its declared Auth Broker lifecycle hook",
            ));
        };
        let action = fixed_args.iter().map(String::as_str).collect::<Vec<_>>();
        let hook = hook.args.iter().map(String::as_str).collect::<Vec<_>>();
        if action.is_empty() || action.len() > hook.len() || action != hook[..action.len()] {
            return Err(ActionOverrideError::new(
                ActionOverrideErrorCode::AuthPathConflict,
                "actions.fixed_args",
                "an auth action route must be a nonempty prefix of its Auth Broker lifecycle path",
            ));
        }
        return Ok(());
    }

    let conflicts = [
        lifecycle.status.as_ref(),
        lifecycle.login.as_ref(),
        lifecycle.logout.as_ref(),
        lifecycle.refresh.as_ref(),
    ]
    .into_iter()
    .flatten()
    .any(|hook| {
        let hook = hook.args.iter().map(String::as_str).collect::<Vec<_>>();
        prefixes_overlap(&action_prefix, &hook)
    });
    if conflicts {
        return Err(ActionOverrideError::new(
            ActionOverrideErrorCode::AuthPathConflict,
            "actions.fixed_args",
            "a model-facing action cannot overlap an Auth Broker lifecycle path",
        ));
    }
    Ok(())
}

fn prefixes_overlap(left: &[&str], right: &[&str]) -> bool {
    let common = left.len().min(right.len());
    left[..common] == right[..common]
}

const fn invalid_fixed_args() -> ActionOverrideError {
    ActionOverrideError::new(
        ActionOverrideErrorCode::InvalidFixedArguments,
        "actions.fixed_args",
        "fixed action arguments exceed limits or create an unsafe interpreter prefix",
    )
}

fn compile_parameter(
    parameter: &TypedActionParameter,
    maximum_parameter_bytes: u64,
) -> Result<(Value, ParameterShape), ActionOverrideError> {
    match parameter {
        TypedActionParameter::String {
            description,
            required,
            default,
            enum_values,
            min_length,
            max_length,
            ..
        } => {
            bounded_len(
                enum_values.len(),
                MAX_TYPED_ENUM_VALUES,
                "actions.parameters.enum_values",
            )?;
            let minimum = min_length.unwrap_or(0);
            let maximum = max_length.unwrap_or(maximum_parameter_bytes);
            if minimum > maximum || maximum > maximum_parameter_bytes {
                return Err(invalid_parameter_constraints());
            }
            let mut total_enum_bytes = 0usize;
            for value in enum_values {
                validate_bounded_string(value, minimum, maximum)?;
                total_enum_bytes = total_enum_bytes
                    .checked_add(value.len())
                    .ok_or_else(invalid_parameter_constraints)?;
                if total_enum_bytes > MAX_FIXED_ARGUMENT_BYTES {
                    return Err(invalid_parameter_constraints());
                }
            }
            if let Some(default) = default {
                validate_bounded_string(default, minimum, maximum)?;
                if !enum_values.is_empty()
                    && !enum_values.contains(default)
                    && !(!required && default.is_empty())
                {
                    return Err(invalid_parameter_constraints());
                }
            }
            let mut schema = property_schema("string", description);
            insert(&mut schema, "minLength", minimum);
            insert(&mut schema, "maxLength", maximum);
            insert(&mut schema, "x-max-utf8-bytes", maximum);
            if !enum_values.is_empty() {
                insert(
                    &mut schema,
                    "enum",
                    enum_values.iter().cloned().collect::<Vec<_>>(),
                );
            }
            if let Some(default) = default {
                insert(&mut schema, "default", default.clone());
            }
            Ok((
                Value::Object(schema),
                ParameterShape::Scalar {
                    max_bytes: maximum as usize,
                },
            ))
        },
        TypedActionParameter::WorkspacePath {
            description,
            access,
            max_length,
            ..
        } => {
            let maximum = max_length.unwrap_or(maximum_parameter_bytes);
            if maximum == 0 || maximum > maximum_parameter_bytes {
                return Err(invalid_parameter_constraints());
            }
            let mut schema = property_schema("string", description);
            insert(&mut schema, "minLength", 1u64);
            insert(&mut schema, "maxLength", maximum);
            insert(&mut schema, "x-max-utf8-bytes", maximum);
            insert(&mut schema, "x-magician-workspace-path", true);
            insert(
                &mut schema,
                "x-magician-path-access",
                match access {
                    WorkspacePathAccess::ReadFile => "read_file",
                    WorkspacePathAccess::CreateFile => "create_file",
                    WorkspacePathAccess::CreateDirectory => "create_directory",
                },
            );
            Ok((
                Value::Object(schema),
                ParameterShape::Scalar {
                    max_bytes: maximum as usize,
                },
            ))
        },
        TypedActionParameter::Integer {
            description,
            default,
            enum_values,
            minimum,
            maximum,
            ..
        } => {
            bounded_len(
                enum_values.len(),
                MAX_TYPED_ENUM_VALUES,
                "actions.parameters.enum_values",
            )?;
            if (*minimum).zip(*maximum).is_some_and(|(min, max)| min > max)
                || (*default).is_some_and(|value| minimum.is_some_and(|min| value < min))
                || (*default).is_some_and(|value| maximum.is_some_and(|max| value > max))
                || (*default)
                    .is_some_and(|value| !enum_values.is_empty() && !enum_values.contains(&value))
                || enum_values.iter().any(|value| {
                    minimum.is_some_and(|minimum| value < &minimum)
                        || maximum.is_some_and(|maximum| value > &maximum)
                })
            {
                return Err(invalid_parameter_constraints());
            }
            let mut schema = property_schema("integer", description);
            if let Some(value) = minimum {
                insert(&mut schema, "minimum", *value);
            }
            if let Some(value) = maximum {
                insert(&mut schema, "maximum", *value);
            }
            if !enum_values.is_empty() {
                schema.insert(
                    "enum".to_owned(),
                    Value::Array(enum_values.iter().copied().map(Value::from).collect()),
                );
            }
            if let Some(value) = default {
                insert(&mut schema, "default", *value);
            }
            Ok((
                Value::Object(schema),
                ParameterShape::Scalar { max_bytes: 32 },
            ))
        },
        TypedActionParameter::Number {
            description,
            default,
            minimum,
            maximum,
            ..
        } => {
            let minimum_value = minimum.as_ref().and_then(Number::as_f64);
            let maximum_value = maximum.as_ref().and_then(Number::as_f64);
            let default_value = default.as_ref().and_then(Number::as_f64);
            if minimum_value
                .zip(maximum_value)
                .is_some_and(|(min, max)| min > max)
                || default_value
                    .zip(minimum_value)
                    .is_some_and(|(value, min)| value < min)
                || default_value
                    .zip(maximum_value)
                    .is_some_and(|(value, max)| value > max)
            {
                return Err(invalid_parameter_constraints());
            }
            let mut schema = property_schema("number", description);
            if let Some(value) = minimum {
                schema.insert("minimum".to_owned(), Value::Number(value.clone()));
            }
            if let Some(value) = maximum {
                schema.insert("maximum".to_owned(), Value::Number(value.clone()));
            }
            if let Some(value) = default {
                schema.insert("default".to_owned(), Value::Number(value.clone()));
            }
            Ok((
                Value::Object(schema),
                ParameterShape::Scalar { max_bytes: 64 },
            ))
        },
        TypedActionParameter::Boolean {
            description,
            default,
            ..
        } => {
            let mut schema = property_schema("boolean", description);
            if let Some(value) = default {
                insert(&mut schema, "default", *value);
            }
            Ok((Value::Object(schema), ParameterShape::Boolean))
        },
        TypedActionParameter::StringArray {
            description,
            min_items,
            max_items,
            max_item_bytes,
            ..
        } => {
            let minimum = min_items.unwrap_or(0);
            let maximum = max_items.unwrap_or(MAX_FIXED_ARGUMENTS as u64);
            let item_bytes = max_item_bytes.unwrap_or(MAX_ARGUMENT_BYTES as u64);
            if minimum > maximum
                || maximum > MAX_FIXED_ARGUMENTS as u64
                || item_bytes == 0
                || item_bytes > MAX_ARGUMENT_BYTES as u64
                || maximum.saturating_mul(item_bytes) > MAX_FIXED_ARGUMENT_BYTES as u64
            {
                return Err(invalid_parameter_constraints());
            }
            let mut items = Map::new();
            insert(&mut items, "type", "string");
            insert(&mut items, "maxLength", item_bytes);
            insert(&mut items, "x-max-utf8-bytes", item_bytes);
            insert(&mut items, "pattern", r"^[^\u0000-\u001F\u007F]*$");
            let mut schema = property_schema("array", description);
            schema.insert("items".to_owned(), Value::Object(items));
            insert(&mut schema, "minItems", minimum);
            insert(&mut schema, "maxItems", maximum);
            insert(
                &mut schema,
                "x-max-combined-utf8-bytes",
                maximum.saturating_mul(item_bytes),
            );
            Ok((
                Value::Object(schema),
                ParameterShape::StringArray {
                    max_items: maximum as usize,
                    max_item_bytes: item_bytes as usize,
                },
            ))
        },
        TypedActionParameter::JsonObject {
            description,
            max_json_bytes,
            max_depth,
            max_nodes,
            ..
        } => {
            let bytes = max_json_bytes.unwrap_or(maximum_parameter_bytes);
            let depth = max_depth.unwrap_or(MAX_TYPED_JSON_DEPTH as u64);
            let nodes = max_nodes.unwrap_or(MAX_TYPED_JSON_NODES as u64);
            if bytes == 0
                || bytes > maximum_parameter_bytes
                || depth == 0
                || depth > MAX_TYPED_JSON_DEPTH as u64
                || nodes == 0
                || nodes > MAX_TYPED_JSON_NODES as u64
            {
                return Err(invalid_parameter_constraints());
            }
            let mut schema = property_schema("object", description);
            insert(&mut schema, "additionalProperties", true);
            insert(&mut schema, "x-max-json-bytes", bytes);
            insert(&mut schema, "x-max-json-depth", depth);
            insert(&mut schema, "x-max-json-nodes", nodes);
            Ok((
                Value::Object(schema),
                ParameterShape::JsonObject {
                    max_bytes: bytes as usize,
                },
            ))
        },
        TypedActionParameter::JsonArray {
            description,
            max_json_bytes,
            max_depth,
            max_nodes,
            max_items,
            ..
        } => {
            let bytes = max_json_bytes.unwrap_or(maximum_parameter_bytes);
            let depth = max_depth.unwrap_or(MAX_TYPED_JSON_DEPTH as u64);
            let nodes = max_nodes.unwrap_or(MAX_TYPED_JSON_NODES as u64);
            let items = max_items.unwrap_or(MAX_FIXED_ARGUMENTS as u64);
            if bytes == 0
                || bytes > maximum_parameter_bytes
                || depth == 0
                || depth > MAX_TYPED_JSON_DEPTH as u64
                || nodes == 0
                || nodes > MAX_TYPED_JSON_NODES as u64
                || items > MAX_FIXED_ARGUMENTS as u64
            {
                return Err(invalid_parameter_constraints());
            }
            let mut schema = property_schema("array", description);
            insert(&mut schema, "maxItems", items);
            insert(&mut schema, "x-max-json-bytes", bytes);
            insert(&mut schema, "x-max-json-depth", depth);
            insert(&mut schema, "x-max-json-nodes", nodes);
            Ok((
                Value::Object(schema),
                ParameterShape::JsonArray {
                    max_bytes: bytes as usize,
                },
            ))
        },
    }
}

fn validate_bounded_string(
    value: &str,
    min_length: u64,
    max_length: u64,
) -> Result<(), ActionOverrideError> {
    let characters = value.chars().count() as u64;
    if characters < min_length
        || characters > max_length
        || value.len() > max_length as usize
        || value.chars().any(char::is_control)
    {
        return Err(invalid_parameter_constraints());
    }
    Ok(())
}

const fn invalid_parameter_constraints() -> ActionOverrideError {
    ActionOverrideError::new(
        ActionOverrideErrorCode::InvalidParameter,
        "actions.parameters",
        "parameter constraints or defaults are invalid or exceed runtime limits",
    )
}

fn validate_mappings(
    mappings: &[TypedArgumentMapping],
    parameters: &BTreeMap<String, ParameterShape>,
    limits: SynthesizedArgumentLimits,
) -> Result<(), ActionOverrideError> {
    if mappings.len() > MAX_TYPED_MAPPINGS {
        return Err(invalid_mapping());
    }
    let mut seen = BTreeSet::new();
    let mut projected_items = 0usize;
    let mut projected_bytes = 0usize;
    for mapping in mappings {
        let Some(parameter) = mapping.parameter() else {
            let TypedArgumentMapping::Literal { arguments } = mapping else {
                return Err(invalid_mapping());
            };
            validate_fixed_arguments(arguments, "actions.mappings.literal")
                .map_err(|_| invalid_mapping())?;
            projected_items = projected_items
                .checked_add(arguments.len())
                .ok_or_else(projected_invocation_too_large)?;
            projected_bytes = projected_bytes
                .checked_add(arguments.iter().map(String::len).sum())
                .ok_or_else(projected_invocation_too_large)?;
            if projected_items > limits.max_items || projected_bytes > limits.max_combined_bytes {
                return Err(projected_invocation_too_large());
            }
            continue;
        };
        if !seen.insert(parameter) {
            return Err(invalid_mapping());
        }
        let Some(shape) = parameters.get(parameter) else {
            return Err(invalid_mapping());
        };
        if let Some(flag) = mapping.flag() {
            validate_flag(flag)?;
        }
        let (items, bytes) = mapping_projection(mapping, *shape)?;
        projected_items = projected_items
            .checked_add(items)
            .ok_or_else(projected_invocation_too_large)?;
        projected_bytes = projected_bytes
            .checked_add(bytes)
            .ok_or_else(projected_invocation_too_large)?;
        if projected_items > limits.max_items || projected_bytes > limits.max_combined_bytes {
            return Err(projected_invocation_too_large());
        }
    }
    if seen.len() != parameters.len() {
        return Err(invalid_mapping());
    }
    Ok(())
}

fn mapping_projection(
    mapping: &TypedArgumentMapping,
    shape: ParameterShape,
) -> Result<(usize, usize), ActionOverrideError> {
    let flag_bytes = mapping.flag().map(str::len).unwrap_or(0);
    match (mapping, shape) {
        (TypedArgumentMapping::Positional { .. }, ParameterShape::Scalar { max_bytes }) => {
            Ok((1, max_bytes))
        },
        (TypedArgumentMapping::Flag { .. }, ParameterShape::Scalar { max_bytes }) => {
            Ok((2, flag_bytes.saturating_add(max_bytes)))
        },
        (TypedArgumentMapping::Flag { .. }, ParameterShape::Boolean) => {
            Ok((2, flag_bytes.saturating_add(5)))
        },
        (TypedArgumentMapping::BoolFlag { .. }, ParameterShape::Boolean) => Ok((1, flag_bytes)),
        (
            TypedArgumentMapping::RepeatedFlag { .. },
            ParameterShape::StringArray {
                max_items,
                max_item_bytes,
            },
        ) => Ok((
            max_items.saturating_mul(2),
            max_items.saturating_mul(flag_bytes.saturating_add(max_item_bytes)),
        )),
        (
            TypedArgumentMapping::Passthrough { .. },
            ParameterShape::StringArray {
                max_items,
                max_item_bytes,
            },
        ) => Ok((max_items, max_items.saturating_mul(max_item_bytes))),
        (TypedArgumentMapping::JsonFlag { .. }, ParameterShape::JsonObject { max_bytes }) => {
            Ok((2, flag_bytes.saturating_add(max_bytes)))
        },
        (TypedArgumentMapping::JsonFlag { .. }, ParameterShape::JsonArray { max_bytes }) => {
            Ok((2, flag_bytes.saturating_add(max_bytes)))
        },
        (
            TypedArgumentMapping::SplitPositional {
                max_items,
                max_item_bytes,
                ..
            },
            ParameterShape::Scalar { max_bytes },
        ) => {
            let max_items = usize::try_from(*max_items).map_err(|_| invalid_mapping())?;
            let max_item_bytes = usize::try_from(*max_item_bytes).map_err(|_| invalid_mapping())?;
            if max_items == 0 || max_item_bytes == 0 || max_item_bytes > MAX_ARGUMENT_BYTES {
                return Err(invalid_mapping());
            }
            Ok((
                max_items,
                max_bytes.min(max_items.saturating_mul(max_item_bytes)),
            ))
        },
        (TypedArgumentMapping::Literal { .. }, _) => Err(invalid_mapping()),
        (TypedArgumentMapping::RuntimeControl { .. }, _) => Ok((0, 0)),
        _ => Err(invalid_mapping()),
    }
}

fn validate_flag(flag: &str) -> Result<(), ActionOverrideError> {
    if flag.len() > MAX_ARGUMENT_BYTES
        || matches!(flag, "" | "-" | "--")
        || !flag.starts_with('-')
        || flag.chars().any(char::is_control)
    {
        return Err(invalid_mapping());
    }
    Ok(())
}

const fn invalid_mapping() -> ActionOverrideError {
    ActionOverrideError::new(
        ActionOverrideErrorCode::InvalidMapping,
        "actions.mappings",
        "every parameter must have exactly one compatible bounded argv mapping",
    )
}

const fn invalid_argument_rules() -> ActionOverrideError {
    ActionOverrideError::new(
        ActionOverrideErrorCode::InvalidArgumentRules,
        "actions.argument_rules",
        "argument rules must be finite, unambiguous, and contain valid inert tokens",
    )
}

const fn projected_invocation_too_large() -> ActionOverrideError {
    ActionOverrideError::new(
        ActionOverrideErrorCode::ProjectedInvocationTooLarge,
        "actions.mappings",
        "the maximum mapped invocation exceeds the base argument ceiling",
    )
}

fn compose_policy(
    base: &SynthesizedSecurityFloor,
    refinement: &ActionPolicyRefinement,
) -> Result<EffectiveActionPolicy, ActionOverrideError> {
    bounded_len(
        refinement.additional_required_grants.len(),
        MAX_POLICY_ENTRIES,
        "actions.policy.additional_required_grants",
    )?;
    bounded_len(
        refinement.additional_resource_scopes.len(),
        MAX_POLICY_ENTRIES,
        "actions.policy.additional_resource_scopes",
    )?;
    bounded_len(
        refinement.additional_required_resource_authorities.len(),
        MAX_POLICY_ENTRIES,
        "actions.policy.additional_required_resource_authorities",
    )?;
    for reference in refinement
        .additional_required_grants
        .iter()
        .chain(refinement.additional_resource_scopes.iter())
        .chain(refinement.additional_required_resource_authorities.iter())
    {
        if !is_reference(reference) {
            return Err(ActionOverrideError::new(
                ActionOverrideErrorCode::InvalidPolicyRefinement,
                "actions.policy",
                "policy additions must be portable reference identifiers",
            ));
        }
    }

    let mut required_approvals = BTreeSet::from([base.policy.approval]);
    required_approvals.extend(refinement.additional_approvals.iter().copied());
    let required_grants = union_bounded(
        &base.policy.required_grants,
        &refinement.additional_required_grants,
    )?;
    let resource_scopes = union_bounded(
        &base.policy.resource_scopes,
        &refinement.additional_resource_scopes,
    )?;
    let required_resource_authorities = union_bounded(
        &base.policy.required_resource_authorities,
        &refinement.additional_required_resource_authorities,
    )?;
    Ok(EffectiveActionPolicy {
        required_approvals,
        required_grants,
        resource_scopes,
        required_resource_authorities,
    })
}

fn union_bounded(
    base: &BTreeSet<String>,
    additions: &BTreeSet<String>,
) -> Result<BTreeSet<String>, ActionOverrideError> {
    let mut effective = base.clone();
    effective.extend(additions.iter().cloned());
    if effective.len() > MAX_POLICY_ENTRIES {
        return Err(ActionOverrideError::new(
            ActionOverrideErrorCode::InvalidPolicyRefinement,
            "actions.policy",
            "the effective policy exceeds its bounded entry limit",
        ));
    }
    Ok(effective)
}

fn object_schema(properties: Map<String, Value>, required: BTreeSet<String>) -> Value {
    let mut schema = Map::new();
    insert(&mut schema, "type", "object");
    schema.insert("properties".to_owned(), Value::Object(properties));
    insert(
        &mut schema,
        "required",
        required.into_iter().collect::<Vec<_>>(),
    );
    insert(&mut schema, "additionalProperties", false);
    Value::Object(schema)
}

fn property_schema(schema_type: &'static str, description: &str) -> Map<String, Value> {
    let mut schema = Map::new();
    insert(&mut schema, "type", schema_type);
    insert(&mut schema, "description", description);
    schema
}

trait IntoSchemaValue {
    fn into_schema_value(self) -> Value;
}

impl IntoSchemaValue for &str {
    fn into_schema_value(self) -> Value {
        Value::String(self.to_owned())
    }
}

impl IntoSchemaValue for String {
    fn into_schema_value(self) -> Value {
        Value::String(self)
    }
}

impl IntoSchemaValue for bool {
    fn into_schema_value(self) -> Value {
        Value::Bool(self)
    }
}

impl IntoSchemaValue for u32 {
    fn into_schema_value(self) -> Value {
        Value::from(self)
    }
}

impl IntoSchemaValue for u64 {
    fn into_schema_value(self) -> Value {
        Value::from(self)
    }
}

impl IntoSchemaValue for i64 {
    fn into_schema_value(self) -> Value {
        Value::from(self)
    }
}

impl IntoSchemaValue for Vec<String> {
    fn into_schema_value(self) -> Value {
        Value::Array(self.into_iter().map(Value::String).collect())
    }
}

fn insert<T: IntoSchemaValue>(map: &mut Map<String, Value>, key: &'static str, value: T) {
    map.insert(key.to_owned(), value.into_schema_value());
}

fn bounded_len(
    actual: usize,
    maximum: usize,
    field: &'static str,
) -> Result<(), ActionOverrideError> {
    if actual > maximum {
        return Err(ActionOverrideError::new(
            ActionOverrideErrorCode::CollectionTooLarge,
            field,
            "the typed override exceeds its collection safety limit",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, thread};

    use super::*;
    use crate::{
        manifest::{
            AuthContract, AuthKind, AuthRequirement, AuthStorage, CliInteraction, DataSensitivity,
            LifecycleHook, McpDiscoveryPolicy, McpTransport, PolicyFloor, ProfileSelection,
            RuntimeLimits, RuntimeProtocol, RuntimeRequirements, SkillRuntimeContract,
            SkillRuntimeContractVersion, StdinContract, StdinMode, WorkingDirectoryContract,
            WorkingDirectoryMode,
        },
        manifest_validation::{validate_skill_runtime_contract, ManifestValidationErrorCode},
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

    fn action(description: &str) -> TypedActionOverride {
        TypedActionOverride {
            description: description.to_owned(),
            executable: None,
            route: TypedActionRoute::Execute,
            fixed_args: Vec::new(),
            suffix_args: Vec::new(),
            stdin: TypedActionStdin::Inherit,
            parameters: BTreeMap::new(),
            mappings: Vec::new(),
            argument_rules: TypedArgumentRules::default(),
            timeout_secs: None,
            policy: ActionPolicyRefinement::default(),
        }
    }

    fn override_set(action_id: &str, action: TypedActionOverride) -> TypedActionOverrideSet {
        TypedActionOverrideSet {
            schema_version: TYPED_ACTION_OVERRIDES_V1.to_owned(),
            input_delivery: TypedActionInputDelivery::Argv,
            actions: BTreeMap::from([(action_id.to_owned(), action)]),
        }
    }

    #[test]
    fn omitted_action_stdin_preserves_the_manifest_owned_lane() {
        let parsed: TypedActionOverrideSet = serde_yaml::from_str(
            r#"
schema_version: tool-runtime.typed-action-overrides.v1
actions:
  inspect:
    description: Inspect with the base runtime contract.
"#,
        )
        .expect("parse typed action without an authored stdin refinement");

        assert_eq!(parsed.actions["inspect"].stdin, TypedActionStdin::Inherit);
    }

    fn string_parameter(description: &str, required: bool) -> TypedActionParameter {
        TypedActionParameter::String {
            description: description.to_owned(),
            required,
            default: None,
            enum_values: BTreeSet::new(),
            min_length: None,
            max_length: Some(256),
        }
    }

    fn compile(
        skill_id: &str,
        contract: &SkillRuntimeContract,
        overrides: &TypedActionOverrideSet,
    ) -> Result<CompiledActionCatalog, ActionOverrideError> {
        let validated = validate_skill_runtime_contract(contract).expect("valid base contract");
        compile_typed_action_overrides(skill_id, validated, overrides)
    }

    #[test]
    fn typed_shape_replaces_raw_args_but_preserves_runtime_and_security_controls() {
        let mut contract = cli_contract("gws");
        contract.auth.kind = AuthKind::CliProfile;
        contract.auth.requirement = AuthRequirement::Required;
        contract.auth.provider = Some("google-workspace".to_owned());
        contract.auth.profile_selection = ProfileSelection::Selectable { default: None };
        contract.auth.storage = AuthStorage::ScopedDirectory {
            namespace: "gws".to_owned(),
            partition_by_profile: true,
        };
        contract.policy_floor.approval = ApprovalClass::ConditionalExternalSideEffect;
        contract
            .policy_floor
            .required_grants
            .insert("mail/read".to_owned());
        contract
            .policy_floor
            .resource_scopes
            .insert("workspace/default".to_owned());
        contract
            .policy_floor
            .required_resource_authorities
            .insert("mail/daily-budget".to_owned());
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
        limits.stdin_bytes = Some(2048);
        limits.timeout_secs = Some(90);

        let mut send = action("Send a typed message.");
        send.fixed_args = vec!["gmail".to_owned(), "+send".to_owned()];
        send.parameters
            .insert("body".to_owned(), string_parameter("Message body.", true));
        send.parameters.insert(
            "dry_run".to_owned(),
            TypedActionParameter::Boolean {
                description: "Validate without sending.".to_owned(),
                required: false,
                default: Some(false),
            },
        );
        send.mappings = vec![
            TypedArgumentMapping::Flag {
                flag: "--body".to_owned(),
                parameter: "body".to_owned(),
                omit_if_empty: false,
            },
            TypedArgumentMapping::BoolFlag {
                flag: "--dry-run".to_owned(),
                parameter: "dry_run".to_owned(),
            },
        ];
        send.timeout_secs = Some(30);
        send.policy
            .additional_approvals
            .insert(ApprovalClass::DelegatedWorkspaceWrite);
        send.policy
            .additional_required_grants
            .insert("mail/write".to_owned());
        send.policy
            .additional_resource_scopes
            .insert("mail/outbox".to_owned());
        send.policy
            .additional_required_resource_authorities
            .insert("mail/send-budget".to_owned());

        let catalog =
            compile("gws", &contract, &override_set("send", send)).expect("compile typed action");
        let compiled = catalog.actions.get("send").expect("send action");
        let properties = compiled.definition.input_schema["properties"]
            .as_object()
            .expect("properties");
        assert_eq!(compiled.definition.name, "gws.send");
        assert!(!properties.contains_key("args"));
        for expected in [
            "body",
            "dry_run",
            "profile",
            "stdin",
            "working_dir",
            "timeout_secs",
        ] {
            assert!(properties.contains_key(expected), "missing {expected}");
        }
        assert_eq!(properties["timeout_secs"]["maximum"], 30);
        assert_eq!(
            compiled.definition.input_schema["required"],
            serde_json::json!(["body", "profile", "stdin"])
        );
        assert_eq!(catalog.execution.executable, "gws");
        assert_eq!(catalog.security_floor.auth_kind, AuthKind::CliProfile);
        assert_eq!(
            catalog.security_floor.auth_requirement,
            AuthRequirement::Required
        );
        assert_eq!(
            catalog.security_floor.profile_selection,
            ProfileSelection::Selectable { default: None }
        );
        assert_eq!(
            compiled.effective_policy.required_approvals,
            BTreeSet::from([
                ApprovalClass::ConditionalExternalSideEffect,
                ApprovalClass::DelegatedWorkspaceWrite,
            ])
        );
        assert_eq!(
            compiled.effective_policy.required_grants,
            BTreeSet::from(["mail/read".to_owned(), "mail/write".to_owned()])
        );
        assert_eq!(
            compiled.effective_policy.resource_scopes,
            BTreeSet::from(["mail/outbox".to_owned(), "workspace/default".to_owned(),])
        );
        assert_eq!(
            compiled.effective_policy.required_resource_authorities,
            BTreeSet::from([
                "mail/daily-budget".to_owned(),
                "mail/send-budget".to_owned(),
            ])
        );
    }

    #[test]
    fn weakening_fields_are_structurally_unrepresentable_and_reserved_controls_fail_closed() {
        let auth_replacement = format!(
            r#"{{"schema_version":"{TYPED_ACTION_OVERRIDES_V1}","actions":{{"run":{{"description":"run","auth_requirement":"none"}}}}}}"#
        );
        assert!(serde_json::from_str::<TypedActionOverrideSet>(&auth_replacement).is_err());
        let policy_replacement = format!(
            r#"{{"schema_version":"{TYPED_ACTION_OVERRIDES_V1}","actions":{{"run":{{"description":"run","policy":{{"approval":"ordinary"}}}}}}}}"#
        );
        assert!(serde_json::from_str::<TypedActionOverrideSet>(&policy_replacement).is_err());

        let mut run = action("Run safely.");
        run.parameters.insert(
            "profile".to_owned(),
            string_parameter("Attempted profile replacement.", false),
        );
        run.mappings.push(TypedArgumentMapping::Positional {
            parameter: "profile".to_owned(),
        });
        let error = compile("demo", &cli_contract("demo"), &override_set("run", run))
            .expect_err("reserved parameter must fail");
        assert_eq!(error.code, ActionOverrideErrorCode::InvalidParameter);
    }

    #[test]
    fn timeout_override_can_only_lower_the_manifest_ceiling() {
        let mut contract = cli_contract("demo");
        let RuntimeProtocol::Cli { limits, .. } = &mut contract.runtime else {
            unreachable!();
        };
        limits.timeout_secs = Some(40);
        let mut lower = action("Lower timeout.");
        lower.timeout_secs = Some(15);
        let catalog =
            compile("demo", &contract, &override_set("lower", lower)).expect("lower timeout");
        assert_eq!(catalog.actions["lower"].invocation.timeout_ceiling_secs, 15);

        let mut higher = action("Raise timeout.");
        higher.timeout_secs = Some(41);
        let error = compile("demo", &contract, &override_set("higher", higher))
            .expect_err("higher timeout must fail");
        assert_eq!(error.code, ActionOverrideErrorCode::InvalidTimeout);
    }

    #[test]
    fn mcp_contracts_reject_typed_action_overrides_before_discovery() {
        let contract = SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires: RuntimeRequirements::default(),
            runtime: RuntimeProtocol::Mcp {
                transport: McpTransport::StreamableHttp {
                    endpoint: "https://provider.example/mcp".to_owned(),
                },
                discovery: McpDiscoveryPolicy::default(),
                limits: RuntimeLimits::default(),
            },
            auth: AuthContract::default(),
            policy_floor: PolicyFloor::default(),
        };
        let error = compile(
            "provider",
            &contract,
            &override_set("invented", action("Must not invent MCP tools.")),
        )
        .expect_err("MCP override must fail");
        assert_eq!(error.code, ActionOverrideErrorCode::UnsupportedRuntime);
    }

    #[test]
    fn fixed_action_args_are_revalidated_without_echoing_authored_values() {
        let contract = cli_contract("provider-cli");
        let mut unsafe_action = action("Unsafe fixed argument attempt.");
        unsafe_action.fixed_args = vec!["SECRET_SOURCE_CANARY\n".to_owned()];
        let error = compile("shell", &contract, &override_set("run", unsafe_action))
            .expect_err("inline interpreter source must fail");
        assert_eq!(error.code, ActionOverrideErrorCode::InvalidFixedArguments);
        assert!(!error.to_string().contains("SECRET_SOURCE_CANARY"));
    }

    #[test]
    fn model_facing_actions_cannot_overlap_auth_lifecycle_paths() {
        let mut contract = cli_contract("gws");
        contract.auth.kind = AuthKind::CliProfile;
        contract.auth.requirement = AuthRequirement::Required;
        contract.auth.provider = Some("google-workspace".to_owned());
        contract.auth.profile_selection = ProfileSelection::Implicit;
        contract.auth.storage = AuthStorage::CliOwned;
        contract.auth.lifecycle.login = Some(LifecycleHook {
            args: vec!["auth".to_owned(), "login".to_owned()],
            interaction: CliInteraction::Pty,
            timeout_secs: Some(120),
        });

        let mut conflicting = action("Conflicting auth path.");
        conflicting.fixed_args = vec!["auth".to_owned()];
        let error = compile("gws", &contract, &override_set("conflict", conflicting))
            .expect_err("auth lifecycle overlap must fail");
        assert_eq!(error.code, ActionOverrideErrorCode::AuthPathConflict);

        let mut routed = action("Run the declared login lifecycle.");
        routed.fixed_args = vec!["auth".to_owned(), "login".to_owned()];
        routed.route = TypedActionRoute::AuthLogin;
        let catalog = compile("gws", &contract, &override_set("auth_login", routed))
            .expect("an exact explicit lifecycle route must compile");
        assert_eq!(
            catalog.actions["auth_login"].invocation.route,
            TypedActionRoute::AuthLogin
        );

        let mut safe = action("Read mail.");
        safe.fixed_args = vec!["gmail".to_owned(), "list".to_owned()];
        compile("gws", &contract, &override_set("read", safe))
            .expect("disjoint action path is safe");
    }

    #[test]
    fn explicit_args_parameter_restores_a_bounded_passthrough_escape_hatch() {
        let mut run = action("Run exact bounded argv.");
        run.parameters.insert(
            "args".to_owned(),
            TypedActionParameter::StringArray {
                description: "Exact argv tokens.".to_owned(),
                required: true,
                min_items: Some(1),
                max_items: Some(8),
                max_item_bytes: Some(64),
            },
        );
        run.mappings.push(TypedArgumentMapping::Passthrough {
            parameter: "args".to_owned(),
        });
        let catalog = compile("demo", &cli_contract("demo"), &override_set("run", run))
            .expect("explicit args parameter must compile");
        assert_eq!(
            catalog.actions["run"].definition.input_schema["required"],
            serde_json::json!(["args"])
        );
    }

    #[test]
    fn every_parameter_requires_one_compatible_mapping() {
        let mut unmapped = action("Unmapped parameter.");
        unmapped
            .parameters
            .insert("query".to_owned(), string_parameter("Query.", false));
        let error = compile(
            "demo",
            &cli_contract("demo"),
            &override_set("unmapped", unmapped),
        )
        .expect_err("unmapped parameter must fail");
        assert_eq!(error.code, ActionOverrideErrorCode::InvalidMapping);

        let mut incompatible = action("Incompatible mapping.");
        incompatible.parameters.insert(
            "enabled".to_owned(),
            TypedActionParameter::Boolean {
                description: "Enable.".to_owned(),
                required: false,
                default: None,
            },
        );
        incompatible
            .mappings
            .push(TypedArgumentMapping::RepeatedFlag {
                flag: "--enabled".to_owned(),
                parameter: "enabled".to_owned(),
            });
        let error = compile(
            "demo",
            &cli_contract("demo"),
            &override_set("incompatible", incompatible),
        )
        .expect_err("incompatible mapping must fail");
        assert_eq!(error.code, ActionOverrideErrorCode::InvalidMapping);
    }

    #[test]
    fn literal_mapping_preserves_the_action_override_error_boundary() {
        let mut invalid = action("Reject a non-inert literal.");
        invalid.mappings.push(TypedArgumentMapping::Literal {
            arguments: vec!["unsafe\nargument".to_owned()],
        });

        let error = compile(
            "demo",
            &cli_contract("demo"),
            &override_set("invalid_literal", invalid),
        )
        .expect_err("a control-bearing literal must fail through the override boundary");

        assert_eq!(error.code, ActionOverrideErrorCode::InvalidMapping);
        assert_eq!(error.field, "actions.mappings");
    }

    #[test]
    fn declarative_argument_rules_preserve_local_cli_policy_without_a_wrapper() {
        let mut run = action("Run one policy-constrained native CLI command.");
        run.parameters.insert(
            "args".to_owned(),
            TypedActionParameter::StringArray {
                description: "Exact native CLI arguments.".to_owned(),
                required: true,
                min_items: Some(1),
                max_items: Some(32),
                max_item_bytes: Some(2_048),
            },
        );
        run.mappings.push(TypedArgumentMapping::Passthrough {
            parameter: "args".to_owned(),
        });
        run.argument_rules.denied_prefixes = vec![vec!["auth".to_owned()]];
        run.argument_rules.constrained_prefixes = vec![TypedConstrainedArgumentPrefix {
            prefix: vec!["workspace".to_owned()],
            allowed_next_tokens: BTreeSet::from(["list".to_owned(), "status".to_owned()]),
        }];

        let catalog = compile("native", &cli_contract("native"), &override_set("run", run))
            .expect("bounded argument rules compile");
        let action = &catalog.actions["run"];
        let allowed = lower_typed_action_invocation(
            action,
            &serde_json::json!({"args": ["workspace", "status", "--json"]}),
        )
        .expect("read-only workspace command");
        assert_eq!(allowed.arguments, ["workspace", "status", "--json"]);

        for denied in [
            serde_json::json!({"args": ["auth", "login"]}),
            serde_json::json!({"args": ["workspace", "set", "team"]}),
            serde_json::json!({"args": ["workspace"]}),
        ] {
            let error = lower_typed_action_invocation(action, &denied)
                .expect_err("argument policy must fail closed");
            assert_eq!(error.code, TypedActionInvocationErrorCode::InvalidParameter);
            assert!(!error.to_string().contains("auth"));
            assert!(!error.to_string().contains("workspace"));
        }
    }

    #[test]
    fn malformed_or_ambiguous_argument_rules_fail_at_compile_time() {
        let mut empty_prefix = action("Invalid rule.");
        empty_prefix.argument_rules.denied_prefixes = vec![Vec::new()];
        let error = compile(
            "native",
            &cli_contract("native"),
            &override_set("run", empty_prefix),
        )
        .expect_err("empty prefix must fail");
        assert_eq!(error.code, ActionOverrideErrorCode::InvalidArgumentRules);

        let mut overlapping = action("Ambiguous rule.");
        overlapping.argument_rules.constrained_prefixes = vec![
            TypedConstrainedArgumentPrefix {
                prefix: vec!["workspace".to_owned()],
                allowed_next_tokens: BTreeSet::from(["list".to_owned()]),
            },
            TypedConstrainedArgumentPrefix {
                prefix: vec!["workspace".to_owned(), "list".to_owned()],
                allowed_next_tokens: BTreeSet::from(["--json".to_owned()]),
            },
        ];
        let error = compile(
            "native",
            &cli_contract("native"),
            &override_set("run", overlapping),
        )
        .expect_err("overlapping constrained prefixes must fail");
        assert_eq!(error.code, ActionOverrideErrorCode::InvalidArgumentRules);

        let mut aggregate_bomb = action("Oversized rule corpus.");
        aggregate_bomb.argument_rules.denied_prefixes = (0..MAX_TYPED_ARGUMENT_RULES)
            .map(|rule| {
                (0..MAX_TYPED_ARGUMENT_RULE_PREFIX_TOKENS)
                    .map(|token| format!("rule-{rule:02}-{token:02}-{}", "x".repeat(2_048)))
                    .collect()
            })
            .collect();
        let error = compile(
            "native",
            &cli_contract("native"),
            &override_set("run", aggregate_bomb),
        )
        .expect_err("aggregate rule bytes must be bounded");
        assert_eq!(error.code, ActionOverrideErrorCode::InvalidArgumentRules);
    }

    #[test]
    fn worst_case_mapping_expansion_must_fit_the_base_argument_budget() {
        let mut repeated = action("Repeated values.");
        repeated.parameters.insert(
            "values".to_owned(),
            TypedActionParameter::StringArray {
                description: "Many values.".to_owned(),
                required: false,
                min_items: None,
                max_items: Some(MAX_FIXED_ARGUMENTS as u64),
                max_item_bytes: Some(8),
            },
        );
        repeated.mappings.push(TypedArgumentMapping::RepeatedFlag {
            flag: "--value".to_owned(),
            parameter: "values".to_owned(),
        });
        let error = compile(
            "demo",
            &cli_contract("demo"),
            &override_set("repeat", repeated),
        )
        .expect_err("projected argv must be bounded");
        assert_eq!(
            error.code,
            ActionOverrideErrorCode::ProjectedInvocationTooLarge
        );
    }

    #[test]
    fn finite_parameter_vocabulary_compiles_to_bounded_standard_json_schema() {
        let mut typed = action("All finite parameter kinds.");
        typed.parameters.insert(
            "choice".to_owned(),
            TypedActionParameter::String {
                description: "Choice.".to_owned(),
                required: true,
                default: Some("one".to_owned()),
                enum_values: BTreeSet::from(["one".to_owned(), "two".to_owned()]),
                min_length: Some(1),
                max_length: Some(8),
            },
        );
        typed.parameters.insert(
            "count".to_owned(),
            TypedActionParameter::Integer {
                description: "Count.".to_owned(),
                required: false,
                default: Some(2),
                enum_values: BTreeSet::new(),
                minimum: Some(1),
                maximum: Some(3),
            },
        );
        typed.parameters.insert(
            "ratio".to_owned(),
            TypedActionParameter::Number {
                description: "Ratio.".to_owned(),
                required: false,
                default: Some(Number::from(1)),
                minimum: Some(Number::from(0)),
                maximum: Some(Number::from(2)),
            },
        );
        typed.parameters.insert(
            "enabled".to_owned(),
            TypedActionParameter::Boolean {
                description: "Enabled.".to_owned(),
                required: false,
                default: Some(true),
            },
        );
        typed.parameters.insert(
            "tags".to_owned(),
            TypedActionParameter::StringArray {
                description: "Tags.".to_owned(),
                required: false,
                min_items: Some(0),
                max_items: Some(3),
                max_item_bytes: Some(16),
            },
        );
        typed.parameters.insert(
            "payload".to_owned(),
            TypedActionParameter::JsonObject {
                description: "Payload.".to_owned(),
                required: false,
                max_json_bytes: Some(512),
                max_depth: Some(4),
                max_nodes: Some(32),
            },
        );
        typed.parameters.insert(
            "input_file".to_owned(),
            TypedActionParameter::WorkspacePath {
                description: "Workspace input.".to_owned(),
                access: WorkspacePathAccess::ReadFile,
                required: true,
                max_length: Some(4096),
            },
        );
        typed.mappings = vec![
            TypedArgumentMapping::Flag {
                flag: "--choice".to_owned(),
                parameter: "choice".to_owned(),
                omit_if_empty: false,
            },
            TypedArgumentMapping::Flag {
                flag: "--count".to_owned(),
                parameter: "count".to_owned(),
                omit_if_empty: false,
            },
            TypedArgumentMapping::Flag {
                flag: "--ratio".to_owned(),
                parameter: "ratio".to_owned(),
                omit_if_empty: false,
            },
            TypedArgumentMapping::BoolFlag {
                flag: "--enabled".to_owned(),
                parameter: "enabled".to_owned(),
            },
            TypedArgumentMapping::Passthrough {
                parameter: "tags".to_owned(),
            },
            TypedArgumentMapping::JsonFlag {
                flag: "--payload".to_owned(),
                parameter: "payload".to_owned(),
            },
            TypedArgumentMapping::Flag {
                flag: "--input-file".to_owned(),
                parameter: "input_file".to_owned(),
                omit_if_empty: false,
            },
        ];
        let catalog = compile("demo", &cli_contract("demo"), &override_set("typed", typed))
            .expect("compile all finite types");
        let properties = &catalog.actions["typed"].definition.input_schema["properties"];
        assert_eq!(properties["choice"]["type"], "string");
        assert_eq!(
            properties["choice"]["enum"],
            serde_json::json!(["one", "two"])
        );
        assert_eq!(properties["count"]["type"], "integer");
        assert_eq!(properties["ratio"]["type"], "number");
        assert_eq!(properties["enabled"]["type"], "boolean");
        assert_eq!(properties["tags"]["items"]["type"], "string");
        assert_eq!(properties["payload"]["type"], "object");
        assert_eq!(properties["payload"]["x-max-json-depth"], 4);
        assert_eq!(properties["input_file"]["type"], "string");
        assert_eq!(properties["input_file"]["x-magician-workspace-path"], true);
        assert_eq!(
            properties["input_file"]["x-magician-path-access"],
            "read_file"
        );
        assert!(catalog.actions["typed"]
            .effective_policy
            .resource_scopes
            .contains("workspace"));
        assert_eq!(
            catalog.actions["typed"].definition.input_schema["additionalProperties"],
            false
        );
    }

    #[test]
    fn invalid_defaults_and_policy_references_return_value_free_diagnostics() {
        let canary = "SECRET_DEFAULT_CANARY";
        let mut invalid = action("Invalid default.");
        invalid.parameters.insert(
            "choice".to_owned(),
            TypedActionParameter::String {
                description: "Choice.".to_owned(),
                required: false,
                default: Some(canary.to_owned()),
                enum_values: BTreeSet::from(["safe".to_owned()]),
                min_length: None,
                max_length: None,
            },
        );
        invalid.mappings.push(TypedArgumentMapping::Positional {
            parameter: "choice".to_owned(),
        });
        let error = compile(
            "demo",
            &cli_contract("demo"),
            &override_set("invalid", invalid),
        )
        .expect_err("invalid default must fail");
        let serialized = serde_json::to_string(&error).expect("serialize diagnostic");
        assert_eq!(error.code, ActionOverrideErrorCode::InvalidParameter);
        assert!(!error.to_string().contains(canary));
        assert!(!serialized.contains(canary));

        let reference_canary = "../../SECRET_POLICY_CANARY";
        let mut invalid_policy = action("Invalid policy.");
        invalid_policy
            .policy
            .additional_required_grants
            .insert(reference_canary.to_owned());
        let error = compile(
            "demo",
            &cli_contract("demo"),
            &override_set("policy", invalid_policy),
        )
        .expect_err("invalid policy reference must fail");
        assert!(!error.to_string().contains(reference_canary));
    }

    #[test]
    fn workspace_create_parameter_always_adds_write_approval_floor() {
        let mut typed = action("Create a workspace output.");
        typed.parameters.insert(
            "output_file".to_owned(),
            TypedActionParameter::WorkspacePath {
                description: "New output.".to_owned(),
                access: WorkspacePathAccess::CreateFile,
                required: true,
                max_length: Some(4096),
            },
        );
        typed.mappings.push(TypedArgumentMapping::Flag {
            flag: "--output-file".to_owned(),
            parameter: "output_file".to_owned(),
            omit_if_empty: false,
        });

        let catalog = compile(
            "demo",
            &cli_contract("demo"),
            &override_set("create", typed),
        )
        .unwrap();

        assert!(catalog.actions["create"]
            .effective_policy
            .required_approvals
            .contains(&ApprovalClass::DelegatedWorkspaceWrite));
    }

    #[test]
    fn output_is_deterministic_across_authored_map_order() {
        fn build(reverse: bool) -> TypedActionOverrideSet {
            let ids = if reverse {
                ["zeta", "alpha"]
            } else {
                ["alpha", "zeta"]
            };
            let mut actions = BTreeMap::new();
            for id in ids {
                let mut value = action("Deterministic action.");
                let parameter_ids = if reverse { ["z", "a"] } else { ["a", "z"] };
                for parameter in parameter_ids {
                    value.parameters.insert(
                        parameter.to_owned(),
                        string_parameter("Deterministic parameter.", false),
                    );
                }
                value.mappings = vec![
                    TypedArgumentMapping::Flag {
                        flag: "--a".to_owned(),
                        parameter: "a".to_owned(),
                        omit_if_empty: false,
                    },
                    TypedArgumentMapping::Flag {
                        flag: "--z".to_owned(),
                        parameter: "z".to_owned(),
                        omit_if_empty: false,
                    },
                ];
                actions.insert(id.to_owned(), value);
            }
            TypedActionOverrideSet {
                schema_version: TYPED_ACTION_OVERRIDES_V1.to_owned(),
                input_delivery: TypedActionInputDelivery::Argv,
                actions,
            }
        }
        let contract = cli_contract("demo");
        let first = compile("demo", &contract, &build(false)).expect("first compile");
        let second = compile("demo", &contract, &build(true)).expect("second compile");
        assert_eq!(first, second);
        assert_eq!(
            serde_json::to_vec(&first).expect("serialize first"),
            serde_json::to_vec(&second).expect("serialize second")
        );
    }

    #[test]
    fn required_resource_authority_is_a_validated_manifest_floor() {
        let mut contract = cli_contract("demo");
        contract
            .policy_floor
            .required_resource_authorities
            .insert("../../escape".to_owned());
        let error = validate_skill_runtime_contract(&contract)
            .expect_err("invalid resource authority must fail");
        assert_eq!(error.code, ManifestValidationErrorCode::InvalidPolicyFloor);
        assert_eq!(error.field, "policy_floor.required_resource_authorities");
    }

    #[test]
    fn maximum_action_catalog_compiles_and_serializes_on_a_small_stack() {
        let result = thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| {
                let actions = (0..MAX_TYPED_ACTIONS)
                    .map(|index| {
                        (
                            format!("action_{index:03}"),
                            action("Bounded deterministic action."),
                        )
                    })
                    .collect();
                let overrides = TypedActionOverrideSet {
                    schema_version: TYPED_ACTION_OVERRIDES_V1.to_owned(),
                    input_delivery: TypedActionInputDelivery::Argv,
                    actions,
                };
                let catalog = compile("demo", &cli_contract("demo"), &overrides)
                    .expect("compile maximum catalog");
                serde_json::to_vec(&catalog)
                    .expect("serialize maximum catalog")
                    .len()
            })
            .expect("spawn small-stack compiler")
            .join()
            .expect("compiler must not overflow");
        assert!(result > 100_000);
    }

    #[test]
    fn version_empty_and_action_count_boundaries_fail_closed() {
        let contract = cli_contract("demo");
        let unsupported = TypedActionOverrideSet {
            schema_version: "tool-runtime.typed-action-overrides.v999".to_owned(),
            input_delivery: TypedActionInputDelivery::Argv,
            actions: BTreeMap::from([("run".to_owned(), action("Run."))]),
        };
        assert_eq!(
            compile("demo", &contract, &unsupported)
                .expect_err("forward version must fail")
                .code,
            ActionOverrideErrorCode::UnsupportedSchemaVersion
        );
        let empty = TypedActionOverrideSet {
            schema_version: TYPED_ACTION_OVERRIDES_V1.to_owned(),
            input_delivery: TypedActionInputDelivery::Argv,
            actions: BTreeMap::new(),
        };
        assert_eq!(
            compile("demo", &contract, &empty)
                .expect_err("empty override must fail")
                .code,
            ActionOverrideErrorCode::EmptyOverride
        );
        let actions = (0..=MAX_TYPED_ACTIONS)
            .map(|index| (format!("action_{index}"), action("Bounded action.")))
            .collect();
        let oversized = TypedActionOverrideSet {
            schema_version: TYPED_ACTION_OVERRIDES_V1.to_owned(),
            input_delivery: TypedActionInputDelivery::Argv,
            actions,
        };
        assert_eq!(
            compile("demo", &contract, &oversized)
                .expect_err("oversized override must fail")
                .code,
            ActionOverrideErrorCode::CollectionTooLarge
        );
    }

    #[test]
    fn specialized_runtime_controls_are_bounded_but_never_become_child_argv() {
        let mut typed = action("Drive one trusted interactive controller.");
        typed.parameters.insert(
            "billing_mode".to_owned(),
            TypedActionParameter::String {
                description: "Select a declared billing lane.".to_owned(),
                required: false,
                default: Some("subscription".to_owned()),
                enum_values: BTreeSet::from(["api".to_owned(), "subscription".to_owned()]),
                min_length: None,
                max_length: Some(16),
            },
        );
        typed.mappings.push(TypedArgumentMapping::RuntimeControl {
            parameter: "billing_mode".to_owned(),
        });
        typed.parameters.insert(
            "storyboard".to_owned(),
            TypedActionParameter::JsonArray {
                description: "Pass one bounded native-controller storyboard.".to_owned(),
                required: false,
                max_json_bytes: Some(MAX_TYPED_RUNTIME_CONTROL_STRING_BYTES),
                max_depth: Some(8),
                max_nodes: Some(512),
                max_items: Some(32),
            },
        );
        typed.mappings.push(TypedArgumentMapping::RuntimeControl {
            parameter: "storyboard".to_owned(),
        });
        let catalog = compile(
            "coding-agent",
            &cli_contract("coding-agent"),
            &override_set("run", typed),
        )
        .expect("runtime control must compile");
        let lowered = lower_typed_action_invocation(
            &catalog.actions["run"],
            &serde_json::json!({
                "billing_mode": "api",
                "storyboard": [{"id": "intro"}]
            }),
        )
        .expect("runtime control must lower");
        assert!(lowered.arguments.is_empty());
        assert_eq!(
            lowered.runtime_controls,
            BTreeMap::from([
                ("billing_mode".to_owned(), Value::String("api".to_owned())),
                (
                    "storyboard".to_owned(),
                    serde_json::json!([{"id": "intro"}]),
                ),
            ])
        );
    }

    #[test]
    fn runtime_lowering_keeps_metacharacters_in_inert_argv_tokens() {
        let mut typed = action("Send a bounded message.");
        typed.fixed_args = vec!["gmail".to_owned(), "+send".to_owned()];
        typed
            .parameters
            .insert("body".to_owned(), string_parameter("Message body.", true));
        typed.parameters.insert(
            "dry_run".to_owned(),
            TypedActionParameter::Boolean {
                description: "Do not commit.".to_owned(),
                required: false,
                default: Some(false),
            },
        );
        typed.mappings = vec![
            TypedArgumentMapping::Flag {
                flag: "--body".to_owned(),
                parameter: "body".to_owned(),
                omit_if_empty: false,
            },
            TypedArgumentMapping::BoolFlag {
                flag: "--dry-run".to_owned(),
                parameter: "dry_run".to_owned(),
            },
        ];
        typed.timeout_secs = Some(20);
        let catalog =
            compile("gmail", &cli_contract("gws"), &override_set("send", typed)).expect("compile");
        let lowered = lower_typed_action_invocation(
            &catalog.actions["send"],
            &serde_json::json!({"body": "hello; touch /tmp/canary", "timeout_secs": 7}),
        )
        .expect("lower");
        assert_eq!(
            lowered.arguments,
            vec!["gmail", "+send", "--body", "hello; touch /tmp/canary"]
        );
        assert_eq!(lowered.timeout_secs, 7);
    }

    #[test]
    fn runtime_lowering_distinguishes_boolean_values_from_presence_flags() {
        let mut typed = action("Lower both boolean CLI conventions.");
        typed.parameters.insert(
            "can_query".to_owned(),
            TypedActionParameter::Boolean {
                description: "Emit an explicit boolean value.".to_owned(),
                required: true,
                default: None,
            },
        );
        typed.parameters.insert(
            "compact".to_owned(),
            TypedActionParameter::Boolean {
                description: "Emit a presence-only toggle.".to_owned(),
                required: false,
                default: Some(false),
            },
        );
        typed.mappings = vec![
            TypedArgumentMapping::Flag {
                flag: "--can-query".to_owned(),
                parameter: "can_query".to_owned(),
                omit_if_empty: false,
            },
            TypedArgumentMapping::BoolFlag {
                flag: "--compact".to_owned(),
                parameter: "compact".to_owned(),
            },
        ];

        let catalog = compile(
            "metabase",
            &cli_contract("metabase-pp-cli"),
            &override_set("table_list", typed),
        )
        .expect("compile boolean CLI conventions");
        let lowered = lower_typed_action_invocation(
            &catalog.actions["table_list"],
            &serde_json::json!({"can_query": false, "compact": true}),
        )
        .expect("lower boolean CLI conventions");

        assert_eq!(lowered.arguments, vec!["--can-query", "false", "--compact"]);
    }

    #[test]
    fn runtime_lowering_applies_defaults_and_all_mapping_shapes() {
        let mut typed = action("Lower every mapping.");
        typed.parameters.insert(
            "position".to_owned(),
            TypedActionParameter::String {
                description: "Position.".to_owned(),
                required: false,
                default: Some("default-value".to_owned()),
                enum_values: BTreeSet::new(),
                min_length: None,
                max_length: None,
            },
        );
        for name in ["repeat", "extra"] {
            typed.parameters.insert(
                name.to_owned(),
                TypedActionParameter::StringArray {
                    description: "Values.".to_owned(),
                    required: true,
                    min_items: Some(1),
                    max_items: Some(4),
                    max_item_bytes: Some(64),
                },
            );
        }
        typed.parameters.insert(
            "payload".to_owned(),
            TypedActionParameter::JsonObject {
                description: "Payload.".to_owned(),
                required: true,
                max_json_bytes: Some(256),
                max_depth: Some(4),
                max_nodes: Some(16),
            },
        );
        typed.mappings = vec![
            TypedArgumentMapping::Positional {
                parameter: "position".to_owned(),
            },
            TypedArgumentMapping::RepeatedFlag {
                flag: "--tag".to_owned(),
                parameter: "repeat".to_owned(),
            },
            TypedArgumentMapping::Passthrough {
                parameter: "extra".to_owned(),
            },
            TypedArgumentMapping::JsonFlag {
                flag: "--json".to_owned(),
                parameter: "payload".to_owned(),
            },
        ];
        let catalog =
            compile("demo", &cli_contract("demo"), &override_set("all", typed)).expect("compile");
        let lowered = lower_typed_action_invocation(
            &catalog.actions["all"],
            &serde_json::json!({
                "repeat": ["one", "two"],
                "extra": ["--literal", "value"],
                "payload": {"b": 2, "a": 1}
            }),
        )
        .expect("lower");
        assert_eq!(
            lowered.arguments,
            vec![
                "default-value",
                "--tag",
                "one",
                "--tag",
                "two",
                "--literal",
                "value",
                "--json",
                r#"{"a":1,"b":2}"#,
            ]
        );
    }

    /// An optional flag string that is empty must contribute nothing to argv.
    ///
    /// Several shipped skills expose `flags` as a `split_positional` string whose
    /// default is `''`. If that lowered to a single empty token the invocation
    /// would be malformed — `awk "" '{print $2}' file` selects an empty program
    /// and prints nothing — so the splitter must yield no tokens at all, whether
    /// the empty value arrives as the declared default or as an explicit
    /// argument. Pinned here because it is easy to "fix" the manifests for a
    /// failure this is not the cause of.
    #[test]
    fn runtime_lowering_drops_an_empty_split_value_instead_of_emitting_an_empty_token() {
        let mut typed = action("Lower an optional flag string.");
        typed.parameters.insert(
            "flags".to_owned(),
            TypedActionParameter::String {
                description: "Optional flags.".to_owned(),
                required: false,
                default: Some(String::new()),
                enum_values: BTreeSet::new(),
                min_length: None,
                max_length: Some(4096),
            },
        );
        typed.parameters.insert(
            "program".to_owned(),
            TypedActionParameter::String {
                description: "Program.".to_owned(),
                required: true,
                default: None,
                enum_values: BTreeSet::new(),
                min_length: None,
                max_length: Some(4096),
            },
        );
        typed.mappings = vec![
            TypedArgumentMapping::SplitPositional {
                parameter: "flags".to_owned(),
                max_items: 64,
                max_item_bytes: 4096,
            },
            TypedArgumentMapping::Positional {
                parameter: "program".to_owned(),
            },
        ];
        let catalog =
            compile("demo", &cli_contract("demo"), &override_set("run", typed)).expect("compile");
        let action = &catalog.actions["run"];

        let defaulted =
            lower_typed_action_invocation(action, &serde_json::json!({"program": "{print $2}"}))
                .expect("lower with the declared default");
        assert_eq!(defaulted.arguments, vec!["{print $2}"]);

        let explicit = lower_typed_action_invocation(
            action,
            &serde_json::json!({"program": "{print $2}", "flags": ""}),
        )
        .expect("lower with an explicit empty value");
        assert_eq!(explicit.arguments, vec!["{print $2}"]);

        let populated = lower_typed_action_invocation(
            action,
            &serde_json::json!({"program": "{print $2}", "flags": "-F, -v OFS=;"}),
        )
        .expect("lower with populated flags");
        assert_eq!(
            populated.arguments,
            vec!["-F,", "-v", "OFS=;", "{print $2}"]
        );
    }

    #[test]
    fn runtime_lowering_rejects_unknown_missing_wrong_and_oversized_inputs_value_free() {
        let mut typed = action("Bounded action.");
        typed.parameters.insert(
            "required".to_owned(),
            TypedActionParameter::String {
                description: "Required.".to_owned(),
                required: true,
                default: None,
                enum_values: BTreeSet::new(),
                min_length: Some(1),
                max_length: Some(4),
            },
        );
        typed.mappings = vec![TypedArgumentMapping::Flag {
            flag: "--value".to_owned(),
            parameter: "required".to_owned(),
            omit_if_empty: false,
        }];
        let catalog =
            compile("demo", &cli_contract("demo"), &override_set("run", typed)).expect("compile");
        let action = &catalog.actions["run"];

        assert_eq!(
            lower_typed_action_invocation(action, &serde_json::json!({}))
                .expect_err("missing")
                .code,
            TypedActionInvocationErrorCode::MissingRequiredParameter
        );
        assert_eq!(
            lower_typed_action_invocation(
                action,
                &serde_json::json!({"required": "ok", "canary-secret": "never"})
            )
            .expect_err("unknown")
            .code,
            TypedActionInvocationErrorCode::UnknownParameter
        );
        let error = lower_typed_action_invocation(
            action,
            &serde_json::json!({"required": "SECRET-CANARY-TOO-LONG"}),
        )
        .expect_err("oversized");
        assert_eq!(error.code, TypedActionInvocationErrorCode::InvalidParameter);
        assert!(!error.to_string().contains("SECRET-CANARY"));
        assert!(!serde_json::to_string(&error)
            .expect("serialize")
            .contains("SECRET-CANARY"));
    }

    #[test]
    fn v2_canonical_json_stdin_is_validated_defaulted_and_not_model_supplied() {
        let mut contract = cli_contract("protocol-adapter");
        let RuntimeProtocol::Cli { stdin, limits, .. } = &mut contract.runtime else {
            unreachable!();
        };
        stdin.mode = StdinMode::Required;
        stdin.sensitivity = DataSensitivity::Private;
        limits.timeout_secs = Some(30);
        limits.stdin_bytes = Some(4_096);

        let mut run = action("Run one protocol adapter request.");
        run.parameters.insert(
            "query".to_owned(),
            TypedActionParameter::String {
                description: "Query.".to_owned(),
                required: true,
                default: None,
                enum_values: BTreeSet::new(),
                min_length: Some(1),
                max_length: Some(64),
            },
        );
        run.parameters.insert(
            "include_answer".to_owned(),
            TypedActionParameter::Boolean {
                description: "Include an answer.".to_owned(),
                required: false,
                default: Some(false),
            },
        );
        run.fixed_args = vec!["request".to_owned()];
        run.suffix_args = vec!["--format".to_owned(), "json".to_owned()];
        let overrides = TypedActionOverrideSet {
            schema_version: TYPED_ACTION_OVERRIDES_V2.to_owned(),
            input_delivery: TypedActionInputDelivery::CanonicalJsonStdin,
            actions: BTreeMap::from([("run".to_owned(), run)]),
        };
        let catalog = compile("protocol-adapter", &contract, &overrides).expect("compile v2");
        let action = &catalog.actions["run"];
        let properties = action.definition.input_schema["properties"]
            .as_object()
            .expect("properties");
        assert!(!properties.contains_key("stdin"));
        assert_eq!(action.invocation.mappings, Vec::new());

        let lowered =
            lower_typed_action_invocation(action, &serde_json::json!({"query": "current news"}))
                .expect("lower canonical JSON");
        assert_eq!(lowered.arguments, ["request", "--format", "json"]);
        assert_eq!(
            lowered.stdin.as_deref(),
            Some(r#"{"include_answer":false,"query":"current news"}"#)
        );
        assert_eq!(lowered.timeout_secs, 30);

        let error =
            lower_typed_action_invocation(action, &serde_json::json!({"query": "x".repeat(65)}))
                .expect_err("typed limits remain authoritative");
        assert_eq!(error.code, TypedActionInvocationErrorCode::InvalidParameter);
    }

    #[test]
    fn canonical_json_parameters_use_the_owned_stdin_ceiling_and_cap_the_whole_payload() {
        let mut contract = cli_contract("protocol-adapter");
        let RuntimeProtocol::Cli { stdin, limits, .. } = &mut contract.runtime else {
            unreachable!();
        };
        stdin.mode = StdinMode::Required;
        stdin.sensitivity = DataSensitivity::Private;
        limits.stdin_bytes = Some(16 * 1024);

        let mut run = action("Run one bounded canonical JSON request.");
        run.parameters.insert(
            "payload".to_owned(),
            TypedActionParameter::String {
                description: "Provider payload.".to_owned(),
                required: true,
                default: None,
                enum_values: BTreeSet::new(),
                min_length: Some(1),
                max_length: Some(16 * 1024),
            },
        );
        let overrides = TypedActionOverrideSet {
            schema_version: TYPED_ACTION_OVERRIDES_V2.to_owned(),
            input_delivery: TypedActionInputDelivery::CanonicalJsonStdin,
            actions: BTreeMap::from([("run".to_owned(), run)]),
        };
        let catalog = compile("protocol-adapter", &contract, &overrides)
            .expect("canonical JSON parameters may use their owned stdin lane");
        let action = &catalog.actions["run"];

        let lowered = lower_typed_action_invocation(
            action,
            &serde_json::json!({"payload": "x".repeat(5_000)}),
        )
        .expect("a parameter larger than argv remains valid on bounded canonical stdin");
        assert!(lowered
            .stdin
            .as_ref()
            .is_some_and(|stdin| stdin.len() > 5_000));

        let error = lower_typed_action_invocation(
            action,
            &serde_json::json!({"payload": "x".repeat(16_380)}),
        )
        .expect_err("JSON framing must remain inside the aggregate stdin ceiling");
        assert_eq!(
            error.code,
            TypedActionInvocationErrorCode::InvocationTooLarge
        );
    }

    #[test]
    fn canonical_json_stdin_rejects_v1_mappings_and_unowned_stdin() {
        let mut contract = cli_contract("protocol-adapter");
        let mut run = action("Run one protocol adapter request.");
        run.parameters
            .insert("query".to_owned(), string_parameter("Query.", true));
        let v1 = TypedActionOverrideSet {
            schema_version: TYPED_ACTION_OVERRIDES_V1.to_owned(),
            input_delivery: TypedActionInputDelivery::CanonicalJsonStdin,
            actions: BTreeMap::from([("run".to_owned(), run.clone())]),
        };
        assert_eq!(
            compile("protocol-adapter", &contract, &v1)
                .expect_err("v1 cannot opt into v2 delivery")
                .code,
            ActionOverrideErrorCode::UnsupportedSchemaVersion
        );

        let v2 = TypedActionOverrideSet {
            schema_version: TYPED_ACTION_OVERRIDES_V2.to_owned(),
            input_delivery: TypedActionInputDelivery::CanonicalJsonStdin,
            actions: BTreeMap::from([("run".to_owned(), run.clone())]),
        };
        assert_eq!(
            compile("protocol-adapter", &contract, &v2)
                .expect_err("denied stdin cannot carry generated input")
                .code,
            ActionOverrideErrorCode::BaseContractInvariantViolation
        );

        let RuntimeProtocol::Cli { stdin, .. } = &mut contract.runtime else {
            unreachable!();
        };
        stdin.mode = StdinMode::Required;
        run.mappings.push(TypedArgumentMapping::Positional {
            parameter: "query".to_owned(),
        });
        let v2 = TypedActionOverrideSet {
            schema_version: TYPED_ACTION_OVERRIDES_V2.to_owned(),
            input_delivery: TypedActionInputDelivery::CanonicalJsonStdin,
            actions: BTreeMap::from([("run".to_owned(), run)]),
        };
        assert_eq!(
            compile("protocol-adapter", &contract, &v2)
                .expect_err("JSON delivery cannot retain an argv schema")
                .code,
            ActionOverrideErrorCode::InvalidMapping
        );
    }

    #[test]
    fn argv_actions_refine_stdin_and_append_only_fixed_suffix_tokens() {
        let mut contract = cli_contract("metabase-pp-cli");
        let RuntimeProtocol::Cli { stdin, limits, .. } = &mut contract.runtime else {
            unreachable!();
        };
        stdin.mode = StdinMode::Optional;
        stdin.sensitivity = DataSensitivity::Private;
        limits.stdin_bytes = Some(4_096);

        let mut create = action("Create one governed card.");
        create.fixed_args = vec!["card".to_owned(), "create".to_owned()];
        create.suffix_args = vec!["--stdin".to_owned(), "--compact".to_owned()];
        create.stdin = TypedActionStdin::Required;
        create.parameters.insert(
            "card_id".to_owned(),
            TypedActionParameter::Integer {
                description: "Card id.".to_owned(),
                required: true,
                default: None,
                enum_values: BTreeSet::new(),
                minimum: Some(1),
                maximum: None,
            },
        );
        create.mappings.push(TypedArgumentMapping::Positional {
            parameter: "card_id".to_owned(),
        });

        let compiled = compile("metabase", &contract, &override_set("create", create))
            .expect("compile refined stdin action");
        let action = &compiled.actions["create"];
        assert!(action.definition.input_schema["required"]
            .as_array()
            .is_some_and(|required| required.iter().any(|value| value == "stdin")));
        let lowered = lower_typed_action_invocation(
            action,
            &serde_json::json!({"card_id": 7, "stdin": "{\"name\":\"demo\"}"}),
        )
        .expect("lower refined stdin action");
        assert_eq!(
            lowered.arguments,
            ["card", "create", "7", "--stdin", "--compact"]
        );
        assert_eq!(lowered.stdin.as_deref(), Some("{\"name\":\"demo\"}"));
    }

    #[test]
    fn runtime_json_validation_is_iterative_and_small_stack_safe() {
        let result = thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| {
                let mut typed = action("JSON action.");
                typed.parameters.insert(
                    "payload".to_owned(),
                    TypedActionParameter::JsonObject {
                        description: "Payload.".to_owned(),
                        required: true,
                        max_json_bytes: Some(MAX_ARGUMENT_BYTES as u64),
                        max_depth: Some(MAX_TYPED_JSON_DEPTH as u64),
                        max_nodes: Some(MAX_TYPED_JSON_NODES as u64),
                    },
                );
                typed.mappings = vec![TypedArgumentMapping::JsonFlag {
                    flag: "--json".to_owned(),
                    parameter: "payload".to_owned(),
                }];
                let catalog = compile("demo", &cli_contract("demo"), &override_set("run", typed))
                    .expect("compile");
                let mut nested = Value::from("leaf");
                for _ in 0..14 {
                    nested = Value::Object(Map::from_iter([("nested".to_owned(), nested)]));
                }
                let payload = Value::Object(
                    (0..200)
                        .map(|index| (format!("key_{index}"), Value::from(index)))
                        .chain([("nested".to_owned(), nested)])
                        .collect(),
                );
                lower_typed_action_invocation(
                    &catalog.actions["run"],
                    &serde_json::json!({"payload": payload}),
                )
                .expect("lower")
                .arguments
                .len()
            })
            .expect("spawn")
            .join()
            .expect("no stack overflow");
        assert_eq!(result, 2);
    }

    #[test]
    fn canonical_json_delivery_is_small_stack_safe() {
        let result = thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| {
                let mut contract = cli_contract("protocol-adapter");
                let RuntimeProtocol::Cli { stdin, limits, .. } = &mut contract.runtime else {
                    unreachable!();
                };
                stdin.mode = StdinMode::Required;
                stdin.sensitivity = DataSensitivity::Private;
                limits.stdin_bytes = Some(MAX_ARGUMENT_BYTES as u64);

                let mut run = action("Canonical JSON action.");
                run.parameters.insert(
                    "payload".to_owned(),
                    TypedActionParameter::JsonObject {
                        description: "Payload.".to_owned(),
                        required: true,
                        max_json_bytes: Some(MAX_ARGUMENT_BYTES as u64),
                        max_depth: Some(MAX_TYPED_JSON_DEPTH as u64),
                        max_nodes: Some(MAX_TYPED_JSON_NODES as u64),
                    },
                );
                let overrides = TypedActionOverrideSet {
                    schema_version: TYPED_ACTION_OVERRIDES_V2.to_owned(),
                    input_delivery: TypedActionInputDelivery::CanonicalJsonStdin,
                    actions: BTreeMap::from([("run".to_owned(), run)]),
                };
                let catalog = compile("protocol-adapter", &contract, &overrides)
                    .expect("compile canonical JSON action");

                let mut nested = Value::from("leaf");
                for _ in 0..14 {
                    nested = Value::Object(Map::from_iter([("nested".to_owned(), nested)]));
                }
                let payload = Value::Object(
                    (0..200)
                        .map(|index| (format!("key_{index}"), Value::from(index)))
                        .chain([("nested".to_owned(), nested)])
                        .collect(),
                );
                lower_typed_action_invocation(
                    &catalog.actions["run"],
                    &serde_json::json!({"payload": payload}),
                )
                .expect("lower canonical JSON")
                .stdin
                .expect("generated stdin")
                .len()
            })
            .expect("spawn")
            .join()
            .expect("no stack overflow");
        assert!(result > 1_000);
    }
}
