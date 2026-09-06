//! Bounded `SKILL.md` frontmatter extraction for the versioned runtime contract.
//!
//! The parser accepts source text, not a path: filesystem ownership, symlink
//! policy, and scoped package discovery stay with their eventual caller. It
//! performs no execution, credential resolution, environment access, or network
//! work.

use std::{collections::BTreeSet, error::Error, fmt};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_yaml::{Mapping, Value};

use crate::{
    action_overrides::TypedActionOverrideSet,
    inventory::validate_yaml_shape,
    manifest::{
        ProfileSelection, SkillRuntimeContract, SkillRuntimeContractVersion,
        SKILL_RUNTIME_CONTRACT_V1,
    },
    manifest_validation::is_reference,
};

pub const MAX_SKILL_MARKDOWN_BYTES: usize = 1024 * 1024;
/// Large reviewed CLI catalogs (notably browser automation) legitimately carry
/// hundreds of typed actions/controls in the one-file drop-in package. Keep the
/// envelope bounded well below the complete SKILL.md ceiling while allowing the
/// active catalog to remain the sole schema source.
pub const MAX_SKILL_FRONTMATTER_BYTES: usize = 512 * 1024;
const MAX_PARSED_YAML_DEPTH: usize = 64;
const MAX_PARSED_YAML_NODES: usize = 20_000;
const MAX_DIAGNOSTIC_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestParseErrorCode {
    SourceTooLarge,
    MissingFrontmatter,
    UnterminatedFrontmatter,
    FrontmatterTooLarge,
    UnsafeYamlShape,
    YamlReferencesUnsupported,
    InvalidYaml,
    ParsedYamlTooLarge,
    YamlTagsUnsupported,
    InvalidEnvelope,
    MissingSchemaVersion,
    InvalidSchemaVersion,
    UnsupportedSchemaVersion,
    InvalidRuntimeContract,
    ActionsWithoutRuntimeContract,
    InvalidRuntimeActions,
    InvalidRuntimeCatalog,
    InvalidMagicianExtension,
}

/// Independent audience flags for one skill document.
///
/// Agents and apps share the same SKILL.md. These flags only decide who may
/// see the tool. They grant no execution authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillExposeAudience {
    /// When omitted, the skill stays in the ordinary agent catalog.
    #[serde(default = "default_agents_exposed")]
    pub agents: bool,
    /// When omitted, the skill is not app-eligible. Catalog snapshot and app
    /// lock require an explicit `true`.
    #[serde(default)]
    pub apps: bool,
}

impl Default for SkillExposeAudience {
    fn default() -> Self {
        Self {
            agents: true,
            apps: false,
        }
    }
}

const fn default_agents_exposed() -> bool {
    true
}

/// Read `metadata.magician.expose`. A missing map is the default
/// (`agents: true`, `apps: false`). A present but invalid map fails closed.
pub fn parse_skill_expose(source: &str) -> Result<SkillExposeAudience, ManifestParseError> {
    Ok(parse_skill_magician_extension(source, "expose")?.unwrap_or_default())
}

/// Complete executable package authored in one `SKILL.md` frontmatter.
#[derive(Debug, Clone, PartialEq)]
pub struct SkillRuntimePackage {
    pub contract: SkillRuntimeContract,
    pub actions: Option<TypedActionOverrideSet>,
    pub catalog: SkillRuntimeCatalogMetadata,
}

/// Non-authoritative catalog hints retained while a skill moves off its old
/// pack schema. Security, execution, auth, and resource authority remain in
/// the validated runtime contract and typed actions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SkillRuntimeCatalogMetadata {
    pub categories: Vec<String>,
    pub composition_category: Option<String>,
    /// Optional product adapter identifier preserved as bounded declarative
    /// presentation metadata. The product maps only exact known values; the
    /// universal runtime does not depend on product adapter types.
    pub chat_inline_adapter: Option<String>,
    /// Optional model-facing name for the reviewed MCP endpoint-alias selector.
    /// The selected value is still resolved only from the contract's exact alias
    /// map; this field can never expose an arbitrary URL.
    pub mcp_endpoint_parameter: Option<String>,
    pub profile_parameter: Option<SkillRuntimeProfileParameterMetadata>,
    /// Preserve an existing model-facing `timeout_secs` action control while
    /// execution authority remains the runtime-owned timeout ceiling.
    #[serde(default)]
    pub expose_timeout_control: bool,
    /// Compatibility default for the outer capability timeout control. It may
    /// not exceed the validated runtime ceiling; individual typed actions may
    /// still lower their own ceiling.
    #[serde(default)]
    pub timeout_default_secs: Option<u32>,
    /// Preserve a model-facing working-directory control for tools whose
    /// native CLI is intentionally run inside a caller-selected workspace.
    /// The runtime still resolves and authorizes the path.
    #[serde(default)]
    pub expose_working_directory_control: bool,
    /// Optional compatibility name for the model-facing working-directory
    /// control. Runtime lowering always canonicalizes it back to `working_dir`.
    #[serde(default)]
    pub working_directory_parameter: Option<String>,
    /// Optional compatibility default for the working-directory control.
    #[serde(default)]
    pub working_directory_default: Option<String>,
    /// Optional provider-neutral external-resource spend declaration retained
    /// from the package. It is presentation/policy metadata only; the product
    /// treasurer remains the authority that creates and settles spend gates.
    #[serde(default)]
    pub spend: Option<SkillRuntimeSpendMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SkillRuntimeSpendMetadata {
    Committed {
        commodity: String,
        cost_parameter: String,
    },
    Metered {
        commodity: String,
        estimated_cost: String,
        #[serde(default)]
        max_cost: Option<String>,
    },
    Counted {
        commodity: String,
        cost_per_action: String,
    },
}

/// Model-facing name and finite suggestions for a selectable profile. This is
/// presentation metadata only: the validated profile registry remains the
/// authority for whether an alias exists and can be used in the active scope.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillRuntimeProfileParameterMetadata {
    pub name: String,
    #[serde(default)]
    pub enum_values: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectedProfileParameter<'a> {
    pub name: &'a str,
    pub enum_values: Option<&'a BTreeSet<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectedWorkingDirectoryParameter<'a> {
    pub name: &'a str,
}

impl SkillRuntimePackage {
    /// Return the one model-facing selector for a selectable profile. Runtime
    /// authority always remains the canonical `profile`; this view only keeps
    /// a compatible public parameter name while catalogs migrate.
    pub fn projected_profile_parameter(&self) -> Option<ProjectedProfileParameter<'_>> {
        if !matches!(
            self.contract.auth.profile_selection,
            ProfileSelection::Selectable { .. }
        ) {
            return None;
        }
        Some(match self.catalog.profile_parameter.as_ref() {
            Some(parameter) => ProjectedProfileParameter {
                name: &parameter.name,
                enum_values: Some(&parameter.enum_values),
            },
            None => ProjectedProfileParameter {
                name: "profile",
                enum_values: None,
            },
        })
    }

    /// Return the one model-facing working-directory control while preserving
    /// the runtime-owned canonical name internally.
    pub fn projected_working_directory_parameter(
        &self,
    ) -> Option<ProjectedWorkingDirectoryParameter<'_>> {
        self.catalog
            .expose_working_directory_control
            .then(|| ProjectedWorkingDirectoryParameter {
                name: self
                    .catalog
                    .working_directory_parameter
                    .as_deref()
                    .unwrap_or("working_dir"),
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestParseError {
    pub code: ManifestParseErrorCode,
    pub message: String,
    pub found_version: Option<String>,
    pub supported_versions: Vec<String>,
}

impl ManifestParseError {
    fn new(code: ManifestParseErrorCode, message: impl AsRef<str>) -> Self {
        Self {
            code,
            message: bounded_diagnostic(message.as_ref()),
            found_version: None,
            supported_versions: Vec::new(),
        }
    }

    fn unsupported_version(found: &str) -> Self {
        Self {
            code: ManifestParseErrorCode::UnsupportedSchemaVersion,
            message: "skill runtime contract uses an unsupported schema version".to_owned(),
            found_version: Some(bounded_diagnostic(found)),
            supported_versions: vec![SKILL_RUNTIME_CONTRACT_V1.to_owned()],
        }
    }
}

impl fmt::Display for ManifestParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(version) = &self.found_version {
            write!(
                formatter,
                "{} (found {version:?}; supported: {})",
                self.message,
                self.supported_versions.join(", ")
            )
        } else {
            formatter.write_str(&self.message)
        }
    }
}

impl Error for ManifestParseError {}

/// Extract and deserialize the optional versioned runtime contract from a
/// complete `SKILL.md` source document.
///
/// A valid legacy frontmatter document without `runtime_contract` returns
/// `Ok(None)`, enabling migration inventory without opting that skill into the
/// new runtime. Once the key is present, all contract fields are strict.
pub fn parse_skill_runtime_contract(
    source: &str,
) -> Result<Option<SkillRuntimeContract>, ManifestParseError> {
    Ok(parse_skill_runtime_package(source)?.map(|package| package.contract))
}

/// Deserialize the complete bounded SKILL.md frontmatter into a caller-owned
/// envelope. This gives ordinary skill discovery the same source-size,
/// structural-depth, anchor/tag, and node limits as executable packages.
pub fn parse_skill_frontmatter<T>(source: &str) -> Result<T, ManifestParseError>
where
    T: DeserializeOwned,
{
    let document = parse_frontmatter_document(source)?;
    serde_yaml::from_value(document).map_err(|error| {
        ManifestParseError::new(
            ManifestParseErrorCode::InvalidEnvelope,
            yaml_diagnostic("SKILL.md frontmatter does not match its envelope", &error),
        )
    })
}

/// Parse one optional product extension from the same bounded
/// `metadata.magician` mapping that owns the governed runtime contract.
///
/// This is the universal escape valve for declarative product integrations:
/// callers supply their strict owned type, while this module retains sole
/// ownership of SKILL.md size, YAML-shape, anchor/tag, and depth limits. A
/// product must not introduce a sibling manifest merely because its schema is
/// not part of executable dispatch.
pub fn parse_skill_magician_extension<T>(
    source: &str,
    extension: &str,
) -> Result<Option<T>, ManifestParseError>
where
    T: DeserializeOwned,
{
    if extension.is_empty()
        || extension.len() > 64
        || !extension
            .chars()
            .all(|character| character.is_ascii_lowercase() || character == '_')
    {
        return Err(ManifestParseError::new(
            ManifestParseErrorCode::InvalidMagicianExtension,
            "metadata.magician extension name is invalid",
        ));
    }
    let document = parse_frontmatter_document(source)?;
    let root = mapping(&document, "SKILL.md frontmatter")?;
    let Some(metadata) = mapping_value(root, "metadata") else {
        return Ok(None);
    };
    let metadata = mapping(metadata, "SKILL.md metadata")?;
    let Some(magician) = mapping_value(metadata, "magician") else {
        return Ok(None);
    };
    let magician = mapping(magician, "SKILL.md metadata.magician")?;
    let Some(value) = mapping_value(magician, extension) else {
        return Ok(None);
    };
    serde_yaml::from_value(value.clone())
        .map(Some)
        .map_err(|error| {
            ManifestParseError::new(
                ManifestParseErrorCode::InvalidMagicianExtension,
                yaml_diagnostic(&format!("metadata.magician.{extension} is invalid"), &error),
            )
        })
}

/// Parse the complete optional runtime package from one bounded `SKILL.md`.
/// `runtime_actions` may never opt in without the matching runtime contract.
pub fn parse_skill_runtime_package(
    source: &str,
) -> Result<Option<SkillRuntimePackage>, ManifestParseError> {
    let document = parse_frontmatter_document(source)?;
    let root = mapping(&document, "SKILL.md frontmatter")?;
    let Some(metadata) = mapping_value(root, "metadata") else {
        return Ok(None);
    };
    let metadata = mapping(metadata, "SKILL.md metadata")?;
    let Some(magician) = mapping_value(metadata, "magician") else {
        return Ok(None);
    };
    let magician = mapping(magician, "SKILL.md metadata.magician")?;
    let contract_value = mapping_value(magician, "runtime_contract");
    let actions_value = mapping_value(magician, "runtime_actions");
    if contract_value.is_none() && actions_value.is_some() {
        return Err(ManifestParseError::new(
            ManifestParseErrorCode::ActionsWithoutRuntimeContract,
            "runtime_actions requires runtime_contract in the same SKILL.md",
        ));
    }
    let Some(contract_value) = contract_value else {
        return Ok(None);
    };
    let contract = parse_contract_value(contract_value)?;
    let actions = actions_value
        .map(|value| {
            serde_yaml::from_value(value.clone()).map_err(|error| {
                ManifestParseError::new(
                    ManifestParseErrorCode::InvalidRuntimeActions,
                    yaml_diagnostic(
                        "runtime_actions does not match the supported typed action vocabulary",
                        &error,
                    ),
                )
            })
        })
        .transpose()?;
    let catalog = mapping_value(magician, "runtime_catalog")
        .map(|value| {
            serde_yaml::from_value(value.clone()).map_err(|error| {
                ManifestParseError::new(
                    ManifestParseErrorCode::InvalidRuntimeCatalog,
                    yaml_diagnostic(
                        "runtime_catalog does not match the supported catalog vocabulary",
                        &error,
                    ),
                )
            })
        })
        .transpose()?
        .unwrap_or_default();
    validate_runtime_catalog(&contract, &catalog)?;
    Ok(Some(SkillRuntimePackage {
        contract,
        actions,
        catalog,
    }))
}

fn validate_runtime_catalog(
    contract: &SkillRuntimeContract,
    catalog: &SkillRuntimeCatalogMetadata,
) -> Result<(), ManifestParseError> {
    const MAX_CATEGORIES: usize = 32;
    const MAX_CATEGORY_BYTES: usize = 64;
    const MAX_PROFILE_ENUM_VALUES: usize = 64;
    const MAX_PROFILE_ALIAS_BYTES: usize = 128;
    if catalog.categories.len() > MAX_CATEGORIES
        || catalog.categories.iter().any(|value| {
            value.is_empty() || value.len() > MAX_CATEGORY_BYTES || !portable_catalog_name(value)
        })
        || catalog
            .composition_category
            .as_deref()
            .is_some_and(|value| {
                value.is_empty()
                    || value.len() > MAX_CATEGORY_BYTES
                    || !portable_catalog_name(value)
            })
        || catalog.chat_inline_adapter.as_deref().is_some_and(|value| {
            value.is_empty() || value.len() > MAX_CATEGORY_BYTES || !portable_catalog_name(value)
        })
    {
        return Err(invalid_runtime_catalog());
    }
    if catalog.timeout_default_secs.is_some_and(|default| {
        default == 0
            || match &contract.runtime {
                crate::manifest::RuntimeProtocol::Cli { limits, .. } => {
                    limits.timeout_secs.is_some_and(|ceiling| default > ceiling)
                },
                crate::manifest::RuntimeProtocol::Mcp { .. } => true,
            }
    }) {
        return Err(invalid_runtime_catalog());
    }
    let working_directory_mode = match &contract.runtime {
        crate::manifest::RuntimeProtocol::Cli {
            working_directory, ..
        } => Some(working_directory.mode),
        crate::manifest::RuntimeProtocol::Mcp { .. } => None,
    };
    let has_mcp_endpoint_aliases = matches!(
        &contract.runtime,
        crate::manifest::RuntimeProtocol::Mcp { discovery, .. }
            if !discovery.endpoint_aliases.is_empty()
    );
    if catalog
        .mcp_endpoint_parameter
        .as_deref()
        .is_some_and(|value| {
            !has_mcp_endpoint_aliases
                || value.is_empty()
                || value.len() > MAX_CATEGORY_BYTES
                || !portable_model_parameter(value)
                || matches!(
                    value,
                    "profile"
                        | "tool_name"
                        | "arguments_json"
                        | "risk"
                        | "confirmed"
                        | "intent_summary"
                        | "timeout_secs"
                )
        })
    {
        return Err(invalid_runtime_catalog());
    }
    if (catalog.working_directory_default.is_some()
        || catalog.working_directory_parameter.is_some())
        && !catalog.expose_working_directory_control
        || catalog.expose_working_directory_control
            && working_directory_mode != Some(crate::manifest::WorkingDirectoryMode::Workspace)
        || catalog
            .working_directory_default
            .as_deref()
            .is_some_and(|value| !portable_working_directory_default(value))
        || catalog
            .working_directory_parameter
            .as_deref()
            .is_some_and(|value| {
                value.is_empty()
                    || value.len() > MAX_CATEGORY_BYTES
                    || !portable_model_parameter(value)
                    || matches!(value, "profile" | "stdin" | "timeout_secs")
            })
    {
        return Err(invalid_runtime_catalog());
    }
    if catalog.spend.as_ref().is_some_and(|spend| match spend {
        SkillRuntimeSpendMetadata::Committed {
            commodity,
            cost_parameter,
        } => !is_reference(commodity) || !portable_model_parameter(cost_parameter),
        SkillRuntimeSpendMetadata::Metered {
            commodity,
            estimated_cost,
            max_cost,
        } => {
            !is_reference(commodity)
                || !portable_positive_decimal(estimated_cost)
                || max_cost
                    .as_deref()
                    .is_some_and(|value| !portable_positive_decimal(value))
        },
        SkillRuntimeSpendMetadata::Counted {
            commodity,
            cost_per_action,
        } => !is_reference(commodity) || !portable_positive_decimal(cost_per_action),
    }) {
        return Err(invalid_runtime_catalog());
    }
    let Some(parameter) = catalog.profile_parameter.as_ref() else {
        return Ok(());
    };
    if !matches!(
        contract.auth.profile_selection,
        ProfileSelection::Selectable { .. }
    ) || parameter.name.is_empty()
        || parameter.name.len() > MAX_CATEGORY_BYTES
        || !portable_model_parameter(&parameter.name)
        || parameter.enum_values.len() > MAX_PROFILE_ENUM_VALUES
        || parameter.enum_values.iter().any(|value| {
            value.is_empty()
                || value.len() > MAX_PROFILE_ALIAS_BYTES
                || !portable_profile_alias(value)
        })
    {
        return Err(invalid_runtime_catalog());
    }
    if let ProfileSelection::Selectable {
        default: Some(default),
    } = &contract.auth.profile_selection
    {
        if !parameter.enum_values.is_empty() && !parameter.enum_values.contains(default) {
            return Err(invalid_runtime_catalog());
        }
    }
    Ok(())
}

fn portable_catalog_name(value: &str) -> bool {
    value.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
    })
}

fn portable_model_parameter(value: &str) -> bool {
    value.bytes().enumerate().all(|(index, byte)| {
        byte.is_ascii_lowercase() || byte == b'_' || (index > 0 && byte.is_ascii_digit())
    })
}

fn portable_profile_alias(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn portable_positive_decimal(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 || value.starts_with('-') {
        return false;
    }
    let mut separator = false;
    let mut digit = false;
    for byte in value.bytes() {
        if byte.is_ascii_digit() {
            digit = true;
        } else if byte == b'.' && !separator {
            separator = true;
        } else {
            return false;
        }
    }
    digit && value.bytes().any(|byte| matches!(byte, b'1'..=b'9'))
}

fn portable_working_directory_default(value: &str) -> bool {
    if value == "." {
        return true;
    }
    !value.is_empty()
        && value.len()
            <= crate::manifest_synthesis::MAX_SYNTHESIZED_WORKING_DIRECTORY_BYTES as usize
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && value
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}

fn invalid_runtime_catalog() -> ManifestParseError {
    ManifestParseError::new(
        ManifestParseErrorCode::InvalidRuntimeCatalog,
        "runtime_catalog is incompatible with the bounded catalog vocabulary",
    )
}

fn parse_frontmatter_document(source: &str) -> Result<Value, ManifestParseError> {
    if source.len() > MAX_SKILL_MARKDOWN_BYTES {
        return Err(ManifestParseError::new(
            ManifestParseErrorCode::SourceTooLarge,
            "SKILL.md exceeds the parser size limit",
        ));
    }
    let frontmatter = extract_frontmatter(source)?;
    if frontmatter.len() > MAX_SKILL_FRONTMATTER_BYTES {
        return Err(ManifestParseError::new(
            ManifestParseErrorCode::FrontmatterTooLarge,
            "SKILL.md frontmatter exceeds the parser size limit",
        ));
    }
    validate_yaml_shape(frontmatter).map_err(|_| {
        ManifestParseError::new(
            ManifestParseErrorCode::UnsafeYamlShape,
            "SKILL.md frontmatter exceeds YAML structural limits",
        )
    })?;
    validate_block_depth(frontmatter)?;
    reject_yaml_references(frontmatter)?;

    let document: Value = serde_yaml::from_str(frontmatter).map_err(|error| {
        ManifestParseError::new(
            ManifestParseErrorCode::InvalidYaml,
            yaml_diagnostic("SKILL.md frontmatter is invalid YAML", &error),
        )
    })?;
    validate_parsed_yaml(&document)?;
    Ok(document)
}

fn parse_contract_value(
    contract_value: &Value,
) -> Result<SkillRuntimeContract, ManifestParseError> {
    let contract_mapping = mapping(contract_value, "runtime_contract")?;
    let version = contract_mapping
        .get(Value::String("schema_version".to_owned()))
        .ok_or_else(|| {
            ManifestParseError::new(
                ManifestParseErrorCode::MissingSchemaVersion,
                "runtime_contract.schema_version is required",
            )
        })?;
    let version = version.as_str().ok_or_else(|| {
        ManifestParseError::new(
            ManifestParseErrorCode::InvalidSchemaVersion,
            "runtime_contract.schema_version must be a string",
        )
    })?;
    if !is_schema_version(version) {
        return Err(ManifestParseError::new(
            ManifestParseErrorCode::InvalidSchemaVersion,
            "runtime_contract.schema_version is not a portable version identifier",
        ));
    }
    if version != SKILL_RUNTIME_CONTRACT_V1 {
        return Err(ManifestParseError::unsupported_version(version));
    }

    let contract: SkillRuntimeContract =
        serde_yaml::from_value(contract_value.clone()).map_err(|error| {
            ManifestParseError::new(
                ManifestParseErrorCode::InvalidRuntimeContract,
                yaml_diagnostic(
                    "runtime_contract does not match the supported v1 vocabulary",
                    &error,
                ),
            )
        })?;
    debug_assert_eq!(contract.schema_version, SkillRuntimeContractVersion::v1());
    Ok(contract)
}

fn extract_frontmatter(source: &str) -> Result<&str, ManifestParseError> {
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    let Some(first_newline) = source.find('\n') else {
        return if source.trim_end_matches('\r') == "---" {
            Err(ManifestParseError::new(
                ManifestParseErrorCode::UnterminatedFrontmatter,
                "SKILL.md frontmatter has no closing delimiter",
            ))
        } else {
            Err(ManifestParseError::new(
                ManifestParseErrorCode::MissingFrontmatter,
                "SKILL.md must start with YAML frontmatter",
            ))
        };
    };
    if source[..first_newline].trim_end_matches('\r') != "---" {
        return Err(ManifestParseError::new(
            ManifestParseErrorCode::MissingFrontmatter,
            "SKILL.md must start with YAML frontmatter",
        ));
    }
    let start = first_newline + 1;
    let mut offset = start;
    for line in source[start..].split_inclusive('\n') {
        if line.trim_end_matches(['\r', '\n']) == "---" {
            return Ok(&source[start..offset]);
        }
        offset = offset.checked_add(line.len()).ok_or_else(|| {
            ManifestParseError::new(
                ManifestParseErrorCode::FrontmatterTooLarge,
                "SKILL.md frontmatter offset overflowed",
            )
        })?;
        if offset.saturating_sub(start) > MAX_SKILL_FRONTMATTER_BYTES {
            return Err(ManifestParseError::new(
                ManifestParseErrorCode::FrontmatterTooLarge,
                "SKILL.md frontmatter exceeds the parser size limit",
            ));
        }
    }
    Err(ManifestParseError::new(
        ManifestParseErrorCode::UnterminatedFrontmatter,
        "SKILL.md frontmatter has no closing delimiter",
    ))
}

fn validate_parsed_yaml(root: &Value) -> Result<(), ManifestParseError> {
    let mut pending = vec![(root, 0usize)];
    let mut nodes = 0usize;
    while let Some((value, depth)) = pending.pop() {
        nodes = nodes.checked_add(1).ok_or_else(|| {
            ManifestParseError::new(
                ManifestParseErrorCode::ParsedYamlTooLarge,
                "parsed YAML node count overflowed",
            )
        })?;
        if nodes > MAX_PARSED_YAML_NODES || depth > MAX_PARSED_YAML_DEPTH {
            return Err(ManifestParseError::new(
                ManifestParseErrorCode::ParsedYamlTooLarge,
                "parsed YAML exceeds the depth or node limit",
            ));
        }
        match value {
            Value::Sequence(values) => {
                pending.extend(values.iter().map(|value| (value, depth + 1)));
            },
            Value::Mapping(values) => {
                for (key, value) in values {
                    pending.push((key, depth + 1));
                    pending.push((value, depth + 1));
                }
            },
            Value::Tagged(_) => {
                return Err(ManifestParseError::new(
                    ManifestParseErrorCode::YamlTagsUnsupported,
                    "SKILL.md frontmatter may not use YAML tags",
                ));
            },
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {},
        }
    }
    Ok(())
}

fn mapping<'a>(value: &'a Value, label: &str) -> Result<&'a Mapping, ManifestParseError> {
    value.as_mapping().ok_or_else(|| {
        ManifestParseError::new(
            ManifestParseErrorCode::InvalidEnvelope,
            format!("{label} must be a mapping"),
        )
    })
}

fn mapping_value<'a>(mapping: &'a Mapping, key: &str) -> Option<&'a Value> {
    mapping.get(Value::String(key.to_owned()))
}

fn validate_block_depth(source: &str) -> Result<(), ManifestParseError> {
    let mut indentation = Vec::<usize>::new();
    let mut block_scalar_indent = None;
    for line in source.lines() {
        let leading_spaces = line.bytes().take_while(|byte| *byte == b' ').count();
        if let Some(indent) = block_scalar_indent {
            if leading_spaces > indent {
                continue;
            }
            block_scalar_indent = None;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        while indentation
            .last()
            .is_some_and(|indent| *indent >= leading_spaces)
        {
            indentation.pop();
        }
        indentation.push(leading_spaces);

        let mut compact_sequences = 0usize;
        let mut remainder = line.trim_start();
        while let Some(rest) = remainder
            .strip_prefix("- ")
            .or_else(|| remainder.strip_prefix("? "))
        {
            compact_sequences += 1;
            remainder = rest;
        }
        if indentation.len().saturating_add(compact_sequences) > MAX_PARSED_YAML_DEPTH {
            return Err(ManifestParseError::new(
                ManifestParseErrorCode::UnsafeYamlShape,
                "SKILL.md frontmatter exceeds the YAML block-depth limit",
            ));
        }
        if block_scalar_indicator(line) {
            block_scalar_indent = Some(leading_spaces);
        }
    }
    Ok(())
}

fn is_schema_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn yaml_diagnostic(prefix: &str, error: &serde_yaml::Error) -> String {
    error.location().map_or_else(
        || prefix.to_owned(),
        |location| {
            format!(
                "{prefix} at line {}, column {}",
                location.line(),
                location.column()
            )
        },
    )
}

fn reject_yaml_references(source: &str) -> Result<(), ManifestParseError> {
    let mut block_scalar_indent = None;
    for line in source.lines() {
        let leading_spaces = line.bytes().take_while(|byte| *byte == b' ').count();
        if let Some(indent) = block_scalar_indent {
            if leading_spaces > indent {
                continue;
            }
            block_scalar_indent = None;
        }
        if block_scalar_indicator(line) {
            block_scalar_indent = Some(leading_spaces);
            continue;
        }
        let mut single_quoted = false;
        let mut double_quoted = false;
        let mut escaped = false;
        let bytes = line.as_bytes();
        for (index, byte) in bytes.iter().copied().enumerate() {
            if escaped {
                escaped = false;
                continue;
            }
            if double_quoted && byte == b'\\' {
                escaped = true;
                continue;
            }
            match byte {
                b'\'' if !double_quoted => single_quoted = !single_quoted,
                b'"' if !single_quoted => double_quoted = !double_quoted,
                b'#' if !single_quoted && !double_quoted => break,
                b'&' | b'*' if !single_quoted && !double_quoted => {
                    let boundary = index == 0
                        || bytes[index - 1].is_ascii_whitespace()
                        || matches!(bytes[index - 1], b'[' | b'{' | b',' | b':' | b'-');
                    let named = bytes
                        .get(index + 1)
                        .is_some_and(|next| next.is_ascii_alphanumeric() || *next == b'_');
                    if boundary && named {
                        return Err(ManifestParseError::new(
                            ManifestParseErrorCode::YamlReferencesUnsupported,
                            "SKILL.md frontmatter may not use YAML anchors or aliases",
                        ));
                    }
                },
                _ => {},
            }
        }
    }
    Ok(())
}

fn block_scalar_indicator(line: &str) -> bool {
    let without_comment = line.split('#').next().unwrap_or_default().trim_end();
    let Some((_, indicator)) = without_comment.rsplit_once(':') else {
        return false;
    };
    let indicator = indicator.trim();
    let mut characters = indicator.chars();
    matches!(characters.next(), Some('|' | '>'))
        && characters.all(|character| character.is_ascii_digit() || matches!(character, '+' | '-'))
}

fn bounded_diagnostic(value: &str) -> String {
    if value.len() <= MAX_DIAGNOSTIC_BYTES {
        return value.to_owned();
    }
    let mut end = MAX_DIAGNOSTIC_BYTES;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{AuthKind, RuntimeProtocol};

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct FixtureExtension {
        schema_version: u32,
        action: String,
    }

    fn skill(contract: &str) -> String {
        format!(
            "---\nname: fixture\nversion: 0.1.0\ndescription: fixture\nmetadata:\n  magician:\n    skill_type: tool\n    install_hint:\n      docs: |\n        Literal *not-an-alias and &not-an-anchor text.\n    runtime_contract:\n{}---\n# Body\n",
            contract
                .lines()
                .map(|line| format!("      {line}\n"))
                .collect::<String>()
        )
    }

    fn cli_contract() -> &'static str {
        "schema_version: tool-runtime.skill-runtime.v1\nrequires:\n  bins: [jq]\nruntime:\n  protocol: cli\n  command_prefix: []\n"
    }

    fn error_code(source: &str) -> ManifestParseErrorCode {
        parse_skill_runtime_contract(source)
            .expect_err("fixture must fail")
            .code
    }

    #[test]
    fn extracts_contract_while_ignoring_known_or_future_outer_metadata() {
        let parsed = parse_skill_runtime_contract(&skill(cli_contract()))
            .expect("parse contract")
            .expect("contract present");

        assert_eq!(parsed.auth.kind, AuthKind::None);
        assert!(matches!(parsed.runtime, RuntimeProtocol::Cli { .. }));
    }

    #[test]
    fn valid_legacy_frontmatter_without_runtime_contract_is_not_opted_in() {
        let source = "---\nname: legacy\nmetadata:\n  magician:\n    requires:\n      bins: [jq]\n---\nbody\n";
        assert_eq!(parse_skill_runtime_contract(source).unwrap(), None);
    }

    #[test]
    fn typed_magician_extension_uses_the_same_bounded_frontmatter() {
        let source = r#"---
name: fixture
description: fixture
metadata:
  magician:
    content_reader:
      schema_version: 1
      action: convert
---
Body.
"#;

        let parsed = parse_skill_magician_extension::<FixtureExtension>(source, "content_reader")
            .unwrap()
            .unwrap();

        assert_eq!(
            parsed,
            FixtureExtension {
                schema_version: 1,
                action: "convert".to_owned(),
            }
        );
        assert!(
            parse_skill_magician_extension::<FixtureExtension>(source, "content_source")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn typed_magician_extension_rejects_unknown_fields_and_invalid_names() {
        let unknown = r#"---
name: fixture
description: fixture
metadata:
  magician:
    content_reader:
      schema_version: 1
      action: convert
      surprise: true
---
Body.
"#;
        assert_eq!(
            parse_skill_magician_extension::<FixtureExtension>(unknown, "content_reader")
                .unwrap_err()
                .code,
            ManifestParseErrorCode::InvalidMagicianExtension
        );
        assert_eq!(
            parse_skill_magician_extension::<FixtureExtension>(unknown, "Content-Reader")
                .unwrap_err()
                .code,
            ManifestParseErrorCode::InvalidMagicianExtension
        );
    }

    #[test]
    fn complete_runtime_package_parses_actions_and_catalog_from_one_skill_file() {
        let source = r#"---
name: fixture
description: fixture
metadata:
  magician:
    runtime_contract:
      schema_version: tool-runtime.skill-runtime.v1
      requires:
        bins: [gws]
      runtime:
        protocol: cli
        command_prefix: []
    runtime_actions:
      schema_version: tool-runtime.typed-action-overrides.v1
      actions:
        list:
          description: List bounded records.
          fixed_args: [records, list]
          parameters:
            args:
              type: string_array
              description: Exact bounded argv.
              required: true
              max_items: 8
              max_item_bytes: 64
          mappings:
            - type: passthrough
              parameter: args
    runtime_catalog:
      categories: [productivity, records]
      composition_category: record_operations
---
# Body
"#;
        let package = parse_skill_runtime_package(source)
            .expect("parse package")
            .expect("package present");
        assert_eq!(package.contract.requires.bins.len(), 1);
        assert!(package
            .actions
            .as_ref()
            .is_some_and(|actions| actions.actions.contains_key("list")));
        assert_eq!(
            package.catalog.categories,
            vec!["productivity".to_owned(), "records".to_owned()]
        );
        assert_eq!(
            package.catalog.composition_category.as_deref(),
            Some("record_operations")
        );
    }

    #[test]
    fn working_directory_catalog_control_is_bounded_and_requires_workspace_authority() {
        let valid = r#"---
name: fixture
metadata:
  magician:
    runtime_contract:
      schema_version: tool-runtime.skill-runtime.v1
      requires: {bins: [fixture]}
      runtime:
        protocol: cli
        command_prefix: []
        working_directory: {mode: workspace}
    runtime_catalog:
      expose_working_directory_control: true
      working_directory_default: .
---
"#;
        let package = parse_skill_runtime_package(valid)
            .expect("parse package")
            .expect("package present");
        assert!(package.catalog.expose_working_directory_control);
        assert_eq!(
            package.catalog.working_directory_default.as_deref(),
            Some(".")
        );

        for invalid in [
            valid.replace("      expose_working_directory_control: true\n", ""),
            valid.replace(
                "working_directory_default: .",
                "working_directory_default: /tmp",
            ),
            valid.replace(
                "        working_directory: {mode: workspace}",
                "        working_directory: {mode: denied}",
            ),
        ] {
            assert_eq!(
                parse_skill_runtime_package(&invalid)
                    .expect_err("invalid working-directory catalog")
                    .code,
                ManifestParseErrorCode::InvalidRuntimeCatalog
            );
        }
    }

    #[test]
    fn selectable_profile_can_publish_one_bounded_model_parameter_alias() {
        let source = r#"---
name: fixture
metadata:
  magician:
    runtime_contract:
      schema_version: tool-runtime.skill-runtime.v1
      requires: {bins: [gws]}
      runtime: {protocol: cli, command_prefix: []}
      auth:
        kind: cli_profile
        requirement: required
        provider: google-workspace
        profile_selection: {mode: selectable, default: work}
        storage: {kind: scoped_directory, namespace: gws, partition_by_profile: true}
    runtime_catalog:
      profile_parameter:
        name: account
        enum_values: [work, personal, business]
---
"#;
        let package = parse_skill_runtime_package(source)
            .expect("parse package")
            .expect("package present");
        let projected = package
            .projected_profile_parameter()
            .expect("profile projection");
        assert_eq!(projected.name, "account");
        assert_eq!(
            projected.enum_values.expect("finite aliases"),
            &[
                "business".to_owned(),
                "personal".to_owned(),
                "work".to_owned()
            ]
            .into_iter()
            .collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn profile_parameter_metadata_fails_closed_for_nonselectable_or_missing_default_alias() {
        let fixed = r#"---
name: fixture
metadata:
  magician:
    runtime_contract:
      schema_version: tool-runtime.skill-runtime.v1
      requires: {bins: [gws]}
      runtime: {protocol: cli, command_prefix: []}
      auth:
        kind: cli_profile
        requirement: required
        provider: google-workspace
        profile_selection: {mode: fixed, alias: work}
        storage: {kind: scoped_directory, namespace: gws, partition_by_profile: true}
    runtime_catalog:
      profile_parameter: {name: account, enum_values: [work]}
---
"#;
        assert_eq!(
            parse_skill_runtime_package(fixed)
                .expect_err("fixed profile cannot publish a selector alias")
                .code,
            ManifestParseErrorCode::InvalidRuntimeCatalog
        );

        let missing_default = fixed
            .replace(
                "{mode: fixed, alias: work}",
                "{mode: selectable, default: work}",
            )
            .replace("enum_values: [work]", "enum_values: [personal]");
        assert_eq!(
            parse_skill_runtime_package(&missing_default)
                .expect_err("finite aliases must retain the declared default")
                .code,
            ManifestParseErrorCode::InvalidRuntimeCatalog
        );
    }

    #[test]
    fn runtime_actions_without_contract_fail_closed() {
        let source = r#"---
name: fixture
metadata:
  magician:
    runtime_actions:
      schema_version: tool-runtime.typed-action-overrides.v1
      actions: {}
---
"#;
        assert_eq!(
            parse_skill_runtime_package(source)
                .expect_err("actions cannot opt in alone")
                .code,
            ManifestParseErrorCode::ActionsWithoutRuntimeContract
        );
    }

    #[test]
    fn bom_crlf_and_body_content_do_not_change_contract_parsing() {
        let source =
            skill(cli_contract())
                .replace('\n', "\r\n")
                .replacen("---\r\n", "\u{feff}---\r\n", 1)
                + "\n&body_anchor body YAML is not frontmatter\n";
        assert!(parse_skill_runtime_contract(&source).unwrap().is_some());
    }

    #[test]
    fn missing_and_unterminated_frontmatter_are_distinct() {
        assert_eq!(
            error_code("# no frontmatter\n"),
            ManifestParseErrorCode::MissingFrontmatter
        );
        assert_eq!(
            error_code("---\nname: unfinished\n"),
            ManifestParseErrorCode::UnterminatedFrontmatter
        );
    }

    #[test]
    fn source_and_frontmatter_limits_fail_before_yaml_deserialization() {
        let oversized_source = "x".repeat(MAX_SKILL_MARKDOWN_BYTES + 1);
        assert_eq!(
            error_code(&oversized_source),
            ManifestParseErrorCode::SourceTooLarge
        );
        let oversized_frontmatter = format!(
            "---\nvalue: {}\n---\n",
            "x".repeat(MAX_SKILL_FRONTMATTER_BYTES)
        );
        assert_eq!(
            error_code(&oversized_frontmatter),
            ManifestParseErrorCode::FrontmatterTooLarge
        );
    }

    #[test]
    fn deep_yaml_references_and_tags_fail_closed() {
        let deep = format!("---\nmetadata:\n{}magician: {{}}\n---\n", " ".repeat(257));
        assert_eq!(error_code(&deep), ManifestParseErrorCode::UnsafeYamlShape);
        let compact = format!("---\n{}value\n---\n", "- ".repeat(65));
        assert_eq!(
            error_code(&compact),
            ManifestParseErrorCode::UnsafeYamlShape
        );
        let compact_mapping = format!("---\n{}value\n---\n", "? ".repeat(65));
        assert_eq!(
            error_code(&compact_mapping),
            ManifestParseErrorCode::UnsafeYamlShape
        );
        let nested = (0..65)
            .map(|depth| format!("{}key_{depth}:\n", " ".repeat(depth)))
            .collect::<String>();
        assert_eq!(
            error_code(&format!("---\n{nested}---\n")),
            ManifestParseErrorCode::UnsafeYamlShape
        );
        let alias = "---\nbase: &base {x: 1}\ncopy: *base\n---\n";
        assert_eq!(
            error_code(alias),
            ManifestParseErrorCode::YamlReferencesUnsupported
        );
        let tagged = "---\nmetadata: !custom {}\n---\n";
        assert_eq!(
            error_code(tagged),
            ManifestParseErrorCode::YamlTagsUnsupported
        );
    }

    #[test]
    fn parsed_node_budget_rejects_wide_documents_iteratively() {
        let entries = (0..10_100)
            .map(|index| format!("key_{index}: {index}\n"))
            .collect::<String>();
        let source = format!("---\n{entries}---\n");

        assert!(source.len() < MAX_SKILL_FRONTMATTER_BYTES);
        assert_eq!(
            error_code(&source),
            ManifestParseErrorCode::ParsedYamlTooLarge
        );
    }

    #[test]
    fn hostile_depth_is_rejected_on_a_small_stack() {
        let source = format!("---\n{}value\n---\n", "- ".repeat(65));
        let result = std::thread::Builder::new()
            .name("manifest-parser-small-stack".to_owned())
            .stack_size(128 * 1024)
            .spawn(move || error_code(&source))
            .expect("spawn small-stack parser")
            .join()
            .expect("parser must not panic or overflow");

        assert_eq!(result, ManifestParseErrorCode::UnsafeYamlShape);
    }

    #[test]
    fn malformed_envelopes_and_yaml_have_typed_diagnostics() {
        assert_eq!(
            error_code("---\nmetadata: [not, a, map]\n---\n"),
            ManifestParseErrorCode::InvalidEnvelope
        );
        assert_eq!(
            error_code("---\nmetadata: {broken\n---\n"),
            ManifestParseErrorCode::InvalidYaml
        );
    }

    #[test]
    fn missing_non_string_and_forward_versions_are_distinct() {
        let missing = skill("runtime:\n  protocol: cli\n");
        assert_eq!(
            error_code(&missing),
            ManifestParseErrorCode::MissingSchemaVersion
        );
        let non_string = skill("schema_version: 1\nruntime:\n  protocol: cli\n");
        assert_eq!(
            error_code(&non_string),
            ManifestParseErrorCode::InvalidSchemaVersion
        );
        let forward =
            skill("schema_version: tool-runtime.skill-runtime.v2\nfuture_security_field: true\n");
        let error = parse_skill_runtime_contract(&forward).expect_err("forward version");
        assert_eq!(error.code, ManifestParseErrorCode::UnsupportedSchemaVersion);
        assert_eq!(
            error.found_version.as_deref(),
            Some("tool-runtime.skill-runtime.v2")
        );
        assert_eq!(
            error.supported_versions,
            vec![SKILL_RUNTIME_CONTRACT_V1.to_owned()]
        );
        let diagnostic = serde_json::to_value(&error).expect("serialize diagnostic");
        assert_eq!(
            diagnostic.get("code"),
            Some(&serde_json::json!("unsupported_schema_version"))
        );

        let secret_canary = "secret-canary-".to_owned() + &"x".repeat(200);
        let invalid = skill(&format!(
            "schema_version: {secret_canary}\nruntime:\n  protocol: cli\n"
        ));
        let error = parse_skill_runtime_contract(&invalid).expect_err("invalid version");
        assert_eq!(error.code, ManifestParseErrorCode::InvalidSchemaVersion);
        assert_eq!(error.found_version, None);
        assert!(!error.message.contains(&secret_canary));
    }

    #[test]
    fn unknown_or_duplicate_v1_contract_fields_fail_closed() {
        let unknown = skill(
            "schema_version: tool-runtime.skill-runtime.v1\nruntime:\n  protocol: cli\nraw_token: forbidden\n",
        );
        assert_eq!(
            error_code(&unknown),
            ManifestParseErrorCode::InvalidRuntimeContract
        );
        let duplicate = skill(
            "schema_version: tool-runtime.skill-runtime.v1\nschema_version: tool-runtime.skill-runtime.v1\nruntime:\n  protocol: cli\n",
        );
        assert_eq!(error_code(&duplicate), ManifestParseErrorCode::InvalidYaml);
    }

    #[test]
    fn diagnostics_are_bounded_and_do_not_echo_scalar_values() {
        let secret_canary = "secret-canary-".to_owned() + &"x".repeat(700);
        let source = skill(&format!(
            "schema_version: tool-runtime.skill-runtime.v1\nruntime:\n  protocol: cli\nunknown: {secret_canary}\n"
        ));
        let error = parse_skill_runtime_contract(&source).expect_err("unknown field");

        assert!(error.message.len() <= MAX_DIAGNOSTIC_BYTES + '…'.len_utf8());
        assert!(!error.message.contains(&secret_canary));
    }

    #[test]
    fn missing_expose_defaults_to_agents_only() {
        let source = r#"---
name: fixture
description: fixture
metadata:
  magician:
    skill_type: tool
---
# Body
"#;
        let expose = parse_skill_expose(source).expect("default expose");
        assert!(expose.agents);
        assert!(!expose.apps);
    }

    #[test]
    fn explicit_expose_apps_is_honored_and_agents_default_remains_true() {
        let source = r#"---
name: fixture
description: fixture
metadata:
  magician:
    skill_type: tool
    expose:
      apps: true
---
# Body
"#;
        let expose = parse_skill_expose(source).expect("explicit apps expose");
        assert!(expose.agents);
        assert!(expose.apps);
    }

    #[test]
    fn expose_can_hide_a_skill_from_both_audiences() {
        let source = r#"---
name: fixture
description: fixture
metadata:
  magician:
    skill_type: tool
    expose:
      agents: false
      apps: false
---
# Body
"#;
        let expose = parse_skill_expose(source).expect("hidden expose");
        assert!(!expose.agents);
        assert!(!expose.apps);
    }

    #[test]
    fn unknown_expose_fields_fail_closed() {
        let source = r#"---
name: fixture
description: fixture
metadata:
  magician:
    skill_type: tool
    expose:
      apps: true
      marketplace: true
---
# Body
"#;
        assert_eq!(
            parse_skill_expose(source)
                .expect_err("unknown expose field")
                .code,
            ManifestParseErrorCode::InvalidMagicianExtension
        );
    }
}
