//! Credential-free Phase 0C replay fixtures for schema-backed tool actions.
//!
//! This compiler projects the checked-in schema source into a bounded, typed
//! description of the invocation that today's runtime would perform. It never
//! reads process environment, runtime configuration, secret stores, auth hook
//! bodies, parameter defaults, descriptions, or adapter contents.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};

use crate::{
    action_overrides::{
        compile_typed_action_overrides, TypedActionInputDelivery, TypedActionParameter,
        TypedArgumentMapping, TypedArgumentRules,
    },
    classification::{
        ApprovalClass, AuthStrategy, ClassificationCompiler, ClassificationManifest,
        ProfileClassification, RuntimeOwner, SourceClassification, CLASSIFICATION_SCHEMA_VERSION,
    },
    inventory::{
        read_bounded_utf8, validate_yaml_shape, SourceInventory, SourceInventoryScanner,
        ToolSkillSourceInventory, SOURCE_INVENTORY_SCHEMA_VERSION,
    },
    manifest::{
        AuthStorage, InjectionSource, InjectionTarget, ProfileSelection, RuntimeProtocol,
        WorkingDirectoryMode,
    },
    manifest_parser::parse_skill_runtime_package,
    manifest_validation::validate_skill_runtime_contract,
    mcp_catalog_projection::{project_mcp_catalog, McpCatalogParameterProjection},
};

pub const REPLAY_FIXTURE_SCHEMA_VERSION: &str = "tool-runtime.replay-fixtures.v1";
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_ENV_BINDINGS: usize = 512;
const MAX_ACTIONS_PER_SKILL: usize = 2_048;
const MAX_PARAMETERS_PER_ACTION: usize = 2_048;
const MAX_ROOT_PARAMETERS: usize = 2_048;
const MAX_ARG_MAPPINGS: usize = 4_096;
const MAX_STATIC_TOKENS: usize = 8_192;
const MAX_TOTAL_SKILLS: usize = 1_024;
const MAX_TOTAL_FIXTURES: usize = 100_000;
const MAX_TOTAL_PROJECTED_RECORDS: usize = 2_000_000;
const MAX_TOTAL_SCHEMA_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PARSED_YAML_NODES: usize = 250_000;
const MAX_PARSED_YAML_DEPTH: usize = 256;
const MAX_YAML_REFERENCES: usize = 4_096;
const MAX_ALIAS_EXPANDED_BYTES: usize = 16 * 1024 * 1024;
const RESERVED_BROWSER_SKILL_ID: &str = "browser";

const GOOGLE_WORKSPACE_SKILLS: [&str; 6] = [
    "calendar",
    "gmail",
    "presto-calendar",
    "presto-gmail",
    "presto-sheets",
    "sheets",
];
const EXPECTED_GOOGLE_WORKSPACE_ACTIONS: usize = 98;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayFixtureCatalog {
    pub schema_version: String,
    pub source_inventory_schema_version: String,
    pub source_classification_schema_version: String,
    pub summary: ReplaySummary,
    pub fixtures: Vec<ReplayFixture>,
}

impl ReplayFixtureCatalog {
    pub fn to_pretty_json(&self) -> Result<String> {
        let mut rendered =
            serde_json::to_string_pretty(self).context("serializing replay fixtures as JSON")?;
        rendered.push('\n');
        Ok(rendered)
    }

    pub fn to_markdown(&self) -> String {
        let mut out = String::from(
            "# Tool Runtime Phase 0C Replay Fixtures\n\n\
             This generated report freezes the credential-free invocation shape of every \
             current schema action. It records executable identity, exact static argv, typed \
             argument mappings, safe environment names, profile policy, approval, timeout, \
             and output class. It never reads or records credential values, environment \
             values, parameter defaults, auth command bodies, descriptions, or adapter \
             contents. Production dispatch is unchanged.\n\n",
        );
        out.push_str("## Summary\n\n");
        out.push_str(&format!(
            "- Schema version: `{}`\n\
             - Replay fixtures: {}\n\
             - Google Workspace fixtures: {}\n\
             - Primitive process fixtures: {}\n\
             - Command process fixtures: {}\n\
             - Compiled-provider fixtures: {}\n\
             - Official MCP SDK fixtures: {}\n\
             - Fixtures accepting stdin: {}\n\
             - Declared environment bindings: {}\n\
             - Explicitly recorded ignored legacy fields: {}\n\n",
            self.schema_version,
            self.summary.fixtures,
            self.summary.google_workspace_fixtures,
            self.summary.primitive_process_fixtures,
            self.summary.command_process_fixtures,
            self.summary.compiled_provider_fixtures,
            self.summary.official_mcp_sdk_fixtures,
            self.summary.stdin_fixtures,
            self.summary.environment_bindings,
            self.summary.ignored_legacy_fields,
        ));

        out.push_str("## Skills\n\n");
        out.push_str(
            "| Skill | Fixtures | Dispatch | Approval | Profile | Required env | Ignored legacy fields |\n\
             |---|---:|---|---|---|---:|---:|\n",
        );
        let mut skills: BTreeMap<&str, Vec<&ReplayFixture>> = BTreeMap::new();
        for fixture in &self.fixtures {
            skills.entry(&fixture.skill_id).or_default().push(fixture);
        }
        for (skill, fixtures) in skills {
            let dispatch = fixtures
                .iter()
                .map(|fixture| enum_label(&fixture.dispatch.kind))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ");
            let first = fixtures[0];
            let ignored = fixtures
                .iter()
                .map(|fixture| fixture.ignored_legacy_fields.len())
                .sum::<usize>();
            out.push_str(&format!(
                "| `{}` | {} | `{}` | `{}` | `{}` / `{}` | {} | {} |\n",
                markdown_cell(skill),
                fixtures.len(),
                markdown_cell(&dispatch),
                enum_label(&first.approval_class),
                enum_label(&first.profile.policy),
                enum_label(&first.profile.source),
                first.environment.required_names.len(),
                ignored,
            ));
        }

        out.push_str("\n## Contract notes\n\n");
        out.push_str(
            "- `primitive_process` mirrors the current CLI-template dispatcher: the \
             implementation command (or skill id fallback), action argv/name, action \
             mappings, action suffix, then implementation suffix.\n\
             - `command_process` mirrors the current command provider: implementation \
             fixed args, implementation mappings, then implementation suffix. Action-level \
             argv/mapping metadata is listed as ignored when present.\n\
             - `compiled_provider` records a typed schema boundary without inventing a \
             subprocess recipe.\n\
             - `official_mcp_sdk` records the stable product controls above live SDK \
             discovery without freezing remote provider tool schemas.\n\
             - Environment bindings retain only variable names and placeholder names. \
             Literal environment content is represented by a boolean and is never copied.\n",
        );
        out
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplaySummary {
    pub fixtures: usize,
    pub google_workspace_fixtures: usize,
    pub primitive_process_fixtures: usize,
    pub command_process_fixtures: usize,
    pub compiled_provider_fixtures: usize,
    #[serde(default)]
    pub official_mcp_sdk_fixtures: usize,
    pub stdin_fixtures: usize,
    pub environment_bindings: usize,
    pub ignored_legacy_fields: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayFixture {
    pub id: String,
    pub skill_id: String,
    pub action_name: String,
    pub runtime_owner: RuntimeOwner,
    pub approval_class: ApprovalClass,
    pub auth_strategies: Vec<AuthStrategy>,
    pub profile: ProfileClassification,
    pub dispatch: ReplayDispatch,
    pub parameters: Vec<ReplayParameter>,
    pub environment: ReplayEnvironment,
    pub cwd: Option<TemplateShape>,
    pub stdin: ReplayStdin,
    pub timeout: ReplayTimeout,
    pub output_class: OutputClass,
    pub ignored_legacy_fields: Vec<IgnoredLegacyField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayDispatch {
    pub kind: DispatchKind,
    pub program: Option<String>,
    pub provider_name: Option<String>,
    pub prefix_args: Vec<String>,
    pub action_args: Vec<String>,
    pub argument_mode: ArgumentMode,
    pub mappings: Vec<ReplayArgMapping>,
    pub action_suffix_args: Vec<String>,
    pub implementation_suffix_args: Vec<String>,
    #[serde(default, skip_serializing_if = "TypedArgumentRules::is_empty")]
    pub argument_rules: TypedArgumentRules,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchKind {
    PrimitiveProcess,
    CommandProcess,
    CompiledProvider,
    OfficialMcpSdk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgumentMode {
    ExplicitMappings,
    CanonicalJsonStdin,
    ArgsOrSortedFlags,
    ImplementationMappings,
    CompiledSchema,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReplayArgMapping {
    Positional { param: String },
    Flag { flag: String, param: String },
    BoolFlag { flag: String, param: String },
    SplitPositional { param: String },
    EnvFlag { flag: String, env_var: String },
    FixedArgs { args: Vec<String> },
    Passthrough { param: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayParameter {
    pub name: String,
    pub value_kind: ReplayValueKind,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayValueKind {
    String,
    Integer,
    Number,
    Boolean,
    Array,
    Object,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayEnvironment {
    pub required_names: Vec<String>,
    pub bindings: Vec<EnvironmentBinding>,
    pub mapping_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentBinding {
    pub name: String,
    pub placeholder_names: Vec<String>,
    pub contains_literal_component: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateShape {
    pub placeholder_names: Vec<String>,
    pub contains_literal_component: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayStdin {
    pub accepted: bool,
    pub parameter_declared: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayTimeout {
    pub default_secs: Option<u64>,
    pub source: TimeoutSource,
    pub caller_override_supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeoutSource {
    Action,
    Implementation,
    Execution,
    RuntimePrimitiveDefault,
    RuntimeCommandDefault,
    CompiledProviderDefault,
    OfficialMcpSdkDefault,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputClass {
    ToolOutput,
    Email,
    Web,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IgnoredLegacyField {
    PrimitiveProgram,
    PrimitiveFixedArgs,
    PrimitiveArgMappings,
    PrimitiveContentType,
    CommandActionArgv,
    CommandActionSkipToolName,
    CommandActionArgMappings,
    CommandActionSuffixArgs,
    CommandActionTimeout,
    CompiledCommand,
    CompiledCwd,
    CompiledEnv,
    CompiledSuffixArgs,
    CompiledTimeout,
}

pub struct ReplayCompiler;

impl ReplayCompiler {
    pub fn compile(
        skill_root: impl AsRef<Path>,
        inventory: &SourceInventory,
        classification_manifest: ClassificationManifest,
        classification: &SourceClassification,
    ) -> Result<ReplayFixtureCatalog> {
        let skill_root = skill_root.as_ref();
        validate_inputs(inventory, classification)?;
        validate_schema_sources(skill_root, inventory)?;
        let observed_inventory =
            SourceInventoryScanner::new(skill_root, inventory.source_root.clone())?.scan()?;
        if &observed_inventory != inventory {
            return Err(anyhow!(
                "source inventory is stale or does not describe the selected skill root"
            ));
        }
        let observed_classification =
            ClassificationCompiler::compile(inventory, classification_manifest)?;
        if &observed_classification != classification {
            return Err(anyhow!(
                "source classification is stale or does not match its authoring manifest"
            ));
        }
        Self::compile_inventory_join(skill_root, inventory, classification)
    }

    fn compile_inventory_join(
        skill_root: &Path,
        inventory: &SourceInventory,
        classification: &SourceClassification,
    ) -> Result<ReplayFixtureCatalog> {
        validate_inputs(inventory, classification)?;
        if !skill_root.is_dir() {
            return Err(anyhow!(
                "skill root '{}' is not a directory",
                skill_root.display()
            ));
        }

        if inventory.summary.schema_actions > MAX_TOTAL_FIXTURES {
            return Err(anyhow!(
                "inventory action count exceeds the replay fixture safety limit"
            ));
        }
        let classified = classification
            .skills
            .iter()
            .map(|skill| (skill.id.as_str(), skill))
            .collect::<BTreeMap<_, _>>();
        let mut fixtures = Vec::with_capacity(inventory.summary.schema_actions);
        let mut remaining_projection_records = MAX_TOTAL_PROJECTED_RECORDS;
        let mut errors = Vec::new();
        for source_skill in &inventory.skills {
            let Some(classified_skill) = classified.get(source_skill.id.as_str()) else {
                continue;
            };
            match compile_skill(
                skill_root,
                source_skill,
                classified_skill,
                &mut remaining_projection_records,
            ) {
                Ok(mut compiled) => fixtures.append(&mut compiled),
                Err(error) => errors.push(format!("{}: {error:#}", source_skill.id)),
            }
        }
        if !errors.is_empty() {
            errors.sort();
            return Err(anyhow!(
                "replay fixture contract has {} error(s):\n- {}",
                errors.len(),
                errors.join("\n- ")
            ));
        }
        fixtures.sort_by(|left, right| left.id.cmp(&right.id));
        let unique_ids = fixtures
            .iter()
            .map(|fixture| fixture.id.as_str())
            .collect::<BTreeSet<_>>();
        if unique_ids.len() != fixtures.len() {
            return Err(anyhow!("replay fixture ids are not unique"));
        }
        if fixtures.len() != inventory.summary.schema_actions {
            return Err(anyhow!(
                "compiled {} fixtures for {} inventoried actions",
                fixtures.len(),
                inventory.summary.schema_actions
            ));
        }
        validate_google_workspace_coverage(inventory, &fixtures)?;

        let summary = ReplaySummary {
            fixtures: fixtures.len(),
            google_workspace_fixtures: fixtures
                .iter()
                .filter(|fixture| GOOGLE_WORKSPACE_SKILLS.contains(&fixture.skill_id.as_str()))
                .count(),
            primitive_process_fixtures: count_dispatch(&fixtures, DispatchKind::PrimitiveProcess),
            command_process_fixtures: count_dispatch(&fixtures, DispatchKind::CommandProcess),
            compiled_provider_fixtures: count_dispatch(&fixtures, DispatchKind::CompiledProvider),
            official_mcp_sdk_fixtures: count_dispatch(&fixtures, DispatchKind::OfficialMcpSdk),
            stdin_fixtures: fixtures
                .iter()
                .filter(|fixture| fixture.stdin.accepted)
                .count(),
            environment_bindings: fixtures
                .iter()
                .map(|fixture| fixture.environment.bindings.len())
                .sum(),
            ignored_legacy_fields: fixtures
                .iter()
                .map(|fixture| fixture.ignored_legacy_fields.len())
                .sum(),
        };
        Ok(ReplayFixtureCatalog {
            schema_version: REPLAY_FIXTURE_SCHEMA_VERSION.to_string(),
            source_inventory_schema_version: inventory.schema_version.clone(),
            source_classification_schema_version: classification.schema_version.clone(),
            summary,
            fixtures,
        })
    }
}

fn validate_inputs(
    inventory: &SourceInventory,
    classification: &SourceClassification,
) -> Result<()> {
    let mut errors = Vec::new();
    if inventory.schema_version != SOURCE_INVENTORY_SCHEMA_VERSION {
        errors.push(format!(
            "source inventory schema '{}' does not equal '{}'",
            inventory.schema_version, SOURCE_INVENTORY_SCHEMA_VERSION
        ));
    }
    if inventory.has_errors() {
        errors.push("source inventory contains error findings".to_string());
    }
    if classification.schema_version != CLASSIFICATION_SCHEMA_VERSION {
        errors.push(format!(
            "source classification schema '{}' does not equal '{}'",
            classification.schema_version, CLASSIFICATION_SCHEMA_VERSION
        ));
    }
    if classification.source_inventory_schema_version != inventory.schema_version {
        errors.push("classification does not target this inventory schema".to_string());
    }
    let source_ids = inventory
        .skills
        .iter()
        .map(|skill| skill.id.as_str())
        .collect::<BTreeSet<_>>();
    let classified_ids = classification
        .skills
        .iter()
        .map(|skill| skill.id.as_str())
        .collect::<BTreeSet<_>>();
    if inventory.skills.len() != source_ids.len() {
        errors.push("source inventory contains a duplicate skill id".to_string());
    }
    if source_ids != classified_ids {
        errors
            .push("classification skill ids do not exactly match inventory skill ids".to_string());
    }
    if classification.skills.len() != classified_ids.len() {
        errors.push("classification contains a duplicate skill id".to_string());
    }
    if inventory.skills.len() > MAX_TOTAL_SKILLS || classification.skills.len() > MAX_TOTAL_SKILLS {
        errors.push("inventory or classification exceeds the skill safety limit".to_string());
    }
    if !errors.is_empty() {
        return Err(anyhow!(errors.join("; ")));
    }
    Ok(())
}

fn validate_schema_sources(skill_root: &Path, inventory: &SourceInventory) -> Result<()> {
    if inventory.skills.len() > MAX_TOTAL_SKILLS {
        return Err(anyhow!("source inventory exceeds the skill safety limit"));
    }
    let mut total = 0_u64;
    for skill in &inventory.skills {
        validate_path_segment(&skill.id, "skill id")?;
        let directory = skill_root.join(&skill.id);
        let directory_metadata = fs::symlink_metadata(&directory)
            .with_context(|| format!("reading skill metadata '{}'", directory.display()))?;
        if !directory_metadata.file_type().is_dir() {
            return Err(anyhow!("skill source is not a regular directory"));
        }
        let legacy_path = directory.join("tool_schema.yaml");
        let path = if legacy_path.is_file() {
            legacy_path
        } else {
            directory.join("SKILL.md")
        };
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("reading schema metadata '{}'", path.display()))?;
        if !metadata.file_type().is_file() {
            return Err(anyhow!("schema source is not a regular file"));
        }
        total = total
            .checked_add(metadata.len())
            .ok_or_else(|| anyhow!("aggregate schema source size overflowed"))?;
        if total > MAX_TOTAL_SCHEMA_BYTES {
            return Err(anyhow!(
                "aggregate schema source exceeds the {}-byte safety limit",
                MAX_TOTAL_SCHEMA_BYTES
            ));
        }
        let source = read_bounded_utf8(&path)?;
        if path.file_name().and_then(|name| name.to_str()) == Some("tool_schema.yaml") {
            validate_yaml_shape(&source)?;
            validate_yaml_alias_safety(&source)?;
        } else {
            let frontmatter = crate::inventory::extract_frontmatter(&source)
                .ok_or_else(|| anyhow!("active SKILL.md source has no bounded frontmatter"))?;
            validate_yaml_shape(frontmatter)?;
            parse_skill_runtime_package(&source)
                .context("validating governed SKILL.md runtime package")?
                .ok_or_else(|| anyhow!("active SKILL.md source has no runtime package"))?;
        }
    }
    Ok(())
}

#[derive(Debug)]
struct YamlAnchorDefinition {
    indent: usize,
    source_bytes: usize,
    aliases: usize,
}

pub(crate) fn validate_yaml_alias_safety(source: &str) -> Result<()> {
    let mut definitions = BTreeMap::<String, YamlAnchorDefinition>::new();
    let mut anchored_blocks = Vec::<String>::new();
    let mut references = 0_usize;
    let mut block_scalar_indent = None;
    for line in source.lines() {
        let leading_spaces = line.bytes().take_while(|byte| *byte == b' ').count();
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(block_indent) = block_scalar_indent {
            if leading_spaces > block_indent {
                add_anchor_source_bytes(&mut definitions, &anchored_blocks, line.len() + 1)?;
                continue;
            }
            block_scalar_indent = None;
        }
        while anchored_blocks
            .last()
            .and_then(|name| definitions.get(name))
            .is_some_and(|definition| leading_spaces <= definition.indent)
        {
            anchored_blocks.pop();
        }
        add_anchor_source_bytes(&mut definitions, &anchored_blocks, line.len() + 1)?;
        if replay_block_scalar_indicator(line) {
            block_scalar_indent = Some(leading_spaces);
            continue;
        }
        let (anchors, aliases) = yaml_references(line);
        references = references
            .checked_add(anchors.len())
            .and_then(|count| count.checked_add(aliases.len()))
            .ok_or_else(|| anyhow!("YAML reference count overflowed"))?;
        if references > MAX_YAML_REFERENCES {
            return Err(anyhow!("YAML reference count exceeds the safety limit"));
        }
        if !aliases.is_empty() && (!anchored_blocks.is_empty() || !anchors.is_empty()) {
            return Err(anyhow!(
                "YAML aliases may not be nested inside anchored values"
            ));
        }
        for alias in aliases {
            let definition = definitions
                .get_mut(&alias)
                .ok_or_else(|| anyhow!("YAML alias references an undefined anchor"))?;
            definition.aliases = definition
                .aliases
                .checked_add(1)
                .ok_or_else(|| anyhow!("YAML alias count overflowed"))?;
        }
        for anchor in anchors {
            if definitions
                .insert(
                    anchor.clone(),
                    YamlAnchorDefinition {
                        indent: leading_spaces,
                        source_bytes: line.len() + 1,
                        aliases: 0,
                    },
                )
                .is_some()
            {
                return Err(anyhow!("YAML anchor name is defined more than once"));
            }
            anchored_blocks.push(anchor);
        }
    }
    let projected_bytes = definitions
        .values()
        .try_fold(source.len(), |total, definition| {
            definition
                .source_bytes
                .checked_mul(definition.aliases)
                .and_then(|expanded| total.checked_add(expanded))
                .ok_or_else(|| anyhow!("YAML alias expansion estimate overflowed"))
        })?;
    if projected_bytes > MAX_ALIAS_EXPANDED_BYTES {
        return Err(anyhow!("YAML alias expansion exceeds the safety limit"));
    }
    Ok(())
}

fn add_anchor_source_bytes(
    definitions: &mut BTreeMap<String, YamlAnchorDefinition>,
    active: &[String],
    bytes: usize,
) -> Result<()> {
    for name in active {
        let definition = definitions
            .get_mut(name)
            .ok_or_else(|| anyhow!("active YAML anchor has no definition"))?;
        definition.source_bytes = definition
            .source_bytes
            .checked_add(bytes)
            .ok_or_else(|| anyhow!("YAML anchor source size overflowed"))?;
    }
    Ok(())
}

fn yaml_references(line: &str) -> (Vec<String>, Vec<String>) {
    let bytes = line.as_bytes();
    let mut anchors = Vec::new();
    let mut aliases = Vec::new();
    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut escaped = false;
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
                    || matches!(bytes[index - 1], b'[' | b'{' | b',' | b':' | b'-' | b'?');
                let named = bytes
                    .get(index + 1)
                    .is_some_and(|next| next.is_ascii_alphanumeric() || *next == b'_');
                if boundary && named {
                    let end = bytes[index + 1..]
                        .iter()
                        .position(|next| {
                            !(next.is_ascii_alphanumeric() || matches!(*next, b'_' | b'-' | b'.'))
                        })
                        .map_or(bytes.len(), |offset| index + 1 + offset);
                    let name = String::from_utf8_lossy(&bytes[index + 1..end]).into_owned();
                    if byte == b'&' {
                        anchors.push(name);
                    } else {
                        aliases.push(name);
                    }
                }
            },
            _ => {},
        }
    }
    (anchors, aliases)
}

fn replay_block_scalar_indicator(line: &str) -> bool {
    let without_comment = line.split('#').next().unwrap_or_default().trim_end();
    let Some((_, indicator)) = without_comment.rsplit_once(':') else {
        return false;
    };
    let indicator = indicator.trim();
    let mut characters = indicator.chars();
    matches!(characters.next(), Some('|' | '>'))
        && characters.all(|character| character.is_ascii_digit() || matches!(character, '+' | '-'))
}

pub(crate) fn validate_parsed_yaml_budget(root: &Value) -> Result<()> {
    let mut pending = vec![(root, 0_usize)];
    let mut nodes = 0_usize;
    while let Some((value, depth)) = pending.pop() {
        if depth > MAX_PARSED_YAML_DEPTH {
            return Err(anyhow!("parsed YAML exceeds the depth safety limit"));
        }
        nodes = nodes
            .checked_add(1)
            .ok_or_else(|| anyhow!("parsed YAML node count overflowed"))?;
        if nodes > MAX_PARSED_YAML_NODES {
            return Err(anyhow!("parsed YAML exceeds the node safety limit"));
        }
        let next_depth = depth.saturating_add(1);
        match value {
            Value::Sequence(values) => {
                pending.extend(values.iter().map(|value| (value, next_depth)));
            },
            Value::Mapping(values) => {
                for (key, value) in values {
                    pending.push((key, next_depth));
                    pending.push((value, next_depth));
                }
            },
            Value::Tagged(value) => pending.push((&value.value, next_depth)),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {},
        }
    }
    Ok(())
}

fn compiled_provider_name(
    skill_id: &str,
    implementation_type: &str,
    implementation: &Mapping,
) -> Result<Option<String>> {
    let declared = optional_string(implementation, "provider_name")?;
    if let Some(provider) = &declared {
        validate_identifier(provider, "compiled provider name")?;
        if implementation_type != "primitive" {
            return Err(anyhow!(
                "provider_name is only executable on a primitive implementation"
            ));
        }
    }
    if implementation_type == "primitive" && skill_id == RESERVED_BROWSER_SKILL_ID {
        if declared
            .as_deref()
            .is_some_and(|provider| provider != RESERVED_BROWSER_SKILL_ID)
        {
            return Err(anyhow!(
                "reserved browser route cannot declare a different provider"
            ));
        }
        return Ok(Some(RESERVED_BROWSER_SKILL_ID.to_string()));
    }
    Ok(declared)
}

fn validated_compiled_provider(
    skill_id: &str,
    implementation_type: &str,
    implementation: &Mapping,
    classification: &crate::classification::SkillClassification,
) -> Result<Option<String>> {
    let provider = compiled_provider_name(skill_id, implementation_type, implementation)?;
    let compiled = provider.is_some();
    if compiled != (classification.runtime_owner == RuntimeOwner::CompiledProvider) {
        return Err(anyhow!(
            "runtime-owner classification does not match the executable dispatch route"
        ));
    }
    Ok(provider)
}

fn consume_projection_budget(
    remaining: &mut usize,
    parameters: &[ReplayParameter],
    bindings: &[EnvironmentBinding],
    required_env_names: &[String],
    dispatch: &ReplayDispatch,
) -> Result<()> {
    let fixed_mapping_args = dispatch
        .mappings
        .iter()
        .map(|mapping| match mapping {
            ReplayArgMapping::FixedArgs { args } => args.len(),
            _ => 0,
        })
        .try_fold(0_usize, |total, count| total.checked_add(count))
        .ok_or_else(|| anyhow!("projected replay record count overflowed"))?;
    let argument_rule_tokens = dispatch
        .argument_rules
        .denied_prefixes
        .iter()
        .map(Vec::len)
        .chain(
            dispatch
                .argument_rules
                .constrained_prefixes
                .iter()
                .map(|constraint| {
                    constraint
                        .prefix
                        .len()
                        .saturating_add(constraint.allowed_next_tokens.len())
                }),
        )
        .try_fold(0_usize, |total, count| total.checked_add(count))
        .ok_or_else(|| anyhow!("projected replay record count overflowed"))?;
    let counts = [
        1,
        parameters.len(),
        bindings.len(),
        required_env_names.len(),
        dispatch.mappings.len(),
        fixed_mapping_args,
        dispatch.prefix_args.len(),
        dispatch.action_args.len(),
        dispatch.action_suffix_args.len(),
        dispatch.implementation_suffix_args.len(),
        argument_rule_tokens,
    ];
    let cost = counts
        .into_iter()
        .try_fold(0_usize, |total, count| total.checked_add(count))
        .ok_or_else(|| anyhow!("projected replay record count overflowed"))?;
    if cost > *remaining {
        return Err(anyhow!(
            "replay projection exceeds the aggregate record safety limit"
        ));
    }
    *remaining -= cost;
    Ok(())
}

fn compile_skill(
    skill_root: &Path,
    source: &ToolSkillSourceInventory,
    classification: &crate::classification::SkillClassification,
    remaining_projection_records: &mut usize,
) -> Result<Vec<ReplayFixture>> {
    validate_path_segment(&source.id, "skill id")?;
    let schema_path = skill_root.join(&source.id).join("tool_schema.yaml");
    if !schema_path.is_file() {
        return compile_governed_skill(
            skill_root,
            source,
            classification,
            remaining_projection_records,
        );
    }
    let schema_source = read_bounded_utf8(&schema_path)?;
    validate_yaml_shape(&schema_source)?;
    let root: Value = serde_yaml::from_str(&schema_source)
        .with_context(|| format!("parsing '{}'", schema_path.display()))?;
    validate_parsed_yaml_budget(&root)?;
    let root = as_mapping(&root, "schema root")?;
    let schema_name = required_string(root, "name")?;
    if schema_name != source.id {
        return Err(anyhow!(
            "schema name '{}' does not match inventory id '{}'",
            schema_name,
            source.id
        ));
    }
    let actions = required_mapping(root, "native_action_schemas")?;
    if actions.len() > MAX_ACTIONS_PER_SKILL {
        return Err(anyhow!("schema action map exceeds the safety limit"));
    }
    let action_names = actions
        .keys()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| anyhow!("action name is not a string"))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let inventory_names = source
        .action_names
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if action_names != inventory_names || actions.len() != source.action_names.len() {
        return Err(anyhow!(
            "schema action names do not exactly match the Phase 0A inventory"
        ));
    }

    let root_parameters = parse_root_parameters(root)?;
    let implementation = required_mapping(root, "implementation")?;
    let implementation_type = required_string(implementation, "type")?;
    let compiled_provider = validated_compiled_provider(
        &source.id,
        &implementation_type,
        implementation,
        classification,
    )?;
    let execution = optional_mapping(root, "execution")?;
    let execution_timeout = execution
        .and_then(|mapping| mapping_get(mapping, "default_timeout_secs"))
        .map(|value| parse_u64(value, "execution.default_timeout_secs"))
        .transpose()?;
    let required_env_names = source
        .required_env_names
        .iter()
        .map(|name| {
            validate_env_name(name)?;
            Ok(name.clone())
        })
        .collect::<Result<Vec<_>>>()?;
    let (bindings, cwd) = if compiled_provider.is_some() {
        (Vec::new(), None)
    } else {
        (
            parse_environment_bindings(implementation)?,
            optional_string(implementation, "cwd")?
                .map(|template| template_shape(&template))
                .transpose()?,
        )
    };
    let declared_output_class = parse_output_class(implementation)?;

    let mut fixtures = Vec::with_capacity(actions.len());
    for (action_name_value, action_value) in actions {
        let action_name = action_name_value
            .as_str()
            .ok_or_else(|| anyhow!("action name is not a string"))?;
        validate_identifier(action_name, "action name")?;
        let action = as_mapping(action_value, "action schema")?;
        let parameters = parse_action_parameters(action, &root_parameters)?;
        let parameter_names = parameters
            .iter()
            .map(|parameter| parameter.name.as_str())
            .collect::<BTreeSet<_>>();
        let parameter_declared_stdin = parameter_names.contains("stdin");
        let (dispatch, timeout, ignored) = match implementation_type.as_str() {
            "primitive" if compiled_provider.is_some() => (
                ReplayDispatch {
                    kind: DispatchKind::CompiledProvider,
                    program: None,
                    provider_name: compiled_provider.clone(),
                    prefix_args: Vec::new(),
                    action_args: Vec::new(),
                    argument_mode: ArgumentMode::CompiledSchema,
                    mappings: Vec::new(),
                    action_suffix_args: Vec::new(),
                    implementation_suffix_args: Vec::new(),
                    argument_rules: TypedArgumentRules::default(),
                },
                compiled_replay_timeout(action, execution_timeout)?,
                compiled_ignored_fields(implementation),
            ),
            "primitive" => compile_primitive_dispatch(
                &source.id,
                action_name,
                action,
                implementation,
                execution_timeout,
                &parameter_names,
            )?,
            "command" => compile_command_dispatch(
                action,
                implementation,
                execution_timeout,
                &parameter_names,
            )?,
            other => return Err(anyhow!("unsupported implementation type '{other}'")),
        };
        let mapping_names = dispatch
            .mappings
            .iter()
            .filter_map(|mapping| match mapping {
                ReplayArgMapping::EnvFlag { env_var, .. } => Some(env_var.clone()),
                _ => None,
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let accepts_stdin = dispatch.kind == DispatchKind::PrimitiveProcess;
        consume_projection_budget(
            remaining_projection_records,
            &parameters,
            &bindings,
            &required_env_names,
            &dispatch,
        )?;
        fixtures.push(ReplayFixture {
            id: format!("{}::{}", source.id, action_name),
            skill_id: source.id.clone(),
            action_name: action_name.to_string(),
            runtime_owner: classification.runtime_owner.clone(),
            approval_class: classification.approval_class.clone(),
            auth_strategies: classification.auth_strategies.clone(),
            profile: classification.profile.clone(),
            dispatch,
            parameters,
            environment: ReplayEnvironment {
                required_names: required_env_names.clone(),
                bindings: bindings.clone(),
                mapping_names,
            },
            cwd: cwd.clone(),
            stdin: ReplayStdin {
                accepted: accepts_stdin,
                parameter_declared: parameter_declared_stdin,
            },
            timeout,
            output_class: if implementation_type == "command" {
                declared_output_class.clone()
            } else {
                OutputClass::ToolOutput
            },
            ignored_legacy_fields: ignored,
        });
    }
    Ok(fixtures)
}

fn compile_governed_skill(
    skill_root: &Path,
    source: &ToolSkillSourceInventory,
    classification: &crate::classification::SkillClassification,
    remaining_projection_records: &mut usize,
) -> Result<Vec<ReplayFixture>> {
    let skill_path = skill_root.join(&source.id).join("SKILL.md");
    let skill_source = read_bounded_utf8(&skill_path)?;
    let package = parse_skill_runtime_package(&skill_source)
        .context("parsing governed replay package")?
        .ok_or_else(|| anyhow!("governed replay source has no runtime package"))?;
    let validated = validate_skill_runtime_contract(&package.contract)
        .context("validating governed replay contract")?;
    if matches!(&package.contract.runtime, RuntimeProtocol::Mcp { .. }) {
        return compile_governed_mcp_skill(
            source,
            classification,
            &package,
            remaining_projection_records,
        );
    }
    let actions = package
        .actions
        .as_ref()
        .ok_or_else(|| anyhow!("governed replay package has no typed actions"))?;
    let compiled = compile_typed_action_overrides(&source.id, validated, actions)
        .context("compiling governed replay actions")?;
    let compiled_names = compiled.actions.keys().cloned().collect::<BTreeSet<_>>();
    let inventory_names = source.action_names.iter().cloned().collect::<BTreeSet<_>>();
    if compiled_names != inventory_names {
        return Err(anyhow!(
            "governed action names do not exactly match the Phase 0A inventory"
        ));
    }

    let RuntimeProtocol::Cli {
        limits,
        working_directory,
        ..
    } = &package.contract.runtime
    else {
        return Err(anyhow!("governed replay currently requires a CLI runtime"));
    };
    let cwd = match working_directory.mode {
        WorkingDirectoryMode::Denied => None,
        WorkingDirectoryMode::Workspace | WorkingDirectoryMode::OutputRoot => Some(TemplateShape {
            placeholder_names: vec!["working_dir".to_owned()],
            contains_literal_component: true,
        }),
    };
    let required_env_names = source
        .required_env_names
        .iter()
        .map(|name| {
            validate_env_name(name)?;
            Ok(name.clone())
        })
        .collect::<Result<Vec<_>>>()?;
    let projected_profile_name = package
        .projected_profile_parameter()
        .map(|parameter| parameter.name.to_owned());
    let bindings = governed_environment_bindings(
        &package.contract.auth.storage,
        &package.contract.auth.profile_selection,
        &package.contract.auth.injections,
        projected_profile_name.as_deref(),
    )?;
    let mut fixtures = Vec::with_capacity(compiled.actions.len());
    for (action_name, action) in &compiled.actions {
        let authored = actions
            .actions
            .get(action_name)
            .ok_or_else(|| anyhow!("compiled action lost its authored source"))?;
        let mut parameters = authored
            .parameters
            .iter()
            .map(|(name, parameter)| ReplayParameter {
                name: name.clone(),
                value_kind: governed_parameter_kind(parameter),
                required: governed_parameter_required(parameter),
            })
            .collect::<Vec<_>>();
        if let Some(profile_name) = projected_profile_name.as_ref() {
            let profile_required = action
                .definition
                .input_schema
                .get("required")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some("profile")));
            parameters.push(ReplayParameter {
                name: profile_name.clone(),
                value_kind: ReplayValueKind::String,
                required: profile_required,
            });
        }
        let compiled_properties = action
            .definition
            .input_schema
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| anyhow!("compiled governed action lost its property map"))?;
        let compiled_required = action
            .definition
            .input_schema
            .get("required")
            .and_then(serde_json::Value::as_array);
        for control in ["stdin", "working_dir"] {
            if compiled_properties.contains_key(control) {
                parameters.push(ReplayParameter {
                    name: control.to_owned(),
                    value_kind: ReplayValueKind::String,
                    required: compiled_required.is_some_and(|values| {
                        values.iter().any(|value| value.as_str() == Some(control))
                    }),
                });
            }
        }
        let mappings = action
            .invocation
            .mappings
            .iter()
            .filter_map(|mapping| governed_replay_mapping(mapping).transpose())
            .collect::<Result<Vec<_>>>()?;
        let dispatch = ReplayDispatch {
            kind: DispatchKind::PrimitiveProcess,
            program: Some(action.invocation.executable.clone()),
            provider_name: None,
            prefix_args: compiled.execution.command_prefix.clone(),
            action_args: action.invocation.fixed_args.clone(),
            argument_mode: match action.invocation.input_delivery {
                TypedActionInputDelivery::Argv => ArgumentMode::ExplicitMappings,
                TypedActionInputDelivery::CanonicalJsonStdin => ArgumentMode::CanonicalJsonStdin,
            },
            mappings,
            action_suffix_args: action.invocation.suffix_args.clone(),
            implementation_suffix_args: Vec::new(),
            argument_rules: action.invocation.argument_rules.clone(),
        };
        let parameter_declared_stdin = parameters.iter().any(|parameter| parameter.name == "stdin");
        consume_projection_budget(
            remaining_projection_records,
            &parameters,
            &bindings,
            &required_env_names,
            &dispatch,
        )?;
        fixtures.push(ReplayFixture {
            id: format!("{}::{action_name}", source.id),
            skill_id: source.id.clone(),
            action_name: action_name.clone(),
            runtime_owner: classification.runtime_owner.clone(),
            approval_class: classification.approval_class.clone(),
            auth_strategies: classification.auth_strategies.clone(),
            profile: classification.profile.clone(),
            dispatch,
            parameters,
            environment: ReplayEnvironment {
                required_names: required_env_names.clone(),
                bindings: bindings.clone(),
                mapping_names: Vec::new(),
            },
            cwd: cwd.clone(),
            stdin: ReplayStdin {
                accepted: matches!(
                    action.invocation.input_delivery,
                    TypedActionInputDelivery::CanonicalJsonStdin
                ) || parameter_declared_stdin,
                parameter_declared: parameter_declared_stdin,
            },
            timeout: ReplayTimeout {
                default_secs: Some(u64::from(action.invocation.timeout_ceiling_secs)),
                source: if authored.timeout_secs.is_some() {
                    TimeoutSource::Action
                } else if limits.timeout_secs.is_some() {
                    TimeoutSource::Implementation
                } else {
                    TimeoutSource::RuntimePrimitiveDefault
                },
                caller_override_supported: true,
            },
            output_class: OutputClass::ToolOutput,
            ignored_legacy_fields: Vec::new(),
        });
    }
    Ok(fixtures)
}

fn compile_governed_mcp_skill(
    source: &ToolSkillSourceInventory,
    classification: &crate::classification::SkillClassification,
    package: &crate::manifest_parser::SkillRuntimePackage,
    remaining_projection_records: &mut usize,
) -> Result<Vec<ReplayFixture>> {
    let projection = project_mcp_catalog(package).map_err(|error| anyhow!(error))?;
    let projected_names = projection.actions.keys().cloned().collect::<BTreeSet<_>>();
    let inventory_names = source.action_names.iter().cloned().collect::<BTreeSet<_>>();
    if projected_names != inventory_names {
        return Err(anyhow!(
            "governed MCP action names do not exactly match the Phase 0A inventory"
        ));
    }
    if classification.runtime_owner != RuntimeOwner::OfficialMcpSdk {
        return Err(anyhow!(
            "governed MCP package is not classified under the official SDK runtime owner"
        ));
    }

    let required_env_names = source
        .required_env_names
        .iter()
        .map(|name| {
            validate_env_name(name)?;
            Ok(name.clone())
        })
        .collect::<Result<Vec<_>>>()?;
    let timeout_secs = projection.timeout_secs;
    let mut fixtures = Vec::with_capacity(projection.actions.len());
    for (action_name, action) in projection.actions {
        let parameters = action
            .parameters
            .iter()
            .map(mcp_replay_parameter)
            .collect::<Result<Vec<_>>>()?;
        let dispatch = ReplayDispatch {
            kind: DispatchKind::OfficialMcpSdk,
            program: None,
            provider_name: None,
            prefix_args: Vec::new(),
            action_args: Vec::new(),
            argument_mode: ArgumentMode::CompiledSchema,
            mappings: Vec::new(),
            action_suffix_args: Vec::new(),
            implementation_suffix_args: Vec::new(),
            argument_rules: TypedArgumentRules::default(),
        };
        consume_projection_budget(
            remaining_projection_records,
            &parameters,
            &[],
            &required_env_names,
            &dispatch,
        )?;
        fixtures.push(ReplayFixture {
            id: format!("{}::{action_name}", source.id),
            skill_id: source.id.clone(),
            action_name,
            runtime_owner: classification.runtime_owner.clone(),
            approval_class: classification.approval_class.clone(),
            auth_strategies: classification.auth_strategies.clone(),
            profile: classification.profile.clone(),
            dispatch,
            parameters,
            environment: ReplayEnvironment {
                required_names: required_env_names.clone(),
                bindings: Vec::new(),
                mapping_names: Vec::new(),
            },
            cwd: None,
            stdin: ReplayStdin {
                accepted: false,
                parameter_declared: false,
            },
            timeout: ReplayTimeout {
                default_secs: Some(timeout_secs),
                source: TimeoutSource::OfficialMcpSdkDefault,
                caller_override_supported: false,
            },
            output_class: OutputClass::ToolOutput,
            ignored_legacy_fields: Vec::new(),
        });
    }
    Ok(fixtures)
}

fn mcp_replay_parameter(parameter: &McpCatalogParameterProjection) -> Result<ReplayParameter> {
    let value_kind = match parameter
        .schema
        .get("type")
        .and_then(serde_json::Value::as_str)
    {
        Some("string") => ReplayValueKind::String,
        Some("integer") => ReplayValueKind::Integer,
        Some("number") => ReplayValueKind::Number,
        Some("boolean") => ReplayValueKind::Boolean,
        Some("array") => ReplayValueKind::Array,
        Some("object") => ReplayValueKind::Object,
        _ => {
            return Err(anyhow!(
                "official MCP SDK parameter has no supported JSON type"
            ));
        },
    };
    Ok(ReplayParameter {
        name: parameter.name.clone(),
        value_kind,
        required: parameter.required,
    })
}

fn governed_parameter_kind(parameter: &TypedActionParameter) -> ReplayValueKind {
    match parameter {
        TypedActionParameter::String { .. } | TypedActionParameter::WorkspacePath { .. } => {
            ReplayValueKind::String
        },
        TypedActionParameter::Integer { .. } => ReplayValueKind::Integer,
        TypedActionParameter::Number { .. } => ReplayValueKind::Number,
        TypedActionParameter::Boolean { .. } => ReplayValueKind::Boolean,
        TypedActionParameter::StringArray { .. } => ReplayValueKind::Array,
        TypedActionParameter::JsonObject { .. } => ReplayValueKind::Object,
        TypedActionParameter::JsonArray { .. } => ReplayValueKind::Array,
    }
}

fn governed_parameter_required(parameter: &TypedActionParameter) -> bool {
    match parameter {
        TypedActionParameter::String { required, .. }
        | TypedActionParameter::WorkspacePath { required, .. }
        | TypedActionParameter::Integer { required, .. }
        | TypedActionParameter::Number { required, .. }
        | TypedActionParameter::Boolean { required, .. }
        | TypedActionParameter::StringArray { required, .. }
        | TypedActionParameter::JsonObject { required, .. }
        | TypedActionParameter::JsonArray { required, .. } => *required,
    }
}

fn governed_replay_mapping(mapping: &TypedArgumentMapping) -> Result<Option<ReplayArgMapping>> {
    match mapping {
        TypedArgumentMapping::Positional { parameter } => Ok(Some(ReplayArgMapping::Positional {
            param: parameter.clone(),
        })),
        TypedArgumentMapping::Flag {
            flag, parameter, ..
        }
        | TypedArgumentMapping::JsonFlag { flag, parameter } => Ok(Some(ReplayArgMapping::Flag {
            flag: flag.clone(),
            param: parameter.clone(),
        })),
        TypedArgumentMapping::BoolFlag { flag, parameter } => {
            Ok(Some(ReplayArgMapping::BoolFlag {
                flag: flag.clone(),
                param: parameter.clone(),
            }))
        },
        TypedArgumentMapping::Passthrough { parameter } => {
            Ok(Some(ReplayArgMapping::Passthrough {
                param: parameter.clone(),
            }))
        },
        TypedArgumentMapping::RepeatedFlag { .. } => Err(anyhow!(
            "replay projection does not yet represent repeated typed flags"
        )),
        TypedArgumentMapping::Literal { arguments } => Ok(Some(ReplayArgMapping::FixedArgs {
            args: arguments.clone(),
        })),
        TypedArgumentMapping::SplitPositional { parameter, .. } => {
            Ok(Some(ReplayArgMapping::SplitPositional {
                param: parameter.clone(),
            }))
        },
        TypedArgumentMapping::RuntimeControl { .. } => Ok(None),
    }
}

fn governed_environment_bindings(
    storage: &AuthStorage,
    profile_selection: &ProfileSelection,
    injections: &[crate::manifest::InjectionBinding],
    projected_profile_name: Option<&str>,
) -> Result<Vec<EnvironmentBinding>> {
    let AuthStorage::ScopedDirectory { namespace, .. } = storage else {
        return Ok(Vec::new());
    };
    validate_identifier(namespace, "auth storage namespace")?;
    match profile_selection {
        ProfileSelection::Fixed { alias } => validate_identifier(alias, "fixed profile alias")?,
        ProfileSelection::Selectable { .. } => {},
        ProfileSelection::None | ProfileSelection::Implicit => {
            return Err(anyhow!(
                "scoped auth storage has no replayable profile selector"
            ));
        },
    }
    let mut bindings = Vec::new();
    for injection in injections {
        let InjectionSource::ProfileAuthRoot { .. } = &injection.source else {
            continue;
        };
        let InjectionTarget::Environment { name } = &injection.target else {
            continue;
        };
        validate_env_name(name)?;
        let mut placeholder_names = vec!["scope_capability_auth_root".to_owned()];
        if matches!(profile_selection, ProfileSelection::Selectable { .. }) {
            let name = projected_profile_name
                .ok_or_else(|| anyhow!("selectable profile lost its replay projection"))?;
            placeholder_names.push(name.to_owned());
            placeholder_names.sort();
        }
        bindings.push(EnvironmentBinding {
            name: name.clone(),
            placeholder_names,
            contains_literal_component: true,
        });
    }
    bindings.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(bindings)
}

fn compile_primitive_dispatch(
    skill_id: &str,
    action_name: &str,
    action: &Mapping,
    implementation: &Mapping,
    execution_timeout: Option<u64>,
    parameter_names: &BTreeSet<&str>,
) -> Result<(ReplayDispatch, ReplayTimeout, Vec<IgnoredLegacyField>)> {
    let command = optional_string_sequence(implementation, "command")?;
    let base = command.unwrap_or_else(|| vec![skill_id.to_string()]);
    if base.is_empty() {
        return Err(anyhow!("primitive implementation command cannot be empty"));
    }
    validate_tokens(&base, "primitive command")?;
    let program = base[0].clone();
    let prefix_args = base[1..].to_vec();
    let explicit_argv = optional_string_sequence(action, "argv")?.unwrap_or_default();
    validate_tokens(&explicit_argv, "action argv")?;
    let skip_tool_name = optional_bool(action, "skip_tool_name")?.unwrap_or(false);
    let action_args = if !explicit_argv.is_empty() {
        explicit_argv
    } else if skip_tool_name {
        Vec::new()
    } else {
        vec![action_name.to_string()]
    };
    let mappings = parse_mappings(action, "arg_mappings", parameter_names)?;
    let argument_mode = if mappings.is_empty() {
        ArgumentMode::ArgsOrSortedFlags
    } else {
        ArgumentMode::ExplicitMappings
    };
    let action_suffix_args = optional_string_sequence(action, "suffix_args")?.unwrap_or_default();
    let implementation_suffix_args =
        optional_string_sequence(implementation, "suffix_args")?.unwrap_or_default();
    validate_tokens(&action_suffix_args, "action suffix_args")?;
    validate_tokens(&implementation_suffix_args, "implementation suffix_args")?;
    Ok((
        ReplayDispatch {
            kind: DispatchKind::PrimitiveProcess,
            program: Some(program),
            provider_name: None,
            prefix_args,
            action_args,
            argument_mode,
            mappings,
            action_suffix_args,
            implementation_suffix_args,
            argument_rules: TypedArgumentRules::default(),
        },
        replay_timeout(action, implementation, execution_timeout, true)?,
        primitive_ignored_fields(implementation),
    ))
}

fn compile_command_dispatch(
    action: &Mapping,
    implementation: &Mapping,
    execution_timeout: Option<u64>,
    parameter_names: &BTreeSet<&str>,
) -> Result<(ReplayDispatch, ReplayTimeout, Vec<IgnoredLegacyField>)> {
    let program = required_string(implementation, "program")?;
    validate_token(&program, "command program")?;
    let prefix_args = optional_string_sequence(implementation, "fixed_args")?.unwrap_or_default();
    let mappings = parse_mappings(implementation, "arg_mappings", parameter_names)?;
    let implementation_suffix_args =
        optional_string_sequence(implementation, "suffix_args")?.unwrap_or_default();
    validate_tokens(&prefix_args, "command fixed_args")?;
    validate_tokens(
        &implementation_suffix_args,
        "command implementation suffix_args",
    )?;
    let mut ignored = Vec::new();
    push_if_present(
        action,
        "argv",
        IgnoredLegacyField::CommandActionArgv,
        &mut ignored,
    );
    push_if_present(
        action,
        "skip_tool_name",
        IgnoredLegacyField::CommandActionSkipToolName,
        &mut ignored,
    );
    push_if_present(
        action,
        "arg_mappings",
        IgnoredLegacyField::CommandActionArgMappings,
        &mut ignored,
    );
    push_if_present(
        action,
        "suffix_args",
        IgnoredLegacyField::CommandActionSuffixArgs,
        &mut ignored,
    );
    push_if_present(
        action,
        "timeout_secs",
        IgnoredLegacyField::CommandActionTimeout,
        &mut ignored,
    );
    Ok((
        ReplayDispatch {
            kind: DispatchKind::CommandProcess,
            program: Some(program),
            provider_name: None,
            prefix_args,
            action_args: Vec::new(),
            argument_mode: ArgumentMode::ImplementationMappings,
            mappings,
            action_suffix_args: Vec::new(),
            implementation_suffix_args,
            argument_rules: TypedArgumentRules::default(),
        },
        replay_timeout(action, implementation, execution_timeout, false)?,
        ignored,
    ))
}

fn replay_timeout(
    action: &Mapping,
    implementation: &Mapping,
    execution_timeout: Option<u64>,
    primitive: bool,
) -> Result<ReplayTimeout> {
    if primitive {
        if let Some(value) = mapping_get(action, "timeout_secs") {
            return Ok(ReplayTimeout {
                default_secs: Some(parse_u64(value, "action.timeout_secs")?),
                source: TimeoutSource::Action,
                caller_override_supported: true,
            });
        }
        if let Some(value) = mapping_get(implementation, "timeout_secs") {
            return Ok(ReplayTimeout {
                default_secs: Some(parse_u64(value, "implementation.timeout_secs")?),
                source: TimeoutSource::Implementation,
                caller_override_supported: true,
            });
        }
    }
    if let Some(default_secs) = execution_timeout {
        return Ok(ReplayTimeout {
            default_secs: Some(default_secs),
            source: TimeoutSource::Execution,
            caller_override_supported: true,
        });
    }
    Ok(ReplayTimeout {
        default_secs: Some(if primitive { 60 } else { 30 }),
        source: if primitive {
            TimeoutSource::RuntimePrimitiveDefault
        } else {
            TimeoutSource::RuntimeCommandDefault
        },
        caller_override_supported: true,
    })
}

fn compiled_replay_timeout(
    action: &Mapping,
    execution_timeout: Option<u64>,
) -> Result<ReplayTimeout> {
    if let Some(value) = mapping_get(action, "timeout_secs") {
        return Ok(ReplayTimeout {
            default_secs: Some(parse_u64(value, "action.timeout_secs")?),
            source: TimeoutSource::Action,
            caller_override_supported: false,
        });
    }
    if let Some(default_secs) = execution_timeout {
        return Ok(ReplayTimeout {
            default_secs: Some(default_secs),
            source: TimeoutSource::Execution,
            caller_override_supported: false,
        });
    }
    Ok(ReplayTimeout {
        default_secs: None,
        source: TimeoutSource::CompiledProviderDefault,
        caller_override_supported: false,
    })
}

fn primitive_ignored_fields(implementation: &Mapping) -> Vec<IgnoredLegacyField> {
    let mut ignored = Vec::new();
    push_if_present(
        implementation,
        "program",
        IgnoredLegacyField::PrimitiveProgram,
        &mut ignored,
    );
    push_if_present(
        implementation,
        "fixed_args",
        IgnoredLegacyField::PrimitiveFixedArgs,
        &mut ignored,
    );
    push_if_present(
        implementation,
        "arg_mappings",
        IgnoredLegacyField::PrimitiveArgMappings,
        &mut ignored,
    );
    push_if_present(
        implementation,
        "content_type",
        IgnoredLegacyField::PrimitiveContentType,
        &mut ignored,
    );
    ignored
}

fn compiled_ignored_fields(implementation: &Mapping) -> Vec<IgnoredLegacyField> {
    let mut ignored = primitive_ignored_fields(implementation);
    push_if_present(
        implementation,
        "command",
        IgnoredLegacyField::CompiledCommand,
        &mut ignored,
    );
    push_if_present(
        implementation,
        "cwd",
        IgnoredLegacyField::CompiledCwd,
        &mut ignored,
    );
    push_if_present(
        implementation,
        "env",
        IgnoredLegacyField::CompiledEnv,
        &mut ignored,
    );
    push_if_present(
        implementation,
        "suffix_args",
        IgnoredLegacyField::CompiledSuffixArgs,
        &mut ignored,
    );
    push_if_present(
        implementation,
        "timeout_secs",
        IgnoredLegacyField::CompiledTimeout,
        &mut ignored,
    );
    ignored
}

fn push_if_present(
    mapping: &Mapping,
    key: &str,
    field: IgnoredLegacyField,
    output: &mut Vec<IgnoredLegacyField>,
) {
    if mapping_get(mapping, key).is_some() {
        output.push(field);
    }
}

fn parse_root_parameters(root: &Mapping) -> Result<BTreeMap<String, ReplayValueKind>> {
    let mut parameters = BTreeMap::new();
    let Some(value) = mapping_get(root, "parameters") else {
        return Ok(parameters);
    };
    let sequence = value
        .as_sequence()
        .ok_or_else(|| anyhow!("parameters must be a sequence"))?;
    if sequence.len() > MAX_ROOT_PARAMETERS {
        return Err(anyhow!("root parameter count exceeds the safety limit"));
    }
    for parameter in sequence {
        let parameter = as_mapping(parameter, "root parameter")?;
        let name = required_string(parameter, "name")?;
        validate_identifier(&name, "parameter name")?;
        let kind = required_string(parameter, "param_type")?;
        let kind = parse_value_kind(&kind)?;
        if parameters.insert(name.clone(), kind).is_some() {
            return Err(anyhow!("root parameter '{name}' is duplicated"));
        }
    }
    Ok(parameters)
}

fn parse_action_parameters(
    action: &Mapping,
    root_parameters: &BTreeMap<String, ReplayValueKind>,
) -> Result<Vec<ReplayParameter>> {
    let names = optional_string_sequence(action, "parameters")?.unwrap_or_default();
    if names.len() > MAX_PARAMETERS_PER_ACTION {
        return Err(anyhow!("action parameter count exceeds the safety limit"));
    }
    let required_values = optional_string_sequence(action, "required")?.unwrap_or_default();
    if required_values.len() > MAX_PARAMETERS_PER_ACTION {
        return Err(anyhow!("action required count exceeds the safety limit"));
    }
    let required = required_values.iter().cloned().collect::<BTreeSet<_>>();
    if required.len() != required_values.len() {
        return Err(anyhow!("action repeats a required parameter name"));
    }
    let name_set = names.iter().cloned().collect::<BTreeSet<_>>();
    if name_set.len() != names.len() {
        return Err(anyhow!("action repeats a parameter name"));
    }
    if !required.is_subset(&name_set) {
        return Err(anyhow!(
            "action required list references an undeclared parameter"
        ));
    }
    let overrides = optional_mapping(action, "parameter_overrides")?;
    names
        .into_iter()
        .map(|name| {
            validate_identifier(&name, "parameter name")?;
            let override_kind = overrides
                .and_then(|mapping| mapping_get(mapping, &name))
                .map(|value| {
                    let mapping = as_mapping(value, "parameter override")?;
                    required_string(mapping, "type").and_then(|kind| parse_value_kind(&kind))
                })
                .transpose()?;
            let value_kind = override_kind
                .or_else(|| root_parameters.get(&name).cloned())
                .ok_or_else(|| anyhow!("parameter '{name}' has no declared type"))?;
            Ok(ReplayParameter {
                required: required.contains(&name),
                name,
                value_kind,
            })
        })
        .collect()
}

fn parse_mappings(
    owner: &Mapping,
    key: &str,
    parameter_names: &BTreeSet<&str>,
) -> Result<Vec<ReplayArgMapping>> {
    let Some(value) = mapping_get(owner, key) else {
        return Ok(Vec::new());
    };
    let mappings = value
        .as_sequence()
        .ok_or_else(|| anyhow!("{key} must be a sequence"))?;
    if mappings.len() > MAX_ARG_MAPPINGS {
        return Err(anyhow!("{key} exceeds the mapping safety limit"));
    }
    mappings
        .iter()
        .map(|mapping| {
            let mapping = as_mapping(mapping, "argument mapping")?;
            let mapping_type = required_string(mapping, "type")?;
            let param = |mapping: &Mapping| -> Result<String> {
                let param = required_string(mapping, "param")?;
                validate_identifier(&param, "mapping parameter")?;
                if !parameter_names.contains(param.as_str()) {
                    return Err(anyhow!(
                        "argument mapping references undeclared parameter '{param}'"
                    ));
                }
                Ok(param)
            };
            let flag = |mapping: &Mapping| -> Result<String> {
                let flag = required_string(mapping, "flag")?;
                validate_token(&flag, "argument flag")?;
                Ok(flag)
            };
            match mapping_type.as_str() {
                "positional" => Ok(ReplayArgMapping::Positional {
                    param: param(mapping)?,
                }),
                "flag" => Ok(ReplayArgMapping::Flag {
                    flag: flag(mapping)?,
                    param: param(mapping)?,
                }),
                "bool_flag" => Ok(ReplayArgMapping::BoolFlag {
                    flag: flag(mapping)?,
                    param: param(mapping)?,
                }),
                "split_positional" => Ok(ReplayArgMapping::SplitPositional {
                    param: param(mapping)?,
                }),
                "env_flag" => {
                    let env_var = required_string(mapping, "env_var")?;
                    validate_env_name(&env_var)?;
                    Ok(ReplayArgMapping::EnvFlag {
                        flag: flag(mapping)?,
                        env_var,
                    })
                },
                "fixed_args" => {
                    let args = required_string_sequence(mapping, "args")?;
                    validate_tokens(&args, "fixed mapping args")?;
                    Ok(ReplayArgMapping::FixedArgs { args })
                },
                "passthrough" => Ok(ReplayArgMapping::Passthrough {
                    param: param(mapping)?,
                }),
                other => Err(anyhow!("unsupported argument mapping type '{other}'")),
            }
        })
        .collect()
}

fn parse_environment_bindings(implementation: &Mapping) -> Result<Vec<EnvironmentBinding>> {
    let Some(value) = mapping_get(implementation, "env") else {
        return Ok(Vec::new());
    };
    let env = as_mapping(value, "implementation env")?;
    if env.len() > MAX_ENV_BINDINGS {
        return Err(anyhow!("implementation env exceeds the safety limit"));
    }
    let mut bindings = Vec::with_capacity(env.len());
    for (name, template) in env {
        let name = name
            .as_str()
            .ok_or_else(|| anyhow!("environment binding name is not a string"))?;
        validate_env_name(name)?;
        let template = template
            .as_str()
            .ok_or_else(|| anyhow!("environment binding value is not a string"))?;
        let shape = template_shape(template)?;
        bindings.push(EnvironmentBinding {
            name: name.to_string(),
            placeholder_names: shape.placeholder_names,
            contains_literal_component: shape.contains_literal_component,
        });
    }
    bindings.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(bindings)
}

fn template_shape(template: &str) -> Result<TemplateShape> {
    validate_token(template, "template")?;
    let mut placeholders = BTreeSet::new();
    let mut literal_bytes = 0usize;
    let bytes = template.as_bytes();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        if bytes[cursor] == b'}' {
            return Err(anyhow!("template contains an unmatched closing brace"));
        }
        if bytes[cursor] != b'{' {
            literal_bytes += 1;
            cursor += 1;
            continue;
        }
        let start = cursor + 1;
        let Some(relative_end) = bytes[start..].iter().position(|byte| *byte == b'}') else {
            return Err(anyhow!("template contains an unmatched opening brace"));
        };
        let end = start + relative_end;
        let name = std::str::from_utf8(&bytes[start..end]).context("template placeholder UTF-8")?;
        validate_identifier(name, "template placeholder")?;
        placeholders.insert(name.to_string());
        cursor = end + 1;
    }
    Ok(TemplateShape {
        placeholder_names: placeholders.into_iter().collect(),
        contains_literal_component: literal_bytes > 0,
    })
}

fn parse_output_class(implementation: &Mapping) -> Result<OutputClass> {
    match optional_string(implementation, "content_type")?.as_deref() {
        None | Some("tool_output") => Ok(OutputClass::ToolOutput),
        Some("email") => Ok(OutputClass::Email),
        Some("web") => Ok(OutputClass::Web),
        Some("file") => Ok(OutputClass::File),
        Some(other) => Err(anyhow!("unsupported content_type '{other}'")),
    }
}

fn validate_google_workspace_coverage(
    inventory: &SourceInventory,
    fixtures: &[ReplayFixture],
) -> Result<()> {
    let present = inventory
        .skills
        .iter()
        .filter(|skill| GOOGLE_WORKSPACE_SKILLS.contains(&skill.id.as_str()))
        .map(|skill| skill.id.as_str())
        .collect::<BTreeSet<_>>();
    if present.is_empty() {
        return Ok(());
    }
    let expected = GOOGLE_WORKSPACE_SKILLS.into_iter().collect::<BTreeSet<_>>();
    if present != expected {
        return Err(anyhow!(
            "Google Workspace replay coverage is partial: found {} of 6 skills",
            present.len()
        ));
    }
    let count = fixtures
        .iter()
        .filter(|fixture| GOOGLE_WORKSPACE_SKILLS.contains(&fixture.skill_id.as_str()))
        .count();
    if count != EXPECTED_GOOGLE_WORKSPACE_ACTIONS {
        return Err(anyhow!(
            "Google Workspace replay coverage is {count}; expected {EXPECTED_GOOGLE_WORKSPACE_ACTIONS}"
        ));
    }
    Ok(())
}

fn count_dispatch(fixtures: &[ReplayFixture], kind: DispatchKind) -> usize {
    fixtures
        .iter()
        .filter(|fixture| fixture.dispatch.kind == kind)
        .count()
}

fn mapping_get<'a>(mapping: &'a Mapping, key: &str) -> Option<&'a Value> {
    mapping.get(Value::String(key.to_string()))
}

fn as_mapping<'a>(value: &'a Value, label: &str) -> Result<&'a Mapping> {
    value
        .as_mapping()
        .ok_or_else(|| anyhow!("{label} must be a mapping"))
}

fn required_mapping<'a>(mapping: &'a Mapping, key: &str) -> Result<&'a Mapping> {
    optional_mapping(mapping, key)?.ok_or_else(|| anyhow!("missing required mapping '{key}'"))
}

fn optional_mapping<'a>(mapping: &'a Mapping, key: &str) -> Result<Option<&'a Mapping>> {
    mapping_get(mapping, key)
        .map(|value| as_mapping(value, key))
        .transpose()
}

fn required_string(mapping: &Mapping, key: &str) -> Result<String> {
    optional_string(mapping, key)?.ok_or_else(|| anyhow!("missing required string '{key}'"))
}

fn optional_string(mapping: &Mapping, key: &str) -> Result<Option<String>> {
    mapping_get(mapping, key)
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| anyhow!("'{key}' must be a string"))
        })
        .transpose()
}

fn required_string_sequence(mapping: &Mapping, key: &str) -> Result<Vec<String>> {
    optional_string_sequence(mapping, key)?
        .ok_or_else(|| anyhow!("missing required string sequence '{key}'"))
}

fn optional_string_sequence(mapping: &Mapping, key: &str) -> Result<Option<Vec<String>>> {
    mapping_get(mapping, key)
        .map(|value| {
            value
                .as_sequence()
                .ok_or_else(|| anyhow!("'{key}' must be a sequence"))?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_string)
                        .ok_or_else(|| anyhow!("'{key}' must contain only strings"))
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()
}

fn optional_bool(mapping: &Mapping, key: &str) -> Result<Option<bool>> {
    mapping_get(mapping, key)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| anyhow!("'{key}' must be a boolean"))
        })
        .transpose()
}

fn parse_u64(value: &Value, label: &str) -> Result<u64> {
    value
        .as_u64()
        .ok_or_else(|| anyhow!("{label} must be a non-negative integer"))
}

fn parse_value_kind(value: &str) -> Result<ReplayValueKind> {
    match value {
        "string" => Ok(ReplayValueKind::String),
        "integer" => Ok(ReplayValueKind::Integer),
        "number" => Ok(ReplayValueKind::Number),
        "boolean" => Ok(ReplayValueKind::Boolean),
        "array" => Ok(ReplayValueKind::Array),
        "object" => Ok(ReplayValueKind::Object),
        other => Err(anyhow!("unsupported parameter type '{other}'")),
    }
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !valid {
        return Err(anyhow!("{label} '{value}' is not a safe identifier"));
    }
    Ok(())
}

fn validate_path_segment(value: &str, label: &str) -> Result<()> {
    validate_identifier(value, label)?;
    if matches!(value, "." | "..") {
        return Err(anyhow!("{label} '{value}' is not a safe path segment"));
    }
    Ok(())
}

fn validate_env_name(value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    if !valid {
        return Err(anyhow!("environment name '{value}' is invalid"));
    }
    Ok(())
}

fn validate_tokens(tokens: &[String], label: &str) -> Result<()> {
    if tokens.len() > MAX_STATIC_TOKENS {
        return Err(anyhow!("{label} exceeds the static-token safety limit"));
    }
    for token in tokens {
        validate_token(token, label)?;
    }
    Ok(())
}

fn validate_token(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_TOKEN_BYTES || value.chars().any(char::is_control) {
        return Err(anyhow!("{label} contains an invalid bounded argv token"));
    }
    Ok(())
}

fn enum_label<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

fn markdown_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('`', "\\`")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        classification::{
            AuthRequirement, IdentityVerification, ProfilePolicy, ProfileSource,
            SessionClassification, SessionOwner, SessionStore, SetupPath, SkillClassification,
        },
        inventory::{
            AuthSurface, ExecutionSurface, ImplementationSurface, SkillSourcePaths,
            SourceInventorySummary,
        },
    };
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static TEST_ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "tool-runtime-replay-{}-{nonce}-{}",
                std::process::id(),
                TEST_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).expect("create fixture root");
            Self(path)
        }

        fn add(&self, id: &str, schema: &str, action_names: &[&str]) -> ToolSkillSourceInventory {
            let directory = self.0.join(id);
            fs::create_dir_all(&directory).expect("create skill");
            fs::write(directory.join("tool_schema.yaml"), schema).expect("write schema");
            ToolSkillSourceInventory {
                id: id.to_string(),
                version: Some("1.0.0".to_string()),
                declared_skill_type: Some("tool".to_string()),
                sources: SkillSourcePaths {
                    skill_markdown: format!("{id}/SKILL.md"),
                    tool_schema: format!("{id}/tool_schema.yaml"),
                },
                required_binaries: Vec::new(),
                required_env_names: Vec::new(),
                action_names: action_names
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
                implementation: ImplementationSurface::default(),
                auth: AuthSurface::default(),
                profile_selectors: Vec::new(),
                execution: ExecutionSurface::default(),
                adapter_files: Vec::new(),
            }
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn classification(id: &str, owner: RuntimeOwner) -> SkillClassification {
        SkillClassification {
            id: id.to_string(),
            auth_strategies: vec![AuthStrategy::None],
            auth_requirement: AuthRequirement::None,
            auth_provider: None,
            profile: ProfileClassification {
                policy: ProfilePolicy::None,
                source: ProfileSource::None,
                selector: None,
                fixed_alias: None,
            },
            session: SessionClassification {
                owner: SessionOwner::None,
                store: SessionStore::None,
            },
            setup_path: SetupPath::None,
            identity_verification: IdentityVerification::None,
            approval_class: ApprovalClass::Ordinary,
            runtime_owner: owner,
        }
    }

    fn compile(
        root: &TestRoot,
        skills: Vec<ToolSkillSourceInventory>,
        classified: Vec<SkillClassification>,
    ) -> Result<ReplayFixtureCatalog> {
        let actions = skills.iter().map(|skill| skill.action_names.len()).sum();
        ReplayCompiler::compile_inventory_join(
            &root.0,
            &SourceInventory {
                schema_version: SOURCE_INVENTORY_SCHEMA_VERSION.to_string(),
                source_root: "test".to_string(),
                activation_rule: "test".to_string(),
                summary: SourceInventorySummary {
                    active_tool_skills: skills.len(),
                    schema_actions: actions,
                    ..Default::default()
                },
                skills,
                findings: Vec::new(),
            },
            &SourceClassification {
                schema_version: CLASSIFICATION_SCHEMA_VERSION.to_string(),
                source_inventory_schema_version: SOURCE_INVENTORY_SCHEMA_VERSION.to_string(),
                summary: Default::default(),
                skills: classified,
                adapters: Vec::new(),
                finding_dispositions: Vec::new(),
                exceptions: Vec::new(),
                unknowns: Vec::new(),
            },
        )
    }

    #[test]
    fn compiles_exact_primitive_recipe_without_defaults_or_env_values() {
        let root = TestRoot::new();
        let mut skill = root.add(
            "demo",
            r#"name: demo
parameters:
- name: profile
  param_type: string
  default: secret-default-canary
native_action_schemas:
  run:
    description: prose-canary
    argv: [sub, run]
    parameters: [profile, input, enabled, stdin]
    required: [input]
    parameter_overrides:
      input: {type: string, default: parameter-secret-canary}
      enabled: {type: boolean}
      stdin: {type: string}
    arg_mappings:
    - {type: flag, flag: --input, param: input}
    - {type: bool_flag, flag: --enabled, param: enabled}
    suffix_args: [--json]
    timeout_secs: 17
implementation:
  type: primitive
  command: [tool, family]
  program: ignored-program
  fixed_args: [ignored-fixed]
  arg_mappings: [{type: positional, param: profile}]
  content_type: email
  env:
    DEMO_HOME: "{scope_capability_auth_root}/demo-{profile}-env-secret-canary"
  suffix_args: [--quiet]
execution:
  default_timeout_secs: 9
"#,
            &["run"],
        );
        skill.required_env_names = vec!["DEMO_TOKEN".to_string()];
        let catalog = compile(
            &root,
            vec![skill],
            vec![classification("demo", RuntimeOwner::ExternalCli)],
        )
        .expect("compile");
        let fixture = &catalog.fixtures[0];
        assert_eq!(fixture.dispatch.program.as_deref(), Some("tool"));
        assert_eq!(fixture.dispatch.prefix_args, ["family"]);
        assert_eq!(fixture.dispatch.action_args, ["sub", "run"]);
        assert_eq!(fixture.dispatch.action_suffix_args, ["--json"]);
        assert_eq!(fixture.dispatch.implementation_suffix_args, ["--quiet"]);
        assert_eq!(fixture.timeout.default_secs, Some(17));
        assert_eq!(fixture.timeout.source, TimeoutSource::Action);
        assert!(fixture.stdin.accepted && fixture.stdin.parameter_declared);
        assert_eq!(fixture.output_class, OutputClass::ToolOutput);
        assert_eq!(fixture.ignored_legacy_fields.len(), 4);
        assert_eq!(fixture.environment.bindings[0].name, "DEMO_HOME");
        assert_eq!(
            fixture.environment.bindings[0].placeholder_names,
            ["profile", "scope_capability_auth_root"]
        );
        let json = catalog.to_pretty_json().expect("json");
        let report = catalog.to_markdown();
        for canary in [
            "secret-default-canary",
            "parameter-secret-canary",
            "prose-canary",
            "env-secret-canary",
        ] {
            assert!(!json.contains(canary), "leaked {canary}");
            assert!(!report.contains(canary), "report leaked {canary}");
        }
    }

    #[test]
    fn command_recipe_records_action_metadata_as_ignored() {
        let root = TestRoot::new();
        let skill = root.add(
            "draw",
            r#"name: draw
native_action_schemas:
  render:
    argv: [ignored]
    parameters: [shape]
    required: [shape]
    parameter_overrides: {shape: {type: string}}
    skip_tool_name: true
    arg_mappings: [{type: flag, flag: --ignored, param: shape}]
    suffix_args: [ignored]
    timeout_secs: 2
implementation:
  type: command
  program: curl
  fixed_args: [-s, -X, POST]
  arg_mappings: [{type: positional, param: shape}]
  suffix_args: [--fail]
  content_type: web
execution: {default_timeout_secs: 5}
"#,
            &["render"],
        );
        let catalog = compile(
            &root,
            vec![skill],
            vec![classification("draw", RuntimeOwner::HostGateway)],
        )
        .expect("compile");
        let fixture = &catalog.fixtures[0];
        assert_eq!(fixture.dispatch.kind, DispatchKind::CommandProcess);
        assert_eq!(fixture.dispatch.prefix_args, ["-s", "-X", "POST"]);
        assert!(fixture.dispatch.action_args.is_empty());
        assert_eq!(fixture.timeout.default_secs, Some(5));
        assert_eq!(fixture.output_class, OutputClass::Web);
        assert_eq!(fixture.ignored_legacy_fields.len(), 5);
    }

    #[test]
    fn projects_all_mapping_forms_in_source_order() {
        let root = TestRoot::new();
        let skill = root.add(
            "mapping-demo",
            r#"name: mapping-demo
native_action_schemas:
  run:
    parameters: [first, second, enabled, words, tail]
    parameter_overrides:
      first: {type: string}
      second: {type: string}
      enabled: {type: boolean}
      words: {type: string}
      tail: {type: array}
    arg_mappings:
    - {type: positional, param: first}
    - {type: flag, flag: --second, param: second}
    - {type: bool_flag, flag: --enabled, param: enabled}
    - {type: split_positional, param: words}
    - {type: env_flag, flag: --token, env_var: DEMO_TOKEN}
    - {type: fixed_args, args: [fixed, value]}
    - {type: passthrough, param: tail}
implementation: {type: primitive, command: [demo]}
"#,
            &["run"],
        );
        let catalog = compile(
            &root,
            vec![skill],
            vec![classification("mapping-demo", RuntimeOwner::ExternalCli)],
        )
        .expect("compile");
        assert_eq!(
            catalog.fixtures[0].dispatch.mappings,
            vec![
                ReplayArgMapping::Positional {
                    param: "first".to_string(),
                },
                ReplayArgMapping::Flag {
                    flag: "--second".to_string(),
                    param: "second".to_string(),
                },
                ReplayArgMapping::BoolFlag {
                    flag: "--enabled".to_string(),
                    param: "enabled".to_string(),
                },
                ReplayArgMapping::SplitPositional {
                    param: "words".to_string(),
                },
                ReplayArgMapping::EnvFlag {
                    flag: "--token".to_string(),
                    env_var: "DEMO_TOKEN".to_string(),
                },
                ReplayArgMapping::FixedArgs {
                    args: vec!["fixed".to_string(), "value".to_string()],
                },
                ReplayArgMapping::Passthrough {
                    param: "tail".to_string(),
                },
            ]
        );
        assert_eq!(
            catalog.fixtures[0].environment.mapping_names,
            ["DEMO_TOKEN"]
        );
    }

    #[test]
    fn compiled_provider_has_no_invented_process() {
        let root = TestRoot::new();
        let skill = root.add(
            "browser",
            "name: browser\nnative_action_schemas:\n  click:\n    parameters: [args]\n    parameter_overrides:\n      args: {type: array}\nimplementation:\n  type: primitive\n  command: [ignored]\n  cwd: /ignored\n  env: {IGNORED: literal}\n  suffix_args: [ignored]\n  timeout_secs: 7\n",
            &["click"],
        );
        let catalog = compile(
            &root,
            vec![skill],
            vec![classification("browser", RuntimeOwner::CompiledProvider)],
        )
        .expect("compile");
        let fixture = &catalog.fixtures[0];
        assert_eq!(fixture.dispatch.kind, DispatchKind::CompiledProvider);
        assert_eq!(fixture.dispatch.program, None);
        assert_eq!(fixture.dispatch.provider_name.as_deref(), Some("browser"));
        assert_eq!(fixture.dispatch.argument_mode, ArgumentMode::CompiledSchema);
        assert!(!fixture.stdin.accepted);
        assert_eq!(fixture.timeout.default_secs, None);
        assert_eq!(
            fixture.timeout.source,
            TimeoutSource::CompiledProviderDefault
        );
        assert!(!fixture.timeout.caller_override_supported);
        assert!(fixture.environment.bindings.is_empty());
        assert_eq!(fixture.cwd, None);
        assert!(fixture
            .ignored_legacy_fields
            .contains(&IgnoredLegacyField::CompiledCommand));
        assert!(fixture
            .ignored_legacy_fields
            .contains(&IgnoredLegacyField::CompiledCwd));
        assert!(fixture
            .ignored_legacy_fields
            .contains(&IgnoredLegacyField::CompiledEnv));
        assert!(fixture
            .ignored_legacy_fields
            .contains(&IgnoredLegacyField::CompiledSuffixArgs));
        assert!(fixture
            .ignored_legacy_fields
            .contains(&IgnoredLegacyField::CompiledTimeout));
    }

    #[test]
    fn executable_route_and_classification_must_agree() {
        let root = TestRoot::new();
        let browser = root.add(
            "browser",
            "name: browser\nnative_action_schemas:\n  open: {parameters: []}\nimplementation: {type: primitive}\n",
            &["open"],
        );
        assert!(compile(
            &root,
            vec![browser],
            vec![classification("browser", RuntimeOwner::ExternalCli)]
        )
        .is_err());

        let provider = root.add(
            "provider-demo",
            "name: provider-demo\nnative_action_schemas:\n  run: {parameters: []}\nimplementation: {type: primitive, provider_name: native-demo}\n",
            &["run"],
        );
        let catalog = compile(
            &root,
            vec![provider],
            vec![classification(
                "provider-demo",
                RuntimeOwner::CompiledProvider,
            )],
        )
        .expect("compiled provider route");
        assert_eq!(
            catalog.fixtures[0].dispatch.provider_name.as_deref(),
            Some("native-demo")
        );
    }

    #[test]
    fn public_compiler_rejects_stale_inventory_and_classification() {
        let root = TestRoot::new();
        let skill_root = root.0.join("exact");
        fs::create_dir_all(&skill_root).expect("create exact skill");
        fs::write(
            skill_root.join("SKILL.md"),
            "---\nname: exact\nversion: 1.0.0\nmetadata:\n  magician:\n    skill_type: tool\n---\n# Exact\n",
        )
        .expect("write exact skill manifest");
        fs::write(
            skill_root.join("tool_schema.yaml"),
            "name: exact\nversion: 1.0.0\nnative_action_schemas:\n  run: {parameters: []}\nimplementation: {type: primitive, command: [exact]}\n",
        )
        .expect("write exact schema");

        let inventory = SourceInventoryScanner::new(&root.0, "test")
            .expect("scanner")
            .scan()
            .expect("inventory");
        let manifest = ClassificationManifest::from_yaml(
            r#"
schema_version: tool-runtime.source-classification-manifest.v1
inventory_schema_version: tool-runtime.source-inventory.v1
skill_groups:
  - skills: [exact]
    auth_strategies: [none]
    auth_requirement: none
    auth_provider: null
    profile: { policy: none, source: none, selector: null, fixed_alias: null }
    session: { owner: none, store: none }
    setup_path: none
    identity_verification: none
    approval_class: ordinary
    runtime_owner: external_cli
adapter_groups: []
finding_dispositions: []
exceptions: []
unknowns: []
"#,
        )
        .expect("manifest");
        let classification =
            ClassificationCompiler::compile(&inventory, manifest.clone()).expect("classification");
        ReplayCompiler::compile(&root.0, &inventory, manifest.clone(), &classification)
            .expect("fresh inputs");

        let mut stale_inventory = inventory.clone();
        stale_inventory.activation_rule = "stale".to_string();
        assert!(ReplayCompiler::compile(
            &root.0,
            &stale_inventory,
            manifest.clone(),
            &classification,
        )
        .is_err());

        let mut stale_classification = classification.clone();
        stale_classification.skills[0].runtime_owner = RuntimeOwner::SkillAdapter;
        assert!(
            ReplayCompiler::compile(&root.0, &inventory, manifest, &stale_classification,).is_err()
        );
    }

    #[test]
    fn rejects_missing_extra_duplicate_and_invalid_mapping_parameters() {
        let root = TestRoot::new();
        let skill = root.add(
            "bad",
            "name: bad\nnative_action_schemas:\n  run:\n    parameters: [input]\n    parameter_overrides: {input: {type: string}}\n    arg_mappings: [{type: positional, param: missing}]\nimplementation: {type: primitive}\n",
            &["run"],
        );
        assert!(compile(
            &root,
            vec![skill.clone()],
            vec![classification("bad", RuntimeOwner::ExternalCli)]
        )
        .is_err());
        let mut missing = skill.clone();
        missing.action_names = vec!["other".to_string()];
        assert!(compile(
            &root,
            vec![missing],
            vec![classification("bad", RuntimeOwner::ExternalCli)]
        )
        .is_err());
        assert!(compile(
            &root,
            vec![skill],
            vec![
                classification("bad", RuntimeOwner::ExternalCli),
                classification("bad", RuntimeOwner::ExternalCli),
            ]
        )
        .is_err());
    }

    #[test]
    fn rejects_invalid_environment_names_and_deep_yaml_without_recursing() {
        let root = TestRoot::new();
        let invalid = root.add(
            "invalid-env",
            "name: invalid-env\nnative_action_schemas:\n  run: {parameters: []}\nimplementation:\n  type: primitive\n  env: {BAD-NAME: value}\n",
            &["run"],
        );
        assert!(compile(
            &root,
            vec![invalid],
            vec![classification("invalid-env", RuntimeOwner::ExternalCli)]
        )
        .is_err());

        let invalid_token = root.add(
            "invalid-token",
            "name: invalid-token\nnative_action_schemas:\n  run: {parameters: []}\nimplementation:\n  type: primitive\n  command: ['']\n",
            &["run"],
        );
        assert!(compile(
            &root,
            vec![invalid_token],
            vec![classification("invalid-token", RuntimeOwner::ExternalCli)]
        )
        .is_err());

        let invalid_template = root.add(
            "invalid-template",
            "name: invalid-template\nnative_action_schemas:\n  run: {parameters: []}\nimplementation:\n  type: primitive\n  env: {GOOD_NAME: '{broken'}\n",
            &["run"],
        );
        assert!(compile(
            &root,
            vec![invalid_template],
            vec![classification(
                "invalid-template",
                RuntimeOwner::ExternalCli
            )]
        )
        .is_err());

        let nested = format!(
            "name: deep\nnative_action_schemas:\n  run: {{parameters: []}}\nimplementation:\n  type: primitive\n  command: [{}]\n",
            "[".repeat(80) + &"]".repeat(80)
        );
        let deep = root.add("deep", &nested, &["run"]);
        assert!(compile(
            &root,
            vec![deep],
            vec![classification("deep", RuntimeOwner::ExternalCli)]
        )
        .is_err());
    }

    #[test]
    fn rejects_alias_expansion_and_projection_amplification_before_output() {
        let safe_alias = "parameters:\n  shared: &shared\n    type: string\n  copy: *shared\n";
        validate_yaml_alias_safety(safe_alias).expect("single-level alias");
        let nested_alias = "parameters:\n  first: &first\n    type: string\n  second: &second\n    values: [*first, *first]\n";
        assert!(validate_yaml_alias_safety(nested_alias).is_err());

        let dispatch = ReplayDispatch {
            kind: DispatchKind::PrimitiveProcess,
            program: Some("demo".to_string()),
            provider_name: None,
            prefix_args: Vec::new(),
            action_args: Vec::new(),
            argument_mode: ArgumentMode::ArgsOrSortedFlags,
            mappings: Vec::new(),
            action_suffix_args: Vec::new(),
            implementation_suffix_args: Vec::new(),
            argument_rules: TypedArgumentRules::default(),
        };
        let mut remaining = 0;
        assert!(consume_projection_budget(&mut remaining, &[], &[], &[], &dispatch).is_err());
        assert!(validate_path_segment("..", "skill id").is_err());
    }

    #[test]
    fn parsed_yaml_depth_budget_is_iterative() {
        let mut value = Value::Null;
        for _ in 0..=MAX_PARSED_YAML_DEPTH {
            value = Value::Sequence(vec![value]);
        }
        assert!(validate_parsed_yaml_budget(&value).is_err());
    }

    #[test]
    fn output_is_deterministic_across_source_order() {
        let root = TestRoot::new();
        let alpha = root.add(
            "alpha",
            "name: alpha\nnative_action_schemas:\n  z: {parameters: []}\n  a: {parameters: []}\nimplementation: {type: primitive}\n",
            &["a", "z"],
        );
        let beta = root.add(
            "beta",
            "name: beta\nnative_action_schemas:\n  b: {parameters: []}\nimplementation: {type: primitive}\n",
            &["b"],
        );
        let left = compile(
            &root,
            vec![beta.clone(), alpha.clone()],
            vec![
                classification("alpha", RuntimeOwner::ExternalCli),
                classification("beta", RuntimeOwner::ExternalCli),
            ],
        )
        .expect("left");
        let right = compile(
            &root,
            vec![alpha, beta],
            vec![
                classification("beta", RuntimeOwner::ExternalCli),
                classification("alpha", RuntimeOwner::ExternalCli),
            ],
        )
        .expect("right");
        assert_eq!(
            left.to_pretty_json().unwrap(),
            right.to_pretty_json().unwrap()
        );
        assert_eq!(
            left.fixtures
                .iter()
                .map(|item| item.id.as_str())
                .collect::<Vec<_>>(),
            ["alpha::a", "alpha::z", "beta::b"]
        );
    }

    #[test]
    fn partial_google_workspace_family_is_rejected() {
        let root = TestRoot::new();
        let gmail = root.add(
            "gmail",
            "name: gmail\nnative_action_schemas:\n  read: {parameters: []}\nimplementation: {type: primitive}\n",
            &["read"],
        );
        let error = compile(
            &root,
            vec![gmail],
            vec![classification("gmail", RuntimeOwner::ExternalCli)],
        )
        .expect_err("partial family must fail");
        assert!(error.to_string().contains("partial"));
    }
}
