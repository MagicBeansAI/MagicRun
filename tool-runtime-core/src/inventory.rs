//! Deterministic, secret-safe source inventory for schema-backed tool skills.
//!
//! This is an audit boundary, not a runtime loader. It deliberately projects a
//! small allowlisted subset of `SKILL.md` and `tool_schema.yaml`; arbitrary
//! values, command bodies, defaults, and prose never enter the inventory.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use walkdir::WalkDir;

use crate::{
    action_overrides::{compile_typed_action_overrides, ActionOverrideError},
    manifest::{AuthKind, AuthRequirement, InjectionTarget, ProfileSelection, RuntimeProtocol},
    manifest_parser::{parse_skill_runtime_package, ManifestParseError, ManifestParseErrorCode},
    manifest_validation::{validate_skill_runtime_contract, ManifestValidationError},
    mcp_catalog_projection::{project_mcp_catalog, OFFICIAL_MCP_SDK_IMPLEMENTATION},
};

pub const SOURCE_INVENTORY_SCHEMA_VERSION: &str = "tool-runtime.source-inventory.v1";

const MAX_SOURCE_BYTES: u64 = 1024 * 1024;
const MAX_ACTIVE_SKILLS: usize = 1_024;
const MAX_ACTIONS_PER_SKILL: usize = 2_048;
const MAX_ADAPTER_FILES_PER_SKILL: usize = 512;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_YAML_INDENT_BYTES: usize = 256;
const MAX_YAML_FLOW_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceInventory {
    pub schema_version: String,
    pub source_root: String,
    pub activation_rule: String,
    pub summary: SourceInventorySummary,
    pub skills: Vec<ToolSkillSourceInventory>,
    pub findings: Vec<InventoryFinding>,
}

impl SourceInventory {
    pub fn has_errors(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity == FindingSeverity::Error)
    }

    pub fn to_pretty_json(&self) -> Result<String> {
        let mut rendered =
            serde_json::to_string_pretty(self).context("serializing source inventory as JSON")?;
        rendered.push('\n');
        Ok(rendered)
    }

    pub fn to_markdown(&self) -> String {
        let mut out = String::from(
            "# Tool Runtime Phase 0A Source Inventory\n\n\
             This report is generated from the canonical schema-backed tool-skill source. \
             It contains only allowlisted identifiers and counts: credential values, \
             lifecycle command bodies, arbitrary defaults, and skill prose are never \
             copied into this artifact.\n\n",
        );
        out.push_str("## Summary\n\n");
        out.push_str(&format!(
            "- Schema version: `{}`\n\
             - Activation rule: {}\n\
             - Active tool skills: {}\n\
             - Schema actions: {}\n\
             - Auth blocks: {}\n\
             - Required binary declarations: {}\n\
             - Required environment-name declarations: {}\n\
             - Injected environment-name declarations: {}\n\
             - Adapter/support files: {}\n\
             - Profile selectors: {}\n\
             - Errors: {}\n\
             - Warnings: {}\n\n",
            self.schema_version,
            self.activation_rule,
            self.summary.active_tool_skills,
            self.summary.schema_actions,
            self.summary.auth_blocks,
            self.summary.required_binary_declarations,
            self.summary.required_env_name_declarations,
            self.summary.injected_env_name_declarations,
            self.summary.adapter_files,
            self.summary.profile_selectors,
            self.summary.errors,
            self.summary.warnings,
        ));

        out.push_str("## Active tool skills\n\n");
        out.push_str(
            "| Skill | Version | Program | Actions | Auth | Required env | Adapters | Profiles |\n\
             |---|---:|---|---:|---:|---:|---:|---|\n",
        );
        for skill in &self.skills {
            let profiles = skill
                .profile_selectors
                .iter()
                .map(|selector| selector.parameter.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!(
                "| `{}` | `{}` | `{}` | {} | {} | {} | {} | {} |\n",
                markdown_cell(&skill.id),
                markdown_cell(skill.version.as_deref().unwrap_or("unknown")),
                markdown_cell(skill.implementation.program.as_deref().unwrap_or("unknown")),
                skill.action_names.len(),
                if skill.auth.declared { "yes" } else { "no" },
                skill.required_env_names.len(),
                skill.adapter_files.len(),
                if profiles.is_empty() {
                    "—".to_string()
                } else {
                    markdown_cell(&profiles)
                },
            ));
        }

        out.push_str("\n## Findings\n\n");
        if self.findings.is_empty() {
            out.push_str("No inventory-contract findings.\n");
        } else {
            for finding in &self.findings {
                out.push_str(&format!(
                    "- **{:?}** `{}` `{}`: {}\n",
                    finding.severity,
                    markdown_cell(&finding.code),
                    markdown_cell(&finding.source),
                    finding.detail,
                ));
            }
        }
        out
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceInventorySummary {
    pub active_tool_skills: usize,
    pub schema_actions: usize,
    pub auth_blocks: usize,
    pub required_binary_declarations: usize,
    pub required_env_name_declarations: usize,
    pub injected_env_name_declarations: usize,
    pub adapter_files: usize,
    pub profile_selectors: usize,
    pub errors: usize,
    pub warnings: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolSkillSourceInventory {
    pub id: String,
    pub version: Option<String>,
    pub declared_skill_type: Option<String>,
    pub sources: SkillSourcePaths,
    pub required_binaries: Vec<String>,
    pub required_env_names: Vec<String>,
    pub action_names: Vec<String>,
    pub implementation: ImplementationSurface,
    pub auth: AuthSurface,
    pub profile_selectors: Vec<ProfileSelector>,
    pub execution: ExecutionSurface,
    pub adapter_files: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillSourcePaths {
    pub skill_markdown: String,
    pub tool_schema: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImplementationSurface {
    pub kind: Option<String>,
    pub program: Option<String>,
    pub fixed_prefix_arity: usize,
    pub injected_env_names: Vec<String>,
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthSurface {
    pub declared: bool,
    pub required: Option<bool>,
    pub lifecycle_hooks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileSelector {
    pub parameter: String,
    pub aliases: Vec<String>,
    pub default_alias: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionSurface {
    pub requires_browser_session: Option<bool>,
    pub categories: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryFinding {
    pub severity: FindingSeverity,
    pub code: String,
    pub skill_id: Option<String>,
    pub source: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct SourceInventoryScanner {
    skill_root: PathBuf,
    source_label: String,
}

impl SourceInventoryScanner {
    pub fn new(skill_root: impl Into<PathBuf>, source_label: impl Into<String>) -> Result<Self> {
        let skill_root = skill_root.into();
        let source_label = source_label.into();
        validate_relative_label(&source_label)?;
        Ok(Self {
            skill_root,
            source_label,
        })
    }

    pub fn scan(&self) -> Result<SourceInventory> {
        if !self.skill_root.is_dir() {
            return Err(anyhow!(
                "skill root '{}' is not a directory",
                self.skill_root.display()
            ));
        }

        let mut skill_dirs = Vec::new();
        for entry in fs::read_dir(&self.skill_root)
            .with_context(|| format!("reading skill root '{}'", self.skill_root.display()))?
        {
            let entry = entry.context("reading skill-root directory entry")?;
            let file_type = entry.file_type().context("reading skill entry type")?;
            if !file_type.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            let has_schema = entry.path().join("tool_schema.yaml").is_file();
            let has_runtime_package = entry.path().join("SKILL.md").is_file()
                && fs::read_to_string(entry.path().join("SKILL.md"))
                    .ok()
                    .is_some_and(|source| source.contains("runtime_contract:"));
            if !has_schema && !has_runtime_package {
                continue;
            }
            skill_dirs.push((name, entry.path()));
        }
        skill_dirs.sort_by(|left, right| left.0.cmp(&right.0));
        if skill_dirs.len() > MAX_ACTIVE_SKILLS {
            return Err(anyhow!(
                "active tool-skill count {} exceeds limit {}",
                skill_dirs.len(),
                MAX_ACTIVE_SKILLS
            ));
        }

        let mut skills = Vec::with_capacity(skill_dirs.len());
        let mut findings = Vec::new();
        for (directory_id, directory) in skill_dirs {
            match self.scan_skill(&directory_id, &directory, &mut findings) {
                Ok(Some(skill)) => skills.push(skill),
                Ok(None) => {},
                Err(error) => {
                    findings.push(self.finding(
                        FindingSeverity::Error,
                        "skill_scan_failed",
                        Some(&directory_id),
                        &directory_id,
                        safe_error_class(&error),
                    ));
                },
            }
        }

        skills.sort_by(|left, right| left.id.cmp(&right.id));
        findings.sort_by(|left, right| {
            (
                left.severity as u8,
                left.skill_id.as_deref(),
                left.code.as_str(),
                left.source.as_str(),
            )
                .cmp(&(
                    right.severity as u8,
                    right.skill_id.as_deref(),
                    right.code.as_str(),
                    right.source.as_str(),
                ))
        });

        let mut inventory = SourceInventory {
            schema_version: SOURCE_INVENTORY_SCHEMA_VERSION.to_string(),
            source_root: self.source_label.clone(),
            activation_rule: "direct child directory containing one governed SKILL.md runtime package or legacy tool_schema.yaml".to_string(),
            summary: SourceInventorySummary::default(),
            skills,
            findings,
        };
        inventory.summary = summarize(&inventory);
        Ok(inventory)
    }

    fn scan_skill(
        &self,
        directory_id: &str,
        directory: &Path,
        findings: &mut Vec<InventoryFinding>,
    ) -> Result<Option<ToolSkillSourceInventory>> {
        if !is_safe_identifier(directory_id) {
            findings.push(self.finding(
                FindingSeverity::Error,
                "unsafe_skill_directory_name",
                Some(directory_id),
                directory_id,
                "skill directory is not a bounded portable identifier",
            ));
            return Ok(None);
        }

        let schema_path = directory.join("tool_schema.yaml");
        let skill_path = directory.join("SKILL.md");
        if !skill_path.is_file() {
            findings.push(self.finding(
                FindingSeverity::Error,
                "missing_skill_markdown",
                Some(directory_id),
                &format!("{directory_id}/SKILL.md"),
                "schema-backed tool has no sibling SKILL.md",
            ));
            return Ok(None);
        }

        let skill_source = read_bounded_utf8(&skill_path)?;
        let frontmatter_source = extract_frontmatter(&skill_source)
            .ok_or_else(|| anyhow!("SKILL.md has no bounded YAML frontmatter"))?;
        validate_yaml_shape(frontmatter_source).context("validating SKILL.md YAML shape")?;
        let frontmatter: Value =
            serde_yaml::from_str(frontmatter_source).context("parsing SKILL.md frontmatter")?;
        let governed_package = parse_skill_runtime_package(&skill_source)
            .context("parsing governed SKILL.md runtime package")?;
        if governed_package.is_some() && schema_path.is_file() {
            findings.push(self.finding(
                FindingSeverity::Error,
                "duplicate_active_catalog_sources",
                Some(directory_id),
                directory_id,
                "skill declares both a governed runtime package and legacy tool_schema.yaml",
            ));
            return Ok(None);
        }
        if let Some(package) = governed_package {
            return self.scan_governed_skill(
                directory_id,
                directory,
                &frontmatter,
                package,
                findings,
            );
        }
        let schema_source = read_bounded_utf8(&schema_path)?;
        validate_yaml_shape(&schema_source).context("validating tool_schema.yaml shape")?;
        let schema: Value =
            serde_yaml::from_str(&schema_source).context("parsing tool_schema.yaml")?;

        let manifest_name = safe_scalar(mapping_get(&frontmatter, "name"));
        let schema_name = safe_scalar(mapping_get(&schema, "name"));
        compare_declared_name(
            directory_id,
            manifest_name.as_deref(),
            "skill_name_mismatch",
            "SKILL.md",
            findings,
            self,
        );
        compare_declared_name(
            directory_id,
            schema_name.as_deref(),
            "schema_name_mismatch",
            "tool_schema.yaml",
            findings,
            self,
        );

        let manifest_version = safe_scalar(mapping_get(&frontmatter, "version"));
        let schema_version = safe_scalar(mapping_get(&schema, "version"));
        if manifest_version.is_some()
            && schema_version.is_some()
            && manifest_version != schema_version
        {
            findings.push(self.finding(
                FindingSeverity::Warning,
                "version_mismatch",
                Some(directory_id),
                &format!("{directory_id}/tool_schema.yaml"),
                "SKILL.md and tool_schema.yaml declare different versions",
            ));
        }

        let magician_metadata =
            mapping_get(&frontmatter, "metadata").and_then(|value| mapping_get(value, "magician"));
        let declared_skill_type = magician_metadata
            .and_then(|value| mapping_get(value, "skill_type"))
            .and_then(|value| safe_scalar(Some(value)));
        if let Some(skill_type) = declared_skill_type.as_deref() {
            if skill_type != "tool" {
                findings.push(self.finding(
                    FindingSeverity::Error,
                    "schema_skill_type_conflict",
                    Some(directory_id),
                    &format!("{directory_id}/SKILL.md"),
                    "schema-backed skill explicitly declares a non-executable skill_type",
                ));
            }
        }

        let requires = magician_metadata.and_then(|value| mapping_get(value, "requires"));
        let required_binaries = extract_safe_sequence(
            requires.and_then(|value| mapping_get(value, "bins")),
            IdentifierKind::Program,
            directory_id,
            "invalid_required_binary",
            "SKILL.md",
            findings,
            self,
        );
        let required_env_names = extract_safe_sequence(
            requires.and_then(|value| mapping_get(value, "env")),
            IdentifierKind::Environment,
            directory_id,
            "invalid_required_env_name",
            "SKILL.md",
            findings,
            self,
        );

        let action_names = extract_action_names(directory_id, &schema, findings, self);
        let implementation = extract_implementation(directory_id, &schema, findings, self);
        let auth = extract_auth_surface(directory_id, &schema, findings, self);
        let profile_selectors = extract_profile_selectors(&schema);
        let execution = extract_execution(directory_id, &schema, findings, self);
        let adapter_files = scan_adapter_files(directory_id, directory, findings, self)?;

        Ok(Some(ToolSkillSourceInventory {
            id: directory_id.to_string(),
            version: schema_version.or(manifest_version),
            declared_skill_type,
            sources: SkillSourcePaths {
                skill_markdown: self.source_path(directory_id, "SKILL.md"),
                tool_schema: self.source_path(directory_id, "tool_schema.yaml"),
            },
            required_binaries,
            required_env_names,
            action_names,
            implementation,
            auth,
            profile_selectors,
            execution,
            adapter_files,
        }))
    }

    fn scan_governed_skill(
        &self,
        directory_id: &str,
        directory: &Path,
        frontmatter: &Value,
        package: crate::manifest_parser::SkillRuntimePackage,
        findings: &mut Vec<InventoryFinding>,
    ) -> Result<Option<ToolSkillSourceInventory>> {
        let manifest_name = safe_scalar(mapping_get(frontmatter, "name"));
        compare_declared_name(
            directory_id,
            manifest_name.as_deref(),
            "skill_name_mismatch",
            "SKILL.md",
            findings,
            self,
        );
        let manifest_version = safe_scalar(mapping_get(frontmatter, "version"));
        let magician_metadata =
            mapping_get(frontmatter, "metadata").and_then(|value| mapping_get(value, "magician"));
        let declared_skill_type = magician_metadata
            .and_then(|value| mapping_get(value, "skill_type"))
            .and_then(|value| safe_scalar(Some(value)));
        let required_env_names = extract_safe_sequence(
            magician_metadata
                .and_then(|value| mapping_get(value, "requires"))
                .and_then(|value| mapping_get(value, "env")),
            IdentifierKind::Environment,
            directory_id,
            "invalid_required_env_name",
            "SKILL.md",
            findings,
            self,
        );
        let validated = validate_skill_runtime_contract(&package.contract)
            .context("validating governed runtime contract")?;
        let (
            action_names,
            implementation_kind,
            implementation_program,
            fixed_prefix_arity,
            timeout_secs,
        ) = match &package.contract.runtime {
            RuntimeProtocol::Cli { limits, .. } => {
                let actions = package
                    .actions
                    .as_ref()
                    .ok_or_else(|| anyhow!("governed CLI skill has no typed actions"))?;
                let compiled = compile_typed_action_overrides(directory_id, validated, actions)
                    .context("compiling governed typed actions")?;
                (
                    compiled.actions.keys().cloned().collect::<Vec<_>>(),
                    "primitive".to_owned(),
                    compiled.execution.executable.clone(),
                    compiled.execution.command_prefix.len(),
                    limits.timeout_secs.map(u64::from),
                )
            },
            RuntimeProtocol::Mcp { .. } => {
                let projected = project_mcp_catalog(&package)
                    .map_err(|error| anyhow!(error))
                    .context("projecting governed MCP product actions")?;
                (
                    projected.actions.keys().cloned().collect::<Vec<_>>(),
                    "mcp".to_owned(),
                    OFFICIAL_MCP_SDK_IMPLEMENTATION.to_owned(),
                    0,
                    Some(projected.timeout_secs),
                )
            },
        };
        let mut injected_env_names = package
            .contract
            .auth
            .injections
            .iter()
            .filter_map(|binding| match &binding.target {
                InjectionTarget::Environment { name } => Some(name.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        injected_env_names.sort();
        injected_env_names.dedup();
        let lifecycle = &package.contract.auth.lifecycle;
        let mut lifecycle_hooks = Vec::new();
        if lifecycle.status.is_some() {
            lifecycle_hooks.push("check_command".to_owned());
        }
        if lifecycle.login.is_some() {
            lifecycle_hooks.push("reauth_command".to_owned());
            lifecycle_hooks.push("setup_command".to_owned());
        }
        if lifecycle.refresh.is_some() {
            lifecycle_hooks.push("refresh_command".to_owned());
        }
        if lifecycle.logout.is_some() {
            lifecycle_hooks.push("logout_command".to_owned());
        }
        lifecycle_hooks.sort();
        let projected_profile = package.projected_profile_parameter().map(|parameter| {
            (
                parameter.name.to_owned(),
                parameter
                    .enum_values
                    .map(|values| values.iter().cloned().collect::<Vec<_>>())
                    .unwrap_or_default(),
            )
        });
        let profile_selectors = match &package.contract.auth.profile_selection {
            ProfileSelection::Selectable { default } => {
                let (parameter, aliases) = projected_profile
                    .ok_or_else(|| anyhow!("selectable profile lost its catalog projection"))?;
                vec![ProfileSelector {
                    parameter,
                    aliases,
                    default_alias: default.clone(),
                }]
            },
            ProfileSelection::None
            | ProfileSelection::Fixed { .. }
            | ProfileSelection::Implicit => Vec::new(),
        };
        let mut categories = package.catalog.categories;
        categories.sort();
        categories.dedup();
        let adapter_files = scan_adapter_files(directory_id, directory, findings, self)?;
        Ok(Some(ToolSkillSourceInventory {
            id: directory_id.to_owned(),
            version: manifest_version,
            declared_skill_type,
            sources: SkillSourcePaths {
                skill_markdown: self.source_path(directory_id, "SKILL.md"),
                tool_schema: self.source_path(directory_id, "SKILL.md"),
            },
            required_binaries: package.contract.requires.bins.iter().cloned().collect(),
            required_env_names,
            action_names,
            implementation: ImplementationSurface {
                kind: Some(implementation_kind),
                program: Some(implementation_program),
                fixed_prefix_arity,
                injected_env_names,
                timeout_secs,
            },
            auth: AuthSurface {
                declared: package.contract.auth.kind != AuthKind::None,
                required: Some(matches!(
                    package.contract.auth.requirement,
                    AuthRequirement::Required | AuthRequirement::AtLeastOne
                )),
                lifecycle_hooks,
            },
            profile_selectors,
            execution: ExecutionSurface {
                requires_browser_session: Some(false),
                categories,
            },
            adapter_files,
        }))
    }

    fn source_path(&self, skill_id: &str, leaf: &str) -> String {
        format!("{}/{skill_id}/{leaf}", self.source_label)
    }

    fn finding(
        &self,
        severity: FindingSeverity,
        code: &str,
        skill_id: Option<&str>,
        source_suffix: &str,
        detail: &str,
    ) -> InventoryFinding {
        InventoryFinding {
            severity,
            code: code.to_string(),
            skill_id: skill_id.map(str::to_string),
            source: format!("{}/{}", self.source_label, source_suffix),
            detail: detail.to_string(),
        }
    }
}

fn compare_declared_name(
    directory_id: &str,
    declared: Option<&str>,
    code: &str,
    leaf: &str,
    findings: &mut Vec<InventoryFinding>,
    scanner: &SourceInventoryScanner,
) {
    match declared {
        Some(name) if name == directory_id => {},
        Some(_) => findings.push(scanner.finding(
            FindingSeverity::Error,
            code,
            Some(directory_id),
            &format!("{directory_id}/{leaf}"),
            "declared name does not match its containing skill directory",
        )),
        None => findings.push(scanner.finding(
            FindingSeverity::Error,
            code,
            Some(directory_id),
            &format!("{directory_id}/{leaf}"),
            "declared name is missing or is not a safe identifier",
        )),
    }
}

fn extract_action_names(
    skill_id: &str,
    schema: &Value,
    findings: &mut Vec<InventoryFinding>,
    scanner: &SourceInventoryScanner,
) -> Vec<String> {
    let Some(action_value) = mapping_get(schema, "native_action_schemas") else {
        return Vec::new();
    };
    let Some(actions) = action_value.as_mapping() else {
        findings.push(scanner.finding(
            FindingSeverity::Error,
            "invalid_native_actions_shape",
            Some(skill_id),
            &format!("{skill_id}/tool_schema.yaml"),
            "native_action_schemas must be a mapping",
        ));
        return Vec::new();
    };
    if actions.len() > MAX_ACTIONS_PER_SKILL {
        findings.push(scanner.finding(
            FindingSeverity::Error,
            "too_many_schema_actions",
            Some(skill_id),
            &format!("{skill_id}/tool_schema.yaml"),
            "native action count exceeds the inventory safety limit",
        ));
        return Vec::new();
    }

    let mut names = BTreeSet::new();
    for name in actions.keys() {
        let Some(name) = name.as_str() else {
            findings.push(scanner.finding(
                FindingSeverity::Error,
                "invalid_action_name",
                Some(skill_id),
                &format!("{skill_id}/tool_schema.yaml"),
                "native action name is not a string",
            ));
            continue;
        };
        if is_safe_identifier(name) {
            names.insert(name.to_string());
        } else {
            findings.push(scanner.finding(
                FindingSeverity::Error,
                "invalid_action_name",
                Some(skill_id),
                &format!("{skill_id}/tool_schema.yaml"),
                "native action name is not a bounded portable identifier",
            ));
        }
    }
    names.into_iter().collect()
}

fn extract_implementation(
    skill_id: &str,
    schema: &Value,
    findings: &mut Vec<InventoryFinding>,
    scanner: &SourceInventoryScanner,
) -> ImplementationSurface {
    let Some(implementation) = mapping_get(schema, "implementation") else {
        return ImplementationSurface::default();
    };
    if !implementation.is_mapping() {
        findings.push(scanner.finding(
            FindingSeverity::Error,
            "invalid_implementation_shape",
            Some(skill_id),
            &format!("{skill_id}/tool_schema.yaml"),
            "implementation must be a mapping",
        ));
        return ImplementationSurface::default();
    }
    let kind = safe_scalar(mapping_get(implementation, "type"));
    let program_field = bounded_string(mapping_get(implementation, "program"));
    let command_value = mapping_get(implementation, "command");
    let command = command_value.and_then(Value::as_sequence);
    if command_value.is_some() && command.is_none() {
        findings.push(scanner.finding(
            FindingSeverity::Error,
            "invalid_command_shape",
            Some(skill_id),
            &format!("{skill_id}/tool_schema.yaml"),
            "implementation command must be an argv sequence",
        ));
    } else if command.is_some_and(Vec::is_empty) {
        findings.push(scanner.finding(
            FindingSeverity::Error,
            "empty_command",
            Some(skill_id),
            &format!("{skill_id}/tool_schema.yaml"),
            "implementation command must contain an executable",
        ));
    }
    let command_program = command
        .and_then(|items| items.first())
        .and_then(|item| bounded_string(Some(item)));
    if let (Some(program), Some(command_program)) = (&program_field, &command_program) {
        if program != command_program {
            findings.push(scanner.finding(
                FindingSeverity::Error,
                "program_command_mismatch",
                Some(skill_id),
                &format!("{skill_id}/tool_schema.yaml"),
                "implementation program differs from command argv[0]",
            ));
        }
    }
    let program_candidate = program_field.or(command_program);
    let program = match program_candidate {
        Some(program) if is_safe_program(&program) => Some(program),
        Some(_) => {
            findings.push(scanner.finding(
                FindingSeverity::Error,
                "unsafe_program_identity",
                Some(skill_id),
                &format!("{skill_id}/tool_schema.yaml"),
                "implementation program is not a bounded executable identity",
            ));
            None
        },
        None => None,
    };
    let fixed_args_value = mapping_get(implementation, "fixed_args");
    let fixed_args = fixed_args_value.and_then(Value::as_sequence);
    if fixed_args_value.is_some() && fixed_args.is_none() {
        findings.push(scanner.finding(
            FindingSeverity::Error,
            "invalid_fixed_args_shape",
            Some(skill_id),
            &format!("{skill_id}/tool_schema.yaml"),
            "implementation fixed_args must be an argv sequence",
        ));
    }
    let fixed_prefix_arity = command
        .map_or(0, |values| values.len().saturating_sub(1))
        .saturating_add(fixed_args.map_or(0, Vec::len));
    let injected_env_names = extract_mapping_keys(
        mapping_get(implementation, "env"),
        IdentifierKind::Environment,
        skill_id,
        "invalid_injected_env_name",
        findings,
        scanner,
    );
    let timeout_secs = mapping_get(implementation, "timeout_secs").and_then(safe_u64);

    ImplementationSurface {
        kind,
        program,
        fixed_prefix_arity,
        injected_env_names,
        timeout_secs,
    }
}

fn extract_auth_surface(
    skill_id: &str,
    schema: &Value,
    findings: &mut Vec<InventoryFinding>,
    scanner: &SourceInventoryScanner,
) -> AuthSurface {
    const HOOKS: [&str; 6] = [
        "setup_command",
        "check_command",
        "reauth_command",
        "refresh_command",
        "logout_command",
        "clear_command",
    ];
    let Some(auth) = mapping_get(schema, "auth") else {
        return AuthSurface::default();
    };
    if !auth.is_mapping() {
        findings.push(scanner.finding(
            FindingSeverity::Error,
            "invalid_auth_shape",
            Some(skill_id),
            &format!("{skill_id}/tool_schema.yaml"),
            "auth must be a mapping",
        ));
        return AuthSurface::default();
    }
    if let Some(required) = mapping_get(auth, "required") {
        if required.as_bool().is_none() {
            findings.push(scanner.finding(
                FindingSeverity::Error,
                "invalid_auth_required_shape",
                Some(skill_id),
                &format!("{skill_id}/tool_schema.yaml"),
                "auth.required must be a boolean",
            ));
        }
    }
    for hook in HOOKS {
        if let Some(command) = mapping_get(auth, hook) {
            if command.as_str().is_none() {
                findings.push(scanner.finding(
                    FindingSeverity::Error,
                    "invalid_auth_hook_shape",
                    Some(skill_id),
                    &format!("{skill_id}/tool_schema.yaml"),
                    "auth lifecycle hooks must be command strings",
                ));
            }
        }
    }
    let mut lifecycle_hooks = HOOKS
        .iter()
        .filter(|hook| mapping_get(auth, hook).is_some())
        .map(|hook| (*hook).to_string())
        .collect::<Vec<_>>();
    lifecycle_hooks.sort();
    AuthSurface {
        declared: true,
        required: mapping_get(auth, "required").and_then(Value::as_bool),
        lifecycle_hooks,
    }
}

#[derive(Default)]
struct ProfileSelectorBuilder {
    aliases: BTreeSet<String>,
    default_alias: Option<String>,
}

fn extract_profile_selectors(schema: &Value) -> Vec<ProfileSelector> {
    let mut selectors: BTreeMap<String, ProfileSelectorBuilder> = BTreeMap::new();
    if let Some(parameters) = mapping_get(schema, "parameters").and_then(Value::as_sequence) {
        for parameter in parameters {
            collect_profile_parameter(parameter, &mut selectors);
        }
    }
    if let Some(actions) = mapping_get(schema, "native_action_schemas").and_then(Value::as_mapping)
    {
        for action in actions.values() {
            let Some(overrides) =
                mapping_get(action, "parameter_overrides").and_then(Value::as_mapping)
            else {
                continue;
            };
            for (name, definition) in overrides {
                let Some(name) = name.as_str() else {
                    continue;
                };
                if is_profile_parameter(name) {
                    collect_profile_definition(name, definition, &mut selectors);
                }
            }
        }
    }

    selectors
        .into_iter()
        .map(|(parameter, builder)| ProfileSelector {
            parameter,
            aliases: builder.aliases.into_iter().collect(),
            default_alias: builder.default_alias,
        })
        .collect()
}

fn collect_profile_parameter(
    parameter: &Value,
    selectors: &mut BTreeMap<String, ProfileSelectorBuilder>,
) {
    let Some(name) = mapping_get(parameter, "name").and_then(Value::as_str) else {
        return;
    };
    if is_profile_parameter(name) {
        collect_profile_definition(name, parameter, selectors);
    }
}

fn collect_profile_definition(
    name: &str,
    definition: &Value,
    selectors: &mut BTreeMap<String, ProfileSelectorBuilder>,
) {
    let builder = selectors.entry(name.to_string()).or_default();
    let enum_value =
        mapping_get(definition, "enum").or_else(|| mapping_get(definition, "enum_values"));
    if let Some(aliases) = enum_value.and_then(Value::as_sequence) {
        for alias in aliases {
            if let Some(alias) = safe_profile_alias(alias) {
                builder.aliases.insert(alias);
            }
        }
    }
    if builder.default_alias.is_none() {
        builder.default_alias = mapping_get(definition, "default").and_then(safe_profile_alias);
    }
}

fn extract_execution(
    skill_id: &str,
    schema: &Value,
    findings: &mut Vec<InventoryFinding>,
    scanner: &SourceInventoryScanner,
) -> ExecutionSurface {
    let Some(execution) = mapping_get(schema, "execution") else {
        return ExecutionSurface::default();
    };
    if !execution.is_mapping() {
        findings.push(scanner.finding(
            FindingSeverity::Error,
            "invalid_execution_shape",
            Some(skill_id),
            &format!("{skill_id}/tool_schema.yaml"),
            "execution must be a mapping",
        ));
        return ExecutionSurface::default();
    }
    let mut categories = mapping_get(execution, "categories")
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(safe_profile_alias)
        .collect::<Vec<_>>();
    if let Some(category) = mapping_get(execution, "category").and_then(safe_profile_alias) {
        categories.push(category);
    }
    categories.sort();
    categories.dedup();
    ExecutionSurface {
        requires_browser_session: mapping_get(execution, "requires_browser_session")
            .and_then(Value::as_bool),
        categories,
    }
}

fn scan_adapter_files(
    skill_id: &str,
    directory: &Path,
    findings: &mut Vec<InventoryFinding>,
    scanner: &SourceInventoryScanner,
) -> Result<Vec<String>> {
    let mut adapter_files = BTreeSet::new();
    for entry in WalkDir::new(directory)
        .min_depth(2)
        .max_depth(4)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            !entry.file_name().to_string_lossy().starts_with('.')
                && entry.file_name() != "__pycache__"
                && entry.file_name() != "node_modules"
                && entry.file_name() != ".venv"
        })
    {
        let entry = entry.context("walking skill adapter files")?;
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(directory)
            .context("adapter file escaped skill directory")?;
        if !is_adapter_candidate(relative) {
            continue;
        }
        if adapter_files.len() >= MAX_ADAPTER_FILES_PER_SKILL {
            findings.push(scanner.finding(
                FindingSeverity::Error,
                "too_many_adapter_files",
                Some(skill_id),
                skill_id,
                "adapter/support file count exceeds the inventory safety limit",
            ));
            break;
        }
        let Some(relative) = portable_relative_path(relative) else {
            findings.push(scanner.finding(
                FindingSeverity::Error,
                "unsafe_adapter_path",
                Some(skill_id),
                skill_id,
                "adapter/support path is not portable and relative",
            ));
            continue;
        };
        adapter_files.insert(relative);
    }
    Ok(adapter_files.into_iter().collect())
}

fn is_adapter_candidate(relative: &Path) -> bool {
    let mut components = relative.components();
    let Some(Component::Normal(root)) = components.next() else {
        return false;
    };
    if root != "scripts" && root != "bin" {
        return false;
    }
    let extension = relative.extension().and_then(|value| value.to_str());
    matches!(extension, Some("sh" | "py" | "js" | "mjs" | "cjs" | "ts"))
        || (root == "bin" && extension.is_none())
}

fn extract_safe_sequence(
    value: Option<&Value>,
    kind: IdentifierKind,
    skill_id: &str,
    code: &str,
    leaf: &str,
    findings: &mut Vec<InventoryFinding>,
    scanner: &SourceInventoryScanner,
) -> Vec<String> {
    let Some(value) = value else {
        return Vec::new();
    };
    let Some(values) = value.as_sequence() else {
        findings.push(scanner.finding(
            FindingSeverity::Error,
            code,
            Some(skill_id),
            &format!("{skill_id}/{leaf}"),
            "declaration must be a sequence of identifiers",
        ));
        return Vec::new();
    };
    let mut result = BTreeSet::new();
    for value in values {
        let Some(value) = value.as_str() else {
            findings.push(scanner.finding(
                FindingSeverity::Error,
                code,
                Some(skill_id),
                &format!("{skill_id}/{leaf}"),
                "declaration contains a non-string identifier",
            ));
            continue;
        };
        if kind.is_safe(value) {
            result.insert(value.to_string());
        } else {
            findings.push(scanner.finding(
                FindingSeverity::Error,
                code,
                Some(skill_id),
                &format!("{skill_id}/{leaf}"),
                "declaration contains an unsafe identifier",
            ));
        }
    }
    result.into_iter().collect()
}

fn extract_mapping_keys(
    value: Option<&Value>,
    kind: IdentifierKind,
    skill_id: &str,
    code: &str,
    findings: &mut Vec<InventoryFinding>,
    scanner: &SourceInventoryScanner,
) -> Vec<String> {
    let Some(value) = value else {
        return Vec::new();
    };
    let Some(values) = value.as_mapping() else {
        findings.push(scanner.finding(
            FindingSeverity::Error,
            code,
            Some(skill_id),
            &format!("{skill_id}/tool_schema.yaml"),
            "environment declaration must be a mapping",
        ));
        return Vec::new();
    };
    let mut result = BTreeSet::new();
    for key in values.keys() {
        let Some(key) = key.as_str() else {
            findings.push(scanner.finding(
                FindingSeverity::Error,
                code,
                Some(skill_id),
                &format!("{skill_id}/tool_schema.yaml"),
                "environment mapping contains a non-string name",
            ));
            continue;
        };
        if kind.is_safe(key) {
            result.insert(key.to_string());
        } else {
            findings.push(scanner.finding(
                FindingSeverity::Error,
                code,
                Some(skill_id),
                &format!("{skill_id}/tool_schema.yaml"),
                "environment mapping contains an unsafe name",
            ));
        }
    }
    result.into_iter().collect()
}

#[derive(Clone, Copy)]
enum IdentifierKind {
    Program,
    Environment,
}

impl IdentifierKind {
    fn is_safe(self, value: &str) -> bool {
        match self {
            Self::Program => is_safe_program(value),
            Self::Environment => is_safe_env_name(value),
        }
    }
}

fn summarize(inventory: &SourceInventory) -> SourceInventorySummary {
    SourceInventorySummary {
        active_tool_skills: inventory.skills.len(),
        schema_actions: inventory
            .skills
            .iter()
            .map(|skill| skill.action_names.len())
            .sum(),
        auth_blocks: inventory
            .skills
            .iter()
            .filter(|skill| skill.auth.declared)
            .count(),
        required_binary_declarations: inventory
            .skills
            .iter()
            .map(|skill| skill.required_binaries.len())
            .sum(),
        required_env_name_declarations: inventory
            .skills
            .iter()
            .map(|skill| skill.required_env_names.len())
            .sum(),
        injected_env_name_declarations: inventory
            .skills
            .iter()
            .map(|skill| skill.implementation.injected_env_names.len())
            .sum(),
        adapter_files: inventory
            .skills
            .iter()
            .map(|skill| skill.adapter_files.len())
            .sum(),
        profile_selectors: inventory
            .skills
            .iter()
            .map(|skill| skill.profile_selectors.len())
            .sum(),
        errors: inventory
            .findings
            .iter()
            .filter(|finding| finding.severity == FindingSeverity::Error)
            .count(),
        warnings: inventory
            .findings
            .iter()
            .filter(|finding| finding.severity == FindingSeverity::Warning)
            .count(),
    }
}

fn mapping_get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .as_mapping()?
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
}

fn safe_scalar(value: Option<&Value>) -> Option<String> {
    let value = value?.as_str()?;
    if is_safe_identifier(value) {
        Some(value.to_string())
    } else {
        None
    }
}

fn bounded_string(value: Option<&Value>) -> Option<String> {
    let value = value?.as_str()?;
    (!value.is_empty() && value.len() <= MAX_IDENTIFIER_BYTES).then(|| value.to_string())
}

fn safe_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

fn safe_profile_alias(value: &Value) -> Option<String> {
    let value = value.as_str()?;
    (is_safe_identifier(value) && !value.contains('@')).then(|| value.to_string())
}

fn is_profile_parameter(value: &str) -> bool {
    value == "account"
        || value == "profile"
        || value.ends_with("_account")
        || value.ends_with("_profile")
}

fn is_safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+'))
}

fn is_safe_program(value: &str) -> bool {
    if is_safe_identifier(value) {
        return true;
    }
    const ALLOWED_PREFIXES: [&str; 8] = [
        "{skill_runtime_root}/",
        "{scope_capabilities_root}/",
        "{scope_capability_auth_root}/",
        "/bin/",
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/local/bin/",
        "/opt/homebrew/bin/",
    ];
    let Some(suffix) = ALLOWED_PREFIXES
        .iter()
        .find_map(|prefix| value.strip_prefix(prefix))
    else {
        return false;
    };
    !suffix.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && suffix.split('/').all(is_safe_identifier)
}

fn is_safe_env_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(first) if first.is_ascii_alphabetic() || first == b'_')
        && value.len() <= MAX_IDENTIFIER_BYTES
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn validate_relative_label(value: &str) -> Result<()> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || path.is_absolute()
        || path.components().any(|component| match component {
            Component::Normal(component) => component
                .to_str()
                .is_none_or(|component| !is_safe_identifier(component)),
            _ => true,
        })
    {
        return Err(anyhow!("source label must be a bounded relative path"));
    }
    Ok(())
}

fn portable_relative_path(path: &Path) -> Option<String> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return None;
    }
    let components = path
        .components()
        .map(|component| match component {
            Component::Normal(value) => value.to_str().filter(|value| is_safe_identifier(value)),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    (!components.is_empty()).then(|| components.join("/"))
}

pub(crate) fn read_bounded_utf8(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading metadata for '{}'", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(anyhow!("source path is not a regular file"));
    }
    if metadata.len() > MAX_SOURCE_BYTES {
        return Err(anyhow!("source file exceeds the size limit"));
    }
    fs::read_to_string(path).with_context(|| format!("reading UTF-8 source '{}'", path.display()))
}

pub(crate) fn validate_yaml_shape(source: &str) -> Result<()> {
    let mut flow_depth = 0usize;
    let mut block_scalar_indent = None;
    for line in source.lines() {
        let leading_spaces = line.bytes().take_while(|byte| *byte == b' ').count();
        if leading_spaces > MAX_YAML_INDENT_BYTES {
            return Err(anyhow!("YAML indentation exceeds the safety limit"));
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(block_indent) = block_scalar_indent {
            if leading_spaces > block_indent {
                continue;
            }
            block_scalar_indent = None;
        }
        if has_block_scalar_indicator(line) {
            block_scalar_indent = Some(leading_spaces);
            continue;
        }

        let mut single_quoted = false;
        let mut double_quoted = false;
        let mut escaped = false;
        for character in line.chars() {
            if escaped {
                escaped = false;
                continue;
            }
            if double_quoted && character == '\\' {
                escaped = true;
                continue;
            }
            match character {
                '\'' if !double_quoted => single_quoted = !single_quoted,
                '"' if !single_quoted => double_quoted = !double_quoted,
                '#' if !single_quoted && !double_quoted => break,
                '[' | '{' if !single_quoted && !double_quoted => {
                    flow_depth = flow_depth.saturating_add(1);
                    if flow_depth > MAX_YAML_FLOW_DEPTH {
                        return Err(anyhow!("YAML flow nesting exceeds the safety limit"));
                    }
                },
                ']' | '}' if !single_quoted && !double_quoted => {
                    flow_depth = flow_depth.saturating_sub(1);
                },
                _ => {},
            }
        }
    }
    Ok(())
}

fn has_block_scalar_indicator(line: &str) -> bool {
    let without_comment = line.split('#').next().unwrap_or_default().trim_end();
    let Some((_, indicator)) = without_comment.rsplit_once(':') else {
        return false;
    };
    let indicator = indicator.trim();
    let mut characters = indicator.chars();
    matches!(characters.next(), Some('|' | '>'))
        && characters.all(|character| character.is_ascii_digit() || matches!(character, '+' | '-'))
}

pub(crate) fn extract_frontmatter(source: &str) -> Option<&str> {
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    let mut lines = source.split_inclusive('\n');
    let first = lines.next()?;
    if first.trim_end_matches(['\r', '\n']) != "---" {
        return None;
    }
    let start = first.len();
    let mut offset = start;
    for line in lines {
        if line.trim_end_matches(['\r', '\n']) == "---" {
            return Some(&source[start..offset]);
        }
        offset += line.len();
    }
    None
}

fn safe_error_class(error: &anyhow::Error) -> &'static str {
    for source in error.chain() {
        if let Some(error) = source.downcast_ref::<ActionOverrideError>() {
            return error.message;
        }
        if let Some(error) = source.downcast_ref::<ManifestValidationError>() {
            return error.message;
        }
        if let Some(error) = source.downcast_ref::<ManifestParseError>() {
            return match error.code {
                ManifestParseErrorCode::SourceTooLarge => {
                    "SKILL.md exceeded the bounded source limit"
                },
                ManifestParseErrorCode::MissingFrontmatter
                | ManifestParseErrorCode::UnterminatedFrontmatter
                | ManifestParseErrorCode::FrontmatterTooLarge
                | ManifestParseErrorCode::UnsafeYamlShape
                | ManifestParseErrorCode::YamlReferencesUnsupported
                | ManifestParseErrorCode::InvalidYaml
                | ManifestParseErrorCode::ParsedYamlTooLarge
                | ManifestParseErrorCode::YamlTagsUnsupported => {
                    "SKILL.md frontmatter could not be parsed safely"
                },
                ManifestParseErrorCode::InvalidEnvelope
                | ManifestParseErrorCode::MissingSchemaVersion
                | ManifestParseErrorCode::InvalidSchemaVersion
                | ManifestParseErrorCode::UnsupportedSchemaVersion
                | ManifestParseErrorCode::InvalidRuntimeContract
                | ManifestParseErrorCode::ActionsWithoutRuntimeContract
                | ManifestParseErrorCode::InvalidRuntimeActions
                | ManifestParseErrorCode::InvalidRuntimeCatalog
                | ManifestParseErrorCode::InvalidMagicianExtension => {
                    "SKILL.md governed runtime package is invalid"
                },
            };
        }
    }
    let message = error.to_string();
    if message.contains("frontmatter") {
        "SKILL.md frontmatter could not be parsed"
    } else if message.contains("tool_schema") {
        "tool_schema.yaml could not be parsed"
    } else if message.contains("size limit") {
        "source file exceeded the inventory size limit"
    } else if message.contains("regular file") {
        "source path was not a regular file"
    } else if message.contains("YAML") {
        "skill source exceeded the YAML structural safety limits"
    } else {
        "skill source could not be inventoried"
    }
}

fn markdown_cell(value: &str) -> String {
    value.replace('|', "\\|").replace(['\r', '\n'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static FIXTURE_ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct FixtureRoot {
        path: PathBuf,
    }

    impl FixtureRoot {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "tool-runtime-source-inventory-{label}-{}-{nonce}-{}",
                std::process::id(),
                FIXTURE_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).expect("create fixture root");
            Self { path }
        }

        fn write_skill(&self, directory: &str, skill: &str, schema: &str) {
            let root = self.path.join(directory);
            fs::create_dir_all(&root).expect("create skill fixture");
            fs::write(root.join("SKILL.md"), skill).expect("write fixture SKILL.md");
            fs::write(root.join("tool_schema.yaml"), schema)
                .expect("write fixture tool_schema.yaml");
        }
    }

    impl Drop for FixtureRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn manifest(name: &str, secret_value: &str) -> String {
        format!(
            "---\nname: {name}\nversion: 1.2.3\ndescription: {secret_value}\nmetadata:\n  magician:\n    skill_type: tool\n    requires:\n      bins: [demo-cli]\n      env: [DEMO_TOKEN]\n---\n# Demo\n{secret_value}\n"
        )
    }

    fn schema(name: &str, secret_value: &str) -> String {
        format!(
            "name: {name}\nversion: 1.2.3\nparameters:\n  - name: account\n    param_type: string\n    default: work\n    enum_values: [personal, work]\n  - name: prompt\n    default: {secret_value}\nauth:\n  required: true\n  setup_command: demo-cli login --token {secret_value}\n  check_command: demo-cli status\nnative_action_schemas:\n  zeta: {{description: ignored}}\n  alpha: {{description: ignored}}\nimplementation:\n  type: primitive\n  command: [sh, '{{skill_runtime_root}}/scripts/run.sh', --flag]\n  env:\n    DEMO_PROMPT: '{{prompt}}'\n  timeout_secs: 30\nexecution:\n  requires_browser_session: false\n  categories: [demo, local]\n"
        )
    }

    #[test]
    fn scans_allowlisted_surface_without_copying_secret_values() {
        let fixture = FixtureRoot::new("allowlist");
        let canary = "TOP_SECRET_CANARY_8f0d";
        fixture.write_skill("demo", &manifest("demo", canary), &schema("demo", canary));
        let scripts = fixture.path.join("demo/scripts");
        fs::create_dir_all(&scripts).expect("create scripts fixture");
        fs::write(scripts.join("run.sh"), format!("secret={canary}"))
            .expect("write adapter fixture");

        let inventory = SourceInventoryScanner::new(&fixture.path, "skillshub")
            .expect("valid scanner")
            .scan()
            .expect("scan fixture");
        let rendered = inventory.to_pretty_json().expect("render inventory");

        assert!(!rendered.contains(canary));
        assert_eq!(inventory.summary.active_tool_skills, 1);
        assert_eq!(inventory.summary.schema_actions, 2);
        assert_eq!(inventory.summary.auth_blocks, 1);
        let skill = &inventory.skills[0];
        assert_eq!(skill.action_names, ["alpha", "zeta"]);
        assert_eq!(skill.required_binaries, ["demo-cli"]);
        assert_eq!(skill.required_env_names, ["DEMO_TOKEN"]);
        assert_eq!(skill.implementation.program.as_deref(), Some("sh"));
        assert_eq!(skill.implementation.fixed_prefix_arity, 2);
        assert_eq!(skill.implementation.injected_env_names, ["DEMO_PROMPT"]);
        assert_eq!(
            skill.auth.lifecycle_hooks,
            ["check_command", "setup_command"]
        );
        assert_eq!(skill.adapter_files, ["scripts/run.sh"]);
        assert_eq!(skill.profile_selectors[0].aliases, ["personal", "work"]);
    }

    #[test]
    fn output_is_deterministic_across_creation_order() {
        let left = FixtureRoot::new("deterministic-left");
        left.write_skill(
            "zeta",
            &manifest("zeta", "ignored"),
            &schema("zeta", "ignored"),
        );
        left.write_skill(
            "alpha",
            &manifest("alpha", "ignored"),
            &schema("alpha", "ignored"),
        );
        let right = FixtureRoot::new("deterministic-right");
        right.write_skill(
            "alpha",
            &manifest("alpha", "ignored"),
            &schema("alpha", "ignored"),
        );
        right.write_skill(
            "zeta",
            &manifest("zeta", "ignored"),
            &schema("zeta", "ignored"),
        );

        let scan = |path: &Path| {
            SourceInventoryScanner::new(path, "skillshub")
                .expect("valid scanner")
                .scan()
                .expect("scan fixture")
                .to_pretty_json()
                .expect("render fixture")
        };
        assert_eq!(scan(&left.path), scan(&right.path));
    }

    #[test]
    fn ignores_non_schema_skill_directories() {
        let fixture = FixtureRoot::new("non-tools");
        fs::create_dir_all(fixture.path.join("procedure")).expect("create procedure");
        fs::write(
            fixture.path.join("procedure/SKILL.md"),
            "---\nname: procedure\nmetadata:\n  magician:\n    skill_type: procedure\n---\n",
        )
        .expect("write procedure");

        let inventory = SourceInventoryScanner::new(&fixture.path, "skillshub")
            .expect("valid scanner")
            .scan()
            .expect("scan fixture");
        assert!(inventory.skills.is_empty());
        assert!(inventory.findings.is_empty());
    }

    #[test]
    fn rejects_facade_as_a_skill_type() {
        let fixture = FixtureRoot::new("facade");
        let skill = "---\nname: demo\nversion: 1.2.3\nmetadata:\n  magician:\n    skill_type: facade\n---\n";
        fixture.write_skill("demo", skill, &schema("demo", "ignored"));

        let inventory = SourceInventoryScanner::new(&fixture.path, "skillshub")
            .expect("valid scanner")
            .scan()
            .expect("scan fixture");
        assert!(inventory.has_errors());
        assert!(inventory
            .findings
            .iter()
            .any(|finding| { finding.code == "schema_skill_type_conflict" }));
    }

    #[test]
    fn records_missing_skill_markdown_as_error_without_panicking() {
        let fixture = FixtureRoot::new("missing-manifest");
        fs::create_dir_all(fixture.path.join("broken")).expect("create broken skill");
        fs::write(
            fixture.path.join("broken/tool_schema.yaml"),
            schema("broken", "ignored"),
        )
        .expect("write schema");

        let inventory = SourceInventoryScanner::new(&fixture.path, "skillshub")
            .expect("valid scanner")
            .scan()
            .expect("scan fixture");
        assert!(inventory.skills.is_empty());
        assert!(inventory.has_errors());
        assert_eq!(inventory.findings[0].code, "missing_skill_markdown");
    }

    #[test]
    fn reports_identity_and_type_conflicts_without_exposing_declared_values() {
        let fixture = FixtureRoot::new("identity-conflicts");
        let skill = "---\nname: another-name\nversion: 1.0.0\nmetadata:\n  magician:\n    skill_type: procedure\n---\nsecret body\n";
        fixture.write_skill("demo", skill, &schema("schema-name", "secret-default"));

        let inventory = SourceInventoryScanner::new(&fixture.path, "skillshub")
            .expect("valid scanner")
            .scan()
            .expect("scan fixture");
        let codes = inventory
            .findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<BTreeSet<_>>();
        assert!(codes.contains("skill_name_mismatch"));
        assert!(codes.contains("schema_name_mismatch"));
        assert!(codes.contains("schema_skill_type_conflict"));
        let rendered = inventory.to_pretty_json().expect("render fixture");
        assert!(!rendered.contains("another-name"));
        assert!(!rendered.contains("schema-name"));
        assert!(!rendered.contains("secret-default"));
    }

    #[test]
    fn rejects_unsafe_environment_and_program_identifiers() {
        let fixture = FixtureRoot::new("unsafe-identifiers");
        let skill = "---\nname: demo\nversion: 1.0.0\nmetadata:\n  magician:\n    requires:\n      bins: ['demo;bad']\n      env: ['TOKEN=value']\n---\n";
        let schema = "name: demo\nversion: 1.0.0\nimplementation:\n  command: ['https://example.test/cmd']\n  env:\n    'BAD-NAME': ignored\n";
        fixture.write_skill("demo", skill, schema);

        let inventory = SourceInventoryScanner::new(&fixture.path, "skillshub")
            .expect("valid scanner")
            .scan()
            .expect("scan fixture");
        let skill = &inventory.skills[0];
        assert!(skill.required_binaries.is_empty());
        assert!(skill.required_env_names.is_empty());
        assert!(skill.implementation.program.is_none());
        assert!(skill.implementation.injected_env_names.is_empty());
        assert_eq!(inventory.summary.errors, 4);
    }

    #[test]
    fn counts_command_and_fixed_args_in_the_prefix_and_reads_singular_category() {
        let fixture = FixtureRoot::new("fixed-prefix");
        let schema = "name: demo\nversion: 1.2.3\nnative_action_schemas:\n  run: {}\nimplementation:\n  type: primitive\n  command: [demo-cli]\n  program: demo-cli\n  fixed_args: [service, operation]\nexecution:\n  category: browser\n";
        fixture.write_skill("demo", &manifest("demo", "ignored"), schema);

        let inventory = SourceInventoryScanner::new(&fixture.path, "skillshub")
            .expect("valid scanner")
            .scan()
            .expect("scan fixture");
        let skill = &inventory.skills[0];
        assert_eq!(skill.implementation.fixed_prefix_arity, 2);
        assert_eq!(skill.execution.categories, ["browser"]);
        assert!(!inventory.has_errors());
    }

    #[test]
    fn malformed_declaration_shapes_are_explicit_errors() {
        let fixture = FixtureRoot::new("invalid-shapes");
        let skill = "---\nname: demo\nversion: 1.2.3\nmetadata:\n  magician:\n    requires:\n      bins: demo-cli\n      env: DEMO_TOKEN\n---\n";
        let schema = "name: demo\nversion: 1.2.3\nnative_action_schemas: []\nimplementation:\n  command: demo-cli\n  fixed_args: service\n  env: [DEMO_VALUE]\n";
        fixture.write_skill("demo", skill, schema);

        let inventory = SourceInventoryScanner::new(&fixture.path, "skillshub")
            .expect("valid scanner")
            .scan()
            .expect("scan fixture");
        let codes = inventory
            .findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<BTreeSet<_>>();
        assert!(codes.contains("invalid_required_binary"));
        assert!(codes.contains("invalid_required_env_name"));
        assert!(codes.contains("invalid_native_actions_shape"));
        assert!(codes.contains("invalid_command_shape"));
        assert!(codes.contains("invalid_fixed_args_shape"));
        assert!(codes.contains("invalid_injected_env_name"));
    }

    #[test]
    fn malformed_top_level_sections_are_explicit_errors() {
        let fixture = FixtureRoot::new("invalid-sections");
        let schema =
            "name: demo\nversion: 1.2.3\nimplementation: primitive\nauth: []\nexecution: false\n";
        fixture.write_skill("demo", &manifest("demo", "ignored"), schema);

        let inventory = SourceInventoryScanner::new(&fixture.path, "skillshub")
            .expect("valid scanner")
            .scan()
            .expect("scan fixture");
        let codes = inventory
            .findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<BTreeSet<_>>();
        assert!(codes.contains("invalid_implementation_shape"));
        assert!(codes.contains("invalid_auth_shape"));
        assert!(codes.contains("invalid_execution_shape"));
    }

    #[test]
    fn rejects_disagreement_between_program_and_command_identity() {
        let fixture = FixtureRoot::new("program-mismatch");
        let schema =
            "name: demo\nversion: 1.2.3\nimplementation:\n  command: [first]\n  program: second\n";
        fixture.write_skill("demo", &manifest("demo", "ignored"), schema);

        let inventory = SourceInventoryScanner::new(&fixture.path, "skillshub")
            .expect("valid scanner")
            .scan()
            .expect("scan fixture");
        assert!(inventory.has_errors());
        assert!(inventory
            .findings
            .iter()
            .any(|finding| finding.code == "program_command_mismatch"));
    }

    #[test]
    fn malformed_yaml_becomes_a_safe_classified_finding() {
        let fixture = FixtureRoot::new("malformed");
        fixture.write_skill(
            "broken",
            &manifest("broken", "CANARY_IN_MANIFEST"),
            "name: broken\nprivate: CANARY_IN_SCHEMA\nimplementation: [\n",
        );

        let inventory = SourceInventoryScanner::new(&fixture.path, "skillshub")
            .expect("valid scanner")
            .scan()
            .expect("scan fixture");
        let rendered = inventory.to_pretty_json().expect("render fixture");
        assert!(inventory.has_errors());
        assert_eq!(inventory.findings[0].code, "skill_scan_failed");
        assert!(!rendered.contains("CANARY_IN_MANIFEST"));
        assert!(!rendered.contains("CANARY_IN_SCHEMA"));
        assert!(!rendered.contains("implementation: ["));
    }

    #[test]
    fn rejects_deep_yaml_before_deserialization_but_skips_block_scalar_text() {
        let deep_flow = format!(
            "value: {}0{}\n",
            "[".repeat(MAX_YAML_FLOW_DEPTH + 1),
            "]".repeat(MAX_YAML_FLOW_DEPTH + 1)
        );
        assert!(validate_yaml_shape(&deep_flow).is_err());

        let deep_indent = format!("{}value: true\n", " ".repeat(MAX_YAML_INDENT_BYTES + 1));
        assert!(validate_yaml_shape(&deep_indent).is_err());

        let block_scalar = format!(
            "description: |\n  {}\nname: demo\n",
            "[".repeat(MAX_YAML_FLOW_DEPTH + 100)
        );
        validate_yaml_shape(&block_scalar).expect("block scalar text is not YAML structure");
    }

    #[test]
    fn rejects_non_portable_adapter_paths_without_copying_them() {
        let fixture = FixtureRoot::new("adapter-path");
        fixture.write_skill(
            "demo",
            &manifest("demo", "ignored"),
            &schema("demo", "ignored"),
        );
        let scripts = fixture.path.join("demo/scripts");
        fs::create_dir_all(&scripts).expect("create scripts fixture");
        fs::write(scripts.join("unsafe name.sh"), "ignored").expect("write unsafe adapter");

        let inventory = SourceInventoryScanner::new(&fixture.path, "skillshub")
            .expect("valid scanner")
            .scan()
            .expect("scan fixture");
        assert!(inventory.skills[0].adapter_files.is_empty());
        assert_eq!(inventory.findings[0].code, "unsafe_adapter_path");
        assert!(!inventory
            .to_pretty_json()
            .expect("render inventory")
            .contains("unsafe name.sh"));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_source_files() {
        use std::os::unix::fs::symlink;

        let fixture = FixtureRoot::new("symlink");
        let skill_root = fixture.path.join("demo");
        fs::create_dir_all(&skill_root).expect("create skill root");
        let target = fixture.path.join("manifest-target");
        fs::write(&target, manifest("demo", "SYMLINK_SECRET_CANARY"))
            .expect("write symlink target");
        symlink(&target, skill_root.join("SKILL.md")).expect("create manifest symlink");
        fs::write(
            skill_root.join("tool_schema.yaml"),
            schema("demo", "ignored"),
        )
        .expect("write schema");

        let inventory = SourceInventoryScanner::new(&fixture.path, "skillshub")
            .expect("valid scanner")
            .scan()
            .expect("scan fixture");
        assert!(inventory.has_errors());
        assert!(inventory.skills.is_empty());
        assert!(!inventory
            .to_pretty_json()
            .expect("render inventory")
            .contains("SYMLINK_SECRET_CANARY"));
    }

    #[test]
    fn rejects_non_portable_source_labels() {
        assert!(SourceInventoryScanner::new("/tmp", "../skillshub").is_err());
        assert!(SourceInventoryScanner::new("/tmp", "skill\nshub").is_err());
        assert!(SourceInventoryScanner::new("/tmp", "/absolute").is_err());
    }

    #[test]
    fn markdown_report_is_stable_and_secret_safe() {
        let fixture = FixtureRoot::new("markdown");
        let canary = "MARKDOWN_SECRET_CANARY";
        fixture.write_skill("demo", &manifest("demo", canary), &schema("demo", canary));
        let inventory = SourceInventoryScanner::new(&fixture.path, "skillshub")
            .expect("valid scanner")
            .scan()
            .expect("scan fixture");
        let report = inventory.to_markdown();
        assert!(report.contains("Active tool skills: 1"));
        assert!(report.contains("| `demo` | `1.2.3` | `sh` | 2 |"));
        assert!(!report.contains(canary));
    }
}
