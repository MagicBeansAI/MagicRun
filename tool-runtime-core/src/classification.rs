//! Declarative Phase 0B auth/runtime/adapter classification.
//!
//! The hand-authored manifest contains only enums, safe identifiers, and exact
//! source references. This compiler joins it to the frozen Phase 0A inventory,
//! rejects incomplete or contradictory decisions, and emits a deterministic
//! normalized artifact. It is an audit boundary, not a production runtime.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use crate::inventory::SourceInventory;

pub const CLASSIFICATION_MANIFEST_SCHEMA_VERSION: &str =
    "tool-runtime.source-classification-manifest.v1";
pub const CLASSIFICATION_SCHEMA_VERSION: &str = "tool-runtime.source-classification.v1";

const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_YAML_INDENT_BYTES: usize = 256;
const MAX_YAML_FLOW_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassificationManifest {
    pub schema_version: String,
    pub inventory_schema_version: String,
    pub skill_groups: Vec<SkillClassificationGroup>,
    pub adapter_groups: Vec<AdapterClassificationGroup>,
    pub finding_dispositions: Vec<FindingDisposition>,
    #[serde(default)]
    pub exceptions: Vec<ClassificationException>,
    #[serde(default)]
    pub unknowns: Vec<ClassificationUnknown>,
}

impl ClassificationManifest {
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        validate_manifest_shape(yaml)?;
        serde_yaml::from_str(yaml)
            .map_err(|error| anyhow!("parsing classification manifest: {error}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillClassificationGroup {
    pub skills: Vec<String>,
    pub auth_strategies: Vec<AuthStrategy>,
    pub auth_requirement: AuthRequirement,
    pub auth_provider: Option<String>,
    pub profile: ProfileClassification,
    pub session: SessionClassification,
    pub setup_path: SetupPath,
    pub identity_verification: IdentityVerification,
    pub approval_class: ApprovalClass,
    pub runtime_owner: RuntimeOwner,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthStrategy {
    None,
    Secrets,
    CliProfile,
    #[serde(rename = "oauth_session")]
    OAuthSession,
    BrowserProfile,
    NativePermission,
    DelegatedCredential,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthRequirement {
    None,
    Optional,
    Required,
    Conditional,
    AtLeastOne,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfilePolicy {
    None,
    Selectable,
    Fixed,
    Implicit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileSource {
    None,
    SchemaSelector,
    RuntimeNamed,
    FixedBinding,
    CliActiveIdentity,
    SessionIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileClassification {
    pub policy: ProfilePolicy,
    pub source: ProfileSource,
    pub selector: Option<String>,
    pub fixed_alias: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionOwner {
    None,
    Runtime,
    Cli,
    BrowserController,
    OperatingSystem,
    DelegatedExecutor,
    LegacyProtocolWrapper,
    OfficialSdk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStore {
    None,
    ScopedSecretStore,
    ScopedCliDirectory,
    CliOwnedStore,
    ScopedSkillCache,
    BrowserProfile,
    OsPermissionStore,
    EphemeralGrant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionClassification {
    pub owner: SessionOwner,
    pub store: SessionStore,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupPath {
    None,
    OperatorSecretBinding,
    ExternalCliLogin,
    SchemaAuthHook,
    BrowserLogin,
    OsSettings,
    DelegatedGrant,
    AuthBrokerBrowserOauth,
    ExternalCliQrLogin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityVerification {
    None,
    ProviderRequest,
    CliStatus,
    SchemaCheckHook,
    BrowserSessionEvidence,
    OsPermissionCheck,
    GrantBinding,
    SdkCredentialStatus,
    CliSession,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalClass {
    Ordinary,
    ConditionalExternalSideEffect,
    DelegatedWorkspaceWrite,
    NativeUiControl,
    CommerceCheckout,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeOwner {
    ExternalCli,
    SkillAdapter,
    CompiledProvider,
    HostGateway,
    LegacyMcpWrapper,
    OfficialMcpSdk,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterClassificationGroup {
    pub files: Vec<AdapterFileRef>,
    pub role: AdapterRole,
    pub ownership: Vec<WrapperOwnership>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterFileRef {
    pub skill: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterRole {
    RuntimeEntrypoint,
    ProtocolImplementation,
    PolicyImplementation,
    ArtifactBridge,
    Installer,
    Verifier,
    Test,
    Support,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WrapperOwnership {
    ProtocolAdapter,
    PolicyAdapter,
    ArtifactAdapter,
    RemovablePlumbing,
    NotWrapper,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingDisposition {
    pub skill: String,
    pub code: String,
    pub source: String,
    pub disposition: FindingDispositionKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingDispositionKind {
    AcceptBaseline,
    FixBeforePhase1,
    SeparateInPhase0d,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassificationException {
    pub id: String,
    pub skills: Vec<String>,
    pub kind: ExceptionKind,
    pub resolution: ExceptionResolution,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionKind {
    UndeclaredSecretRequirement,
    DeclaredEnvironmentIsOptional,
    ConditionalAuthPath,
    MultipleAuthLanes,
    LegacyMcpAndPolicyCoupled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionResolution {
    ClassificationOverride,
    RepresentedByMultipleStrategies,
    SeparateInPhase0d,
    DeclaredInRuntimeContract,
    DeclaredConditionalAuthContract,
    RepresentedByGovernedCliAuthContract,
    OfficialSdkTransportWithLocalCommercePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassificationUnknown {
    pub id: String,
    pub skills: Vec<String>,
    pub kind: UnknownKind,
    pub resolve_by: ResolutionPhase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownKind {
    #[serde(rename = "session_scope_not_machine_declared")]
    SessionScope,
    #[serde(rename = "profile_alias_contract_not_machine_declared")]
    ProfileAliasContract,
    #[serde(rename = "identity_probe_not_machine_declared")]
    IdentityProbe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionPhase {
    Phase1Contract,
    Phase2AuthBroker,
    Phase5McpRuntime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceClassification {
    pub schema_version: String,
    pub source_inventory_schema_version: String,
    pub summary: ClassificationSummary,
    pub skills: Vec<SkillClassification>,
    pub adapters: Vec<AdapterClassification>,
    pub finding_dispositions: Vec<FindingDisposition>,
    pub exceptions: Vec<ClassificationException>,
    pub unknowns: Vec<ClassificationUnknown>,
}

impl SourceClassification {
    pub fn to_pretty_json(&self) -> Result<String> {
        let mut rendered = serde_json::to_string_pretty(self)
            .map_err(|error| anyhow!("serializing classification: {error}"))?;
        rendered.push('\n');
        Ok(rendered)
    }

    pub fn to_markdown(&self) -> String {
        let mut out = String::from(
            "# Tool Runtime Phase 0B Classification\n\n\
             This report is generated by strictly joining the declarative Phase 0B manifest \
             to the frozen Phase 0A source inventory. It records ownership and contract \
             decisions only; it contains no credential values, command bodies, or source prose.\n\n",
        );
        out.push_str("## Summary\n\n");
        out.push_str(&format!(
            "- Schema version: `{}`\n\
             - Classified skills: {}\n\
             - Classified adapter/support files: {}\n\
             - Authenticated or conditionally authenticated skills: {}\n\
             - Unauthenticated skills: {}\n\
             - Source findings dispositioned: {}\n\
             - Explicit exceptions: {}\n\
             - Retained unknowns: {}\n\n",
            self.schema_version,
            self.summary.classified_skills,
            self.summary.classified_adapters,
            self.summary.authenticated_skills,
            self.summary.unauthenticated_skills,
            self.summary.dispositioned_findings,
            self.summary.exceptions,
            self.summary.unknowns,
        ));

        out.push_str("## Skills\n\n");
        out.push_str(
            "| Skill | Auth | Requirement | Profile | Session | Setup | Approval | Runtime |\n\
             |---|---|---|---|---|---|---|---|\n",
        );
        for skill in &self.skills {
            out.push_str(&format!(
                "| `{}` | {} | `{}` | `{}` | `{}` / `{}` | `{}` | `{}` | `{}` |\n",
                markdown_cell(&skill.id),
                skill
                    .auth_strategies
                    .iter()
                    .map(|strategy| format!("`{}`", enum_label(strategy)))
                    .collect::<Vec<_>>()
                    .join(", "),
                enum_label(&skill.auth_requirement),
                enum_label(&skill.profile.policy),
                enum_label(&skill.session.owner),
                enum_label(&skill.session.store),
                enum_label(&skill.setup_path),
                enum_label(&skill.approval_class),
                enum_label(&skill.runtime_owner),
            ));
        }

        out.push_str("\n## Adapter ownership\n\n");
        out.push_str("| Skill | File | Role | Ownership |\n|---|---|---|---|\n");
        for adapter in &self.adapters {
            out.push_str(&format!(
                "| `{}` | `{}` | `{}` | {} |\n",
                markdown_cell(&adapter.skill),
                markdown_cell(&adapter.path),
                enum_label(&adapter.role),
                adapter
                    .ownership
                    .iter()
                    .map(|ownership| format!("`{}`", enum_label(ownership)))
                    .collect::<Vec<_>>()
                    .join(", "),
            ));
        }

        out.push_str("\n## Exceptions and retained unknowns\n\n");
        if self.exceptions.is_empty() && self.unknowns.is_empty() {
            out.push_str("None.\n");
        } else {
            for exception in &self.exceptions {
                out.push_str(&format!(
                    "- Exception `{}`: `{}` → `{}` ({})\n",
                    markdown_cell(&exception.id),
                    enum_label(&exception.kind),
                    enum_label(&exception.resolution),
                    exception
                        .skills
                        .iter()
                        .map(|skill| format!("`{}`", markdown_cell(skill)))
                        .collect::<Vec<_>>()
                        .join(", "),
                ));
            }
            for unknown in &self.unknowns {
                out.push_str(&format!(
                    "- Unknown `{}`: `{}`; resolve by `{}` ({})\n",
                    markdown_cell(&unknown.id),
                    enum_label(&unknown.kind),
                    enum_label(&unknown.resolve_by),
                    unknown
                        .skills
                        .iter()
                        .map(|skill| format!("`{}`", markdown_cell(skill)))
                        .collect::<Vec<_>>()
                        .join(", "),
                ));
            }
        }
        out
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassificationSummary {
    pub classified_skills: usize,
    pub classified_adapters: usize,
    pub authenticated_skills: usize,
    pub unauthenticated_skills: usize,
    pub dispositioned_findings: usize,
    pub exceptions: usize,
    pub unknowns: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillClassification {
    pub id: String,
    pub auth_strategies: Vec<AuthStrategy>,
    pub auth_requirement: AuthRequirement,
    pub auth_provider: Option<String>,
    pub profile: ProfileClassification,
    pub session: SessionClassification,
    pub setup_path: SetupPath,
    pub identity_verification: IdentityVerification,
    pub approval_class: ApprovalClass,
    pub runtime_owner: RuntimeOwner,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterClassification {
    pub skill: String,
    pub path: String,
    pub role: AdapterRole,
    pub ownership: Vec<WrapperOwnership>,
}

pub struct ClassificationCompiler;

impl ClassificationCompiler {
    pub fn compile(
        inventory: &SourceInventory,
        manifest: ClassificationManifest,
    ) -> Result<SourceClassification> {
        let mut errors = Vec::new();
        if manifest.schema_version != CLASSIFICATION_MANIFEST_SCHEMA_VERSION {
            errors.push(format!(
                "manifest schema version '{}' does not equal '{}'",
                manifest.schema_version, CLASSIFICATION_MANIFEST_SCHEMA_VERSION
            ));
        }
        if manifest.inventory_schema_version != inventory.schema_version {
            errors.push(format!(
                "manifest inventory schema version '{}' does not equal source '{}'",
                manifest.inventory_schema_version, inventory.schema_version
            ));
        }

        let source_skills = inventory
            .skills
            .iter()
            .map(|skill| (skill.id.as_str(), skill))
            .collect::<BTreeMap<_, _>>();
        let mut classified = BTreeMap::new();
        for group in manifest.skill_groups {
            if group.skills.is_empty() {
                errors.push("skill classification group has no skills".to_string());
                continue;
            }
            for skill_id in &group.skills {
                validate_identifier(skill_id, "skill id", &mut errors);
                let Some(source) = source_skills.get(skill_id.as_str()) else {
                    errors.push(format!(
                        "classification references unknown skill '{skill_id}'"
                    ));
                    continue;
                };
                if classified.contains_key(skill_id) {
                    errors.push(format!("skill '{skill_id}' is classified more than once"));
                    continue;
                }
                validate_skill_group(skill_id, source, &group, &mut errors);
                classified.insert(
                    skill_id.clone(),
                    SkillClassification {
                        id: skill_id.clone(),
                        auth_strategies: group.auth_strategies.clone(),
                        auth_requirement: group.auth_requirement.clone(),
                        auth_provider: group.auth_provider.clone(),
                        profile: group.profile.clone(),
                        session: group.session.clone(),
                        setup_path: group.setup_path.clone(),
                        identity_verification: group.identity_verification.clone(),
                        approval_class: group.approval_class.clone(),
                        runtime_owner: group.runtime_owner.clone(),
                    },
                );
            }
        }
        for skill_id in source_skills.keys() {
            if !classified.contains_key(*skill_id) {
                errors.push(format!("source skill '{skill_id}' has no classification"));
            }
        }

        let expected_adapters = inventory
            .skills
            .iter()
            .flat_map(|skill| {
                skill.adapter_files.iter().map(move |path| AdapterFileRef {
                    skill: skill.id.clone(),
                    path: path.clone(),
                })
            })
            .collect::<BTreeSet<_>>();
        let mut adapters = BTreeMap::new();
        for group in manifest.adapter_groups {
            validate_adapter_group(&group, &mut errors);
            for file in group.files {
                if !expected_adapters.contains(&file) {
                    errors.push(format!(
                        "adapter classification references unknown file '{}:{}'",
                        file.skill, file.path
                    ));
                    continue;
                }
                if adapters.contains_key(&file) {
                    errors.push(format!(
                        "adapter file '{}:{}' is classified more than once",
                        file.skill, file.path
                    ));
                    continue;
                }
                adapters.insert(
                    file.clone(),
                    AdapterClassification {
                        skill: file.skill,
                        path: file.path,
                        role: group.role.clone(),
                        ownership: group.ownership.clone(),
                    },
                );
            }
        }
        for file in &expected_adapters {
            if !adapters.contains_key(file) {
                errors.push(format!(
                    "source adapter '{}:{}' has no ownership classification",
                    file.skill, file.path
                ));
            }
        }

        for skill in classified.values() {
            let Some(source) = inventory.skills.iter().find(|source| source.id == skill.id) else {
                errors.push(format!(
                    "classified skill '{}' is missing from the source inventory",
                    skill.id
                ));
                continue;
            };
            let has_adapters = !source.adapter_files.is_empty();
            if matches!(
                &skill.runtime_owner,
                RuntimeOwner::SkillAdapter | RuntimeOwner::LegacyMcpWrapper
            ) && !has_adapters
            {
                errors.push(format!(
                    "skill '{}' assigns adapter runtime ownership but has no inventoried adapter files",
                    skill.id
                ));
            }
            let is_official_mcp_source = source.implementation.kind.as_deref() == Some("mcp")
                && source.implementation.program.as_deref() == Some("official_mcp_sdk");
            let is_official_mcp_owner =
                matches!(&skill.runtime_owner, RuntimeOwner::OfficialMcpSdk);
            if is_official_mcp_source != is_official_mcp_owner {
                errors.push(format!(
                    "skill '{}' official MCP source and runtime-owner classification disagree",
                    skill.id
                ));
            }
            if is_official_mcp_owner && has_adapters {
                errors.push(format!(
                    "skill '{}' assigns official SDK ownership but still inventories a local adapter",
                    skill.id
                ));
            }
        }

        let expected_findings = inventory
            .findings
            .iter()
            .map(|finding| {
                (
                    finding.skill_id.clone().unwrap_or_default(),
                    finding.code.clone(),
                    finding.source.clone(),
                )
            })
            .collect::<BTreeSet<_>>();
        let mut dispositions = BTreeMap::new();
        for disposition in manifest.finding_dispositions {
            let key = (
                disposition.skill.clone(),
                disposition.code.clone(),
                disposition.source.clone(),
            );
            if !expected_findings.contains(&key) {
                errors.push(format!(
                    "finding disposition references unknown finding '{}:{}:{}'",
                    key.0, key.1, key.2
                ));
            } else if disposition.disposition == FindingDispositionKind::AcceptBaseline
                && inventory.findings.iter().any(|finding| {
                    finding.skill_id.as_deref().unwrap_or_default() == key.0
                        && finding.code == key.1
                        && finding.source == key.2
                        && finding.severity == crate::inventory::FindingSeverity::Error
                })
            {
                errors.push(format!(
                    "error finding '{}:{}:{}' cannot be accepted as baseline",
                    key.0, key.1, key.2
                ));
            } else if dispositions.insert(key.clone(), disposition).is_some() {
                errors.push(format!(
                    "finding '{}:{}:{}' is dispositioned more than once",
                    key.0, key.1, key.2
                ));
            }
        }
        for finding in &expected_findings {
            if !dispositions.contains_key(finding) {
                errors.push(format!(
                    "source finding '{}:{}:{}' has no disposition",
                    finding.0, finding.1, finding.2
                ));
            }
        }

        validate_exception_sets(
            &manifest.exceptions,
            &manifest.unknowns,
            &source_skills,
            &mut errors,
        );

        if !errors.is_empty() {
            errors.sort();
            return Err(anyhow!(
                "classification contract has {} error(s):\n- {}",
                errors.len(),
                errors.join("\n- ")
            ));
        }

        let skills = classified.into_values().collect::<Vec<_>>();
        let authenticated_skills = skills
            .iter()
            .filter(|skill| skill.auth_requirement != AuthRequirement::None)
            .count();
        let unauthenticated_skills = skills.len() - authenticated_skills;
        let adapters = adapters.into_values().collect::<Vec<_>>();
        let finding_dispositions = dispositions.into_values().collect::<Vec<_>>();
        let mut exceptions = manifest.exceptions;
        exceptions.sort_by(|left, right| left.id.cmp(&right.id));
        let mut unknowns = manifest.unknowns;
        unknowns.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(SourceClassification {
            schema_version: CLASSIFICATION_SCHEMA_VERSION.to_string(),
            source_inventory_schema_version: inventory.schema_version.clone(),
            summary: ClassificationSummary {
                classified_skills: skills.len(),
                classified_adapters: adapters.len(),
                authenticated_skills,
                unauthenticated_skills,
                dispositioned_findings: finding_dispositions.len(),
                exceptions: exceptions.len(),
                unknowns: unknowns.len(),
            },
            skills,
            adapters,
            finding_dispositions,
            exceptions,
            unknowns,
        })
    }
}

fn validate_skill_group(
    skill_id: &str,
    source: &crate::inventory::ToolSkillSourceInventory,
    group: &SkillClassificationGroup,
    errors: &mut Vec<String>,
) {
    if group.auth_strategies.is_empty() {
        errors.push(format!("skill '{skill_id}' has no auth strategy"));
    }
    let strategy_count = group.auth_strategies.iter().collect::<BTreeSet<_>>().len();
    if strategy_count != group.auth_strategies.len() {
        errors.push(format!("skill '{skill_id}' repeats an auth strategy"));
    }
    let has_none = group.auth_strategies.contains(&AuthStrategy::None);
    if has_none && group.auth_strategies.len() != 1 {
        errors.push(format!(
            "skill '{skill_id}' combines 'none' with another auth strategy"
        ));
    }
    if (group.auth_requirement == AuthRequirement::None) != has_none {
        errors.push(format!(
            "skill '{skill_id}' must pair auth requirement 'none' exactly with strategy 'none'"
        ));
    }
    if !source.required_env_names.is_empty()
        && !group.auth_strategies.contains(&AuthStrategy::Secrets)
    {
        errors.push(format!(
            "skill '{skill_id}' declares environment requirements but is not classified with secrets"
        ));
    }
    if source.auth.declared && has_none {
        errors.push(format!(
            "skill '{skill_id}' declares schema auth but is classified unauthenticated"
        ));
    }
    if let Some(provider) = &group.auth_provider {
        validate_identifier(provider, "auth provider", errors);
    } else if !has_none {
        errors.push(format!(
            "authenticated skill '{skill_id}' has no auth provider identifier"
        ));
    }
    if has_none && group.auth_provider.is_some() {
        errors.push(format!(
            "unauthenticated skill '{skill_id}' declares an auth provider"
        ));
    }
    validate_profile(skill_id, source, &group.profile, errors);
    let no_session =
        group.session.owner == SessionOwner::None && group.session.store == SessionStore::None;
    if has_none != no_session {
        errors.push(format!(
            "skill '{skill_id}' must pair unauthenticated state with a fully empty session contract"
        ));
    }
    if (group.setup_path == SetupPath::None) != has_none {
        errors.push(format!(
            "skill '{skill_id}' must pair setup path 'none' exactly with unauthenticated state"
        ));
    }
    if (group.identity_verification == IdentityVerification::None) != has_none {
        errors.push(format!(
            "skill '{skill_id}' must pair identity verification 'none' exactly with unauthenticated state"
        ));
    }
    let valid_session_pair = matches!(
        (&group.session.owner, &group.session.store),
        (SessionOwner::None, SessionStore::None)
            | (SessionOwner::Runtime, SessionStore::ScopedSecretStore)
            | (SessionOwner::Cli, SessionStore::ScopedCliDirectory)
            | (SessionOwner::Cli, SessionStore::CliOwnedStore)
            | (
                SessionOwner::BrowserController,
                SessionStore::BrowserProfile
            )
            | (
                SessionOwner::OperatingSystem,
                SessionStore::OsPermissionStore
            )
            | (
                SessionOwner::DelegatedExecutor,
                SessionStore::EphemeralGrant
            )
            | (
                SessionOwner::LegacyProtocolWrapper,
                SessionStore::ScopedSkillCache
            )
            | (SessionOwner::OfficialSdk, SessionStore::ScopedSecretStore)
    );
    if !valid_session_pair {
        errors.push(format!(
            "skill '{skill_id}' has an invalid session owner/store pair"
        ));
    }
    let has_strategy = |strategy| group.auth_strategies.contains(&strategy);
    if has_strategy(AuthStrategy::CliProfile) && group.session.owner != SessionOwner::Cli {
        errors.push(format!(
            "skill '{skill_id}' CLI profile is not owned by the CLI"
        ));
    }
    if has_strategy(AuthStrategy::Secrets)
        && group.auth_strategies.len() == 1
        && group.session.owner != SessionOwner::Runtime
    {
        errors.push(format!(
            "skill '{skill_id}' secret-only auth is not owned by the runtime"
        ));
    }
    if has_strategy(AuthStrategy::OAuthSession)
        && !matches!(
            group.session.owner,
            SessionOwner::Cli | SessionOwner::LegacyProtocolWrapper | SessionOwner::OfficialSdk
        )
    {
        errors.push(format!(
            "skill '{skill_id}' OAuth session has an invalid owner"
        ));
    }
    if has_strategy(AuthStrategy::BrowserProfile)
        && group.session.owner != SessionOwner::BrowserController
    {
        errors.push(format!(
            "skill '{skill_id}' browser profile has an invalid owner"
        ));
    }
    if has_strategy(AuthStrategy::NativePermission)
        && group.session.owner != SessionOwner::OperatingSystem
    {
        errors.push(format!(
            "skill '{skill_id}' native permission has an invalid owner"
        ));
    }
    if has_strategy(AuthStrategy::DelegatedCredential)
        && !matches!(
            group.session.owner,
            SessionOwner::BrowserController | SessionOwner::DelegatedExecutor
        )
    {
        errors.push(format!(
            "skill '{skill_id}' delegated credential has an invalid owner"
        ));
    }
}

fn validate_profile(
    skill_id: &str,
    source: &crate::inventory::ToolSkillSourceInventory,
    profile: &ProfileClassification,
    errors: &mut Vec<String>,
) {
    if let Some(selector) = &profile.selector {
        validate_identifier(selector, "profile selector", errors);
    }
    if let Some(alias) = &profile.fixed_alias {
        validate_identifier(alias, "fixed profile alias", errors);
    }
    match profile.policy {
        ProfilePolicy::None => {
            if profile.source != ProfileSource::None
                || profile.selector.is_some()
                || profile.fixed_alias.is_some()
            {
                errors.push(format!("skill '{skill_id}' has a non-empty 'none' profile"));
            }
        },
        ProfilePolicy::Selectable => {
            if !matches!(
                profile.source,
                ProfileSource::SchemaSelector | ProfileSource::RuntimeNamed
            ) || profile.fixed_alias.is_some()
            {
                errors.push(format!(
                    "skill '{skill_id}' has an invalid selectable-profile source or fixed alias"
                ));
            }
            if profile.source == ProfileSource::SchemaSelector {
                let selector_matches = profile.selector.as_ref().is_some_and(|selector| {
                    source
                        .profile_selectors
                        .iter()
                        .any(|candidate| candidate.parameter == *selector)
                });
                if !selector_matches {
                    errors.push(format!(
                        "skill '{skill_id}' profile selector is not present in the source inventory"
                    ));
                }
            } else if profile.selector.is_some() {
                errors.push(format!(
                    "skill '{skill_id}' runtime-named profile cannot declare a schema selector"
                ));
            }
        },
        ProfilePolicy::Fixed => {
            if profile.source != ProfileSource::FixedBinding
                || profile.selector.is_some()
                || profile.fixed_alias.is_none()
            {
                errors.push(format!("skill '{skill_id}' has an invalid fixed profile"));
            }
        },
        ProfilePolicy::Implicit => {
            if !matches!(
                profile.source,
                ProfileSource::CliActiveIdentity | ProfileSource::SessionIdentity
            ) || profile.selector.is_some()
                || profile.fixed_alias.is_some()
            {
                errors.push(format!(
                    "skill '{skill_id}' has an invalid implicit profile"
                ));
            }
        },
    }
    if !(source.profile_selectors.is_empty()
        || profile.policy == ProfilePolicy::Selectable
            && profile.source == ProfileSource::SchemaSelector)
    {
        errors.push(format!(
            "skill '{skill_id}' inventories a profile selector but does not classify it as schema-selectable"
        ));
    }
}

fn validate_adapter_group(group: &AdapterClassificationGroup, errors: &mut Vec<String>) {
    if group.files.is_empty() {
        errors.push("adapter classification group has no files".to_string());
    }
    if group.ownership.is_empty() {
        errors.push("adapter classification group has no ownership decision".to_string());
    }
    let ownership_count = group.ownership.iter().collect::<BTreeSet<_>>().len();
    if ownership_count != group.ownership.len() {
        errors.push("adapter classification group repeats an ownership decision".to_string());
    }
    if group.ownership.contains(&WrapperOwnership::NotWrapper) && group.ownership.len() != 1 {
        errors.push("adapter ownership 'not_wrapper' cannot be combined".to_string());
    }
    let non_wrapper_role = matches!(
        group.role,
        AdapterRole::Installer | AdapterRole::Verifier | AdapterRole::Test | AdapterRole::Support
    );
    if non_wrapper_role != group.ownership.contains(&WrapperOwnership::NotWrapper) {
        errors.push(format!(
            "adapter role '{:?}' has inconsistent not-wrapper ownership",
            group.role
        ));
    }
    let required_ownership = match group.role {
        AdapterRole::RuntimeEntrypoint => Some(WrapperOwnership::RemovablePlumbing),
        AdapterRole::ProtocolImplementation => Some(WrapperOwnership::ProtocolAdapter),
        AdapterRole::PolicyImplementation => Some(WrapperOwnership::PolicyAdapter),
        AdapterRole::ArtifactBridge => Some(WrapperOwnership::ArtifactAdapter),
        AdapterRole::Installer
        | AdapterRole::Verifier
        | AdapterRole::Test
        | AdapterRole::Support => None,
    };
    if required_ownership.is_some_and(|required| !group.ownership.contains(&required)) {
        errors.push(format!(
            "adapter role '{}' is missing its required ownership decision",
            enum_label(&group.role)
        ));
    }
}

fn validate_exception_sets(
    exceptions: &[ClassificationException],
    unknowns: &[ClassificationUnknown],
    source_skills: &BTreeMap<&str, &crate::inventory::ToolSkillSourceInventory>,
    errors: &mut Vec<String>,
) {
    let mut ids = BTreeSet::new();
    for (kind, id, skills) in exceptions
        .iter()
        .map(|item| ("exception", &item.id, &item.skills))
        .chain(
            unknowns
                .iter()
                .map(|item| ("unknown", &item.id, &item.skills)),
        )
    {
        validate_identifier(id, kind, errors);
        if !ids.insert(id) {
            errors.push(format!("classification id '{id}' is repeated"));
        }
        if skills.is_empty() {
            errors.push(format!("classification {kind} '{id}' has no skills"));
        }
        let mut seen = BTreeSet::new();
        for skill in skills {
            if !source_skills.contains_key(skill.as_str()) {
                errors.push(format!(
                    "classification {kind} '{id}' references unknown skill '{skill}'"
                ));
            }
            if !seen.insert(skill) {
                errors.push(format!(
                    "classification {kind} '{id}' repeats skill '{skill}'"
                ));
            }
        }
    }
}

fn validate_identifier(value: &str, label: &str, errors: &mut Vec<String>) {
    let valid = !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !valid {
        errors.push(format!("{label} '{value}' is not a safe identifier"));
    }
}

fn validate_manifest_shape(yaml: &str) -> Result<()> {
    if yaml.len() > MAX_MANIFEST_BYTES {
        return Err(anyhow!(
            "classification manifest is {} bytes; limit is {}",
            yaml.len(),
            MAX_MANIFEST_BYTES
        ));
    }
    let mut flow_depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (line_number, line) in yaml.lines().enumerate() {
        let indent = line
            .as_bytes()
            .iter()
            .take_while(|byte| **byte == b' ')
            .count();
        if indent > MAX_YAML_INDENT_BYTES {
            return Err(anyhow!(
                "classification manifest line {} exceeds indentation limit {}",
                line_number + 1,
                MAX_YAML_INDENT_BYTES
            ));
        }
        for character in line.chars() {
            if escaped {
                escaped = false;
                continue;
            }
            if character == '\\' && quote == Some('"') {
                escaped = true;
                continue;
            }
            if matches!(character, '\'' | '"') {
                if quote == Some(character) {
                    quote = None;
                } else if quote.is_none() {
                    quote = Some(character);
                }
                continue;
            }
            if quote.is_some() {
                continue;
            }
            match character {
                '&' | '*' | '!' => {
                    return Err(anyhow!(
                        "classification manifest uses unsupported YAML anchor, alias, or tag syntax"
                    ));
                },
                '[' | '{' => {
                    flow_depth += 1;
                    if flow_depth > MAX_YAML_FLOW_DEPTH {
                        return Err(anyhow!(
                            "classification manifest exceeds flow-depth limit {}",
                            MAX_YAML_FLOW_DEPTH
                        ));
                    }
                },
                ']' | '}' => flow_depth = flow_depth.saturating_sub(1),
                _ => {},
            }
        }
    }
    Ok(())
}

fn markdown_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

fn enum_label<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::{
        AuthSurface, ExecutionSurface, ImplementationSurface, InventoryFinding, SkillSourcePaths,
        SourceInventorySummary, ToolSkillSourceInventory,
    };

    fn source_inventory() -> SourceInventory {
        SourceInventory {
            schema_version: "tool-runtime.source-inventory.v1".to_string(),
            source_root: "skillshub".to_string(),
            activation_rule: "fixture".to_string(),
            summary: SourceInventorySummary::default(),
            skills: vec![ToolSkillSourceInventory {
                id: "mail".to_string(),
                version: Some("1.0.0".to_string()),
                declared_skill_type: Some("tool".to_string()),
                sources: SkillSourcePaths {
                    skill_markdown: "skillshub/mail/SKILL.md".to_string(),
                    tool_schema: "skillshub/mail/tool_schema.yaml".to_string(),
                },
                required_binaries: vec!["mail".to_string()],
                required_env_names: vec!["MAIL_KEY".to_string()],
                action_names: vec!["send".to_string()],
                implementation: ImplementationSurface::default(),
                auth: AuthSurface::default(),
                profile_selectors: vec![crate::inventory::ProfileSelector {
                    parameter: "account".to_string(),
                    aliases: vec!["work".to_string()],
                    default_alias: Some("work".to_string()),
                }],
                execution: ExecutionSurface::default(),
                adapter_files: vec!["scripts/run.sh".to_string()],
            }],
            findings: vec![InventoryFinding {
                severity: crate::inventory::FindingSeverity::Warning,
                code: "version_mismatch".to_string(),
                skill_id: Some("mail".to_string()),
                source: "skillshub/mail/tool_schema.yaml".to_string(),
                detail: "not copied".to_string(),
            }],
        }
    }

    fn valid_manifest_yaml() -> &'static str {
        r#"
schema_version: tool-runtime.source-classification-manifest.v1
inventory_schema_version: tool-runtime.source-inventory.v1
skill_groups:
  - skills: [mail]
    auth_strategies: [secrets]
    auth_requirement: required
    auth_provider: mail
    profile:
      policy: selectable
      source: schema_selector
      selector: account
      fixed_alias: null
    session: { owner: runtime, store: scoped_secret_store }
    setup_path: operator_secret_binding
    identity_verification: provider_request
    approval_class: conditional_external_side_effect
    runtime_owner: skill_adapter
adapter_groups:
  - files: [{ skill: mail, path: scripts/run.sh }]
    role: runtime_entrypoint
    ownership: [removable_plumbing]
finding_dispositions:
  - skill: mail
    code: version_mismatch
    source: skillshub/mail/tool_schema.yaml
    disposition: fix_before_phase1
exceptions: []
unknowns: []
"#
    }

    #[test]
    fn compiles_complete_exact_classification() {
        let manifest = ClassificationManifest::from_yaml(valid_manifest_yaml()).unwrap();
        let result = ClassificationCompiler::compile(&source_inventory(), manifest).unwrap();
        assert_eq!(result.summary.classified_skills, 1);
        assert_eq!(result.summary.classified_adapters, 1);
        assert_eq!(result.summary.dispositioned_findings, 1);
        assert_eq!(result.skills[0].id, "mail");
    }

    #[test]
    fn phase7_exception_resolutions_are_stable_manifest_vocabulary() {
        let resolutions: Vec<ExceptionResolution> = serde_yaml::from_str(
            r#"
- declared_in_runtime_contract
- declared_conditional_auth_contract
- represented_by_governed_cli_auth_contract
- official_sdk_transport_with_local_commerce_policy
"#,
        )
        .expect("parse Phase 7 exception resolutions");

        assert_eq!(
            resolutions,
            vec![
                ExceptionResolution::DeclaredInRuntimeContract,
                ExceptionResolution::DeclaredConditionalAuthContract,
                ExceptionResolution::RepresentedByGovernedCliAuthContract,
                ExceptionResolution::OfficialSdkTransportWithLocalCommercePolicy,
            ]
        );
    }

    #[test]
    fn rejects_missing_duplicate_and_extra_skill_or_adapter_decisions() {
        let source = source_inventory();
        for bad in [
            valid_manifest_yaml().replace("skills: [mail]", "skills: []"),
            valid_manifest_yaml().replace("  - skills: [mail]", "  - skills: [mail, mail]\n"),
            valid_manifest_yaml().replace("path: scripts/run.sh", "path: scripts/other.sh"),
        ] {
            let manifest = ClassificationManifest::from_yaml(&bad).unwrap();
            assert!(ClassificationCompiler::compile(&source, manifest).is_err());
        }
    }

    #[test]
    fn rejects_auth_and_profile_contradictions() {
        let source = source_inventory();
        for bad in [
            valid_manifest_yaml().replace("auth_strategies: [secrets]", "auth_strategies: [none]"),
            valid_manifest_yaml().replace("source: schema_selector", "source: runtime_named"),
            valid_manifest_yaml().replace("selector: account", "selector: identity"),
            valid_manifest_yaml().replace("owner: runtime", "owner: none"),
            valid_manifest_yaml().replace("store: scoped_secret_store", "store: cli_owned_store"),
        ] {
            let manifest = ClassificationManifest::from_yaml(&bad).unwrap();
            assert!(ClassificationCompiler::compile(&source, manifest).is_err());
        }
    }

    #[test]
    fn rejects_adapter_role_without_matching_ownership() {
        let bad = valid_manifest_yaml().replace(
            "ownership: [removable_plumbing]",
            "ownership: [protocol_adapter]",
        );
        let manifest = ClassificationManifest::from_yaml(&bad).unwrap();
        assert!(ClassificationCompiler::compile(&source_inventory(), manifest).is_err());
    }

    #[test]
    fn rejects_missing_or_invented_finding_dispositions() {
        let source = source_inventory();
        for bad in [
            valid_manifest_yaml().replace(
                "  - skill: mail\n    code: version_mismatch\n    source: skillshub/mail/tool_schema.yaml\n    disposition: fix_before_phase1",
                "",
            ),
            valid_manifest_yaml().replace("code: version_mismatch", "code: invented"),
        ] {
            let manifest = ClassificationManifest::from_yaml(&bad).unwrap();
            assert!(ClassificationCompiler::compile(&source, manifest).is_err());
        }
    }

    #[test]
    fn rejects_unknown_fields_and_deep_yaml_before_deserialization() {
        assert!(
            ClassificationManifest::from_yaml(&valid_manifest_yaml().replace(
                "inventory_schema_version:",
                "unexpected: value\ninventory_schema_version:",
            ))
            .is_err()
        );
        let deep = format!("value: {}", "[".repeat(MAX_YAML_FLOW_DEPTH + 1));
        assert!(ClassificationManifest::from_yaml(&deep).is_err());
        assert!(ClassificationManifest::from_yaml("value: &anchor [one]").is_err());
    }

    #[test]
    fn output_is_deterministic_and_does_not_copy_source_detail() {
        let manifest = ClassificationManifest::from_yaml(valid_manifest_yaml()).unwrap();
        let first = ClassificationCompiler::compile(&source_inventory(), manifest)
            .unwrap()
            .to_pretty_json()
            .unwrap();
        let manifest = ClassificationManifest::from_yaml(valid_manifest_yaml()).unwrap();
        let second = ClassificationCompiler::compile(&source_inventory(), manifest)
            .unwrap()
            .to_pretty_json()
            .unwrap();
        assert_eq!(first, second);
        assert!(!first.contains("not copied"));
        assert!(!first.contains("credential"));
    }
}
