//! Versioned, provider-neutral skill runtime contract vocabulary.
//!
//! These types describe the declarative contract nested beneath
//! `metadata.magician.runtime_contract` in a `SKILL.md` frontmatter document.
//! They deliberately contain no executor, credential resolver, network client,
//! filesystem lookup, or ambient process-environment access. Phase 1B owns the
//! bounded frontmatter parser and Phase 1C owns semantic validation.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// First supported `metadata.magician.runtime_contract.schema_version` value.
pub const SKILL_RUNTIME_CONTRACT_V1: &str = "tool-runtime.skill-runtime.v1";

/// An authored schema version is retained as data so the Phase 1B compiler can
/// return a precise unsupported/forward-version diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SkillRuntimeContractVersion(pub String);

impl SkillRuntimeContractVersion {
    pub fn v1() -> Self {
        Self(SKILL_RUNTIME_CONTRACT_V1.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Complete normalized authoring contract. Collection fields whose order has
/// no runtime meaning use `BTreeSet`; argv-like fields retain `Vec` ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillRuntimeContract {
    pub schema_version: SkillRuntimeContractVersion,
    #[serde(default)]
    pub requires: RuntimeRequirements,
    pub runtime: RuntimeProtocol,
    #[serde(default)]
    pub auth: AuthContract,
    #[serde(default)]
    pub policy_floor: PolicyFloor,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeRequirements {
    /// Executable names only. Paths and executable selection are compiler/runtime
    /// concerns and are never model-controlled.
    pub bins: BTreeSet<String>,
    /// Exact CLI process entrypoint when a package requires more than one
    /// reviewed executable. Omitted single-binary packages retain their sole
    /// executable as the entrypoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<String>,
    /// Fixed public child environment authored by the package. Credential
    /// material has a separate typed source in `auth.injections`; validation
    /// rejects collisions and process-loader variables without guessing from
    /// variable names. Values never come from model input or the ambient parent
    /// environment.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub environment: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeProtocol {
    Cli {
        /// Exact tokens inserted after the fixed executable and before model argv.
        #[serde(default)]
        command_prefix: Vec<String>,
        #[serde(default)]
        interaction: CliInteraction,
        #[serde(default)]
        stdin: StdinContract,
        #[serde(default)]
        working_directory: WorkingDirectoryContract,
        #[serde(default)]
        limits: RuntimeLimits,
    },
    Mcp {
        transport: McpTransport,
        #[serde(default)]
        discovery: McpDiscoveryPolicy,
        #[serde(default)]
        limits: RuntimeLimits,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CliInteraction {
    #[default]
    Batch,
    Pty,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum McpTransport {
    Stdio {
        executable: String,
        #[serde(default)]
        args: Vec<String>,
    },
    StreamableHttp {
        endpoint: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct McpDiscoveryPolicy {
    /// Optional stable local prefix for discovered server tools.
    pub namespace: Option<String>,
    /// Empty means no additional allowlist restriction.
    pub allow_tools: BTreeSet<String>,
    /// Local deny rules always win over allow rules and server metadata.
    pub deny_tools: BTreeSet<String>,
    /// Exact remote-tool policies authored locally. Remote metadata cannot create,
    /// replace, or weaken these entries.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub tool_policies: BTreeMap<String, McpToolPolicy>,
    /// Additional exact Streamable HTTP endpoints owned by the same skill.
    /// Model input selects only one of these aliases; it can never supply a URL.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub endpoint_aliases: BTreeMap<String, String>,
    /// Alias used when a multi-endpoint skill does not explicitly select one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_endpoint_alias: Option<String>,
    /// Exact OAuth connection binding for a remote MCP server. The official SDK
    /// still owns discovery, registration, PKCE, callbacks, refresh, and tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth: Option<McpOAuthConnectionPolicy>,
    /// Optional provider-neutral commerce controls applied above the official
    /// MCP SDK. This is local policy, never server or model-authored metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commerce: Option<McpCommercePolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpOAuthConnectionPolicy {
    /// Expected authorization-server issuer pinned by the reviewed skill.
    pub authorization_issuer: String,
    /// Exact OAuth scopes requested by the public native client.
    #[serde(default)]
    pub scopes: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpCommercePolicy {
    /// Resource Authority commodity, normally `INR` for local commerce skills.
    pub commodity: String,
    /// Exact resource scope satisfied by the governed commerce boundary.
    pub resource_scope: String,
    /// Exact Resource Authority class satisfied by reserve/commit/rollback.
    pub required_resource_authority: String,
    /// Model-facing call parameter containing the reviewed decimal amount.
    pub amount_parameter: String,
    /// Exact remote tools that always finalize checkout/payment/reservation.
    #[serde(default)]
    pub final_tools: BTreeSet<String>,
    /// Remote tools that finalize only when a bounded JSON boolean predicate
    /// matches their tool arguments (for example `/confirmOrder == true`).
    #[serde(default)]
    pub conditional_final_tools: BTreeMap<String, McpJsonBooleanCondition>,
    /// Conservative lower-case name fragments that classify unknown/future
    /// remote tools as checkout-like rather than trusting a caller label.
    #[serde(default)]
    pub checkout_name_terms: BTreeSet<String>,
    /// Lower-case fragments used to locate a live cart-read tool.
    #[serde(default)]
    pub cart_name_terms: BTreeSet<String>,
    /// Lower-case verb fragments preferred on candidate cart-read tools.
    #[serde(default)]
    pub cart_read_verb_terms: BTreeSet<String>,
    /// Normalized lower-case response field names in priority order.
    #[serde(default)]
    pub total_field_priority: Vec<String>,
    #[serde(default)]
    pub cart_amount_unit: McpMoneyUnit,
    /// Absolute amount tolerance in minor units (paise for INR).
    #[serde(default)]
    pub absolute_tolerance_minor: u64,
    /// Percentage tolerance in basis points (500 = 5%).
    #[serde(default)]
    pub percentage_tolerance_bps: u16,
    /// Optional per-call ceiling in minor units.
    #[serde(default)]
    pub max_order_minor: Option<u64>,
    /// Explicit escape hatches. Both default false and remain local policy.
    #[serde(default)]
    pub allow_cartless_checkout: bool,
    /// Multi-endpoint aliases whose reviewed workflow genuinely has no cart.
    /// This prevents a cartless escape hatch from weakening sibling endpoints.
    #[serde(default)]
    pub cartless_endpoint_aliases: BTreeSet<String>,
    #[serde(default)]
    pub allow_unverified_cart: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpJsonBooleanCondition {
    pub pointer: String,
    pub equals: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpMoneyUnit {
    #[default]
    Major,
    Minor,
}

/// Trusted local risk posture for one discovered MCP tool.
///
/// `Unclassified` is deliberately conservative at catalog projection time; it is not
/// equivalent to `ReadOnly`, even when a remote annotation claims read-only behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpToolRiskClass {
    #[default]
    Unclassified,
    ReadOnly,
    ExternalSideEffect,
    WorkspaceWrite,
    NativeUiControl,
    Commerce,
}

/// Additive local policy for one exact remote MCP tool name.
///
/// There is no removal/replacement form for the skill-wide policy floor. The trusted
/// description is the only prose eligible for the eventual model catalog; untrusted
/// server title/description fields remain outside this contract.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct McpToolPolicy {
    pub risk: McpToolRiskClass,
    pub trusted_description: Option<String>,
    pub additional_approvals: BTreeSet<ApprovalClass>,
    pub additional_required_grants: BTreeSet<String>,
    pub additional_resource_scopes: BTreeSet<String>,
    pub additional_required_resource_authorities: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeLimits {
    /// Skill-requested ceilings. The runtime may impose lower ceilings, never higher.
    pub timeout_secs: Option<u32>,
    pub stdin_bytes: Option<u64>,
    pub stdout_bytes: Option<u64>,
    pub stderr_bytes: Option<u64>,
    /// Maximum virtual address space for a spawned CLI process. Supported
    /// Unix runners enforce this before exec; it also participates in the
    /// global governed memory reservation budget.
    pub memory_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StdinContract {
    pub mode: StdinMode,
    pub sensitivity: DataSensitivity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StdinMode {
    #[default]
    Denied,
    Optional,
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataSensitivity {
    #[default]
    Public,
    Private,
    Secret,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WorkingDirectoryContract {
    pub mode: WorkingDirectoryMode,
}

/// Canonical MiniMax auth directory target name used by MMX CLI tooling.
pub const MMX_CONFIG_DIR: &str = "MMX_CONFIG_DIR";

/// Canonical MiniMax provider name in reviewed manifests.
pub const MINIMAX_PROVIDER: &str = "minimax";

/// Canonical filename expected under `MMX_CONFIG_DIR`.
pub const MMX_CONFIG_FILE: &str = "config.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkingDirectoryMode {
    #[default]
    Denied,
    Workspace,
    OutputRoot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthContract {
    pub kind: AuthKind,
    pub requirement: AuthRequirement,
    pub provider: Option<String>,
    pub profile_selection: ProfileSelection,
    pub secret_bindings: Vec<SecretBindingRef>,
    pub storage: AuthStorage,
    pub injections: Vec<InjectionBinding>,
    pub lifecycle: AuthLifecycle,
    pub identity: IdentityContract,
}

impl Default for AuthContract {
    fn default() -> Self {
        Self {
            kind: AuthKind::None,
            requirement: AuthRequirement::None,
            provider: None,
            profile_selection: ProfileSelection::None,
            secret_bindings: Vec::new(),
            storage: AuthStorage::None,
            injections: Vec::new(),
            lifecycle: AuthLifecycle::default(),
            identity: IdentityContract::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    #[default]
    None,
    Secrets,
    CliProfile,
    #[serde(rename = "oauth_session")]
    OAuthSession,
    BrowserProfile,
    NativePermission,
    DelegatedCredential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthRequirement {
    #[default]
    None,
    Optional,
    Required,
    /// Multiple declared secret bindings are alternatives; at least one must
    /// resolve before execution, while absent alternatives are not injected.
    AtLeastOne,
    Conditional,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProfileSelection {
    #[default]
    None,
    Selectable {
        default: Option<String>,
    },
    Fixed {
        alias: String,
    },
    /// The provider/CLI owns the active identity and the model receives no selector.
    Implicit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretBindingRef {
    /// Stable local binding name referenced by `InjectionSource::Secret`.
    pub name: String,
    /// Reference name resolved by the existing scoped secret/grant boundary.
    pub secret_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthStorage {
    #[default]
    None,
    ScopedDirectory {
        namespace: String,
        #[serde(default)]
        partition_by_profile: bool,
    },
    CliOwned,
    BrowserProfile,
    OperatingSystem,
    EphemeralGrant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InjectionBinding {
    pub source: InjectionSource,
    pub target: InjectionTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InjectionSource {
    Secret {
        binding: String,
    },
    ProfileAuthRoot {
        #[serde(default)]
        path: Vec<String>,
    },
    ProfileAlias,
    ExpectedIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InjectionTarget {
    Environment { name: String },
    Stdin,
    ScopedFile { relative_path: String },
    ConfigDirectory { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthLifecycle {
    pub status: Option<LifecycleHook>,
    pub status_observation: Option<LifecycleStatusObservation>,
    pub login: Option<LifecycleHook>,
    pub logout: Option<LifecycleHook>,
    pub refresh: Option<LifecycleHook>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleHook {
    /// Exact broker-owned argv tokens after the fixed executable. Lifecycle
    /// hooks do not inherit the model-facing runtime command prefix.
    pub args: Vec<String>,
    #[serde(default)]
    pub interaction: CliInteraction,
    #[serde(default)]
    pub timeout_secs: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleStatusObservation {
    pub format: LifecycleStatusOutputFormat,
    pub rules: Vec<LifecycleStatusRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleStatusOutputFormat {
    ExitCode,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleStatusRule {
    pub state: LifecycleObservedAuthState,
    #[serde(default = "default_lifecycle_success_exit_codes")]
    pub exit_codes: BTreeSet<i32>,
    #[serde(default)]
    pub all: Vec<LifecycleJsonPredicate>,
}

fn default_lifecycle_success_exit_codes() -> BTreeSet<i32> {
    BTreeSet::from([0])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleObservedAuthState {
    Missing,
    InteractionRequired,
    Ready,
    Expired,
    Revoked,
    Denied,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LifecycleJsonPredicate {
    Equals {
        pointer: String,
        value: LifecycleJsonScalar,
    },
    Exists {
        pointer: String,
    },
    Missing {
        pointer: String,
    },
    ArrayContainsAllStrings {
        pointer: String,
        values: BTreeSet<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LifecycleJsonScalar {
    String { value: String },
    Boolean { value: bool },
    Integer { value: i64 },
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum IdentityContract {
    #[default]
    None,
    ProfileExpected {
        selector: IdentitySelector,
    },
    /// Explicitly records a provider limitation; it never implies a match.
    Unverified {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IdentitySelector {
    JsonPointer { pointer: String },
    JsonPointerAsciiCaseInsensitive { pointer: String },
}

/// Minimum local policy attached to a skill. Later policy composition may only
/// preserve or strengthen this floor; manifest contents never grant authority.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyFloor {
    pub approval: ApprovalClass,
    pub required_grants: BTreeSet<String>,
    pub resource_scopes: BTreeSet<String>,
    pub required_resource_authorities: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalClass {
    #[default]
    Ordinary,
    ConditionalExternalSideEffect,
    DelegatedWorkspaceWrite,
    NativeUiControl,
    CommerceCheckout,
}

/// Auth lifecycle states are public vocabulary but are not produced by this
/// pure contract module. The Auth Broker state machine is implemented later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthState {
    Unknown,
    Missing,
    InteractionRequired,
    Authenticating,
    Ready,
    Expired,
    Revoked,
    IdentityMismatch,
    Denied,
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_contract(yaml: &str) -> SkillRuntimeContract {
        serde_yaml::from_str(yaml).expect("fixture must match the Phase 1A vocabulary")
    }

    #[test]
    fn unauthenticated_cli_contract_round_trips_with_safe_defaults() {
        let contract = parse_contract(
            r#"
schema_version: tool-runtime.skill-runtime.v1
requires:
  bins: [jq]
runtime:
  protocol: cli
  command_prefix: []
"#,
        );

        assert_eq!(contract.schema_version.as_str(), SKILL_RUNTIME_CONTRACT_V1);
        assert_eq!(contract.auth, AuthContract::default());
        assert_eq!(contract.policy_floor, PolicyFloor::default());
        assert_eq!(
            serde_yaml::from_str::<SkillRuntimeContract>(
                &serde_yaml::to_string(&contract).expect("serialize contract")
            )
            .expect("deserialize contract"),
            contract
        );
    }

    #[test]
    fn profile_cli_contract_keeps_identity_and_secret_values_out_of_the_manifest() {
        let contract = parse_contract(
            r#"
schema_version: tool-runtime.skill-runtime.v1
requires:
  bins: [gws]
runtime:
  protocol: cli
  command_prefix: [gmail]
  limits:
    timeout_secs: 30
auth:
  kind: cli_profile
  requirement: required
  provider: google-workspace
  profile_selection:
    mode: selectable
    default: work
  storage:
    kind: scoped_directory
    namespace: gws
    partition_by_profile: true
  injections:
    - source:
        kind: profile_auth_root
        path: []
      target:
        kind: environment
        name: GOOGLE_WORKSPACE_CLI_CONFIG_DIR
    - source:
        kind: profile_auth_root
        path: [cloudsdk]
      target:
        kind: environment
        name: CLOUDSDK_CONFIG
  lifecycle:
    status:
      args: [auth, status, --json]
      timeout_secs: 30
    status_observation:
      format: json
      rules:
        - state: ready
          all:
            - kind: equals
              pointer: /ready
              value: {kind: boolean, value: true}
    login:
      args: [auth, login, -s, "gmail,sheets,drive,docs,calendar"]
      interaction: pty
      timeout_secs: 300
  identity:
    mode: profile_expected
    selector:
      kind: json_pointer
      pointer: /account/email
policy_floor:
  approval: conditional_external_side_effect
  required_grants: [google-workspace]
"#,
        );

        let serialized = serde_json::to_string(&contract).expect("serialize contract");
        assert!(
            !serialized.contains("@"),
            "manifest must not contain an identity value"
        );
        assert!(
            !serialized.contains("token"),
            "manifest must not contain token material"
        );
        assert!(matches!(
            contract.auth.profile_selection,
            ProfileSelection::Selectable { ref default } if default.as_deref() == Some("work")
        ));
        assert!(matches!(
            contract.auth.identity,
            IdentityContract::ProfileExpected { .. }
        ));
    }

    #[test]
    fn static_secret_contract_stores_only_a_reference_and_typed_target() {
        let contract = parse_contract(
            r#"
schema_version: tool-runtime.skill-runtime.v1
requires:
  bins: [provider-cli]
runtime:
  protocol: cli
auth:
  kind: secrets
  requirement: required
  secret_bindings:
    - name: provider_api_key
      secret_ref: PROVIDER_API_KEY
  injections:
    - source:
        kind: secret
        binding: provider_api_key
      target:
        kind: environment
        name: PROVIDER_API_KEY
"#,
        );

        assert_eq!(contract.auth.secret_bindings.len(), 1);
        assert!(matches!(
            contract.auth.injections.as_slice(),
            [InjectionBinding {
                source: InjectionSource::Secret { binding },
                target: InjectionTarget::Environment { name },
            }] if binding == "provider_api_key" && name == "PROVIDER_API_KEY"
        ));
    }

    #[test]
    fn every_auth_and_profile_discriminant_has_a_stable_wire_name() {
        let auth_kinds = [
            (AuthKind::None, "none"),
            (AuthKind::Secrets, "secrets"),
            (AuthKind::CliProfile, "cli_profile"),
            (AuthKind::OAuthSession, "oauth_session"),
            (AuthKind::BrowserProfile, "browser_profile"),
            (AuthKind::NativePermission, "native_permission"),
            (AuthKind::DelegatedCredential, "delegated_credential"),
        ];
        for (kind, expected) in auth_kinds {
            assert_eq!(
                serde_json::to_value(kind).expect("serialize auth kind"),
                serde_json::json!(expected)
            );
        }

        let profiles = [
            (ProfileSelection::None, "none"),
            (ProfileSelection::Implicit, "implicit"),
        ];
        for (profile, expected) in profiles {
            assert_eq!(
                serde_json::to_value(profile).expect("serialize profile mode"),
                serde_json::json!({"mode": expected})
            );
        }
    }

    #[test]
    fn stdio_and_streamable_http_are_the_only_mcp_transport_variants() {
        let stdio = parse_contract(
            r#"
schema_version: tool-runtime.skill-runtime.v1
requires:
  bins: [provider-mcp-server]
runtime:
  protocol: mcp
  transport:
    kind: stdio
    executable: provider-mcp-server
    args: [--stdio]
"#,
        );
        let remote = parse_contract(
            r#"
schema_version: tool-runtime.skill-runtime.v1
runtime:
  protocol: mcp
  transport:
    kind: streamable_http
    endpoint: https://provider.example/mcp
  discovery:
    namespace: provider
    allow_tools: [read, search]
    deny_tools: [admin]
auth:
  kind: oauth_session
  requirement: required
  provider: provider-mcp
  profile_selection:
    mode: selectable
    default: personal
"#,
        );

        assert!(matches!(
            stdio.runtime,
            RuntimeProtocol::Mcp {
                transport: McpTransport::Stdio { .. },
                ..
            }
        ));
        assert!(matches!(
            remote.runtime,
            RuntimeProtocol::Mcp {
                transport: McpTransport::StreamableHttp { .. },
                ..
            }
        ));
    }

    #[test]
    fn unordered_contract_sets_serialize_deterministically() {
        let contract = parse_contract(
            r#"
schema_version: tool-runtime.skill-runtime.v1
requires:
  bins: [zeta, alpha]
runtime:
  protocol: cli
policy_floor:
  required_grants: [write, read]
  resource_scopes: [workspace, output]
"#,
        );
        let yaml = serde_yaml::to_string(&contract).expect("serialize contract");

        assert!(yaml.find("alpha").unwrap() < yaml.find("zeta").unwrap());
        assert!(yaml.find("read").unwrap() < yaml.find("write").unwrap());
        assert!(yaml.find("output").unwrap() < yaml.find("workspace").unwrap());
    }

    #[test]
    fn unknown_security_fields_are_not_part_of_the_v1_vocabulary() {
        let error = serde_yaml::from_str::<SkillRuntimeContract>(
            r#"
schema_version: tool-runtime.skill-runtime.v1
runtime:
  protocol: cli
auth:
  kind: none
  raw_token: do-not-accept
"#,
        )
        .expect_err("unknown auth field must be rejected");

        assert!(error.to_string().contains("unknown field `raw_token`"));
    }

    #[test]
    fn forward_version_is_retained_for_the_phase_1b_diagnostic() {
        let contract = parse_contract(
            r#"
schema_version: tool-runtime.skill-runtime.v2
runtime:
  protocol: cli
"#,
        );

        assert_eq!(
            contract.schema_version.as_str(),
            "tool-runtime.skill-runtime.v2"
        );
        assert_ne!(contract.schema_version.as_str(), SKILL_RUNTIME_CONTRACT_V1);
    }
}
