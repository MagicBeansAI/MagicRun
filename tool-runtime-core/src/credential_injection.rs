//! Provider-neutral credential injection and audit metadata contracts.
//!
//! Phase 3A compiles a validated runtime manifest and the exact Phase 2 preparation
//! proof into a deterministic injection plan. The plan contains names, relative paths,
//! target kinds, and redaction identities only. It cannot read prepared values, inspect
//! the parent environment, create a file, spawn a process, persist a receipt, or enable
//! a production route. Later Phase 3 slices materialize this contract inside the sealed
//! one-call credential lifetime.

use std::{collections::BTreeSet, error::Error, fmt};

use serde::Serialize;

use crate::{
    credential_preparation::{
        CredentialMaterialBindingName, CredentialMaterialKind, CredentialPreparationPlan,
    },
    credential_profiles::{
        CredentialProfileBinding, CredentialProfileKey, CredentialProfileRevision, CredentialScope,
        ExpectedCredentialIdentity,
    },
    manifest::{AuthKind, InjectionSource, InjectionTarget, RuntimeProtocol},
    manifest_validation::{is_identifier, ValidatedSkillRuntimeContract},
    scoped_paths::ScopedPathComponent,
};

pub const CREDENTIAL_INJECTION_V1: &str = "tool-runtime.credential-injection.v1";
pub const CREDENTIAL_INJECTION_RECEIPT_V1: &str = "tool-runtime.credential-injection-receipt.v1";
pub const MAX_CREDENTIAL_CALL_ID_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialInjectionErrorCode {
    ContractMismatch,
    PlanMismatch,
    EnvironmentCollision,
    TargetCollision,
    InvalidCallId,
}

/// Stable, value-free failure returned while compiling injection metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CredentialInjectionError {
    pub code: CredentialInjectionErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl CredentialInjectionError {
    const fn new(
        code: CredentialInjectionErrorCode,
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

impl fmt::Display for CredentialInjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for CredentialInjectionError {}

/// Runtime-owned variables that may be copied into an otherwise empty child
/// environment. This finite enum prevents a manifest or model from widening the
/// inherited environment. Values are deliberately absent from the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChildEnvironmentVariable {
    Path,
    Home,
    Lang,
    LcAll,
    LcCtype,
    Term,
    Tz,
    SslCertFile,
}

impl ChildEnvironmentVariable {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Path => "PATH",
            Self::Home => "HOME",
            Self::Lang => "LANG",
            Self::LcAll => "LC_ALL",
            Self::LcCtype => "LC_CTYPE",
            Self::Term => "TERM",
            Self::Tz => "TZ",
            Self::SslCertFile => "SSL_CERT_FILE",
        }
    }
}

/// Name-only policy for rebuilding a child environment after `env_clear`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChildEnvironmentBaseline {
    variables: BTreeSet<ChildEnvironmentVariable>,
}

impl ChildEnvironmentBaseline {
    /// Fully hermetic baseline. Only declared credential environment targets may be
    /// present in the future child call.
    pub fn hermetic() -> Self {
        Self {
            variables: BTreeSet::new(),
        }
    }

    /// Hermetic CLI baseline that admits only a runtime-owned executable search
    /// directory. Specialized local sandboxes use this when locale, terminal,
    /// trust-store and home discovery are neither required nor authorized.
    pub fn path_only() -> Self {
        Self {
            variables: BTreeSet::from([ChildEnvironmentVariable::Path]),
        }
    }

    /// Portable CLI baseline whose values must later come from runtime-owned policy,
    /// never by cloning the complete parent environment. `SSL_CERT_FILE` is admitted
    /// so that adapters whose interpreter ships no trust store can still verify TLS;
    /// its value remains runtime-owned, never inherited from the caller.
    pub fn portable_cli() -> Self {
        Self {
            variables: BTreeSet::from([
                ChildEnvironmentVariable::Path,
                ChildEnvironmentVariable::Lang,
                ChildEnvironmentVariable::LcAll,
                ChildEnvironmentVariable::LcCtype,
                ChildEnvironmentVariable::Term,
                ChildEnvironmentVariable::Tz,
                ChildEnvironmentVariable::SslCertFile,
            ]),
        }
    }

    /// CLI-owned session baseline. `HOME` is deliberately available only to
    /// contracts whose authentication storage is owned by the installed CLI;
    /// ordinary provider adapters continue to use [`Self::portable_cli`] and
    /// cannot discover ambient user configuration.
    pub fn cli_owned_session() -> Self {
        let mut baseline = Self::portable_cli();
        baseline.variables.insert(ChildEnvironmentVariable::Home);
        baseline
    }

    pub fn variables(&self) -> &BTreeSet<ChildEnvironmentVariable> {
        &self.variables
    }

    fn contains_name(&self, name: &str) -> bool {
        self.variables
            .iter()
            .any(|variable| variable.as_str().eq_ignore_ascii_case(name))
    }
}

impl Default for ChildEnvironmentBaseline {
    fn default() -> Self {
        Self::portable_cli()
    }
}

/// Validated relative file path copied from an already validated runtime contract.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct CredentialRelativePath(String);

impl CredentialRelativePath {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_string(value: String) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialInjectionSource {
    PreparedBinding {
        binding: CredentialMaterialBindingName,
        required: bool,
    },
    ProfileAuthRoot {
        path: Vec<ScopedPathComponent>,
    },
    ProfileAlias,
    ExpectedIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialInjectionTarget {
    Environment {
        name: String,
    },
    Stdin,
    ScopedFile {
        relative_path: CredentialRelativePath,
    },
    ConfigDirectory {
        name: ScopedPathComponent,
    },
}

impl CredentialInjectionTarget {
    pub const fn kind(&self) -> CredentialInjectionTargetKind {
        match self {
            Self::Environment { .. } => CredentialInjectionTargetKind::Environment,
            Self::Stdin => CredentialInjectionTargetKind::Stdin,
            Self::ScopedFile { .. } => CredentialInjectionTargetKind::ScopedFile,
            Self::ConfigDirectory { .. } => CredentialInjectionTargetKind::ConfigDirectory,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialInjectionTargetKind {
    Environment,
    Stdin,
    ScopedFile,
    ConfigDirectory,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct CredentialInjectionBinding {
    source: CredentialInjectionSource,
    target: CredentialInjectionTarget,
}

impl CredentialInjectionBinding {
    pub fn source(&self) -> &CredentialInjectionSource {
        &self.source
    }

    pub fn target(&self) -> &CredentialInjectionTarget {
        &self.target
    }
}

/// One metadata-only identity that later redaction must bind to its prepared value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialRedactionBinding {
    binding: CredentialMaterialBindingName,
    material_kind: CredentialMaterialKind,
    required: bool,
}

impl CredentialRedactionBinding {
    pub fn binding(&self) -> &CredentialMaterialBindingName {
        &self.binding
    }

    pub fn material_kind(&self) -> CredentialMaterialKind {
        self.material_kind
    }

    pub fn is_required(&self) -> bool {
        self.required
    }
}

/// Deterministic metadata plan for a future governed child call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialInjectionPlan {
    schema_version: &'static str,
    scope: CredentialScope,
    auth_kind: AuthKind,
    selected_profile: Option<CredentialProfileKey>,
    selected_profile_revision: Option<CredentialProfileRevision>,
    selected_expected_identity: Option<ExpectedCredentialIdentity>,
    implicit_profile: Option<(String, CredentialProfileBinding)>,
    baseline: ChildEnvironmentBaseline,
    child_environment_names: Vec<String>,
    injections: Vec<CredentialInjectionBinding>,
    redaction_bindings: Vec<CredentialRedactionBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum InjectionCollisionKey {
    Environment(String),
    Stdin,
    ScopedFile(String),
    ConfigDirectory(String),
}

impl CredentialInjectionPlan {
    /// Compile only from a validated contract and its exact Phase 2 preparation plan.
    /// No ambient state or credential material is consulted.
    pub fn compile(
        validated: ValidatedSkillRuntimeContract<'_>,
        preparation: &CredentialPreparationPlan,
        baseline: ChildEnvironmentBaseline,
    ) -> Result<Self, CredentialInjectionError> {
        let contract = validated.contract();
        if !preparation.matches_validated_contract(validated) {
            return Err(contract_mismatch());
        }
        if matches!(
            &contract.runtime,
            RuntimeProtocol::Mcp {
                transport: crate::manifest::McpTransport::StreamableHttp { .. },
                ..
            }
        ) && !contract.auth.injections.is_empty()
        {
            return Err(contract_mismatch());
        }

        let prepared = preparation
            .bindings()
            .iter()
            .map(|binding| (binding.name(), binding.kind(), binding.is_required()))
            .collect::<Vec<_>>();
        let mut used_secret_bindings = BTreeSet::new();
        let mut injections = Vec::with_capacity(contract.auth.injections.len());
        let mut occupied_targets = BTreeSet::new();
        let mut child_environment_names = baseline
            .variables()
            .iter()
            .map(|variable| variable.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        // `requires.environment` is the contract's fixed public configuration. The
        // executor hands those names to the child through `provide_fixed`, so the
        // plan must admit them or `governed_environment` rejects the whole
        // environment as a baseline mismatch and the call never dispatches.
        //
        // Admitting them cannot shadow anything: `validate_fixed_environment`
        // already refuses process-sensitive names and any name colliding with an
        // authored injection target, and `provide_fixed` already refuses a name
        // that collides with a baseline variable. Validation has run — `compile`
        // only accepts an already-validated contract.
        child_environment_names.extend(contract.requires.environment.keys().cloned());

        for authored in &contract.auth.injections {
            let source = match &authored.source {
                InjectionSource::Secret { binding } => {
                    let binding = CredentialMaterialBindingName::new(binding.clone())
                        .map_err(|_| plan_mismatch())?;
                    if prepared
                        .iter()
                        .find(|(name, _, _)| *name == &binding)
                        .map(|(_, kind, _)| *kind)
                        != Some(CredentialMaterialKind::SecretBinding)
                    {
                        return Err(plan_mismatch());
                    }
                    used_secret_bindings.insert(binding.clone());
                    let required = prepared
                        .iter()
                        .find(|(name, _, _)| *name == &binding)
                        .map(|(_, _, required)| *required)
                        .ok_or_else(plan_mismatch)?;
                    CredentialInjectionSource::PreparedBinding { binding, required }
                },
                InjectionSource::ProfileAuthRoot { path } => {
                    let path = path
                        .iter()
                        .cloned()
                        .map(ScopedPathComponent::new)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| contract_mismatch())?;
                    CredentialInjectionSource::ProfileAuthRoot { path }
                },
                InjectionSource::ProfileAlias => CredentialInjectionSource::ProfileAlias,
                InjectionSource::ExpectedIdentity => CredentialInjectionSource::ExpectedIdentity,
            };
            let target = match &authored.target {
                InjectionTarget::Environment { name } => {
                    if baseline.contains_name(name)
                        || !occupied_targets.insert(InjectionCollisionKey::Environment(
                            name.to_ascii_uppercase(),
                        ))
                    {
                        return Err(environment_collision());
                    }
                    child_environment_names.insert(name.clone());
                    CredentialInjectionTarget::Environment { name: name.clone() }
                },
                InjectionTarget::Stdin => {
                    if !occupied_targets.insert(InjectionCollisionKey::Stdin) {
                        return Err(target_collision());
                    }
                    CredentialInjectionTarget::Stdin
                },
                InjectionTarget::ScopedFile { relative_path } => {
                    if !occupied_targets.insert(InjectionCollisionKey::ScopedFile(
                        relative_path.to_ascii_lowercase(),
                    )) {
                        return Err(target_collision());
                    }
                    CredentialInjectionTarget::ScopedFile {
                        relative_path: CredentialRelativePath(relative_path.clone()),
                    }
                },
                InjectionTarget::ConfigDirectory { name } => {
                    child_environment_names.insert(name.as_str().to_owned());
                    if !occupied_targets.insert(InjectionCollisionKey::ConfigDirectory(
                        name.to_ascii_lowercase(),
                    )) {
                        return Err(target_collision());
                    }
                    CredentialInjectionTarget::ConfigDirectory {
                        name: ScopedPathComponent::new(name.clone())
                            .map_err(|_| contract_mismatch())?,
                    }
                },
            };
            injections.push(CredentialInjectionBinding { source, target });
        }

        if prepared.iter().any(|(binding, kind, _)| {
            *kind == CredentialMaterialKind::SecretBinding
                && !used_secret_bindings.contains(*binding)
        }) {
            return Err(plan_mismatch());
        }
        if injections.iter().any(|injection| {
            matches!(
                &injection.source,
                CredentialInjectionSource::ExpectedIdentity
            )
        }) && preparation.selected_expected_identity().is_none()
        {
            return Err(plan_mismatch());
        }

        injections.sort();
        let redaction_bindings = prepared
            .into_iter()
            .map(
                |(binding, material_kind, required)| CredentialRedactionBinding {
                    binding: binding.clone(),
                    material_kind,
                    required,
                },
            )
            .collect();

        Ok(Self {
            schema_version: CREDENTIAL_INJECTION_V1,
            scope: preparation.scope().clone(),
            auth_kind: preparation.auth_kind(),
            selected_profile: preparation.selected_profile_key().cloned(),
            selected_profile_revision: preparation.selected_profile_revision(),
            selected_expected_identity: preparation.selected_expected_identity().cloned(),
            implicit_profile: preparation
                .implicit_identity()
                .map(|(provider, binding)| (provider.as_str().to_owned(), binding.clone())),
            baseline,
            child_environment_names: child_environment_names.into_iter().collect(),
            injections,
            redaction_bindings,
        })
    }

    pub fn schema_version(&self) -> &'static str {
        self.schema_version
    }

    pub fn scope(&self) -> &CredentialScope {
        &self.scope
    }

    pub fn auth_kind(&self) -> AuthKind {
        self.auth_kind
    }

    pub fn selected_profile(&self) -> Option<&CredentialProfileKey> {
        self.selected_profile.as_ref()
    }

    pub fn selected_expected_identity(&self) -> Option<&ExpectedCredentialIdentity> {
        self.selected_expected_identity.as_ref()
    }

    pub fn selected_profile_revision(&self) -> Option<CredentialProfileRevision> {
        self.selected_profile_revision
    }

    pub fn baseline(&self) -> &ChildEnvironmentBaseline {
        &self.baseline
    }

    pub fn child_environment_names(&self) -> &[String] {
        &self.child_environment_names
    }

    pub fn injections(&self) -> &[CredentialInjectionBinding] {
        &self.injections
    }

    pub fn redaction_bindings(&self) -> &[CredentialRedactionBinding] {
        &self.redaction_bindings
    }
}

/// Runtime-owned correlation id admitted into a secret-free audit receipt.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct CredentialCallId(String);

impl CredentialCallId {
    pub fn new(value: impl Into<String>) -> Result<Self, CredentialInjectionError> {
        let value = value.into();
        if value.len() > MAX_CREDENTIAL_CALL_ID_BYTES || !is_identifier(&value) {
            return Err(invalid_call_id());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialExecutionFailure {
    ResolutionFailed,
    AuthorizationDenied,
    ApprovalDenied,
    EnvironmentUnavailable,
    StdinUnavailable,
    ScopedPathUnavailable,
    MaterializationFailed,
    ProcessCancelled,
    ProcessTimedOut,
    /// The child was terminated for passing its declared memory ceiling. Kept
    /// distinct from `ProcessTimedOut` so an operator reading the audit can tell
    /// a runaway allocation from a slow one.
    ProcessMemoryExceeded,
    ProcessExitedNonZero,
    OutputMalformed,
    OutputTruncated,
    RedactionFailed,
    CleanupFailed,
    AuditFailed,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CredentialExecutionOutcome {
    Succeeded,
    Cancelled,
    Failed { failure: CredentialExecutionFailure },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct CredentialInjectionTargetCounts {
    pub environment: usize,
    pub stdin: usize,
    pub scoped_file: usize,
    pub config_directory: usize,
}

impl CredentialInjectionTargetCounts {
    fn from_plan(plan: &CredentialInjectionPlan) -> Self {
        let mut counts = Self::default();
        for injection in plan.injections() {
            match injection.target.kind() {
                CredentialInjectionTargetKind::Environment => counts.environment += 1,
                CredentialInjectionTargetKind::Stdin => counts.stdin += 1,
                CredentialInjectionTargetKind::ScopedFile => counts.scoped_file += 1,
                CredentialInjectionTargetKind::ConfigDirectory => counts.config_directory += 1,
            }
        }
        counts
    }
}

/// Secret-free deterministic receipt body. A later audit adapter owns timestamps,
/// durability, and publication; this type cannot carry values, paths, argv, output, or
/// process diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialInjectionReceipt {
    schema_version: &'static str,
    call_id: CredentialCallId,
    scope: CredentialScope,
    auth_kind: AuthKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_profile: Option<CredentialProfileKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_profile_revision: Option<CredentialProfileRevision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    implicit_profile: Option<(String, CredentialProfileBinding)>,
    prepared_binding_count: usize,
    injection_count: usize,
    inherited_environment_name_count: usize,
    target_counts: CredentialInjectionTargetCounts,
    outcome: CredentialExecutionOutcome,
}

impl CredentialInjectionReceipt {
    /// Derive a metadata-only receipt from an already compiled plan. Callers cannot
    /// override any plan identity or target-count field.
    pub fn new(
        call_id: CredentialCallId,
        plan: &CredentialInjectionPlan,
        outcome: CredentialExecutionOutcome,
    ) -> Self {
        Self {
            schema_version: CREDENTIAL_INJECTION_RECEIPT_V1,
            call_id,
            scope: plan.scope.clone(),
            auth_kind: plan.auth_kind,
            selected_profile: plan.selected_profile.clone(),
            selected_profile_revision: plan.selected_profile_revision,
            implicit_profile: plan.implicit_profile.clone(),
            prepared_binding_count: plan.redaction_bindings.len(),
            injection_count: plan.injections.len(),
            inherited_environment_name_count: plan.baseline.variables.len(),
            target_counts: CredentialInjectionTargetCounts::from_plan(plan),
            outcome,
        }
    }

    pub fn schema_version(&self) -> &'static str {
        self.schema_version
    }

    pub fn call_id(&self) -> &CredentialCallId {
        &self.call_id
    }

    pub fn scope(&self) -> &CredentialScope {
        &self.scope
    }

    pub fn auth_kind(&self) -> AuthKind {
        self.auth_kind
    }

    pub fn selected_profile(&self) -> Option<&CredentialProfileKey> {
        self.selected_profile.as_ref()
    }

    pub fn selected_profile_revision(&self) -> Option<CredentialProfileRevision> {
        self.selected_profile_revision
    }

    pub fn implicit_profile(&self) -> Option<(&str, &CredentialProfileBinding)> {
        self.implicit_profile
            .as_ref()
            .map(|(provider, binding)| (provider.as_str(), binding))
    }

    pub fn prepared_binding_count(&self) -> usize {
        self.prepared_binding_count
    }

    pub fn injection_count(&self) -> usize {
        self.injection_count
    }

    pub fn inherited_environment_name_count(&self) -> usize {
        self.inherited_environment_name_count
    }

    pub fn target_counts(&self) -> CredentialInjectionTargetCounts {
        self.target_counts
    }

    pub fn outcome(&self) -> CredentialExecutionOutcome {
        self.outcome
    }
}

const fn contract_mismatch() -> CredentialInjectionError {
    CredentialInjectionError::new(
        CredentialInjectionErrorCode::ContractMismatch,
        "runtime_contract",
        "the validated runtime contract is incompatible with the credential plan",
    )
}

const fn plan_mismatch() -> CredentialInjectionError {
    CredentialInjectionError::new(
        CredentialInjectionErrorCode::PlanMismatch,
        "credential_plan",
        "the credential injection bindings do not exactly match the preparation plan",
    )
}

const fn environment_collision() -> CredentialInjectionError {
    CredentialInjectionError::new(
        CredentialInjectionErrorCode::EnvironmentCollision,
        "child_environment",
        "a credential target collides with the runtime-owned child environment",
    )
}

const fn target_collision() -> CredentialInjectionError {
    CredentialInjectionError::new(
        CredentialInjectionErrorCode::TargetCollision,
        "credential_target",
        "credential injection targets must remain distinct across supported platforms",
    )
}

const fn invalid_call_id() -> CredentialInjectionError {
    CredentialInjectionError::new(
        CredentialInjectionErrorCode::InvalidCallId,
        "call_id",
        "credential audit call ids must be bounded portable identifiers",
    )
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::{
        credential_preparation::{
            CredentialPreparationBinding, CredentialPreparationError,
            MAX_PREPARED_CREDENTIAL_BINDINGS,
        },
        credential_profiles::{
            CanonicalCredentialUrl, CredentialProfileAvailability, CredentialProfileMetadata,
            CredentialProfileRegistrySnapshot, CredentialProfileRevision, CredentialProfileStatus,
        },
        manifest::{
            AuthContract, AuthRequirement, AuthStorage, CliInteraction, InjectionBinding,
            McpDiscoveryPolicy, McpTransport, PolicyFloor, ProfileSelection, RuntimeLimits,
            RuntimeRequirements, SecretBindingRef, SkillRuntimeContract,
            SkillRuntimeContractVersion, StdinContract, WorkingDirectoryContract, MINIMAX_PROVIDER,
        },
        manifest_validation::validate_skill_runtime_contract,
        profile_selection::{
            select_credential_profile_from_snapshot, CredentialProfileSelectionRequest,
        },
    };

    fn scope() -> CredentialScope {
        CredentialScope::new("owner", "default").expect("scope")
    }

    fn cli_contract(auth: AuthContract) -> SkillRuntimeContract {
        SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires: RuntimeRequirements {
                bins: BTreeSet::from(["fixture-cli".to_owned()]),
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
            auth,
            policy_floor: PolicyFloor::default(),
        }
    }

    fn none_selection(
        selected_scope: &CredentialScope,
    ) -> crate::profile_selection::CredentialProfileSelectionDecision {
        let request = CredentialProfileSelectionRequest::new(
            selected_scope.clone(),
            None,
            CredentialProfileBinding::Provider,
            &ProfileSelection::None,
            None,
        )
        .expect("none selection request");
        let snapshot = CredentialProfileRegistrySnapshot::new(selected_scope.clone(), Vec::new())
            .expect("empty snapshot");
        select_credential_profile_from_snapshot(&request, &snapshot).expect("none selection")
    }

    fn implicit_selection(
        selected_scope: &CredentialScope,
        provider: &str,
    ) -> crate::profile_selection::CredentialProfileSelectionDecision {
        implicit_selection_with_binding(
            selected_scope,
            provider,
            CredentialProfileBinding::Provider,
        )
    }

    fn implicit_selection_with_binding(
        selected_scope: &CredentialScope,
        provider: &str,
        binding: CredentialProfileBinding,
    ) -> crate::profile_selection::CredentialProfileSelectionDecision {
        let request = CredentialProfileSelectionRequest::new(
            selected_scope.clone(),
            Some(provider),
            binding,
            &ProfileSelection::Implicit,
            None,
        )
        .expect("implicit selection request");
        let snapshot = CredentialProfileRegistrySnapshot::new(selected_scope.clone(), Vec::new())
            .expect("empty snapshot");
        select_credential_profile_from_snapshot(&request, &snapshot).expect("implicit selection")
    }

    fn mcp_oauth_contract(
        endpoint: &str,
        profile_selection: ProfileSelection,
    ) -> SkillRuntimeContract {
        SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires: RuntimeRequirements::default(),
            runtime: RuntimeProtocol::Mcp {
                transport: McpTransport::StreamableHttp {
                    endpoint: endpoint.to_owned(),
                },
                discovery: McpDiscoveryPolicy {
                    oauth: Some(crate::manifest::McpOAuthConnectionPolicy {
                        authorization_issuer: "https://issuer.example".to_owned(),
                        scopes: Default::default(),
                    }),
                    ..McpDiscoveryPolicy::default()
                },
                limits: RuntimeLimits::default(),
            },
            auth: AuthContract {
                kind: AuthKind::OAuthSession,
                requirement: AuthRequirement::Required,
                provider: Some("provider-mcp".to_owned()),
                profile_selection,
                ..AuthContract::default()
            },
            policy_floor: PolicyFloor::default(),
        }
    }

    fn selected_mcp_oauth_plan(
        selected_scope: &CredentialScope,
        binding: CredentialProfileBinding,
    ) -> CredentialPreparationPlan {
        let key = CredentialProfileKey::new(
            selected_scope.clone(),
            "provider-mcp",
            "work",
            binding.clone(),
        )
        .expect("profile key");
        let metadata = CredentialProfileMetadata::new(
            key,
            None,
            true,
            CredentialProfileAvailability::Enabled,
            CredentialProfileRevision::new(7).expect("revision"),
        )
        .expect("metadata");
        let status = CredentialProfileStatus::new(metadata, crate::manifest::AuthState::Ready)
            .expect("status");
        let snapshot = CredentialProfileRegistrySnapshot::new(selected_scope.clone(), vec![status])
            .expect("snapshot");
        let request = CredentialProfileSelectionRequest::new(
            selected_scope.clone(),
            Some("provider-mcp"),
            binding,
            &ProfileSelection::Fixed {
                alias: "work".to_owned(),
            },
            None,
        )
        .expect("selection request");
        let selection = select_credential_profile_from_snapshot(&request, &snapshot)
            .expect("profile selection");
        CredentialPreparationPlan::new(
            selected_scope.clone(),
            AuthKind::OAuthSession,
            &selection,
            Vec::new(),
        )
        .expect("preparation plan")
    }

    fn binding(
        name: &str,
        kind: CredentialMaterialKind,
    ) -> Result<CredentialPreparationBinding, CredentialPreparationError> {
        CredentialPreparationBinding::new(CredentialMaterialBindingName::new(name)?, kind, 1024)
    }

    fn secret_contract() -> SkillRuntimeContract {
        cli_contract(AuthContract {
            kind: AuthKind::Secrets,
            requirement: AuthRequirement::Required,
            secret_bindings: vec![
                SecretBindingRef {
                    name: "api_key".to_owned(),
                    secret_ref: "VAULT_PROVIDER_API_KEY".to_owned(),
                },
                SecretBindingRef {
                    name: "password".to_owned(),
                    secret_ref: "VAULT_PROVIDER_PASSWORD".to_owned(),
                },
            ],
            injections: vec![
                InjectionBinding {
                    source: InjectionSource::Secret {
                        binding: "api_key".to_owned(),
                    },
                    target: InjectionTarget::Environment {
                        name: "PROVIDER_API_KEY".to_owned(),
                    },
                },
                InjectionBinding {
                    source: InjectionSource::Secret {
                        binding: "api_key".to_owned(),
                    },
                    target: InjectionTarget::ScopedFile {
                        relative_path: "provider/api-key.txt".to_owned(),
                    },
                },
                InjectionBinding {
                    source: InjectionSource::Secret {
                        binding: "password".to_owned(),
                    },
                    target: InjectionTarget::Stdin,
                },
            ],
            ..AuthContract::default()
        })
    }

    fn secret_plan(selected_scope: &CredentialScope) -> CredentialPreparationPlan {
        CredentialPreparationPlan::new(
            selected_scope.clone(),
            AuthKind::Secrets,
            &none_selection(selected_scope),
            vec![
                binding("password", CredentialMaterialKind::SecretBinding).unwrap(),
                binding("api_key", CredentialMaterialKind::SecretBinding).unwrap(),
            ],
        )
        .expect("secret preparation plan")
    }

    #[test]
    fn validated_contract_compiles_to_deterministic_metadata_without_argv_or_values() {
        let contract = secret_contract();
        let plan = secret_plan(&scope());
        let compiled = CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract).expect("validated contract"),
            &plan,
            ChildEnvironmentBaseline::portable_cli(),
        )
        .expect("injection plan");

        assert_eq!(compiled.schema_version(), CREDENTIAL_INJECTION_V1);
        assert_eq!(compiled.scope(), &scope());
        assert_eq!(compiled.auth_kind(), AuthKind::Secrets);
        assert_eq!(compiled.injections().len(), 3);
        assert_eq!(compiled.redaction_bindings().len(), 2);
        assert_eq!(
            compiled
                .child_environment_names()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec![
                "LANG",
                "LC_ALL",
                "LC_CTYPE",
                "PATH",
                "PROVIDER_API_KEY",
                "SSL_CERT_FILE",
                "TERM",
                "TZ",
            ]
        );
        let api_key = compiled
            .redaction_bindings()
            .iter()
            .find(|binding| binding.binding().as_str() == "api_key")
            .expect("api key redaction identity");
        assert_eq!(
            api_key.material_kind(),
            CredentialMaterialKind::SecretBinding
        );

        let serialized = serde_json::to_string(&compiled).expect("serialize injection metadata");
        assert!(!serialized.contains("VAULT_PROVIDER_API_KEY"));
        assert!(!serialized.contains("VAULT_PROVIDER_PASSWORD"));
        assert!(!serialized.contains("credential-value-canary"));
        assert!(!serialized.contains("argv"));
        assert_eq!(
            serde_json::to_vec(&compiled).unwrap(),
            serde_json::to_vec(&compiled).unwrap()
        );
    }

    #[test]
    fn baseline_collision_is_explicit_and_hermetic_mode_remains_available() {
        let mut contract = secret_contract();
        contract.auth.injections[0].target = InjectionTarget::Environment {
            name: "lang".to_owned(),
        };
        let plan = secret_plan(&scope());
        let validated = validate_skill_runtime_contract(&contract).expect("validated contract");
        assert_eq!(
            CredentialInjectionPlan::compile(
                validated,
                &plan,
                ChildEnvironmentBaseline::portable_cli(),
            )
            .expect_err("baseline collision")
            .code,
            CredentialInjectionErrorCode::EnvironmentCollision
        );
        let hermetic = CredentialInjectionPlan::compile(
            validated,
            &plan,
            ChildEnvironmentBaseline::hermetic(),
        )
        .expect("hermetic environment");
        assert_eq!(
            hermetic
                .child_environment_names()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["lang"]
        );
    }

    #[test]
    fn fixed_public_environment_is_admitted_into_the_child_environment() {
        // A contract's `requires.environment` reaches the child through
        // `provide_fixed`. If the plan does not admit those names,
        // `governed_environment` rejects the whole environment as a baseline
        // mismatch and the call fails with `CredentialMaterializationFailed`
        // before dispatch — which is what took every officecli-backed skill
        // dark while declaring no credential at all.
        let mut contract = secret_contract();
        contract.requires.environment = BTreeMap::from([
            ("OFFICECLI_SKIP_UPDATE".to_owned(), "1".to_owned()),
            ("OFFICECLI_NO_AUTO_RESIDENT".to_owned(), "1".to_owned()),
        ]);
        let plan = secret_plan(&scope());
        let compiled = CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract).expect("validated contract"),
            &plan,
            ChildEnvironmentBaseline::portable_cli(),
        )
        .expect("injection plan");

        let names = compiled
            .child_environment_names()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert!(names.contains(&"OFFICECLI_SKIP_UPDATE"));
        assert!(names.contains(&"OFFICECLI_NO_AUTO_RESIDENT"));
        // The fixed names are additive: baseline variables and authored
        // injection targets must still be admitted alongside them.
        assert!(names.contains(&"PATH"));
        assert!(names.contains(&"PROVIDER_API_KEY"));
        // `governed_environment` resolves these by binary search, so an
        // unsorted list would silently fail to admit them.
        assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn config_directory_injections_are_admitted_to_the_child_environment() {
        let selected_scope = scope();
        let contract = cli_contract(AuthContract {
            kind: AuthKind::Secrets,
            requirement: AuthRequirement::Required,
            provider: Some(MINIMAX_PROVIDER.to_owned()),
            secret_bindings: vec![SecretBindingRef {
                name: "api_key".to_owned(),
                secret_ref: "VAULT_PROVIDER_API_KEY".to_owned(),
            }],
            injections: vec![InjectionBinding {
                source: InjectionSource::Secret {
                    binding: "api_key".to_owned(),
                },
                target: InjectionTarget::ConfigDirectory {
                    name: "MMX_CONFIG_DIR".to_owned(),
                },
            }],
            ..AuthContract::default()
        });
        let plan = CredentialPreparationPlan::new(
            selected_scope.clone(),
            AuthKind::Secrets,
            &none_selection(&selected_scope),
            vec![binding("api_key", CredentialMaterialKind::SecretBinding).unwrap()],
        )
        .expect("single secret preparation");

        let compiled = CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract)
                .expect("validated config-directory contract"),
            &plan,
            ChildEnvironmentBaseline::hermetic(),
        )
        .expect("compiled config-directory contract");

        let names = compiled
            .child_environment_names()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert!(names.contains(&"MMX_CONFIG_DIR"));
    }

    #[test]
    fn case_folded_file_target_aliases_fail_before_materialization() {
        let mut contract = secret_contract();
        contract.auth.injections.push(InjectionBinding {
            source: InjectionSource::Secret {
                binding: "api_key".to_owned(),
            },
            target: InjectionTarget::ScopedFile {
                relative_path: "Provider/API-KEY.txt".to_owned(),
            },
        });
        let plan = secret_plan(&scope());
        assert_eq!(
            CredentialInjectionPlan::compile(
                validate_skill_runtime_contract(&contract).expect("validated aliases"),
                &plan,
                ChildEnvironmentBaseline::hermetic(),
            )
            .expect_err("case-folded file alias")
            .code,
            CredentialInjectionErrorCode::TargetCollision
        );
    }

    #[test]
    fn contract_plan_auth_identity_and_binding_drift_fail_closed() {
        let contract = secret_contract();
        let validated = validate_skill_runtime_contract(&contract).expect("validated contract");
        let selected_scope = scope();
        let missing_binding = CredentialPreparationPlan::new(
            selected_scope.clone(),
            AuthKind::Secrets,
            &none_selection(&selected_scope),
            vec![binding("api_key", CredentialMaterialKind::SecretBinding).unwrap()],
        )
        .expect("partial plan");
        assert_eq!(
            CredentialInjectionPlan::compile(
                validated,
                &missing_binding,
                ChildEnvironmentBaseline::hermetic(),
            )
            .expect_err("missing binding")
            .code,
            CredentialInjectionErrorCode::PlanMismatch
        );

        let delegated = CredentialPreparationPlan::new(
            selected_scope.clone(),
            AuthKind::DelegatedCredential,
            &none_selection(&selected_scope),
            vec![binding(
                "delegated_credential",
                CredentialMaterialKind::DelegatedCredential,
            )
            .unwrap()],
        )
        .expect("delegated plan");
        assert_eq!(
            CredentialInjectionPlan::compile(
                validated,
                &delegated,
                ChildEnvironmentBaseline::hermetic(),
            )
            .expect_err("auth drift")
            .code,
            CredentialInjectionErrorCode::ContractMismatch
        );
    }

    #[test]
    fn profile_auth_root_is_metadata_only_and_never_becomes_a_physical_path() {
        let selected_scope = scope();
        let contract = cli_contract(AuthContract {
            kind: AuthKind::CliProfile,
            requirement: AuthRequirement::Required,
            provider: Some("google-workspace".to_owned()),
            profile_selection: ProfileSelection::Implicit,
            storage: AuthStorage::CliOwned,
            injections: vec![InjectionBinding {
                source: InjectionSource::ProfileAuthRoot {
                    path: vec!["cloudsdk".to_owned()],
                },
                target: InjectionTarget::ConfigDirectory {
                    name: "gcloud_config".to_owned(),
                },
            }],
            ..AuthContract::default()
        });
        let plan = CredentialPreparationPlan::new(
            selected_scope.clone(),
            AuthKind::CliProfile,
            &implicit_selection(&selected_scope, "google-workspace"),
            Vec::new(),
        )
        .expect("profile plan");
        let compiled = CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract).expect("profile contract"),
            &plan,
            ChildEnvironmentBaseline::hermetic(),
        )
        .expect("profile injection plan");

        assert!(compiled.redaction_bindings().is_empty());
        assert_eq!(compiled.injections().len(), 1);
        let serialized = serde_json::to_string(&compiled).expect("serialize profile metadata");
        assert!(serialized.contains("cloudsdk"));
        assert!(!serialized.contains("/Users/"));
        assert!(!serialized.contains("MagicianNotes"));
    }

    #[test]
    fn delegated_material_is_redaction_bound_but_has_no_manifest_forged_target() {
        let selected_scope = scope();
        let contract = cli_contract(AuthContract {
            kind: AuthKind::DelegatedCredential,
            requirement: AuthRequirement::Required,
            provider: Some("provider-a".to_owned()),
            storage: AuthStorage::EphemeralGrant,
            ..AuthContract::default()
        });
        let plan = CredentialPreparationPlan::new(
            selected_scope.clone(),
            AuthKind::DelegatedCredential,
            &none_selection(&selected_scope),
            vec![binding(
                "delegated_credential",
                CredentialMaterialKind::DelegatedCredential,
            )
            .unwrap()],
        )
        .expect("delegated plan");
        let compiled = CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract).expect("delegated contract"),
            &plan,
            ChildEnvironmentBaseline::hermetic(),
        )
        .expect("delegated injection metadata");

        assert!(compiled.injections().is_empty());
        assert_eq!(compiled.redaction_bindings().len(), 1);
        assert_eq!(
            compiled.redaction_bindings()[0].material_kind(),
            CredentialMaterialKind::DelegatedCredential
        );
    }

    #[test]
    fn receipts_are_deterministic_typed_and_secret_free() {
        let contract = secret_contract();
        let plan = secret_plan(&scope());
        let compiled = CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract).expect("validated contract"),
            &plan,
            ChildEnvironmentBaseline::portable_cli(),
        )
        .expect("injection plan");
        let receipt = CredentialInjectionReceipt::new(
            CredentialCallId::new("exec_qualification_001").expect("call id"),
            &compiled,
            CredentialExecutionOutcome::Failed {
                failure: CredentialExecutionFailure::ProcessExitedNonZero,
            },
        );
        assert_eq!(receipt.prepared_binding_count(), 2);
        assert_eq!(receipt.injection_count(), 3);
        assert_eq!(receipt.inherited_environment_name_count(), 7);
        assert_eq!(receipt.target_counts().environment, 1);
        assert_eq!(receipt.target_counts().stdin, 1);
        assert_eq!(receipt.target_counts().scoped_file, 1);
        let serialized = serde_json::to_string(&receipt).expect("serialize receipt");
        for canary in [
            "VAULT_PROVIDER_API_KEY",
            "VAULT_PROVIDER_PASSWORD",
            "credential-value-canary",
            "/Users/owner",
        ] {
            assert!(!serialized.contains(canary));
        }

        let call_canary = "../CALL_ID_CANARY";
        let error = CredentialCallId::new(call_canary).expect_err("invalid call id");
        assert_eq!(error.code, CredentialInjectionErrorCode::InvalidCallId);
        assert!(!format!("{error:?} {error}").contains(call_canary));
    }

    #[test]
    fn remote_mcp_oauth_rejects_provider_only_and_wrong_resource_bindings() {
        let endpoint = "https://provider.example/mcp";
        let contract = mcp_oauth_contract(
            endpoint,
            ProfileSelection::Fixed {
                alias: "work".to_owned(),
            },
        );
        let validated = validate_skill_runtime_contract(&contract).expect("validated contract");

        let provider_only = selected_mcp_oauth_plan(&scope(), CredentialProfileBinding::Provider);
        assert_eq!(
            CredentialInjectionPlan::compile(
                validated,
                &provider_only,
                ChildEnvironmentBaseline::hermetic(),
            )
            .expect_err("provider-only binding must not cross remote MCP OAuth boundary")
            .code,
            CredentialInjectionErrorCode::ContractMismatch
        );

        let wrong_resource = CredentialProfileBinding::McpOauth {
            resource_url: CanonicalCredentialUrl::new("https://other.example/mcp")
                .expect("resource"),
            authorization_issuer: CanonicalCredentialUrl::new("https://issuer.example")
                .expect("issuer"),
        };
        let wrong = selected_mcp_oauth_plan(&scope(), wrong_resource);
        assert_eq!(
            CredentialInjectionPlan::compile(
                validated,
                &wrong,
                ChildEnvironmentBaseline::hermetic(),
            )
            .expect_err("wrong OAuth resource must fail closed")
            .code,
            CredentialInjectionErrorCode::ContractMismatch
        );
    }

    #[test]
    fn remote_mcp_oauth_receipt_preserves_exact_binding_issuer_and_revision() {
        let endpoint = "https://provider.example/mcp";
        let binding = CredentialProfileBinding::McpOauth {
            resource_url: CanonicalCredentialUrl::new(endpoint).expect("resource"),
            authorization_issuer: CanonicalCredentialUrl::new("https://issuer.example/tenant")
                .expect("issuer"),
        };
        let preparation = selected_mcp_oauth_plan(&scope(), binding.clone());
        let contract = mcp_oauth_contract(
            endpoint,
            ProfileSelection::Fixed {
                alias: "work".to_owned(),
            },
        );
        let injection = CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract).expect("validated contract"),
            &preparation,
            ChildEnvironmentBaseline::hermetic(),
        )
        .expect("exact MCP OAuth binding");
        let receipt = CredentialInjectionReceipt::new(
            CredentialCallId::new("exec_mcp_oauth_001").expect("call id"),
            &injection,
            CredentialExecutionOutcome::Succeeded,
        );

        assert_eq!(
            receipt.selected_profile().map(|profile| &profile.binding),
            Some(&binding)
        );
        assert_eq!(
            receipt
                .selected_profile_revision()
                .map(|revision| revision.get()),
            Some(7)
        );
        let serialized = serde_json::to_value(&receipt).expect("serialize receipt");
        assert_eq!(
            serialized["selected_profile"]["binding"]["authorization_issuer"],
            "https://issuer.example/tenant"
        );
        assert_eq!(serialized["selected_profile_revision"], 7);
    }

    #[test]
    fn remote_mcp_oauth_implicit_identity_preserves_its_exact_binding() {
        let endpoint = "https://provider.example/mcp";
        let binding = CredentialProfileBinding::McpOauth {
            resource_url: CanonicalCredentialUrl::new(endpoint).expect("resource"),
            authorization_issuer: CanonicalCredentialUrl::new("https://issuer.example")
                .expect("issuer"),
        };
        let selected_scope = scope();
        let selection =
            implicit_selection_with_binding(&selected_scope, "provider-mcp", binding.clone());
        let preparation = CredentialPreparationPlan::new(
            selected_scope,
            AuthKind::OAuthSession,
            &selection,
            Vec::new(),
        )
        .expect("implicit preparation");
        let contract = mcp_oauth_contract(endpoint, ProfileSelection::Implicit);
        let injection = CredentialInjectionPlan::compile(
            validate_skill_runtime_contract(&contract).expect("validated contract"),
            &preparation,
            ChildEnvironmentBaseline::hermetic(),
        )
        .expect("exact implicit MCP OAuth binding");
        let receipt = CredentialInjectionReceipt::new(
            CredentialCallId::new("exec_mcp_implicit_001").expect("call id"),
            &injection,
            CredentialExecutionOutcome::Succeeded,
        );
        assert_eq!(receipt.implicit_profile(), Some(("provider-mcp", &binding)));
    }

    #[test]
    fn maximum_injection_plan_compiles_and_serializes_on_a_small_stack() {
        let join = std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| {
                let selected_scope = scope();
                let mut contract = cli_contract(AuthContract {
                    kind: AuthKind::Secrets,
                    requirement: AuthRequirement::Required,
                    ..AuthContract::default()
                });
                let mut bindings = Vec::new();
                for index in 0..MAX_PREPARED_CREDENTIAL_BINDINGS {
                    let name = format!("secret_{index:02}");
                    contract.auth.secret_bindings.push(SecretBindingRef {
                        name: name.clone(),
                        secret_ref: format!("VAULT_SECRET_{index:02}"),
                    });
                    contract.auth.injections.push(InjectionBinding {
                        source: InjectionSource::Secret {
                            binding: name.clone(),
                        },
                        target: InjectionTarget::Environment {
                            name: format!("PROVIDER_SECRET_{index:02}"),
                        },
                    });
                    bindings.push(binding(&name, CredentialMaterialKind::SecretBinding).unwrap());
                }
                let plan = CredentialPreparationPlan::new(
                    selected_scope.clone(),
                    AuthKind::Secrets,
                    &none_selection(&selected_scope),
                    bindings,
                )
                .expect("maximum preparation plan");
                let compiled = CredentialInjectionPlan::compile(
                    validate_skill_runtime_contract(&contract).expect("maximum contract"),
                    &plan,
                    ChildEnvironmentBaseline::hermetic(),
                )
                .expect("maximum injection plan");
                assert_eq!(
                    compiled.injections().len(),
                    MAX_PREPARED_CREDENTIAL_BINDINGS
                );
                assert_eq!(
                    serde_json::to_vec(&compiled).expect("serialize maximum plan"),
                    serde_json::to_vec(&compiled).expect("serialize maximum plan again")
                );
            })
            .expect("spawn small-stack injection compiler");
        assert!(join.join().is_ok());
    }

    #[test]
    fn child_environment_baselines_are_finite_name_only_policies() {
        let baseline = ChildEnvironmentBaseline::portable_cli();
        assert_eq!(baseline.variables().len(), 7);
        assert!(!baseline.variables().iter().any(|variable| {
            matches!(
                variable.as_str(),
                "HOME" | "TMPDIR" | "DYLD_INSERT_LIBRARIES" | "NODE_OPTIONS"
            )
        }));
        let serialized = serde_json::to_string(&baseline).expect("serialize baseline names");
        assert!(!serialized.contains('=') && !serialized.contains("credential-value-canary"));
        assert!(ChildEnvironmentBaseline::hermetic().variables().is_empty());
    }

    #[test]
    fn portable_cli_admits_the_ca_bundle() {
        let baseline = ChildEnvironmentBaseline::portable_cli();
        assert!(baseline.contains_name("SSL_CERT_FILE"));
    }

    #[test]
    fn hermetic_baseline_still_admits_nothing() {
        let baseline = ChildEnvironmentBaseline::hermetic();
        assert!(!baseline.contains_name("SSL_CERT_FILE"));
        assert!(baseline.variables().is_empty());
    }
}
