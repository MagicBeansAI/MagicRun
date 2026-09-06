//! Trusted local policy projection for discovered MCP tools.
//!
//! Remote names select exact locally authored rules, but remote descriptions,
//! annotations, schemas, endpoints, and authentication material never enter this
//! contract. Phase 5D2 applies the compiled contract to SDK-validated descriptors.
//! This module performs no discovery, I/O, catalog publication, or authorization.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    sync::Arc,
};

use serde::Serialize;

use crate::{
    manifest::{ApprovalClass, McpToolPolicy, McpToolRiskClass, PolicyFloor},
    manifest_synthesis::{
        synthesize_runtime_catalog, SynthesizedMcpCatalogLimits, SynthesizedRuntime,
        MAX_SYNTHESIZED_TOOL_NAME_BYTES,
    },
    manifest_validation::{is_mcp_tool_name, ValidatedSkillRuntimeContract, MAX_POLICY_ENTRIES},
};

pub const MCP_CATALOG_POLICY_CONTRACT_V1: &str = "tool-runtime.mcp-catalog-policy.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpCatalogPolicyErrorCode {
    UnsupportedRuntime,
    InvalidSkillIdentity,
    InvalidRemoteToolName,
    LocalToolNameTooLong,
    InvalidEffectivePolicy,
}

/// Stable, value-free compiler diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct McpCatalogPolicyError {
    pub code: McpCatalogPolicyErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl McpCatalogPolicyError {
    const fn new(
        code: McpCatalogPolicyErrorCode,
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

impl fmt::Display for McpCatalogPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for McpCatalogPolicyError {}

/// Transport- and credential-free policy compiled from a validated MCP skill contract.
///
/// Remote tool names remain private lookup keys. This type deliberately has no
/// serialization contract and is not a model-facing catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpCatalogPolicyContract {
    pub schema_version: &'static str,
    local_namespace: String,
    allow_tools: BTreeSet<String>,
    deny_tools: BTreeSet<String>,
    catalog_limits: SynthesizedMcpCatalogLimits,
    base_policy: Arc<PolicyFloor>,
    tool_policies: BTreeMap<String, McpToolPolicy>,
}

impl McpCatalogPolicyContract {
    pub fn compile(
        skill_id: &str,
        validated: ValidatedSkillRuntimeContract<'_>,
    ) -> Result<Self, McpCatalogPolicyError> {
        let catalog = synthesize_runtime_catalog(skill_id, validated).map_err(|_| {
            McpCatalogPolicyError::new(
                McpCatalogPolicyErrorCode::InvalidSkillIdentity,
                "skill_id",
                "the validated MCP skill identity could not be synthesized",
            )
        })?;
        let SynthesizedRuntime::Mcp { discovery } = catalog.runtime else {
            return Err(McpCatalogPolicyError::new(
                McpCatalogPolicyErrorCode::UnsupportedRuntime,
                "runtime.protocol",
                "the MCP catalog policy compiler requires an MCP runtime",
            ));
        };
        let base = catalog.security_floor.policy;
        let contract = Self {
            schema_version: MCP_CATALOG_POLICY_CONTRACT_V1,
            local_namespace: discovery.local_namespace,
            allow_tools: discovery.policy.allow_tools,
            deny_tools: discovery.policy.deny_tools,
            catalog_limits: discovery.catalog_limits,
            base_policy: Arc::new(base),
            tool_policies: discovery.policy.tool_policies,
        };
        for policy in contract.tool_policies.values() {
            contract.compose_effective(policy.risk, Some(policy))?;
        }
        Ok(contract)
    }

    pub fn local_namespace(&self) -> &str {
        &self.local_namespace
    }

    pub fn catalog_limits(&self) -> SynthesizedMcpCatalogLimits {
        self.catalog_limits
    }

    /// Mint the exact stable local name after enforcing the trusted portable remote-name
    /// vocabulary. This is injective for one fixed namespace and performs no lossy slugging.
    pub fn local_tool_name(&self, remote_tool_name: &str) -> Result<String, McpCatalogPolicyError> {
        if !is_mcp_tool_name(remote_tool_name)
            || remote_tool_name.len() > self.catalog_limits.max_tool_name_bytes
        {
            return Err(McpCatalogPolicyError::new(
                McpCatalogPolicyErrorCode::InvalidRemoteToolName,
                "remote_tool_name",
                "the remote MCP tool name is not portable or exceeds its local limit",
            ));
        }
        let length = self
            .local_namespace
            .len()
            .checked_add(1)
            .and_then(|length| length.checked_add(remote_tool_name.len()))
            .ok_or_else(|| {
                McpCatalogPolicyError::new(
                    McpCatalogPolicyErrorCode::LocalToolNameTooLong,
                    "local_tool_name",
                    "the projected MCP tool name exceeds its local limit",
                )
            })?;
        if length > MAX_SYNTHESIZED_TOOL_NAME_BYTES {
            return Err(McpCatalogPolicyError::new(
                McpCatalogPolicyErrorCode::LocalToolNameTooLong,
                "local_tool_name",
                "the projected MCP tool name exceeds its local limit",
            ));
        }
        Ok(format!("{}.{}", self.local_namespace, remote_tool_name))
    }

    /// Apply exact allow/deny rules and return the additive local policy. Deny always
    /// wins. An eligible tool without an exact policy receives `Unclassified` risk.
    pub fn decision(
        &self,
        remote_tool_name: &str,
    ) -> Result<McpToolPublicationDecision, McpCatalogPolicyError> {
        if self.deny_tools.contains(remote_tool_name)
            || (!self.allow_tools.is_empty() && !self.allow_tools.contains(remote_tool_name))
        {
            return Ok(McpToolPublicationDecision::Denied);
        }
        let local = self.tool_policies.get(remote_tool_name);
        let risk = local.map_or(McpToolRiskClass::Unclassified, |policy| policy.risk);
        self.compose_effective(risk, local)
            .map(McpToolPublicationDecision::Publish)
    }

    fn compose_effective(
        &self,
        risk: McpToolRiskClass,
        local: Option<&McpToolPolicy>,
    ) -> Result<McpEffectiveToolPolicy, McpCatalogPolicyError> {
        let mut required_approvals =
            BTreeSet::from([self.base_policy.approval, risk_approval(risk)]);
        let (
            trusted_description,
            additional_required_grants,
            additional_resource_scopes,
            additional_required_resource_authorities,
        ) = if let Some(local) = local {
            required_approvals.extend(local.additional_approvals.iter().copied());
            (
                local.trusted_description.clone(),
                local.additional_required_grants.clone(),
                local.additional_resource_scopes.clone(),
                local.additional_required_resource_authorities.clone(),
            )
        } else {
            (None, BTreeSet::new(), BTreeSet::new(), BTreeSet::new())
        };
        if union_len(
            &self.base_policy.required_grants,
            &additional_required_grants,
        ) > MAX_POLICY_ENTRIES
            || union_len(
                &self.base_policy.resource_scopes,
                &additional_resource_scopes,
            ) > MAX_POLICY_ENTRIES
            || union_len(
                &self.base_policy.required_resource_authorities,
                &additional_required_resource_authorities,
            ) > MAX_POLICY_ENTRIES
        {
            return Err(McpCatalogPolicyError::new(
                McpCatalogPolicyErrorCode::InvalidEffectivePolicy,
                "runtime.discovery.tool_policies",
                "the effective MCP tool policy exceeds its bounded local policy ceiling",
            ));
        }
        Ok(McpEffectiveToolPolicy {
            schema_version: MCP_CATALOG_POLICY_CONTRACT_V1,
            risk,
            trusted_description,
            required_approvals,
            base_policy: Arc::clone(&self.base_policy),
            additional_required_grants,
            additional_resource_scopes,
            additional_required_resource_authorities,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpToolPublicationDecision {
    Denied,
    Publish(McpEffectiveToolPolicy),
}

/// Additive effective policy for one locally eligible remote tool.
/// The skill-wide floor is shared across projected entries so a maximum-size catalog
/// cannot multiply large policy sets once per discovered tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpEffectiveToolPolicy {
    pub schema_version: &'static str,
    risk: McpToolRiskClass,
    trusted_description: Option<String>,
    required_approvals: BTreeSet<ApprovalClass>,
    base_policy: Arc<PolicyFloor>,
    additional_required_grants: BTreeSet<String>,
    additional_resource_scopes: BTreeSet<String>,
    additional_required_resource_authorities: BTreeSet<String>,
}

impl McpEffectiveToolPolicy {
    pub fn risk(&self) -> McpToolRiskClass {
        self.risk
    }

    pub fn trusted_description(&self) -> Option<&str> {
        self.trusted_description.as_deref()
    }

    pub fn required_approvals(&self) -> &BTreeSet<ApprovalClass> {
        &self.required_approvals
    }

    pub fn required_grants(&self) -> impl Iterator<Item = &str> + '_ {
        union_iter(
            &self.base_policy.required_grants,
            &self.additional_required_grants,
        )
    }

    pub fn resource_scopes(&self) -> impl Iterator<Item = &str> + '_ {
        union_iter(
            &self.base_policy.resource_scopes,
            &self.additional_resource_scopes,
        )
    }

    pub fn required_resource_authorities(&self) -> impl Iterator<Item = &str> + '_ {
        union_iter(
            &self.base_policy.required_resource_authorities,
            &self.additional_required_resource_authorities,
        )
    }

    /// Retained string bytes shared by every projected tool from this skill.
    ///
    /// This is an accounting primitive for bounded catalog ownership, not a wire-size
    /// estimate. Callers must charge it once per projected skill catalog rather than once
    /// per tool because the underlying policy floor is held in one shared `Arc`.
    pub fn shared_policy_accounted_bytes(&self) -> usize {
        set_text_bytes(&self.base_policy.required_grants)
            .saturating_add(set_text_bytes(&self.base_policy.resource_scopes))
            .saturating_add(set_text_bytes(
                &self.base_policy.required_resource_authorities,
            ))
    }

    /// Retained locally authored string bytes unique to this effective tool policy.
    /// The trusted description is included here alongside additive policy references.
    pub fn tool_policy_accounted_bytes(&self) -> usize {
        self.trusted_description
            .as_ref()
            .map_or(0, String::len)
            .saturating_add(set_text_bytes(&self.additional_required_grants))
            .saturating_add(set_text_bytes(&self.additional_resource_scopes))
            .saturating_add(set_text_bytes(
                &self.additional_required_resource_authorities,
            ))
    }
}

fn set_text_bytes(values: &BTreeSet<String>) -> usize {
    values
        .iter()
        .fold(0usize, |total, value| total.saturating_add(value.len()))
}

fn union_len(base: &BTreeSet<String>, additions: &BTreeSet<String>) -> usize {
    base.len()
        + additions
            .iter()
            .filter(|value| !base.contains(*value))
            .count()
}

fn union_iter<'a>(
    base: &'a BTreeSet<String>,
    additions: &'a BTreeSet<String>,
) -> impl Iterator<Item = &'a str> + 'a {
    base.iter().map(String::as_str).chain(
        additions
            .iter()
            .filter(|value| !base.contains(*value))
            .map(String::as_str),
    )
}

fn risk_approval(risk: McpToolRiskClass) -> ApprovalClass {
    match risk {
        McpToolRiskClass::ReadOnly => ApprovalClass::Ordinary,
        McpToolRiskClass::Unclassified | McpToolRiskClass::ExternalSideEffect => {
            ApprovalClass::ConditionalExternalSideEffect
        },
        McpToolRiskClass::WorkspaceWrite => ApprovalClass::DelegatedWorkspaceWrite,
        McpToolRiskClass::NativeUiControl => ApprovalClass::NativeUiControl,
        McpToolRiskClass::Commerce => ApprovalClass::CommerceCheckout,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::Arc,
        thread,
    };

    use super::*;
    use crate::{
        manifest::{
            AuthContract, McpDiscoveryPolicy, McpTransport, PolicyFloor, RuntimeLimits,
            RuntimeProtocol, RuntimeRequirements, SkillRuntimeContract,
            SkillRuntimeContractVersion,
        },
        manifest_synthesis::MAX_DISCOVERED_MCP_TOOLS,
        manifest_validation::validate_skill_runtime_contract,
    };

    fn contract(discovery: McpDiscoveryPolicy) -> SkillRuntimeContract {
        SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires: RuntimeRequirements::default(),
            runtime: RuntimeProtocol::Mcp {
                transport: McpTransport::StreamableHttp {
                    endpoint: "https://endpoint-canary.example/mcp".to_owned(),
                },
                discovery,
                limits: RuntimeLimits::default(),
            },
            auth: AuthContract::default(),
            policy_floor: PolicyFloor {
                approval: ApprovalClass::Ordinary,
                required_grants: BTreeSet::from(["base-grant".to_owned()]),
                resource_scopes: BTreeSet::from(["base-scope".to_owned()]),
                required_resource_authorities: BTreeSet::from(["base-authority".to_owned()]),
            },
        }
    }

    fn compile(discovery: McpDiscoveryPolicy) -> McpCatalogPolicyContract {
        let source = contract(discovery);
        let validated = validate_skill_runtime_contract(&source).expect("valid MCP contract");
        McpCatalogPolicyContract::compile("provider", validated).expect("compiled policy")
    }

    #[test]
    fn exact_local_policy_is_additive_and_deny_wins() {
        let mut tool_policies = BTreeMap::new();
        tool_policies.insert(
            "read".to_owned(),
            McpToolPolicy {
                risk: McpToolRiskClass::ReadOnly,
                trusted_description: Some("Read trusted provider records.".to_owned()),
                additional_required_resource_authorities: BTreeSet::from([
                    "records-read".to_owned()
                ]),
                ..McpToolPolicy::default()
            },
        );
        tool_policies.insert(
            "write".to_owned(),
            McpToolPolicy {
                risk: McpToolRiskClass::WorkspaceWrite,
                additional_required_grants: BTreeSet::from(["write-grant".to_owned()]),
                ..McpToolPolicy::default()
            },
        );
        let policy = compile(McpDiscoveryPolicy {
            namespace: Some("mail".to_owned()),
            allow_tools: BTreeSet::from([
                "read".to_owned(),
                "write".to_owned(),
                "hidden".to_owned(),
            ]),
            deny_tools: BTreeSet::from(["hidden".to_owned()]),
            tool_policies,
            ..McpDiscoveryPolicy::default()
        });

        assert_eq!(policy.local_namespace(), "provider.mail");
        let McpToolPublicationDecision::Publish(read) = policy.decision("read").unwrap() else {
            panic!("read must publish");
        };
        assert_eq!(read.risk(), McpToolRiskClass::ReadOnly);
        assert_eq!(
            read.required_approvals(),
            &BTreeSet::from([ApprovalClass::Ordinary])
        );
        assert_eq!(
            read.required_grants().collect::<BTreeSet<_>>(),
            BTreeSet::from(["base-grant"])
        );
        assert_eq!(
            read.required_resource_authorities()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["base-authority", "records-read"])
        );
        assert_eq!(
            read.trusted_description(),
            Some("Read trusted provider records.")
        );

        let McpToolPublicationDecision::Publish(write) = policy.decision("write").unwrap() else {
            panic!("write must publish");
        };
        assert!(write
            .required_approvals()
            .contains(&ApprovalClass::DelegatedWorkspaceWrite));
        assert!(write.required_grants().any(|grant| grant == "base-grant"));
        assert!(write.required_grants().any(|grant| grant == "write-grant"));
        assert_eq!(
            policy.decision("hidden").unwrap(),
            McpToolPublicationDecision::Denied
        );
        assert_eq!(
            policy.decision("outside-allowlist").unwrap(),
            McpToolPublicationDecision::Denied
        );
    }

    #[test]
    fn unclassified_tools_get_conservative_local_approval() {
        let policy = compile(McpDiscoveryPolicy::default());
        let McpToolPublicationDecision::Publish(effective) =
            policy.decision("server-added-tool").unwrap()
        else {
            panic!("default discovery permits bounded tools");
        };
        assert_eq!(effective.risk(), McpToolRiskClass::Unclassified);
        assert!(effective
            .required_approvals()
            .contains(&ApprovalClass::ConditionalExternalSideEffect));
        assert_eq!(effective.trusted_description(), None);
    }

    #[test]
    fn every_risk_class_preserves_the_floor_and_only_adds_requirements() {
        let expected = [
            (McpToolRiskClass::ReadOnly, ApprovalClass::Ordinary),
            (
                McpToolRiskClass::Unclassified,
                ApprovalClass::ConditionalExternalSideEffect,
            ),
            (
                McpToolRiskClass::ExternalSideEffect,
                ApprovalClass::ConditionalExternalSideEffect,
            ),
            (
                McpToolRiskClass::WorkspaceWrite,
                ApprovalClass::DelegatedWorkspaceWrite,
            ),
            (
                McpToolRiskClass::NativeUiControl,
                ApprovalClass::NativeUiControl,
            ),
            (McpToolRiskClass::Commerce, ApprovalClass::CommerceCheckout),
        ];
        for (index, (risk, risk_approval)) in expected.into_iter().enumerate() {
            let name = format!("tool-{index}");
            let mut discovery = McpDiscoveryPolicy::default();
            discovery.tool_policies.insert(
                name.clone(),
                McpToolPolicy {
                    risk,
                    additional_approvals: BTreeSet::from([ApprovalClass::NativeUiControl]),
                    additional_required_grants: BTreeSet::from(["tool-grant".to_owned()]),
                    additional_resource_scopes: BTreeSet::from(["tool-scope".to_owned()]),
                    additional_required_resource_authorities: BTreeSet::from([
                        "tool-authority".to_owned()
                    ]),
                    ..McpToolPolicy::default()
                },
            );
            let policy = compile(discovery);
            let McpToolPublicationDecision::Publish(effective) =
                policy.decision(&name).expect("bounded policy")
            else {
                panic!("exact local policy must publish")
            };

            assert!(effective
                .required_approvals()
                .contains(&ApprovalClass::Ordinary));
            assert!(effective.required_approvals().contains(&risk_approval));
            assert!(effective
                .required_approvals()
                .contains(&ApprovalClass::NativeUiControl));
            assert_eq!(
                effective.required_grants().collect::<BTreeSet<_>>(),
                BTreeSet::from(["base-grant", "tool-grant"])
            );
            assert_eq!(
                effective.resource_scopes().collect::<BTreeSet<_>>(),
                BTreeSet::from(["base-scope", "tool-scope"])
            );
            assert_eq!(
                effective
                    .required_resource_authorities()
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from(["base-authority", "tool-authority"])
            );
        }
    }

    #[test]
    fn policy_accounting_charges_shared_and_per_tool_strings_separately() {
        let mut discovery = McpDiscoveryPolicy::default();
        discovery.tool_policies.insert(
            "read".to_owned(),
            McpToolPolicy {
                trusted_description: Some("trusted".to_owned()),
                additional_required_grants: BTreeSet::from(["tool-grant".to_owned()]),
                additional_resource_scopes: BTreeSet::from(["tool-scope".to_owned()]),
                additional_required_resource_authorities: BTreeSet::from([
                    "tool-authority".to_owned()
                ]),
                ..McpToolPolicy::default()
            },
        );
        let policy = compile(discovery);
        let McpToolPublicationDecision::Publish(effective) = policy.decision("read").unwrap()
        else {
            panic!("read must publish")
        };
        assert_eq!(
            effective.shared_policy_accounted_bytes(),
            "base-grant".len() + "base-scope".len() + "base-authority".len()
        );
        assert_eq!(
            effective.tool_policy_accounted_bytes(),
            "trusted".len() + "tool-grant".len() + "tool-scope".len() + "tool-authority".len()
        );
    }

    #[test]
    fn compiled_policy_omits_transport_endpoint_and_remote_metadata() {
        let policy = compile(McpDiscoveryPolicy::default());
        let encoded = format!("{policy:?}");
        assert!(!encoded.contains("endpoint-canary"));
        assert!(!encoded.contains("remote-description-canary"));
        assert!(!encoded.contains("oauth"));
    }

    #[test]
    fn local_names_are_exact_portable_and_bounded_without_slug_aliases() {
        let policy = compile(McpDiscoveryPolicy::default());
        assert_eq!(
            policy.local_tool_name("mail/read").unwrap(),
            "provider.mail/read"
        );
        assert_eq!(
            policy.local_tool_name("mail:read").unwrap(),
            "provider.mail:read"
        );
        assert_ne!(
            policy.local_tool_name("mail/read").unwrap(),
            policy.local_tool_name("mail:read").unwrap()
        );
        assert_eq!(
            policy.local_tool_name("not portable").unwrap_err().code,
            McpCatalogPolicyErrorCode::InvalidRemoteToolName
        );

        let oversized_policy = compile(McpDiscoveryPolicy {
            namespace: Some("n".repeat(256)),
            ..McpDiscoveryPolicy::default()
        });
        assert_eq!(
            oversized_policy
                .local_tool_name(&"r".repeat(256))
                .unwrap_err()
                .code,
            McpCatalogPolicyErrorCode::LocalToolNameTooLong
        );
    }

    #[test]
    fn maximum_catalog_shares_the_base_policy_on_a_small_stack() {
        thread::Builder::new()
            .stack_size(96 * 1024)
            .spawn(|| {
                let mut source = contract(McpDiscoveryPolicy::default());
                source.policy_floor.required_grants = (0..MAX_POLICY_ENTRIES)
                    .map(|index| format!("base-grant-{index}"))
                    .collect();
                let validated = validate_skill_runtime_contract(&source).expect("valid contract");
                let policy =
                    McpCatalogPolicyContract::compile("provider", validated).expect("policy");
                let projected = (0..MAX_DISCOVERED_MCP_TOOLS)
                    .map(|index| {
                        let McpToolPublicationDecision::Publish(effective) = policy
                            .decision(&format!("remote-tool-{index}"))
                            .expect("bounded policy")
                        else {
                            panic!("default discovery permits the bounded catalog")
                        };
                        effective
                    })
                    .collect::<Vec<_>>();

                assert_eq!(projected.len(), MAX_DISCOVERED_MCP_TOOLS);
                assert!(projected
                    .windows(2)
                    .all(|pair| Arc::ptr_eq(&pair[0].base_policy, &pair[1].base_policy)));
                assert_eq!(projected[0].required_grants().count(), MAX_POLICY_ENTRIES);
            })
            .expect("bounded-stack worker")
            .join()
            .expect("bounded-stack projection");
    }
}
