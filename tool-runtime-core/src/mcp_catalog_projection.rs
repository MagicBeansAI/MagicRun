//! Provider-neutral product projection for governed MCP runtime packages.
//!
//! The official SDK discovers remote tools at runtime, but the product exposes
//! one small, stable control surface for every MCP skill. Keeping that surface
//! here gives catalog registration, source inventory, and replay fixtures one
//! authoritative projection instead of three hand-maintained copies.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use crate::{
    manifest::{ProfileSelection, RuntimeProtocol},
    manifest_parser::SkillRuntimePackage,
};

pub const OFFICIAL_MCP_SDK_IMPLEMENTATION: &str = "official_mcp_sdk";
pub const DEFAULT_MCP_ACTION_TIMEOUT_SECS: u64 = 90;

#[derive(Debug, Clone, PartialEq)]
pub struct McpCatalogProjection {
    pub timeout_secs: u64,
    pub actions: BTreeMap<String, McpCatalogActionProjection>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct McpCatalogActionProjection {
    pub description: String,
    pub parameters: Vec<McpCatalogParameterProjection>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct McpCatalogParameterProjection {
    pub name: String,
    pub required: bool,
    pub schema: Value,
}

/// Project the five stable product actions shared by every official-SDK MCP
/// package. Remote tool identities and schemas remain live discovery data and
/// never become authored Rust branches.
pub fn project_mcp_catalog(package: &SkillRuntimePackage) -> Result<McpCatalogProjection, String> {
    let RuntimeProtocol::Mcp {
        discovery, limits, ..
    } = &package.contract.runtime
    else {
        return Err("MCP catalog projection received a non-MCP runtime".to_owned());
    };
    if package.actions.is_some() {
        return Err(
            "MCP runtime packages must use SDK discovery, not authored CLI actions".to_owned(),
        );
    }

    let timeout_secs = limits
        .timeout_secs
        .map(u64::from)
        .unwrap_or(DEFAULT_MCP_ACTION_TIMEOUT_SECS);
    let mut common = Vec::new();
    let mut names = BTreeSet::new();

    if !discovery.endpoint_aliases.is_empty() {
        let name = package
            .catalog
            .mcp_endpoint_parameter
            .as_deref()
            .unwrap_or("endpoint_alias")
            .to_owned();
        insert_unique_parameter_name(&mut names, &name)?;
        let mut schema = json!({
            "type": "string",
            "description": "Reviewed local MCP endpoint alias; arbitrary URLs are not accepted.",
            "enum": discovery.endpoint_aliases.keys().cloned().collect::<Vec<_>>()
        });
        let required = discovery.default_endpoint_alias.is_none();
        if let Some(default) = discovery.default_endpoint_alias.as_ref() {
            schema
                .as_object_mut()
                .ok_or_else(|| "MCP endpoint schema construction failed".to_owned())?
                .insert("default".to_owned(), Value::String(default.clone()));
        }
        common.push(McpCatalogParameterProjection {
            name,
            required,
            schema,
        });
    }

    if let Some(profile) = package.projected_profile_parameter() {
        let name = profile.name.to_owned();
        insert_unique_parameter_name(&mut names, &name)?;
        let mut schema = json!({
            "type": "string",
            "description": "Configured local credential profile alias.",
            "pattern": "^[A-Za-z0-9._-]+$",
            "minLength": 1,
            "maxLength": 128
        });
        let schema_object = schema
            .as_object_mut()
            .ok_or_else(|| "MCP profile schema construction failed".to_owned())?;
        if let Some(values) = profile.enum_values.filter(|values| !values.is_empty()) {
            schema_object.insert(
                "enum".to_owned(),
                json!(values.iter().cloned().collect::<Vec<_>>()),
            );
        }
        let default = match &package.contract.auth.profile_selection {
            ProfileSelection::Selectable { default } => default.as_ref(),
            ProfileSelection::None
            | ProfileSelection::Fixed { .. }
            | ProfileSelection::Implicit => None,
        };
        let required = default.is_none();
        if let Some(default) = default {
            schema_object.insert("default".to_owned(), Value::String(default.clone()));
        }
        common.push(McpCatalogParameterProjection {
            name,
            required,
            schema,
        });
    }

    let mut actions = BTreeMap::new();
    insert_action(
        &mut actions,
        "status",
        "Inspect the exact scoped MCP OAuth binding without exposing credential material.",
        &common,
        Vec::new(),
    )?;
    insert_action(
        &mut actions,
        "auth_start",
        "Begin official-SDK browser OAuth for the exact scoped MCP binding.",
        &common,
        Vec::new(),
    )?;
    insert_action(
        &mut actions,
        "list_tools",
        "Discover and return the live MCP tool catalog after applying trusted local policy.",
        &common,
        Vec::new(),
    )?;
    insert_action(
        &mut actions,
        "clear_auth",
        "Remove local credentials for the exact scoped MCP binding.",
        &common,
        Vec::new(),
    )?;

    let mut call_parameters = vec![
        McpCatalogParameterProjection {
            name: "tool_name".to_owned(),
            required: true,
            schema: json!({
                "type": "string",
                "description": "Exact discovered local or remote MCP tool name.",
                "minLength": 1,
                "maxLength": 1024
            }),
        },
        McpCatalogParameterProjection {
            name: "arguments_json".to_owned(),
            required: false,
            schema: json!({
                "type": "string",
                "description": "Bounded JSON object sent to the exact discovered MCP tool; the remote server remains authoritative for its input schema.",
                "default": "{}",
                "maxLength": 16777216
            }),
        },
        McpCatalogParameterProjection {
            name: "risk".to_owned(),
            required: false,
            schema: json!({
                "type": "string",
                "description": "Caller summary retained only for conservative cross-checking; local policy remains authoritative.",
                "enum": ["read", "cart_mutation", "checkout_or_payment"],
                "default": "read"
            }),
        },
        McpCatalogParameterProjection {
            name: "intent_summary".to_owned(),
            required: false,
            schema: json!({
                "type": "string",
                "description": "Concise audit summary for a requested side effect.",
                "default": "",
                "maxLength": 4096
            }),
        },
    ];
    if let Some(commerce) = discovery.commerce.as_ref() {
        call_parameters.push(McpCatalogParameterProjection {
            name: commerce.amount_parameter.clone(),
            required: false,
            schema: json!({
                "type": "number",
                "description": "Reviewed order amount in major currency units; required for checkout-like calls.",
                "minimum": 0,
                "default": 0
            }),
        });
    }
    insert_action(
        &mut actions,
        "call_tool",
        "Call one exact tool from the current official-SDK discovery snapshot. Local policy, approval, and resource authority remain authoritative.",
        &common,
        call_parameters,
    )?;

    Ok(McpCatalogProjection {
        timeout_secs,
        actions,
    })
}

fn insert_action(
    actions: &mut BTreeMap<String, McpCatalogActionProjection>,
    name: &str,
    description: &str,
    common: &[McpCatalogParameterProjection],
    action_parameters: Vec<McpCatalogParameterProjection>,
) -> Result<(), String> {
    let mut names = BTreeSet::new();
    let mut parameters = Vec::with_capacity(common.len().saturating_add(action_parameters.len()));
    for parameter in common.iter().cloned().chain(action_parameters) {
        insert_unique_parameter_name(&mut names, &parameter.name)?;
        parameters.push(parameter);
    }
    if actions
        .insert(
            name.to_owned(),
            McpCatalogActionProjection {
                description: description.to_owned(),
                parameters,
            },
        )
        .is_some()
    {
        return Err("MCP product action is defined more than once".to_owned());
    }
    Ok(())
}

fn insert_unique_parameter_name(names: &mut BTreeSet<String>, name: &str) -> Result<(), String> {
    if !names.insert(name.to_owned()) {
        return Err("MCP catalog parameter aliases collide".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        manifest::{
            ApprovalClass, AuthContract, AuthRequirement, AuthStorage, McpDiscoveryPolicy,
            McpTransport, PolicyFloor, ProfileSelection, RuntimeLimits, SkillRuntimeContract,
            SkillRuntimeContractVersion,
        },
        manifest_parser::{SkillRuntimeCatalogMetadata, SkillRuntimePackage},
    };

    fn package() -> SkillRuntimePackage {
        SkillRuntimePackage {
            contract: SkillRuntimeContract {
                schema_version: SkillRuntimeContractVersion::v1(),
                requires: Default::default(),
                runtime: RuntimeProtocol::Mcp {
                    transport: McpTransport::StreamableHttp {
                        endpoint: "https://provider.example/mcp".to_owned(),
                    },
                    discovery: McpDiscoveryPolicy::default(),
                    limits: RuntimeLimits::default(),
                },
                auth: AuthContract {
                    kind: crate::manifest::AuthKind::OAuthSession,
                    requirement: AuthRequirement::Required,
                    provider: Some("provider".to_owned()),
                    storage: AuthStorage::None,
                    profile_selection: ProfileSelection::Selectable {
                        default: Some("personal".to_owned()),
                    },
                    ..AuthContract::default()
                },
                policy_floor: PolicyFloor {
                    approval: ApprovalClass::Ordinary,
                    ..PolicyFloor::default()
                },
            },
            catalog: SkillRuntimeCatalogMetadata::default(),
            actions: None,
        }
    }

    #[test]
    fn projection_exposes_only_the_stable_sdk_control_surface() {
        let projected = project_mcp_catalog(&package()).expect("project MCP catalog");
        assert_eq!(
            projected
                .actions
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec![
                "auth_start",
                "call_tool",
                "clear_auth",
                "list_tools",
                "status"
            ]
        );
        assert!(projected.actions["call_tool"]
            .parameters
            .iter()
            .any(|parameter| parameter.name == "tool_name" && parameter.required));
    }

    #[test]
    fn projection_rejects_profile_and_action_parameter_alias_collisions() {
        let mut package = package();
        package.catalog.profile_parameter = Some(
            crate::manifest_parser::SkillRuntimeProfileParameterMetadata {
                name: "tool_name".to_owned(),
                enum_values: Default::default(),
            },
        );
        assert!(project_mcp_catalog(&package).is_err());
    }
}
