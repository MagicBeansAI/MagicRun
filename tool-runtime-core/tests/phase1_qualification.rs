//! Phase 1F compatibility and adversarial qualification.
//!
//! Every fixture in this module is inert test data. The exercised Phase 1 API
//! accepts strings and typed values and returns normalized values; it has no
//! filesystem, environment, credential, process, transport, publication, or
//! production-routing handle.

use std::{
    collections::{BTreeMap, BTreeSet},
    thread,
};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tool_runtime_core::{
    action_overrides::{
        compile_typed_action_overrides, ActionPolicyRefinement, CompiledActionCatalog,
        TypedActionOverride, TypedActionOverrideSet, TypedActionParameter, TypedArgumentMapping,
        TYPED_ACTION_OVERRIDES_V1,
    },
    manifest::{
        ApprovalClass, AuthContract, AuthKind, AuthRequirement, AuthStorage, CliInteraction,
        IdentityContract, IdentitySelector, InjectionBinding, InjectionSource, InjectionTarget,
        LifecycleHook, LifecycleJsonPredicate, LifecycleJsonScalar, LifecycleObservedAuthState,
        LifecycleStatusObservation, LifecycleStatusOutputFormat, LifecycleStatusRule,
        McpDiscoveryPolicy, McpTransport, PolicyFloor, ProfileSelection, RuntimeLimits,
        RuntimeProtocol, RuntimeRequirements, SecretBindingRef, SkillRuntimeContract,
        SkillRuntimeContractVersion, StdinContract, StdinMode, WorkingDirectoryContract,
    },
    manifest_parser::{
        parse_skill_runtime_contract, ManifestParseErrorCode, MAX_SKILL_MARKDOWN_BYTES,
    },
    manifest_synthesis::{
        synthesize_runtime_catalog, SynthesizedRuntime, SynthesizedRuntimeCatalog,
        SYNTHESIZED_RUNTIME_CATALOG_V1,
    },
    manifest_validation::validate_skill_runtime_contract,
    replay::{ReplayArgMapping, ReplayFixture, ReplayValueKind, TimeoutSource},
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

fn required_auth(kind: AuthKind) -> AuthContract {
    AuthContract {
        kind,
        requirement: AuthRequirement::Required,
        ..AuthContract::default()
    }
}

fn skill_source(contract: &SkillRuntimeContract, body: &str) -> String {
    let yaml = serde_yaml::to_string(contract).expect("serialize test-only contract");
    let indented = yaml
        .lines()
        .map(|line| format!("      {line}\n"))
        .collect::<String>();
    format!(
        "---\nname: qualification-fixture\nmetadata:\n  magician:\n    runtime_contract:\n{indented}---\n{body}\n"
    )
}

fn raw_skill_source(contract: &str, body: &str) -> String {
    let indented = contract
        .lines()
        .map(|line| format!("      {line}\n"))
        .collect::<String>();
    format!(
        "---\nname: qualification-fixture\nmetadata:\n  magician:\n    runtime_contract:\n{indented}---\n{body}\n"
    )
}

fn compile_default(skill_id: &str, source: &str) -> SynthesizedRuntimeCatalog {
    let contract = parse_skill_runtime_contract(source)
        .expect("parse qualification fixture")
        .expect("runtime contract present");
    let validated = validate_skill_runtime_contract(&contract).expect("validate fixture");
    synthesize_runtime_catalog(skill_id, validated).expect("synthesize fixture")
}

fn string_parameter(description: &str, required: bool) -> TypedActionParameter {
    TypedActionParameter::String {
        description: description.to_owned(),
        required,
        default: None,
        enum_values: BTreeSet::new(),
        min_length: None,
        max_length: Some(4 * 1024),
    }
}

fn representative_contracts() -> Vec<(&'static str, SkillRuntimeContract)> {
    let none = cli_contract("jq");

    let mut secrets = cli_contract("provider-cli");
    secrets.auth = required_auth(AuthKind::Secrets);
    secrets.auth.secret_bindings.push(SecretBindingRef {
        name: "provider_api_key".to_owned(),
        secret_ref: "PROVIDER_API_KEY".to_owned(),
    });
    secrets.auth.injections.push(InjectionBinding {
        source: InjectionSource::Secret {
            binding: "provider_api_key".to_owned(),
        },
        target: InjectionTarget::Environment {
            name: "PROVIDER_API_KEY".to_owned(),
        },
    });

    let mut cli_profile = cli_contract("gws");
    cli_profile.auth = required_auth(AuthKind::CliProfile);
    cli_profile.auth.provider = Some("google-workspace".to_owned());
    cli_profile.auth.profile_selection = ProfileSelection::Selectable {
        default: Some("work".to_owned()),
    };
    cli_profile.auth.storage = AuthStorage::ScopedDirectory {
        namespace: "gws".to_owned(),
        partition_by_profile: true,
    };
    cli_profile.auth.lifecycle.status = Some(LifecycleHook {
        args: vec!["auth".to_owned(), "status".to_owned(), "--json".to_owned()],
        interaction: CliInteraction::Batch,
        timeout_secs: Some(30),
    });
    cli_profile.auth.lifecycle.status_observation = Some(LifecycleStatusObservation {
        format: LifecycleStatusOutputFormat::Json,
        rules: vec![LifecycleStatusRule {
            state: LifecycleObservedAuthState::Ready,
            exit_codes: BTreeSet::from([0]),
            all: vec![LifecycleJsonPredicate::Equals {
                pointer: "/ready".to_owned(),
                value: LifecycleJsonScalar::Boolean { value: true },
            }],
        }],
    });
    cli_profile.auth.identity = IdentityContract::ProfileExpected {
        selector: IdentitySelector::JsonPointer {
            pointer: "/account/email".to_owned(),
        },
    };
    cli_profile.auth.injections.push(InjectionBinding {
        source: InjectionSource::ProfileAuthRoot {
            path: vec!["cloudsdk".to_owned()],
        },
        target: InjectionTarget::Environment {
            name: "CLOUDSDK_CONFIG".to_owned(),
        },
    });

    let mut oauth = cli_contract("unused");
    oauth.requires.bins.clear();
    oauth.runtime = RuntimeProtocol::Mcp {
        transport: McpTransport::StreamableHttp {
            endpoint: "https://provider.example/mcp".to_owned(),
        },
        discovery: McpDiscoveryPolicy {
            oauth: Some(tool_runtime_core::manifest::McpOAuthConnectionPolicy {
                authorization_issuer: "https://issuer.example".to_owned(),
                scopes: BTreeSet::new(),
            }),
            ..McpDiscoveryPolicy::default()
        },
        limits: RuntimeLimits::default(),
    };
    oauth.auth = required_auth(AuthKind::OAuthSession);
    oauth.auth.provider = Some("provider-mcp".to_owned());
    oauth.auth.profile_selection = ProfileSelection::Selectable {
        default: Some("personal".to_owned()),
    };

    let mut browser = cli_contract("agent-browser");
    browser.auth = required_auth(AuthKind::BrowserProfile);
    browser.auth.provider = Some("browser-controller".to_owned());
    browser.auth.profile_selection = ProfileSelection::Implicit;
    browser.auth.storage = AuthStorage::BrowserProfile;

    let mut native = cli_contract("screencapture");
    native.auth = required_auth(AuthKind::NativePermission);
    native.auth.provider = Some("macos".to_owned());
    native.auth.storage = AuthStorage::OperatingSystem;

    let mut delegated = cli_contract("provider-cli");
    delegated.auth = required_auth(AuthKind::DelegatedCredential);
    delegated.auth.provider = Some("provider".to_owned());
    delegated.auth.storage = AuthStorage::EphemeralGrant;

    vec![
        ("none", none),
        ("secrets", secrets),
        ("cli-profile", cli_profile),
        ("oauth", oauth),
        ("browser", browser),
        ("native", native),
        ("delegated", delegated),
    ]
}

#[test]
fn golden_contracts_cross_parser_validation_and_synthesis_for_every_auth_kind() {
    let mut observed = Vec::new();
    let mut golden = Sha256::new();
    for (skill_id, authored) in representative_contracts() {
        let source = skill_source(&authored, "# inert qualification prose");
        let parsed = parse_skill_runtime_contract(&source)
            .expect("parse golden contract")
            .expect("golden contract present");
        assert_eq!(parsed, authored);
        if !observed.contains(&parsed.auth.kind) {
            observed.push(parsed.auth.kind);
        }

        let validated = validate_skill_runtime_contract(&parsed).expect("validate golden contract");
        let catalog = synthesize_runtime_catalog(skill_id, validated).expect("compile golden");
        assert_eq!(catalog.schema_version, SYNTHESIZED_RUNTIME_CATALOG_V1);
        assert_eq!(catalog.security_floor.auth_kind, parsed.auth.kind);
        assert_eq!(
            catalog.security_floor.auth_requirement,
            parsed.auth.requirement
        );
        assert_eq!(catalog.security_floor.provider, parsed.auth.provider);
        assert_eq!(
            catalog.security_floor.profile_selection,
            parsed.auth.profile_selection
        );
        let encoded = serde_json::to_vec(&catalog).expect("serialize golden catalog");
        golden.update((encoded.len() as u64).to_be_bytes());
        golden.update(encoded);
    }

    assert_eq!(observed.len(), 7);
    for expected in [
        AuthKind::None,
        AuthKind::Secrets,
        AuthKind::CliProfile,
        AuthKind::OAuthSession,
        AuthKind::BrowserProfile,
        AuthKind::NativePermission,
        AuthKind::DelegatedCredential,
    ] {
        assert!(observed.contains(&expected), "missing {expected:?}");
    }
    assert_eq!(
        format!("{:x}", golden.finalize()),
        "cf98952179a62dddff952915482ec31e7eba7c994bff6d6241e1af8c9a074712"
    );
}

#[test]
fn cli_property_matrix_preserves_runtime_controls_through_the_full_chain() {
    for interaction in [CliInteraction::Batch, CliInteraction::Pty] {
        for stdin_mode in [StdinMode::Denied, StdinMode::Optional, StdinMode::Required] {
            for timeout in [None, Some(1), Some(86_400)] {
                let mut contract = cli_contract("matrix-cli");
                let RuntimeProtocol::Cli {
                    interaction: authored_interaction,
                    stdin,
                    limits,
                    ..
                } = &mut contract.runtime
                else {
                    unreachable!();
                };
                *authored_interaction = interaction;
                stdin.mode = stdin_mode;
                limits.timeout_secs = timeout;

                let source = skill_source(&contract, "matrix body");
                let catalog = compile_default("matrix", &source);
                let SynthesizedRuntime::Cli { action, execution } = catalog.runtime else {
                    panic!("matrix CLI must synthesize a CLI action");
                };
                assert_eq!(execution.interaction, interaction);
                assert_eq!(execution.stdin_mode, stdin_mode);
                assert_eq!(execution.limits.timeout_secs, timeout);
                assert_eq!(
                    action.input_schema.properties.contains_key("stdin"),
                    stdin_mode != StdinMode::Denied
                );
                assert_eq!(
                    action.input_schema.required.contains(&"stdin".to_owned()),
                    stdin_mode == StdinMode::Required
                );
            }
        }
    }
}

#[test]
fn both_mcp_transport_goldens_remain_discovery_only_and_bounded() {
    let stdio = raw_skill_source(
        "schema_version: tool-runtime.skill-runtime.v1\nrequires:\n  bins: [provider-mcp]\nruntime:\n  protocol: mcp\n  transport:\n    kind: stdio\n    executable: provider-mcp\n    args: [serve, --stdio]\n  discovery:\n    namespace: mail\n    allow_tools: [mail/read, mail/search]\n    deny_tools: [mail/search]\n",
        "stdio body",
    );
    let remote = raw_skill_source(
        "schema_version: tool-runtime.skill-runtime.v1\nruntime:\n  protocol: mcp\n  transport:\n    kind: streamable_http\n    endpoint: https://provider.example/mcp\n  discovery:\n    namespace: remote\n  limits:\n    timeout_secs: 20\n",
        "remote body",
    );

    for (source, namespace, max_tools) in [
        (&stdio, "provider.mail", 1usize),
        (&remote, "provider.remote", 512usize),
    ] {
        let catalog = compile_default("provider", source);
        let SynthesizedRuntime::Mcp { discovery } = catalog.runtime else {
            panic!("MCP golden must remain a discovery seed");
        };
        assert_eq!(discovery.local_namespace, namespace);
        assert_eq!(discovery.catalog_limits.max_tools, max_tools);
        assert_eq!(discovery.naming_strategy, "skill_namespace_dot_v1");
    }
}

#[test]
fn malformed_unknown_forward_and_unsafe_inputs_have_stable_compatibility_codes() {
    let malformed = "---\nmetadata: {broken\n---\n".to_owned();
    let unknown = raw_skill_source(
        "schema_version: tool-runtime.skill-runtime.v1\nruntime:\n  protocol: cli\nunknown_security_switch: true\n",
        "body",
    );
    let forward = raw_skill_source(
        "schema_version: tool-runtime.skill-runtime.v2\nfuture_security_switch: true\n",
        "body",
    );
    let alias = "---\nbase: &base {x: 1}\ncopy: *base\n---\n".to_owned();

    for (source, expected) in [
        (malformed, ManifestParseErrorCode::InvalidYaml),
        (unknown, ManifestParseErrorCode::InvalidRuntimeContract),
        (forward, ManifestParseErrorCode::UnsupportedSchemaVersion),
        (alias, ManifestParseErrorCode::YamlReferencesUnsupported),
    ] {
        let error = parse_skill_runtime_contract(&source).expect_err("fixture must fail closed");
        assert_eq!(error.code, expected);
    }

    let oversized = "x".repeat(MAX_SKILL_MARKDOWN_BYTES + 1);
    assert_eq!(
        parse_skill_runtime_contract(&oversized)
            .expect_err("oversized source")
            .code,
        ManifestParseErrorCode::SourceTooLarge
    );
}

#[test]
fn key_order_set_order_and_irrelevant_prose_cannot_change_catalog_bytes() {
    let first = raw_skill_source(
        "schema_version: tool-runtime.skill-runtime.v1\nrequires:\n  bins: [jq]\nruntime:\n  protocol: cli\n  command_prefix: [fixed]\npolicy_floor:\n  required_grants: [write, read]\n  resource_scopes: [z, a]\n",
        "# first prose",
    );
    let second = raw_skill_source(
        "policy_floor:\n  resource_scopes: [a, z]\n  required_grants: [read, write]\nruntime:\n  command_prefix: [fixed]\n  protocol: cli\nrequires:\n  bins: [jq]\nschema_version: tool-runtime.skill-runtime.v1\n",
        "Completely different prose with `examples` and YAML-looking: text.",
    );

    let first = compile_default("jq", &first);
    let second = compile_default("jq", &second);
    assert_eq!(first, second);
    assert_eq!(
        serde_json::to_vec(&first).expect("serialize first catalog"),
        serde_json::to_vec(&second).expect("serialize second catalog")
    );
}

#[test]
fn hostile_depth_is_rejected_and_the_full_chain_is_safe_on_a_small_stack() {
    let hostile = format!("---\n{}value\n---\n", "- ".repeat(65));
    let valid = skill_source(&cli_contract("jq"), "small-stack body");
    let result = thread::Builder::new()
        .name("phase1-qualification-small-stack".to_owned())
        .stack_size(128 * 1024)
        .spawn(move || {
            let hostile_code = parse_skill_runtime_contract(&hostile)
                .expect_err("hostile depth")
                .code;
            let catalog = compile_default("jq", &valid);
            (
                hostile_code,
                serde_json::to_vec(&catalog).expect("serialize"),
            )
        })
        .expect("spawn qualification thread")
        .join()
        .expect("qualification must not panic or overflow");

    assert_eq!(result.0, ManifestParseErrorCode::UnsafeYamlShape);
    assert!(!result.1.is_empty());
}

fn native_call_contract() -> SkillRuntimeContract {
    let mut contract = cli_contract("python3");
    let RuntimeProtocol::Cli {
        command_prefix,
        stdin,
        limits,
        ..
    } = &mut contract.runtime
    else {
        unreachable!();
    };
    command_prefix.push("{skill_runtime_root}/scripts/cua_call.py".to_owned());
    stdin.mode = StdinMode::Optional;
    limits.timeout_secs = Some(30);
    contract.auth = required_auth(AuthKind::NativePermission);
    contract.auth.provider = Some("macos".to_owned());
    contract.auth.storage = AuthStorage::OperatingSystem;
    contract.policy_floor.approval = ApprovalClass::NativeUiControl;
    contract
}

fn native_call_overrides() -> TypedActionOverrideSet {
    let parameters = BTreeMap::from([
        (
            "action_name".to_owned(),
            string_parameter("Native action name.", true),
        ),
        (
            "args_json".to_owned(),
            string_parameter("Serialized native arguments.", false),
        ),
        (
            "screenshot_out_file".to_owned(),
            string_parameter("Authorized screenshot output path.", false),
        ),
    ]);
    TypedActionOverrideSet {
        schema_version: TYPED_ACTION_OVERRIDES_V1.to_owned(),
        input_delivery: tool_runtime_core::action_overrides::TypedActionInputDelivery::Argv,
        actions: BTreeMap::from([(
            "call".to_owned(),
            TypedActionOverride {
                description: "Call one governed native action.".to_owned(),
                executable: None,
                route: tool_runtime_core::action_overrides::TypedActionRoute::Execute,
                fixed_args: Vec::new(),
                suffix_args: Vec::new(),
                stdin: tool_runtime_core::action_overrides::TypedActionStdin::Inherit,
                parameters,
                mappings: vec![
                    TypedArgumentMapping::Positional {
                        parameter: "action_name".to_owned(),
                    },
                    TypedArgumentMapping::Positional {
                        parameter: "args_json".to_owned(),
                    },
                    TypedArgumentMapping::Flag {
                        flag: "--screenshot-out-file".to_owned(),
                        parameter: "screenshot_out_file".to_owned(),
                        omit_if_empty: true,
                    },
                ],
                argument_rules: Default::default(),
                timeout_secs: None,
                policy: ActionPolicyRefinement::default(),
            },
        )]),
    }
}

fn compile_native_call() -> CompiledActionCatalog {
    let source = skill_source(&native_call_contract(), "Phase 0 comparison body");
    let contract = parse_skill_runtime_contract(&source)
        .expect("parse native fixture")
        .expect("native contract");
    let validated = validate_skill_runtime_contract(&contract).expect("validate native fixture");
    compile_typed_action_overrides("macos-ui-automation", validated, &native_call_overrides())
        .expect("compile native action")
}

fn normalized_replay_mapping(mapping: &ReplayArgMapping) -> Value {
    match mapping {
        ReplayArgMapping::Positional { param } => json!(["positional", param, null]),
        ReplayArgMapping::Flag { flag, param } => json!(["flag", param, flag]),
        ReplayArgMapping::BoolFlag { flag, param } => json!(["bool_flag", param, flag]),
        ReplayArgMapping::Passthrough { param } => json!(["passthrough", param, null]),
        other => panic!("unsupported comparison mapping: {other:?}"),
    }
}

fn normalized_typed_mapping(mapping: &TypedArgumentMapping) -> Value {
    match mapping {
        TypedArgumentMapping::Positional { parameter } => {
            json!(["positional", parameter, null])
        },
        TypedArgumentMapping::Flag {
            flag, parameter, ..
        } => json!(["flag", parameter, flag]),
        TypedArgumentMapping::BoolFlag { flag, parameter } => {
            json!(["bool_flag", parameter, flag])
        },
        TypedArgumentMapping::Passthrough { parameter } => {
            json!(["passthrough", parameter, null])
        },
        other => panic!("unexpected comparison mapping: {other:?}"),
    }
}

#[test]
fn phase0_normalized_invocation_matches_the_phase1_compiler() {
    let replay: ReplayFixture =
        serde_json::from_str(include_str!("fixtures/phase1/phase0-native-call-v1.json"))
            .expect("parse checked Phase 0 fixture");
    let catalog = compile_native_call();
    let action = catalog.actions.get("call").expect("compiled call action");

    assert_eq!(replay.skill_id, catalog.skill_id);
    assert_eq!(replay.action_name, "call");
    assert_eq!(replay.dispatch.program.as_deref(), Some("python3"));
    assert_eq!(
        replay.dispatch.prefix_args,
        catalog.execution.command_prefix
    );
    assert_eq!(replay.dispatch.action_args, action.invocation.fixed_args);
    assert!(replay.dispatch.action_suffix_args.is_empty());
    assert!(replay.dispatch.implementation_suffix_args.is_empty());
    assert!(replay.environment.required_names.is_empty());
    assert!(replay.environment.bindings.is_empty());
    assert!(replay.environment.mapping_names.is_empty());
    assert!(replay.cwd.is_none());

    let replay_mappings = replay
        .dispatch
        .mappings
        .iter()
        .map(normalized_replay_mapping)
        .collect::<Vec<_>>();
    let typed_mappings = action
        .invocation
        .mappings
        .iter()
        .map(normalized_typed_mapping)
        .collect::<Vec<_>>();
    assert_eq!(replay_mappings, typed_mappings);

    let properties = action.definition.input_schema["properties"]
        .as_object()
        .expect("compiled properties");
    let required = action.definition.input_schema["required"]
        .as_array()
        .expect("compiled required fields");
    for parameter in &replay.parameters {
        let property = properties.get(&parameter.name).expect("compiled parameter");
        let expected_type = match &parameter.value_kind {
            ReplayValueKind::String => "string",
            ReplayValueKind::Integer => "integer",
            other => panic!("unexpected comparison parameter kind: {other:?}"),
        };
        assert_eq!(property["type"], expected_type);
        assert_eq!(
            required.contains(&Value::String(parameter.name.clone())),
            parameter.required
        );
    }

    assert!(replay.stdin.accepted);
    assert!(!replay.stdin.parameter_declared);
    assert_eq!(catalog.execution.stdin_mode, StdinMode::Optional);
    assert!(properties.contains_key("stdin"));
    assert_eq!(replay.timeout.source, TimeoutSource::Action);
    assert_eq!(
        replay.timeout.default_secs,
        Some(u64::from(action.invocation.timeout_ceiling_secs))
    );
    assert!(replay.timeout.caller_override_supported);
    assert_eq!(
        serde_json::to_value(&replay.auth_strategies[0]).expect("serialize replay auth"),
        serde_json::to_value(catalog.security_floor.auth_kind).expect("serialize contract auth")
    );
    assert_eq!(
        serde_json::to_value(replay.approval_class).expect("serialize replay approval"),
        serde_json::to_value(catalog.security_floor.policy.approval)
            .expect("serialize contract approval")
    );
}

#[test]
fn security_canaries_and_downgrade_fields_never_cross_the_compiled_boundary() {
    let secret_canary = "PHASE1F_SECRET_REFERENCE_CANARY";
    let target_canary = "PHASE1F_SECRET_ENV_CANARY";
    let mut contract = cli_contract("provider-cli");
    contract.auth = required_auth(AuthKind::Secrets);
    contract.auth.secret_bindings.push(SecretBindingRef {
        name: "api_key".to_owned(),
        secret_ref: secret_canary.to_owned(),
    });
    contract.auth.injections.push(InjectionBinding {
        source: InjectionSource::Secret {
            binding: "api_key".to_owned(),
        },
        target: InjectionTarget::Environment {
            name: target_canary.to_owned(),
        },
    });
    contract
        .policy_floor
        .required_resource_authorities
        .insert("provider/write-budget".to_owned());

    let source = skill_source(&contract, "canary body");
    let parsed = parse_skill_runtime_contract(&source)
        .expect("parse secret-reference fixture")
        .expect("secret-reference contract");
    let validated = validate_skill_runtime_contract(&parsed).expect("validate canary fixture");
    let compiled = compile_typed_action_overrides(
        "provider",
        validated,
        &TypedActionOverrideSet {
            schema_version: TYPED_ACTION_OVERRIDES_V1.to_owned(),
            input_delivery: tool_runtime_core::action_overrides::TypedActionInputDelivery::Argv,
            actions: BTreeMap::from([(
                "read".to_owned(),
                TypedActionOverride {
                    description: "Read provider data.".to_owned(),
                    executable: None,
                    route: tool_runtime_core::action_overrides::TypedActionRoute::Execute,
                    fixed_args: vec!["read".to_owned()],
                    suffix_args: Vec::new(),
                    stdin: tool_runtime_core::action_overrides::TypedActionStdin::Inherit,
                    parameters: BTreeMap::new(),
                    mappings: Vec::new(),
                    argument_rules: Default::default(),
                    timeout_secs: None,
                    policy: ActionPolicyRefinement::default(),
                },
            )]),
        },
    )
    .expect("compile canary fixture");
    let serialized = serde_json::to_string(&compiled).expect("serialize compiled canary fixture");
    assert!(!serialized.contains(secret_canary));
    assert!(!serialized.contains(target_canary));
    assert!(!serialized.contains("api_key"));
    assert!(serialized.contains("provider/write-budget"));

    for forbidden in [
        r#"{"schema_version":"tool-runtime.typed-action-overrides.v1","actions":{},"auth":{"kind":"none"}}"#,
        r#"{"schema_version":"tool-runtime.typed-action-overrides.v1","actions":{},"policy_floor":{}}"#,
        r#"{"schema_version":"tool-runtime.typed-action-overrides.v1","actions":{},"executable":"other"}"#,
    ] {
        assert!(serde_json::from_str::<TypedActionOverrideSet>(forbidden).is_err());
    }
}
