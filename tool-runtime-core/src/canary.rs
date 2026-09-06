//! Tier 2 live-canary declarations authored in `SKILL.md` frontmatter.
//!
//! A canary is the smallest real call that proves a tool skill still works
//! end to end against its actual provider. It exists because the runtime was
//! rewritten and twenty-one of sixty-four skills went dark without a single
//! test going red: the manifests still parsed, the adapters still had unit
//! tests, and the eval that should have caught it drove a hand-built execution
//! path production no longer had, so it reported green against a runtime that
//! did not exist.
//!
//! This module owns only the *vocabulary* — schema, parse, and validation. It
//! opens no socket, resolves no credential, and executes nothing. The runner
//! that spends real money lives beside the production coordinator so that it
//! cannot drift into re-implementing one.
//!
//! Two shapes are declarable, and the difference is deliberate:
//!
//! * a **run** canary, which names one action, its input, and what the result
//!   must satisfy; and
//! * an **exemption**, which records in the manifest itself why a skill has no
//!   safe live call — a skill that only sends messages, places orders, or
//!   drives the operator's GUI must never be canaried.
//!
//! An exemption is a declaration, not an absence. `every_tool_skill_declares_a_canary`
//! accepts an exemption and still fails on a missing block, so "this cannot be
//! canaried" stays a reviewed statement in the package rather than a silent gap
//! that looks identical to an oversight.

use std::{collections::BTreeMap, error::Error, fmt};

use serde::{Deserialize, Serialize};

pub const SKILL_RUNTIME_CANARY_V1: &str = "tool-runtime.canary.v1";

/// Upper bound on a declared canary deadline. A canary is a liveness probe,
/// not a workload: anything claiming to need longer than this is describing a
/// batch job and would stall the lane rather than report on it.
pub const MAX_CANARY_LATENCY_MS: u64 = 600_000;
const MAX_CANARY_IDENTIFIER_BYTES: usize = 128;
const MAX_CANARY_REASON_BYTES: usize = 512;
const MAX_CANARY_INPUT_PARAMETERS: usize = 32;
const MAX_CANARY_REQUIRED_POINTERS: usize = 16;
const MAX_CANARY_SUBSTRING_BYTES: usize = 256;
const MAX_CANARY_FIXTURES: usize = 8;
const MAX_CANARY_FIXTURE_BYTES: usize = 64 * 1024;
const MAX_CANARY_FIXTURE_NAME_BYTES: usize = 128;

/// What one canary call is expected to cost when it runs.
///
/// The tier is a spend gate, not a description: the default lane runs `free`
/// and `cheap`, and `expensive` runs only when explicitly asked for. Media
/// generation and delegating coding agents bill per call in real money, so
/// they must never be reachable by simply running the suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryCostTier {
    /// A local binary, or a public API that bills nothing.
    Free,
    /// A metered API whose per-call cost is a fraction of a cent.
    Cheap,
    /// Media generation, deep research, or a delegated coding agent.
    Expensive,
}

impl CanaryCostTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Cheap => "cheap",
            Self::Expensive => "expensive",
        }
    }

    /// Tiers that run when the operator asked for `requested` and no higher.
    pub fn runs_at(self, requested: Self) -> bool {
        self <= requested
    }
}

impl fmt::Display for CanaryCostTier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What the result of one canary call must satisfy.
///
/// At least one *positive* assertion is required — see
/// [`SkillRuntimeCanary::parse`]. A canary that only checks the process exited
/// zero is the false green this harness exists to eliminate: the adapters that
/// broke still exited zero on some paths, and an agent that received nothing
/// reported `PartialSuccess` rather than an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryExpectation {
    /// Minimum number of items the result must carry. When set it is at least
    /// one, because "the provider answered with nothing" is precisely the
    /// outcome that went unnoticed for a third of the tool surface.
    pub min_items: Option<u32>,
    /// RFC 6901 pointer to the item array. Optional: when the package declares
    /// `content_source.output.items_pointer`, the runner reads the manifest's
    /// own pointer and this stays absent, so the canary asserts against the
    /// shape the product actually consumes rather than a second copy of it.
    pub items_pointer: Option<String>,
    /// RFC 6901 pointer to the adapter's error envelope. A canary fails when
    /// this resolves to anything, whatever the exit status.
    pub error_pointer: Option<String>,
    /// Pointers that must each resolve to a non-null value. This is how a
    /// non-content skill states a positive assertion.
    pub require_pointers: Vec<String>,
    /// Substring the textual result must contain, for adapters whose output is
    /// plain text rather than JSON.
    pub stdout_contains: Option<String>,
    /// Wall-clock ceiling for the whole governed call.
    pub max_latency_ms: u64,
    /// Spend ceiling, when the adapter reports its own cost.
    pub max_cost_microunits: Option<u64>,
    /// The commodity `max_cost_microunits` counts, which the package's own
    /// `content_source.output.cost.commodity` must agree with.
    ///
    /// A bare number is not a ceiling. Packages price in different commodities
    /// on purpose — exa reports `usd`, tavily reports `tavily_credit`, and the
    /// product's own retrieval budgets are keyed by commodity for exactly that
    /// reason — so a ceiling copied from one package onto another silently
    /// changes what it means. That is not hypothetical: tavily carried exa's
    /// USD ceiling of 20000 and a one-credit basic search read as a dollar of
    /// spend, a hundredfold overstatement of a real cost near $0.008.
    ///
    /// Required whenever a ceiling is declared, and checked against the
    /// package rather than trusted, so the mistake cannot be made again.
    pub max_cost_commodity: Option<String>,
}

/// One live call: which action, with what input, judged how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryRun {
    pub cost_tier: CanaryCostTier,
    pub action: String,
    pub input: BTreeMap<String, serde_json::Value>,
    /// Files the runner materializes inside the governed working directory
    /// before the call, keyed by workspace-relative name.
    ///
    /// A local tool that reads a file cannot be canaried without one, and
    /// pointing at a file that happens to exist on the developer's machine
    /// would make the canary report on the host rather than the package. The
    /// content is authored here so the probe is self-contained and identical
    /// everywhere it runs.
    pub fixtures: BTreeMap<String, String>,
    pub expect: CanaryExpectation,
}

/// A reviewed statement that this skill has no safe live call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryExemption {
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanaryDeclaration {
    Run(Box<CanaryRun>),
    Exempt(CanaryExemption),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillRuntimeCanary {
    pub schema_version: String,
    pub declaration: CanaryDeclaration,
}

impl SkillRuntimeCanary {
    pub fn run(&self) -> Option<&CanaryRun> {
        match &self.declaration {
            CanaryDeclaration::Run(run) => Some(run),
            CanaryDeclaration::Exempt(_) => None,
        }
    }

    pub fn exemption(&self) -> Option<&CanaryExemption> {
        match &self.declaration {
            CanaryDeclaration::Exempt(exemption) => Some(exemption),
            CanaryDeclaration::Run(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryParseErrorCode {
    InvalidEnvelope,
    MissingSchemaVersion,
    UnsupportedSchemaVersion,
    AmbiguousDeclaration,
    IncompleteDeclaration,
    InvalidCostTier,
    InvalidAction,
    InvalidInput,
    InvalidExpectation,
    VacuousExpectation,
    InvalidPointer,
    InvalidFixture,
    InvalidReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CanaryParseError {
    pub code: CanaryParseErrorCode,
    pub message: String,
}

impl CanaryParseError {
    fn new(code: CanaryParseErrorCode, message: impl Into<String>) -> Self {
        let mut message = message.into();
        message.truncate(MAX_CANARY_REASON_BYTES);
        Self { code, message }
    }
}

impl fmt::Display for CanaryParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for CanaryParseError {}

/// The raw authored shape. Both forms share one envelope so that a manifest
/// mixing them — an exemption that also declares an action — is rejected
/// rather than silently resolving to one of the two.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanaryDocument {
    #[serde(default)]
    schema_version: Option<String>,
    #[serde(default)]
    exempt: Option<ExemptDocument>,
    #[serde(default)]
    cost_tier: Option<serde_yaml::Value>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    input: Option<serde_yaml::Value>,
    #[serde(default)]
    fixtures: Option<BTreeMap<String, String>>,
    #[serde(default)]
    expect: Option<ExpectDocument>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExemptDocument {
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectDocument {
    #[serde(default)]
    min_items: Option<u32>,
    #[serde(default)]
    items_pointer: Option<String>,
    #[serde(default)]
    error_pointer: Option<String>,
    #[serde(default)]
    require_pointers: Option<Vec<String>>,
    #[serde(default)]
    stdout_contains: Option<String>,
    max_latency_ms: u64,
    #[serde(default)]
    max_cost_microunits: Option<u64>,
    #[serde(default)]
    max_cost_commodity: Option<String>,
}

impl SkillRuntimeCanary {
    /// Read `metadata.magician.runtime_canary` off a parsed frontmatter value.
    ///
    /// Returns `Ok(None)` when the node is absent — that is the *undeclared*
    /// case, which the contract assertion turns into a failure. It is
    /// deliberately distinct from a parse error so an unreadable declaration
    /// never reads as a missing one.
    pub fn parse(frontmatter: &serde_yaml::Value) -> Result<Option<Self>, CanaryParseError> {
        let Some(node) = frontmatter
            .get("metadata")
            .and_then(|value| value.get("magician"))
            .and_then(|value| value.get("runtime_canary"))
        else {
            return Ok(None);
        };
        Self::parse_node(node).map(Some)
    }

    /// Parse one already-located `runtime_canary` node.
    pub fn parse_node(node: &serde_yaml::Value) -> Result<Self, CanaryParseError> {
        let mut document: CanaryDocument =
            serde_yaml::from_value(node.clone()).map_err(|error| {
                CanaryParseError::new(
                    CanaryParseErrorCode::InvalidEnvelope,
                    format!("runtime_canary does not match the canary vocabulary: {error}"),
                )
            })?;

        let schema_version = document.schema_version.take().ok_or_else(|| {
            CanaryParseError::new(
                CanaryParseErrorCode::MissingSchemaVersion,
                "runtime_canary declares no schema_version",
            )
        })?;
        if schema_version != SKILL_RUNTIME_CANARY_V1 {
            return Err(CanaryParseError::new(
                CanaryParseErrorCode::UnsupportedSchemaVersion,
                format!(
                    "runtime_canary schema_version is {schema_version}, expected \
                     {SKILL_RUNTIME_CANARY_V1}"
                ),
            ));
        }

        let declares_run = document.cost_tier.is_some()
            || document.action.is_some()
            || document.input.is_some()
            || document.fixtures.is_some()
            || document.expect.is_some();
        let exempt = document.exempt.take();
        let declaration = match (exempt, declares_run) {
            (Some(_), true) => {
                return Err(CanaryParseError::new(
                    CanaryParseErrorCode::AmbiguousDeclaration,
                    "runtime_canary declares both an exemption and a live call",
                ));
            },
            (Some(exempt), false) => {
                let reason = exempt.reason.trim().to_owned();
                if reason.is_empty() || reason.len() > MAX_CANARY_REASON_BYTES {
                    return Err(CanaryParseError::new(
                        CanaryParseErrorCode::InvalidReason,
                        "a canary exemption must state a bounded, non-empty reason",
                    ));
                }
                CanaryDeclaration::Exempt(CanaryExemption { reason })
            },
            (None, false) => {
                return Err(CanaryParseError::new(
                    CanaryParseErrorCode::IncompleteDeclaration,
                    "runtime_canary declares neither a live call nor an exemption",
                ));
            },
            (None, true) => CanaryDeclaration::Run(Box::new(parse_run(document)?)),
        };

        Ok(Self {
            schema_version,
            declaration,
        })
    }
}

fn parse_run(document: CanaryDocument) -> Result<CanaryRun, CanaryParseError> {
    let cost_tier = document.cost_tier.ok_or_else(|| {
        CanaryParseError::new(
            CanaryParseErrorCode::InvalidCostTier,
            "a canary must declare a cost_tier so the lane can gate real spend",
        )
    })?;
    let cost_tier: CanaryCostTier = serde_yaml::from_value(cost_tier).map_err(|_| {
        CanaryParseError::new(
            CanaryParseErrorCode::InvalidCostTier,
            "cost_tier must be one of free, cheap, expensive",
        )
    })?;

    let action = document.action.unwrap_or_default();
    if !valid_identifier(&action) {
        return Err(CanaryParseError::new(
            CanaryParseErrorCode::InvalidAction,
            "a canary must name one action of its own package",
        ));
    }

    let input = match document.input {
        None => BTreeMap::new(),
        Some(value) => {
            let mapping = value.as_mapping().ok_or_else(|| {
                CanaryParseError::new(
                    CanaryParseErrorCode::InvalidInput,
                    "canary input must be a mapping of parameter name to value",
                )
            })?;
            if mapping.len() > MAX_CANARY_INPUT_PARAMETERS {
                return Err(CanaryParseError::new(
                    CanaryParseErrorCode::InvalidInput,
                    "canary input declares more parameters than the bound allows",
                ));
            }
            let mut input = BTreeMap::new();
            for (key, item) in mapping {
                let name = key.as_str().ok_or_else(|| {
                    CanaryParseError::new(
                        CanaryParseErrorCode::InvalidInput,
                        "canary input parameter names must be strings",
                    )
                })?;
                if !valid_identifier(name) {
                    return Err(CanaryParseError::new(
                        CanaryParseErrorCode::InvalidInput,
                        format!("canary input parameter {name} is not a valid parameter name"),
                    ));
                }
                // Round-tripping through the JSON model is what the governed
                // runtime will carry, so an authored value that cannot survive
                // that trip is rejected here rather than at spend time.
                let value = serde_json::to_value(item).map_err(|_| {
                    CanaryParseError::new(
                        CanaryParseErrorCode::InvalidInput,
                        format!("canary input parameter {name} is not representable as JSON"),
                    )
                })?;
                input.insert(name.to_owned(), value);
            }
            input
        },
    };

    let fixtures = document.fixtures.unwrap_or_default();
    if fixtures.len() > MAX_CANARY_FIXTURES {
        return Err(CanaryParseError::new(
            CanaryParseErrorCode::InvalidFixture,
            "canary fixtures exceed the declared bound",
        ));
    }
    for (name, content) in &fixtures {
        if !valid_fixture_name(name) {
            return Err(CanaryParseError::new(
                CanaryParseErrorCode::InvalidFixture,
                format!(
                    "canary fixture {name} must be a bounded workspace-relative name with no \
                     parent or root component"
                ),
            ));
        }
        if content.len() > MAX_CANARY_FIXTURE_BYTES {
            return Err(CanaryParseError::new(
                CanaryParseErrorCode::InvalidFixture,
                format!("canary fixture {name} exceeds the size bound"),
            ));
        }
    }

    let expect = document.expect.ok_or_else(|| {
        CanaryParseError::new(
            CanaryParseErrorCode::InvalidExpectation,
            "a canary must declare what its result has to satisfy",
        )
    })?;
    let expect = parse_expectation(expect)?;

    Ok(CanaryRun {
        cost_tier,
        action,
        input,
        fixtures,
        expect,
    })
}

/// A fixture name must resolve inside the governed working directory and
/// nowhere else. Rejecting `..`, absolute paths, and anything non-portable here
/// means the runner never has to reason about escape when it writes them.
fn valid_fixture_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_CANARY_FIXTURE_NAME_BYTES
        && !name.starts_with('/')
        && !name.contains('\\')
        && !name.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        })
}

fn parse_expectation(document: ExpectDocument) -> Result<CanaryExpectation, CanaryParseError> {
    if document.max_latency_ms == 0 || document.max_latency_ms > MAX_CANARY_LATENCY_MS {
        return Err(CanaryParseError::new(
            CanaryParseErrorCode::InvalidExpectation,
            format!(
                "max_latency_ms must be between 1 and {MAX_CANARY_LATENCY_MS}; a canary is a \
                 liveness probe, not a workload"
            ),
        ));
    }
    if let Some(min_items) = document.min_items {
        if min_items == 0 {
            // Zero items is the exact shape of the failure this harness exists
            // to catch: the provider answered, the process exited zero, and the
            // agent got nothing. Declaring it as the bar would enshrine it.
            return Err(CanaryParseError::new(
                CanaryParseErrorCode::InvalidExpectation,
                "min_items must be at least 1; an empty result is a failure, not a bar",
            ));
        }
    }
    for pointer in [&document.items_pointer, &document.error_pointer]
        .into_iter()
        .flatten()
    {
        validate_pointer(pointer)?;
    }
    let require_pointers = document.require_pointers.unwrap_or_default();
    if require_pointers.len() > MAX_CANARY_REQUIRED_POINTERS {
        return Err(CanaryParseError::new(
            CanaryParseErrorCode::InvalidExpectation,
            "require_pointers exceeds the declared bound",
        ));
    }
    for pointer in &require_pointers {
        validate_pointer(pointer)?;
    }
    if let Some(substring) = document.stdout_contains.as_ref() {
        if substring.is_empty() || substring.len() > MAX_CANARY_SUBSTRING_BYTES {
            return Err(CanaryParseError::new(
                CanaryParseErrorCode::InvalidExpectation,
                "stdout_contains must be a bounded, non-empty substring",
            ));
        }
    }

    // A spend ceiling must name what it counts. Without the commodity the
    // number is only a number, and the runner has to assume a currency it was
    // never told — which is how a package priced in provider credits came to
    // be judged against a ceiling written in dollars.
    match (
        document.max_cost_microunits,
        document.max_cost_commodity.as_deref(),
    ) {
        (Some(_), None) => {
            return Err(CanaryParseError::new(
                CanaryParseErrorCode::InvalidExpectation,
                "max_cost_microunits requires max_cost_commodity: a ceiling with no \
                 commodity cannot be compared to what the package reports",
            ));
        },
        (Some(0), _) => {
            return Err(CanaryParseError::new(
                CanaryParseErrorCode::InvalidExpectation,
                "max_cost_microunits must be positive; a zero ceiling forbids the call \
                 the canary is declared to make",
            ));
        },
        (None, Some(_)) => {
            return Err(CanaryParseError::new(
                CanaryParseErrorCode::InvalidExpectation,
                "max_cost_commodity without max_cost_microunits declares a unit for a \
                 ceiling that does not exist",
            ));
        },
        _ => {},
    }
    if let Some(commodity) = document.max_cost_commodity.as_deref() {
        if !valid_identifier(commodity) {
            return Err(CanaryParseError::new(
                CanaryParseErrorCode::InvalidExpectation,
                "max_cost_commodity must be a bounded identifier",
            ));
        }
    }

    // The governing rule. A canary whose only assertion is "the process exited
    // zero" proves nothing that a broken adapter would not also satisfy, and a
    // suite of those reports green over a dark tool surface.
    let asserts_something = document.min_items.is_some()
        || !require_pointers.is_empty()
        || document.stdout_contains.is_some();
    if !asserts_something {
        return Err(CanaryParseError::new(
            CanaryParseErrorCode::VacuousExpectation,
            "a canary must assert something positive about the result: min_items, \
             require_pointers, or stdout_contains",
        ));
    }

    Ok(CanaryExpectation {
        min_items: document.min_items,
        items_pointer: document.items_pointer,
        error_pointer: document.error_pointer,
        require_pointers,
        stdout_contains: document.stdout_contains,
        max_latency_ms: document.max_latency_ms,
        max_cost_microunits: document.max_cost_microunits,
        max_cost_commodity: document.max_cost_commodity,
    })
}

fn validate_pointer(pointer: &str) -> Result<(), CanaryParseError> {
    // The empty pointer is RFC 6901's whole document, which is the correct
    // items pointer for an adapter that returns a bare array.
    if pointer.is_empty() {
        return Ok(());
    }
    if !pointer.starts_with('/') || pointer.len() > MAX_CANARY_IDENTIFIER_BYTES {
        return Err(CanaryParseError::new(
            CanaryParseErrorCode::InvalidPointer,
            format!("{pointer} is not a bounded RFC 6901 pointer"),
        ));
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CANARY_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(source: &str) -> Result<SkillRuntimeCanary, CanaryParseError> {
        let value: serde_yaml::Value = serde_yaml::from_str(source).expect("test YAML parses");
        SkillRuntimeCanary::parse_node(&value)
    }

    #[test]
    fn a_run_canary_parses() {
        let canary = parse(
            r#"
schema_version: tool-runtime.canary.v1
cost_tier: cheap
action: run
input:
  query: "rust programming language"
  num_results: 2
expect:
  min_items: 1
  max_latency_ms: 30000
  max_cost_microunits: 10000
  max_cost_commodity: usd
"#,
        )
        .expect("canary parses");
        let run = canary.run().expect("run declaration");
        assert_eq!(run.cost_tier, CanaryCostTier::Cheap);
        assert_eq!(run.action, "run");
        assert_eq!(run.expect.min_items, Some(1));
        assert_eq!(run.expect.max_cost_microunits, Some(10_000));
        assert_eq!(run.expect.max_cost_commodity.as_deref(), Some("usd"));
        assert_eq!(
            run.input.get("num_results"),
            Some(&serde_json::json!(2)),
            "authored scalars survive the trip through the JSON model"
        );
    }

    /// A spend ceiling is refused unless it names what it counts.
    ///
    /// This is the shape the tavily canary actually shipped: exa's ceiling of
    /// 20000, written in dollars, copied onto a package that reports provider
    /// credits. Both numbers parsed, both looked like "microunits", and the
    /// comparison overstated a real cost near $0.008 as $1.00.
    #[test]
    fn a_cost_ceiling_without_a_commodity_is_refused() {
        let error = parse(
            r#"
schema_version: tool-runtime.canary.v1
cost_tier: cheap
action: run
input:
  query: "rust"
expect:
  min_items: 1
  max_latency_ms: 30000
  max_cost_microunits: 20000
"#,
        )
        .expect_err("a ceiling with no commodity must not parse");
        assert_eq!(error.code, CanaryParseErrorCode::InvalidExpectation);
    }

    #[test]
    fn a_commodity_without_a_ceiling_is_refused() {
        let error = parse(
            r#"
schema_version: tool-runtime.canary.v1
cost_tier: cheap
action: run
input:
  query: "rust"
expect:
  min_items: 1
  max_latency_ms: 30000
  max_cost_commodity: usd
"#,
        )
        .expect_err("a unit for a ceiling that does not exist must not parse");
        assert_eq!(error.code, CanaryParseErrorCode::InvalidExpectation);
    }

    #[test]
    fn a_zero_cost_ceiling_is_refused() {
        let error = parse(
            r#"
schema_version: tool-runtime.canary.v1
cost_tier: cheap
action: run
input:
  query: "rust"
expect:
  min_items: 1
  max_latency_ms: 30000
  max_cost_microunits: 0
  max_cost_commodity: usd
"#,
        )
        .expect_err("a zero ceiling forbids the declared call");
        assert_eq!(error.code, CanaryParseErrorCode::InvalidExpectation);
    }

    #[test]
    fn an_exemption_parses_and_is_not_a_run() {
        let canary = parse(
            r#"
schema_version: tool-runtime.canary.v1
exempt:
  reason: "every action sends a message to a real recipient"
"#,
        )
        .expect("exemption parses");
        assert!(canary.run().is_none());
        assert_eq!(
            canary.exemption().map(|exempt| exempt.reason.as_str()),
            Some("every action sends a message to a real recipient")
        );
    }

    #[test]
    fn an_absent_declaration_is_not_an_error() {
        let frontmatter: serde_yaml::Value =
            serde_yaml::from_str("metadata:\n  magician:\n    runtime_contract: {}\n")
                .expect("frontmatter parses");
        assert_eq!(SkillRuntimeCanary::parse(&frontmatter), Ok(None));
    }

    #[test]
    fn a_vacuous_expectation_is_rejected() {
        // The whole point: exit-zero alone is what a broken adapter also
        // achieves, so it may never be the entire bar.
        let error = parse(
            r#"
schema_version: tool-runtime.canary.v1
cost_tier: free
action: run
expect:
  max_latency_ms: 5000
"#,
        )
        .expect_err("a canary asserting nothing is rejected");
        assert_eq!(error.code, CanaryParseErrorCode::VacuousExpectation);
    }

    #[test]
    fn zero_min_items_is_rejected() {
        let error = parse(
            r#"
schema_version: tool-runtime.canary.v1
cost_tier: free
action: run
expect:
  min_items: 0
  max_latency_ms: 5000
"#,
        )
        .expect_err("an empty result may not be declared as the bar");
        assert_eq!(error.code, CanaryParseErrorCode::InvalidExpectation);
    }

    #[test]
    fn a_mixed_declaration_is_rejected() {
        let error = parse(
            r#"
schema_version: tool-runtime.canary.v1
cost_tier: free
action: run
expect:
  min_items: 1
  max_latency_ms: 5000
exempt:
  reason: "cannot decide"
"#,
        )
        .expect_err("an exemption and a live call are mutually exclusive");
        assert_eq!(error.code, CanaryParseErrorCode::AmbiguousDeclaration);
    }

    #[test]
    fn an_unsupported_version_is_rejected() {
        let error = parse(
            r#"
schema_version: tool-runtime.canary.v0
cost_tier: free
action: run
expect:
  min_items: 1
  max_latency_ms: 5000
"#,
        )
        .expect_err("only v1 is supported");
        assert_eq!(error.code, CanaryParseErrorCode::UnsupportedSchemaVersion);
    }

    #[test]
    fn an_unknown_field_is_rejected() {
        // `deny_unknown_fields` is what stops a typo becoming a silently
        // ignored assertion — the failure mode that lets a canary look
        // stricter than it is.
        let error = parse(
            r#"
schema_version: tool-runtime.canary.v1
cost_tier: free
action: run
expect:
  min_items: 1
  max_latency_ms: 5000
  max_latency: 10
"#,
        )
        .expect_err("an unknown expectation field is rejected");
        assert_eq!(error.code, CanaryParseErrorCode::InvalidEnvelope);
    }

    #[test]
    fn a_fixture_escaping_its_workspace_is_rejected() {
        for name in ["../outside.json", "/etc/passwd", "nested/../../up.json"] {
            let error = parse(&format!(
                r#"
schema_version: tool-runtime.canary.v1
cost_tier: free
action: run
fixtures:
  "{name}": "{{}}"
expect:
  stdout_contains: "x"
  max_latency_ms: 5000
"#
            ))
            .expect_err("a fixture may not escape the governed working directory");
            assert_eq!(error.code, CanaryParseErrorCode::InvalidFixture, "{name}");
        }
    }

    #[test]
    fn a_nested_fixture_is_accepted() {
        let canary = parse(
            r#"
schema_version: tool-runtime.canary.v1
cost_tier: free
action: run
fixtures:
  canary-fixtures/input.json: "{\"items\":[1]}"
expect:
  stdout_contains: "1"
  max_latency_ms: 5000
"#,
        )
        .expect("a bounded relative fixture parses");
        let run = canary.run().expect("run declaration");
        assert_eq!(run.fixtures.len(), 1);
        assert!(run.fixtures.contains_key("canary-fixtures/input.json"));
    }

    #[test]
    fn tier_gating_is_ordered() {
        assert!(CanaryCostTier::Free.runs_at(CanaryCostTier::Cheap));
        assert!(CanaryCostTier::Cheap.runs_at(CanaryCostTier::Cheap));
        assert!(!CanaryCostTier::Expensive.runs_at(CanaryCostTier::Cheap));
        assert!(CanaryCostTier::Expensive.runs_at(CanaryCostTier::Expensive));
    }
}
