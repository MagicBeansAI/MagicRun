//! Bounded, deterministic interpretation of CLI authentication lifecycle results.
//!
//! Phase 4B accepts only a borrow-scoped command observation and the immutable command
//! plan compiled in Phase 4A. It projects declared exit-code or JSON rules into one
//! public auth state, verifies an expected identity before `ready` can escape, and
//! discards every unselected output field. It does not spawn a process, persist output,
//! cache status, coordinate login, or enable a production route.

use std::{collections::BTreeSet, error::Error, fmt};

use serde::Serialize;
use serde_json::Value;

use crate::{
    credential_lifecycle::{CredentialLifecycleOperation, CredentialLifecyclePlan},
    credential_profiles::ExpectedCredentialIdentity,
    manifest::{
        AuthState, IdentityContract, IdentitySelector, LifecycleJsonPredicate, LifecycleJsonScalar,
        LifecycleObservedAuthState, LifecycleStatusOutputFormat,
    },
};

pub const CREDENTIAL_LIFECYCLE_STATUS_RESULT_V1: &str =
    "tool-runtime.credential-lifecycle-status-result.v1";
pub const MAX_LIFECYCLE_OBSERVATION_STDOUT_BYTES: usize = 256 * 1024;
pub const MAX_LIFECYCLE_OBSERVATION_STDERR_BYTES: usize = 256 * 1024;
pub const MAX_LIFECYCLE_OBSERVATION_TOTAL_BYTES: usize = 384 * 1024;
pub const MAX_LIFECYCLE_STATUS_JSON_DEPTH: usize = 32;
pub const MAX_LIFECYCLE_STATUS_JSON_NODES: usize = 16 * 1024;
pub const MAX_LIFECYCLE_STATUS_EVALUATION_WORK: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialLifecycleTermination {
    Exited { code: u8 },
    Signaled,
    TimedOut,
    Cancelled,
    SpawnFailed,
}

/// Borrow-scoped, bounded process result. Output bytes cannot be cloned, serialized, or
/// formatted through this type and are released by the caller after evaluation.
pub struct CredentialLifecycleCommandObservation<'a> {
    operation: CredentialLifecycleOperation,
    termination: CredentialLifecycleTermination,
    stdout: &'a [u8],
    stderr: &'a [u8],
}

impl<'a> CredentialLifecycleCommandObservation<'a> {
    pub fn new(
        operation: CredentialLifecycleOperation,
        termination: CredentialLifecycleTermination,
        stdout: &'a [u8],
        stderr: &'a [u8],
    ) -> Result<Self, CredentialLifecycleObservationError> {
        let total = stdout
            .len()
            .checked_add(stderr.len())
            .ok_or_else(output_too_large)?;
        if stdout.len() > MAX_LIFECYCLE_OBSERVATION_STDOUT_BYTES
            || stderr.len() > MAX_LIFECYCLE_OBSERVATION_STDERR_BYTES
            || total > MAX_LIFECYCLE_OBSERVATION_TOTAL_BYTES
        {
            return Err(output_too_large());
        }
        Ok(Self {
            operation,
            termination,
            stdout,
            stderr,
        })
    }

    pub fn operation(&self) -> CredentialLifecycleOperation {
        self.operation
    }

    pub fn termination(&self) -> CredentialLifecycleTermination {
        self.termination
    }

    pub fn stdout_len(&self) -> usize {
        self.stdout.len()
    }

    pub fn stderr_len(&self) -> usize {
        self.stderr.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialLifecycleObservationErrorCode {
    OutputTooLarge,
    WrongOperation,
    MissingStatusContract,
    Cancelled,
    TimedOut,
    ProcessFailed,
    MalformedOutput,
    OutputTooDeep,
    OutputTooComplex,
    EvaluationLimitExceeded,
    UnmappedStatus,
    AmbiguousStatus,
    MissingIdentity,
    InvalidIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CredentialLifecycleObservationError {
    pub code: CredentialLifecycleObservationErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl CredentialLifecycleObservationError {
    const fn new(
        code: CredentialLifecycleObservationErrorCode,
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

impl fmt::Display for CredentialLifecycleObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for CredentialLifecycleObservationError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ObservedCredentialIdentity(String);

impl ObservedCredentialIdentity {
    fn from_status(value: &str) -> Result<Self, CredentialLifecycleObservationError> {
        ExpectedCredentialIdentity::new(value.to_owned()).map_err(|_| invalid_identity())?;
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialIdentityVerification {
    NotEvaluated,
    NotDeclared,
    ProviderUnverified,
    Matched,
    Mismatched,
}

/// Public, non-secret projection of one status observation.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct CredentialLifecycleStatusResult {
    pub schema_version: &'static str,
    #[serde(skip)]
    plan: CredentialLifecyclePlan,
    state: AuthState,
    identity_verification: CredentialIdentityVerification,
    expected_identity: Option<ExpectedCredentialIdentity>,
    actual_identity: Option<ObservedCredentialIdentity>,
}

impl CredentialLifecycleStatusResult {
    pub fn state(&self) -> AuthState {
        self.state
    }

    pub fn identity_verification(&self) -> CredentialIdentityVerification {
        self.identity_verification
    }

    pub fn expected_identity(&self) -> Option<&ExpectedCredentialIdentity> {
        self.expected_identity.as_ref()
    }

    pub fn actual_identity(&self) -> Option<&ObservedCredentialIdentity> {
        self.actual_identity.as_ref()
    }

    pub fn is_execution_ready(&self) -> bool {
        self.state == AuthState::Ready
            && matches!(
                self.identity_verification,
                CredentialIdentityVerification::NotDeclared
                    | CredentialIdentityVerification::ProviderUnverified
                    | CredentialIdentityVerification::Matched
            )
    }

    pub(crate) fn plan(&self) -> &CredentialLifecyclePlan {
        &self.plan
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialLifecycleSuccessPostcondition {
    EvaluateStatusObservation,
    FreshStatusRequired,
    InvalidateVerifiedStatus,
}

/// A successful login/refresh can never itself become `ready`; it always requires a new
/// status command and full Phase 4B evaluation. Logout invalidates prior verified state.
pub fn lifecycle_success_postcondition(
    plan: &CredentialLifecyclePlan,
) -> CredentialLifecycleSuccessPostcondition {
    match plan.operation() {
        CredentialLifecycleOperation::Status => {
            CredentialLifecycleSuccessPostcondition::EvaluateStatusObservation
        },
        CredentialLifecycleOperation::Login | CredentialLifecycleOperation::Refresh => {
            CredentialLifecycleSuccessPostcondition::FreshStatusRequired
        },
        CredentialLifecycleOperation::Logout => {
            CredentialLifecycleSuccessPostcondition::InvalidateVerifiedStatus
        },
    }
}

pub fn evaluate_lifecycle_status(
    plan: &CredentialLifecyclePlan,
    observation: &CredentialLifecycleCommandObservation<'_>,
) -> Result<CredentialLifecycleStatusResult, CredentialLifecycleObservationError> {
    if plan.operation() != CredentialLifecycleOperation::Status
        || observation.operation != CredentialLifecycleOperation::Status
    {
        return Err(wrong_operation());
    }
    let contract = plan
        .status_observation()
        .ok_or_else(missing_status_contract)?;
    let exit_code = match observation.termination {
        CredentialLifecycleTermination::Exited { code } => i32::from(code),
        CredentialLifecycleTermination::Cancelled => return Err(cancelled()),
        CredentialLifecycleTermination::TimedOut => return Err(timed_out()),
        CredentialLifecycleTermination::Signaled | CredentialLifecycleTermination::SpawnFailed => {
            return Err(process_failed())
        },
    };

    let payload = match contract.format {
        LifecycleStatusOutputFormat::ExitCode => None,
        LifecycleStatusOutputFormat::Json => Some(parse_bounded_json(observation.stdout)?),
    };
    let mut matched_states = BTreeSet::new();
    let mut budget = EvaluationBudget::new();
    for rule in contract
        .rules
        .iter()
        .filter(|rule| rule.exit_codes.contains(&exit_code))
    {
        budget.consume(1)?;
        let mut matches = true;
        for predicate in &rule.all {
            if !predicate_matches(predicate, payload.as_ref(), &mut budget)? {
                matches = false;
                break;
            }
        }
        if matches {
            matched_states.insert(rule.state);
        }
    }
    let projected = match matched_states.len() {
        0 => return Err(unmapped_status()),
        1 => *matched_states.first().expect("one matched state"),
        _ => return Err(ambiguous_status()),
    };
    let state = auth_state(projected);
    verify_identity(plan, state, payload.as_ref())
}

fn verify_identity(
    plan: &CredentialLifecyclePlan,
    state: AuthState,
    payload: Option<&Value>,
) -> Result<CredentialLifecycleStatusResult, CredentialLifecycleObservationError> {
    let expected = plan.expected_identity().cloned();
    if state != AuthState::Ready {
        return Ok(status_result(
            plan,
            state,
            CredentialIdentityVerification::NotEvaluated,
            expected,
            None,
        ));
    }

    match plan.identity_contract() {
        IdentityContract::None => Ok(status_result(
            plan,
            state,
            CredentialIdentityVerification::NotDeclared,
            None,
            None,
        )),
        IdentityContract::Unverified { .. } => Ok(status_result(
            plan,
            state,
            CredentialIdentityVerification::ProviderUnverified,
            None,
            None,
        )),
        IdentityContract::ProfileExpected { selector } => {
            let expected = expected.ok_or_else(missing_identity)?;
            let payload = payload.ok_or_else(missing_identity)?;
            let (pointer, ascii_case_insensitive) = match selector {
                IdentitySelector::JsonPointer { pointer } => (pointer.as_str(), false),
                IdentitySelector::JsonPointerAsciiCaseInsensitive { pointer } => {
                    (pointer.as_str(), true)
                },
            };
            let actual = payload
                .pointer(pointer)
                .and_then(Value::as_str)
                .ok_or_else(missing_identity)
                .and_then(ObservedCredentialIdentity::from_status)?;
            let matches = if ascii_case_insensitive {
                expected.as_str().eq_ignore_ascii_case(actual.as_str())
            } else {
                expected.as_str() == actual.as_str()
            };
            Ok(status_result(
                plan,
                if matches {
                    AuthState::Ready
                } else {
                    AuthState::IdentityMismatch
                },
                if matches {
                    CredentialIdentityVerification::Matched
                } else {
                    CredentialIdentityVerification::Mismatched
                },
                Some(expected),
                Some(actual),
            ))
        },
    }
}

fn status_result(
    plan: &CredentialLifecyclePlan,
    state: AuthState,
    identity_verification: CredentialIdentityVerification,
    expected_identity: Option<ExpectedCredentialIdentity>,
    actual_identity: Option<ObservedCredentialIdentity>,
) -> CredentialLifecycleStatusResult {
    CredentialLifecycleStatusResult {
        schema_version: CREDENTIAL_LIFECYCLE_STATUS_RESULT_V1,
        plan: plan.clone(),
        state,
        identity_verification,
        expected_identity,
        actual_identity,
    }
}

fn auth_state(state: LifecycleObservedAuthState) -> AuthState {
    match state {
        LifecycleObservedAuthState::Missing => AuthState::Missing,
        LifecycleObservedAuthState::InteractionRequired => AuthState::InteractionRequired,
        LifecycleObservedAuthState::Ready => AuthState::Ready,
        LifecycleObservedAuthState::Expired => AuthState::Expired,
        LifecycleObservedAuthState::Revoked => AuthState::Revoked,
        LifecycleObservedAuthState::Denied => AuthState::Denied,
        LifecycleObservedAuthState::Error => AuthState::Error,
    }
}

struct EvaluationBudget {
    remaining: usize,
}

impl EvaluationBudget {
    fn new() -> Self {
        Self {
            remaining: MAX_LIFECYCLE_STATUS_EVALUATION_WORK,
        }
    }

    fn consume(&mut self, amount: usize) -> Result<(), CredentialLifecycleObservationError> {
        self.remaining = self
            .remaining
            .checked_sub(amount)
            .ok_or_else(evaluation_limit_exceeded)?;
        Ok(())
    }
}

fn predicate_matches(
    predicate: &LifecycleJsonPredicate,
    payload: Option<&Value>,
    budget: &mut EvaluationBudget,
) -> Result<bool, CredentialLifecycleObservationError> {
    budget.consume(1)?;
    let Some(payload) = payload else {
        return Ok(false);
    };
    Ok(match predicate {
        LifecycleJsonPredicate::Equals { pointer, value } => payload
            .pointer(pointer)
            .is_some_and(|actual| scalar_matches(value, actual)),
        LifecycleJsonPredicate::Exists { pointer } => payload.pointer(pointer).is_some(),
        LifecycleJsonPredicate::Missing { pointer } => payload.pointer(pointer).is_none(),
        LifecycleJsonPredicate::ArrayContainsAllStrings { pointer, values } => payload
            .pointer(pointer)
            .and_then(Value::as_array)
            .map(|actual| array_contains_all_strings(actual, values, budget))
            .transpose()?
            .unwrap_or(false),
    })
}

fn array_contains_all_strings(
    actual: &[Value],
    required: &BTreeSet<String>,
    budget: &mut EvaluationBudget,
) -> Result<bool, CredentialLifecycleObservationError> {
    budget.consume(actual.len().saturating_add(required.len()))?;
    let actual = actual
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    Ok(required
        .iter()
        .all(|required| actual.contains(required.as_str())))
}

fn scalar_matches(expected: &LifecycleJsonScalar, actual: &Value) -> bool {
    match expected {
        LifecycleJsonScalar::String { value } => actual.as_str() == Some(value.as_str()),
        LifecycleJsonScalar::Boolean { value } => actual.as_bool() == Some(*value),
        LifecycleJsonScalar::Integer { value } => actual.as_i64() == Some(*value),
        LifecycleJsonScalar::Null => actual.is_null(),
    }
}

fn parse_bounded_json(bytes: &[u8]) -> Result<Value, CredentialLifecycleObservationError> {
    validate_json_nesting(bytes)?;
    let value: Value = serde_json::from_slice(bytes).map_err(|_| malformed_output())?;
    validate_json_nodes(&value)?;
    Ok(value)
}

fn validate_json_nesting(bytes: &[u8]) -> Result<(), CredentialLifecycleObservationError> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match *byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth = depth.checked_add(1).ok_or_else(output_too_deep)?;
                if depth > MAX_LIFECYCLE_STATUS_JSON_DEPTH {
                    return Err(output_too_deep());
                }
            },
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {},
        }
    }
    Ok(())
}

fn validate_json_nodes(value: &Value) -> Result<(), CredentialLifecycleObservationError> {
    let mut stack = vec![value];
    let mut nodes = 0usize;
    while let Some(value) = stack.pop() {
        nodes = nodes.checked_add(1).ok_or_else(output_too_complex)?;
        if nodes > MAX_LIFECYCLE_STATUS_JSON_NODES {
            return Err(output_too_complex());
        }
        match value {
            Value::Array(values) => stack.extend(values.iter()),
            Value::Object(values) => stack.extend(values.values()),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {},
        }
    }
    Ok(())
}

const fn output_too_large() -> CredentialLifecycleObservationError {
    CredentialLifecycleObservationError::new(
        CredentialLifecycleObservationErrorCode::OutputTooLarge,
        "lifecycle.output",
        "the authentication lifecycle output exceeds its bounded capture limit",
    )
}

const fn wrong_operation() -> CredentialLifecycleObservationError {
    CredentialLifecycleObservationError::new(
        CredentialLifecycleObservationErrorCode::WrongOperation,
        "lifecycle.operation",
        "only a status plan can interpret an authentication status observation",
    )
}

const fn missing_status_contract() -> CredentialLifecycleObservationError {
    CredentialLifecycleObservationError::new(
        CredentialLifecycleObservationErrorCode::MissingStatusContract,
        "auth.lifecycle.status_observation",
        "the status plan does not carry a validated observation contract",
    )
}

const fn cancelled() -> CredentialLifecycleObservationError {
    CredentialLifecycleObservationError::new(
        CredentialLifecycleObservationErrorCode::Cancelled,
        "lifecycle.termination",
        "the authentication lifecycle operation was cancelled",
    )
}

const fn timed_out() -> CredentialLifecycleObservationError {
    CredentialLifecycleObservationError::new(
        CredentialLifecycleObservationErrorCode::TimedOut,
        "lifecycle.termination",
        "the authentication lifecycle operation timed out",
    )
}

const fn process_failed() -> CredentialLifecycleObservationError {
    CredentialLifecycleObservationError::new(
        CredentialLifecycleObservationErrorCode::ProcessFailed,
        "lifecycle.termination",
        "the authentication lifecycle process did not produce an exit status",
    )
}

const fn malformed_output() -> CredentialLifecycleObservationError {
    CredentialLifecycleObservationError::new(
        CredentialLifecycleObservationErrorCode::MalformedOutput,
        "lifecycle.stdout",
        "the authentication status output is malformed",
    )
}

const fn output_too_deep() -> CredentialLifecycleObservationError {
    CredentialLifecycleObservationError::new(
        CredentialLifecycleObservationErrorCode::OutputTooDeep,
        "lifecycle.stdout",
        "the authentication status output exceeds its nesting limit",
    )
}

const fn output_too_complex() -> CredentialLifecycleObservationError {
    CredentialLifecycleObservationError::new(
        CredentialLifecycleObservationErrorCode::OutputTooComplex,
        "lifecycle.stdout",
        "the authentication status output exceeds its structural limit",
    )
}

const fn evaluation_limit_exceeded() -> CredentialLifecycleObservationError {
    CredentialLifecycleObservationError::new(
        CredentialLifecycleObservationErrorCode::EvaluationLimitExceeded,
        "lifecycle.stdout",
        "the authentication status output exceeds its evaluation work limit",
    )
}

const fn unmapped_status() -> CredentialLifecycleObservationError {
    CredentialLifecycleObservationError::new(
        CredentialLifecycleObservationErrorCode::UnmappedStatus,
        "auth.lifecycle.status_observation",
        "the authentication status output matches no declared state",
    )
}

const fn ambiguous_status() -> CredentialLifecycleObservationError {
    CredentialLifecycleObservationError::new(
        CredentialLifecycleObservationErrorCode::AmbiguousStatus,
        "auth.lifecycle.status_observation",
        "the authentication status output matches conflicting declared states",
    )
}

const fn missing_identity() -> CredentialLifecycleObservationError {
    CredentialLifecycleObservationError::new(
        CredentialLifecycleObservationErrorCode::MissingIdentity,
        "auth.identity",
        "a ready authentication status is missing its declared identity",
    )
}

const fn invalid_identity() -> CredentialLifecycleObservationError {
    CredentialLifecycleObservationError::new(
        CredentialLifecycleObservationErrorCode::InvalidIdentity,
        "auth.identity",
        "the observed authentication identity is invalid",
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fmt, thread};

    use serde::Serialize;
    use static_assertions::assert_not_impl_any;

    use super::*;
    use crate::{
        credential_profiles::{
            CreateCredentialProfileReference, CredentialProfileAvailability,
            CredentialProfileBinding, CredentialProfileError, CredentialProfileKey,
            CredentialProfileMetadata, CredentialProfileRegistry,
            CredentialProfileRegistrySnapshot, CredentialProfileRevision, CredentialProfileStatus,
            CredentialScope, SetCredentialProfileDisabled, UpdateCredentialProfileMetadata,
        },
        manifest::{
            AuthContract, AuthKind, AuthLifecycle, AuthRequirement, AuthStorage, CliInteraction,
            LifecycleHook, LifecycleStatusObservation, LifecycleStatusRule, ProfileSelection,
            RuntimeLimits, RuntimeProtocol, RuntimeRequirements, SkillRuntimeContract,
            SkillRuntimeContractVersion, StdinContract, WorkingDirectoryContract,
        },
        manifest_validation::validate_skill_runtime_contract,
    };

    struct OneRegistry(CredentialProfileStatus);

    impl CredentialProfileRegistry for OneRegistry {
        fn snapshot(
            &self,
            scope: &CredentialScope,
        ) -> Result<CredentialProfileRegistrySnapshot, CredentialProfileError> {
            CredentialProfileRegistrySnapshot::new(scope.clone(), vec![self.0.clone()])
        }

        fn status(
            &self,
            key: &CredentialProfileKey,
        ) -> Result<Option<CredentialProfileStatus>, CredentialProfileError> {
            Ok((self.0.key() == key).then(|| self.0.clone()))
        }

        fn create_reference(
            &self,
            _request: CreateCredentialProfileReference,
        ) -> Result<CredentialProfileStatus, CredentialProfileError> {
            Err(CredentialProfileError::registry_unavailable())
        }

        fn update_metadata(
            &self,
            _request: UpdateCredentialProfileMetadata,
        ) -> Result<CredentialProfileStatus, CredentialProfileError> {
            Err(CredentialProfileError::registry_unavailable())
        }

        fn set_disabled(
            &self,
            _request: SetCredentialProfileDisabled,
        ) -> Result<CredentialProfileStatus, CredentialProfileError> {
            Err(CredentialProfileError::registry_unavailable())
        }
    }

    fn scope() -> CredentialScope {
        CredentialScope::new("owner", "default").expect("scope")
    }

    fn string_equals(pointer: &str, value: &str) -> LifecycleJsonPredicate {
        LifecycleJsonPredicate::Equals {
            pointer: pointer.to_owned(),
            value: LifecycleJsonScalar::String {
                value: value.to_owned(),
            },
        }
    }

    fn rule(state: LifecycleObservedAuthState, value: &str) -> LifecycleStatusRule {
        LifecycleStatusRule {
            state,
            exit_codes: BTreeSet::from([0]),
            all: vec![string_equals("/state", value)],
        }
    }

    fn json_rules() -> Vec<LifecycleStatusRule> {
        vec![
            rule(LifecycleObservedAuthState::Ready, "ready"),
            rule(LifecycleObservedAuthState::Missing, "missing"),
            rule(
                LifecycleObservedAuthState::InteractionRequired,
                "interaction_required",
            ),
            rule(LifecycleObservedAuthState::Expired, "expired"),
            rule(LifecycleObservedAuthState::Revoked, "revoked"),
            rule(LifecycleObservedAuthState::Denied, "denied"),
            rule(LifecycleObservedAuthState::Error, "error"),
        ]
    }

    fn contract(
        observation: LifecycleStatusObservation,
        identity: IdentityContract,
    ) -> SkillRuntimeContract {
        SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires: RuntimeRequirements {
                bins: BTreeSet::from(["provider-cli".to_owned()]),
                entrypoint: Default::default(),
                environment: Default::default(),
            },
            runtime: RuntimeProtocol::Cli {
                command_prefix: vec!["resource".to_owned()],
                interaction: CliInteraction::Batch,
                stdin: StdinContract::default(),
                working_directory: WorkingDirectoryContract::default(),
                limits: RuntimeLimits::default(),
            },
            auth: AuthContract {
                kind: AuthKind::CliProfile,
                requirement: AuthRequirement::Required,
                provider: Some("provider".to_owned()),
                profile_selection: ProfileSelection::Fixed {
                    alias: "work".to_owned(),
                },
                storage: AuthStorage::CliOwned,
                lifecycle: AuthLifecycle {
                    status: Some(LifecycleHook {
                        args: vec!["auth".to_owned(), "status".to_owned()],
                        interaction: CliInteraction::Batch,
                        timeout_secs: Some(30),
                    }),
                    status_observation: Some(observation),
                    login: Some(LifecycleHook {
                        args: vec!["auth".to_owned(), "login".to_owned()],
                        interaction: CliInteraction::Pty,
                        timeout_secs: Some(300),
                    }),
                    logout: Some(LifecycleHook {
                        args: vec!["auth".to_owned(), "logout".to_owned()],
                        interaction: CliInteraction::Batch,
                        timeout_secs: Some(30),
                    }),
                    refresh: Some(LifecycleHook {
                        args: vec!["auth".to_owned(), "refresh".to_owned()],
                        interaction: CliInteraction::Batch,
                        timeout_secs: Some(30),
                    }),
                },
                identity,
                ..AuthContract::default()
            },
            policy_floor: Default::default(),
        }
    }

    fn profile(expected: Option<&str>) -> CredentialProfileStatus {
        let key = CredentialProfileKey::new(
            scope(),
            "provider",
            "work",
            CredentialProfileBinding::Provider,
        )
        .expect("key");
        let metadata = CredentialProfileMetadata::new(
            key,
            expected.map(|value| ExpectedCredentialIdentity::new(value).expect("identity")),
            false,
            CredentialProfileAvailability::Enabled,
            CredentialProfileRevision::new(7).expect("revision"),
        )
        .expect("metadata");
        CredentialProfileStatus::new(metadata, AuthState::Unknown).expect("status")
    }

    fn plan(
        contract: &SkillRuntimeContract,
        profile: &CredentialProfileStatus,
        operation: CredentialLifecycleOperation,
    ) -> CredentialLifecyclePlan {
        let registry = OneRegistry(profile.clone());
        CredentialLifecyclePlan::for_profile(
            &registry,
            validate_skill_runtime_contract(contract).expect("validated contract"),
            profile.key(),
            operation,
        )
        .expect("lifecycle plan")
    }

    fn json_observation(bytes: &[u8]) -> CredentialLifecycleCommandObservation<'_> {
        CredentialLifecycleCommandObservation::new(
            CredentialLifecycleOperation::Status,
            CredentialLifecycleTermination::Exited { code: 0 },
            bytes,
            &[],
        )
        .expect("bounded observation")
    }

    #[test]
    fn json_rules_project_every_provider_observable_state() {
        let contract = contract(
            LifecycleStatusObservation {
                format: LifecycleStatusOutputFormat::Json,
                rules: json_rules(),
            },
            IdentityContract::None,
        );
        let profile = profile(None);
        let plan = plan(&contract, &profile, CredentialLifecycleOperation::Status);

        for (wire, expected) in [
            ("ready", AuthState::Ready),
            ("missing", AuthState::Missing),
            ("interaction_required", AuthState::InteractionRequired),
            ("expired", AuthState::Expired),
            ("revoked", AuthState::Revoked),
            ("denied", AuthState::Denied),
            ("error", AuthState::Error),
        ] {
            let bytes = format!(r#"{{"state":"{wire}"}}"#);
            let result = evaluate_lifecycle_status(&plan, &json_observation(bytes.as_bytes()))
                .expect("mapped status");
            assert_eq!(result.state(), expected);
            assert_eq!(
                result.identity_verification(),
                if expected == AuthState::Ready {
                    CredentialIdentityVerification::NotDeclared
                } else {
                    CredentialIdentityVerification::NotEvaluated
                }
            );
            assert_eq!(result.is_execution_ready(), expected == AuthState::Ready);
        }
    }

    #[test]
    fn expected_identity_is_verified_with_declared_ascii_case_policy() {
        let contract = contract(
            LifecycleStatusObservation {
                format: LifecycleStatusOutputFormat::Json,
                rules: json_rules(),
            },
            IdentityContract::ProfileExpected {
                selector: IdentitySelector::JsonPointerAsciiCaseInsensitive {
                    pointer: "/user".to_owned(),
                },
            },
        );
        let profile = profile(Some("owner@example.com"));
        let plan = plan(&contract, &profile, CredentialLifecycleOperation::Status);
        let result = evaluate_lifecycle_status(
            &plan,
            &json_observation(br#"{"state":"ready","user":"OWNER@EXAMPLE.COM"}"#),
        )
        .expect("verified identity");

        assert_eq!(result.state(), AuthState::Ready);
        assert_eq!(
            result.identity_verification(),
            CredentialIdentityVerification::Matched
        );
        assert_eq!(
            result
                .expected_identity()
                .map(ExpectedCredentialIdentity::as_str),
            Some("owner@example.com")
        );
        assert_eq!(
            result
                .actual_identity()
                .map(ObservedCredentialIdentity::as_str),
            Some("OWNER@EXAMPLE.COM")
        );
        assert!(result.is_execution_ready());
    }

    #[test]
    fn exact_identity_mismatch_is_a_non_ready_public_state() {
        let contract = contract(
            LifecycleStatusObservation {
                format: LifecycleStatusOutputFormat::Json,
                rules: json_rules(),
            },
            IdentityContract::ProfileExpected {
                selector: IdentitySelector::JsonPointer {
                    pointer: "/user".to_owned(),
                },
            },
        );
        let profile = profile(Some("owner@example.com"));
        let plan = plan(&contract, &profile, CredentialLifecycleOperation::Status);
        let result = evaluate_lifecycle_status(
            &plan,
            &json_observation(br#"{"state":"ready","user":"OWNER@example.com"}"#),
        )
        .expect("deterministic mismatch");

        assert_eq!(result.state(), AuthState::IdentityMismatch);
        assert_eq!(
            result.identity_verification(),
            CredentialIdentityVerification::Mismatched
        );
        assert!(!result.is_execution_ready());
    }

    #[test]
    fn explicitly_unverified_provider_identity_is_visible_without_claiming_a_match() {
        let contract = contract(
            LifecycleStatusObservation {
                format: LifecycleStatusOutputFormat::Json,
                rules: json_rules(),
            },
            IdentityContract::Unverified {
                reason: "provider does not expose an authenticated identity".to_owned(),
            },
        );
        let profile = profile(None);
        let plan = plan(&contract, &profile, CredentialLifecycleOperation::Status);
        let result = evaluate_lifecycle_status(&plan, &json_observation(br#"{"state":"ready"}"#))
            .expect("provider-observed readiness");

        assert_eq!(result.state(), AuthState::Ready);
        assert_eq!(
            result.identity_verification(),
            CredentialIdentityVerification::ProviderUnverified
        );
        assert!(result.is_execution_ready());
    }

    #[test]
    fn ready_status_requires_a_valid_declared_identity_value() {
        let contract = contract(
            LifecycleStatusObservation {
                format: LifecycleStatusOutputFormat::Json,
                rules: json_rules(),
            },
            IdentityContract::ProfileExpected {
                selector: IdentitySelector::JsonPointer {
                    pointer: "/user".to_owned(),
                },
            },
        );
        let profile = profile(Some("owner@example.com"));
        let plan = plan(&contract, &profile, CredentialLifecycleOperation::Status);

        for (bytes, code) in [
            (
                br#"{"state":"ready"}"#.as_slice(),
                CredentialLifecycleObservationErrorCode::MissingIdentity,
            ),
            (
                br#"{"state":"ready","user":7}"#.as_slice(),
                CredentialLifecycleObservationErrorCode::MissingIdentity,
            ),
            (
                b"{\"state\":\"ready\",\"user\":\" owner@example.com\"}".as_slice(),
                CredentialLifecycleObservationErrorCode::InvalidIdentity,
            ),
        ] {
            assert_eq!(
                evaluate_lifecycle_status(&plan, &json_observation(bytes))
                    .expect_err("invalid ready identity")
                    .code,
                code
            );
        }
    }

    #[test]
    fn exact_predicate_vocabulary_handles_scalars_presence_and_string_sets() {
        let ready = LifecycleStatusRule {
            state: LifecycleObservedAuthState::Ready,
            exit_codes: BTreeSet::from([0]),
            all: vec![
                LifecycleJsonPredicate::Equals {
                    pointer: "/boolean".to_owned(),
                    value: LifecycleJsonScalar::Boolean { value: true },
                },
                LifecycleJsonPredicate::Equals {
                    pointer: "/integer".to_owned(),
                    value: LifecycleJsonScalar::Integer { value: 7 },
                },
                LifecycleJsonPredicate::Equals {
                    pointer: "/nothing".to_owned(),
                    value: LifecycleJsonScalar::Null,
                },
                LifecycleJsonPredicate::Exists {
                    pointer: "/present".to_owned(),
                },
                LifecycleJsonPredicate::Missing {
                    pointer: "/absent".to_owned(),
                },
                LifecycleJsonPredicate::ArrayContainsAllStrings {
                    pointer: "/scopes".to_owned(),
                    values: BTreeSet::from(["mail".to_owned(), "calendar".to_owned()]),
                },
            ],
        };
        let contract = contract(
            LifecycleStatusObservation {
                format: LifecycleStatusOutputFormat::Json,
                rules: vec![ready],
            },
            IdentityContract::None,
        );
        let profile = profile(None);
        let plan = plan(&contract, &profile, CredentialLifecycleOperation::Status);
        let result = evaluate_lifecycle_status(
            &plan,
            &json_observation(
                br#"{"boolean":true,"integer":7,"nothing":null,"present":false,"scopes":["calendar","extra","mail"]}"#,
            ),
        )
        .expect("all exact predicates");
        assert_eq!(result.state(), AuthState::Ready);
    }

    #[test]
    fn exit_code_contract_maps_without_parsing_output() {
        let contract = contract(
            LifecycleStatusObservation {
                format: LifecycleStatusOutputFormat::ExitCode,
                rules: vec![
                    LifecycleStatusRule {
                        state: LifecycleObservedAuthState::Ready,
                        exit_codes: BTreeSet::from([0]),
                        all: Vec::new(),
                    },
                    LifecycleStatusRule {
                        state: LifecycleObservedAuthState::Missing,
                        exit_codes: BTreeSet::from([5]),
                        all: Vec::new(),
                    },
                ],
            },
            IdentityContract::None,
        );
        let profile = profile(None);
        let plan = plan(&contract, &profile, CredentialLifecycleOperation::Status);
        for (code, state) in [(0, AuthState::Ready), (5, AuthState::Missing)] {
            let observation = CredentialLifecycleCommandObservation::new(
                CredentialLifecycleOperation::Status,
                CredentialLifecycleTermination::Exited { code },
                b"not-json-and-never-parsed",
                &[],
            )
            .expect("observation");
            assert_eq!(
                evaluate_lifecycle_status(&plan, &observation)
                    .expect("exit mapping")
                    .state(),
                state
            );
        }
    }

    #[test]
    fn conflicting_and_unmapped_json_rules_fail_closed() {
        let mut rules = json_rules();
        rules.push(LifecycleStatusRule {
            state: LifecycleObservedAuthState::Expired,
            exit_codes: BTreeSet::from([0]),
            all: vec![LifecycleJsonPredicate::Equals {
                pointer: "/expired".to_owned(),
                value: LifecycleJsonScalar::Boolean { value: true },
            }],
        });
        let contract = contract(
            LifecycleStatusObservation {
                format: LifecycleStatusOutputFormat::Json,
                rules,
            },
            IdentityContract::None,
        );
        let profile = profile(None);
        let plan = plan(&contract, &profile, CredentialLifecycleOperation::Status);

        assert_eq!(
            evaluate_lifecycle_status(
                &plan,
                &json_observation(br#"{"state":"ready","expired":true}"#),
            )
            .expect_err("conflicting states")
            .code,
            CredentialLifecycleObservationErrorCode::AmbiguousStatus
        );
        assert_eq!(
            evaluate_lifecycle_status(&plan, &json_observation(br#"{"state":"other"}"#))
                .expect_err("unmapped state")
                .code,
            CredentialLifecycleObservationErrorCode::UnmappedStatus
        );
    }

    #[test]
    fn malformed_deep_wide_and_oversized_outputs_are_bounded() {
        let contract = contract(
            LifecycleStatusObservation {
                format: LifecycleStatusOutputFormat::Json,
                rules: json_rules(),
            },
            IdentityContract::None,
        );
        let profile = profile(None);
        let plan = plan(&contract, &profile, CredentialLifecycleOperation::Status);

        assert_eq!(
            evaluate_lifecycle_status(&plan, &json_observation(b"{"))
                .expect_err("malformed")
                .code,
            CredentialLifecycleObservationErrorCode::MalformedOutput
        );
        let deep = format!(
            "{}0{}",
            "[".repeat(MAX_LIFECYCLE_STATUS_JSON_DEPTH + 1),
            "]".repeat(MAX_LIFECYCLE_STATUS_JSON_DEPTH + 1)
        );
        assert_eq!(
            evaluate_lifecycle_status(&plan, &json_observation(deep.as_bytes()))
                .expect_err("deep")
                .code,
            CredentialLifecycleObservationErrorCode::OutputTooDeep
        );
        let wide = format!(
            "[{}]",
            std::iter::repeat_n("0", MAX_LIFECYCLE_STATUS_JSON_NODES + 1)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(
            evaluate_lifecycle_status(&plan, &json_observation(wide.as_bytes()))
                .expect_err("wide")
                .code,
            CredentialLifecycleObservationErrorCode::OutputTooComplex
        );
        let oversized = vec![b'x'; MAX_LIFECYCLE_OBSERVATION_STDOUT_BYTES + 1];
        assert_eq!(
            CredentialLifecycleCommandObservation::new(
                CredentialLifecycleOperation::Status,
                CredentialLifecycleTermination::Exited { code: 0 },
                &oversized,
                &[],
            )
            .err()
            .expect("oversized")
            .code,
            CredentialLifecycleObservationErrorCode::OutputTooLarge
        );
    }

    #[test]
    fn repeated_large_array_predicates_stop_at_the_evaluation_work_ceiling() {
        let predicates = (0..crate::manifest_validation::MAX_LIFECYCLE_STATUS_PREDICATES)
            .map(|index| LifecycleJsonPredicate::ArrayContainsAllStrings {
                pointer: "/scopes".to_owned(),
                values: BTreeSet::from([format!("scope-{index}")]),
            })
            .collect();
        let contract = contract(
            LifecycleStatusObservation {
                format: LifecycleStatusOutputFormat::Json,
                rules: vec![LifecycleStatusRule {
                    state: LifecycleObservedAuthState::Ready,
                    exit_codes: BTreeSet::from([0]),
                    all: predicates,
                }],
            },
            IdentityContract::None,
        );
        let profile = profile(None);
        let plan = plan(&contract, &profile, CredentialLifecycleOperation::Status);
        let scopes = (0..16_000)
            .map(|index| Value::String(format!("scope-{}", index % 32)))
            .collect();
        let bytes = serde_json::to_vec(&serde_json::json!({ "scopes": Value::Array(scopes) }))
            .expect("status payload");

        assert_eq!(
            evaluate_lifecycle_status(&plan, &json_observation(&bytes))
                .expect_err("bounded evaluation work")
                .code,
            CredentialLifecycleObservationErrorCode::EvaluationLimitExceeded
        );
    }

    #[test]
    fn cancellation_timeout_and_process_failures_are_distinct_and_value_free() {
        let contract = contract(
            LifecycleStatusObservation {
                format: LifecycleStatusOutputFormat::Json,
                rules: json_rules(),
            },
            IdentityContract::None,
        );
        let profile = profile(None);
        let plan = plan(&contract, &profile, CredentialLifecycleOperation::Status);
        for (termination, code) in [
            (
                CredentialLifecycleTermination::Cancelled,
                CredentialLifecycleObservationErrorCode::Cancelled,
            ),
            (
                CredentialLifecycleTermination::TimedOut,
                CredentialLifecycleObservationErrorCode::TimedOut,
            ),
            (
                CredentialLifecycleTermination::Signaled,
                CredentialLifecycleObservationErrorCode::ProcessFailed,
            ),
            (
                CredentialLifecycleTermination::SpawnFailed,
                CredentialLifecycleObservationErrorCode::ProcessFailed,
            ),
        ] {
            let observation = CredentialLifecycleCommandObservation::new(
                CredentialLifecycleOperation::Status,
                termination,
                b"CANARY",
                b"CANARY",
            )
            .expect("bounded");
            let error = evaluate_lifecycle_status(&plan, &observation).expect_err("failure");
            assert_eq!(error.code, code);
            assert!(!format!("{error:?} {error}").contains("CANARY"));
        }
    }

    #[test]
    fn successful_login_and_refresh_require_fresh_status_verification() {
        let contract = contract(
            LifecycleStatusObservation {
                format: LifecycleStatusOutputFormat::Json,
                rules: json_rules(),
            },
            IdentityContract::None,
        );
        let profile = profile(None);
        for operation in [
            CredentialLifecycleOperation::Login,
            CredentialLifecycleOperation::Refresh,
        ] {
            let plan = plan(&contract, &profile, operation);
            assert_eq!(
                lifecycle_success_postcondition(&plan),
                CredentialLifecycleSuccessPostcondition::FreshStatusRequired
            );
            let observation = json_observation(br#"{"state":"ready"}"#);
            assert_eq!(
                evaluate_lifecycle_status(&plan, &observation)
                    .expect_err("mutation success cannot become ready")
                    .code,
                CredentialLifecycleObservationErrorCode::WrongOperation
            );
        }
        let logout = plan(&contract, &profile, CredentialLifecycleOperation::Logout);
        assert_eq!(
            lifecycle_success_postcondition(&logout),
            CredentialLifecycleSuccessPostcondition::InvalidateVerifiedStatus
        );
        let status = plan(&contract, &profile, CredentialLifecycleOperation::Status);
        assert_eq!(
            lifecycle_success_postcondition(&status),
            CredentialLifecycleSuccessPostcondition::EvaluateStatusObservation
        );
    }

    #[test]
    fn output_owner_is_borrow_only_and_public_result_is_metadata_only() {
        assert_not_impl_any!(
            CredentialLifecycleCommandObservation<'static>: Clone,
            fmt::Debug,
            Serialize
        );

        let contract = contract(
            LifecycleStatusObservation {
                format: LifecycleStatusOutputFormat::Json,
                rules: json_rules(),
            },
            IdentityContract::None,
        );
        let profile = profile(None);
        let plan = plan(&contract, &profile, CredentialLifecycleOperation::Status);
        let result = evaluate_lifecycle_status(
            &plan,
            &json_observation(br#"{"state":"ready","discarded":"CANARY"}"#),
        )
        .expect("result");
        let encoded = serde_json::to_string(&result).expect("serialize result");
        assert!(!encoded.contains("CANARY"));
        assert!(encoded.contains("\"state\":\"ready\""));
    }

    #[test]
    fn maximum_well_formed_status_evaluation_fits_a_small_stack() {
        let handle = thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| {
                let mut rules = Vec::new();
                for index in 0..crate::manifest_validation::MAX_LIFECYCLE_STATUS_RULES {
                    rules.push(LifecycleStatusRule {
                        state: if index == 0 {
                            LifecycleObservedAuthState::Ready
                        } else {
                            LifecycleObservedAuthState::Missing
                        },
                        exit_codes: BTreeSet::from([0]),
                        all: vec![string_equals("/state", &format!("state-{index}"))],
                    });
                }
                let contract = contract(
                    LifecycleStatusObservation {
                        format: LifecycleStatusOutputFormat::Json,
                        rules,
                    },
                    IdentityContract::None,
                );
                let profile = profile(None);
                let plan = plan(&contract, &profile, CredentialLifecycleOperation::Status);
                evaluate_lifecycle_status(&plan, &json_observation(br#"{"state":"state-0"}"#))
                    .expect("bounded status")
                    .state()
            })
            .expect("thread");
        assert_eq!(handle.join().expect("join"), AuthState::Ready);
    }
}
