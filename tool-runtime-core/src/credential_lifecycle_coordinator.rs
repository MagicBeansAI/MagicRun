//! Bounded, process-local coordination for interactive CLI authentication.
//!
//! Phase 4D owns only safe lifecycle state. It never spawns a process, opens a callback
//! listener, or stores provider URLs, device codes, OTP values, QR payloads, terminal
//! output, or operator text. The Phase 4E interaction bridge will retain those sensitive
//! values and use this coordinator only for exact lease and transition authority.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex, OnceLock,
    },
    time::{Duration, Instant},
};

use serde::Serialize;

use crate::{
    credential_lifecycle::{CredentialLifecycleOperation, CredentialLifecyclePlan},
    credential_lifecycle_observation::{
        lifecycle_success_postcondition, CredentialLifecycleSuccessPostcondition,
    },
    credential_profiles::{
        CredentialProfileBinding, CredentialProfileKey, CredentialProviderId, CredentialScope,
    },
    credential_status_cache::{CredentialProcessEpoch, CredentialVerifiedStatusCache},
    manifest::CliInteraction,
};

pub const CREDENTIAL_LIFECYCLE_COORDINATOR_V1: &str =
    "tool-runtime.credential-lifecycle-coordinator.v1";
pub const MAX_ACTIVE_CREDENTIAL_LIFECYCLE_LEASES: usize = 256;
pub const MAX_REGISTERED_CREDENTIAL_LIFECYCLE_EPOCHS: usize = 256;
pub const DEFAULT_CREDENTIAL_LOGIN_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub const MAX_CREDENTIAL_LOGIN_TIMEOUT: Duration = Duration::from_secs(15 * 60);
pub const MAX_CREDENTIAL_LIFECYCLE_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

static NEXT_COORDINATOR_INSTANCE: AtomicU64 = AtomicU64::new(1);
static ACTIVE_COORDINATOR_EPOCHS: OnceLock<Mutex<BTreeSet<u64>>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialLifecycleCoordinatorErrorCode {
    InvalidIdleTimeout,
    WrongOperation,
    InvalidLoginTimeout,
    ProcessEpochMismatch,
    StatusInvalidationFailed,
    LeaseAlreadyActive,
    CapacityExceeded,
    LeaseNotFound,
    LeaseMismatch,
    StaleRevision,
    InvalidTransition,
    LeaseStale,
    ClockRegression,
    RevisionExhausted,
    TimeOverflow,
    CoordinatorIdExhausted,
    CoordinatorAlreadyActive,
    CoordinatorRegistryFull,
    LeaseIdExhausted,
    LockPoisoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CredentialLifecycleCoordinatorError {
    pub code: CredentialLifecycleCoordinatorErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl CredentialLifecycleCoordinatorError {
    const fn new(
        code: CredentialLifecycleCoordinatorErrorCode,
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

impl fmt::Display for CredentialLifecycleCoordinatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for CredentialLifecycleCoordinatorError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialLifecycleCoordinatorInstant(Instant);

impl CredentialLifecycleCoordinatorInstant {
    pub fn now() -> Self {
        Self(Instant::now())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialLifecycleIdleTimeout(Duration);

impl CredentialLifecycleIdleTimeout {
    pub fn new(value: Duration) -> Result<Self, CredentialLifecycleCoordinatorError> {
        if value.is_zero() || value > MAX_CREDENTIAL_LIFECYCLE_IDLE_TIMEOUT {
            return Err(invalid_idle_timeout());
        }
        Ok(Self(value))
    }

    pub fn get(self) -> Duration {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct CredentialLifecycleLeaseId {
    process_epoch: u64,
    coordinator_instance: u64,
    sequence: u64,
}

impl CredentialLifecycleLeaseId {
    pub fn process_epoch(self) -> u64 {
        self.process_epoch
    }

    pub fn coordinator_instance(self) -> u64 {
        self.coordinator_instance
    }

    pub fn sequence(self) -> u64 {
        self.sequence
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialLifecyclePendingKind {
    BrowserCallback,
    DeviceCode,
    Otp,
    Qr,
    OperatorRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum CredentialLifecycleLeaseState {
    Running,
    Pending(CredentialLifecyclePendingKind),
    Cancelling,
    RecoveryRequired(CredentialLifecycleStaleReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialLifecycleStaleReason {
    Idle,
    Deadline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialLifecycleTerminalOutcome {
    Succeeded,
    Cancelled,
    TimedOut,
    ProcessFailed,
}

/// Safe, non-authorizing view of a lease. It deliberately omits provider, scope, profile,
/// executable, argv, expected identity, and all interaction payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CredentialLifecycleLeaseSnapshot {
    pub schema_version: &'static str,
    pub lease_id: CredentialLifecycleLeaseId,
    pub revision: u64,
    pub state: CredentialLifecycleLeaseState,
    pub interaction: CliInteraction,
    pub deadline_remaining_ms: u64,
    pub idle_remaining_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CredentialLifecycleLeaseCompletion {
    pub schema_version: &'static str,
    pub lease_id: CredentialLifecycleLeaseId,
    pub outcome: CredentialLifecycleTerminalOutcome,
    pub postcondition: Option<CredentialLifecycleSuccessPostcondition>,
}

/// Unique internal authority held by the future process/interaction owner. It cannot be
/// serialized or cloned; after terminal completion its identifier no longer resolves.
pub struct CredentialLifecycleLease {
    id: CredentialLifecycleLeaseId,
    target: CredentialLifecycleLeaseTarget,
    plan: CredentialLifecyclePlan,
}

impl fmt::Debug for CredentialLifecycleLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialLifecycleLease")
            .field("lease_id", &self.id)
            .field("operation", &self.plan.operation())
            .finish()
    }
}

impl CredentialLifecycleLease {
    pub fn id(&self) -> CredentialLifecycleLeaseId {
        self.id
    }

    pub fn plan(&self) -> &CredentialLifecyclePlan {
        &self.plan
    }
}

/// Consume-once proof that a stale lease was observed and its process/callback resources
/// must be cleaned up before the occupied target can be released.
pub struct CredentialLifecycleStaleRecoveryTicket {
    id: CredentialLifecycleLeaseId,
    target: CredentialLifecycleLeaseTarget,
    revision: u64,
    reason: CredentialLifecycleStaleReason,
}

impl fmt::Debug for CredentialLifecycleStaleRecoveryTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialLifecycleStaleRecoveryTicket")
            .field("lease_id", &self.id)
            .field("revision", &self.revision)
            .field("reason", &self.reason)
            .finish()
    }
}

impl CredentialLifecycleStaleRecoveryTicket {
    pub fn lease_id(&self) -> CredentialLifecycleLeaseId {
        self.id
    }

    pub fn reason(&self) -> CredentialLifecycleStaleReason {
        self.reason
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum CredentialLifecycleLeaseTarget {
    Profile(CredentialProfileKey),
    Implicit {
        scope: CredentialScope,
        provider: CredentialProviderId,
        binding: CredentialProfileBinding,
    },
}

struct CredentialLifecycleLeaseRecord {
    id: CredentialLifecycleLeaseId,
    revision: u64,
    state: CredentialLifecycleLeaseState,
    interaction: CliInteraction,
    last_activity: Instant,
    deadline: Instant,
}

struct CredentialLifecycleCoordinatorState {
    next_sequence: u64,
    leases: BTreeMap<CredentialLifecycleLeaseTarget, CredentialLifecycleLeaseRecord>,
}

/// Process-local lifecycle coordinator. Construction is single-owner for one trusted
/// process epoch, preventing two independent maps from admitting duplicate login/callback
/// ownership for that epoch. Its debug view exposes only safe counts and instance metadata.
pub struct CredentialLifecycleCoordinator {
    process_epoch: CredentialProcessEpoch,
    coordinator_instance: u64,
    idle_timeout: CredentialLifecycleIdleTimeout,
    state: Mutex<CredentialLifecycleCoordinatorState>,
}

impl fmt::Debug for CredentialLifecycleCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let active_count = self
            .state
            .lock()
            .map(|state| state.leases.len())
            .unwrap_or_default();
        formatter
            .debug_struct("CredentialLifecycleCoordinator")
            .field("schema_version", &CREDENTIAL_LIFECYCLE_COORDINATOR_V1)
            .field("coordinator_instance", &self.coordinator_instance)
            .field("active_count", &active_count)
            .finish()
    }
}

impl CredentialLifecycleCoordinator {
    pub fn new(
        process_epoch: CredentialProcessEpoch,
        idle_timeout: CredentialLifecycleIdleTimeout,
    ) -> Result<Self, CredentialLifecycleCoordinatorError> {
        let epoch = process_epoch.get();
        let epochs = ACTIVE_COORDINATOR_EPOCHS.get_or_init(|| Mutex::new(BTreeSet::new()));
        let mut active_epochs = epochs.lock().map_err(|_| lock_poisoned())?;
        if active_epochs.contains(&epoch) {
            return Err(coordinator_already_active());
        }
        if active_epochs.len() >= MAX_REGISTERED_CREDENTIAL_LIFECYCLE_EPOCHS {
            return Err(coordinator_registry_full());
        }
        active_epochs.insert(epoch);
        drop(active_epochs);

        let coordinator_instance = match NEXT_COORDINATOR_INSTANCE.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| current.checked_add(1),
        ) {
            Ok(instance) => instance,
            Err(_) => {
                unregister_epoch(epoch);
                return Err(coordinator_id_exhausted());
            },
        };
        Ok(Self {
            process_epoch,
            coordinator_instance,
            idle_timeout,
            state: Mutex::new(CredentialLifecycleCoordinatorState {
                next_sequence: 1,
                leases: BTreeMap::new(),
            }),
        })
    }

    /// Begin one exact login and invalidate any cached readiness before the authentication
    /// directory can be mutated. A target remains occupied until normal completion or
    /// confirmed stale-resource cleanup.
    pub fn begin_login(
        &self,
        status_cache: &CredentialVerifiedStatusCache,
        plan: CredentialLifecyclePlan,
        now: CredentialLifecycleCoordinatorInstant,
    ) -> Result<CredentialLifecycleLease, CredentialLifecycleCoordinatorError> {
        if plan.operation() != CredentialLifecycleOperation::Login {
            return Err(wrong_operation());
        }
        let timeout = Duration::from_secs(
            plan.timeout_secs()
                .map(u64::from)
                .unwrap_or_else(|| DEFAULT_CREDENTIAL_LOGIN_TIMEOUT.as_secs()),
        );
        if timeout.is_zero() || timeout > MAX_CREDENTIAL_LOGIN_TIMEOUT {
            return Err(invalid_login_timeout());
        }
        let deadline = now.0.checked_add(timeout).ok_or_else(time_overflow)?;
        let target = lease_target(&plan);

        let mut state = self.state.lock().map_err(|_| lock_poisoned())?;
        if state.leases.contains_key(&target) {
            return Err(lease_already_active());
        }
        if state.leases.len() >= MAX_ACTIVE_CREDENTIAL_LIFECYCLE_LEASES {
            return Err(capacity_exceeded());
        }
        if let Err(error) = status_cache
            .invalidate_after_lifecycle_mutation_for_process_epoch(&plan, self.process_epoch)
        {
            return Err(if error.code
                == crate::credential_status_cache::CredentialStatusCacheErrorCode::ProcessEpochMismatch
            {
                process_epoch_mismatch()
            } else {
                status_invalidation_failed()
            });
        }

        let sequence = state.next_sequence;
        state.next_sequence = state
            .next_sequence
            .checked_add(1)
            .ok_or_else(lease_id_exhausted)?;
        let id = CredentialLifecycleLeaseId {
            process_epoch: self.process_epoch.get(),
            coordinator_instance: self.coordinator_instance,
            sequence,
        };
        state.leases.insert(
            target.clone(),
            CredentialLifecycleLeaseRecord {
                id,
                revision: 1,
                state: CredentialLifecycleLeaseState::Running,
                interaction: plan.interaction(),
                last_activity: now.0,
                deadline,
            },
        );
        Ok(CredentialLifecycleLease { id, target, plan })
    }

    pub fn snapshot(
        &self,
        lease: &CredentialLifecycleLease,
        now: CredentialLifecycleCoordinatorInstant,
    ) -> Result<CredentialLifecycleLeaseSnapshot, CredentialLifecycleCoordinatorError> {
        let state = self.state.lock().map_err(|_| lock_poisoned())?;
        let record = exact_record(&state, lease)?;
        snapshot_for(record, self.idle_timeout, now)
    }

    /// Publish only a pending class. Sensitive presentation/input material remains owned
    /// by the Phase 4E bridge and never enters this state machine.
    pub fn publish_pending(
        &self,
        lease: &CredentialLifecycleLease,
        expected_revision: u64,
        kind: CredentialLifecyclePendingKind,
        now: CredentialLifecycleCoordinatorInstant,
    ) -> Result<CredentialLifecycleLeaseSnapshot, CredentialLifecycleCoordinatorError> {
        let mut state = self.state.lock().map_err(|_| lock_poisoned())?;
        let record = exact_record_mut(&mut state, lease)?;
        ensure_live(record, self.idle_timeout, now)?;
        ensure_revision(record, expected_revision)?;
        if matches!(record.state, CredentialLifecycleLeaseState::Cancelling)
            || matches!(
                record.state,
                CredentialLifecycleLeaseState::RecoveryRequired(_)
            )
        {
            return Err(invalid_transition());
        }
        record.revision = next_revision(record.revision)?;
        record.state = CredentialLifecycleLeaseState::Pending(kind);
        record.last_activity = now.0;
        snapshot_for(record, self.idle_timeout, now)
    }

    /// Resume process-owned work after the exact pending revision is satisfied.
    pub fn resume(
        &self,
        lease: &CredentialLifecycleLease,
        expected_revision: u64,
        now: CredentialLifecycleCoordinatorInstant,
    ) -> Result<CredentialLifecycleLeaseSnapshot, CredentialLifecycleCoordinatorError> {
        let mut state = self.state.lock().map_err(|_| lock_poisoned())?;
        let record = exact_record_mut(&mut state, lease)?;
        ensure_live(record, self.idle_timeout, now)?;
        ensure_revision(record, expected_revision)?;
        if !matches!(record.state, CredentialLifecycleLeaseState::Pending(_)) {
            return Err(invalid_transition());
        }
        record.revision = next_revision(record.revision)?;
        record.state = CredentialLifecycleLeaseState::Running;
        record.last_activity = now.0;
        snapshot_for(record, self.idle_timeout, now)
    }

    pub fn heartbeat(
        &self,
        lease: &CredentialLifecycleLease,
        now: CredentialLifecycleCoordinatorInstant,
    ) -> Result<CredentialLifecycleLeaseSnapshot, CredentialLifecycleCoordinatorError> {
        let mut state = self.state.lock().map_err(|_| lock_poisoned())?;
        let record = exact_record_mut(&mut state, lease)?;
        ensure_live(record, self.idle_timeout, now)?;
        if matches!(record.state, CredentialLifecycleLeaseState::Cancelling)
            || matches!(
                record.state,
                CredentialLifecycleLeaseState::RecoveryRequired(_)
            )
        {
            return Err(invalid_transition());
        }
        record.last_activity = now.0;
        snapshot_for(record, self.idle_timeout, now)
    }

    /// Request process-tree and interaction-bridge cancellation. The target remains
    /// occupied until `complete` confirms terminal cleanup.
    pub fn request_cancel(
        &self,
        lease: &CredentialLifecycleLease,
        now: CredentialLifecycleCoordinatorInstant,
    ) -> Result<CredentialLifecycleLeaseSnapshot, CredentialLifecycleCoordinatorError> {
        let mut state = self.state.lock().map_err(|_| lock_poisoned())?;
        let record = exact_record_mut(&mut state, lease)?;
        ensure_live(record, self.idle_timeout, now)?;
        if !matches!(record.state, CredentialLifecycleLeaseState::Cancelling) {
            record.revision = next_revision(record.revision)?;
            record.state = CredentialLifecycleLeaseState::Cancelling;
            record.last_activity = now.0;
        }
        snapshot_for(record, self.idle_timeout, now)
    }

    /// Finish after the process and any callback/input resources are terminal. Successful
    /// login returns only `FreshStatusRequired`; it never produces ready state directly.
    pub fn complete(
        &self,
        lease: &CredentialLifecycleLease,
        outcome: CredentialLifecycleTerminalOutcome,
        now: CredentialLifecycleCoordinatorInstant,
    ) -> Result<CredentialLifecycleLeaseCompletion, CredentialLifecycleCoordinatorError> {
        let mut state = self.state.lock().map_err(|_| lock_poisoned())?;
        let record = exact_record(&state, lease)?;
        if matches!(
            record.state,
            CredentialLifecycleLeaseState::RecoveryRequired(_)
        ) {
            return Err(invalid_transition());
        }
        if outcome == CredentialLifecycleTerminalOutcome::Succeeded {
            ensure_live(record, self.idle_timeout, now)?;
            if matches!(record.state, CredentialLifecycleLeaseState::Cancelling) {
                return Err(invalid_transition());
            }
        }
        state.leases.remove(&lease.target);
        Ok(CredentialLifecycleLeaseCompletion {
            schema_version: CREDENTIAL_LIFECYCLE_COORDINATOR_V1,
            lease_id: lease.id,
            outcome,
            postcondition: (outcome == CredentialLifecycleTerminalOutcome::Succeeded)
                .then(|| lifecycle_success_postcondition(&lease.plan)),
        })
    }

    /// Mark bounded stale leases for external cleanup. Marked targets remain occupied;
    /// callers must stop/reap the child and callback/input resources before confirming a
    /// ticket with `finish_stale_recovery`. A ticket is issued once; losing it fails
    /// closed until process restart rather than risking concurrent cleanup owners.
    pub fn stale_recovery_tickets(
        &self,
        now: CredentialLifecycleCoordinatorInstant,
    ) -> Result<Vec<CredentialLifecycleStaleRecoveryTicket>, CredentialLifecycleCoordinatorError>
    {
        let mut state = self.state.lock().map_err(|_| lock_poisoned())?;
        let mut due = Vec::with_capacity(state.leases.len());
        for (target, record) in &state.leases {
            let reason = match record.state {
                CredentialLifecycleLeaseState::RecoveryRequired(_) => None,
                _ => stale_reason(record, self.idle_timeout, now)?,
            };
            if let Some(reason) = reason {
                if !matches!(
                    record.state,
                    CredentialLifecycleLeaseState::RecoveryRequired(_)
                ) && record.revision == u64::MAX
                {
                    return Err(revision_exhausted());
                }
                due.push((target.clone(), reason));
            }
        }

        let mut tickets = Vec::with_capacity(due.len());
        for (target, reason) in due {
            let record = state
                .leases
                .get_mut(&target)
                .expect("preflighted lifecycle target remains present under one lock");
            record.revision = next_revision(record.revision)?;
            record.state = CredentialLifecycleLeaseState::RecoveryRequired(reason);
            tickets.push(CredentialLifecycleStaleRecoveryTicket {
                id: record.id,
                target,
                revision: record.revision,
                reason,
            });
        }
        Ok(tickets)
    }

    /// Release one stale target only after the product owner confirms process/callback
    /// cleanup. Consuming the ticket prevents accidental reuse by one caller.
    pub fn finish_stale_recovery(
        &self,
        ticket: CredentialLifecycleStaleRecoveryTicket,
    ) -> Result<CredentialLifecycleLeaseId, CredentialLifecycleCoordinatorError> {
        let mut state = self.state.lock().map_err(|_| lock_poisoned())?;
        let Some(record) = state.leases.get(&ticket.target) else {
            return Err(lease_not_found());
        };
        if record.id != ticket.id {
            return Err(lease_mismatch());
        }
        if record.revision != ticket.revision {
            return Err(stale_revision());
        }
        if !matches!(
            record.state,
            CredentialLifecycleLeaseState::RecoveryRequired(_)
        ) {
            return Err(invalid_transition());
        }
        state.leases.remove(&ticket.target);
        Ok(ticket.id)
    }

    pub fn active_count(&self) -> Result<usize, CredentialLifecycleCoordinatorError> {
        self.state
            .lock()
            .map(|state| state.leases.len())
            .map_err(|_| lock_poisoned())
    }
}

impl Drop for CredentialLifecycleCoordinator {
    fn drop(&mut self) {
        let has_no_active_leases = self
            .state
            .get_mut()
            .map(|state| state.leases.is_empty())
            .unwrap_or(false);
        if has_no_active_leases {
            unregister_epoch(self.process_epoch.get());
        }
    }
}

fn unregister_epoch(epoch: u64) {
    let Some(epochs) = ACTIVE_COORDINATOR_EPOCHS.get() else {
        return;
    };
    if let Ok(mut active_epochs) = epochs.lock() {
        active_epochs.remove(&epoch);
    }
}

fn lease_target(plan: &CredentialLifecyclePlan) -> CredentialLifecycleLeaseTarget {
    if let Some(key) = plan.selected_profile_key() {
        return CredentialLifecycleLeaseTarget::Profile(key.clone());
    }
    let (provider, binding) = plan
        .implicit_identity()
        .expect("validated lifecycle plans always have one target mode");
    CredentialLifecycleLeaseTarget::Implicit {
        scope: plan.scope().clone(),
        provider: provider.clone(),
        binding: binding.clone(),
    }
}

fn exact_record<'a>(
    state: &'a CredentialLifecycleCoordinatorState,
    lease: &CredentialLifecycleLease,
) -> Result<&'a CredentialLifecycleLeaseRecord, CredentialLifecycleCoordinatorError> {
    let record = state
        .leases
        .get(&lease.target)
        .ok_or_else(lease_not_found)?;
    if record.id != lease.id {
        return Err(lease_mismatch());
    }
    Ok(record)
}

fn exact_record_mut<'a>(
    state: &'a mut CredentialLifecycleCoordinatorState,
    lease: &CredentialLifecycleLease,
) -> Result<&'a mut CredentialLifecycleLeaseRecord, CredentialLifecycleCoordinatorError> {
    let record = state
        .leases
        .get_mut(&lease.target)
        .ok_or_else(lease_not_found)?;
    if record.id != lease.id {
        return Err(lease_mismatch());
    }
    Ok(record)
}

fn ensure_revision(
    record: &CredentialLifecycleLeaseRecord,
    expected_revision: u64,
) -> Result<(), CredentialLifecycleCoordinatorError> {
    if record.revision != expected_revision {
        return Err(stale_revision());
    }
    Ok(())
}

fn ensure_live(
    record: &CredentialLifecycleLeaseRecord,
    idle_timeout: CredentialLifecycleIdleTimeout,
    now: CredentialLifecycleCoordinatorInstant,
) -> Result<(), CredentialLifecycleCoordinatorError> {
    if stale_reason(record, idle_timeout, now)?.is_some() {
        return Err(lease_stale());
    }
    Ok(())
}

fn stale_reason(
    record: &CredentialLifecycleLeaseRecord,
    idle_timeout: CredentialLifecycleIdleTimeout,
    now: CredentialLifecycleCoordinatorInstant,
) -> Result<Option<CredentialLifecycleStaleReason>, CredentialLifecycleCoordinatorError> {
    if now.0 < record.last_activity {
        return Err(clock_regression());
    }
    if now.0 >= record.deadline {
        return Ok(Some(CredentialLifecycleStaleReason::Deadline));
    }
    if now.0.duration_since(record.last_activity) >= idle_timeout.0 {
        return Ok(Some(CredentialLifecycleStaleReason::Idle));
    }
    Ok(None)
}

fn snapshot_for(
    record: &CredentialLifecycleLeaseRecord,
    idle_timeout: CredentialLifecycleIdleTimeout,
    now: CredentialLifecycleCoordinatorInstant,
) -> Result<CredentialLifecycleLeaseSnapshot, CredentialLifecycleCoordinatorError> {
    if now.0 < record.last_activity {
        return Err(clock_regression());
    }
    let deadline_remaining = record.deadline.saturating_duration_since(now.0);
    let idle_deadline = record
        .last_activity
        .checked_add(idle_timeout.0)
        .ok_or_else(time_overflow)?;
    let idle_remaining = idle_deadline.saturating_duration_since(now.0);
    Ok(CredentialLifecycleLeaseSnapshot {
        schema_version: CREDENTIAL_LIFECYCLE_COORDINATOR_V1,
        lease_id: record.id,
        revision: record.revision,
        state: record.state,
        interaction: record.interaction,
        deadline_remaining_ms: duration_millis(deadline_remaining),
        idle_remaining_ms: duration_millis(idle_remaining),
    })
}

fn duration_millis(value: Duration) -> u64 {
    u64::try_from(value.as_millis()).unwrap_or(u64::MAX)
}

fn next_revision(value: u64) -> Result<u64, CredentialLifecycleCoordinatorError> {
    value.checked_add(1).ok_or_else(revision_exhausted)
}

const fn invalid_idle_timeout() -> CredentialLifecycleCoordinatorError {
    CredentialLifecycleCoordinatorError::new(
        CredentialLifecycleCoordinatorErrorCode::InvalidIdleTimeout,
        "lifecycle_coordinator.idle_timeout",
        "the lifecycle idle timeout must be positive and within its fixed ceiling",
    )
}

const fn wrong_operation() -> CredentialLifecycleCoordinatorError {
    CredentialLifecycleCoordinatorError::new(
        CredentialLifecycleCoordinatorErrorCode::WrongOperation,
        "lifecycle_coordinator.operation",
        "the interactive lifecycle coordinator accepts only exact login plans",
    )
}

const fn invalid_login_timeout() -> CredentialLifecycleCoordinatorError {
    CredentialLifecycleCoordinatorError::new(
        CredentialLifecycleCoordinatorErrorCode::InvalidLoginTimeout,
        "lifecycle_coordinator.login_timeout",
        "the login timeout must be positive and within its fixed ceiling",
    )
}

const fn process_epoch_mismatch() -> CredentialLifecycleCoordinatorError {
    CredentialLifecycleCoordinatorError::new(
        CredentialLifecycleCoordinatorErrorCode::ProcessEpochMismatch,
        "lifecycle_coordinator.process_epoch",
        "the verified-status cache belongs to a different process epoch",
    )
}

const fn status_invalidation_failed() -> CredentialLifecycleCoordinatorError {
    CredentialLifecycleCoordinatorError::new(
        CredentialLifecycleCoordinatorErrorCode::StatusInvalidationFailed,
        "lifecycle_coordinator.status_cache",
        "verified authentication status could not be invalidated",
    )
}

const fn lease_already_active() -> CredentialLifecycleCoordinatorError {
    CredentialLifecycleCoordinatorError::new(
        CredentialLifecycleCoordinatorErrorCode::LeaseAlreadyActive,
        "lifecycle_coordinator.target",
        "an authentication login is already active for this exact target",
    )
}

const fn capacity_exceeded() -> CredentialLifecycleCoordinatorError {
    CredentialLifecycleCoordinatorError::new(
        CredentialLifecycleCoordinatorErrorCode::CapacityExceeded,
        "lifecycle_coordinator.leases",
        "the lifecycle coordinator reached its fixed active-lease limit",
    )
}

const fn lease_not_found() -> CredentialLifecycleCoordinatorError {
    CredentialLifecycleCoordinatorError::new(
        CredentialLifecycleCoordinatorErrorCode::LeaseNotFound,
        "lifecycle_coordinator.lease",
        "the lifecycle lease is not active",
    )
}

const fn lease_mismatch() -> CredentialLifecycleCoordinatorError {
    CredentialLifecycleCoordinatorError::new(
        CredentialLifecycleCoordinatorErrorCode::LeaseMismatch,
        "lifecycle_coordinator.lease",
        "the lifecycle lease does not belong to this active target",
    )
}

const fn stale_revision() -> CredentialLifecycleCoordinatorError {
    CredentialLifecycleCoordinatorError::new(
        CredentialLifecycleCoordinatorErrorCode::StaleRevision,
        "lifecycle_coordinator.revision",
        "the lifecycle interaction revision is stale",
    )
}

const fn invalid_transition() -> CredentialLifecycleCoordinatorError {
    CredentialLifecycleCoordinatorError::new(
        CredentialLifecycleCoordinatorErrorCode::InvalidTransition,
        "lifecycle_coordinator.state",
        "the requested lifecycle state transition is not allowed",
    )
}

const fn lease_stale() -> CredentialLifecycleCoordinatorError {
    CredentialLifecycleCoordinatorError::new(
        CredentialLifecycleCoordinatorErrorCode::LeaseStale,
        "lifecycle_coordinator.lease",
        "the lifecycle lease requires stale-resource recovery",
    )
}

const fn clock_regression() -> CredentialLifecycleCoordinatorError {
    CredentialLifecycleCoordinatorError::new(
        CredentialLifecycleCoordinatorErrorCode::ClockRegression,
        "lifecycle_coordinator.time",
        "the lifecycle observation time moved backward",
    )
}

const fn revision_exhausted() -> CredentialLifecycleCoordinatorError {
    CredentialLifecycleCoordinatorError::new(
        CredentialLifecycleCoordinatorErrorCode::RevisionExhausted,
        "lifecycle_coordinator.revision",
        "the lifecycle interaction revision space is exhausted",
    )
}

const fn time_overflow() -> CredentialLifecycleCoordinatorError {
    CredentialLifecycleCoordinatorError::new(
        CredentialLifecycleCoordinatorErrorCode::TimeOverflow,
        "lifecycle_coordinator.time",
        "the lifecycle deadline could not be represented",
    )
}

const fn coordinator_id_exhausted() -> CredentialLifecycleCoordinatorError {
    CredentialLifecycleCoordinatorError::new(
        CredentialLifecycleCoordinatorErrorCode::CoordinatorIdExhausted,
        "lifecycle_coordinator.instance",
        "the process-local lifecycle coordinator identity space is exhausted",
    )
}

const fn coordinator_already_active() -> CredentialLifecycleCoordinatorError {
    CredentialLifecycleCoordinatorError::new(
        CredentialLifecycleCoordinatorErrorCode::CoordinatorAlreadyActive,
        "lifecycle_coordinator.instance",
        "a lifecycle coordinator already owns this process epoch",
    )
}

const fn coordinator_registry_full() -> CredentialLifecycleCoordinatorError {
    CredentialLifecycleCoordinatorError::new(
        CredentialLifecycleCoordinatorErrorCode::CoordinatorRegistryFull,
        "lifecycle_coordinator.instance",
        "the bounded process-epoch coordinator registry is full",
    )
}

const fn lease_id_exhausted() -> CredentialLifecycleCoordinatorError {
    CredentialLifecycleCoordinatorError::new(
        CredentialLifecycleCoordinatorErrorCode::LeaseIdExhausted,
        "lifecycle_coordinator.lease",
        "the process-local lifecycle lease identity space is exhausted",
    )
}

const fn lock_poisoned() -> CredentialLifecycleCoordinatorError {
    CredentialLifecycleCoordinatorError::new(
        CredentialLifecycleCoordinatorErrorCode::LockPoisoned,
        "lifecycle_coordinator",
        "the lifecycle coordinator is unavailable",
    )
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        sync::{Arc, Barrier},
        thread,
    };

    #[cfg(unix)]
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering as AtomicOrdering},
    };

    use static_assertions::assert_not_impl_any;

    use super::*;
    use crate::{
        credential_profiles::{
            CreateCredentialProfileReference, CredentialProfileAvailability,
            CredentialProfileError, CredentialProfileMetadata, CredentialProfileRegistry,
            CredentialProfileRegistrySnapshot, CredentialProfileRevision, CredentialProfileStatus,
            SetCredentialProfileDisabled, UpdateCredentialProfileMetadata,
        },
        credential_status_cache::CredentialPolicyRevision,
        manifest::{
            AuthContract, AuthKind, AuthLifecycle, AuthRequirement, AuthState, AuthStorage,
            LifecycleHook, LifecycleJsonPredicate, LifecycleJsonScalar, LifecycleObservedAuthState,
            LifecycleStatusObservation, LifecycleStatusOutputFormat, LifecycleStatusRule,
            ProfileSelection, RuntimeRequirements, SkillRuntimeContract,
            SkillRuntimeContractVersion, StdinContract, WorkingDirectoryContract,
        },
        manifest_validation::validate_skill_runtime_contract,
    };

    #[cfg(unix)]
    use crate::{
        credential_lifecycle_observation::{
            evaluate_lifecycle_status, CredentialLifecycleCommandObservation,
            CredentialLifecycleTermination,
        },
        credential_status_cache::{
            CredentialAuthDirectoryRevision, CredentialStatusCacheErrorCode,
            CredentialStatusCacheInstant, CredentialStatusCacheTtl,
        },
        scoped_paths::{ScopedPathAuthority, ScopedPathComponent},
    };

    #[cfg(unix)]
    static NEXT_DIRECTORY_FIXTURE: AtomicU64 = AtomicU64::new(1);

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

    fn contract(
        selection: ProfileSelection,
        login_timeout_secs: Option<u32>,
    ) -> SkillRuntimeContract {
        let storage = if selection == ProfileSelection::Implicit {
            AuthStorage::CliOwned
        } else {
            AuthStorage::ScopedDirectory {
                namespace: "provider".to_owned(),
                partition_by_profile: true,
            }
        };
        SkillRuntimeContract {
            schema_version: SkillRuntimeContractVersion::v1(),
            requires: RuntimeRequirements {
                bins: BTreeSet::from(["provider-cli".to_owned()]),
                entrypoint: Default::default(),
                environment: Default::default(),
            },
            runtime: crate::manifest::RuntimeProtocol::Cli {
                command_prefix: vec!["resource".to_owned()],
                interaction: CliInteraction::Batch,
                stdin: StdinContract::default(),
                working_directory: WorkingDirectoryContract::default(),
                limits: Default::default(),
            },
            auth: AuthContract {
                kind: AuthKind::CliProfile,
                requirement: AuthRequirement::Required,
                provider: Some("provider".to_owned()),
                profile_selection: selection,
                storage,
                lifecycle: AuthLifecycle {
                    status: Some(LifecycleHook {
                        args: vec!["auth".to_owned(), "status".to_owned(), "--json".to_owned()],
                        interaction: CliInteraction::Batch,
                        timeout_secs: Some(30),
                    }),
                    status_observation: Some(LifecycleStatusObservation {
                        format: LifecycleStatusOutputFormat::Json,
                        rules: vec![LifecycleStatusRule {
                            state: LifecycleObservedAuthState::Ready,
                            exit_codes: BTreeSet::from([0]),
                            all: vec![LifecycleJsonPredicate::Equals {
                                pointer: "/ready".to_owned(),
                                value: LifecycleJsonScalar::Boolean { value: true },
                            }],
                        }],
                    }),
                    login: Some(LifecycleHook {
                        args: vec!["auth".to_owned(), "login".to_owned()],
                        interaction: CliInteraction::Pty,
                        timeout_secs: login_timeout_secs,
                    }),
                    ..AuthLifecycle::default()
                },
                ..AuthContract::default()
            },
            policy_floor: Default::default(),
        }
    }

    fn profile(alias: &str, revision: u64) -> CredentialProfileStatus {
        let key = CredentialProfileKey::new(
            scope(),
            "provider",
            alias,
            CredentialProfileBinding::Provider,
        )
        .expect("key");
        let metadata = CredentialProfileMetadata::new(
            key,
            None,
            false,
            CredentialProfileAvailability::Enabled,
            CredentialProfileRevision::new(revision).expect("revision"),
        )
        .expect("metadata");
        CredentialProfileStatus::new(metadata, AuthState::Missing).expect("status")
    }

    fn profile_plan(
        alias: &str,
        revision: u64,
        operation: CredentialLifecycleOperation,
        login_timeout_secs: Option<u32>,
    ) -> CredentialLifecyclePlan {
        let contract = contract(
            ProfileSelection::Selectable { default: None },
            login_timeout_secs,
        );
        let validated = validate_skill_runtime_contract(&contract).expect("contract");
        let profile = profile(alias, revision);
        CredentialLifecyclePlan::for_profile(
            &OneRegistry(profile.clone()),
            validated,
            profile.key(),
            operation,
        )
        .expect("plan")
    }

    fn implicit_plan(operation: CredentialLifecycleOperation) -> CredentialLifecyclePlan {
        let contract = contract(ProfileSelection::Implicit, Some(300));
        let validated = validate_skill_runtime_contract(&contract).expect("contract");
        CredentialLifecyclePlan::for_implicit(validated, scope(), operation).expect("plan")
    }

    fn cache(epoch: u64) -> CredentialVerifiedStatusCache {
        CredentialVerifiedStatusCache::new(
            CredentialProcessEpoch::new(epoch).expect("epoch"),
            CredentialPolicyRevision::new(1).expect("policy"),
        )
    }

    fn coordinator(epoch: u64, idle_timeout: Duration) -> CredentialLifecycleCoordinator {
        CredentialLifecycleCoordinator::new(
            CredentialProcessEpoch::new(epoch).expect("epoch"),
            CredentialLifecycleIdleTimeout::new(idle_timeout).expect("idle timeout"),
        )
        .expect("coordinator")
    }

    fn later(
        instant: CredentialLifecycleCoordinatorInstant,
        duration: Duration,
    ) -> CredentialLifecycleCoordinatorInstant {
        CredentialLifecycleCoordinatorInstant(instant.0.checked_add(duration).expect("test time"))
    }

    #[test]
    fn exact_target_is_single_flight_but_distinct_profiles_can_login() {
        let coordinator = coordinator(1, Duration::from_secs(30));
        let cache = cache(1);
        let now = CredentialLifecycleCoordinatorInstant::now();
        let work = coordinator
            .begin_login(
                &cache,
                profile_plan("work", 1, CredentialLifecycleOperation::Login, Some(300)),
                now,
            )
            .expect("work login");

        let duplicate = coordinator
            .begin_login(
                &cache,
                profile_plan("work", 2, CredentialLifecycleOperation::Login, Some(300)),
                now,
            )
            .expect_err("same logical profile remains occupied across revision changes");
        assert_eq!(
            duplicate.code,
            CredentialLifecycleCoordinatorErrorCode::LeaseAlreadyActive
        );

        let personal = coordinator
            .begin_login(
                &cache,
                profile_plan(
                    "personal",
                    1,
                    CredentialLifecycleOperation::Login,
                    Some(300),
                ),
                now,
            )
            .expect("distinct profile");
        assert_eq!(coordinator.active_count().unwrap(), 2);
        coordinator
            .complete(
                &work,
                CredentialLifecycleTerminalOutcome::ProcessFailed,
                now,
            )
            .unwrap();
        coordinator
            .complete(
                &personal,
                CredentialLifecycleTerminalOutcome::ProcessFailed,
                now,
            )
            .unwrap();
    }

    #[test]
    fn implicit_target_has_the_same_single_flight_boundary() {
        let coordinator = coordinator(2, Duration::from_secs(30));
        let cache = cache(2);
        let now = CredentialLifecycleCoordinatorInstant::now();
        let lease = coordinator
            .begin_login(
                &cache,
                implicit_plan(CredentialLifecycleOperation::Login),
                now,
            )
            .expect("implicit login");
        assert_eq!(
            coordinator
                .begin_login(
                    &cache,
                    implicit_plan(CredentialLifecycleOperation::Login),
                    now,
                )
                .expect_err("duplicate implicit login")
                .code,
            CredentialLifecycleCoordinatorErrorCode::LeaseAlreadyActive
        );
        coordinator
            .complete(&lease, CredentialLifecycleTerminalOutcome::Cancelled, now)
            .unwrap();
    }

    #[test]
    fn non_login_plan_is_rejected_before_a_lease_exists() {
        let coordinator = coordinator(3, Duration::from_secs(30));
        let cache = cache(3);
        let error = coordinator
            .begin_login(
                &cache,
                profile_plan("work", 1, CredentialLifecycleOperation::Status, Some(300)),
                CredentialLifecycleCoordinatorInstant::now(),
            )
            .expect_err("status cannot become a login lease");
        assert_eq!(
            error.code,
            CredentialLifecycleCoordinatorErrorCode::WrongOperation
        );
        assert_eq!(coordinator.active_count().unwrap(), 0);
    }

    #[test]
    fn status_cache_must_share_the_exact_process_epoch() {
        let coordinator = coordinator(17, Duration::from_secs(30));
        let wrong_cache = cache(18);
        let error = coordinator
            .begin_login(
                &wrong_cache,
                profile_plan("work", 1, CredentialLifecycleOperation::Login, Some(300)),
                CredentialLifecycleCoordinatorInstant::now(),
            )
            .expect_err("cross-epoch cache");
        assert_eq!(
            error.code,
            CredentialLifecycleCoordinatorErrorCode::ProcessEpochMismatch
        );
        assert_eq!(coordinator.active_count().unwrap(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn login_atomically_invalidates_an_observation_started_before_it() {
        let epoch = 21;
        let coordinator = coordinator(epoch, Duration::from_secs(30));
        let cache = cache(epoch);
        let now = CredentialLifecycleCoordinatorInstant::now();
        let status_plan = profile_plan("work", 1, CredentialLifecycleOperation::Status, Some(300));
        let login_plan = profile_plan("work", 1, CredentialLifecycleOperation::Login, Some(300));

        let sequence = NEXT_DIRECTORY_FIXTURE.fetch_add(1, AtomicOrdering::Relaxed);
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "tool-runtime-lifecycle-coordinator-{}-{sequence}",
                std::process::id()
            ));
        let scopes_root = root.join("scopes");
        let principal_root = scopes_root.join("owner");
        let workspace_root = principal_root.join("default");
        let auth_root = workspace_root.join("auth");
        let profile_root = auth_root.join("profile-work");
        fs::create_dir_all(&profile_root).unwrap();
        for (path, mode) in [
            (&root, 0o700),
            (&scopes_root, 0o755),
            (&principal_root, 0o755),
            (&workspace_root, 0o755),
            (&auth_root, 0o700),
            (&profile_root, 0o700),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
        let directory = ScopedPathAuthority::open(&scopes_root)
            .unwrap()
            .resolve_profile_root(
                status_plan.selected_profile_key().unwrap(),
                ScopedPathComponent::new("profile-work").unwrap(),
            )
            .unwrap();

        let ticket = cache
            .begin_observation(
                &status_plan,
                &directory,
                CredentialAuthDirectoryRevision::new(1).unwrap(),
            )
            .unwrap();
        let observation = CredentialLifecycleCommandObservation::new(
            CredentialLifecycleOperation::Status,
            CredentialLifecycleTermination::Exited { code: 0 },
            br#"{"ready":true}"#,
            b"",
        )
        .unwrap();
        let result = evaluate_lifecycle_status(&status_plan, &observation).unwrap();

        let lease = coordinator
            .begin_login(&cache, login_plan, now)
            .expect("login starts");
        assert_eq!(
            cache
                .store_ready(
                    ticket,
                    result,
                    CredentialStatusCacheInstant::now(),
                    CredentialStatusCacheTtl::new(Duration::from_secs(30)).unwrap(),
                )
                .expect_err("pre-login observation is stale")
                .code,
            CredentialStatusCacheErrorCode::StaleObservation
        );
        coordinator
            .complete(
                &lease,
                CredentialLifecycleTerminalOutcome::ProcessFailed,
                now,
            )
            .unwrap();
        drop(directory);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn every_pending_class_is_typed_and_revision_bound() {
        let coordinator = coordinator(4, Duration::from_secs(30));
        let cache = cache(4);
        let now = CredentialLifecycleCoordinatorInstant::now();
        let lease = coordinator
            .begin_login(
                &cache,
                profile_plan("work", 1, CredentialLifecycleOperation::Login, Some(300)),
                now,
            )
            .unwrap();
        let mut revision = 1;
        for kind in [
            CredentialLifecyclePendingKind::BrowserCallback,
            CredentialLifecyclePendingKind::DeviceCode,
            CredentialLifecyclePendingKind::Otp,
            CredentialLifecyclePendingKind::Qr,
            CredentialLifecyclePendingKind::OperatorRequired,
        ] {
            let pending = coordinator
                .publish_pending(&lease, revision, kind, now)
                .expect("pending");
            revision += 1;
            assert_eq!(pending.revision, revision);
            assert_eq!(pending.state, CredentialLifecycleLeaseState::Pending(kind));
        }
        let stale = coordinator
            .resume(&lease, 1, now)
            .expect_err("old presentation cannot resume a newer challenge");
        assert_eq!(
            stale.code,
            CredentialLifecycleCoordinatorErrorCode::StaleRevision
        );

        let resumed = coordinator.resume(&lease, revision, now).expect("resume");
        assert_eq!(resumed.state, CredentialLifecycleLeaseState::Running);
        assert_eq!(resumed.revision, revision + 1);
    }

    #[test]
    fn cancellation_is_idempotent_and_requires_terminal_cleanup() {
        let coordinator = coordinator(5, Duration::from_secs(30));
        let cache = cache(5);
        let now = CredentialLifecycleCoordinatorInstant::now();
        let lease = coordinator
            .begin_login(
                &cache,
                profile_plan("work", 1, CredentialLifecycleOperation::Login, Some(300)),
                now,
            )
            .unwrap();
        let first = coordinator.request_cancel(&lease, now).expect("cancel");
        let second = coordinator
            .request_cancel(&lease, now)
            .expect("repeat cancel");
        assert_eq!(first.state, CredentialLifecycleLeaseState::Cancelling);
        assert_eq!(second.revision, first.revision);
        assert_eq!(coordinator.active_count().unwrap(), 1);

        assert_eq!(
            coordinator
                .complete(&lease, CredentialLifecycleTerminalOutcome::Succeeded, now,)
                .expect_err("cancelled work cannot report success")
                .code,
            CredentialLifecycleCoordinatorErrorCode::InvalidTransition
        );
        let completion = coordinator
            .complete(&lease, CredentialLifecycleTerminalOutcome::Cancelled, now)
            .expect("terminal cleanup");
        assert_eq!(
            completion.outcome,
            CredentialLifecycleTerminalOutcome::Cancelled
        );
        assert_eq!(completion.postcondition, None);
        assert_eq!(coordinator.active_count().unwrap(), 0);
    }

    #[test]
    fn success_never_claims_ready_and_requires_fresh_status() {
        let coordinator = coordinator(6, Duration::from_secs(30));
        let cache = cache(6);
        let now = CredentialLifecycleCoordinatorInstant::now();
        let lease = coordinator
            .begin_login(
                &cache,
                profile_plan("work", 1, CredentialLifecycleOperation::Login, Some(300)),
                now,
            )
            .unwrap();
        let completion = coordinator
            .complete(&lease, CredentialLifecycleTerminalOutcome::Succeeded, now)
            .unwrap();
        assert_eq!(
            completion.postcondition,
            Some(CredentialLifecycleSuccessPostcondition::FreshStatusRequired)
        );
        assert_eq!(coordinator.active_count().unwrap(), 0);
        assert_eq!(
            coordinator.snapshot(&lease, now).unwrap_err().code,
            CredentialLifecycleCoordinatorErrorCode::LeaseNotFound
        );
    }

    #[test]
    fn heartbeat_delays_idle_recovery_but_never_extends_absolute_deadline() {
        let coordinator = coordinator(7, Duration::from_secs(10));
        let cache = cache(7);
        let now = CredentialLifecycleCoordinatorInstant::now();
        let lease = coordinator
            .begin_login(
                &cache,
                profile_plan("work", 1, CredentialLifecycleOperation::Login, Some(20)),
                now,
            )
            .unwrap();
        coordinator
            .heartbeat(&lease, later(now, Duration::from_secs(9)))
            .expect("heartbeat");
        assert!(coordinator
            .stale_recovery_tickets(later(now, Duration::from_secs(18)))
            .unwrap()
            .is_empty());
        let tickets = coordinator
            .stale_recovery_tickets(later(now, Duration::from_secs(20)))
            .unwrap();
        assert_eq!(tickets.len(), 1);
        assert_eq!(
            tickets[0].reason(),
            CredentialLifecycleStaleReason::Deadline
        );
    }

    #[test]
    fn stale_recovery_keeps_target_occupied_until_cleanup_confirmation() {
        let coordinator = coordinator(8, Duration::from_secs(10));
        let cache = cache(8);
        let now = CredentialLifecycleCoordinatorInstant::now();
        let _lease = coordinator
            .begin_login(
                &cache,
                profile_plan("work", 1, CredentialLifecycleOperation::Login, Some(300)),
                now,
            )
            .unwrap();
        let mut tickets = coordinator
            .stale_recovery_tickets(later(now, Duration::from_secs(10)))
            .unwrap();
        assert_eq!(tickets.len(), 1);
        assert_eq!(tickets[0].reason(), CredentialLifecycleStaleReason::Idle);
        assert_eq!(
            coordinator
                .begin_login(
                    &cache,
                    profile_plan("work", 2, CredentialLifecycleOperation::Login, Some(300)),
                    later(now, Duration::from_secs(10)),
                )
                .expect_err("stale resources still own the target")
                .code,
            CredentialLifecycleCoordinatorErrorCode::LeaseAlreadyActive
        );
        let recovered = coordinator
            .finish_stale_recovery(tickets.pop().unwrap())
            .expect("cleanup confirmed");
        assert_eq!(recovered.sequence(), 1);
        let replacement = coordinator
            .begin_login(
                &cache,
                profile_plan("work", 2, CredentialLifecycleOperation::Login, Some(300)),
                later(now, Duration::from_secs(10)),
            )
            .expect("replacement after cleanup");
        assert_eq!(replacement.id().sequence(), 2);
    }

    #[test]
    fn stale_recovery_preflight_is_atomic_on_clock_regression() {
        let coordinator = coordinator(19, Duration::from_secs(10));
        let cache = cache(19);
        let now = CredentialLifecycleCoordinatorInstant::now();
        let first = coordinator
            .begin_login(
                &cache,
                profile_plan("a", 1, CredentialLifecycleOperation::Login, Some(300)),
                now,
            )
            .unwrap();
        let second = coordinator
            .begin_login(
                &cache,
                profile_plan("z", 1, CredentialLifecycleOperation::Login, Some(300)),
                now,
            )
            .unwrap();
        coordinator
            .heartbeat(&second, later(now, Duration::from_secs(9)))
            .unwrap();
        coordinator
            .heartbeat(&second, later(now, Duration::from_secs(18)))
            .unwrap();
        let stale_scan = later(now, Duration::from_secs(12));
        assert_eq!(
            coordinator
                .stale_recovery_tickets(stale_scan)
                .expect_err("one future activity rejects the entire scan")
                .code,
            CredentialLifecycleCoordinatorErrorCode::ClockRegression
        );
        assert_eq!(
            coordinator.snapshot(&first, stale_scan).unwrap().state,
            CredentialLifecycleLeaseState::Running
        );
    }

    #[test]
    fn stale_recovery_ticket_is_issued_once_and_cannot_overlap_cleanup() {
        let coordinator = coordinator(9, Duration::from_secs(1));
        let cache = cache(9);
        let now = CredentialLifecycleCoordinatorInstant::now();
        let _lease = coordinator
            .begin_login(
                &cache,
                profile_plan("work", 1, CredentialLifecycleOperation::Login, Some(300)),
                now,
            )
            .unwrap();
        let stale_at = later(now, Duration::from_secs(1));
        let first = coordinator
            .stale_recovery_tickets(stale_at)
            .unwrap()
            .remove(0);
        assert!(coordinator
            .stale_recovery_tickets(stale_at)
            .unwrap()
            .is_empty());
        coordinator.finish_stale_recovery(first).unwrap();
        let replacement = coordinator
            .begin_login(
                &cache,
                profile_plan("work", 2, CredentialLifecycleOperation::Login, Some(300)),
                stale_at,
            )
            .unwrap();
        assert_eq!(
            coordinator
                .snapshot(&replacement, stale_at)
                .unwrap()
                .revision,
            1
        );
    }

    #[test]
    fn concurrent_begin_has_exactly_one_winner() {
        let coordinator = Arc::new(coordinator(10, Duration::from_secs(30)));
        let cache = Arc::new(cache(10));
        let barrier = Arc::new(Barrier::new(16));
        let now = CredentialLifecycleCoordinatorInstant::now();
        let plan = profile_plan("work", 1, CredentialLifecycleOperation::Login, Some(300));
        let handles = (0..16)
            .map(|_| {
                let coordinator = Arc::clone(&coordinator);
                let cache = Arc::clone(&cache);
                let barrier = Arc::clone(&barrier);
                let plan = plan.clone();
                thread::spawn(move || {
                    barrier.wait();
                    coordinator.begin_login(&cache, plan, now)
                })
            })
            .collect::<Vec<_>>();
        let mut winner = None;
        let mut conflicts = 0;
        for handle in handles {
            match handle.join().expect("thread") {
                Ok(lease) => {
                    assert!(winner.replace(lease).is_none(), "only one winner");
                },
                Err(error) => {
                    assert_eq!(
                        error.code,
                        CredentialLifecycleCoordinatorErrorCode::LeaseAlreadyActive
                    );
                    conflicts += 1;
                },
            }
        }
        assert_eq!(conflicts, 15);
        assert_eq!(coordinator.active_count().unwrap(), 1);
        coordinator
            .complete(
                winner.as_ref().unwrap(),
                CredentialLifecycleTerminalOutcome::ProcessFailed,
                now,
            )
            .unwrap();
    }

    #[test]
    fn capacity_is_fixed_and_iterative_on_a_small_stack() {
        let handle = thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(|| {
                let coordinator = coordinator(11, Duration::from_secs(30));
                let cache = cache(11);
                let now = CredentialLifecycleCoordinatorInstant::now();
                let mut leases = Vec::with_capacity(MAX_ACTIVE_CREDENTIAL_LIFECYCLE_LEASES);
                for index in 0..MAX_ACTIVE_CREDENTIAL_LIFECYCLE_LEASES {
                    leases.push(
                        coordinator
                            .begin_login(
                                &cache,
                                profile_plan(
                                    &format!("profile-{index}"),
                                    1,
                                    CredentialLifecycleOperation::Login,
                                    Some(300),
                                ),
                                now,
                            )
                            .expect("within capacity"),
                    );
                }
                assert_eq!(coordinator.active_count().unwrap(), 256);
                assert_eq!(
                    coordinator
                        .begin_login(
                            &cache,
                            profile_plan(
                                "overflow",
                                1,
                                CredentialLifecycleOperation::Login,
                                Some(300),
                            ),
                            now,
                        )
                        .expect_err("capacity")
                        .code,
                    CredentialLifecycleCoordinatorErrorCode::CapacityExceeded
                );
                drop(leases);
            })
            .expect("spawn");
        handle.join().expect("small-stack coordinator");
    }

    #[test]
    fn safe_views_and_debug_output_exclude_target_and_provider_material() {
        let coordinator = coordinator(12, Duration::from_secs(30));
        let cache = cache(12);
        let now = CredentialLifecycleCoordinatorInstant::now();
        let lease = coordinator
            .begin_login(
                &cache,
                profile_plan(
                    "CANARY-secret-profile",
                    1,
                    CredentialLifecycleOperation::Login,
                    Some(300),
                ),
                now,
            )
            .unwrap();
        let snapshot = coordinator.snapshot(&lease, now).unwrap();
        let serialized = serde_json::to_string(&snapshot).unwrap();
        let debug = format!("{coordinator:?} {lease:?}");
        for output in [serialized.as_str(), debug.as_str()] {
            assert!(!output.contains("CANARY"));
            assert!(!output.contains("provider-cli"));
            assert!(!output.contains("auth"));
            assert!(!output.contains("owner"));
        }
    }

    #[test]
    fn coordinator_instance_identity_rejects_cross_instance_tokens() {
        let first = coordinator(13, Duration::from_secs(30));
        assert_eq!(
            CredentialLifecycleCoordinator::new(
                CredentialProcessEpoch::new(13).unwrap(),
                CredentialLifecycleIdleTimeout::new(Duration::from_secs(30)).unwrap(),
            )
            .expect_err("one owner per process epoch")
            .code,
            CredentialLifecycleCoordinatorErrorCode::CoordinatorAlreadyActive
        );
        let second = coordinator(16, Duration::from_secs(30));
        let first_cache = cache(13);
        let second_cache = cache(16);
        let now = CredentialLifecycleCoordinatorInstant::now();
        let first_lease = first
            .begin_login(
                &first_cache,
                profile_plan("work", 1, CredentialLifecycleOperation::Login, Some(300)),
                now,
            )
            .unwrap();
        let second_lease = second
            .begin_login(
                &second_cache,
                profile_plan("work", 1, CredentialLifecycleOperation::Login, Some(300)),
                now,
            )
            .unwrap();
        assert_ne!(
            first_lease.id().coordinator_instance(),
            second_lease.id().coordinator_instance()
        );
        assert_eq!(
            second.snapshot(&first_lease, now).unwrap_err().code,
            CredentialLifecycleCoordinatorErrorCode::LeaseMismatch
        );
    }

    #[test]
    fn dropping_an_active_coordinator_reserves_its_epoch_until_process_restart() {
        let epoch = 20;
        let coordinator = coordinator(epoch, Duration::from_secs(30));
        let cache = cache(epoch);
        let _lease = coordinator
            .begin_login(
                &cache,
                profile_plan("work", 1, CredentialLifecycleOperation::Login, Some(300)),
                CredentialLifecycleCoordinatorInstant::now(),
            )
            .unwrap();
        drop(coordinator);
        assert_eq!(
            CredentialLifecycleCoordinator::new(
                CredentialProcessEpoch::new(epoch).unwrap(),
                CredentialLifecycleIdleTimeout::new(Duration::from_secs(30)).unwrap(),
            )
            .expect_err("active resources fail closed until process restart")
            .code,
            CredentialLifecycleCoordinatorErrorCode::CoordinatorAlreadyActive
        );
    }

    #[test]
    fn poisoned_state_fails_closed_with_a_fixed_diagnostic() {
        let coordinator = Arc::new(coordinator(14, Duration::from_secs(30)));
        let poison = Arc::clone(&coordinator);
        let _ = thread::spawn(move || {
            let _guard = poison.state.lock().unwrap();
            panic!("poison for test");
        })
        .join();
        let error = coordinator.active_count().expect_err("poisoned lock");
        assert_eq!(
            error.code,
            CredentialLifecycleCoordinatorErrorCode::LockPoisoned
        );
        assert_eq!(error.field, "lifecycle_coordinator");
        assert!(!error.to_string().contains("poison for test"));
    }

    #[test]
    fn idle_timeout_and_clock_regression_fail_with_typed_diagnostics() {
        assert_eq!(
            CredentialLifecycleIdleTimeout::new(Duration::ZERO)
                .expect_err("zero idle timeout")
                .code,
            CredentialLifecycleCoordinatorErrorCode::InvalidIdleTimeout
        );
        assert_eq!(
            CredentialLifecycleIdleTimeout::new(
                MAX_CREDENTIAL_LIFECYCLE_IDLE_TIMEOUT + Duration::from_secs(1)
            )
            .expect_err("oversized idle timeout")
            .code,
            CredentialLifecycleCoordinatorErrorCode::InvalidIdleTimeout
        );

        let coordinator = coordinator(15, Duration::from_secs(30));
        let cache = cache(15);
        let now = CredentialLifecycleCoordinatorInstant::now();
        let lease = coordinator
            .begin_login(
                &cache,
                profile_plan("work", 1, CredentialLifecycleOperation::Login, Some(300)),
                now,
            )
            .unwrap();
        let earlier = CredentialLifecycleCoordinatorInstant(
            now.0.checked_sub(Duration::from_secs(1)).expect("earlier"),
        );
        assert_eq!(
            coordinator.snapshot(&lease, earlier).unwrap_err().code,
            CredentialLifecycleCoordinatorErrorCode::ClockRegression
        );
    }

    #[test]
    fn authority_and_recovery_types_cannot_be_cloned_or_serialized() {
        assert_not_impl_any!(CredentialLifecycleLease: Clone, Serialize);
        assert_not_impl_any!(CredentialLifecycleStaleRecoveryTicket: Clone, Serialize);
    }
}
