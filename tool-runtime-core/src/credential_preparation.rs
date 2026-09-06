//! Sealed, one-call preparation of bounded credential material.
//!
//! This module owns only the in-memory handoff boundary. Phase 2F supplies adapters for
//! existing secret and delegated-token authorities; later phases map prepared values to
//! declared child-process or transport injections. Nothing here reads a credential,
//! path, file, process environment, or network, and no production route is enabled.

use std::{collections::BTreeSet, error::Error, fmt, time::Instant};

use serde::{Deserialize, Deserializer, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    credential_profiles::{
        CredentialProfileBinding, CredentialProfileKey, CredentialProfileRevision,
        CredentialProviderId, CredentialScope, ExpectedCredentialIdentity,
    },
    manifest::{AuthKind, McpTransport, ProfileSelection, RuntimeProtocol},
    manifest_validation::{is_identifier, ValidatedSkillRuntimeContract},
    profile_selection::{
        CredentialProfileReadiness, CredentialProfileSelectionDecision,
        CredentialProfileSelectionMode,
    },
};

pub const CREDENTIAL_PREPARATION_V1: &str = "tool-runtime.credential-preparation.v1";
pub const MAX_PREPARED_CREDENTIAL_BINDINGS: usize = 64;
pub const MAX_PREPARED_CREDENTIAL_BYTES: usize = 1024 * 1024;
pub const MAX_TOTAL_PREPARED_CREDENTIAL_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CREDENTIAL_SECRET_REFERENCE_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialPreparationErrorCode {
    InvalidBindingName,
    InvalidBindingLimit,
    InvalidSecretReference,
    TooManyBindings,
    DuplicateBinding,
    TotalLimitExceeded,
    InvalidSelectionProof,
    AuthSelectionMismatch,
    IncompatibleMaterialKind,
    MissingRequiredMaterial,
    SelectionNotReady,
    ScopeMismatch,
    UndeclaredMaterial,
    DuplicateMaterial,
    EmptyMaterial,
    MaterialTooLarge,
    MissingMaterial,
    ResolutionFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialResolutionFailure {
    Missing,
    Denied,
    Expired,
    Stale,
    AlreadyRedeemed,
    BindingMismatch,
    Unavailable,
    Internal,
}

/// Stable, bounded, value-free preparation diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CredentialPreparationError {
    pub code: CredentialPreparationErrorCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution_failure: Option<CredentialResolutionFailure>,
    pub field: &'static str,
    pub message: &'static str,
}

impl CredentialPreparationError {
    const fn new(
        code: CredentialPreparationErrorCode,
        field: &'static str,
        message: &'static str,
    ) -> Self {
        Self {
            code,
            resolution_failure: None,
            field,
            message,
        }
    }

    /// Convert an authority-specific failure into the only value-free error form a
    /// resolver may return across this boundary.
    pub const fn resolution(failure: CredentialResolutionFailure) -> Self {
        Self {
            code: CredentialPreparationErrorCode::ResolutionFailed,
            resolution_failure: Some(failure),
            field: "credential_material",
            message: "credential material resolution failed",
        }
    }
}

impl fmt::Display for CredentialPreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for CredentialPreparationError {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct CredentialMaterialBindingName(String);

impl CredentialMaterialBindingName {
    pub fn new(value: impl Into<String>) -> Result<Self, CredentialPreparationError> {
        let value = value.into();
        if !is_identifier(&value) {
            return Err(invalid_binding_name());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CredentialMaterialBindingName {
    type Error = CredentialPreparationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for CredentialMaterialBindingName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Validated reference into an existing scoped secret authority. It is metadata, not
/// resolved material, and cannot contain an absolute path or traversal component.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct CredentialSecretReference(String);

impl CredentialSecretReference {
    pub fn new(value: impl Into<String>) -> Result<Self, CredentialPreparationError> {
        let value = value.into();
        if !is_secret_reference(&value) {
            return Err(invalid_secret_reference());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CredentialSecretReference {
    type Error = CredentialPreparationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for CredentialSecretReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

fn is_secret_reference(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_CREDENTIAL_SECRET_REFERENCE_BYTES
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
    {
        return false;
    }
    value.split('/').all(|segment| {
        !matches!(segment, "" | "." | "..")
            && segment.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+' | b':')
            })
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialMaterialKind {
    SecretBinding,
    DelegatedCredential,
    OAuthSession,
}

/// One non-secret slot in a preparation plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialPreparationBinding {
    name: CredentialMaterialBindingName,
    kind: CredentialMaterialKind,
    max_bytes: usize,
    required: bool,
}

impl CredentialPreparationBinding {
    pub fn new(
        name: CredentialMaterialBindingName,
        kind: CredentialMaterialKind,
        max_bytes: usize,
    ) -> Result<Self, CredentialPreparationError> {
        if max_bytes == 0 || max_bytes > MAX_PREPARED_CREDENTIAL_BYTES {
            return Err(invalid_binding_limit());
        }
        Ok(Self {
            name,
            kind,
            max_bytes,
            required: true,
        })
    }

    /// Declare material that may be absent without preventing execution. The
    /// binding remains bounded, typed, and eligible only for its declared
    /// injection target when a resolver actually supplies it.
    pub fn optional(
        name: CredentialMaterialBindingName,
        kind: CredentialMaterialKind,
        max_bytes: usize,
    ) -> Result<Self, CredentialPreparationError> {
        let mut binding = Self::new(name, kind, max_bytes)?;
        binding.required = false;
        Ok(binding)
    }

    pub fn name(&self) -> &CredentialMaterialBindingName {
        &self.name
    }

    pub fn kind(&self) -> CredentialMaterialKind {
        self.kind
    }

    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    pub fn is_required(&self) -> bool {
        self.required
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
enum CredentialPreparationIdentity {
    None,
    Implicit {
        provider: CredentialProviderId,
        binding: CredentialProfileBinding,
    },
    Profile {
        key: CredentialProfileKey,
        revision: CredentialProfileRevision,
        expected_identity: Option<ExpectedCredentialIdentity>,
    },
}

/// Validated, deterministic and non-secret preparation plan.
///
/// Construction consumes the opaque Phase 2D selection proof and refuses to prepare a
/// selected profile unless its public readiness is exactly `ready`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialPreparationPlan {
    schema_version: &'static str,
    scope: CredentialScope,
    auth_kind: AuthKind,
    identity: CredentialPreparationIdentity,
    bindings: Vec<CredentialPreparationBinding>,
    minimum_present: usize,
    max_total_bytes: usize,
}

impl CredentialPreparationPlan {
    /// Construct the only valid no-credential preparation directly from an
    /// already-validated scope. This avoids manufacturing a registry decision
    /// for hermetic local runtimes while retaining the same plan identity used
    /// by injection and governed execution.
    pub fn unauthenticated(scope: CredentialScope) -> Self {
        Self {
            schema_version: CREDENTIAL_PREPARATION_V1,
            scope,
            auth_kind: AuthKind::None,
            identity: CredentialPreparationIdentity::None,
            bindings: Vec::new(),
            minimum_present: 0,
            max_total_bytes: 0,
        }
    }

    pub fn new(
        scope: CredentialScope,
        auth_kind: AuthKind,
        selection: &CredentialProfileSelectionDecision,
        bindings: Vec<CredentialPreparationBinding>,
    ) -> Result<Self, CredentialPreparationError> {
        let minimum_present = bindings.iter().filter(|binding| binding.required).count();
        Self::new_with_minimum_present(scope, auth_kind, selection, bindings, minimum_present)
    }

    pub fn new_with_minimum_present(
        scope: CredentialScope,
        auth_kind: AuthKind,
        selection: &CredentialProfileSelectionDecision,
        mut bindings: Vec<CredentialPreparationBinding>,
        minimum_present: usize,
    ) -> Result<Self, CredentialPreparationError> {
        if bindings.len() > MAX_PREPARED_CREDENTIAL_BINDINGS {
            return Err(too_many_bindings());
        }
        if selection.scope() != &scope {
            return Err(scope_mismatch());
        }
        validate_auth_selection(auth_kind, selection.mode())?;
        if matches!(auth_kind, AuthKind::Secrets | AuthKind::DelegatedCredential)
            && bindings.is_empty()
        {
            return Err(missing_required_material());
        }
        if bindings
            .iter()
            .any(|binding| !material_kind_is_compatible(auth_kind, binding.kind))
        {
            return Err(incompatible_material_kind());
        }
        let required_count = bindings.iter().filter(|binding| binding.required).count();
        if minimum_present < required_count || minimum_present > bindings.len() {
            return Err(missing_required_material());
        }
        bindings.sort_by(|left, right| left.name.cmp(&right.name));
        let mut names = BTreeSet::new();
        let mut max_total_bytes = 0usize;
        for binding in &bindings {
            if !names.insert(binding.name.clone()) {
                return Err(duplicate_binding());
            }
            max_total_bytes = max_total_bytes
                .checked_add(binding.max_bytes)
                .ok_or_else(total_limit_exceeded)?;
            if max_total_bytes > MAX_TOTAL_PREPARED_CREDENTIAL_BYTES {
                return Err(total_limit_exceeded());
            }
        }

        let identity = match selection.mode() {
            CredentialProfileSelectionMode::None => CredentialPreparationIdentity::None,
            CredentialProfileSelectionMode::Implicit => {
                let Some((provider, binding)) = selection.implicit_identity() else {
                    return Err(invalid_selection_proof());
                };
                CredentialPreparationIdentity::Implicit {
                    provider: provider.clone(),
                    binding: binding.clone(),
                }
            },
            CredentialProfileSelectionMode::Selected => {
                if selection.readiness() != Some(CredentialProfileReadiness::Ready) {
                    return Err(selection_not_ready());
                }
                let Some(status) = selection.selected_profile() else {
                    return Err(invalid_selection_proof());
                };
                CredentialPreparationIdentity::Profile {
                    key: status.key().clone(),
                    revision: status.metadata().revision(),
                    expected_identity: status.metadata().expected_identity().cloned(),
                }
            },
        };

        Ok(Self {
            schema_version: CREDENTIAL_PREPARATION_V1,
            scope,
            auth_kind,
            identity,
            bindings,
            minimum_present,
            max_total_bytes,
        })
    }

    pub fn scope(&self) -> &CredentialScope {
        &self.scope
    }

    pub fn schema_version(&self) -> &'static str {
        self.schema_version
    }

    pub fn auth_kind(&self) -> AuthKind {
        self.auth_kind
    }

    pub fn bindings(&self) -> &[CredentialPreparationBinding] {
        &self.bindings
    }

    pub fn max_total_bytes(&self) -> usize {
        self.max_total_bytes
    }

    pub fn minimum_present(&self) -> usize {
        self.minimum_present
    }

    pub fn selected_profile_key(&self) -> Option<&CredentialProfileKey> {
        match &self.identity {
            CredentialPreparationIdentity::Profile { key, .. } => Some(key),
            CredentialPreparationIdentity::None
            | CredentialPreparationIdentity::Implicit { .. } => None,
        }
    }

    pub fn implicit_identity(&self) -> Option<(&CredentialProviderId, &CredentialProfileBinding)> {
        match &self.identity {
            CredentialPreparationIdentity::Implicit { provider, binding } => {
                Some((provider, binding))
            },
            CredentialPreparationIdentity::None | CredentialPreparationIdentity::Profile { .. } => {
                None
            },
        }
    }

    pub fn selected_expected_identity(&self) -> Option<&ExpectedCredentialIdentity> {
        match &self.identity {
            CredentialPreparationIdentity::Profile {
                expected_identity, ..
            } => expected_identity.as_ref(),
            CredentialPreparationIdentity::None
            | CredentialPreparationIdentity::Implicit { .. } => None,
        }
    }

    pub fn selected_profile_revision(&self) -> Option<CredentialProfileRevision> {
        match &self.identity {
            CredentialPreparationIdentity::Profile { revision, .. } => Some(*revision),
            CredentialPreparationIdentity::None
            | CredentialPreparationIdentity::Implicit { .. } => None,
        }
    }

    /// Check that this exact selection identity still belongs to the validated runtime
    /// contract that is about to consume it.
    ///
    /// Remote MCP OAuth additionally binds the selected profile to the contract's exact
    /// Streamable HTTP resource URL. The authorization issuer remains runtime-owned
    /// profile identity and is preserved unchanged for execution and audit.
    pub fn matches_validated_contract(&self, validated: ValidatedSkillRuntimeContract<'_>) -> bool {
        let contract = validated.contract();
        if contract.auth.kind != self.auth_kind {
            return false;
        }
        let identity_matches = match &contract.auth.profile_selection {
            ProfileSelection::None => {
                self.selected_profile_key().is_none() && self.implicit_identity().is_none()
            },
            ProfileSelection::Implicit => self.implicit_identity().is_some_and(|(provider, _)| {
                contract.auth.provider.as_deref() == Some(provider.as_str())
            }),
            ProfileSelection::Selectable { .. } => self.selected_profile_key().is_some_and(|key| {
                contract.auth.provider.as_deref() == Some(key.provider.as_str())
            }),
            ProfileSelection::Fixed { alias } => self.selected_profile_key().is_some_and(|key| {
                contract.auth.provider.as_deref() == Some(key.provider.as_str())
                    && key.alias.as_str() == alias
            }),
        };
        identity_matches && self.binding_matches_runtime(&contract.runtime)
    }

    fn binding_matches_runtime(&self, runtime: &RuntimeProtocol) -> bool {
        let binding = self
            .selected_profile_key()
            .map(|key| &key.binding)
            .or_else(|| self.implicit_identity().map(|(_, binding)| binding));
        let Some(binding) = binding else {
            return true;
        };

        match runtime {
            RuntimeProtocol::Mcp {
                transport: McpTransport::StreamableHttp { endpoint },
                ..
            } if self.auth_kind == AuthKind::OAuthSession => match binding {
                CredentialProfileBinding::McpOauth { resource_url, .. } => {
                    crate::credential_profiles::CanonicalCredentialUrl::new(endpoint)
                        .is_ok_and(|endpoint| &endpoint == resource_url)
                },
                CredentialProfileBinding::Provider => false,
            },
            RuntimeProtocol::Cli { .. }
            | RuntimeProtocol::Mcp {
                transport: McpTransport::Stdio { .. },
                ..
            } => matches!(binding, CredentialProfileBinding::Provider),
            RuntimeProtocol::Mcp {
                transport: McpTransport::StreamableHttp { .. },
                ..
            } => true,
        }
    }
}

fn validate_auth_selection(
    auth_kind: AuthKind,
    mode: CredentialProfileSelectionMode,
) -> Result<(), CredentialPreparationError> {
    let profile_auth = matches!(
        auth_kind,
        AuthKind::CliProfile | AuthKind::OAuthSession | AuthKind::BrowserProfile
    );
    if profile_auth == (mode == CredentialProfileSelectionMode::None) {
        return Err(auth_selection_mismatch());
    }
    Ok(())
}

const fn material_kind_is_compatible(
    auth_kind: AuthKind,
    material_kind: CredentialMaterialKind,
) -> bool {
    match auth_kind {
        AuthKind::None | AuthKind::BrowserProfile | AuthKind::NativePermission => false,
        AuthKind::Secrets | AuthKind::CliProfile => {
            matches!(material_kind, CredentialMaterialKind::SecretBinding)
        },
        AuthKind::OAuthSession => matches!(
            material_kind,
            CredentialMaterialKind::SecretBinding | CredentialMaterialKind::OAuthSession
        ),
        AuthKind::DelegatedCredential => {
            matches!(material_kind, CredentialMaterialKind::DelegatedCredential)
        },
    }
}

struct SecretBytes {
    bytes: Box<[u8]>,
    #[cfg(test)]
    drop_probe: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl SecretBytes {
    fn copy_from(value: &[u8]) -> Self {
        let mut bytes = vec![0_u8; value.len()].into_boxed_slice();
        bytes.copy_from_slice(value);
        Self {
            bytes,
            #[cfg(test)]
            drop_probe: None,
        }
    }

    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "Phase 3 governed injection is the first production credential consumer"
        )
    )]
    fn expose(&self) -> &[u8] {
        &self.bytes
    }

    #[cfg(test)]
    fn with_drop_probe(value: &[u8], probe: std::sync::Arc<std::sync::atomic::AtomicBool>) -> Self {
        let mut secret = Self::copy_from(value);
        secret.drop_probe = Some(probe);
        secret
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.bytes.zeroize();
        #[cfg(test)]
        if let Some(probe) = &self.drop_probe {
            use std::sync::atomic::Ordering;
            probe.store(self.bytes.iter().all(|byte| *byte == 0), Ordering::SeqCst);
        }
    }
}

struct PreparedCredentialEntry {
    binding: CredentialMaterialBindingName,
    kind: CredentialMaterialKind,
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "the sealed value is retained for drop zeroization before Phase 3 injection"
        )
    )]
    value: SecretBytes,
}

struct SealedPreparedCredentialMaterial {
    entries: Vec<PreparedCredentialEntry>,
}

/// Borrowed one-call view of sealed material. It has no owning constructor, clone,
/// `Debug`, serialization, or method that returns an owned value.
pub struct PreparedCredentialMaterial<'a> {
    sealed: &'a SealedPreparedCredentialMaterial,
}

impl PreparedCredentialMaterial<'_> {
    pub fn len(&self) -> usize {
        self.sealed.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sealed.entries.is_empty()
    }

    pub fn contains(&self, binding: &CredentialMaterialBindingName) -> bool {
        self.find(binding).is_some()
    }

    pub fn kind(&self, binding: &CredentialMaterialBindingName) -> Option<CredentialMaterialKind> {
        self.find(binding).map(|entry| entry.kind)
    }

    /// Expose one value only inside this crate for the later governed injection layer.
    /// External adapters can fill the sink but cannot read prepared bytes back.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "Phase 3 governed injection is the first production credential consumer"
        )
    )]
    pub(crate) fn with_value<T>(
        &self,
        binding: &CredentialMaterialBindingName,
        consumer: impl for<'value> FnOnce(&'value [u8]) -> T,
    ) -> Option<T> {
        self.find(binding)
            .map(|entry| consumer(entry.value.expose()))
    }

    fn find(&self, binding: &CredentialMaterialBindingName) -> Option<&PreparedCredentialEntry> {
        let index = self
            .sealed
            .entries
            .binary_search_by(|entry| entry.binding.cmp(binding))
            .ok()?;
        self.sealed.entries.get(index)
    }
}

/// Batch sink passed to a resolver exactly once. It accepts only declared binding names
/// and immediately copies each value into zeroizing sealed storage.
pub struct CredentialMaterialSink<'a> {
    plan: &'a CredentialPreparationPlan,
    values: Vec<Option<SecretBytes>>,
    total_bytes: usize,
    #[cfg(test)]
    drop_probe: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl<'a> CredentialMaterialSink<'a> {
    fn new(plan: &'a CredentialPreparationPlan) -> Self {
        Self {
            plan,
            values: std::iter::repeat_with(|| None)
                .take(plan.bindings.len())
                .collect(),
            total_bytes: 0,
            #[cfg(test)]
            drop_probe: None,
        }
    }

    #[cfg(test)]
    fn install_drop_probe(&mut self, probe: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        self.drop_probe = Some(probe);
    }

    pub fn provide(
        &mut self,
        binding: &CredentialMaterialBindingName,
        value: Vec<u8>,
    ) -> Result<(), CredentialPreparationError> {
        let value = Zeroizing::new(value);
        let index = self
            .plan
            .bindings
            .binary_search_by(|candidate| candidate.name.cmp(binding))
            .map_err(|_| undeclared_material())?;
        let expected = self
            .plan
            .bindings
            .get(index)
            .ok_or_else(undeclared_material)?;
        if self.values.get(index).is_some_and(Option::is_some) {
            return Err(duplicate_material());
        }
        if value.is_empty() {
            return Err(empty_material());
        }
        if value.len() > expected.max_bytes {
            return Err(material_too_large());
        }
        let total_bytes = self
            .total_bytes
            .checked_add(value.len())
            .ok_or_else(total_limit_exceeded)?;
        if total_bytes > self.plan.max_total_bytes
            || total_bytes > MAX_TOTAL_PREPARED_CREDENTIAL_BYTES
        {
            return Err(total_limit_exceeded());
        }
        #[cfg(not(test))]
        let sealed = SecretBytes::copy_from(&value);
        #[cfg(test)]
        let sealed = match &self.drop_probe {
            Some(probe) => SecretBytes::with_drop_probe(&value, std::sync::Arc::clone(probe)),
            None => SecretBytes::copy_from(&value),
        };
        self.values[index] = Some(sealed);
        self.total_bytes = total_bytes;
        Ok(())
    }

    fn finish(self) -> Result<SealedPreparedCredentialMaterial, CredentialPreparationError> {
        if self
            .values
            .iter()
            .zip(&self.plan.bindings)
            .any(|(value, binding)| value.is_none() && binding.required)
        {
            return Err(missing_material());
        }
        if self.values.iter().filter(|value| value.is_some()).count() < self.plan.minimum_present {
            return Err(missing_material());
        }
        let entries = self
            .plan
            .bindings
            .iter()
            .cloned()
            .zip(self.values)
            .filter_map(|(binding, value)| {
                value.map(|value| PreparedCredentialEntry {
                    binding: binding.name,
                    kind: binding.kind,
                    value,
                })
            })
            .collect::<Vec<_>>();
        Ok(SealedPreparedCredentialMaterial { entries })
    }
}

/// Adapter boundary implemented in Phase 2F by existing scoped secret and delegated
/// credential authorities. One batch call lets an adapter validate all bindings before
/// consuming any single-use material.
pub trait CredentialMaterialResolver: Send {
    fn resolve_once(
        &mut self,
        plan: &CredentialPreparationPlan,
        sink: &mut CredentialMaterialSink<'_>,
    ) -> Result<(), CredentialPreparationError>;

    /// Deadline-aware adapter entrypoint used by governed execution. Existing local
    /// resolvers inherit a safe preflight; I/O-backed resolvers should override this and
    /// apply the same absolute deadline to their transport.
    fn resolve_once_before(
        &mut self,
        plan: &CredentialPreparationPlan,
        sink: &mut CredentialMaterialSink<'_>,
        deadline: Instant,
    ) -> Result<(), CredentialPreparationError> {
        if Instant::now() >= deadline {
            return Err(CredentialPreparationError::resolution(
                CredentialResolutionFailure::Unavailable,
            ));
        }
        self.resolve_once(plan, sink)?;
        if Instant::now() >= deadline {
            return Err(CredentialPreparationError::resolution(
                CredentialResolutionFailure::Unavailable,
            ));
        }
        Ok(())
    }
}

/// Resolve and consume one sealed preparation. The owner is local to this function, so
/// every success, error, or panic-unwind path drops and zeroizes all prepared values.
pub fn with_prepared_credential_material<T>(
    plan: &CredentialPreparationPlan,
    resolver: &mut dyn CredentialMaterialResolver,
    consumer: impl for<'prepared> FnOnce(&'prepared PreparedCredentialMaterial<'prepared>) -> T,
) -> Result<T, CredentialPreparationError> {
    let mut sink = CredentialMaterialSink::new(plan);
    resolver.resolve_once(plan, &mut sink)?;
    let sealed = sink.finish()?;
    let view = PreparedCredentialMaterial { sealed: &sealed };
    Ok(consumer(&view))
}

pub(crate) fn with_prepared_credential_material_before<T>(
    plan: &CredentialPreparationPlan,
    resolver: &mut dyn CredentialMaterialResolver,
    deadline: Instant,
    consumer: impl for<'prepared> FnOnce(&'prepared PreparedCredentialMaterial<'prepared>) -> T,
) -> Result<T, CredentialPreparationError> {
    let mut sink = CredentialMaterialSink::new(plan);
    resolver.resolve_once_before(plan, &mut sink, deadline)?;
    let sealed = sink.finish()?;
    if Instant::now() >= deadline {
        return Err(CredentialPreparationError::resolution(
            CredentialResolutionFailure::Unavailable,
        ));
    }
    let view = PreparedCredentialMaterial { sealed: &sealed };
    Ok(consumer(&view))
}

const fn invalid_binding_name() -> CredentialPreparationError {
    CredentialPreparationError::new(
        CredentialPreparationErrorCode::InvalidBindingName,
        "binding.name",
        "credential material binding names must be bounded portable identifiers",
    )
}

const fn invalid_binding_limit() -> CredentialPreparationError {
    CredentialPreparationError::new(
        CredentialPreparationErrorCode::InvalidBindingLimit,
        "binding.max_bytes",
        "credential material binding limits must be positive and within the hard ceiling",
    )
}

const fn invalid_secret_reference() -> CredentialPreparationError {
    CredentialPreparationError::new(
        CredentialPreparationErrorCode::InvalidSecretReference,
        "secret_ref",
        "credential secret references must be bounded portable relative references",
    )
}

const fn too_many_bindings() -> CredentialPreparationError {
    CredentialPreparationError::new(
        CredentialPreparationErrorCode::TooManyBindings,
        "bindings",
        "the credential preparation plan exceeds its binding-count limit",
    )
}

const fn duplicate_binding() -> CredentialPreparationError {
    CredentialPreparationError::new(
        CredentialPreparationErrorCode::DuplicateBinding,
        "bindings",
        "the credential preparation plan contains a duplicate binding",
    )
}

const fn total_limit_exceeded() -> CredentialPreparationError {
    CredentialPreparationError::new(
        CredentialPreparationErrorCode::TotalLimitExceeded,
        "credential_material",
        "credential material exceeds the preparation total-byte limit",
    )
}

const fn invalid_selection_proof() -> CredentialPreparationError {
    CredentialPreparationError::new(
        CredentialPreparationErrorCode::InvalidSelectionProof,
        "profile_selection",
        "the credential profile selection proof is inconsistent",
    )
}

const fn auth_selection_mismatch() -> CredentialPreparationError {
    CredentialPreparationError::new(
        CredentialPreparationErrorCode::AuthSelectionMismatch,
        "auth_kind",
        "the authentication strategy and profile selection mode are incompatible",
    )
}

const fn incompatible_material_kind() -> CredentialPreparationError {
    CredentialPreparationError::new(
        CredentialPreparationErrorCode::IncompatibleMaterialKind,
        "bindings.kind",
        "credential material is incompatible with the authentication strategy",
    )
}

const fn missing_required_material() -> CredentialPreparationError {
    CredentialPreparationError::new(
        CredentialPreparationErrorCode::MissingRequiredMaterial,
        "bindings",
        "the authentication strategy requires declared credential material",
    )
}

const fn selection_not_ready() -> CredentialPreparationError {
    CredentialPreparationError::new(
        CredentialPreparationErrorCode::SelectionNotReady,
        "profile_selection",
        "the selected credential profile is not ready for preparation",
    )
}

const fn scope_mismatch() -> CredentialPreparationError {
    CredentialPreparationError::new(
        CredentialPreparationErrorCode::ScopeMismatch,
        "scope",
        "the selected credential profile belongs to a different scope",
    )
}

const fn undeclared_material() -> CredentialPreparationError {
    CredentialPreparationError::new(
        CredentialPreparationErrorCode::UndeclaredMaterial,
        "credential_material",
        "a resolver provided undeclared credential material",
    )
}

const fn duplicate_material() -> CredentialPreparationError {
    CredentialPreparationError::new(
        CredentialPreparationErrorCode::DuplicateMaterial,
        "credential_material",
        "a resolver provided credential material more than once",
    )
}

const fn empty_material() -> CredentialPreparationError {
    CredentialPreparationError::new(
        CredentialPreparationErrorCode::EmptyMaterial,
        "credential_material",
        "a resolver provided empty credential material",
    )
}

const fn material_too_large() -> CredentialPreparationError {
    CredentialPreparationError::new(
        CredentialPreparationErrorCode::MaterialTooLarge,
        "credential_material",
        "resolved credential material exceeds its binding limit",
    )
}

const fn missing_material() -> CredentialPreparationError {
    CredentialPreparationError::new(
        CredentialPreparationErrorCode::MissingMaterial,
        "credential_material",
        "a resolver omitted declared credential material",
    )
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
    };

    use static_assertions::assert_not_impl_any;

    use super::*;
    use crate::{
        credential_profiles::{
            CredentialProfileAvailability, CredentialProfileMetadata,
            CredentialProfileRegistrySnapshot, CredentialProfileRevision, CredentialProfileStatus,
        },
        manifest::{AuthState, ProfileSelection},
        profile_selection::{
            select_credential_profile_from_snapshot, CredentialProfileSelectionRequest,
        },
    };

    fn scope(principal: &str) -> CredentialScope {
        CredentialScope::new(principal, "default").expect("valid scope")
    }

    fn none_selection(selected_scope: &CredentialScope) -> CredentialProfileSelectionDecision {
        let request = CredentialProfileSelectionRequest::new(
            selected_scope.clone(),
            None,
            CredentialProfileBinding::Provider,
            &ProfileSelection::None,
            None,
        )
        .expect("selection request");
        let snapshot = CredentialProfileRegistrySnapshot::new(selected_scope.clone(), Vec::new())
            .expect("empty snapshot");
        select_credential_profile_from_snapshot(&request, &snapshot).expect("none selection")
    }

    fn implicit_selection(selected_scope: &CredentialScope) -> CredentialProfileSelectionDecision {
        let request = CredentialProfileSelectionRequest::new(
            selected_scope.clone(),
            Some("provider-cli"),
            CredentialProfileBinding::Provider,
            &ProfileSelection::Implicit,
            None,
        )
        .expect("selection request");
        let snapshot = CredentialProfileRegistrySnapshot::new(selected_scope.clone(), Vec::new())
            .expect("empty snapshot");
        select_credential_profile_from_snapshot(&request, &snapshot).expect("implicit selection")
    }

    fn profile_selection(
        selected_scope: &CredentialScope,
        state: AuthState,
    ) -> CredentialProfileSelectionDecision {
        let key = CredentialProfileKey::new(
            selected_scope.clone(),
            "google-workspace",
            "work",
            CredentialProfileBinding::Provider,
        )
        .expect("profile key");
        let metadata = CredentialProfileMetadata::new(
            key,
            None,
            false,
            CredentialProfileAvailability::Enabled,
            CredentialProfileRevision::new(1).expect("revision"),
        )
        .expect("metadata");
        let status = CredentialProfileStatus::new(metadata, state).expect("status");
        let snapshot = CredentialProfileRegistrySnapshot::new(selected_scope.clone(), vec![status])
            .expect("snapshot");
        let request = CredentialProfileSelectionRequest::new(
            selected_scope.clone(),
            Some("google-workspace"),
            CredentialProfileBinding::Provider,
            &ProfileSelection::Fixed {
                alias: "work".to_owned(),
            },
            None,
        )
        .expect("selection request");
        select_credential_profile_from_snapshot(&request, &snapshot).expect("profile selection")
    }

    fn binding(name: &str, max_bytes: usize) -> CredentialPreparationBinding {
        typed_binding(name, CredentialMaterialKind::SecretBinding, max_bytes)
    }

    #[test]
    fn scoped_secret_references_are_bounded_relative_and_deserialization_safe() {
        for valid in ["PROVIDER_API_KEY", "vault/provider:key+v1", "a.b-c_d"] {
            assert_eq!(
                CredentialSecretReference::new(valid)
                    .expect("valid secret reference")
                    .as_str(),
                valid
            );
        }
        for invalid in ["", "/absolute", "trailing/", "../escape", "a/./b", "a\\b"] {
            assert_eq!(
                CredentialSecretReference::new(invalid)
                    .expect_err("invalid secret reference")
                    .code,
                CredentialPreparationErrorCode::InvalidSecretReference
            );
        }
        let oversized = "x".repeat(MAX_CREDENTIAL_SECRET_REFERENCE_BYTES + 1);
        assert!(CredentialSecretReference::new(oversized).is_err());
        assert!(serde_json::from_str::<CredentialSecretReference>("\"../escape\"").is_err());
    }

    fn typed_binding(
        name: &str,
        kind: CredentialMaterialKind,
        max_bytes: usize,
    ) -> CredentialPreparationBinding {
        CredentialPreparationBinding::new(
            CredentialMaterialBindingName::new(name).expect("binding name"),
            kind,
            max_bytes,
        )
        .expect("binding")
    }

    struct MapResolver {
        values: BTreeMap<String, Vec<u8>>,
        calls: Arc<AtomicUsize>,
    }

    #[test]
    fn alternative_secret_plan_requires_one_and_seals_only_supplied_material() {
        let selected_scope = scope("owner");
        let selection = none_selection(&selected_scope);
        let alternatives = ["primary", "fallback"]
            .into_iter()
            .map(|name| {
                CredentialPreparationBinding::optional(
                    CredentialMaterialBindingName::new(name).expect("binding name"),
                    CredentialMaterialKind::SecretBinding,
                    128,
                )
                .expect("optional binding")
            })
            .collect();
        let plan = CredentialPreparationPlan::new_with_minimum_present(
            selected_scope,
            AuthKind::Secrets,
            &selection,
            alternatives,
            1,
        )
        .expect("alternative plan");

        let mut one = MapResolver {
            values: BTreeMap::from([("fallback".to_owned(), b"secret".to_vec())]),
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let count = with_prepared_credential_material(&plan, &mut one, |prepared| prepared.len())
            .expect("one alternative is sufficient");
        assert_eq!(count, 1);

        let mut none = MapResolver {
            values: BTreeMap::new(),
            calls: Arc::new(AtomicUsize::new(0)),
        };
        assert_eq!(
            with_prepared_credential_material(&plan, &mut none, |_| ())
                .expect_err("missing every alternative")
                .code,
            CredentialPreparationErrorCode::MissingMaterial
        );
    }

    impl CredentialMaterialResolver for MapResolver {
        fn resolve_once(
            &mut self,
            plan: &CredentialPreparationPlan,
            sink: &mut CredentialMaterialSink<'_>,
        ) -> Result<(), CredentialPreparationError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            for expected in plan.bindings() {
                if let Some(value) = self.values.remove(expected.name().as_str()) {
                    sink.provide(expected.name(), value)?;
                }
            }
            Ok(())
        }
    }

    #[test]
    fn plan_is_scope_bound_sorted_bounded_and_selection_backed() {
        let owner = scope("owner");
        let decision = profile_selection(&owner, AuthState::Ready);
        let plan = CredentialPreparationPlan::new(
            owner.clone(),
            AuthKind::CliProfile,
            &decision,
            vec![binding("zeta", 32), binding("alpha", 16)],
        )
        .expect("plan");
        assert_eq!(plan.scope(), &owner);
        assert_eq!(plan.bindings()[0].name().as_str(), "alpha");
        assert_eq!(plan.bindings()[1].name().as_str(), "zeta");
        assert_eq!(plan.max_total_bytes(), 48);
        assert_eq!(
            plan.selected_profile_key()
                .expect("selected profile")
                .alias
                .as_str(),
            "work"
        );
        assert_eq!(
            plan.selected_profile_revision().map(|value| value.get()),
            Some(1)
        );

        let implicit = CredentialPreparationPlan::new(
            owner.clone(),
            AuthKind::CliProfile,
            &implicit_selection(&owner),
            Vec::new(),
        )
        .expect("implicit plan");
        assert_eq!(
            implicit
                .implicit_identity()
                .expect("implicit identity")
                .0
                .as_str(),
            "provider-cli"
        );

        let not_ready = profile_selection(&owner, AuthState::Unknown);
        assert_eq!(
            CredentialPreparationPlan::new(owner, AuthKind::CliProfile, &not_ready, Vec::new(),)
                .expect_err("non-ready profile")
                .code,
            CredentialPreparationErrorCode::SelectionNotReady
        );
    }

    #[test]
    fn plan_rejects_scope_crossing_duplicates_and_all_limit_overflows_before_resolution() {
        let owner = scope("owner");
        let other = scope("other");
        assert_eq!(
            CredentialPreparationPlan::new(
                owner.clone(),
                AuthKind::CliProfile,
                &profile_selection(&other, AuthState::Ready),
                Vec::new(),
            )
            .expect_err("scope crossing")
            .code,
            CredentialPreparationErrorCode::ScopeMismatch
        );
        assert_eq!(
            CredentialPreparationPlan::new(
                owner.clone(),
                AuthKind::Secrets,
                &none_selection(&other),
                Vec::new(),
            )
            .expect_err("unprofiled selection scope crossing")
            .code,
            CredentialPreparationErrorCode::ScopeMismatch
        );
        assert_eq!(
            CredentialPreparationPlan::new(
                owner.clone(),
                AuthKind::CliProfile,
                &implicit_selection(&other),
                Vec::new(),
            )
            .expect_err("implicit selection scope crossing")
            .code,
            CredentialPreparationErrorCode::ScopeMismatch
        );
        assert_eq!(
            CredentialPreparationPlan::new(
                owner.clone(),
                AuthKind::Secrets,
                &none_selection(&owner),
                vec![binding("same", 1), binding("same", 1)],
            )
            .expect_err("duplicate")
            .code,
            CredentialPreparationErrorCode::DuplicateBinding
        );
        let too_many = (0..=MAX_PREPARED_CREDENTIAL_BINDINGS)
            .map(|index| binding(&format!("b{index:02}"), 1))
            .collect();
        assert_eq!(
            CredentialPreparationPlan::new(
                owner.clone(),
                AuthKind::Secrets,
                &none_selection(&owner),
                too_many,
            )
            .expect_err("too many")
            .code,
            CredentialPreparationErrorCode::TooManyBindings
        );
        assert_eq!(
            CredentialPreparationBinding::new(
                CredentialMaterialBindingName::new("large").unwrap(),
                CredentialMaterialKind::SecretBinding,
                MAX_PREPARED_CREDENTIAL_BYTES + 1,
            )
            .expect_err("binding size")
            .code,
            CredentialPreparationErrorCode::InvalidBindingLimit
        );
        let excessive_total = (0..5)
            .map(|index| binding(&format!("large-{index}"), MAX_PREPARED_CREDENTIAL_BYTES))
            .collect();
        assert_eq!(
            CredentialPreparationPlan::new(
                owner.clone(),
                AuthKind::Secrets,
                &none_selection(&owner),
                excessive_total,
            )
            .expect_err("total size")
            .code,
            CredentialPreparationErrorCode::TotalLimitExceeded
        );
    }

    #[test]
    fn auth_selection_and_material_strategy_matrix_is_fail_closed() {
        let owner = scope("owner");
        let none = none_selection(&owner);
        let implicit = implicit_selection(&owner);

        for auth_kind in [AuthKind::None, AuthKind::NativePermission] {
            CredentialPreparationPlan::new(owner.clone(), auth_kind, &none, Vec::new())
                .expect("non-material strategy");
            assert_eq!(
                CredentialPreparationPlan::new(
                    owner.clone(),
                    auth_kind,
                    &none,
                    vec![binding("secret", 32)],
                )
                .expect_err("non-material strategy cannot accept bytes")
                .code,
                CredentialPreparationErrorCode::IncompatibleMaterialKind
            );
        }

        assert_eq!(
            CredentialPreparationPlan::new(
                owner.clone(),
                AuthKind::Secrets,
                &implicit,
                vec![binding("secret", 32)],
            )
            .expect_err("secret auth cannot claim an implicit profile")
            .code,
            CredentialPreparationErrorCode::AuthSelectionMismatch
        );
        for auth_kind in [AuthKind::Secrets, AuthKind::DelegatedCredential] {
            assert_eq!(
                CredentialPreparationPlan::new(owner.clone(), auth_kind, &none, Vec::new())
                    .expect_err("material-bearing strategy requires a slot")
                    .code,
                CredentialPreparationErrorCode::MissingRequiredMaterial
            );
        }
        CredentialPreparationPlan::new(
            owner.clone(),
            AuthKind::BrowserProfile,
            &implicit,
            Vec::new(),
        )
        .expect("browser-owned profile has no exported material");
        assert_eq!(
            CredentialPreparationPlan::new(
                owner.clone(),
                AuthKind::BrowserProfile,
                &implicit,
                vec![binding("secret", 32)],
            )
            .expect_err("browser credentials stay inside the controller")
            .code,
            CredentialPreparationErrorCode::IncompatibleMaterialKind
        );

        CredentialPreparationPlan::new(
            owner.clone(),
            AuthKind::OAuthSession,
            &implicit,
            vec![typed_binding(
                "oauth",
                CredentialMaterialKind::OAuthSession,
                64,
            )],
        )
        .expect("OAuth material");
        CredentialPreparationPlan::new(
            owner.clone(),
            AuthKind::DelegatedCredential,
            &none,
            vec![typed_binding(
                "delegated",
                CredentialMaterialKind::DelegatedCredential,
                64,
            )],
        )
        .expect("delegated material");
        assert_eq!(
            CredentialPreparationPlan::new(
                owner,
                AuthKind::DelegatedCredential,
                &none,
                vec![binding("secret", 64)],
            )
            .expect_err("delegated auth cannot accept a static secret slot")
            .code,
            CredentialPreparationErrorCode::IncompatibleMaterialKind
        );
    }

    #[test]
    fn one_batch_resolution_invokes_one_consumer_and_exposes_no_owned_value() {
        let owner = scope("owner");
        let plan = CredentialPreparationPlan::new(
            owner.clone(),
            AuthKind::Secrets,
            &none_selection(&owner),
            vec![binding("api_key", 64), binding("session", 64)],
        )
        .expect("plan");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut resolver = MapResolver {
            values: BTreeMap::from([
                ("api_key".to_owned(), b"secret-one".to_vec()),
                ("session".to_owned(), b"secret-two".to_vec()),
            ]),
            calls: Arc::clone(&calls),
        };
        let consumers = AtomicUsize::new(0);
        let summary = with_prepared_credential_material(&plan, &mut resolver, |prepared| {
            consumers.fetch_add(1, Ordering::SeqCst);
            assert_eq!(prepared.len(), 2);
            let api_key = CredentialMaterialBindingName::new("api_key").unwrap();
            assert!(prepared.contains(&api_key));
            assert_eq!(
                prepared.kind(&api_key),
                Some(CredentialMaterialKind::SecretBinding)
            );
            prepared
                .with_value(&api_key, |value| value.len())
                .expect("prepared value")
        })
        .expect("preparation");
        assert_eq!(summary, 10);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(consumers.load(Ordering::SeqCst), 1);

        let serialized_plan = serde_json::to_string(&plan).expect("serialize metadata-only plan");
        assert!(!serialized_plan.contains("secret-one"));
        assert!(!serialized_plan.contains("secret-two"));
        assert!(!serialized_plan.contains("credential-value"));
    }

    struct AdversarialResolver {
        behavior: &'static str,
    }

    impl CredentialMaterialResolver for AdversarialResolver {
        fn resolve_once(
            &mut self,
            plan: &CredentialPreparationPlan,
            sink: &mut CredentialMaterialSink<'_>,
        ) -> Result<(), CredentialPreparationError> {
            let expected = plan.bindings().first().expect("test binding").name();
            match self.behavior {
                "omit" => Ok(()),
                "empty" => sink.provide(expected, Vec::new()),
                "oversized" => sink.provide(expected, vec![b'x'; 9]),
                "duplicate" => {
                    sink.provide(expected, b"first".to_vec())?;
                    sink.provide(expected, b"second".to_vec())
                },
                "undeclared" => sink.provide(
                    &CredentialMaterialBindingName::new("other").unwrap(),
                    b"secret".to_vec(),
                ),
                _ => Err(CredentialPreparationError::resolution(
                    CredentialResolutionFailure::Stale,
                )),
            }
        }
    }

    #[test]
    fn incomplete_duplicate_undeclared_empty_and_oversized_material_fail_before_consumption() {
        let owner = scope("owner");
        let plan = CredentialPreparationPlan::new(
            owner.clone(),
            AuthKind::Secrets,
            &none_selection(&owner),
            vec![binding("expected", 8)],
        )
        .expect("plan");
        let consumer_calls = AtomicUsize::new(0);
        for (behavior, code) in [
            ("omit", CredentialPreparationErrorCode::MissingMaterial),
            ("empty", CredentialPreparationErrorCode::EmptyMaterial),
            (
                "oversized",
                CredentialPreparationErrorCode::MaterialTooLarge,
            ),
            (
                "duplicate",
                CredentialPreparationErrorCode::DuplicateMaterial,
            ),
            (
                "undeclared",
                CredentialPreparationErrorCode::UndeclaredMaterial,
            ),
        ] {
            let error = with_prepared_credential_material(
                &plan,
                &mut AdversarialResolver { behavior },
                |_| consumer_calls.fetch_add(1, Ordering::SeqCst),
            )
            .expect_err("invalid resolution");
            assert_eq!(error.code, code, "behavior {behavior}");
        }
        assert_eq!(consumer_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn typed_resolution_failures_propagate_without_values() {
        let owner = scope("owner");
        let plan = CredentialPreparationPlan::new(
            owner.clone(),
            AuthKind::Secrets,
            &none_selection(&owner),
            vec![binding("expected", 64)],
        )
        .expect("plan");
        let error = with_prepared_credential_material(
            &plan,
            &mut AdversarialResolver { behavior: "fail" },
            |_| (),
        )
        .expect_err("stale material");
        assert_eq!(error.code, CredentialPreparationErrorCode::ResolutionFailed);
        assert_eq!(
            error.resolution_failure,
            Some(CredentialResolutionFailure::Stale)
        );
        let canary = "CREDENTIAL_VALUE_CANARY";
        let serialized = serde_json::to_string(&error).expect("serialize error");
        assert!(!error.to_string().contains(canary));
        assert!(!serialized.contains(canary));
    }

    #[test]
    fn secret_owners_views_and_sinks_are_not_clone_debug_or_serializable() {
        assert_not_impl_any!(SecretBytes: Clone, fmt::Debug, Serialize);
        assert_not_impl_any!(PreparedCredentialEntry: Clone, fmt::Debug, Serialize);
        assert_not_impl_any!(SealedPreparedCredentialMaterial: Clone, fmt::Debug, Serialize);
        assert_not_impl_any!(PreparedCredentialMaterial<'static>: Clone, fmt::Debug, Serialize);
        assert_not_impl_any!(CredentialMaterialSink<'static>: Clone, fmt::Debug, Serialize);
    }

    #[test]
    fn secret_storage_is_zeroized_on_drop() {
        let observed = Arc::new(AtomicBool::new(false));
        {
            let secret = SecretBytes::with_drop_probe(b"zeroize-this-value", Arc::clone(&observed));
            assert_eq!(secret.expose(), b"zeroize-this-value");
        }
        assert!(observed.load(Ordering::SeqCst));
    }

    struct ProbedResolver {
        probe: Arc<AtomicBool>,
        fail_after_fill: bool,
    }

    impl CredentialMaterialResolver for ProbedResolver {
        fn resolve_once(
            &mut self,
            plan: &CredentialPreparationPlan,
            sink: &mut CredentialMaterialSink<'_>,
        ) -> Result<(), CredentialPreparationError> {
            sink.install_drop_probe(Arc::clone(&self.probe));
            sink.provide(
                plan.bindings().first().expect("test binding").name(),
                b"short-lived-secret".to_vec(),
            )?;
            if self.fail_after_fill {
                Err(CredentialPreparationError::resolution(
                    CredentialResolutionFailure::Internal,
                ))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn partial_failure_and_consumer_panic_both_zeroize_prepared_values() {
        let owner = scope("owner");
        let plan = CredentialPreparationPlan::new(
            owner.clone(),
            AuthKind::Secrets,
            &none_selection(&owner),
            vec![binding("expected", 64)],
        )
        .expect("plan");

        let failed_probe = Arc::new(AtomicBool::new(false));
        let error = with_prepared_credential_material(
            &plan,
            &mut ProbedResolver {
                probe: Arc::clone(&failed_probe),
                fail_after_fill: true,
            },
            |_| (),
        )
        .expect_err("resolver failure");
        assert_eq!(error.code, CredentialPreparationErrorCode::ResolutionFailed);
        assert!(failed_probe.load(Ordering::SeqCst));

        let panic_probe = Arc::new(AtomicBool::new(false));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = with_prepared_credential_material(
                &plan,
                &mut ProbedResolver {
                    probe: Arc::clone(&panic_probe),
                    fail_after_fill: false,
                },
                |_| panic!("consumer panic canary"),
            );
        }));
        assert!(result.is_err());
        assert!(panic_probe.load(Ordering::SeqCst));
    }

    #[test]
    fn preparation_does_not_mutate_the_parent_environment() {
        let owner = scope("owner");
        let plan = CredentialPreparationPlan::new(
            owner.clone(),
            AuthKind::Secrets,
            &none_selection(&owner),
            vec![binding("environment_canary", 64)],
        )
        .expect("plan");
        let variable = "TOOL_RUNTIME_CORE_PHASE2E_PARENT_ENV_CANARY";
        let previous = std::env::var_os(variable);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut resolver = MapResolver {
            values: BTreeMap::from([(
                "environment_canary".to_owned(),
                b"credential-value".to_vec(),
            )]),
            calls,
        };
        with_prepared_credential_material(&plan, &mut resolver, |prepared| {
            let binding = CredentialMaterialBindingName::new("environment_canary").unwrap();
            prepared.with_value(&binding, |value| assert_eq!(value, b"credential-value"));
        })
        .expect("preparation");
        assert_eq!(std::env::var_os(variable), previous);
    }

    #[test]
    fn maximum_plan_and_preparation_complete_deterministically_on_a_small_stack() {
        let result = std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| {
                let owner = scope("owner");
                let bindings = (0..MAX_PREPARED_CREDENTIAL_BINDINGS)
                    .rev()
                    .map(|index| binding(&format!("binding-{index:02}"), 32))
                    .collect::<Vec<_>>();
                let plan = CredentialPreparationPlan::new(
                    owner.clone(),
                    AuthKind::Secrets,
                    &none_selection(&owner),
                    bindings,
                )
                .expect("maximum plan");
                let values = plan
                    .bindings()
                    .iter()
                    .map(|binding| (binding.name().as_str().to_owned(), vec![b'x'; 32]))
                    .collect();
                let calls = Arc::new(AtomicUsize::new(0));
                let mut resolver = MapResolver { values, calls };
                let count = with_prepared_credential_material(&plan, &mut resolver, |prepared| {
                    prepared.len()
                })
                .expect("maximum preparation");
                assert_eq!(count, MAX_PREPARED_CREDENTIAL_BINDINGS);
                let first = serde_json::to_vec(&plan).expect("first serialization");
                let second = serde_json::to_vec(&plan).expect("second serialization");
                assert_eq!(first, second);
            })
            .expect("spawn small-stack preparation")
            .join();
        assert!(result.is_ok());
    }
}
