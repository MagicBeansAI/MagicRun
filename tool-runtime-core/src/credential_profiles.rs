//! Provider-neutral credential-profile identity and metadata-only registry contract.
//!
//! Phase 2A defines logical keys and public registry views only. It deliberately has no
//! filesystem path, secret reference, credential value, environment mutation, resolver,
//! persistence, process, network, or production-routing handle. Phase 2B attaches typed
//! scoped-path authority; later slices implement storage, selection, and sealed material.

use std::{collections::BTreeSet, error::Error, fmt};

use serde::{Deserialize, Deserializer, Serialize};
use url::{Host, Url};

use crate::manifest::AuthState;

pub const CREDENTIAL_PROFILE_REGISTRY_V1: &str = "tool-runtime.credential-profile-registry.v1";
pub const MAX_SCOPE_SEGMENT_BYTES: usize = 256;
pub const MAX_PROFILE_IDENTIFIER_BYTES: usize = 128;
pub const MAX_EXPECTED_IDENTITY_BYTES: usize = 1024;
pub const MAX_CREDENTIAL_BINDING_URL_BYTES: usize = 8 * 1024;
pub const MAX_PROFILES_PER_SCOPE: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialProfileErrorCode {
    InvalidScopeSegment,
    InvalidProvider,
    InvalidProfileAlias,
    InvalidExpectedIdentity,
    InvalidBindingUrl,
    InvalidStatus,
    CollectionTooLarge,
    ScopeMismatch,
    DuplicateProfile,
    MultipleDefaults,
    InvalidLegacyConfig,
    NotFound,
    Conflict,
    RegistryUnavailable,
    CommitStateUnknown,
}

/// Stable, bounded, value-free profile diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CredentialProfileError {
    pub code: CredentialProfileErrorCode,
    pub field: &'static str,
    pub message: &'static str,
}

impl CredentialProfileError {
    pub(crate) const fn new(
        code: CredentialProfileErrorCode,
        field: &'static str,
        message: &'static str,
    ) -> Self {
        Self {
            code,
            field,
            message,
        }
    }

    pub const fn not_found() -> Self {
        Self::new(
            CredentialProfileErrorCode::NotFound,
            "profile",
            "the credential profile was not found",
        )
    }

    pub const fn conflict() -> Self {
        Self::new(
            CredentialProfileErrorCode::Conflict,
            "profile",
            "the credential profile changed concurrently",
        )
    }

    pub const fn registry_unavailable() -> Self {
        Self::new(
            CredentialProfileErrorCode::RegistryUnavailable,
            "registry",
            "the credential profile registry is unavailable",
        )
    }

    /// The registry file was published, but durability confirmation failed. Callers
    /// must reconcile by reading the profile before deciding whether to retry.
    pub const fn commit_state_unknown() -> Self {
        Self::new(
            CredentialProfileErrorCode::CommitStateUnknown,
            "registry",
            "the credential profile commit state is unknown; read before retrying",
        )
    }
}

impl fmt::Display for CredentialProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for CredentialProfileError {}

macro_rules! validated_string_type {
    ($name:ident, $validator:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, CredentialProfileError> {
                let value = value.into();
                $validator(&value)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = CredentialProfileError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

validated_string_type!(ScopeSegment, validate_scope_segment);
validated_string_type!(CredentialProviderId, validate_provider);
validated_string_type!(CredentialProfileAlias, validate_profile_alias);
validated_string_type!(ExpectedCredentialIdentity, validate_expected_identity);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct CanonicalCredentialUrl(String);

impl CanonicalCredentialUrl {
    pub fn new(value: impl AsRef<str>) -> Result<Self, CredentialProfileError> {
        let value = value.as_ref();
        if value.is_empty() || value.len() > MAX_CREDENTIAL_BINDING_URL_BYTES {
            return Err(invalid_binding_url());
        }
        let parsed = Url::parse(value).map_err(|_| invalid_binding_url())?;
        if parsed.cannot_be_a_base()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.host().is_none()
            || !secure_binding_scheme(&parsed)
        {
            return Err(invalid_binding_url());
        }
        let canonical = parsed.to_string();
        if canonical.len() > MAX_CREDENTIAL_BINDING_URL_BYTES {
            return Err(invalid_binding_url());
        }
        Ok(Self(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CanonicalCredentialUrl {
    type Error = CredentialProfileError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for CanonicalCredentialUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CredentialProfileBinding {
    #[default]
    Provider,
    McpOauth {
        resource_url: CanonicalCredentialUrl,
        authorization_issuer: CanonicalCredentialUrl,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialScope {
    pub principal: ScopeSegment,
    pub workspace: ScopeSegment,
}

impl CredentialScope {
    pub fn new(
        principal: impl Into<String>,
        workspace: impl Into<String>,
    ) -> Result<Self, CredentialProfileError> {
        Ok(Self {
            principal: ScopeSegment::new(principal)?,
            workspace: ScopeSegment::new(workspace)?,
        })
    }
}

/// Complete logical registry key. It contains no filesystem path or credential material.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialProfileKey {
    pub scope: CredentialScope,
    pub provider: CredentialProviderId,
    pub alias: CredentialProfileAlias,
    #[serde(default)]
    pub binding: CredentialProfileBinding,
}

impl CredentialProfileKey {
    pub fn new(
        scope: CredentialScope,
        provider: impl Into<String>,
        alias: impl Into<String>,
        binding: CredentialProfileBinding,
    ) -> Result<Self, CredentialProfileError> {
        Ok(Self {
            scope,
            provider: CredentialProviderId::new(provider)?,
            alias: CredentialProfileAlias::new(alias)?,
            binding,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialProfileAvailability {
    Enabled,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct CredentialProfileRevision(u64);

impl CredentialProfileRevision {
    pub fn new(value: u64) -> Result<Self, CredentialProfileError> {
        if value == 0 {
            return Err(invalid_status());
        }
        Ok(Self(value))
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for CredentialProfileRevision {
    type Error = CredentialProfileError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for CredentialProfileRevision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Public, non-secret registry metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialProfileMetadata {
    key: CredentialProfileKey,
    expected_identity: Option<ExpectedCredentialIdentity>,
    is_default: bool,
    availability: CredentialProfileAvailability,
    revision: CredentialProfileRevision,
}

impl CredentialProfileMetadata {
    pub fn new(
        key: CredentialProfileKey,
        expected_identity: Option<ExpectedCredentialIdentity>,
        is_default: bool,
        availability: CredentialProfileAvailability,
        revision: CredentialProfileRevision,
    ) -> Result<Self, CredentialProfileError> {
        if is_default && availability == CredentialProfileAvailability::Disabled {
            return Err(invalid_status());
        }
        Ok(Self {
            key,
            expected_identity,
            is_default,
            availability,
            revision,
        })
    }

    pub fn key(&self) -> &CredentialProfileKey {
        &self.key
    }

    pub fn expected_identity(&self) -> Option<&ExpectedCredentialIdentity> {
        self.expected_identity.as_ref()
    }

    pub fn is_default(&self) -> bool {
        self.is_default
    }

    pub fn availability(&self) -> CredentialProfileAvailability {
        self.availability
    }

    pub fn revision(&self) -> CredentialProfileRevision {
        self.revision
    }
}

/// Public profile status. Disabled profiles are always reported as denied, never ready.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialProfileStatus {
    metadata: CredentialProfileMetadata,
    auth_state: AuthState,
}

impl CredentialProfileStatus {
    pub fn new(
        metadata: CredentialProfileMetadata,
        auth_state: AuthState,
    ) -> Result<Self, CredentialProfileError> {
        if metadata.availability == CredentialProfileAvailability::Disabled
            && auth_state != AuthState::Denied
        {
            return Err(invalid_status());
        }
        Ok(Self {
            metadata,
            auth_state,
        })
    }

    pub fn metadata(&self) -> &CredentialProfileMetadata {
        &self.metadata
    }

    pub fn key(&self) -> &CredentialProfileKey {
        self.metadata.key()
    }

    pub fn auth_state(&self) -> AuthState {
        self.auth_state
    }
}

/// Bounded deterministic view returned by registry list operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialProfileRegistrySnapshot {
    pub schema_version: &'static str,
    scope: CredentialScope,
    profiles: Vec<CredentialProfileStatus>,
}

impl CredentialProfileRegistrySnapshot {
    pub fn new(
        scope: CredentialScope,
        mut profiles: Vec<CredentialProfileStatus>,
    ) -> Result<Self, CredentialProfileError> {
        if profiles.len() > MAX_PROFILES_PER_SCOPE {
            return Err(CredentialProfileError::new(
                CredentialProfileErrorCode::CollectionTooLarge,
                "profiles",
                "the credential profile snapshot exceeds its size limit",
            ));
        }

        let mut keys = BTreeSet::new();
        let mut defaults = BTreeSet::new();
        for profile in &profiles {
            if profile.key().scope != scope {
                return Err(CredentialProfileError::new(
                    CredentialProfileErrorCode::ScopeMismatch,
                    "profiles.scope",
                    "a credential profile belongs to a different scope",
                ));
            }
            if !keys.insert(profile.key().clone()) {
                return Err(CredentialProfileError::new(
                    CredentialProfileErrorCode::DuplicateProfile,
                    "profiles",
                    "the credential profile snapshot contains a duplicate key",
                ));
            }
            if profile.metadata().is_default() {
                let group = (
                    profile.key().provider.clone(),
                    profile.key().binding.clone(),
                );
                if !defaults.insert(group) {
                    return Err(CredentialProfileError::new(
                        CredentialProfileErrorCode::MultipleDefaults,
                        "profiles.is_default",
                        "a provider binding has more than one default profile",
                    ));
                }
            }
        }
        profiles.sort_by(|left, right| left.key().cmp(right.key()));
        Ok(Self {
            schema_version: CREDENTIAL_PROFILE_REGISTRY_V1,
            scope,
            profiles,
        })
    }

    pub fn scope(&self) -> &CredentialScope {
        &self.scope
    }

    pub fn profiles(&self) -> &[CredentialProfileStatus] {
        &self.profiles
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CreateCredentialProfileReference {
    key: CredentialProfileKey,
    expected_identity: Option<ExpectedCredentialIdentity>,
    make_default: bool,
}

impl CreateCredentialProfileReference {
    pub fn new(
        key: CredentialProfileKey,
        expected_identity: Option<ExpectedCredentialIdentity>,
        make_default: bool,
    ) -> Self {
        Self {
            key,
            expected_identity,
            make_default,
        }
    }

    pub fn key(&self) -> &CredentialProfileKey {
        &self.key
    }

    pub fn expected_identity(&self) -> Option<&ExpectedCredentialIdentity> {
        self.expected_identity.as_ref()
    }

    pub fn make_default(&self) -> bool {
        self.make_default
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum ExpectedIdentityUpdate {
    Preserve,
    Clear,
    Set { value: ExpectedCredentialIdentity },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "operation", content = "value", rename_all = "snake_case")]
pub enum DefaultProfileUpdate {
    Preserve,
    Set(bool),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpdateCredentialProfileMetadata {
    key: CredentialProfileKey,
    expected_identity: ExpectedIdentityUpdate,
    default_profile: DefaultProfileUpdate,
    expected_revision: CredentialProfileRevision,
}

impl UpdateCredentialProfileMetadata {
    pub fn new(
        key: CredentialProfileKey,
        expected_identity: ExpectedIdentityUpdate,
        default_profile: DefaultProfileUpdate,
        expected_revision: CredentialProfileRevision,
    ) -> Self {
        Self {
            key,
            expected_identity,
            default_profile,
            expected_revision,
        }
    }

    pub fn key(&self) -> &CredentialProfileKey {
        &self.key
    }

    pub fn expected_identity(&self) -> &ExpectedIdentityUpdate {
        &self.expected_identity
    }

    pub fn default_profile(&self) -> DefaultProfileUpdate {
        self.default_profile
    }

    pub fn expected_revision(&self) -> CredentialProfileRevision {
        self.expected_revision
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SetCredentialProfileDisabled {
    key: CredentialProfileKey,
    disabled: bool,
    expected_revision: CredentialProfileRevision,
}

impl SetCredentialProfileDisabled {
    pub fn new(
        key: CredentialProfileKey,
        disabled: bool,
        expected_revision: CredentialProfileRevision,
    ) -> Self {
        Self {
            key,
            disabled,
            expected_revision,
        }
    }

    pub fn key(&self) -> &CredentialProfileKey {
        &self.key
    }

    pub fn disabled(&self) -> bool {
        self.disabled
    }

    pub fn expected_revision(&self) -> CredentialProfileRevision {
        self.expected_revision
    }
}

/// Metadata-only registry surface. Implementations may own storage later, but neither
/// successful results nor typed errors can carry a path, secret reference, grant, or value.
pub trait CredentialProfileRegistry: Send + Sync {
    fn snapshot(
        &self,
        scope: &CredentialScope,
    ) -> Result<CredentialProfileRegistrySnapshot, CredentialProfileError>;

    fn status(
        &self,
        key: &CredentialProfileKey,
    ) -> Result<Option<CredentialProfileStatus>, CredentialProfileError>;

    fn create_reference(
        &self,
        request: CreateCredentialProfileReference,
    ) -> Result<CredentialProfileStatus, CredentialProfileError>;

    fn update_metadata(
        &self,
        request: UpdateCredentialProfileMetadata,
    ) -> Result<CredentialProfileStatus, CredentialProfileError>;

    fn set_disabled(
        &self,
        request: SetCredentialProfileDisabled,
    ) -> Result<CredentialProfileStatus, CredentialProfileError>;
}

fn validate_scope_segment(value: &str) -> Result<(), CredentialProfileError> {
    if !portable_identifier(value, MAX_SCOPE_SEGMENT_BYTES, true) {
        return Err(CredentialProfileError::new(
            CredentialProfileErrorCode::InvalidScopeSegment,
            "scope",
            "scope segments must be bounded canonical portable identifiers",
        ));
    }
    Ok(())
}

fn validate_provider(value: &str) -> Result<(), CredentialProfileError> {
    if !portable_identifier(value, MAX_PROFILE_IDENTIFIER_BYTES, false) {
        return Err(CredentialProfileError::new(
            CredentialProfileErrorCode::InvalidProvider,
            "provider",
            "credential providers must be bounded portable identifiers",
        ));
    }
    Ok(())
}

fn validate_profile_alias(value: &str) -> Result<(), CredentialProfileError> {
    if !portable_identifier(value, MAX_PROFILE_IDENTIFIER_BYTES, false) {
        return Err(CredentialProfileError::new(
            CredentialProfileErrorCode::InvalidProfileAlias,
            "profile_alias",
            "credential profile aliases must be bounded portable identifiers",
        ));
    }
    Ok(())
}

fn portable_identifier(value: &str, max_bytes: usize, allow_at: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value != "."
        && value != ".."
        && !value.contains("..")
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'-' | b'.' | b'+')
                || (allow_at && byte == b'@')
        })
}

fn validate_expected_identity(value: &str) -> Result<(), CredentialProfileError> {
    if value.is_empty()
        || value.len() > MAX_EXPECTED_IDENTITY_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(CredentialProfileError::new(
            CredentialProfileErrorCode::InvalidExpectedIdentity,
            "expected_identity",
            "expected identities must be bounded nonempty control-free metadata",
        ));
    }
    Ok(())
}

fn secure_binding_scheme(url: &Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => match url.host() {
            Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
            Some(Host::Ipv4(address)) => address.is_loopback(),
            Some(Host::Ipv6(address)) => address.is_loopback(),
            None => false,
        },
        _ => false,
    }
}

const fn invalid_binding_url() -> CredentialProfileError {
    CredentialProfileError::new(
        CredentialProfileErrorCode::InvalidBindingUrl,
        "binding_url",
        "credential binding URLs must be canonical secure endpoints without credentials or fragments",
    )
}

const fn invalid_status() -> CredentialProfileError {
    CredentialProfileError::new(
        CredentialProfileErrorCode::InvalidStatus,
        "status",
        "credential profile availability, default, and auth state are inconsistent",
    )
}

#[cfg(test)]
mod tests {
    use std::{sync::Mutex, thread};

    use serde_json::{json, Value};

    use super::*;

    fn scope(principal: &str, workspace: &str) -> CredentialScope {
        CredentialScope::new(principal, workspace).expect("valid scope")
    }

    fn key(alias: &str) -> CredentialProfileKey {
        CredentialProfileKey::new(
            scope("owner", "default"),
            "google-workspace",
            alias,
            CredentialProfileBinding::Provider,
        )
        .expect("valid key")
    }

    fn revision(value: u64) -> CredentialProfileRevision {
        CredentialProfileRevision::new(value).expect("valid revision")
    }

    fn status(alias: &str, is_default: bool) -> CredentialProfileStatus {
        let metadata = CredentialProfileMetadata::new(
            key(alias),
            Some(ExpectedCredentialIdentity::new(format!("{alias}@example.com")).unwrap()),
            is_default,
            CredentialProfileAvailability::Enabled,
            revision(1),
        )
        .expect("valid metadata");
        CredentialProfileStatus::new(metadata, AuthState::Ready).expect("valid status")
    }

    #[test]
    fn logical_identifiers_are_strict_and_deserialization_cannot_bypass_validation() {
        for invalid in [
            "",
            ".",
            "..",
            "../other",
            "safe..other",
            "with/slash",
            "with\\slash",
            " leading",
            "email@example.com",
            "control\nvalue",
        ] {
            assert!(CredentialProfileAlias::new(invalid).is_err(), "{invalid:?}");
            assert!(serde_json::from_value::<CredentialProfileAlias>(json!(invalid)).is_err());
        }
        assert!(CredentialProfileAlias::new("work-1").is_ok());
        assert!(ScopeSegment::new("owner@example.com").is_ok());
        assert!(CredentialProviderId::new("google-workspace").is_ok());

        let canary = "INVALID_PROFILE_CANARY/secret";
        let error = CredentialProfileAlias::new(canary).expect_err("invalid alias");
        let serialized = serde_json::to_string(&error).expect("serialize error");
        assert!(!error.to_string().contains(canary));
        assert!(!serialized.contains(canary));
    }

    #[test]
    fn mcp_binding_urls_are_canonical_secure_and_identity_defining() {
        let resource = CanonicalCredentialUrl::new("HTTPS://Example.COM:443/mcp")
            .expect("secure resource URL");
        let issuer = CanonicalCredentialUrl::new("https://AUTH.example.com/oauth/")
            .expect("secure issuer URL");
        assert_eq!(resource.as_str(), "https://example.com/mcp");
        assert_eq!(issuer.as_str(), "https://auth.example.com/oauth/");
        assert!(CanonicalCredentialUrl::new("http://localhost:8765/mcp").is_ok());
        assert!(CanonicalCredentialUrl::new("http://127.0.0.1:8765/mcp").is_ok());

        for invalid in [
            "http://provider.example/mcp",
            "https://user:password@provider.example/mcp",
            "https://provider.example/mcp#fragment",
            "https://provider.example/mcp?access_token=canary",
            "file:///tmp/mcp.sock",
            "not a URL",
        ] {
            assert!(CanonicalCredentialUrl::new(invalid).is_err(), "{invalid}");
        }

        let first = CredentialProfileKey::new(
            scope("owner", "default"),
            "provider-mcp",
            "personal",
            CredentialProfileBinding::McpOauth {
                resource_url: resource.clone(),
                authorization_issuer: issuer.clone(),
            },
        )
        .unwrap();
        let second = CredentialProfileKey::new(
            scope("owner", "default"),
            "provider-mcp",
            "personal",
            CredentialProfileBinding::McpOauth {
                resource_url: CanonicalCredentialUrl::new("https://other.example/mcp").unwrap(),
                authorization_issuer: issuer,
            },
        )
        .unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn disabled_and_default_statuses_fail_closed() {
        assert_eq!(
            CredentialProfileMetadata::new(
                key("work"),
                None,
                true,
                CredentialProfileAvailability::Disabled,
                revision(1),
            )
            .expect_err("disabled default")
            .code,
            CredentialProfileErrorCode::InvalidStatus
        );

        let disabled = CredentialProfileMetadata::new(
            key("work"),
            None,
            false,
            CredentialProfileAvailability::Disabled,
            revision(1),
        )
        .unwrap();
        assert_eq!(
            CredentialProfileStatus::new(disabled.clone(), AuthState::Ready)
                .expect_err("disabled ready")
                .code,
            CredentialProfileErrorCode::InvalidStatus
        );
        assert!(CredentialProfileStatus::new(disabled, AuthState::Denied).is_ok());
    }

    #[test]
    fn snapshots_are_bounded_sorted_unique_scope_exact_and_single_default() {
        let snapshot = CredentialProfileRegistrySnapshot::new(
            scope("owner", "default"),
            vec![status("work", false), status("personal", true)],
        )
        .expect("valid snapshot");
        assert_eq!(snapshot.profiles()[0].key().alias.as_str(), "personal");
        assert_eq!(snapshot.profiles()[1].key().alias.as_str(), "work");

        let duplicate = status("work", false);
        assert_eq!(
            CredentialProfileRegistrySnapshot::new(
                scope("owner", "default"),
                vec![duplicate.clone(), duplicate],
            )
            .expect_err("duplicate")
            .code,
            CredentialProfileErrorCode::DuplicateProfile
        );
        assert_eq!(
            CredentialProfileRegistrySnapshot::new(
                scope("owner", "default"),
                vec![status("work", true), status("personal", true)],
            )
            .expect_err("multiple defaults")
            .code,
            CredentialProfileErrorCode::MultipleDefaults
        );

        let other_metadata = CredentialProfileMetadata::new(
            CredentialProfileKey::new(
                scope("other", "default"),
                "google-workspace",
                "work",
                CredentialProfileBinding::Provider,
            )
            .unwrap(),
            None,
            false,
            CredentialProfileAvailability::Enabled,
            revision(1),
        )
        .unwrap();
        let other = CredentialProfileStatus::new(other_metadata, AuthState::Missing).unwrap();
        assert_eq!(
            CredentialProfileRegistrySnapshot::new(scope("owner", "default"), vec![other])
                .expect_err("scope mismatch")
                .code,
            CredentialProfileErrorCode::ScopeMismatch
        );

        let oversized = (0..=MAX_PROFILES_PER_SCOPE)
            .map(|index| status(&format!("p{index:03}"), false))
            .collect();
        assert_eq!(
            CredentialProfileRegistrySnapshot::new(scope("owner", "default"), oversized)
                .expect_err("oversized")
                .code,
            CredentialProfileErrorCode::CollectionTooLarge
        );
    }

    #[derive(Debug)]
    struct ContractRegistry {
        current: Mutex<CredentialProfileStatus>,
    }

    impl ContractRegistry {
        fn current(&self) -> CredentialProfileStatus {
            self.current.lock().expect("registry lock").clone()
        }
    }

    impl CredentialProfileRegistry for ContractRegistry {
        fn snapshot(
            &self,
            requested_scope: &CredentialScope,
        ) -> Result<CredentialProfileRegistrySnapshot, CredentialProfileError> {
            CredentialProfileRegistrySnapshot::new(requested_scope.clone(), vec![self.current()])
        }

        fn status(
            &self,
            requested_key: &CredentialProfileKey,
        ) -> Result<Option<CredentialProfileStatus>, CredentialProfileError> {
            let current = self.current();
            Ok((current.key() == requested_key).then_some(current))
        }

        fn create_reference(
            &self,
            _request: CreateCredentialProfileReference,
        ) -> Result<CredentialProfileStatus, CredentialProfileError> {
            Ok(self.current())
        }

        fn update_metadata(
            &self,
            _request: UpdateCredentialProfileMetadata,
        ) -> Result<CredentialProfileStatus, CredentialProfileError> {
            Ok(self.current())
        }

        fn set_disabled(
            &self,
            _request: SetCredentialProfileDisabled,
        ) -> Result<CredentialProfileStatus, CredentialProfileError> {
            Ok(self.current())
        }
    }

    #[test]
    fn registry_trait_is_object_safe_and_every_result_is_metadata_only() {
        let registry = ContractRegistry {
            current: Mutex::new(status("work", true)),
        };
        let registry: &dyn CredentialProfileRegistry = &registry;
        let snapshot = registry
            .snapshot(&scope("owner", "default"))
            .expect("snapshot");
        let value = serde_json::to_value(snapshot).expect("serialize snapshot");
        assert_eq!(
            value,
            json!({
                "schema_version": CREDENTIAL_PROFILE_REGISTRY_V1,
                "scope": {"principal": "owner", "workspace": "default"},
                "profiles": [{
                    "metadata": {
                        "key": {
                            "scope": {"principal": "owner", "workspace": "default"},
                            "provider": "google-workspace",
                            "alias": "work",
                            "binding": {"kind": "provider"}
                        },
                        "expected_identity": "work@example.com",
                        "is_default": true,
                        "availability": "enabled",
                        "revision": 1
                    },
                    "auth_state": "ready"
                }]
            })
        );
        assert_metadata_keys_only(&value);

        let existing = registry.status(&key("work")).unwrap().unwrap();
        let created = registry
            .create_reference(CreateCredentialProfileReference::new(
                key("work"),
                None,
                true,
            ))
            .unwrap();
        let updated = registry
            .update_metadata(UpdateCredentialProfileMetadata::new(
                key("work"),
                ExpectedIdentityUpdate::Preserve,
                DefaultProfileUpdate::Preserve,
                revision(1),
            ))
            .unwrap();
        let disabled = registry
            .set_disabled(SetCredentialProfileDisabled::new(
                key("work"),
                true,
                revision(1),
            ))
            .unwrap();
        assert_eq!(existing, created);
        assert_eq!(created, updated);
        assert_eq!(updated, disabled);
    }

    fn assert_metadata_keys_only(value: &Value) {
        let forbidden = [
            "auth_root",
            "path",
            "secret_bindings",
            "secret_ref",
            "credential",
            "credential_token",
            "grant",
            "environment",
            "value",
        ];
        let mut pending = vec![value];
        while let Some(current) = pending.pop() {
            match current {
                Value::Object(map) => {
                    for (key, child) in map {
                        assert!(!forbidden.contains(&key.as_str()), "forbidden key {key}");
                        pending.push(child);
                    }
                },
                Value::Array(items) => pending.extend(items),
                _ => {},
            }
        }
    }

    #[test]
    fn maximum_snapshot_serializes_on_a_small_stack_without_recursion() {
        let result = thread::Builder::new()
            .name("credential-profile-snapshot-small-stack".to_owned())
            .stack_size(128 * 1024)
            .spawn(|| {
                let profiles = (0..MAX_PROFILES_PER_SCOPE)
                    .map(|index| status(&format!("p{index:03}"), false))
                    .collect();
                let snapshot =
                    CredentialProfileRegistrySnapshot::new(scope("owner", "default"), profiles)
                        .expect("maximum snapshot");
                serde_json::to_vec(&snapshot).expect("serialize maximum snapshot")
            })
            .expect("spawn small-stack profile test")
            .join()
            .expect("profile snapshot must not panic or overflow");

        let serialized: Value = serde_json::from_slice(&result).expect("parse snapshot JSON");
        assert_eq!(
            serialized["profiles"]
                .as_array()
                .expect("profiles array")
                .len(),
            MAX_PROFILES_PER_SCOPE
        );
    }
}
