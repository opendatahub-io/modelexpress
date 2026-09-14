// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The cluster TLS profile from `apiservers.config.openshift.io/cluster`, and
//! how a CR's `tls` block resolves against it.
//!
//! The profile applies only when the APIServer's `tlsAdherence` asks every
//! component to follow it, as `ShouldHonorClusterTLSProfile` in library-go
//! decides. Otherwise the operator keeps its own default, Intermediate.
//!
//! The named profiles mirror `TLSProfiles` in openshift/api
//! (config/v1/types_tlssecurityprofile.go). The server takes the values as
//! written there, so nothing is translated here.

use crate::crd::TlsConfig;
use futures::StreamExt;
use kube::Client;
use kube::api::{Api, ApiResource, DynamicObject, GroupVersionKind};
use kube::runtime::WatchStreamExt;
use kube::runtime::watcher;
use kube::runtime::watcher::metadata_watcher;
use serde::Deserialize;
use tokio_stream::wrappers::ReceiverStream;

pub const API_GROUP: &str = "config.openshift.io";
pub const API_VERSION: &str = "v1";
pub const KIND: &str = "APIServer";
pub const PLURAL: &str = "apiservers";
pub const CLUSTER_OBJECT: &str = "cluster";

/// Where the Secret's `tls.crt` and `tls.key` land in the server container.
pub const MOUNT_PATH: &str = "/etc/modelexpress/tls";

/// A minimum protocol version plus the ciphers to offer, in the spelling the
/// server flags accept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsProfile {
    pub min_version: String,
    pub ciphers: Vec<String>,
    /// Key exchange groups in preference order. The server drops names its
    /// OpenSSL cannot negotiate, so post-quantum entries are safe to pass on.
    pub groups: Vec<String>,
}

/// The groups every named profile carries in openshift/api.
const PROFILE_GROUPS: [&str; 4] = ["X25519MLKEM768", "X25519", "secp256r1", "secp384r1"];

const TLS13_SUITES: [&str; 3] = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
];

const INTERMEDIATE_TLS12_CIPHERS: [&str; 6] = [
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
];

const OLD_EXTRA_CIPHERS: [&str; 15] = [
    "ECDHE-ECDSA-AES128-SHA256",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-ECDSA-AES128-SHA",
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-ECDSA-AES256-SHA384",
    "ECDHE-RSA-AES256-SHA384",
    "ECDHE-ECDSA-AES256-SHA",
    "ECDHE-RSA-AES256-SHA",
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
    "AES128-SHA256",
    "AES256-SHA256",
    "AES128-SHA",
    "AES256-SHA",
    "DES-CBC3-SHA",
];

fn strings(parts: &[&[&str]]) -> Vec<String> {
    parts
        .iter()
        .flat_map(|part| part.iter().map(|s| (*s).to_string()))
        .collect()
}

impl TlsProfile {
    #[must_use]
    pub fn old() -> Self {
        Self {
            min_version: "VersionTLS10".to_string(),
            ciphers: strings(&[
                &TLS13_SUITES,
                &INTERMEDIATE_TLS12_CIPHERS,
                &OLD_EXTRA_CIPHERS,
            ]),
            groups: strings(&[&PROFILE_GROUPS]),
        }
    }

    #[must_use]
    pub fn intermediate() -> Self {
        Self {
            min_version: "VersionTLS12".to_string(),
            ciphers: strings(&[&TLS13_SUITES, &INTERMEDIATE_TLS12_CIPHERS]),
            groups: strings(&[&PROFILE_GROUPS]),
        }
    }

    #[must_use]
    pub fn modern() -> Self {
        Self {
            min_version: "VersionTLS13".to_string(),
            ciphers: strings(&[&TLS13_SUITES]),
            groups: strings(&[&PROFILE_GROUPS]),
        }
    }
}

/// Intermediate is what OpenShift applies when the profile is unset, and what
/// a cluster without the OpenShift config API gets.
impl Default for TlsProfile {
    fn default() -> Self {
        Self::intermediate()
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecurityProfile {
    #[serde(rename = "type")]
    kind: Option<String>,
    custom: Option<CustomProfile>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CustomProfile {
    ciphers: Option<Vec<String>>,
    groups: Option<Vec<String>>,
    #[serde(rename = "minTLSVersion")]
    min_tls_version: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProfileError {
    #[error("tlsSecurityProfile type is Custom but has no custom body")]
    CustomMissing,
}

/// Interpret an APIServer's `spec.tlsSecurityProfile`, matching
/// `GetTLSProfileSpec` in openshift/controller-runtime-common: null, an
/// empty type and an unknown type are Intermediate; Custom is taken as
/// written and is an error without its body.
pub fn from_security_profile(value: &serde_json::Value) -> Result<TlsProfile, ProfileError> {
    let profile: SecurityProfile = serde_json::from_value(value.clone()).unwrap_or_default();
    Ok(match profile.kind.as_deref() {
        Some("Old") => TlsProfile::old(),
        Some("Modern") => TlsProfile::modern(),
        Some("Custom") => {
            let custom = profile.custom.ok_or(ProfileError::CustomMissing)?;
            TlsProfile {
                min_version: custom.min_tls_version.unwrap_or_default(),
                ciphers: custom.ciphers.unwrap_or_default(),
                groups: custom.groups.unwrap_or_default(),
            }
        }
        _ => TlsProfile::intermediate(),
    })
}

/// `spec.tlsAdherence` of the cluster APIServer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsAdherence {
    /// Unset or empty.
    NoOpinion,
    LegacyAdheringComponentsOnly,
    StrictAllComponents,
    /// A value newer than this operator.
    Unknown(String),
}

impl TlsAdherence {
    #[must_use]
    pub fn from_spec(value: Option<&str>) -> Self {
        match value {
            None | Some("") => Self::NoOpinion,
            Some("LegacyAdheringComponentsOnly") => Self::LegacyAdheringComponentsOnly,
            Some("StrictAllComponents") => Self::StrictAllComponents,
            Some(other) => Self::Unknown(other.to_string()),
        }
    }

    /// Whether components outside the legacy set follow the cluster profile.
    /// Unknown values do, so a newer, stricter policy fails secure.
    #[must_use]
    pub fn honors_cluster_profile(&self) -> bool {
        match self {
            Self::NoOpinion | Self::LegacyAdheringComponentsOnly => false,
            Self::StrictAllComponents | Self::Unknown(_) => true,
        }
    }
}

/// The profile this operator follows given an APIServer `spec`: the cluster
/// profile when `tlsAdherence` honors it, Intermediate otherwise. The profile
/// is not parsed when it is not honored, so a broken Custom profile the
/// cluster does not enforce is not an error here either.
pub fn from_apiserver_spec(spec: &serde_json::Value) -> Result<TlsProfile, ProfileError> {
    let adherence = TlsAdherence::from_spec(spec["tlsAdherence"].as_str());
    if !adherence.honors_cluster_profile() {
        return Ok(TlsProfile::default());
    }
    from_security_profile(&spec["tlsSecurityProfile"])
}

/// The `tls` block after the cluster profile fills in what the CR left unset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedTls {
    pub secret_name: String,
    pub service_ca: bool,
    pub min_version: String,
    pub ciphers: Vec<String>,
    pub groups: Vec<String>,
}

#[must_use]
pub fn resolve(config: &TlsConfig, cluster: &TlsProfile) -> ResolvedTls {
    ResolvedTls {
        secret_name: config.secret_name.clone(),
        service_ca: config.service_ca,
        min_version: config
            .min_version
            .clone()
            .unwrap_or_else(|| cluster.min_version.clone()),
        ciphers: if config.cipher_suites.is_empty() {
            cluster.ciphers.clone()
        } else {
            config.cipher_suites.clone()
        },
        groups: if config.groups.is_empty() {
            cluster.groups.clone()
        } else {
            config.groups.clone()
        },
    }
}

/// True when the CR needs the cluster profile at all, so a fully pinned CR
/// never touches the OpenShift API.
#[must_use]
pub fn needs_cluster_profile(config: &TlsConfig) -> bool {
    config.min_version.is_none() || config.cipher_suites.is_empty() || config.groups.is_empty()
}

fn gvk() -> GroupVersionKind {
    GroupVersionKind::gvk(API_GROUP, API_VERSION, KIND)
}

fn api_resource() -> ApiResource {
    let mut resource = ApiResource::from_gvk(&gvk());
    resource.plural = PLURAL.to_string();
    resource
}

/// Fetch the profile to follow, honoring `tlsAdherence`. `None` means the
/// object or the whole API group is absent, which is any non-OpenShift
/// cluster. A 403 is returned as-is: the operator is missing RBAC it ships,
/// and that must not silently degrade to a default profile.
pub async fn fetch(client: &Client) -> Result<Option<TlsProfile>, FetchError> {
    let api = Api::<DynamicObject>::all_with(client.clone(), &api_resource());
    let object = api.get_opt(CLUSTER_OBJECT).await?;
    object
        .map(|obj| from_apiserver_spec(&obj.data["spec"]))
        .transpose()
        .map_err(FetchError::from)
}

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error(transparent)]
    Kube(#[from] kube::Error),
    #[error("apiservers.config.openshift.io/cluster: {0}")]
    Profile(#[from] ProfileError),
}

/// A stream that yields once per change to the cluster APIServer object, for
/// `Controller::reconcile_all_on`. `None` when the API group is not served.
///
/// The watcher runs on its own task and is bridged through a channel because
/// `reconcile_all_on` wants a `Sync` stream and the watcher is not one.
pub async fn change_stream(client: &Client, config: watcher::Config) -> Option<ReceiverStream<()>> {
    if kube::discovery::oneshot::pinned_kind(client, &gvk())
        .await
        .is_err()
    {
        return None;
    }
    let api = Api::<DynamicObject>::all_with(client.clone(), &api_resource());
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        let mut events = metadata_watcher(api, config).touched_objects().boxed();
        while let Some(event) = events.next().await {
            match event {
                Ok(_) => {
                    if tx.send(()).await.is_err() {
                        break;
                    }
                }
                Err(e) => tracing::warn!("APIServer watch error: {e}"),
            }
        }
    });
    Some(ReceiverStream::new(rx))
}

/// The profile to follow, re-read on every change to the cluster APIServer
/// object and yielded only when it differs from the last one, starting from
/// `initial`. A deleted object yields the Intermediate default. The stream
/// ends at once off OpenShift.
pub async fn profile_updates(client: Client, initial: TlsProfile) -> ReceiverStream<TlsProfile> {
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let Some(mut changes) = change_stream(&client, watcher::Config::default()).await else {
        return ReceiverStream::new(rx);
    };
    tokio::spawn(async move {
        let mut current = initial;
        while changes.next().await.is_some() {
            match fetch(&client).await {
                Ok(profile) => {
                    let profile = profile.unwrap_or_default();
                    if profile == current {
                        continue;
                    }
                    current = profile.clone();
                    if tx.send(profile).await.is_err() {
                        break;
                    }
                }
                Err(e) => tracing::warn!("re-reading cluster TLS profile after a change: {e}"),
            }
        }
    });
    ReceiverStream::new(rx)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use crate::crd::TlsConfig;
    use crate::tls_profile::{
        ProfileError, TlsAdherence, TlsProfile, from_apiserver_spec, from_security_profile,
        needs_cluster_profile, resolve,
    };
    use serde_json::json;

    fn profile(value: serde_json::Value) -> TlsProfile {
        from_security_profile(&value).expect("valid profile")
    }

    #[test]
    fn named_profiles_match_openshift_api() {
        let intermediate = TlsProfile::intermediate();
        assert_eq!(intermediate.min_version, "VersionTLS12");
        assert_eq!(intermediate.ciphers.len(), 9);
        assert_eq!(intermediate.ciphers[0], "TLS_AES_128_GCM_SHA256");
        assert_eq!(intermediate.ciphers[8], "ECDHE-RSA-CHACHA20-POLY1305");

        let modern = TlsProfile::modern();
        assert_eq!(modern.min_version, "VersionTLS13");
        assert_eq!(modern.ciphers.len(), 3);

        let old = TlsProfile::old();
        assert_eq!(old.min_version, "VersionTLS10");
        assert_eq!(old.ciphers.len(), 24);
        assert_eq!(old.ciphers[23], "DES-CBC3-SHA");
        assert!(old.ciphers.starts_with(&intermediate.ciphers));

        for profile in [&old, &intermediate, &modern] {
            assert_eq!(
                profile.groups,
                ["X25519MLKEM768", "X25519", "secp256r1", "secp384r1"]
            );
        }
    }

    #[test]
    fn default_is_intermediate() {
        assert_eq!(TlsProfile::default(), TlsProfile::intermediate());
    }

    #[test]
    fn null_empty_and_unknown_types_are_intermediate() {
        assert_eq!(profile(serde_json::Value::Null), TlsProfile::intermediate());
        assert_eq!(profile(json!({})), TlsProfile::intermediate());
        assert_eq!(profile(json!({"type": ""})), TlsProfile::intermediate());
        assert_eq!(
            profile(json!({"type": "Quantum"})),
            TlsProfile::intermediate()
        );
    }

    #[test]
    fn named_types_resolve() {
        assert_eq!(
            profile(json!({"type": "Old", "old": {}})),
            TlsProfile::old()
        );
        assert_eq!(
            profile(json!({"type": "Intermediate", "intermediate": {}})),
            TlsProfile::intermediate()
        );
        assert_eq!(
            profile(json!({"type": "Modern", "modern": {}})),
            TlsProfile::modern()
        );
    }

    #[test]
    fn custom_profile_is_taken_verbatim() {
        let custom = profile(json!({
            "type": "Custom",
            "custom": {
                "minTLSVersion": "VersionTLS13",
                "ciphers": ["TLS_AES_256_GCM_SHA384"],
                "groups": ["X25519"]
            }
        }));
        assert_eq!(custom.min_version, "VersionTLS13");
        assert_eq!(custom.ciphers, ["TLS_AES_256_GCM_SHA384"]);
        assert_eq!(custom.groups, ["X25519"]);
    }

    #[test]
    fn custom_profile_without_body_is_an_error() {
        assert_eq!(
            from_security_profile(&json!({"type": "Custom"})),
            Err(ProfileError::CustomMissing)
        );
    }

    #[test]
    fn custom_profile_is_not_padded_from_intermediate() {
        let custom = profile(json!({
            "type": "Custom",
            "custom": {"minTLSVersion": "VersionTLS11"}
        }));
        assert_eq!(custom.min_version, "VersionTLS11");
        assert!(custom.ciphers.is_empty());
        assert!(custom.groups.is_empty());
    }

    fn config() -> TlsConfig {
        TlsConfig {
            secret_name: "mx-tls".to_string(),
            service_ca: true,
            min_version: None,
            cipher_suites: Vec::new(),
            groups: Vec::new(),
        }
    }

    #[test]
    fn resolve_takes_cluster_values_when_unset() {
        let resolved = resolve(&config(), &TlsProfile::modern());
        assert_eq!(resolved.secret_name, "mx-tls");
        assert!(resolved.service_ca);
        assert_eq!(resolved.min_version, "VersionTLS13");
        assert_eq!(resolved.ciphers, TlsProfile::modern().ciphers);
        assert_eq!(resolved.groups, TlsProfile::modern().groups);
        assert!(needs_cluster_profile(&config()));
    }

    #[test]
    fn resolve_prefers_cr_overrides() {
        let mut config = config();
        config.min_version = Some("TLS1.2".to_string());
        config.cipher_suites = vec!["ECDHE-RSA-AES256-GCM-SHA384".to_string()];
        assert!(
            needs_cluster_profile(&config),
            "groups still come from the cluster"
        );
        config.groups = vec!["secp256r1".to_string()];
        let resolved = resolve(&config, &TlsProfile::modern());
        assert_eq!(resolved.min_version, "TLS1.2");
        assert_eq!(resolved.ciphers, ["ECDHE-RSA-AES256-GCM-SHA384"]);
        assert_eq!(resolved.groups, ["secp256r1"]);
        assert!(!needs_cluster_profile(&config));
    }

    #[test]
    fn partial_override_still_needs_the_cluster() {
        let mut config = config();
        config.min_version = Some("TLS1.3".to_string());
        assert!(needs_cluster_profile(&config));
        let resolved = resolve(&config, &TlsProfile::intermediate());
        assert_eq!(resolved.min_version, "TLS1.3");
        assert_eq!(resolved.ciphers, TlsProfile::intermediate().ciphers);
        assert_eq!(resolved.groups, TlsProfile::intermediate().groups);
    }

    #[test]
    fn adherence_values_parse_like_the_api() {
        assert_eq!(TlsAdherence::from_spec(None), TlsAdherence::NoOpinion);
        assert_eq!(TlsAdherence::from_spec(Some("")), TlsAdherence::NoOpinion);
        assert_eq!(
            TlsAdherence::from_spec(Some("LegacyAdheringComponentsOnly")),
            TlsAdherence::LegacyAdheringComponentsOnly
        );
        assert_eq!(
            TlsAdherence::from_spec(Some("StrictAllComponents")),
            TlsAdherence::StrictAllComponents
        );
        assert_eq!(
            TlsAdherence::from_spec(Some("strictallcomponents")),
            TlsAdherence::Unknown("strictallcomponents".to_string())
        );
    }

    #[test]
    fn only_strict_and_unknown_adherence_honor_the_profile() {
        assert!(!TlsAdherence::NoOpinion.honors_cluster_profile());
        assert!(!TlsAdherence::LegacyAdheringComponentsOnly.honors_cluster_profile());
        assert!(TlsAdherence::StrictAllComponents.honors_cluster_profile());
        assert!(TlsAdherence::Unknown("FutureStrict".to_string()).honors_cluster_profile());
    }

    #[test]
    fn unset_adherence_keeps_intermediate_under_a_modern_profile() {
        let spec = json!({"tlsSecurityProfile": {"type": "Modern", "modern": {}}});
        assert_eq!(from_apiserver_spec(&spec), Ok(TlsProfile::intermediate()));
        let spec = json!({"tlsAdherence": "", "tlsSecurityProfile": {"type": "Modern"}});
        assert_eq!(from_apiserver_spec(&spec), Ok(TlsProfile::intermediate()));
    }

    #[test]
    fn legacy_adherence_keeps_intermediate_under_an_old_profile() {
        let spec = json!({
            "tlsAdherence": "LegacyAdheringComponentsOnly",
            "tlsSecurityProfile": {"type": "Old", "old": {}}
        });
        assert_eq!(from_apiserver_spec(&spec), Ok(TlsProfile::intermediate()));
    }

    #[test]
    fn strict_adherence_applies_the_profile() {
        let spec = json!({
            "tlsAdherence": "StrictAllComponents",
            "tlsSecurityProfile": {"type": "Modern", "modern": {}}
        });
        assert_eq!(from_apiserver_spec(&spec), Ok(TlsProfile::modern()));
    }

    #[test]
    fn unknown_adherence_applies_the_profile() {
        let spec = json!({
            "tlsAdherence": "SomePolicyFromTheFuture",
            "tlsSecurityProfile": {"type": "Old", "old": {}}
        });
        assert_eq!(from_apiserver_spec(&spec), Ok(TlsProfile::old()));
    }

    #[test]
    fn strict_adherence_with_no_profile_is_intermediate() {
        let spec = json!({"tlsAdherence": "StrictAllComponents"});
        assert_eq!(from_apiserver_spec(&spec), Ok(TlsProfile::intermediate()));
    }

    #[test]
    fn broken_custom_profile_matters_only_when_honored() {
        let broken = json!({"type": "Custom"});
        assert_eq!(
            from_apiserver_spec(&json!({"tlsSecurityProfile": broken})),
            Ok(TlsProfile::intermediate())
        );
        assert_eq!(
            from_apiserver_spec(&json!({
                "tlsAdherence": "StrictAllComponents",
                "tlsSecurityProfile": broken
            })),
            Err(ProfileError::CustomMissing)
        );
    }

    #[test]
    fn empty_spec_is_intermediate() {
        assert_eq!(
            from_apiserver_spec(&serde_json::Value::Null),
            Ok(TlsProfile::intermediate())
        );
        assert_eq!(
            from_apiserver_spec(&json!({})),
            Ok(TlsProfile::intermediate())
        );
    }
}
