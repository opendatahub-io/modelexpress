// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! TLS settings for the server pods: the CR's `tls` block over whatever
//! defaults the platform supplies.
//!
//! The operator takes its defaults through [`TlsDefaults`]. The plain build
//! uses [`NoDefaults`], so a CR renders exactly the settings it pins and the
//! server keeps its own defaults for the rest. A platform with a cluster-wide
//! policy plugs in a source that reads it and reports changes.

use crate::crd::TlsConfig;
use futures::Stream;
use std::pin::Pin;

/// Where the Secret's `tls.crt` and `tls.key` land in the server container.
pub const MOUNT_PATH: &str = "/etc/modelexpress/tls";

/// Minimum version, ciphers and groups, in the spelling the server flags
/// accept. Unset or empty means the listener's own default.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TlsSettings {
    pub min_version: Option<String>,
    pub ciphers: Vec<String>,
    pub groups: Vec<String>,
}

pub type TlsDefaultsError = Box<dyn std::error::Error + Send + Sync>;

/// Changes to the defaults. `Sync` because kube's `reconcile_all_on` needs it.
pub type TlsUpdates = Pin<Box<dyn Stream<Item = TlsSettings> + Send + Sync>>;

/// Supplies the settings a CR leaves unset.
#[async_trait::async_trait]
pub trait TlsDefaults: Send + Sync {
    /// The defaults as of now.
    async fn current(&self) -> Result<TlsSettings, TlsDefaultsError>;

    /// A stream yielding the defaults each time they change. It stays
    /// pending for a source that never changes.
    async fn updates(&self) -> TlsUpdates;
}

/// No platform defaults: only what the CR pins is rendered.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoDefaults;

#[async_trait::async_trait]
impl TlsDefaults for NoDefaults {
    async fn current(&self) -> Result<TlsSettings, TlsDefaultsError> {
        Ok(TlsSettings::default())
    }

    async fn updates(&self) -> TlsUpdates {
        Box::pin(futures::stream::pending())
    }
}

/// The `tls` block after `defaults` fill in what the CR left unset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedTls {
    pub secret_name: String,
    pub settings: TlsSettings,
}

#[must_use]
pub fn resolve(config: &TlsConfig, defaults: &TlsSettings) -> ResolvedTls {
    ResolvedTls {
        secret_name: config.secret_name.clone(),
        settings: TlsSettings {
            min_version: config
                .min_version
                .clone()
                .or_else(|| defaults.min_version.clone()),
            ciphers: if config.cipher_suites.is_empty() {
                defaults.ciphers.clone()
            } else {
                config.cipher_suites.clone()
            },
            groups: if config.groups.is_empty() {
                defaults.groups.clone()
            } else {
                config.groups.clone()
            },
        },
    }
}

/// True when the CR leaves something to the defaults, so a fully pinned CR
/// never asks the source.
#[must_use]
pub fn needs_defaults(config: &TlsConfig) -> bool {
    config.min_version.is_none() || config.cipher_suites.is_empty() || config.groups.is_empty()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use crate::crd::TlsConfig;
    use crate::tls::{NoDefaults, TlsDefaults, TlsSettings, needs_defaults, resolve};
    use futures::FutureExt;
    use futures::StreamExt;

    fn config() -> TlsConfig {
        TlsConfig {
            secret_name: "mx-tls".to_string(),
            min_version: None,
            cipher_suites: Vec::new(),
            groups: Vec::new(),
        }
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    fn defaults() -> TlsSettings {
        TlsSettings {
            min_version: Some("VersionTLS13".to_string()),
            ciphers: strings(&["TLS_AES_256_GCM_SHA384"]),
            groups: strings(&["X25519"]),
        }
    }

    #[test]
    fn unset_fields_take_the_defaults() {
        let resolved = resolve(&config(), &defaults());
        assert_eq!(resolved.secret_name, "mx-tls");
        assert_eq!(resolved.settings, defaults());
        assert!(needs_defaults(&config()));
    }

    #[test]
    fn pinned_fields_win() {
        let mut config = config();
        config.min_version = Some("TLS1.2".to_string());
        config.cipher_suites = strings(&["ECDHE-RSA-AES256-GCM-SHA384"]);
        assert!(
            needs_defaults(&config),
            "groups still come from the defaults"
        );
        config.groups = strings(&["secp256r1"]);
        let resolved = resolve(&config, &defaults());
        assert_eq!(resolved.settings.min_version.as_deref(), Some("TLS1.2"));
        assert_eq!(resolved.settings.ciphers, ["ECDHE-RSA-AES256-GCM-SHA384"]);
        assert_eq!(resolved.settings.groups, ["secp256r1"]);
        assert!(!needs_defaults(&config));
    }

    #[test]
    fn partial_pin_keeps_the_other_defaults() {
        let mut config = config();
        config.min_version = Some("TLS1.3".to_string());
        let resolved = resolve(&config, &defaults());
        assert_eq!(resolved.settings.min_version.as_deref(), Some("TLS1.3"));
        assert_eq!(resolved.settings.ciphers, defaults().ciphers);
        assert_eq!(resolved.settings.groups, defaults().groups);
    }

    #[test]
    fn empty_defaults_leave_unset_fields_unset() {
        let resolved = resolve(&config(), &TlsSettings::default());
        assert_eq!(resolved.settings, TlsSettings::default());
    }

    #[tokio::test]
    async fn no_defaults_is_empty_and_never_changes() {
        assert_eq!(
            NoDefaults.current().await.expect("current"),
            TlsSettings::default()
        );
        let mut updates = NoDefaults.updates().await;
        assert!(updates.next().now_or_never().is_none());
    }
}
