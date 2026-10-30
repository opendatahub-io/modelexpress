// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Identity of a single registry entry.
//!
//! Registry backends key every record, lease, and claim on one string. A model name
//! alone is not a sufficient key:
//!
//! - two revisions of the same model must not share a download lease, or a request for
//!   one revision would coalesce onto a download of the other;
//! - a metadata-only download (`ignore_weights`) must not satisfy a later full-weight
//!   request, which would hand back a snapshot with no weights in it.
//!
//! [`EntryKey`] folds those three components into the single string the backends want
//! and parses it back, so cache eviction can still recover the model name and revision
//! it needs in order to delete the right files.
//!
//! An unpinned, full-weight entry encodes to the bare model name, so providers without
//! a revision concept keep the keys they have always used.
//!
//! # Encoding
//!
//! Anything else encodes as `mx1:<revision>:<flags>:<model_name>`. The model name goes
//! last because it is the only field with no character restrictions — a GCS object path
//! accepts almost any byte, so a name like `gs://bucket/models/foo:m:bar` must not be
//! able to impersonate the other fields. Putting it last means nothing after it needs
//! parsing, and the round trip is exact for any name.
//!
//! The revision field does have to avoid `:`, which holds because it is always a commit
//! identifier: Git forbids `:` in ref names, and resolved revisions are commit SHAs.
//!
//! An entry in a tenant's cache partition encodes as
//! `mxt1:<tenant>:<revision>:<flags>:<model_name>`. The tenant is a namespace, so it
//! holds no `:`.

use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};

/// Marks a key that carries a revision or weight mode. Versioned so the format can
/// change without misreading old keys.
const STRUCTURED_PREFIX: &str = "mx1:";
/// Marks a key scoped to a tenant's cache partition.
const TENANT_PREFIX: &str = "mxt1:";
/// Where tenant partitions live under the cache root.
const PARTITIONS_DIR: &str = ".modelexpress/tenants";
/// Weight-mode field values.
const METADATA_FLAG: &str = "m";
const FULL_WEIGHT_FLAG: &str = "-";

/// The namespace whose cache partition an entry lives in, validated as a DNS-1123
/// label.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tenant(String);

impl Tenant {
    /// `None` unless `namespace` is a DNS-1123 label.
    pub fn new(namespace: &str) -> Option<Self> {
        crate::config::is_dns1123_label(namespace).then(|| Self(namespace.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for Tenant {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// `tenant`'s cache directory under `cache_root`, or the root itself when untenanted.
pub fn partition(cache_root: &Path, tenant: Option<&Tenant>) -> PathBuf {
    match tenant {
        Some(tenant) => cache_root.join(PARTITIONS_DIR).join(tenant.as_str()),
        None => cache_root.to_path_buf(),
    }
}

/// The components a registry key is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryKey {
    /// Cache partition the entry belongs to; `None` when tenant isolation is off.
    pub tenant: Option<Tenant>,
    /// Provider-canonical model name.
    pub model_name: String,
    /// Immutable revision the request resolved to, when the provider has one.
    pub revision: Option<String>,
    /// Whether the entry covers a weightless (config/tokenizer only) download.
    pub metadata_only: bool,
}

impl EntryKey {
    pub fn new(
        model_name: impl Into<String>,
        revision: Option<String>,
        metadata_only: bool,
    ) -> Self {
        Self {
            tenant: None,
            model_name: model_name.into(),
            revision,
            metadata_only,
        }
    }

    #[must_use]
    pub fn in_tenant(mut self, tenant: Option<Tenant>) -> Self {
        self.tenant = tenant;
        self
    }

    /// Whether the key needs the structured form.
    ///
    /// A model name that happens to start with the prefix is encoded structurally even
    /// when it carries no revision, so it can never be mistaken for a key we wrote.
    fn needs_structured_form(&self) -> bool {
        self.revision.is_some()
            || self.metadata_only
            || self.model_name.starts_with(STRUCTURED_PREFIX)
            || self.model_name.starts_with(TENANT_PREFIX)
    }

    /// Recover the components of an encoded key.
    ///
    /// A key without the prefix parses back to an unpinned, full-weight entry, which is
    /// how records written before revisions existed are read.
    pub fn parse(key: &str) -> Self {
        if let Some(fields) = key.strip_prefix(TENANT_PREFIX) {
            let mut parts = fields.splitn(4, ':');
            return match (
                parts.next().and_then(Tenant::new),
                parts.next(),
                parts.next(),
                parts.next(),
            ) {
                (Some(tenant), Some(revision), Some(flags), Some(model_name)) => Self::new(
                    model_name,
                    (!revision.is_empty()).then(|| revision.to_string()),
                    flags == METADATA_FLAG,
                )
                .in_tenant(Some(tenant)),
                _ => Self::new(key, None, false),
            };
        }
        let Some(fields) = key.strip_prefix(STRUCTURED_PREFIX) else {
            return Self::new(key, None, false);
        };

        // `splitn(3)` leaves the model name — the only field that may contain `:` —
        // untouched in the final part.
        let mut parts = fields.splitn(3, ':');
        match (parts.next(), parts.next(), parts.next()) {
            (Some(revision), Some(flags), Some(model_name)) => Self::new(
                model_name,
                (!revision.is_empty()).then(|| revision.to_string()),
                flags == METADATA_FLAG,
            ),
            // Not a key this module produced; treat it as a plain model name.
            _ => Self::new(key, None, false),
        }
    }

    /// True when this entry belongs to `model_name` in `tenant`'s partition, whatever its
    /// revision or weight mode. Drives "forget everything about this model" operations
    /// such as `model clear`.
    pub fn belongs_to(&self, tenant: Option<&Tenant>, model_name: &str) -> bool {
        self.tenant.as_ref() == tenant && self.model_name == model_name
    }

    /// The directory holding this entry's files under `cache_root`.
    pub fn cache_dir(&self, cache_root: &Path) -> PathBuf {
        partition(cache_root, self.tenant.as_ref())
    }
}

impl Display for EntryKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let flags = if self.metadata_only {
            METADATA_FLAG
        } else {
            FULL_WEIGHT_FLAG
        };
        if let Some(tenant) = &self.tenant {
            return write!(
                f,
                "{TENANT_PREFIX}{tenant}:{}:{flags}:{}",
                self.revision.as_deref().unwrap_or(""),
                self.model_name
            );
        }
        if !self.needs_structured_form() {
            return f.write_str(&self.model_name);
        }
        write!(
            f,
            "{STRUCTURED_PREFIX}{}:{flags}:{}",
            self.revision.as_deref().unwrap_or(""),
            self.model_name
        )
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use crate::registry::entry_key::*;

    fn roundtrip(key: EntryKey) {
        assert_eq!(EntryKey::parse(&key.to_string()), key);
    }

    #[test]
    fn unpinned_full_weight_entry_encodes_to_the_bare_model_name() {
        let key = EntryKey::new("google-t5/t5-small", None, false);
        assert_eq!(key.to_string(), "google-t5/t5-small");
        roundtrip(key);
    }

    #[test]
    fn every_component_survives_a_roundtrip() {
        roundtrip(EntryKey::new(
            "org/model",
            Some("abc123".to_string()),
            false,
        ));
        roundtrip(EntryKey::new("org/model", None, true));
        roundtrip(EntryKey::new("org/model", Some("abc123".to_string()), true));
        roundtrip(EntryKey::new("gs://bucket/org/model/rev-1", None, false));
    }

    /// A GCS object path accepts almost any byte, so a model name is free to contain
    /// whatever the encoding uses as structure. Misreading one would evict a different
    /// model's files, so every shape has to round-trip exactly.
    #[test]
    fn a_model_name_cannot_impersonate_the_encoding() {
        for name in [
            "gs://bucket/models/foo:m:bar",
            "gs://bucket/models/foo#metadata",
            "gs://bucket/models/foo@rev:abc123",
            "mx1:abc123:m:gs://bucket/models/foo",
            "mx1:",
            ":::",
        ] {
            roundtrip(EntryKey::new(name, None, false));
            roundtrip(EntryKey::new(name, None, true));
            roundtrip(EntryKey::new(name, Some("abc123".to_string()), false));
        }
    }

    #[test]
    fn a_name_that_looks_like_a_key_stays_distinct_from_the_key_it_mimics() {
        // The literal name and the entry whose encoding it copies must not collide.
        let mimic = EntryKey::new("mx1:abc123:m:org/model", None, false);
        let real = EntryKey::new("org/model", Some("abc123".to_string()), true);
        assert_ne!(mimic.to_string(), real.to_string());
        assert_eq!(EntryKey::parse(&mimic.to_string()), mimic);
        assert_eq!(EntryKey::parse(&real.to_string()), real);
    }

    #[test]
    fn a_model_name_with_a_colon_keeps_its_revision_and_weight_mode() {
        let key = EntryKey::new("ngc/org/model:1.0", Some("abc123".to_string()), true);
        let parsed = EntryKey::parse(&key.to_string());
        assert_eq!(parsed.model_name, "ngc/org/model:1.0");
        assert_eq!(parsed.revision.as_deref(), Some("abc123"));
        assert!(parsed.metadata_only);
    }

    #[test]
    fn two_revisions_of_one_model_get_distinct_keys() {
        let first = EntryKey::new("org/model", Some("abc123".to_string()), false).to_string();
        let second = EntryKey::new("org/model", Some("def456".to_string()), false).to_string();
        assert_ne!(first, second);
    }

    #[test]
    fn metadata_only_and_full_weight_entries_do_not_collide() {
        let revision = Some("abc123".to_string());
        assert_ne!(
            EntryKey::new("org/model", revision.clone(), true).to_string(),
            EntryKey::new("org/model", revision, false).to_string()
        );
    }

    #[test]
    fn a_legacy_key_parses_as_unpinned_and_full_weight() {
        let parsed = EntryKey::parse("meta-llama/Llama-3.1-70B");
        assert_eq!(parsed.model_name, "meta-llama/Llama-3.1-70B");
        assert!(parsed.revision.is_none());
        assert!(!parsed.metadata_only);
    }

    #[test]
    fn belongs_to_ignores_revision_and_weight_mode() {
        let key = EntryKey::new("org/model", Some("abc123".to_string()), true);
        assert!(key.belongs_to(None, "org/model"));
        assert!(!key.belongs_to(None, "org/other"));
    }

    fn tenant(namespace: &str) -> Tenant {
        Tenant::new(namespace).expect("valid namespace")
    }

    #[test]
    fn untenanted_keys_are_unchanged() {
        assert_eq!(
            EntryKey::new("org/model", None, false).to_string(),
            "org/model"
        );
        assert_eq!(
            EntryKey::new("org/model", Some("abc123".to_string()), false).to_string(),
            "mx1:abc123:-:org/model"
        );
        assert_eq!(
            EntryKey::new("org/model", Some("abc123".to_string()), true).to_string(),
            "mx1:abc123:m:org/model"
        );
        assert_eq!(
            EntryKey::new("org/model", None, true).to_string(),
            "mx1::m:org/model"
        );
    }

    #[test]
    fn tenanted_keys_roundtrip_in_every_shape() {
        for (revision, metadata_only) in [
            (None, false),
            (None, true),
            (Some("abc123".to_string()), false),
            (Some("abc123".to_string()), true),
        ] {
            for name in [
                "org/model",
                "gs://bucket/a:b",
                "mx1:abc:m:x",
                "mxt1:t:abc:m:x",
            ] {
                roundtrip(
                    EntryKey::new(name, revision.clone(), metadata_only)
                        .in_tenant(Some(tenant("tenant-a"))),
                );
            }
        }
        assert_eq!(
            EntryKey::new("org/model", Some("abc123".to_string()), false)
                .in_tenant(Some(tenant("tenant-a")))
                .to_string(),
            "mxt1:tenant-a:abc123:-:org/model"
        );
    }

    #[test]
    fn the_same_model_in_two_tenants_gets_distinct_keys() {
        let revision = Some("abc123".to_string());
        let a =
            EntryKey::new("org/model", revision.clone(), false).in_tenant(Some(tenant("tenant-a")));
        let b =
            EntryKey::new("org/model", revision.clone(), false).in_tenant(Some(tenant("tenant-b")));
        let open = EntryKey::new("org/model", revision, false);
        assert_ne!(a.to_string(), b.to_string());
        assert_ne!(a.to_string(), open.to_string());
        assert!(a.belongs_to(Some(&tenant("tenant-a")), "org/model"));
        assert!(!a.belongs_to(Some(&tenant("tenant-b")), "org/model"));
        assert!(!a.belongs_to(None, "org/model"));
        assert!(!open.belongs_to(Some(&tenant("tenant-a")), "org/model"));
    }

    #[test]
    fn an_untenanted_name_cannot_impersonate_a_tenant_key() {
        for name in [
            "mxt1:tenant-a:abc123:-:org/model",
            "mxt1:tenant-a::m:org/model",
            "mxt1:",
        ] {
            let key = EntryKey::new(name, None, false);
            let parsed = EntryKey::parse(&key.to_string());
            assert_eq!(parsed, key);
            assert_eq!(parsed.tenant, None);
        }
    }

    #[test]
    fn a_tenant_field_that_is_not_a_namespace_is_not_a_tenant() {
        for key in [
            "mxt1:../../etc:abc:-:org/model",
            "mxt1:Tenant:abc:-:org/model",
            "mxt1::abc:-:org/model",
            "mxt1:tenant-a:abc",
        ] {
            let parsed = EntryKey::parse(key);
            assert_eq!(parsed.tenant, None, "{key}");
            assert_eq!(parsed.model_name, key);
        }
    }

    #[test]
    fn tenants_are_namespaces() {
        assert!(Tenant::new("tenant-a").is_some());
        for bad in ["", "..", "a/b", "A", "-a", "a:b", &"a".repeat(64)] {
            assert!(Tenant::new(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn partitions_live_under_the_cache_root() {
        let root = Path::new("/cache");
        assert_eq!(partition(root, None), PathBuf::from("/cache"));
        assert_eq!(
            partition(root, Some(&tenant("tenant-a"))),
            PathBuf::from("/cache/.modelexpress/tenants/tenant-a")
        );
        let key = EntryKey::new("org/model", None, false).in_tenant(Some(tenant("tenant-b")));
        assert_eq!(
            key.cache_dir(root),
            PathBuf::from("/cache/.modelexpress/tenants/tenant-b")
        );
        assert_eq!(
            EntryKey::new("org/model", None, false).cache_dir(root),
            PathBuf::from("/cache")
        );
    }
}
