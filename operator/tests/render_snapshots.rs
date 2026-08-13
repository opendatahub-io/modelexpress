//! Snapshot tests for everything the operator renders. `cargo insta review`
//! to update after intentional changes.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use modelexpress_operator::crd::{
    AuthMode, CacheConfig, CacheStorage, CredentialsConfig, EmptyDirStorage, ExistingClaimStorage,
    LogConfig, LogFormat, LogLevel, ManagedPvcStorage, MetadataBackend, MetadataOverrides,
    ModelExpressServerSpec, NetworkPolicyConfig, ReaperConfig, RedisBackend, SecretKeyRef,
    SecurityConfig, ServiceAccountRef,
};
use modelexpress_operator::deployment::render;

fn minimal_spec() -> ModelExpressServerSpec {
    serde_json::from_value(serde_json::json!({
        "image": "nvcr.io/nvidia/ai-dynamo/modelexpress-server:0.5.0",
        "metadataBackend": {"kubernetes": {}},
    }))
    .expect("minimal spec")
}

fn full_spec() -> ModelExpressServerSpec {
    ModelExpressServerSpec {
        image: "nvcr.io/nvidia/ai-dynamo/modelexpress-server:0.5.0".into(),
        replicas: 3,
        metadata_backend: MetadataBackend::Redis(RedisBackend {
            url: "redis://mx-redis:6379".into(),
        }),
        port: 8001,
        log: Some(LogConfig {
            level: Some(LogLevel::Debug),
            format: Some(LogFormat::Json),
        }),
        cache: Some(CacheConfig {
            directory: Some("/cache".into()),
            eviction_enabled: Some(true),
            storage: Some(CacheStorage::Pvc(Box::new(ManagedPvcStorage {
                metadata: Some(MetadataOverrides {
                    labels: Some(
                        [("team".to_string(), "llm-d".to_string())]
                            .into_iter()
                            .collect(),
                    ),
                    annotations: None,
                }),
                spec: serde_json::from_value(serde_json::json!({
                    "storageClassName": "ceph-fs",
                    "accessModes": ["ReadWriteMany"],
                    "resources": {"requests": {"storage": "500Gi"}},
                }))
                .expect("pvc spec"),
            }))),
        }),
        security: Some(SecurityConfig {
            mode: AuthMode::Enforce,
            token_audiences: vec!["mx".into()],
            allowed_service_accounts: vec![ServiceAccountRef {
                namespace: "llm-d".into(),
                service_account: "decode".into(),
            }],
            cache_ttl_secs: Some(120),
        }),
        reaper: Some(ReaperConfig {
            scan_interval_secs: Some(10),
            heartbeat_timeout_secs: Some(30),
            gc_timeout_secs: Some(600),
        }),
        credentials: Some(CredentialsConfig {
            hf_token_secret: Some(SecretKeyRef {
                name: "hf-secret".into(),
                key: "HF_TOKEN".into(),
            }),
            ngc_api_key_secret: None,
        }),
        pod_metadata: Some(MetadataOverrides {
            labels: Some(
                [("istio.io/dataplane-mode".to_string(), "ambient".to_string())]
                    .into_iter()
                    .collect(),
            ),
            annotations: None,
        }),
        network_policy: Some(NetworkPolicyConfig {
            allow_from: vec![
                serde_json::from_value(serde_json::json!({
                    "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "llm-d"}},
                }))
                .expect("peer"),
            ],
        }),
        service_account_name: None,
    }
}

#[test]
fn minimal_kubernetes_backend() {
    let state = render("mx-min", &minimal_spec());
    insta::assert_yaml_snapshot!("minimal_deployment", state.deployment);
    insta::assert_yaml_snapshot!("minimal_service", state.service);
    assert!(state.pvc.is_none());
}

#[test]
fn full_redis_backend() {
    let state = render("mx-full", &full_spec());
    insta::assert_yaml_snapshot!("full_deployment", state.deployment);
    insta::assert_yaml_snapshot!("full_service", state.service);
    insta::assert_yaml_snapshot!("full_pvc", state.pvc.expect("managed pvc"));
    insta::assert_yaml_snapshot!(
        "full_networkpolicy",
        state.network_policy.expect("network policy")
    );
}

#[test]
fn empty_dir_with_limit_and_existing_claim() {
    let mut spec = minimal_spec();
    spec.cache = Some(CacheConfig {
        storage: Some(CacheStorage::EmptyDir(EmptyDirStorage {
            size_limit: Some("200Gi".into()),
        })),
        ..CacheConfig::default()
    });
    let state = render("mx-scratch", &spec);
    insta::assert_yaml_snapshot!("empty_dir_pod_volumes", volumes(&state));

    spec.cache = Some(CacheConfig {
        storage: Some(CacheStorage::ExistingClaim(ExistingClaimStorage {
            claim_name: "shared-models".into(),
        })),
        ..CacheConfig::default()
    });
    let state = render("mx-shared", &spec);
    insta::assert_yaml_snapshot!("existing_claim_pod_volumes", volumes(&state));
}

fn volumes(
    state: &modelexpress_operator::deployment::DesiredState,
) -> Vec<k8s_openapi::api::core::v1::Volume> {
    state
        .deployment
        .spec
        .as_ref()
        .expect("spec")
        .template
        .spec
        .as_ref()
        .expect("pod")
        .volumes
        .clone()
        .expect("volumes")
}

// The CRD is also covered by `cargo xtask crdgen --check`; this snapshot
// exists so schema-affecting diffs show up in `cargo insta review` alongside
// the rendered objects.
#[test]
fn crd_schema() {
    insta::assert_yaml_snapshot!("crd", modelexpress_operator::crd::generate_crd());
}
