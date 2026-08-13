// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Renders the Deployment and Service for a ModelExpressServer CR.

use crate::crd::ModelExpressServerSpec;
use crate::env::render_env;
use crate::volume::{CacheVolume, render_cache_volume};
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    Capabilities, Container, ContainerPort, GRPCAction, PersistentVolumeClaim, PodSecurityContext,
    PodSpec, PodTemplateSpec, Probe, SeccompProfile, SecurityContext, Service, ServicePort,
    ServiceSpec,
};
use k8s_openapi::api::networking::v1::{
    NetworkPolicy, NetworkPolicyIngressRule, NetworkPolicyPort, NetworkPolicySpec,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::ObjectMeta;
use std::collections::BTreeMap;

pub const CONTAINER_NAME: &str = "server";
pub const PORT_NAME: &str = "grpc";

/// Everything the reconciler applies for one CR. ownerReferences and
/// namespaces are its job, not the renderer's.
pub struct DesiredState {
    pub deployment: Deployment,
    pub service: Service,
    pub pvc: Option<PersistentVolumeClaim>,
    /// None means "no policy desired": the reconciler deletes any stale one.
    pub network_policy: Option<NetworkPolicy>,
}

pub fn render(cr_name: &str, spec: &ModelExpressServerSpec) -> DesiredState {
    let CacheVolume { volume, mount, pvc } = render_cache_volume(cr_name, spec);
    let labels = pod_labels(cr_name, spec);
    let pod_annotations = spec
        .pod_metadata
        .as_ref()
        .and_then(|meta| meta.annotations.clone());

    // The server wires tonic_health, so use real gRPC probes instead of the
    // chart's TCP socket checks. Liveness is deliberately laxer than
    // readiness: a slow backend should pull the pod from rotation, not
    // restart it.
    let readiness = grpc_probe(spec.port, 5, 10);
    let liveness = grpc_probe(spec.port, 15, 30);

    let container = Container {
        name: CONTAINER_NAME.to_string(),
        image: Some(spec.image.clone()),
        ports: Some(vec![ContainerPort {
            name: Some(PORT_NAME.to_string()),
            container_port: spec.port,
            ..ContainerPort::default()
        }]),
        env: Some(render_env(spec)),
        volume_mounts: Some(vec![mount]),
        readiness_probe: Some(readiness),
        liveness_probe: Some(liveness),
        security_context: Some(container_security_context()),
        ..Container::default()
    };

    let deployment = Deployment {
        metadata: ObjectMeta {
            name: Some(cr_name.to_string()),
            labels: Some(labels.clone()),
            ..ObjectMeta::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(spec.replicas),
            selector: LabelSelector {
                match_labels: Some(selector_labels(cr_name)),
                ..LabelSelector::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels.clone()),
                    annotations: pod_annotations,
                    ..ObjectMeta::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![container],
                    security_context: Some(pod_security_context()),
                    volumes: Some(vec![volume]),
                    service_account_name: Some(crate::rbac::service_account_name(cr_name, spec)),
                    ..PodSpec::default()
                }),
            },
            ..DeploymentSpec::default()
        }),
        status: None,
    };

    let service = Service {
        metadata: ObjectMeta {
            name: Some(cr_name.to_string()),
            labels: Some(labels),
            ..ObjectMeta::default()
        },
        spec: Some(ServiceSpec {
            selector: Some(selector_labels(cr_name)),
            ports: Some(vec![ServicePort {
                name: Some(PORT_NAME.to_string()),
                port: spec.port,
                target_port: Some(IntOrString::String(PORT_NAME.to_string())),
                ..ServicePort::default()
            }]),
            ..ServiceSpec::default()
        }),
        status: None,
    };

    let network_policy = spec.network_policy.as_ref().map(|np| NetworkPolicy {
        metadata: ObjectMeta {
            name: Some(cr_name.to_string()),
            labels: Some(pod_labels(cr_name, spec)),
            ..ObjectMeta::default()
        },
        spec: Some(NetworkPolicySpec {
            pod_selector: LabelSelector {
                match_labels: Some(selector_labels(cr_name)),
                ..LabelSelector::default()
            },
            policy_types: Some(vec!["Ingress".to_string()]),
            ingress: Some(vec![NetworkPolicyIngressRule {
                from: Some(np.allow_from.clone()),
                ports: Some(vec![NetworkPolicyPort {
                    port: Some(IntOrString::Int(spec.port)),
                    protocol: Some("TCP".to_string()),
                    ..NetworkPolicyPort::default()
                }]),
            }]),
            ..NetworkPolicySpec::default()
        }),
    });

    DesiredState {
        deployment,
        service,
        pvc,
        network_policy,
    }
}

/// Immutable subset used for the Deployment selector; changing these on an
/// existing CR would orphan its pods.
fn selector_labels(cr_name: &str) -> BTreeMap<String, String> {
    [
        (
            "app.kubernetes.io/name".to_string(),
            "modelexpress-server".to_string(),
        ),
        (
            "app.kubernetes.io/instance".to_string(),
            cr_name.to_string(),
        ),
    ]
    .into_iter()
    .collect()
}

/// User podMetadata labels first, operator labels on top: the selector subset
/// must never be overridable or the Deployment orphans its pods.
fn pod_labels(cr_name: &str, spec: &ModelExpressServerSpec) -> BTreeMap<String, String> {
    let mut labels = spec
        .pod_metadata
        .as_ref()
        .and_then(|meta| meta.labels.clone())
        .unwrap_or_default();
    labels.extend(selector_labels(cr_name));
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "modelexpress-operator".to_string(),
    );
    labels
}

/// Without these a namespace labelled with the restricted Pod Security
/// Standard rejects the pod outright, and the CRD exposes no override for a
/// user to work around it.
///
/// runAsUser and fsGroup are deliberately absent: OpenShift's restricted-v2
/// SCC assigns both from the namespace range, and pinning them here would
/// conflict with that while buying nothing on vanilla Kubernetes, where the
/// image's own USER applies.
fn pod_security_context() -> PodSecurityContext {
    PodSecurityContext {
        run_as_non_root: Some(true),
        seccomp_profile: Some(SeccompProfile {
            type_: "RuntimeDefault".to_string(),
            localhost_profile: None,
        }),
        ..PodSecurityContext::default()
    }
}

/// readOnlyRootFilesystem is deliberately not set: unlike the controller, the
/// server unpacks downloads and the provider SDKs write scratch state outside
/// the cache mount.
fn container_security_context() -> SecurityContext {
    SecurityContext {
        allow_privilege_escalation: Some(false),
        run_as_non_root: Some(true),
        capabilities: Some(Capabilities {
            drop: Some(vec!["ALL".to_string()]),
            add: None,
        }),
        ..SecurityContext::default()
    }
}

fn grpc_probe(port: i32, initial_delay: i32, period: i32) -> Probe {
    Probe {
        grpc: Some(GRPCAction {
            port,
            service: None,
        }),
        initial_delay_seconds: Some(initial_delay),
        period_seconds: Some(period),
        ..Probe::default()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::crd::{CacheConfig, CacheStorage, ManagedPvcStorage, MetadataBackend, RedisBackend};
    use k8s_openapi::api::core::v1::{PersistentVolumeClaimSpec, VolumeResourceRequirements};
    use k8s_openapi::apimachinery::pkg::api::resource::Quantity;

    fn base_spec() -> ModelExpressServerSpec {
        ModelExpressServerSpec {
            image: "nvcr.io/nvidia/ai-dynamo/modelexpress-server:0.5.0".into(),
            replicas: 2,
            metadata_backend: MetadataBackend::Redis(RedisBackend {
                url: "redis://mx-redis:6379".into(),
            }),
            port: 8001,
            log: None,
            cache: None,
            security: None,
            reaper: None,
            credentials: None,
            pod_metadata: None,
            network_policy: None,
            service_account_name: None,
        }
    }

    fn container(state: &DesiredState) -> &Container {
        &state
            .deployment
            .spec
            .as_ref()
            .expect("deployment spec")
            .template
            .spec
            .as_ref()
            .expect("pod spec")
            .containers[0]
    }

    #[test]
    fn selector_matches_pod_labels() {
        let state = render("mx", &base_spec());
        let dep_spec = state.deployment.spec.as_ref().expect("spec");
        let selector = dep_spec
            .selector
            .match_labels
            .as_ref()
            .expect("match labels");
        let pod_labels = dep_spec
            .template
            .metadata
            .as_ref()
            .expect("pod meta")
            .labels
            .as_ref()
            .expect("pod labels");
        for (k, v) in selector {
            assert_eq!(pod_labels.get(k), Some(v), "selector key {k} not on pod");
        }
        let svc_selector = state
            .service
            .spec
            .as_ref()
            .expect("svc spec")
            .selector
            .as_ref()
            .expect("svc selector");
        assert_eq!(svc_selector, selector);
    }

    #[test]
    fn replicas_image_and_port_propagate() {
        let state = render("mx", &base_spec());
        assert_eq!(
            state.deployment.spec.as_ref().expect("spec").replicas,
            Some(2)
        );
        let c = container(&state);
        assert_eq!(
            c.image.as_deref(),
            Some("nvcr.io/nvidia/ai-dynamo/modelexpress-server:0.5.0")
        );
        assert_eq!(c.ports.as_ref().expect("ports")[0].container_port, 8001);
    }

    #[test]
    fn grpc_probes_target_the_server_port() {
        let mut spec = base_spec();
        spec.port = 9000;
        let state = render("mx", &spec);
        let c = container(&state);
        let readiness = c.readiness_probe.as_ref().expect("readiness");
        let liveness = c.liveness_probe.as_ref().expect("liveness");
        assert_eq!(readiness.grpc.as_ref().expect("grpc").port, 9000);
        assert_eq!(liveness.grpc.as_ref().expect("grpc").port, 9000);
    }

    #[test]
    fn env_and_volume_are_wired_into_the_pod() {
        let state = render("mx", &base_spec());
        let c = container(&state);
        let env = c.env.as_ref().expect("env");
        assert!(env.iter().any(|e| e.name == "MX_METADATA_BACKEND"));
        assert_eq!(
            c.volume_mounts.as_ref().expect("mounts")[0].name,
            "model-cache"
        );
        let volumes = state
            .deployment
            .spec
            .as_ref()
            .expect("spec")
            .template
            .spec
            .as_ref()
            .expect("pod")
            .volumes
            .as_ref()
            .expect("volumes");
        assert_eq!(volumes[0].name, "model-cache");
    }

    #[test]
    fn service_targets_named_port() {
        let state = render("mx", &base_spec());
        let port = &state
            .service
            .spec
            .as_ref()
            .expect("spec")
            .ports
            .as_ref()
            .expect("ports")[0];
        assert_eq!(port.port, 8001);
        assert_eq!(
            port.target_port,
            Some(IntOrString::String("grpc".to_string()))
        );
    }

    #[test]
    fn pod_metadata_merges_but_cannot_override_selector() {
        let mut spec = base_spec();
        spec.pod_metadata = Some(crate::crd::MetadataOverrides {
            labels: Some(
                [
                    ("istio.io/dataplane-mode".to_string(), "ambient".to_string()),
                    // attempt to hijack a selector label; must lose
                    ("app.kubernetes.io/name".to_string(), "evil".to_string()),
                ]
                .into_iter()
                .collect(),
            ),
            annotations: Some(
                [("sidecar.istio.io/inject".to_string(), "false".to_string())]
                    .into_iter()
                    .collect(),
            ),
        });
        let state = render("mx", &spec);
        let template_meta = state
            .deployment
            .spec
            .as_ref()
            .expect("spec")
            .template
            .metadata
            .as_ref()
            .expect("pod meta");
        let labels = template_meta.labels.as_ref().expect("labels");
        assert_eq!(
            labels.get("istio.io/dataplane-mode").map(String::as_str),
            Some("ambient")
        );
        assert_eq!(
            labels.get("app.kubernetes.io/name").map(String::as_str),
            Some("modelexpress-server")
        );
        assert_eq!(
            template_meta
                .annotations
                .as_ref()
                .expect("annotations")
                .get("sidecar.istio.io/inject")
                .map(String::as_str),
            Some("false")
        );
    }

    #[test]
    fn network_policy_absent_by_default() {
        assert!(render("mx", &base_spec()).network_policy.is_none());
    }

    #[test]
    fn network_policy_restricts_grpc_port_to_peers() {
        use k8s_openapi::api::networking::v1::NetworkPolicyPeer;
        let mut spec = base_spec();
        spec.port = 9000;
        spec.network_policy = Some(crate::crd::NetworkPolicyConfig {
            allow_from: vec![NetworkPolicyPeer {
                pod_selector: Some(LabelSelector {
                    match_labels: Some(
                        [("role".to_string(), "worker".to_string())]
                            .into_iter()
                            .collect(),
                    ),
                    ..LabelSelector::default()
                }),
                ..NetworkPolicyPeer::default()
            }],
        });
        let netpol = render("mx", &spec).network_policy.expect("netpol");
        let np_spec = netpol.spec.expect("spec");
        assert_eq!(
            np_spec
                .pod_selector
                .match_labels
                .expect("labels")
                .get("app.kubernetes.io/instance")
                .map(String::as_str),
            Some("mx")
        );
        assert_eq!(np_spec.policy_types, Some(vec!["Ingress".to_string()]));
        let rule = &np_spec.ingress.expect("ingress")[0];
        assert_eq!(rule.from.as_ref().expect("from").len(), 1);
        let port = &rule.ports.as_ref().expect("ports")[0];
        assert_eq!(port.port, Some(IntOrString::Int(9000)));
    }

    #[test]
    fn managed_pvc_flows_through_desired_state() {
        let mut spec = base_spec();
        spec.replicas = 1;
        spec.cache = Some(CacheConfig {
            storage: Some(CacheStorage::Pvc(Box::new(ManagedPvcStorage {
                metadata: None,
                spec: PersistentVolumeClaimSpec {
                    resources: Some(VolumeResourceRequirements {
                        requests: Some(
                            [("storage".to_string(), Quantity("50Gi".into()))]
                                .into_iter()
                                .collect(),
                        ),
                        ..VolumeResourceRequirements::default()
                    }),
                    ..PersistentVolumeClaimSpec::default()
                },
            }))),
            ..CacheConfig::default()
        });
        let state = render("mx", &spec);
        let pvc = state.pvc.expect("pvc");
        assert_eq!(pvc.metadata.name.as_deref(), Some("mx-model-cache"));
    }
}
