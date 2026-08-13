// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The operator's own deploy objects, defined once and emitted as the
//! kustomize base under config/ (cargo xtask manifests).

use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    Capabilities, Container, ContainerPort, HTTPGetAction, PodSecurityContext, PodSpec,
    PodTemplateSpec, Probe, ResourceRequirements, SeccompProfile, SecurityContext, ServiceAccount,
};
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, PolicyRule, RoleRef, Subject};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::ObjectMeta;
use modelexpress_operator::crd::API_GROUP;
use modelexpress_operator::telemetry;
use std::collections::BTreeMap;

pub const NAME: &str = "modelexpress-operator";
/// Must keep reproducing the committed tree, or `--check` fails for anyone
/// who did not pass `--image`.
pub const DEFAULT_IMAGE: &str = "quay.io/opendatahub/odh-modelexpress-operator:latest";

pub fn labels() -> BTreeMap<String, String> {
    [
        ("app.kubernetes.io/name".to_string(), NAME.to_string()),
        (
            "app.kubernetes.io/managed-by".to_string(),
            "xtask".to_string(),
        ),
    ]
    .into_iter()
    .collect()
}

fn crud() -> Vec<String> {
    [
        "get", "list", "watch", "create", "update", "patch", "delete",
    ]
    .map(String::from)
    .to_vec()
}

/// Everything the controller touches. Includes the server's namespace-Role
/// rules verbatim: RBAC escalation prevention means the operator may only
/// grant permissions it holds.
pub fn cluster_role_rules() -> Vec<PolicyRule> {
    let mut rules = vec![
        PolicyRule {
            api_groups: Some(vec![API_GROUP.to_string()]),
            resources: Some(vec!["modelexpressservers".to_string()]),
            verbs: ["get", "list", "watch", "patch"].map(String::from).to_vec(),
            ..PolicyRule::default()
        },
        PolicyRule {
            api_groups: Some(vec![API_GROUP.to_string()]),
            resources: Some(vec![
                "modelexpressservers/status".to_string(),
                "modelexpressservers/finalizers".to_string(),
            ]),
            verbs: ["update", "patch"].map(String::from).to_vec(),
            ..PolicyRule::default()
        },
        PolicyRule {
            api_groups: Some(vec!["apps".to_string()]),
            resources: Some(vec!["deployments".to_string()]),
            verbs: crud(),
            ..PolicyRule::default()
        },
        PolicyRule {
            api_groups: Some(vec![String::new()]),
            resources: Some(vec![
                "services".to_string(),
                "persistentvolumeclaims".to_string(),
                "serviceaccounts".to_string(),
            ]),
            verbs: crud(),
            ..PolicyRule::default()
        },
        PolicyRule {
            api_groups: Some(vec!["networking.k8s.io".to_string()]),
            resources: Some(vec!["networkpolicies".to_string()]),
            verbs: crud(),
            ..PolicyRule::default()
        },
        PolicyRule {
            api_groups: Some(vec!["rbac.authorization.k8s.io".to_string()]),
            resources: Some(vec!["roles".to_string(), "rolebindings".to_string()]),
            verbs: crud(),
            ..PolicyRule::default()
        },
    ];
    rules.extend(modelexpress_operator::rbac::server_policy_rules());
    rules
}

pub fn service_account() -> ServiceAccount {
    ServiceAccount {
        metadata: ObjectMeta {
            name: Some(NAME.to_string()),
            labels: Some(labels()),
            ..ObjectMeta::default()
        },
        ..ServiceAccount::default()
    }
}

pub fn cluster_role() -> ClusterRole {
    ClusterRole {
        metadata: ObjectMeta {
            name: Some(NAME.to_string()),
            labels: Some(labels()),
            ..ObjectMeta::default()
        },
        rules: Some(cluster_role_rules()),
        ..ClusterRole::default()
    }
}

pub fn cluster_role_binding() -> ClusterRoleBinding {
    ClusterRoleBinding {
        metadata: ObjectMeta {
            name: Some(NAME.to_string()),
            labels: Some(labels()),
            ..ObjectMeta::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "ClusterRole".to_string(),
            name: NAME.to_string(),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".to_string(),
            name: NAME.to_string(),
            // placeholder; the kustomize namespace transformer sets the
            // real install namespace
            namespace: Some("modelexpress-operator-system".to_string()),
            ..Subject::default()
        }]),
    }
}

fn http_probe(path: &str) -> Probe {
    Probe {
        http_get: Some(HTTPGetAction {
            path: Some(path.to_string()),
            port: IntOrString::String(telemetry::PORT_NAME.to_string()),
            ..HTTPGetAction::default()
        }),
        initial_delay_seconds: Some(5),
        period_seconds: Some(10),
        ..Probe::default()
    }
}

/// The image ships USER 1000:1000, but that is advisory: without runAsNonRoot
/// the admission plugin has nothing to enforce.
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

/// The controller writes nothing, so a read-only root needs no scratch volume.
fn container_security_context() -> SecurityContext {
    SecurityContext {
        allow_privilege_escalation: Some(false),
        read_only_root_filesystem: Some(true),
        run_as_non_root: Some(true),
        capabilities: Some(Capabilities {
            drop: Some(vec!["ALL".to_string()]),
            add: None,
        }),
        ..SecurityContext::default()
    }
}

pub fn deployment(image: &str) -> Deployment {
    let selector: BTreeMap<String, String> =
        [("app.kubernetes.io/name".to_string(), NAME.to_string())]
            .into_iter()
            .collect();
    Deployment {
        metadata: ObjectMeta {
            name: Some(NAME.to_string()),
            labels: Some(labels()),
            ..ObjectMeta::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(1),
            selector: LabelSelector {
                match_labels: Some(selector.clone()),
                ..LabelSelector::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(selector),
                    annotations: Some(
                        [
                            ("prometheus.io/scrape".to_string(), "true".to_string()),
                            (
                                "prometheus.io/port".to_string(),
                                telemetry::PORT.to_string(),
                            ),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                    ..ObjectMeta::default()
                }),
                spec: Some(PodSpec {
                    service_account_name: Some(NAME.to_string()),
                    security_context: Some(pod_security_context()),
                    containers: vec![Container {
                        name: "operator".to_string(),
                        image: Some(image.to_string()),
                        security_context: Some(container_security_context()),
                        ports: Some(vec![ContainerPort {
                            name: Some(telemetry::PORT_NAME.to_string()),
                            container_port: telemetry::PORT,
                            ..ContainerPort::default()
                        }]),
                        liveness_probe: Some(http_probe("/healthz")),
                        readiness_probe: Some(http_probe("/readyz")),
                        resources: Some(ResourceRequirements {
                            requests: Some(
                                [
                                    ("cpu".to_string(), Quantity("100m".to_string())),
                                    ("memory".to_string(), Quantity("128Mi".to_string())),
                                ]
                                .into_iter()
                                .collect(),
                            ),
                            limits: Some(
                                [("memory".to_string(), Quantity("256Mi".to_string()))]
                                    .into_iter()
                                    .collect(),
                            ),
                            ..ResourceRequirements::default()
                        }),
                        ..Container::default()
                    }],
                    ..PodSpec::default()
                }),
            },
            ..DeploymentSpec::default()
        }),
        status: None,
    }
}
