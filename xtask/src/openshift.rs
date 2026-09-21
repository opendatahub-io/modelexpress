// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! config/manifests/openshift: the operator as deployed on OpenShift.

use crate::objects::{METRICS_SERVICE_NAME, NAME, labels};
use modelexpress_operator::telemetry;
use modelexpress_operator_openshift::images::SERVER_IMAGE_ENV;
use modelexpress_operator_openshift::servicemonitor;
use serde_json::json;

/// Lets the operator read the cluster TLS profile and keep its own
/// ServiceMonitor, neither of which the base manifests need.
pub const OPENSHIFT_ROLE: &str = "modelexpress-operator-openshift";

pub const SERVER_IMAGE_PARAM: &str = "MODELEXPRESS_SERVER_IMAGE";
pub const DEFAULT_SERVER_IMAGE: &str = "quay.io/opendatahub/odh-modelexpress:odh-stable";
const PARAMS_CONFIGMAP: &str = "modelexpress-operator-openshift-params";
pub const METRICS_TLS_SECRET: &str = "modelexpress-operator-metrics-tls";
pub const METRICS_TLS_MOUNT: &str = "/etc/modelexpress-operator/metrics-tls";
pub const SERVICE_CA_CONFIGMAP: &str = "openshift-service-ca.crt";
/// The namespace `config/manifests/default` installs into.
pub const DEFAULT_NAMESPACE: &str = "modelexpress-operator-system";

/// Path of [`component`] relative to an overlay directory.
pub const COMPONENT_PATH: &str = "../components/openshift";

/// The overlay's image parameters, overridable like the base params.env.
pub fn params_env() -> String {
    format!("{SERVER_IMAGE_PARAM}={DEFAULT_SERVER_IMAGE}\n")
}

/// Sets the server image the operator defaults CRs to, from `configmap`'s
/// `MODELEXPRESS_SERVER_IMAGE`.
pub fn server_image_replacement(configmap: &str) -> serde_json::Value {
    json!({
        "source": {"kind": "ConfigMap", "name": configmap, "fieldPath": format!("data.{SERVER_IMAGE_PARAM}")},
        "targets": [{
            "select": {"kind": "Deployment", "name": NAME},
            "fieldPaths": [format!("spec.template.spec.containers.[name=operator].env.[name={SERVER_IMAGE_ENV}].value")],
        }],
    })
}

/// OpenShift overlay: the default install plus [`component`], in a namespace
/// cluster monitoring scrapes.
pub fn overlay() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        (
            "kustomization.yaml",
            json!({
                "apiVersion": "kustomize.config.k8s.io/v1beta1",
                "kind": "Kustomization",
                "namespace": DEFAULT_NAMESPACE,
                "resources": ["../default"],
                "components": [COMPONENT_PATH],
                "generatorOptions": {"disableNameSuffixHash": true},
                "configMapGenerator": [{"name": PARAMS_CONFIGMAP, "envs": ["params.env"]}],
                "replacements": [server_image_replacement(PARAMS_CONFIGMAP)],
                "patches": [
                    {"path": "namespace-patch.yaml", "target": {"kind": "Namespace", "name": DEFAULT_NAMESPACE}},
                ],
            }),
        ),
        (
            "namespace-patch.yaml",
            json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": DEFAULT_NAMESPACE,
                    "labels": {"openshift.io/cluster-monitoring": "true"},
                },
            }),
        ),
    ]
}

/// Kustomize Component: strategic-merge patches and extra objects that turn
/// the metrics endpoint into service-ca TLS, and the RBAC the operator needs
/// to read the cluster TLS profile. Namespace-agnostic, so every overlay that
/// targets OpenShift shares it.
pub fn component() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        (
            "kustomization.yaml",
            json!({
                "apiVersion": "kustomize.config.k8s.io/v1alpha1",
                "kind": "Component",
                "resources": [
                    "openshift-clusterrole.yaml",
                    "openshift-clusterrolebinding.yaml",
                    "service-ca-configmap.yaml",
                ],
                "patches": [
                    {"path": "deployment-patch.yaml", "target": {"kind": "Deployment", "name": NAME}},
                    {"path": "service-patch.yaml", "target": {"kind": "Service", "name": METRICS_SERVICE_NAME}},
                ],
            }),
        ),
        (
            "deployment-patch.yaml",
            json!({
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": NAME},
                "spec": {"template": {
                    "metadata": {"annotations": {"prometheus.io/port": telemetry::METRICS_TLS_PORT.to_string(), "prometheus.io/scheme": "https"}},
                    "spec": {
                        "containers": [{
                            "name": "operator",
                            "env": [
                                {"name": telemetry::METRICS_TLS_DIR_ENV, "value": METRICS_TLS_MOUNT},
                                {"name": SERVER_IMAGE_ENV, "value": "set from params.env"},
                                {
                                    "name": servicemonitor::NAMESPACE_ENV,
                                    "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}},
                                },
                            ],
                            "ports": [
                                {"name": telemetry::HEALTH_PORT_NAME, "containerPort": telemetry::HEALTH_PORT},
                                {"name": telemetry::METRICS_TLS_PORT_NAME, "containerPort": telemetry::METRICS_TLS_PORT},
                            ],
                            "volumeMounts": [{"name": "metrics-tls", "mountPath": METRICS_TLS_MOUNT, "readOnly": true}],
                        }],
                        "volumes": [{"name": "metrics-tls", "secret": {"secretName": METRICS_TLS_SECRET}}],
                    },
                }},
            }),
        ),
        (
            "service-patch.yaml",
            json!({
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {
                    "name": METRICS_SERVICE_NAME,
                    "annotations": {"service.beta.openshift.io/serving-cert-secret-name": METRICS_TLS_SECRET},
                },
                "spec": {"ports": [{
                    "name": telemetry::METRICS_TLS_PORT_NAME,
                    "port": telemetry::METRICS_TLS_PORT,
                    "targetPort": telemetry::METRICS_TLS_PORT_NAME,
                }]},
            }),
        ),
        (
            "service-ca-configmap.yaml",
            json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": SERVICE_CA_CONFIGMAP,
                    "labels": labels(),
                    "annotations": {"service.beta.openshift.io/inject-cabundle": "true"},
                },
            }),
        ),
        (
            "openshift-clusterrole.yaml",
            json!({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole",
                "metadata": {"name": OPENSHIFT_ROLE, "labels": labels()},
                "rules": [
                    {
                        "apiGroups": ["config.openshift.io"],
                        "resources": ["apiservers"],
                        "verbs": ["get", "list", "watch"],
                    },
                    {
                        "apiGroups": [servicemonitor::API_GROUP],
                        "resources": [servicemonitor::PLURAL],
                        "verbs": ["get", "create", "patch", "update"],
                    },
                ],
            }),
        ),
        (
            "openshift-clusterrolebinding.yaml",
            json!({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRoleBinding",
                "metadata": {"name": OPENSHIFT_ROLE, "labels": labels()},
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": OPENSHIFT_ROLE,
                },
                // Namespace unset so kustomize resolves the ServiceAccount by
                // nameReference, as the base ClusterRoleBinding does.
                "subjects": [{"kind": "ServiceAccount", "name": NAME}],
            }),
        ),
    ]
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use crate::openshift::{COMPONENT_PATH, component, overlay};
    use std::collections::BTreeSet;

    /// Files a kustomization names through `resources` and `patches`, minus
    /// directories.
    fn referenced(kustomization: &serde_json::Value) -> BTreeSet<String> {
        let resources = kustomization["resources"].as_array().into_iter().flatten();
        let patches = kustomization["patches"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|patch| &patch["path"]);
        resources
            .chain(patches)
            .map(|path| path.as_str().expect("path is a string").to_string())
            .filter(|path| path.ends_with(".yaml"))
            .collect()
    }

    fn assert_emits_what_it_references(files: Vec<(&'static str, serde_json::Value)>) {
        let kustomization = files
            .iter()
            .find(|(file, _)| *file == "kustomization.yaml")
            .expect("has a kustomization")
            .1
            .clone();
        let emitted: BTreeSet<String> = files
            .iter()
            .map(|(file, _)| (*file).to_string())
            .filter(|file| file != "kustomization.yaml")
            .collect();
        assert_eq!(referenced(&kustomization), emitted);
    }

    #[test]
    fn component_emits_exactly_the_files_it_references() {
        assert_emits_what_it_references(component());
    }

    #[test]
    fn overlay_emits_exactly_the_files_it_references() {
        assert_emits_what_it_references(overlay());
    }

    #[test]
    fn component_is_a_namespace_agnostic_kustomize_component() {
        let files = component();
        let kustomization = &files[0].1;
        assert_eq!(kustomization["kind"], "Component");
        assert_eq!(
            kustomization["apiVersion"],
            "kustomize.config.k8s.io/v1alpha1"
        );
        assert!(kustomization.get("namespace").is_none());
        for (file, value) in &files {
            assert!(
                value["metadata"].get("namespace").is_none(),
                "{file} pins metadata.namespace"
            );
        }
    }

    #[test]
    fn overlay_pulls_in_the_component() {
        let files = overlay();
        assert_eq!(
            files[0].1["components"],
            serde_json::json!([COMPONENT_PATH])
        );
    }
}
