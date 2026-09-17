// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! config/manifests/openshift: the operator as deployed on OpenShift.

use crate::objects::{METRICS_SERVICE_NAME, NAME, labels};
use modelexpress_operator::telemetry;
use modelexpress_operator_openshift::images::SERVER_IMAGE_ENV;
use serde_json::json;

/// Lets the operator read apiservers.config.openshift.io/cluster.
pub const APISERVERS_ROLE: &str = "modelexpress-operator-apiservers";

/// The overlay's image parameters, overridable like the base params.env.
pub const PARAMS_ENV: &str =
    "MODELEXPRESS_SERVER_IMAGE=quay.io/opendatahub/odh-modelexpress:latest\n";
const PARAMS_CONFIGMAP: &str = "modelexpress-operator-openshift-params";
pub const METRICS_TLS_SECRET: &str = "modelexpress-operator-metrics-tls";
pub const METRICS_TLS_MOUNT: &str = "/etc/modelexpress-operator/metrics-tls";
pub const SERVICE_CA_CONFIGMAP: &str = "openshift-service-ca.crt";
/// The namespace `config/manifests/default` installs into; the ServiceMonitor
/// needs it spelled out for TLS server-name verification.
pub const DEFAULT_NAMESPACE: &str = "modelexpress-operator-system";

/// OpenShift overlay: strategic-merge patches and extra objects that turn the
/// metrics endpoint into service-ca TLS, and the RBAC the operator needs to
/// read the cluster TLS profile.
pub fn overlay() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        (
            "kustomization.yaml",
            json!({
                "apiVersion": "kustomize.config.k8s.io/v1beta1",
                "kind": "Kustomization",
                "namespace": DEFAULT_NAMESPACE,
                "resources": [
                    "../default",
                    "apiservers-clusterrole.yaml",
                    "apiservers-clusterrolebinding.yaml",
                    "service-ca-configmap.yaml",
                    "servicemonitor.yaml",
                ],
                "generatorOptions": {"disableNameSuffixHash": true},
                "configMapGenerator": [{"name": PARAMS_CONFIGMAP, "envs": ["params.env"]}],
                "replacements": [{
                    "source": {"kind": "ConfigMap", "name": PARAMS_CONFIGMAP, "fieldPath": "data.MODELEXPRESS_SERVER_IMAGE"},
                    "targets": [{
                        "select": {"kind": "Deployment", "name": NAME},
                        "fieldPaths": [format!("spec.template.spec.containers.[name=operator].env.[name={SERVER_IMAGE_ENV}].value")],
                    }],
                }],
                "patches": [
                    {"path": "deployment-patch.yaml", "target": {"kind": "Deployment", "name": NAME}},
                    {"path": "service-patch.yaml", "target": {"kind": "Service", "name": METRICS_SERVICE_NAME}},
                    {"path": "namespace-patch.yaml", "target": {"kind": "Namespace", "name": DEFAULT_NAMESPACE}},
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
            "servicemonitor.yaml",
            json!({
                "apiVersion": "monitoring.coreos.com/v1",
                "kind": "ServiceMonitor",
                "metadata": {"name": NAME, "labels": labels()},
                "spec": {
                    "selector": {"matchLabels": {"app.kubernetes.io/name": NAME}},
                    "endpoints": [{
                        "port": telemetry::METRICS_TLS_PORT_NAME,
                        "scheme": "https",
                        "bearerTokenFile": "/var/run/secrets/kubernetes.io/serviceaccount/token",
                        "tlsConfig": {
                            "ca": {"configMap": {"name": SERVICE_CA_CONFIGMAP, "key": "service-ca.crt"}},
                            "serverName": format!("{METRICS_SERVICE_NAME}.{DEFAULT_NAMESPACE}.svc"),
                        },
                    }],
                },
            }),
        ),
        (
            "apiservers-clusterrole.yaml",
            json!({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole",
                "metadata": {"name": APISERVERS_ROLE, "labels": labels()},
                "rules": [{
                    "apiGroups": ["config.openshift.io"],
                    "resources": ["apiservers"],
                    "verbs": ["get", "list", "watch"],
                }],
            }),
        ),
        (
            "apiservers-clusterrolebinding.yaml",
            json!({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRoleBinding",
                "metadata": {"name": APISERVERS_ROLE, "labels": labels()},
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": APISERVERS_ROLE,
                },
                // Namespace unset so kustomize resolves the ServiceAccount by
                // nameReference, as the base ClusterRoleBinding does.
                "subjects": [{"kind": "ServiceAccount", "name": NAME}],
            }),
        ),
    ]
}
