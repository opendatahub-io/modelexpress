// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The ServiceMonitor for the operator's own metrics.
//!
//! Prometheus verifies the metrics certificate against
//! `<service>.<namespace>.svc`, so the object has to name the namespace the
//! operator actually runs in. A manifest cannot: kustomize resolves it when
//! the overlay is built, and an installer that re-homes the operator (ODH
//! installs into its own applications namespace) moves the Deployment without
//! touching the rendered serverName. The operator applies it instead, reading
//! its namespace from the downward API.

use kube::api::{Api, ApiResource, DynamicObject, GroupVersionKind, Patch, PatchParams};
use kube::{Client, Error};
use modelexpress_operator::telemetry;
use serde_json::json;

/// Set from the downward API in the OpenShift overlay.
pub const NAMESPACE_ENV: &str = "POD_NAMESPACE";

pub const API_GROUP: &str = "monitoring.coreos.com";
pub const API_VERSION: &str = "v1";
pub const KIND: &str = "ServiceMonitor";
pub const PLURAL: &str = "servicemonitors";

/// The operator's metrics Service, from the base manifests.
pub const METRICS_SERVICE_NAME: &str = "modelexpress-operator-metrics";
/// service-ca's bundle, injected into this ConfigMap by the overlay.
pub const SERVICE_CA_CONFIGMAP: &str = "openshift-service-ca.crt";

pub const NAME: &str = "modelexpress-operator";
const FIELD_MANAGER: &str = "modelexpress-operator";

fn gvk() -> GroupVersionKind {
    GroupVersionKind::gvk(API_GROUP, API_VERSION, KIND)
}

fn api_resource() -> ApiResource {
    let mut resource = ApiResource::from_gvk(&gvk());
    resource.plural = PLURAL.to_string();
    resource
}

/// The ServiceMonitor for the metrics Service in `namespace`.
#[must_use]
pub fn service_monitor(namespace: &str) -> serde_json::Value {
    json!({
        "apiVersion": format!("{API_GROUP}/{API_VERSION}"),
        "kind": KIND,
        "metadata": {
            "name": NAME,
            "namespace": namespace,
            "labels": {"app.kubernetes.io/name": NAME},
        },
        "spec": {
            "selector": {"matchLabels": {"app.kubernetes.io/name": NAME}},
            "endpoints": [{
                "port": telemetry::METRICS_TLS_PORT_NAME,
                "scheme": "https",
                "bearerTokenFile": "/var/run/secrets/kubernetes.io/serviceaccount/token",
                "tlsConfig": {
                    "ca": {"configMap": {"name": SERVICE_CA_CONFIGMAP, "key": "service-ca.crt"}},
                    "serverName": format!("{METRICS_SERVICE_NAME}.{namespace}.svc"),
                },
            }],
        },
    })
}

/// Apply the ServiceMonitor, or explain why it was skipped. Never fatal: a
/// missing scrape config is worth a log, not a dead operator.
pub async fn ensure(client: Client) {
    if std::env::var_os(telemetry::METRICS_TLS_DIR_ENV).is_none() {
        tracing::debug!("metrics are plaintext; no ServiceMonitor applied");
        return;
    }
    let Some(namespace) = std::env::var(NAMESPACE_ENV)
        .ok()
        .filter(|ns| !ns.is_empty())
    else {
        tracing::warn!("{NAMESPACE_ENV} is unset; skipping the metrics ServiceMonitor");
        return;
    };
    if kube::discovery::oneshot::pinned_kind(&client, &gvk())
        .await
        .is_err()
    {
        tracing::info!("{API_GROUP} not served; skipping the metrics ServiceMonitor");
        return;
    }
    match apply(&client, &namespace).await {
        Ok(()) => tracing::info!(namespace, "metrics ServiceMonitor applied"),
        Err(e) => tracing::warn!("applying the metrics ServiceMonitor in {namespace}: {e}"),
    }
}

async fn apply(client: &Client, namespace: &str) -> Result<(), Error> {
    let api = Api::<DynamicObject>::namespaced_with(client.clone(), namespace, &api_resource());
    api.patch(
        NAME,
        &PatchParams::apply(FIELD_MANAGER).force(),
        &Patch::Apply(&service_monitor(namespace)),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use crate::servicemonitor::{METRICS_SERVICE_NAME, NAME, service_monitor};
    use modelexpress_operator::telemetry;

    #[test]
    fn server_name_and_namespace_follow_the_operator() {
        let monitor = service_monitor("redhat-ods-applications");
        assert_eq!(monitor["metadata"]["namespace"], "redhat-ods-applications");
        assert_eq!(
            monitor["spec"]["endpoints"][0]["tlsConfig"]["serverName"],
            format!("{METRICS_SERVICE_NAME}.redhat-ods-applications.svc")
        );
    }

    #[test]
    fn it_scrapes_the_metrics_port_over_https_with_a_token() {
        let monitor = service_monitor("modelexpress-operator-system");
        let endpoint = &monitor["spec"]["endpoints"][0];
        assert_eq!(endpoint["port"], telemetry::METRICS_TLS_PORT_NAME);
        assert_eq!(endpoint["scheme"], "https");
        assert_eq!(
            endpoint["bearerTokenFile"],
            "/var/run/secrets/kubernetes.io/serviceaccount/token"
        );
        assert_eq!(
            endpoint["tlsConfig"]["ca"]["configMap"]["key"],
            "service-ca.crt"
        );
        assert_eq!(
            monitor["spec"]["selector"]["matchLabels"]["app.kubernetes.io/name"],
            NAME
        );
    }
}
