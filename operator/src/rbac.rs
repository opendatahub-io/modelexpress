// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! ServiceAccount and namespace RBAC for the server pod.
//!
//! The kubernetes metadata backend stores state in modelexpress.nvidia.com
//! CRs plus tensor-descriptor ConfigMaps; without these grants the server
//! exits at startup with a 403. Rules mirror upstream's
//! ci/k8s/server/rbac-modelmetadata.yaml.

use crate::crd::{MetadataBackend, ModelExpressServerSpec};
use crate::labels::managed_labels;
use k8s_openapi::api::core::v1::ServiceAccount;
use k8s_openapi::api::rbac::v1::{PolicyRule, Role, RoleBinding, RoleRef, Subject};
use kube::api::ObjectMeta;

pub const UPSTREAM_API_GROUP: &str = "modelexpress.nvidia.com";

/// SA the server pod runs as. Users can bring their own via
/// spec.serviceAccountName; then nothing here is created and binding the
/// upstream Role to it is their job.
pub fn service_account_name(cr_name: &str, spec: &ModelExpressServerSpec) -> String {
    spec.service_account_name
        .clone()
        .unwrap_or_else(|| format!("{cr_name}-server"))
}

pub fn role_name(cr_name: &str) -> String {
    format!("{cr_name}-metadata")
}

pub struct ServerRbac {
    pub service_account: Option<ServiceAccount>,
    pub role: Option<Role>,
    pub role_binding: Option<RoleBinding>,
}

/// The verbs the server needs on the upstream CRs and ConfigMaps. Public so
/// the operator's own ClusterRole can include them: RBAC escalation
/// prevention means the operator can only grant what it holds.
pub fn server_policy_rules() -> Vec<PolicyRule> {
    let crud = vec![
        "get".to_string(),
        "list".to_string(),
        "watch".to_string(),
        "create".to_string(),
        "update".to_string(),
        "patch".to_string(),
        "delete".to_string(),
    ];
    let status = vec!["get".to_string(), "update".to_string(), "patch".to_string()];
    vec![
        PolicyRule {
            api_groups: Some(vec![UPSTREAM_API_GROUP.to_string()]),
            resources: Some(vec![
                "modelmetadatas".to_string(),
                "modelcacheentries".to_string(),
            ]),
            verbs: crud.clone(),
            ..PolicyRule::default()
        },
        PolicyRule {
            api_groups: Some(vec![UPSTREAM_API_GROUP.to_string()]),
            resources: Some(vec![
                "modelmetadatas/status".to_string(),
                "modelcacheentries/status".to_string(),
            ]),
            verbs: status,
            ..PolicyRule::default()
        },
        // Tensor descriptors are stored as ConfigMaps; upstream needs the
        // whole namespace, so run MX in a dedicated one on shared clusters.
        PolicyRule {
            api_groups: Some(vec![String::new()]),
            resources: Some(vec!["configmaps".to_string()]),
            verbs: crud,
            ..PolicyRule::default()
        },
    ]
}

pub fn render_rbac(cr_name: &str, spec: &ModelExpressServerSpec) -> ServerRbac {
    if spec.service_account_name.is_some() {
        return ServerRbac {
            service_account: None,
            role: None,
            role_binding: None,
        };
    }

    let sa_name = service_account_name(cr_name, spec);
    let service_account = Some(ServiceAccount {
        metadata: ObjectMeta {
            name: Some(sa_name.clone()),
            labels: Some(managed_labels(cr_name)),
            ..ObjectMeta::default()
        },
        ..ServiceAccount::default()
    });

    // redis backend keeps state out of the cluster; the SA exists for
    // identity (and future TokenReview auth) but needs no grants
    if !matches!(spec.metadata_backend, MetadataBackend::Kubernetes {}) {
        return ServerRbac {
            service_account,
            role: None,
            role_binding: None,
        };
    }

    let role = Role {
        metadata: ObjectMeta {
            name: Some(role_name(cr_name)),
            labels: Some(managed_labels(cr_name)),
            ..ObjectMeta::default()
        },
        rules: Some(server_policy_rules()),
    };
    let role_binding = RoleBinding {
        metadata: ObjectMeta {
            name: Some(role_name(cr_name)),
            labels: Some(managed_labels(cr_name)),
            ..ObjectMeta::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "Role".to_string(),
            name: role_name(cr_name),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".to_string(),
            name: sa_name,
            ..Subject::default()
        }]),
    };

    ServerRbac {
        service_account,
        role: Some(role),
        role_binding: Some(role_binding),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::crd::RedisBackend;

    fn spec(backend: MetadataBackend, sa: Option<&str>) -> ModelExpressServerSpec {
        ModelExpressServerSpec {
            image: "img".into(),
            replicas: 1,
            metadata_backend: backend,
            port: 8001,
            log: None,
            cache: None,
            security: None,
            reaper: None,
            credentials: None,
            pod_metadata: None,
            resources: None,
            node_selector: None,
            tolerations: None,
            affinity: None,
            network_policy: None,
            service_account_name: sa.map(String::from),
        }
    }

    #[test]
    fn kubernetes_backend_gets_sa_role_binding() {
        let rbac = render_rbac("mx", &spec(MetadataBackend::Kubernetes {}, None));
        assert_eq!(
            rbac.service_account.expect("sa").metadata.name.as_deref(),
            Some("mx-server")
        );
        let role = rbac.role.expect("role");
        assert_eq!(role.metadata.name.as_deref(), Some("mx-metadata"));
        let rules = role.rules.expect("rules");
        assert!(rules.iter().any(|r| {
            r.resources
                .as_ref()
                .is_some_and(|res| res.contains(&"modelmetadatas".to_string()))
        }));
        assert!(rules.iter().any(|r| {
            r.resources
                .as_ref()
                .is_some_and(|res| res.contains(&"configmaps".to_string()))
        }));
        let binding = rbac.role_binding.expect("binding");
        assert_eq!(binding.subjects.expect("subjects")[0].name, "mx-server");
    }

    #[test]
    fn redis_backend_gets_sa_only() {
        let rbac = render_rbac(
            "mx",
            &spec(
                MetadataBackend::Redis(RedisBackend {
                    url: Some("redis://r:6379".into()),
                    url_secret: None,
                }),
                None,
            ),
        );
        assert!(rbac.service_account.is_some());
        assert!(rbac.role.is_none());
        assert!(rbac.role_binding.is_none());
    }

    #[test]
    fn user_supplied_sa_disables_generation() {
        let rbac = render_rbac("mx", &spec(MetadataBackend::Kubernetes {}, Some("my-sa")));
        assert!(rbac.service_account.is_none());
        assert!(rbac.role.is_none());
        assert!(rbac.role_binding.is_none());
        assert_eq!(
            service_account_name("mx", &spec(MetadataBackend::Kubernetes {}, Some("my-sa"))),
            "my-sa"
        );
    }
}
