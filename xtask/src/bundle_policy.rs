// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The module-bundle checks of ODH ADR-0016 over a rendered kustomize build:
//! every operator Deployment has explicit ingress and egress NetworkPolicy
//! coverage with named sources and declared ports, and its ServiceAccount
//! holds the NetworkPolicy verbs its controller needs.

use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::ContainerPort;
use k8s_openapi::api::networking::v1::{
    NetworkPolicy, NetworkPolicyEgressRule, NetworkPolicyPeer, NetworkPolicyPort,
};
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, PolicyRule, Role, RoleBinding};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use serde::Deserialize;
use std::collections::BTreeMap;

pub const NETWORK_POLICY_VERBS: [&str; 7] = [
    "create", "delete", "get", "list", "patch", "update", "watch",
];
const UNIVERSAL_CIDRS: [&str; 2] = ["0.0.0.0/0", "::/0"];

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("document {index}: {source}")]
    Yaml {
        index: usize,
        source: serde_norway::Error,
    },
    #[error("document {index} ({kind}): {source}")]
    Object {
        index: usize,
        kind: String,
        source: serde_json::Error,
    },
}

#[derive(Debug, Default)]
pub struct Bundle {
    pub deployments: Vec<Deployment>,
    pub policies: Vec<NetworkPolicy>,
    pub cluster_roles: Vec<ClusterRole>,
    pub roles: Vec<Role>,
    pub cluster_role_bindings: Vec<ClusterRoleBinding>,
    pub role_bindings: Vec<RoleBinding>,
}

fn typed<T: serde::de::DeserializeOwned>(
    index: usize,
    kind: &str,
    value: serde_json::Value,
) -> Result<T, BundleError> {
    serde_json::from_value(value).map_err(|source| BundleError::Object {
        index,
        kind: kind.to_string(),
        source,
    })
}

impl Bundle {
    /// Parses `kustomize build` output. Objects of the kinds checked here must
    /// deserialize as their stable API version; anything else is skipped.
    pub fn parse(rendered: &str) -> Result<Self, BundleError> {
        let mut bundle = Bundle::default();
        for (index, document) in serde_norway::Deserializer::from_str(rendered).enumerate() {
            let value = serde_json::Value::deserialize(document)
                .map_err(|source| BundleError::Yaml { index, source })?;
            let kind = value["kind"].as_str().unwrap_or_default().to_string();
            match kind.as_str() {
                "Deployment" => bundle.deployments.push(typed(index, &kind, value)?),
                "NetworkPolicy" => bundle.policies.push(typed(index, &kind, value)?),
                "ClusterRole" => bundle.cluster_roles.push(typed(index, &kind, value)?),
                "Role" => bundle.roles.push(typed(index, &kind, value)?),
                "ClusterRoleBinding" => bundle
                    .cluster_role_bindings
                    .push(typed(index, &kind, value)?),
                "RoleBinding" => bundle.role_bindings.push(typed(index, &kind, value)?),
                _ => {}
            }
        }
        Ok(bundle)
    }
}

fn is_empty(selector: &LabelSelector) -> bool {
    selector
        .match_labels
        .as_ref()
        .is_none_or(BTreeMap::is_empty)
        && selector
            .match_expressions
            .as_ref()
            .is_none_or(Vec::is_empty)
}

/// LabelSelector semantics: every matchLabels pair and every requirement.
pub fn selects(selector: &LabelSelector, labels: &BTreeMap<String, String>) -> bool {
    let pairs = selector
        .match_labels
        .iter()
        .flatten()
        .all(|(key, value)| labels.get(key) == Some(value));
    let requirements = selector.match_expressions.iter().flatten().all(|req| {
        let value = labels.get(&req.key);
        let values = req.values.as_deref().unwrap_or_default();
        match req.operator.as_str() {
            "In" => value.is_some_and(|v| values.contains(v)),
            "NotIn" => value.is_none_or(|v| !values.contains(v)),
            "Exists" => value.is_some(),
            "DoesNotExist" => value.is_none(),
            _ => false,
        }
    });
    pairs && requirements
}

fn name(meta: &kube::api::ObjectMeta) -> &str {
    meta.name.as_deref().unwrap_or("<unnamed>")
}

fn pod_labels(deployment: &Deployment) -> BTreeMap<String, String> {
    deployment
        .spec
        .as_ref()
        .and_then(|spec| spec.template.metadata.as_ref())
        .and_then(|meta| meta.labels.clone())
        .unwrap_or_default()
}

fn container_ports(deployment: &Deployment) -> Vec<ContainerPort> {
    deployment
        .spec
        .as_ref()
        .and_then(|spec| spec.template.spec.as_ref())
        .map(|pod| {
            pod.containers
                .iter()
                .flat_map(|c| c.ports.iter().flatten().cloned())
                .collect()
        })
        .unwrap_or_default()
}

fn service_account(deployment: &Deployment) -> &str {
    deployment
        .spec
        .as_ref()
        .and_then(|spec| spec.template.spec.as_ref())
        .and_then(|pod| pod.service_account_name.as_deref())
        .unwrap_or("default")
}

fn policy_types(policy: &NetworkPolicy) -> Vec<&str> {
    policy
        .spec
        .as_ref()
        .and_then(|spec| spec.policy_types.as_ref())
        .map(|types| types.iter().map(String::as_str).collect())
        .unwrap_or_default()
}

fn governs(policy: &NetworkPolicy, deployment: &Deployment) -> bool {
    policy.metadata.namespace == deployment.metadata.namespace
        && policy
            .spec
            .as_ref()
            .is_some_and(|spec| selects(&spec.pod_selector, &pod_labels(deployment)))
}

fn protocol(protocol: Option<&String>) -> &str {
    protocol.map_or("TCP", String::as_str)
}

fn declares(ports: &[ContainerPort], port: &NetworkPolicyPort) -> bool {
    ports.iter().any(|declared| {
        protocol(declared.protocol.as_ref()) == protocol(port.protocol.as_ref())
            && match &port.port {
                Some(IntOrString::Int(number)) => declared.container_port == *number,
                Some(IntOrString::String(port_name)) => declared.name.as_ref() == Some(port_name),
                None => false,
            }
    })
}

fn describe_port(port: &NetworkPolicyPort) -> String {
    let number = match &port.port {
        Some(IntOrString::Int(number)) => number.to_string(),
        Some(IntOrString::String(port_name)) => port_name.clone(),
        None => "*".to_string(),
    };
    format!(
        "{}/{number}",
        protocol(port.protocol.as_ref()).to_lowercase()
    )
}

fn peer_violation(peer: &NetworkPolicyPeer) -> Option<&'static str> {
    if peer.namespace_selector.is_none() && peer.pod_selector.is_none() && peer.ip_block.is_none() {
        return Some("an empty peer admits every source");
    }
    if peer.namespace_selector.as_ref().is_some_and(is_empty) {
        return Some("namespaceSelector {} admits every namespace");
    }
    if peer.namespace_selector.is_none() && peer.pod_selector.as_ref().is_some_and(is_empty) {
        return Some("podSelector {} admits every pod in the operator namespace");
    }
    if peer
        .ip_block
        .as_ref()
        .is_some_and(|block| UNIVERSAL_CIDRS.contains(&block.cidr.as_str()))
    {
        return Some("a universal CIDR admits every source");
    }
    None
}

fn egress_rule_violation(rule: &NetworkPolicyEgressRule) -> Option<&'static str> {
    let to = rule.to.as_ref().is_some_and(|to| !to.is_empty());
    let ports = rule.ports.as_ref().is_some_and(|ports| !ports.is_empty());
    match (to, ports) {
        (false, false) | (true, true) => None,
        _ => Some("a restricted egress rule must name both destinations and ports"),
    }
}

fn policy_violations(policy: &NetworkPolicy, bundle: &Bundle) -> Vec<String> {
    let policy_name = name(&policy.metadata);
    let mut out = Vec::new();
    let mut flag = |message: String| out.push(format!("NetworkPolicy {policy_name}: {message}"));
    let Some(spec) = policy.spec.as_ref() else {
        flag("has no spec".to_string());
        return out;
    };
    if is_empty(&spec.pod_selector) {
        flag("an empty podSelector selects every pod in the namespace".to_string());
    }
    let types = policy_types(policy);
    if types.is_empty() {
        flag("policyTypes must be explicit".to_string());
    }
    for unknown in types.iter().filter(|t| !["Ingress", "Egress"].contains(t)) {
        flag(format!("unknown policyType {unknown}"));
    }
    let ingress = spec.ingress.as_deref().unwrap_or_default();
    if !ingress.is_empty() && !types.contains(&"Ingress") {
        flag("ingress rules without Ingress in policyTypes are ignored".to_string());
    }
    match (&spec.egress, types.contains(&"Egress")) {
        (None, true) => flag("declares Egress but leaves egress unset".to_string()),
        (Some(rules), false) if !rules.is_empty() => {
            flag("egress rules without Egress in policyTypes are ignored".to_string())
        }
        _ => {}
    }
    for (index, rule) in spec.egress.iter().flatten().enumerate() {
        if let Some(problem) = egress_rule_violation(rule) {
            flag(format!("egress rule {index}: {problem}"));
        }
    }

    let selected: Vec<&Deployment> = bundle
        .deployments
        .iter()
        .filter(|deployment| governs(policy, deployment))
        .collect();
    if selected.is_empty() {
        flag("selects no operator workload in the bundle".to_string());
    }
    for (index, rule) in ingress.iter().enumerate() {
        match rule.from.as_deref() {
            None => flag(format!(
                "ingress rule {index}: no `from` admits every source"
            )),
            Some([]) => flag(format!("ingress rule {index}: `from: []` is prohibited")),
            Some(peers) => {
                for problem in peers.iter().filter_map(peer_violation) {
                    flag(format!("ingress rule {index}: {problem}"));
                }
            }
        }
        let ports = rule.ports.as_deref().unwrap_or_default();
        if ports.is_empty() {
            flag(format!(
                "ingress rule {index}: no `ports` admits every port"
            ));
        }
        for port in ports {
            if port.end_port.is_some() {
                flag(format!(
                    "ingress rule {index}: port ranges are not endpoints"
                ));
            }
            for deployment in &selected {
                if !declares(&container_ports(deployment), port) {
                    flag(format!(
                        "ingress rule {index}: {} is not a declared port of Deployment {}",
                        describe_port(port),
                        name(&deployment.metadata)
                    ));
                }
            }
        }
    }
    out
}

fn grants_network_policies(rule: &PolicyRule) -> bool {
    let groups = rule.api_groups.as_deref().unwrap_or_default();
    let resources = rule.resources.as_deref().unwrap_or_default();
    groups
        .iter()
        .any(|group| group == "networking.k8s.io" || group == "*")
        && resources
            .iter()
            .any(|resource| resource == "networkpolicies" || resource == "*")
}

/// NetworkPolicy verbs the Deployment's ServiceAccount holds through the
/// bundle's own bindings.
fn network_policy_verbs(bundle: &Bundle, deployment: &Deployment) -> Vec<String> {
    let sa = service_account(deployment);
    let namespace = &deployment.metadata.namespace;
    let is_subject = |subjects: &Option<Vec<k8s_openapi::api::rbac::v1::Subject>>| {
        subjects.iter().flatten().any(|subject| {
            subject.kind == "ServiceAccount"
                && subject.name == sa
                && &subject.namespace == namespace
        })
    };
    let cluster_role = |role_name: &str| -> Vec<&PolicyRule> {
        bundle
            .cluster_roles
            .iter()
            .filter(|role| role.metadata.name.as_deref() == Some(role_name))
            .flat_map(|role| role.rules.iter().flatten())
            .collect()
    };
    let mut rules: Vec<&PolicyRule> = Vec::new();
    for binding in &bundle.cluster_role_bindings {
        if is_subject(&binding.subjects) && binding.role_ref.kind == "ClusterRole" {
            rules.extend(cluster_role(&binding.role_ref.name));
        }
    }
    for binding in &bundle.role_bindings {
        if binding.metadata.namespace != *namespace || !is_subject(&binding.subjects) {
            continue;
        }
        match binding.role_ref.kind.as_str() {
            "ClusterRole" => rules.extend(cluster_role(&binding.role_ref.name)),
            "Role" => rules.extend(
                bundle
                    .roles
                    .iter()
                    .filter(|role| {
                        role.metadata.namespace == *namespace
                            && role.metadata.name.as_deref() == Some(&binding.role_ref.name)
                    })
                    .flat_map(|role| role.rules.iter().flatten()),
            ),
            _ => {}
        }
    }
    let mut verbs: Vec<String> = rules
        .into_iter()
        .filter(|rule| grants_network_policies(rule))
        .flat_map(|rule| rule.verbs.iter().cloned())
        .collect();
    verbs.sort();
    verbs.dedup();
    verbs
}

fn deployment_violations(deployment: &Deployment, bundle: &Bundle) -> Vec<String> {
    let deployment_name = name(&deployment.metadata);
    let mut out = Vec::new();
    let governing: Vec<&NetworkPolicy> = bundle
        .policies
        .iter()
        .filter(|policy| governs(policy, deployment))
        .collect();
    if !governing
        .iter()
        .any(|policy| policy_types(policy).contains(&"Ingress"))
    {
        out.push(format!(
            "Deployment {deployment_name}: no NetworkPolicy governs its ingress"
        ));
    }
    if !governing.iter().any(|policy| {
        policy_types(policy).contains(&"Egress")
            && policy
                .spec
                .as_ref()
                .is_some_and(|spec| spec.egress.is_some())
    }) {
        out.push(format!(
            "Deployment {deployment_name}: no NetworkPolicy declares its egress"
        ));
    }
    let verbs = network_policy_verbs(bundle, deployment);
    let missing: Vec<&str> = NETWORK_POLICY_VERBS
        .into_iter()
        .filter(|verb| !verbs.iter().any(|held| held == verb || held == "*"))
        .collect();
    if !missing.is_empty() {
        out.push(format!(
            "Deployment {deployment_name}: ServiceAccount {} lacks networkpolicies verbs {}",
            service_account(deployment),
            missing.join(", ")
        ));
    }
    out
}

/// Every ADR-0016 bundle rule the rendered objects break. Empty when compliant.
pub fn violations(bundle: &Bundle) -> Vec<String> {
    let mut out: Vec<String> = bundle
        .policies
        .iter()
        .flat_map(|policy| policy_violations(policy, bundle))
        .collect();
    if bundle.deployments.is_empty() {
        out.push("the bundle renders no operator Deployment".to_string());
    }
    out.extend(
        bundle
            .deployments
            .iter()
            .flat_map(|deployment| deployment_violations(deployment, bundle)),
    );
    out
}

fn describe_egress(rules: &[NetworkPolicyEgressRule]) -> &'static str {
    match rules {
        [] => "deny-all",
        rules
            if rules
                .iter()
                .any(|rule| *rule == NetworkPolicyEgressRule::default()) =>
        {
            "allow-all"
        }
        _ => "restricted",
    }
}

/// One line per Deployment: the policies that govern it, what they admit, and
/// its egress behavior.
pub fn summary(bundle: &Bundle) -> Vec<String> {
    bundle
        .deployments
        .iter()
        .map(|deployment| {
            let namespace = deployment
                .metadata
                .namespace
                .as_deref()
                .unwrap_or("<platform namespace>");
            let policies: Vec<String> = bundle
                .policies
                .iter()
                .filter(|policy| governs(policy, deployment))
                .filter_map(|policy| {
                    let spec = policy.spec.as_ref()?;
                    let ingress: Vec<String> = spec
                        .ingress
                        .iter()
                        .flatten()
                        .flat_map(|rule| rule.ports.iter().flatten().map(describe_port))
                        .collect();
                    let egress = spec.egress.as_deref().map_or("unset", describe_egress);
                    Some(format!(
                        "{} [ingress {}; egress {egress}]",
                        name(&policy.metadata),
                        if ingress.is_empty() {
                            "none".to_string()
                        } else {
                            ingress.join(",")
                        }
                    ))
                })
                .collect();
            format!(
                "Deployment {}/{}: {}",
                namespace,
                name(&deployment.metadata),
                policies.join("; ")
            )
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use crate::bundle_policy::{Bundle, BundleError, selects, summary, violations};
    use crate::objects::{
        cluster_role, cluster_role_binding, deployment, network_policy, pod_labels,
    };
    use k8s_openapi::api::networking::v1::{
        IPBlock, NetworkPolicy, NetworkPolicyEgressRule, NetworkPolicyIngressRule,
        NetworkPolicyPeer, NetworkPolicyPort,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, LabelSelectorRequirement};
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
    use std::collections::BTreeMap;

    const NAMESPACE: &str = "platform-applications";

    /// What `kustomize build` with a namespace override yields for the base.
    fn rendered() -> Bundle {
        let mut deployment = deployment("registry.example/operator@sha256:1111");
        deployment.metadata.namespace = Some(NAMESPACE.to_string());
        let mut policy = network_policy();
        policy.metadata.namespace = Some(NAMESPACE.to_string());
        let mut binding = cluster_role_binding();
        for subject in binding.subjects.iter_mut().flatten() {
            subject.namespace = Some(NAMESPACE.to_string());
        }
        Bundle {
            deployments: vec![deployment],
            policies: vec![policy],
            cluster_roles: vec![cluster_role()],
            cluster_role_bindings: vec![binding],
            ..Bundle::default()
        }
    }

    fn with_policy(edit: impl FnOnce(&mut NetworkPolicy)) -> Bundle {
        let mut bundle = rendered();
        edit(&mut bundle.policies[0]);
        bundle
    }

    fn with_ingress(edit: impl FnOnce(&mut NetworkPolicyIngressRule)) -> Bundle {
        with_policy(|policy| {
            let rule = policy
                .spec
                .as_mut()
                .and_then(|spec| spec.ingress.as_mut())
                .and_then(|rules| rules.first_mut())
                .expect("an ingress rule");
            edit(rule);
        })
    }

    fn with_peer(peer: NetworkPolicyPeer) -> Bundle {
        with_ingress(|rule| rule.from = Some(vec![peer]))
    }

    fn assert_flags(bundle: &Bundle, needle: &str) {
        let found = violations(bundle);
        assert!(
            found.iter().any(|v| v.contains(needle)),
            "expected a violation containing {needle:?}, got {found:#?}"
        );
    }

    #[test]
    fn generated_bundle_is_compliant() {
        assert_eq!(violations(&rendered()), Vec::<String>::new());
    }

    #[test]
    fn summary_records_ports_and_egress() {
        assert_eq!(
            summary(&rendered()),
            [format!(
                "Deployment {NAMESPACE}/modelexpress-operator: modelexpress-operator \
                 [ingress tcp/8080; egress allow-all]"
            )]
        );
    }

    #[test]
    fn parses_rendered_yaml_and_skips_unchecked_kinds() {
        let bundle = rendered();
        let yaml = [
            serde_norway::to_string(&bundle.deployments[0]).expect("yaml"),
            serde_norway::to_string(&bundle.policies[0]).expect("yaml"),
            serde_norway::to_string(&bundle.cluster_roles[0]).expect("yaml"),
            serde_norway::to_string(&bundle.cluster_role_bindings[0]).expect("yaml"),
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: params\n".to_string(),
        ]
        .join("---\n");
        let parsed = Bundle::parse(&yaml).expect("parses");
        assert_eq!(parsed.deployments, bundle.deployments);
        assert_eq!(parsed.policies, bundle.policies);
        assert_eq!(parsed.cluster_roles, bundle.cluster_roles);
        assert_eq!(parsed.cluster_role_bindings, bundle.cluster_role_bindings);
        assert_eq!(violations(&parsed), Vec::<String>::new());
    }

    #[test]
    fn rejects_a_network_policy_of_another_api_version() {
        let yaml = "apiVersion: extensions/v1beta1\nkind: NetworkPolicy\nmetadata:\n  name: old\nspec:\n  podSelector: {}\n";
        assert!(matches!(
            Bundle::parse(yaml),
            Err(BundleError::Object { kind, .. }) if kind == "NetworkPolicy"
        ));
    }

    #[test]
    fn missing_policy_leaves_ingress_and_egress_ungoverned() {
        let mut bundle = rendered();
        bundle.policies.clear();
        assert_flags(&bundle, "no NetworkPolicy governs its ingress");
        assert_flags(&bundle, "no NetworkPolicy declares its egress");
    }

    #[test]
    fn policy_in_another_namespace_governs_nothing() {
        let bundle = with_policy(|policy| policy.metadata.namespace = Some("elsewhere".into()));
        assert_flags(&bundle, "selects no operator workload");
        assert_flags(&bundle, "no NetworkPolicy governs its ingress");
    }

    #[test]
    fn empty_pod_selector_is_rejected() {
        let bundle = with_policy(|policy| {
            policy.spec.as_mut().expect("spec").pod_selector = LabelSelector::default();
        });
        assert_flags(&bundle, "an empty podSelector");
    }

    #[test]
    fn selector_that_misses_the_operator_pods_is_rejected() {
        let bundle = with_policy(|policy| {
            policy.spec.as_mut().expect("spec").pod_selector = LabelSelector {
                match_labels: Some(
                    [(
                        "app.kubernetes.io/name".into(),
                        "modelexpress-server".into(),
                    )]
                    .into(),
                ),
                ..LabelSelector::default()
            };
        });
        assert_flags(&bundle, "selects no operator workload");
    }

    #[test]
    fn policy_types_must_be_explicit() {
        let bundle = with_policy(|policy| policy.spec.as_mut().expect("spec").policy_types = None);
        assert_flags(&bundle, "policyTypes must be explicit");
        assert_flags(&bundle, "no NetworkPolicy governs its ingress");
    }

    #[test]
    fn egress_type_needs_explicit_egress() {
        let bundle = with_policy(|policy| policy.spec.as_mut().expect("spec").egress = None);
        assert_flags(&bundle, "declares Egress but leaves egress unset");
        assert_flags(&bundle, "no NetworkPolicy declares its egress");
    }

    #[test]
    fn egress_rules_without_egress_type_are_flagged() {
        let bundle = with_policy(|policy| {
            policy.spec.as_mut().expect("spec").policy_types = Some(vec!["Ingress".into()]);
        });
        assert_flags(&bundle, "egress rules without Egress in policyTypes");
        assert_flags(&bundle, "no NetworkPolicy declares its egress");
    }

    #[test]
    fn half_restricted_egress_rule_is_rejected() {
        let bundle = with_policy(|policy| {
            policy.spec.as_mut().expect("spec").egress = Some(vec![NetworkPolicyEgressRule {
                to: None,
                ports: Some(vec![NetworkPolicyPort {
                    port: Some(IntOrString::Int(6443)),
                    ..NetworkPolicyPort::default()
                }]),
            }]);
        });
        assert_flags(&bundle, "must name both destinations and ports");
    }

    #[test]
    fn deny_all_egress_is_compliant() {
        let bundle =
            with_policy(|policy| policy.spec.as_mut().expect("spec").egress = Some(vec![]));
        assert_eq!(violations(&bundle), Vec::<String>::new());
        assert!(summary(&bundle)[0].contains("egress deny-all"));
    }

    #[test]
    fn no_ingress_rules_is_a_compliant_deny_all() {
        let bundle =
            with_policy(|policy| policy.spec.as_mut().expect("spec").ingress = Some(vec![]));
        assert_eq!(violations(&bundle), Vec::<String>::new());
        assert!(summary(&bundle)[0].contains("ingress none"));
    }

    #[test]
    fn missing_from_admits_every_source() {
        assert_flags(&with_ingress(|rule| rule.from = None), "no `from`");
    }

    #[test]
    fn empty_from_list_is_prohibited() {
        assert_flags(&with_ingress(|rule| rule.from = Some(vec![])), "`from: []`");
    }

    #[test]
    fn empty_peer_is_prohibited() {
        assert_flags(&with_peer(NetworkPolicyPeer::default()), "an empty peer");
    }

    #[test]
    fn empty_namespace_selector_is_prohibited() {
        let peer = NetworkPolicyPeer {
            namespace_selector: Some(LabelSelector::default()),
            ..NetworkPolicyPeer::default()
        };
        assert_flags(&with_peer(peer), "namespaceSelector {}");
    }

    #[test]
    fn bare_empty_pod_selector_is_prohibited() {
        let peer = NetworkPolicyPeer {
            pod_selector: Some(LabelSelector::default()),
            ..NetworkPolicyPeer::default()
        };
        assert_flags(&with_peer(peer), "podSelector {}");
    }

    #[test]
    fn universal_cidrs_are_prohibited() {
        for cidr in ["0.0.0.0/0", "::/0"] {
            let peer = NetworkPolicyPeer {
                ip_block: Some(IPBlock {
                    cidr: cidr.into(),
                    except: None,
                }),
                ..NetworkPolicyPeer::default()
            };
            assert_flags(&with_peer(peer), "universal CIDR");
        }
    }

    #[test]
    fn missing_ports_admit_every_port() {
        assert_flags(&with_ingress(|rule| rule.ports = None), "no `ports`");
        assert_flags(
            &with_ingress(|rule| rule.ports = Some(vec![])),
            "no `ports`",
        );
    }

    #[test]
    fn undeclared_ports_are_rejected() {
        for port in [
            IntOrString::Int(8081 + 1000),
            IntOrString::String("https-metrics".into()),
        ] {
            let bundle = with_ingress(|rule| {
                rule.ports = Some(vec![NetworkPolicyPort {
                    port: Some(port),
                    protocol: Some("TCP".into()),
                    end_port: None,
                }]);
            });
            assert_flags(&bundle, "is not a declared port of Deployment");
        }
    }

    #[test]
    fn protocol_must_match_the_declared_port() {
        let bundle = with_ingress(|rule| {
            rule.ports = Some(vec![NetworkPolicyPort {
                port: Some(IntOrString::Int(8080)),
                protocol: Some("UDP".into()),
                end_port: None,
            }]);
        });
        assert_flags(&bundle, "udp/8080 is not a declared port");
    }

    #[test]
    fn named_declared_ports_resolve() {
        let bundle = with_ingress(|rule| {
            rule.ports = Some(vec![NetworkPolicyPort {
                port: Some(IntOrString::String("http-metrics".into())),
                protocol: None,
                end_port: None,
            }]);
        });
        assert_eq!(violations(&bundle), Vec::<String>::new());
    }

    #[test]
    fn port_ranges_are_rejected() {
        let bundle = with_ingress(|rule| {
            for port in rule.ports.iter_mut().flatten() {
                port.end_port = Some(8090);
            }
        });
        assert_flags(&bundle, "port ranges");
    }

    #[test]
    fn rbac_must_grant_every_network_policy_verb() {
        let mut bundle = rendered();
        for rule in bundle.cluster_roles[0].rules.iter_mut().flatten() {
            if rule
                .resources
                .iter()
                .flatten()
                .any(|r| r == "networkpolicies")
            {
                rule.verbs.retain(|verb| verb != "watch" && verb != "patch");
            }
        }
        assert_flags(&bundle, "lacks networkpolicies verbs patch, watch");
    }

    #[test]
    fn rbac_bound_to_another_namespace_does_not_count() {
        let mut bundle = rendered();
        for subject in bundle.cluster_role_bindings[0]
            .subjects
            .iter_mut()
            .flatten()
        {
            subject.namespace = Some("elsewhere".into());
        }
        assert_flags(&bundle, "lacks networkpolicies verbs");
    }

    #[test]
    fn rbac_through_a_namespaced_role_binding_counts() {
        use k8s_openapi::api::rbac::v1::{PolicyRule, Role, RoleBinding, RoleRef, Subject};
        let mut bundle = rendered();
        bundle.cluster_role_bindings.clear();
        let meta = |name: &str| kube::api::ObjectMeta {
            name: Some(name.into()),
            namespace: Some(NAMESPACE.into()),
            ..kube::api::ObjectMeta::default()
        };
        bundle.roles.push(Role {
            metadata: meta("netpol"),
            rules: Some(vec![PolicyRule {
                api_groups: Some(vec!["networking.k8s.io".into()]),
                resources: Some(vec!["networkpolicies".into()]),
                verbs: vec!["*".into()],
                ..PolicyRule::default()
            }]),
        });
        bundle.role_bindings.push(RoleBinding {
            metadata: meta("netpol"),
            role_ref: RoleRef {
                api_group: "rbac.authorization.k8s.io".into(),
                kind: "Role".into(),
                name: "netpol".into(),
            },
            subjects: Some(vec![Subject {
                kind: "ServiceAccount".into(),
                name: "modelexpress-operator".into(),
                namespace: Some(NAMESPACE.into()),
                ..Subject::default()
            }]),
        });
        assert_eq!(violations(&bundle), Vec::<String>::new());
    }

    #[test]
    fn empty_bundle_is_not_compliant() {
        assert_flags(&Bundle::default(), "renders no operator Deployment");
    }

    #[test]
    fn label_selector_semantics() {
        let labels: BTreeMap<String, String> =
            [("a".into(), "1".into()), ("b".into(), "2".into())].into();
        let req = |key: &str, operator: &str, values: &[&str]| LabelSelector {
            match_expressions: Some(vec![LabelSelectorRequirement {
                key: key.into(),
                operator: operator.into(),
                values: Some(values.iter().map(|v| (*v).to_string()).collect()),
            }]),
            ..LabelSelector::default()
        };
        assert!(selects(&req("a", "In", &["1", "3"]), &labels));
        assert!(!selects(&req("a", "In", &["3"]), &labels));
        assert!(!selects(&req("c", "In", &["1"]), &labels));
        assert!(selects(&req("a", "NotIn", &["3"]), &labels));
        assert!(!selects(&req("a", "NotIn", &["1"]), &labels));
        assert!(selects(&req("c", "NotIn", &["1"]), &labels));
        assert!(selects(&req("a", "Exists", &[]), &labels));
        assert!(!selects(&req("c", "Exists", &[]), &labels));
        assert!(selects(&req("c", "DoesNotExist", &[]), &labels));
        assert!(!selects(&req("a", "DoesNotExist", &[]), &labels));
        assert!(!selects(&req("a", "Bogus", &["1"]), &labels));
        assert!(selects(
            &LabelSelector {
                match_labels: Some(pod_labels()),
                ..LabelSelector::default()
            },
            &pod_labels()
        ));
    }
}
