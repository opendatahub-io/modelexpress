// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reconcile loop: ModelExpressServer -> Deployment + Service + PVC.

use crate::crd::{CacheStorage, ModelExpressServer, ModelExpressServerStatus};
use crate::deployment::{DesiredState, render};
use crate::rbac::{ServerRbac, render_rbac, role_name, service_account_name};
use futures::StreamExt;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Service, ServiceAccount};
use k8s_openapi::api::networking::v1::NetworkPolicy;
use k8s_openapi::api::rbac::v1::{Role, RoleBinding};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::{Api, ObjectMeta, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher;
use kube::{Client, Resource, ResourceExt};
use std::sync::Arc;
use std::time::Duration;

pub const FIELD_MANAGER: &str = "modelexpress-operator";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("kube api: {0}")]
    Kube(#[from] kube::Error),
    #[error("CR has no namespace")]
    MissingNamespace,
    #[error("CR has no uid")]
    MissingUid,
    #[error("existingClaim {claim} not found")]
    MissingClaim { claim: String },
    #[error(
        "existingClaim {claim} is single-node ({modes:?}) but replicas is {replicas}; \
         scheduling would deadlock"
    )]
    SingleNodeClaim {
        claim: String,
        modes: Vec<String>,
        replicas: i32,
    },
}

pub struct Ctx {
    pub client: Client,
}

pub async fn run(client: Client) -> Result<(), kube::Error> {
    let servers = Api::<ModelExpressServer>::all(client.clone());
    let deployments = Api::<Deployment>::all(client.clone());
    let services = Api::<Service>::all(client.clone());
    let pvcs = Api::<PersistentVolumeClaim>::all(client.clone());

    let netpols = Api::<NetworkPolicy>::all(client.clone());
    let sas = Api::<ServiceAccount>::all(client.clone());
    let roles = Api::<Role>::all(client.clone());
    let bindings = Api::<RoleBinding>::all(client.clone());

    Controller::new(servers, watcher::Config::default())
        .owns(deployments, watcher::Config::default())
        .owns(services, watcher::Config::default())
        .owns(pvcs, watcher::Config::default())
        .owns(netpols, watcher::Config::default())
        .owns(sas, watcher::Config::default())
        .owns(roles, watcher::Config::default())
        .owns(bindings, watcher::Config::default())
        .shutdown_on_signal()
        .run(reconcile, error_policy, Arc::new(Ctx { client }))
        .for_each(|result| async move {
            match result {
                Ok((obj, _)) => tracing::debug!(name = %obj.name, "reconciled"),
                Err(err) => tracing::warn!(%err, "reconcile failed"),
            }
        })
        .await;
    Ok(())
}

async fn reconcile(cr: Arc<ModelExpressServer>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let start = std::time::Instant::now();
    let result = reconcile_inner(cr, ctx).await;
    metrics::histogram!("mxop_reconcile_duration_seconds").record(start.elapsed().as_secs_f64());
    match &result {
        Ok(_) => metrics::counter!("mxop_reconcile_total", "outcome" => "ok").increment(1),
        Err(err) => {
            metrics::counter!("mxop_reconcile_total", "outcome" => "error").increment(1);
            metrics::counter!("mxop_reconcile_errors_total", "reason" => reason(err)).increment(1);
        }
    }
    result
}

#[tracing::instrument(skip_all, fields(name = %cr.name_any(), namespace = cr.namespace()))]
async fn reconcile_inner(cr: Arc<ModelExpressServer>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let ns = cr.namespace().ok_or(Error::MissingNamespace)?;
    let name = cr.name_any();

    let result = apply(&cr, &ns, &name, &ctx).await;
    let (condition, endpoint, observed_generation) = match &result {
        Ok(()) => (
            ready_condition(&cr, "True", "Applied", "resources applied"),
            Some(endpoint(&name, &ns, cr.spec.port)),
            cr.metadata.generation,
        ),
        Err(err) => (
            ready_condition(&cr, "False", reason(err), &err.to_string()),
            None,
            // Nothing was applied, so leave the previous value alone: clients
            // compare generation against observedGeneration to decide whether
            // the current spec has been acted on.
            cr.status.as_ref().and_then(|s| s.observed_generation),
        ),
    };
    write_status(&ns, &name, &ctx, condition, endpoint, observed_generation).await?;

    result.map(|()| Action::requeue(Duration::from_secs(300)))
}

/// What clients set MODEL_EXPRESS_ENDPOINT to. The Service is always named
/// after the CR.
pub fn endpoint(name: &str, ns: &str, port: i32) -> String {
    format!("grpc://{name}.{ns}.svc.cluster.local:{port}")
}

#[tracing::instrument(skip_all)]
async fn apply(cr: &ModelExpressServer, ns: &str, name: &str, ctx: &Ctx) -> Result<(), Error> {
    check_existing_claim(cr, ns, ctx).await?;
    let uid = cr.metadata.uid.clone().ok_or(Error::MissingUid)?;

    let DesiredState {
        mut deployment,
        mut service,
        pvc,
        network_policy,
    } = render(name, &cr.spec);

    let owner = cr.controller_owner_ref(&());
    stamp(&mut deployment.metadata, ns, owner.clone());
    stamp(&mut service.metadata, ns, owner.clone());

    let params = PatchParams::apply(FIELD_MANAGER).force();

    // RBAC before the Deployment: pods referencing a not-yet-existing SA
    // fail admission at the ReplicaSet level.
    apply_rbac(cr, ns, ctx, &params, &uid).await?;

    if let Some(mut pvc) = pvc {
        stamp(&mut pvc.metadata, ns, owner);
        let api = Api::<PersistentVolumeClaim>::namespaced(ctx.client.clone(), ns);
        let pvc_name = pvc.metadata.name.clone().unwrap_or_default();
        api.patch(&pvc_name, &params, &Patch::Apply(&pvc)).await?;
    }

    let api = Api::<Deployment>::namespaced(ctx.client.clone(), ns);
    api.patch(name, &params, &Patch::Apply(&deployment)).await?;

    let api = Api::<Service>::namespaced(ctx.client.clone(), ns);
    api.patch(name, &params, &Patch::Apply(&service)).await?;

    let api = Api::<NetworkPolicy>::namespaced(ctx.client.clone(), ns);
    match network_policy {
        Some(mut netpol) => {
            stamp(&mut netpol.metadata, ns, cr.controller_owner_ref(&()));
            api.patch(name, &params, &Patch::Apply(&netpol)).await?;
        }
        // config removed: clean up the stale policy rather than leave a
        // stray ingress restriction behind
        None => delete_if_owned(&api, name, &uid).await?,
    }

    tracing::debug!("desired state applied");
    Ok(())
}

#[tracing::instrument(skip_all)]
async fn apply_rbac(
    cr: &ModelExpressServer,
    ns: &str,
    ctx: &Ctx,
    params: &PatchParams,
    uid: &str,
) -> Result<(), Error> {
    let name = cr.name_any();
    let ServerRbac {
        service_account,
        role,
        role_binding,
    } = render_rbac(&name, &cr.spec);
    let owner = cr.controller_owner_ref(&());

    let sa_api = Api::<ServiceAccount>::namespaced(ctx.client.clone(), ns);
    let generated_sa = service_account_name(&name, &cr.spec);
    match service_account {
        Some(mut sa) => {
            stamp(&mut sa.metadata, ns, owner.clone());
            sa_api
                .patch(&generated_sa, params, &Patch::Apply(&sa))
                .await?;
        }
        // user brought their own SA: remove the generated one if it lingers
        None => delete_if_owned(&sa_api, &format!("{name}-server"), uid).await?,
    }

    let role_api = Api::<Role>::namespaced(ctx.client.clone(), ns);
    let binding_api = Api::<RoleBinding>::namespaced(ctx.client.clone(), ns);
    let rname = role_name(&name);
    match (role, role_binding) {
        (Some(mut role), Some(mut binding)) => {
            stamp(&mut role.metadata, ns, owner.clone());
            stamp(&mut binding.metadata, ns, owner);
            role_api.patch(&rname, params, &Patch::Apply(&role)).await?;
            binding_api
                .patch(&rname, params, &Patch::Apply(&binding))
                .await?;
        }
        // backend no longer needs grants (redis, or user-managed SA)
        _ => {
            delete_if_owned(&binding_api, &rname, uid).await?;
            delete_if_owned(&role_api, &rname, uid).await?;
        }
    }
    Ok(())
}

/// Delete only what this CR owns.
///
/// Every cleanup path here targets a name derived from the CR, not a name the
/// operator can prove it created. `spec.networkPolicy` is unset by default, so
/// the netpol branch runs on the common path and would otherwise issue a
/// DELETE against `<namespace>/<cr-name>` on every reconcile, taking out a
/// user's unrelated NetworkPolicy that merely shares the name. Checking the
/// ownerReference makes the delete a no-op for anything the operator did not
/// create.
async fn delete_if_owned<K>(api: &Api<K>, name: &str, owner_uid: &str) -> Result<(), Error>
where
    K: kube::Resource + Clone + serde::de::DeserializeOwned + std::fmt::Debug,
{
    let Some(existing) = api.get_opt(name).await? else {
        return Ok(());
    };
    if !is_owned_by(existing.meta(), owner_uid) {
        tracing::debug!(name, "not operator-owned, leaving in place");
        return Ok(());
    }
    match api.delete(name, &Default::default()).await {
        Ok(_) => Ok(()),
        // lost a race with the garbage collector
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn is_owned_by(meta: &ObjectMeta, owner_uid: &str) -> bool {
    meta.owner_references
        .iter()
        .flatten()
        .any(|owner| owner.uid == owner_uid)
}

/// The admission rules can't see an existing claim's access modes; enforce the
/// RWO-multi-replica exclusion here instead.
async fn check_existing_claim(cr: &ModelExpressServer, ns: &str, ctx: &Ctx) -> Result<(), Error> {
    let Some(CacheStorage::ExistingClaim(existing)) = cr
        .spec
        .cache
        .as_ref()
        .and_then(|cache| cache.storage.as_ref())
    else {
        return Ok(());
    };
    if cr.spec.replicas <= 1 {
        return Ok(());
    }

    let api = Api::<PersistentVolumeClaim>::namespaced(ctx.client.clone(), ns);
    let claim = api
        .get_opt(&existing.claim_name)
        .await?
        .ok_or_else(|| Error::MissingClaim {
            claim: existing.claim_name.clone(),
        })?;
    let modes = claim
        .spec
        .and_then(|spec| spec.access_modes)
        .unwrap_or_default();
    if !modes
        .iter()
        .any(|m| m == "ReadWriteMany" || m == "ReadOnlyMany")
    {
        return Err(Error::SingleNodeClaim {
            claim: existing.claim_name.clone(),
            modes,
            replicas: cr.spec.replicas,
        });
    }
    Ok(())
}

fn stamp(
    meta: &mut ObjectMeta,
    ns: &str,
    owner: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference>,
) {
    meta.namespace = Some(ns.to_string());
    meta.owner_references = owner.map(|o| vec![o]);
}

fn reason(err: &Error) -> &'static str {
    match err {
        Error::Kube(_) => "ApplyFailed",
        Error::MissingNamespace => "MissingNamespace",
        Error::MissingUid => "MissingUid",
        Error::MissingClaim { .. } => "CacheClaimMissing",
        Error::SingleNodeClaim { .. } => "CacheClaimSingleNode",
    }
}

pub const READY_CONDITION: &str = "Ready";

/// Per the API conventions lastTransitionTime records when the condition last
/// changed state, so it has to be carried forward while status/reason/message
/// hold. Restamping it every pass would make each applied status differ from
/// the stored one, and since the controller watches ModelExpressServer, every
/// status write would schedule the next reconcile: an unbounded loop that the
/// requeue interval never gates.
fn ready_condition(
    cr: &ModelExpressServer,
    status: &str,
    reason: &str,
    message: &str,
) -> Condition {
    let previous = cr
        .status
        .as_ref()
        .and_then(|s| s.conditions.iter().find(|c| c.type_ == READY_CONDITION));
    let last_transition_time = match previous {
        Some(prev) if prev.status == status && prev.reason == reason && prev.message == message => {
            prev.last_transition_time.clone()
        }
        _ => k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(chrono::Utc::now()),
    };

    Condition {
        type_: READY_CONDITION.to_string(),
        status: status.to_string(),
        reason: reason.to_string(),
        message: message.to_string(),
        observed_generation: cr.metadata.generation,
        last_transition_time,
    }
}

#[tracing::instrument(skip_all)]
async fn write_status(
    ns: &str,
    name: &str,
    ctx: &Ctx,
    condition: Condition,
    endpoint: Option<String>,
    observed_generation: Option<i64>,
) -> Result<(), Error> {
    let status = ModelExpressServerStatus {
        observed_generation,
        conditions: vec![condition],
        endpoint,
    };
    let api = Api::<ModelExpressServer>::namespaced(ctx.client.clone(), ns);
    let patch = serde_json::json!({
        "apiVersion": "modelexpress.wseaton.com/v1alpha1",
        "kind": "ModelExpressServer",
        "status": status,
    });
    api.patch_status(
        name,
        &PatchParams::apply(FIELD_MANAGER).force(),
        &Patch::Apply(&patch),
    )
    .await?;
    Ok(())
}

fn error_policy(_cr: Arc<ModelExpressServer>, err: &Error, _ctx: Arc<Ctx>) -> Action {
    match err {
        // user-fixable config problems: no point hammering the apiserver
        Error::MissingClaim { .. } | Error::SingleNodeClaim { .. } => {
            Action::requeue(Duration::from_secs(120))
        }
        _ => Action::requeue(Duration::from_secs(15)),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::crd::{MetadataBackend, ModelExpressServerSpec, RedisBackend};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{OwnerReference, Time};

    fn server(status: Option<ModelExpressServerStatus>) -> ModelExpressServer {
        let mut cr = ModelExpressServer::new(
            "mx",
            ModelExpressServerSpec {
                image: "img".into(),
                replicas: 1,
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
            },
        );
        cr.metadata.generation = Some(1);
        cr.status = status;
        cr
    }

    fn stamped(at: chrono::DateTime<chrono::Utc>, status: &str, reason: &str) -> Condition {
        Condition {
            type_: READY_CONDITION.to_string(),
            status: status.to_string(),
            reason: reason.to_string(),
            message: "resources applied".to_string(),
            observed_generation: Some(1),
            last_transition_time: Time(at),
        }
    }

    fn with_ready(condition: Condition) -> Option<ModelExpressServerStatus> {
        Some(ModelExpressServerStatus {
            observed_generation: Some(1),
            conditions: vec![condition],
            endpoint: None,
        })
    }

    #[test]
    fn ownership_gates_the_cleanup_deletes() {
        const UID: &str = "11111111-2222-3333-4444-555555555555";
        const OTHER: &str = "99999999-8888-7777-6666-555555555555";

        fn owned_by(uids: &[&str]) -> ObjectMeta {
            ObjectMeta {
                owner_references: Some(
                    uids.iter()
                        .map(|uid| OwnerReference {
                            uid: (*uid).to_string(),
                            ..OwnerReference::default()
                        })
                        .collect(),
                ),
                ..ObjectMeta::default()
            }
        }

        assert!(is_owned_by(&owned_by(&[UID]), UID));
        assert!(
            is_owned_by(&owned_by(&[OTHER, UID]), UID),
            "one of several owners still counts"
        );
        assert!(
            !is_owned_by(&owned_by(&[OTHER]), UID),
            "owned by a different CR"
        );
        // a user's own NetworkPolicy that merely shares the CR's name
        assert!(
            !is_owned_by(&ObjectMeta::default(), UID),
            "an unowned object must never be deleted"
        );
    }

    #[test]
    fn unchanged_condition_keeps_its_transition_time() {
        let earlier = chrono::Utc::now() - chrono::Duration::hours(3);
        let cr = server(with_ready(stamped(earlier, "True", "Applied")));
        let next = ready_condition(&cr, "True", "Applied", "resources applied");
        assert_eq!(
            next.last_transition_time,
            Time(earlier),
            "restamping an unchanged condition re-triggers our own watch"
        );
    }

    #[test]
    fn flipping_status_restamps_transition_time() {
        let earlier = chrono::Utc::now() - chrono::Duration::hours(3);
        let cr = server(with_ready(stamped(earlier, "True", "Applied")));
        let next = ready_condition(&cr, "False", "ApplyFailed", "kube api: boom");
        assert!(next.last_transition_time.0 > earlier);
    }

    #[test]
    fn same_status_but_new_reason_restamps() {
        let earlier = chrono::Utc::now() - chrono::Duration::hours(3);
        let cr = server(with_ready(stamped(earlier, "False", "CacheClaimMissing")));
        let next = ready_condition(&cr, "False", "ApplyFailed", "resources applied");
        assert!(next.last_transition_time.0 > earlier);
    }

    #[test]
    fn same_status_and_reason_but_new_message_restamps() {
        let earlier = chrono::Utc::now() - chrono::Duration::hours(3);
        let cr = server(with_ready(stamped(earlier, "False", "ApplyFailed")));
        let next = ready_condition(&cr, "False", "ApplyFailed", "kube api: different");
        assert!(next.last_transition_time.0 > earlier);
    }

    #[test]
    fn first_reconcile_stamps_a_fresh_time() {
        let before = chrono::Utc::now();
        let cr = server(None);
        let next = ready_condition(&cr, "True", "Applied", "resources applied");
        assert!(next.last_transition_time.0 >= before);
        assert_eq!(next.type_, READY_CONDITION);
        assert_eq!(next.observed_generation, Some(1));
    }

    #[test]
    fn a_foreign_condition_type_does_not_supply_the_timestamp() {
        let earlier = chrono::Utc::now() - chrono::Duration::hours(3);
        let mut other = stamped(earlier, "True", "Applied");
        other.type_ = "Degraded".to_string();
        let before = chrono::Utc::now();
        let cr = server(with_ready(other));
        let next = ready_condition(&cr, "True", "Applied", "resources applied");
        assert!(next.last_transition_time.0 >= before);
    }
}
