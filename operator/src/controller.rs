// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reconcile loop: ModelExpressServer -> Deployment + Service + PVC.

use crate::crd::{CacheStorage, ModelExpressServer, ModelExpressServerStatus};
use crate::deployment::{DesiredState, render};
use crate::labels;
use crate::rbac::{ServerRbac, render_rbac, role_name, service_account_name};
use futures::StreamExt;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Service, ServiceAccount};
use k8s_openapi::api::networking::v1::NetworkPolicy;
use k8s_openapi::api::rbac::v1::{Role, RoleBinding};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::{Api, ObjectMeta, PartialObjectMeta, Patch, PatchParams};
use kube::runtime::WatchStreamExt;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher;
use kube::runtime::watcher::metadata_watcher;
use kube::{Client, Resource, ResourceExt};
use std::sync::Arc;
use std::time::Duration;

pub const FIELD_MANAGER: &str = "modelexpress-operator";

const WATCH_TIMEOUT_SECS: u32 = 290;

const READY_REQUEUE: Duration = Duration::from_secs(300);
const ROLLOUT_REQUEUE: Duration = Duration::from_secs(30);

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

    // Unfiltered these cache every object of their kind in the cluster, and
    // ServiceAccounts and RoleBindings run to thousands in a real one.
    let owned = watcher::Config::default()
        .labels(labels::MANAGED_BY_SELECTOR)
        .timeout(WATCH_TIMEOUT_SECS);

    Controller::new(
        servers,
        watcher::Config::default().timeout(WATCH_TIMEOUT_SECS),
    )
    .owns_stream(owned_meta(deployments, owned.clone()))
    .owns_stream(owned_meta(services, owned.clone()))
    .owns_stream(owned_meta(pvcs, owned.clone()))
    .owns_stream(owned_meta(netpols, owned.clone()))
    .owns_stream(owned_meta(sas, owned.clone()))
    .owns_stream(owned_meta(roles, owned.clone()))
    .owns_stream(owned_meta(bindings, owned))
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

/// Owned objects are only read for their ownerReferences, so the spec and
/// status a full watch would cache are dead weight.
fn owned_meta<K>(
    api: Api<K>,
    config: watcher::Config,
) -> impl futures::Stream<Item = Result<PartialObjectMeta<K>, watcher::Error>> + Send
where
    K: Resource<DynamicType = ()>
        + Clone
        + serde::de::DeserializeOwned
        + std::fmt::Debug
        + Send
        + 'static,
{
    metadata_watcher(api, config).touched_objects()
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

    let result = apply(&cr, &ns, &name, &ctx)
        .await
        .map(|deployment| rollout_state(&deployment));
    let (condition, endpoint, observed_generation) = match &result {
        Ok(rollout) => (
            ready_condition(&cr, rollout.status(), rollout.reason(), rollout.message()),
            Some(endpoint(&name, &ns, cr.spec.port)),
            cr.metadata.generation,
        ),
        Err(err) => (
            ready_condition(&cr, "False", reason(err), &err.to_string()),
            None,
            // clients compare this against metadata.generation to decide
            // whether the current spec has been acted on
            cr.status.as_ref().and_then(|s| s.observed_generation),
        ),
    };
    write_status(&ns, &name, &ctx, condition, endpoint, observed_generation).await?;

    result.map(|rollout| Action::requeue(rollout.requeue()))
}

enum Rollout {
    Available { message: String },
    NotReady { reason: String, message: String },
}

impl Rollout {
    fn status(&self) -> &'static str {
        match self {
            Rollout::Available { .. } => "True",
            Rollout::NotReady { .. } => "False",
        }
    }

    fn reason(&self) -> &str {
        match self {
            Rollout::Available { .. } => AVAILABLE_REASON,
            Rollout::NotReady { reason, .. } => reason,
        }
    }

    fn message(&self) -> &str {
        match self {
            Rollout::Available { message } | Rollout::NotReady { message, .. } => message,
        }
    }

    fn requeue(&self) -> Duration {
        match self {
            Rollout::Available { .. } => READY_REQUEUE,
            Rollout::NotReady { .. } => ROLLOUT_REQUEUE,
        }
    }
}

const AVAILABLE_REASON: &str = "Available";
const PROGRESSING_REASON: &str = "RolloutInProgress";

fn rollout_state(deployment: &Deployment) -> Rollout {
    let status = deployment.status.as_ref();
    let field = |get: fn(&k8s_openapi::api::apps::v1::DeploymentStatus) -> Option<i32>| {
        status.and_then(get).unwrap_or_default()
    };

    let observed = status
        .and_then(|s| s.observed_generation)
        .unwrap_or_default();
    if observed < deployment.metadata.generation.unwrap_or_default() {
        return Rollout::NotReady {
            reason: PROGRESSING_REASON.to_string(),
            message: "waiting for the deployment controller to observe the update".to_string(),
        };
    }

    let stalled = status
        .and_then(|s| s.conditions.as_deref())
        .unwrap_or_default()
        .iter()
        .find(|c| c.type_ == "Progressing" && c.status == "False");
    if let Some(stalled) = stalled {
        return Rollout::NotReady {
            reason: stalled
                .reason
                .clone()
                .filter(|reason| !reason.is_empty())
                .unwrap_or_else(|| PROGRESSING_REASON.to_string()),
            message: stalled
                .message
                .clone()
                .unwrap_or_else(|| "rollout stalled".to_string()),
        };
    }

    let desired = deployment
        .spec
        .as_ref()
        .and_then(|spec| spec.replicas)
        .unwrap_or(1);
    let updated = field(|s| s.updated_replicas);
    let total = field(|s| s.replicas);
    let available = field(|s| s.available_replicas);

    let progress = if updated < desired {
        Some(format!("{updated}/{desired} replicas updated"))
    } else if total > updated {
        Some(format!(
            "{} old replicas pending termination",
            total.saturating_sub(updated)
        ))
    } else if available < updated {
        Some(format!("{available}/{updated} updated replicas available"))
    } else {
        None
    };

    match progress {
        Some(message) => Rollout::NotReady {
            reason: PROGRESSING_REASON.to_string(),
            message,
        },
        None => Rollout::Available {
            message: format!("{available}/{desired} replicas available"),
        },
    }
}

/// What clients set MODEL_EXPRESS_ENDPOINT to. The Service is always named
/// after the CR.
pub fn endpoint(name: &str, ns: &str, port: i32) -> String {
    format!("grpc://{name}.{ns}.svc.cluster.local:{port}")
}

#[tracing::instrument(skip_all)]
async fn apply(
    cr: &ModelExpressServer,
    ns: &str,
    name: &str,
    ctx: &Ctx,
) -> Result<Deployment, Error> {
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
    let applied = api.patch(name, &params, &Patch::Apply(&deployment)).await?;

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
    Ok(applied)
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

/// Cleanup targets names derived from the CR, not names the operator can prove
/// it created. `spec.networkPolicy` is unset by default, so without this check
/// the netpol branch deletes a user's unrelated same-named policy on every
/// reconcile.
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

/// Carries lastTransitionTime forward while the condition holds, per the API
/// conventions. Restamping it makes every status write differ from the stored
/// object, and since the controller watches its own CR that write schedules
/// the next reconcile: an unbounded loop the requeue never gates.
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
    // from the Resource impl so the group is spelled once, in the derive
    let patch = serde_json::json!({
        "apiVersion": ModelExpressServer::api_version(&()),
        "kind": ModelExpressServer::kind(&()),
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
    use k8s_openapi::api::apps::v1::{DeploymentCondition, DeploymentSpec, DeploymentStatus};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{OwnerReference, Time};

    fn server(status: Option<ModelExpressServerStatus>) -> ModelExpressServer {
        let mut cr = ModelExpressServer::new(
            "mx",
            ModelExpressServerSpec {
                image: "img".into(),
                replicas: 1,
                metadata_backend: MetadataBackend::Redis(RedisBackend {
                    url: Some("redis://mx-redis:6379".into()),
                    url_secret: None,
                }),
                port: 8001,
                log: None,
                cache: None,
                security: None,
                reaper: None,
                credentials: None,
                pod_metadata: None,
                resources: None,
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

    fn deployment(generation: i64, status: Option<DeploymentStatus>) -> Deployment {
        Deployment {
            metadata: ObjectMeta {
                name: Some("mx".to_string()),
                generation: Some(generation),
                ..ObjectMeta::default()
            },
            spec: Some(DeploymentSpec {
                replicas: Some(3),
                ..DeploymentSpec::default()
            }),
            status,
        }
    }

    fn dep_condition(
        type_: &str,
        status: &str,
        reason: &str,
        message: &str,
    ) -> DeploymentCondition {
        DeploymentCondition {
            type_: type_.to_string(),
            status: status.to_string(),
            reason: Some(reason.to_string()),
            message: Some(message.to_string()),
            ..DeploymentCondition::default()
        }
    }

    fn progressing(status: &str) -> DeploymentCondition {
        dep_condition("Progressing", status, "ReplicaSetUpdated", "rolling out")
    }

    #[test]
    fn a_generation_the_deployment_controller_has_not_seen_is_not_ready() {
        let state = rollout_state(&deployment(
            2,
            Some(DeploymentStatus {
                observed_generation: Some(1),
                replicas: Some(3),
                updated_replicas: Some(3),
                available_replicas: Some(3),
                ..DeploymentStatus::default()
            }),
        ));
        assert_eq!(
            state.status(),
            "False",
            "the previous spec's status must not report the new one ready"
        );
        assert_eq!(state.reason(), PROGRESSING_REASON);
    }

    #[test]
    fn a_freshly_created_deployment_is_not_ready() {
        let state = rollout_state(&deployment(1, None));
        assert_eq!(state.status(), "False");
        assert_eq!(state.requeue(), ROLLOUT_REQUEUE);
    }

    #[test]
    fn a_fully_rolled_out_deployment_is_ready() {
        let state = rollout_state(&deployment(
            1,
            Some(DeploymentStatus {
                observed_generation: Some(1),
                replicas: Some(3),
                updated_replicas: Some(3),
                ready_replicas: Some(3),
                available_replicas: Some(3),
                conditions: Some(vec![dep_condition(
                    "Progressing",
                    "True",
                    "NewReplicaSetAvailable",
                    "replica set is available",
                )]),
                ..DeploymentStatus::default()
            }),
        ));
        assert_eq!(state.status(), "True");
        assert_eq!(state.reason(), AVAILABLE_REASON);
        assert_eq!(state.message(), "3/3 replicas available");
        assert_eq!(state.requeue(), READY_REQUEUE);
    }

    #[test]
    fn a_new_image_is_not_ready_while_the_old_pods_still_serve() {
        let state = rollout_state(&deployment(
            2,
            Some(DeploymentStatus {
                observed_generation: Some(2),
                replicas: Some(4),
                updated_replicas: Some(1),
                ready_replicas: Some(3),
                available_replicas: Some(3),
                conditions: Some(vec![
                    dep_condition("Available", "True", "MinimumReplicasAvailable", "available"),
                    progressing("True"),
                ]),
                ..DeploymentStatus::default()
            }),
        ));
        assert_eq!(state.status(), "False");
        assert_eq!(state.message(), "1/3 replicas updated");
        assert_eq!(
            state.requeue(),
            ROLLOUT_REQUEUE,
            "an unfinished rollout should be rechecked sooner than a settled one"
        );
    }

    #[test]
    fn old_replicas_still_terminating_are_not_ready() {
        let state = rollout_state(&deployment(
            1,
            Some(DeploymentStatus {
                observed_generation: Some(1),
                replicas: Some(4),
                updated_replicas: Some(3),
                available_replicas: Some(3),
                conditions: Some(vec![progressing("True")]),
                ..DeploymentStatus::default()
            }),
        ));
        assert_eq!(state.status(), "False");
        assert_eq!(state.message(), "1 old replicas pending termination");
    }

    #[test]
    fn updated_replicas_not_yet_serving_are_not_ready() {
        let state = rollout_state(&deployment(
            1,
            Some(DeploymentStatus {
                observed_generation: Some(1),
                replicas: Some(3),
                updated_replicas: Some(3),
                available_replicas: Some(2),
                conditions: Some(vec![progressing("True")]),
                ..DeploymentStatus::default()
            }),
        ));
        assert_eq!(state.status(), "False");
        assert_eq!(state.message(), "2/3 updated replicas available");
    }

    #[test]
    fn a_stalled_rollout_reports_the_deployments_own_reason() {
        let state = rollout_state(&deployment(
            1,
            Some(DeploymentStatus {
                observed_generation: Some(1),
                replicas: Some(3),
                conditions: Some(vec![
                    dep_condition(
                        "Available",
                        "False",
                        "MinimumReplicasUnavailable",
                        "unavailable",
                    ),
                    dep_condition(
                        "Progressing",
                        "False",
                        "ProgressDeadlineExceeded",
                        r#"ReplicaSet "mx-7c9f" has timed out progressing."#,
                    ),
                ]),
                ..DeploymentStatus::default()
            }),
        ));
        assert_eq!(state.status(), "False");
        assert_eq!(
            state.reason(),
            "ProgressDeadlineExceeded",
            "an unpullable image must not read as a rollout still in progress"
        );
        assert!(state.message().contains("timed out"));
    }

    #[test]
    fn a_stalled_rollout_without_a_reason_falls_back() {
        let mut stalled = dep_condition("Progressing", "False", "", "");
        stalled.reason = None;
        stalled.message = None;
        let state = rollout_state(&deployment(
            1,
            Some(DeploymentStatus {
                observed_generation: Some(1),
                conditions: Some(vec![stalled]),
                ..DeploymentStatus::default()
            }),
        ));
        assert_eq!(state.reason(), PROGRESSING_REASON, "reason is never empty");
        assert!(!state.message().is_empty());
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
