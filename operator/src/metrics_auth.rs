// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bearer-token authn/authz for the metrics endpoint: a Kubernetes
//! `TokenReview` to identify the caller, then a `SubjectAccessReview` for
//! `get` on the `/metrics` non-resource URL. The same gate
//! controller-runtime's `WithAuthenticationAndAuthorization` filter applies.

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use k8s_openapi::api::authentication::v1::{TokenReview, TokenReviewSpec};
use k8s_openapi::api::authorization::v1::{
    NonResourceAttributes, SubjectAccessReview, SubjectAccessReviewSpec,
};
use kube::Client;
use kube::api::{Api, PostParams};
use moka::future::Cache;
use std::time::Duration;

/// How long a decision for one token is reused before the apiserver is
/// asked again. Prometheus scrapes every 30s, so this keeps the review
/// traffic at a few requests a minute per scraper.
pub const DECISION_TTL: Duration = Duration::from_secs(60);

/// Cached decisions kept at once. Entries expire with the TTL, but a caller
/// sending a fresh invalid token every request would otherwise grow the map
/// until they do; real scrapers need a handful.
pub const MAX_DECISIONS: u64 = 1024;

/// SHA-256 of the bearer token, the cache key, so tokens are not held in
/// memory.
fn token_key(token: &str) -> [u8; 32] {
    crate::digest::sha256(token.as_bytes())
}

pub const METRICS_PATH: &str = "/metrics";

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing or malformed Authorization header")]
    NoToken,
    #[error("token review: {0}")]
    Review(#[from] kube::Error),
    #[error("token not authenticated")]
    Unauthenticated,
    #[error("caller may not get {METRICS_PATH}")]
    Forbidden,
}

impl AuthError {
    fn status(&self) -> StatusCode {
        match self {
            Self::NoToken | Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Review(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// Cached outcome for one token, keyed by the token's SHA-256.

#[derive(Clone)]
pub struct MetricsAuth {
    client: Client,
    cache: Cache<[u8; 32], Result<(), Denied>>,
}

/// A cached negative decision; transport errors are never cached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Denied {
    Unauthenticated,
    Forbidden,
}

impl MetricsAuth {
    #[must_use]
    pub fn new(client: Client) -> Self {
        Self::with_ttl(client, DECISION_TTL)
    }

    #[must_use]
    pub fn with_ttl(client: Client, ttl: Duration) -> Self {
        Self {
            client,
            cache: Cache::builder()
                .max_capacity(MAX_DECISIONS)
                .time_to_live(ttl)
                .build(),
        }
    }

    /// Decide for a bearer token, consulting the cache first.
    pub async fn authorize(&self, token: &str) -> Result<(), AuthError> {
        let key = token_key(token);
        if let Some(decision) = self.cache.get(&key).await {
            return decision.map_err(|denied| match denied {
                Denied::Unauthenticated => AuthError::Unauthenticated,
                Denied::Forbidden => AuthError::Forbidden,
            });
        }
        let result = self.review(token).await;
        let cacheable = match &result {
            Ok(()) => Some(Ok(())),
            Err(AuthError::Unauthenticated) => Some(Err(Denied::Unauthenticated)),
            Err(AuthError::Forbidden) => Some(Err(Denied::Forbidden)),
            Err(_) => None,
        };
        if let Some(decision) = cacheable {
            self.cache.insert(key, decision).await;
        }
        result
    }

    async fn review(&self, token: &str) -> Result<(), AuthError> {
        let reviews: Api<TokenReview> = Api::all(self.client.clone());
        let review = TokenReview {
            spec: TokenReviewSpec {
                token: Some(token.to_string()),
                audiences: None,
            },
            ..TokenReview::default()
        };
        let status = reviews
            .create(&PostParams::default(), &review)
            .await?
            .status
            .ok_or(AuthError::Unauthenticated)?;
        if !status.authenticated.unwrap_or(false) {
            return Err(AuthError::Unauthenticated);
        }
        let user = status.user.ok_or(AuthError::Unauthenticated)?;

        let access: Api<SubjectAccessReview> = Api::all(self.client.clone());
        let sar = SubjectAccessReview {
            spec: SubjectAccessReviewSpec {
                user: user.username,
                groups: user.groups,
                uid: user.uid,
                non_resource_attributes: Some(NonResourceAttributes {
                    path: Some(METRICS_PATH.to_string()),
                    verb: Some("get".to_string()),
                }),
                ..SubjectAccessReviewSpec::default()
            },
            ..SubjectAccessReview::default()
        };
        let allowed = access
            .create(&PostParams::default(), &sar)
            .await?
            .status
            .is_some_and(|s| s.allowed);
        if allowed {
            Ok(())
        } else {
            Err(AuthError::Forbidden)
        }
    }
}

fn bearer(req: &Request<Body>) -> Option<&str> {
    req.headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

/// axum middleware: reject the request unless the bearer token passes.
pub async fn require_metrics_access(
    State(auth): State<MetricsAuth>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let outcome = match bearer(&req) {
        Some(token) => auth.authorize(token).await,
        None => Err(AuthError::NoToken),
    };
    match outcome {
        Ok(()) => next.run(req).await,
        Err(e) => {
            tracing::debug!("metrics request rejected: {e}");
            let mut response = Response::new(Body::from(e.to_string()));
            *response.status_mut() = e.status();
            if matches!(e, AuthError::NoToken | AuthError::Unauthenticated) {
                response.headers_mut().insert(
                    header::WWW_AUTHENTICATE,
                    "Bearer"
                        .parse()
                        .unwrap_or_else(|_| header::HeaderValue::from_static("Bearer")),
                );
            }
            response
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use crate::metrics_auth::*;
    use axum::Router;
    use axum::routing::get;
    use k8s_openapi::api::authentication::v1::{TokenReviewStatus, UserInfo};
    use k8s_openapi::api::authorization::v1::SubjectAccessReviewStatus;
    use kube::client::Body as KubeBody;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    /// A kube client whose apiserver answers TokenReview and SAR posts from
    /// canned responses, counting how many it served.
    fn fake_client(authenticated: bool, allowed: bool) -> (Client, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let service = tower::service_fn(move |request: http::Request<KubeBody>| {
            counter.fetch_add(1, Ordering::SeqCst);
            let path = request.uri().path().to_string();
            async move {
                let body = if path.contains("tokenreviews") {
                    serde_json::to_vec(&TokenReview {
                        status: Some(TokenReviewStatus {
                            authenticated: Some(authenticated),
                            user: Some(UserInfo {
                                username: Some(
                                    "system:serviceaccount:monitoring:prometheus".into(),
                                ),
                                groups: Some(vec!["system:serviceaccounts".into()]),
                                ..UserInfo::default()
                            }),
                            ..TokenReviewStatus::default()
                        }),
                        ..TokenReview::default()
                    })
                } else {
                    serde_json::to_vec(&SubjectAccessReview {
                        status: Some(SubjectAccessReviewStatus {
                            allowed,
                            ..SubjectAccessReviewStatus::default()
                        }),
                        ..SubjectAccessReview::default()
                    })
                }
                .expect("serialize");
                Ok::<_, tower::BoxError>(
                    http::Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(KubeBody::from(body))
                        .expect("response"),
                )
            }
        });
        (Client::new(service, "default"), calls)
    }

    fn app(auth: MetricsAuth) -> Router {
        Router::new()
            .route("/metrics", get(|| async { "mxop_up 1" }))
            .route_layer(axum::middleware::from_fn_with_state(
                auth,
                require_metrics_access,
            ))
    }

    async fn get_metrics(app: Router, token: Option<&str>) -> StatusCode {
        let mut req = Request::builder().uri("/metrics");
        if let Some(token) = token {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        app.oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn no_token_is_401_without_calling_the_apiserver() {
        let (client, calls) = fake_client(true, true);
        let status = get_metrics(app(MetricsAuth::new(client)), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn authenticated_and_allowed_passes() {
        let (client, calls) = fake_client(true, true);
        let status = get_metrics(app(MetricsAuth::new(client)), Some("tok")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 2, "one TokenReview, one SAR");
    }

    #[tokio::test]
    async fn unauthenticated_token_is_401() {
        let (client, calls) = fake_client(false, true);
        let status = get_metrics(app(MetricsAuth::new(client)), Some("bad")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "no SAR after a failed review"
        );
    }

    #[tokio::test]
    async fn authenticated_but_denied_is_403() {
        let (client, _) = fake_client(true, false);
        let status = get_metrics(app(MetricsAuth::new(client)), Some("tok")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn decisions_are_cached_per_token_until_the_ttl() {
        let (client, calls) = fake_client(true, true);
        let auth = MetricsAuth::with_ttl(client, Duration::from_millis(200));
        let app = app(auth);
        assert_eq!(get_metrics(app.clone(), Some("tok")).await, StatusCode::OK);
        assert_eq!(get_metrics(app.clone(), Some("tok")).await, StatusCode::OK);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "second scrape hits the cache"
        );
        assert_eq!(
            get_metrics(app.clone(), Some("other")).await,
            StatusCode::OK
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            4,
            "a different token is reviewed"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(get_metrics(app, Some("tok")).await, StatusCode::OK);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            6,
            "expired entry is reviewed again"
        );
    }

    #[tokio::test]
    async fn the_cache_stays_bounded_under_unique_tokens() {
        let (client, _calls) = fake_client(false, false);
        let auth = MetricsAuth::new(client);
        for i in 0..(MAX_DECISIONS + 200) {
            let _ = auth.authorize(&format!("token-{i}")).await;
        }
        auth.cache.run_pending_tasks().await;
        assert!(
            auth.cache.entry_count() <= MAX_DECISIONS,
            "cache holds {} entries, cap is {MAX_DECISIONS}",
            auth.cache.entry_count()
        );
    }

    #[tokio::test]
    async fn denials_are_cached_too() {
        let (client, calls) = fake_client(true, false);
        let app = app(MetricsAuth::new(client));
        assert_eq!(
            get_metrics(app.clone(), Some("tok")).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(get_metrics(app, Some("tok")).await, StatusCode::FORBIDDEN);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn apiserver_errors_are_503_and_not_cached() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let service = tower::service_fn(move |_: http::Request<KubeBody>| {
            counter.fetch_add(1, Ordering::SeqCst);
            async move {
                Ok::<_, tower::BoxError>(
                    http::Response::builder()
                        .status(500)
                        .body(KubeBody::from(Vec::new()))
                        .expect("response"),
                )
            }
        });
        let client = Client::new(service, "default");
        let app = app(MetricsAuth::new(client));
        assert_eq!(
            get_metrics(app.clone(), Some("tok")).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            get_metrics(app, Some("tok")).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "errors are retried, not cached"
        );
    }

    #[test]
    fn bearer_parsing() {
        let req = |value: &str| {
            Request::builder()
                .header("authorization", value)
                .body(Body::empty())
                .unwrap()
        };
        assert_eq!(bearer(&req("Bearer abc")), Some("abc"));
        assert_eq!(bearer(&req("Bearer   abc  ")), Some("abc"));
        assert_eq!(bearer(&req("Bearer ")), None);
        assert_eq!(bearer(&req("Basic abc")), None);
        assert_eq!(bearer(&Request::new(Body::empty())), None);
    }
}
