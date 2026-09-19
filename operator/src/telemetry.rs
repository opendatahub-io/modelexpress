// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Prometheus metrics and health endpoints for the operator process.
//!
//! Two listeners: health probes stay plaintext so kubelet can always reach
//! them, and `/metrics` is served either plaintext or, when a certificate
//! directory is configured, over TLS with bearer-token authn/authz.
//!
//! Server-workload metrics are deliberately absent: modelexpress-server has
//! no /metrics endpoint today, so there is nothing to scrape or annotate on
//! its pods.

use crate::metrics_auth::{MetricsAuth, require_metrics_access};
use axum::{Router, middleware, routing::get};
use metrics_exporter_prometheus::{BuildError, PrometheusBuilder, PrometheusHandle};
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

pub const HEALTH_PORT: i32 = 8081;
pub const HEALTH_PORT_NAME: &str = "http-health";
pub const METRICS_PORT: i32 = 8080;
pub const METRICS_PORT_NAME: &str = "http-metrics";
pub const METRICS_TLS_PORT: i32 = 8443;
pub const METRICS_TLS_PORT_NAME: &str = "https-metrics";
/// Directory holding `tls.crt` and `tls.key`; setting it moves `/metrics`
/// to [`METRICS_TLS_PORT`] over TLS with bearer-token auth.
pub const METRICS_TLS_DIR_ENV: &str = "MXOP_METRICS_TLS_DIR";
pub const LOG_FORMAT_ENV: &str = "MXOP_LOG_FORMAT";

#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    #[error("installing metrics recorder: {0}")]
    Recorder(#[from] BuildError),
    #[error("binding {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        source: std::io::Error,
    },
    #[error("http server: {0}")]
    Serve(std::io::Error),
    #[error("initializing tracing subscriber: {0}")]
    TracingInit(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
}

impl LogFormat {
    pub fn from_env() -> Self {
        Self::parse(std::env::var(LOG_FORMAT_ENV).ok().as_deref())
    }

    fn parse(value: Option<&str>) -> Self {
        match value {
            Some("pretty") => LogFormat::Pretty,
            _ => LogFormat::Json,
        }
    }
}

pub fn init_tracing(format: LogFormat) -> Result<(), TelemetryError> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    let result = match format {
        LogFormat::Json => builder
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(true)
            .try_init(),
        LogFormat::Pretty => builder.try_init(),
    };
    result.map_err(|e| TelemetryError::TracingInit(e.to_string()))
}

pub fn install_recorder() -> Result<PrometheusHandle, TelemetryError> {
    Ok(PrometheusBuilder::new().install_recorder()?)
}

pub fn health_router() -> Router {
    Router::new()
        .route("/healthz", get(async || "ok"))
        .route("/readyz", get(async || "ok"))
}

/// `/metrics`, gated by `auth` when given.
pub fn metrics_router(handle: PrometheusHandle, auth: Option<MetricsAuth>) -> Router {
    let router = Router::new().route("/metrics", get(move || async move { handle.render() }));
    match auth {
        Some(auth) => {
            router.route_layer(middleware::from_fn_with_state(auth, require_metrics_access))
        }
        None => router,
    }
}

pub async fn serve_plain(addr: SocketAddr, router: Router) -> Result<(), TelemetryError> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|source| TelemetryError::Bind { addr, source })?;
    axum::serve(listener, router)
        .await
        .map_err(TelemetryError::Serve)
}

#[cfg(feature = "tls-openssl")]
pub async fn serve_tls(
    addr: SocketAddr,
    router: Router,
    config: axum_server::tls_openssl::OpenSSLConfig,
) -> Result<(), TelemetryError> {
    axum_server::bind_openssl(addr, config)
        .serve(router.into_make_service())
        .await
        .map_err(TelemetryError::Serve)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    async fn serve_router(app: Router) -> SocketAddr {
        let server = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = server.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(server, app).await.expect("serve");
        });
        addr
    }

    async fn get(addr: SocketAddr, path: &str) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(format!("GET {path} HTTP/1.0\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .expect("write");
        let mut raw = String::new();
        stream.read_to_string(&mut raw).await.expect("read");
        let status = raw
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .expect("status");
        let body = raw.split("\r\n\r\n").nth(1).unwrap_or_default().to_string();
        (status, body)
    }

    #[tokio::test]
    async fn health_endpoints_respond() {
        let addr = serve_router(health_router()).await;
        assert_eq!(get(addr, "/healthz").await.0, 200);
        assert_eq!(get(addr, "/readyz").await.0, 200);
        assert_eq!(
            get(addr, "/metrics").await.0,
            404,
            "metrics live on their own listener"
        );
    }

    #[tokio::test]
    async fn metrics_endpoint_renders_recorded_values() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            metrics::counter!("mxop_reconcile_total", "outcome" => "ok").increment(3);
        });
        let addr = serve_router(metrics_router(handle, None)).await;
        let (status, body) = get(addr, "/metrics").await;
        assert_eq!(status, 200);
        assert!(
            body.contains("mxop_reconcile_total{outcome=\"ok\"} 3"),
            "{body}"
        );
        assert_eq!(
            get(addr, "/healthz").await.0,
            404,
            "probes live on their own listener"
        );
    }

    /// The TLS listener end to end: a scrape with no token is refused, one
    /// with a token the fake apiserver approves gets the metrics.
    #[cfg(feature = "tls-openssl")]
    #[tokio::test]
    async fn tls_metrics_listener_requires_a_bearer_token() {
        use crate::metrics_auth::MetricsAuth;
        use crate::metrics_tls::{acceptor, tests::self_signed};
        use crate::tls::TlsSettings;
        use axum_server::tls_openssl::OpenSSLConfig;
        use k8s_openapi::api::authentication::v1::{TokenReview, TokenReviewStatus, UserInfo};
        use k8s_openapi::api::authorization::v1::{SubjectAccessReview, SubjectAccessReviewStatus};
        use kube::client::Body as KubeBody;
        use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
        use std::io::{Read, Write};
        use std::sync::Arc;

        let dir = tempfile::TempDir::new().expect("tempdir");
        let paths = self_signed(dir.path());
        let config = OpenSSLConfig::from_acceptor(Arc::new(
            acceptor(&paths, &TlsSettings::default()).expect("acceptor"),
        ));

        let service = tower::service_fn(|request: http::Request<KubeBody>| async move {
            let body = if request.uri().path().contains("tokenreviews") {
                serde_json::to_vec(&TokenReview {
                    status: Some(TokenReviewStatus {
                        authenticated: Some(true),
                        user: Some(UserInfo {
                            username: Some("system:serviceaccount:monitoring:prometheus".into()),
                            ..UserInfo::default()
                        }),
                        ..TokenReviewStatus::default()
                    }),
                    ..TokenReview::default()
                })
            } else {
                serde_json::to_vec(&SubjectAccessReview {
                    status: Some(SubjectAccessReviewStatus {
                        allowed: true,
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
        });
        let auth = MetricsAuth::new(kube::Client::new(service, "default"));

        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            metrics::counter!("mxop_reconcile_total", "outcome" => "ok").increment(1);
        });
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = probe.local_addr().expect("addr");
        drop(probe);
        tokio::spawn(serve_tls(addr, metrics_router(handle, Some(auth)), config));

        let get = move |authorization: Option<&str>| {
            let mut builder = SslConnector::builder(SslMethod::tls_client()).expect("connector");
            builder.set_verify(SslVerifyMode::NONE);
            let connector = builder.build();
            let tcp = loop {
                match std::net::TcpStream::connect(addr) {
                    Ok(tcp) => break tcp,
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
                }
            };
            let mut stream = connector.connect("localhost", tcp).expect("tls");
            let header = authorization
                .map(|a| format!("Authorization: {a}\r\n"))
                .unwrap_or_default();
            stream
                .write_all(format!("GET /metrics HTTP/1.0\r\nHost: x\r\n{header}\r\n").as_bytes())
                .expect("write");
            let mut raw = String::new();
            let _ = stream.read_to_string(&mut raw);
            raw
        };

        let anonymous = tokio::task::spawn_blocking(move || get(None))
            .await
            .expect("join");
        assert!(anonymous.starts_with("HTTP/1.0 401"), "{anonymous}");
        assert!(
            anonymous
                .to_ascii_lowercase()
                .contains("www-authenticate: bearer"),
            "{anonymous}"
        );

        let scraped = tokio::task::spawn_blocking(move || get(Some("Bearer tok")))
            .await
            .expect("join");
        assert!(scraped.starts_with("HTTP/1.0 200"), "{scraped}");
        assert!(
            scraped.contains("mxop_reconcile_total{outcome=\"ok\"} 1"),
            "{scraped}"
        );
    }

    #[test]
    fn log_format_defaults_to_json() {
        assert_eq!(LogFormat::parse(None), LogFormat::Json);
        assert_eq!(LogFormat::parse(Some("pretty")), LogFormat::Pretty);
        assert_eq!(LogFormat::parse(Some("garbage")), LogFormat::Json);
    }
}
