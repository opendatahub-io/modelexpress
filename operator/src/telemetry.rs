// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Prometheus metrics and health endpoints for the operator process.
//!
//! Server-workload metrics are deliberately absent: modelexpress-server has
//! no /metrics endpoint today, so there is nothing to scrape or annotate on
//! its pods. This module only covers the controller itself.

use axum::{Router, routing::get};
use metrics_exporter_prometheus::{BuildError, PrometheusBuilder, PrometheusHandle};
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

pub const DEFAULT_ADDR: &str = "0.0.0.0:8080";
pub const PORT: i32 = 8080;
pub const PORT_NAME: &str = "http-metrics";
/// Set to `pretty` for human-readable local-dev output; anything else (or
/// unset) means JSON.
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

/// Global subscriber: env-filtered, JSON by default (MXOP_LOG_FORMAT=pretty
/// for local dev). Init also installs the log-crate bridge via
/// tracing-subscriber's default tracing-log feature, so log:: records from
/// dependencies land in the same stream.
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

/// Call once at startup: recordings before the global recorder is installed
/// are silently dropped.
pub fn install_recorder() -> Result<PrometheusHandle, TelemetryError> {
    Ok(PrometheusBuilder::new().install_recorder()?)
}

pub fn router(handle: PrometheusHandle) -> Router {
    Router::new()
        .route("/metrics", get(move || async move { handle.render() }))
        .route("/healthz", get(async || "ok"))
        .route("/readyz", get(async || "ok"))
}

pub async fn serve(addr: SocketAddr, handle: PrometheusHandle) -> Result<(), TelemetryError> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|source| TelemetryError::Bind { addr, source })?;
    axum::serve(listener, router(handle))
        .await
        .map_err(TelemetryError::Serve)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    async fn get_ok(path: &str) -> (axum::http::StatusCode, String) {
        // recorder is process-global and tests share the process: build an
        // isolated one instead of install_recorder()
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let app = router(handle);
        let server = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = server.local_addr().expect("addr");
        tokio::spawn(async move {
            axum::serve(server, app).await.expect("serve");
        });
        let body = reqwest_lite(addr, path).await;
        (axum::http::StatusCode::OK, body)
    }

    // avoid pulling reqwest into dev-deps for two GETs
    async fn reqwest_lite(addr: std::net::SocketAddr, path: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(format!("GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n").as_bytes())
            .await
            .expect("write");
        let mut buf = String::new();
        stream.read_to_string(&mut buf).await.expect("read");
        assert!(buf.starts_with("HTTP/1.0 200"), "unexpected: {buf}");
        buf.split("\r\n\r\n").nth(1).unwrap_or_default().to_string()
    }

    #[test]
    fn log_format_defaults_to_json() {
        assert_eq!(LogFormat::parse(None), LogFormat::Json);
        assert_eq!(LogFormat::parse(Some("json")), LogFormat::Json);
        assert_eq!(LogFormat::parse(Some("garbage")), LogFormat::Json);
        assert_eq!(LogFormat::parse(Some("pretty")), LogFormat::Pretty);
    }

    #[tokio::test]
    async fn health_endpoints_respond() {
        let (_, healthz) = get_ok("/healthz").await;
        assert_eq!(healthz, "ok");
        let (_, readyz) = get_ok("/readyz").await;
        assert_eq!(readyz, "ok");
    }

    #[tokio::test]
    async fn metrics_endpoint_renders_recorded_values() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            metrics::counter!("mxop_reconcile_total", "outcome" => "ok").increment(3);
        });
        let rendered = handle.render();
        assert!(
            rendered.contains("mxop_reconcile_total{outcome=\"ok\"} 3"),
            "missing counter in: {rendered}"
        );
    }
}
