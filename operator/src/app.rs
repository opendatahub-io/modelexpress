// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The operator process: tracing, the health and metrics listeners, and the
//! controller, around a platform-supplied source of TLS defaults.

use crate::tls::{TlsDefaults, TlsDefaultsError};
use crate::{controller, telemetry};
use kube::Client;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("kubernetes client: {0}")]
    Client(#[from] kube::Error),
    #[error(transparent)]
    Telemetry(#[from] telemetry::TelemetryError),
    #[error("bad listen addr {addr}: {source}")]
    Addr {
        addr: String,
        source: std::net::AddrParseError,
    },
    #[error("TLS defaults: {0}")]
    TlsDefaults(TlsDefaultsError),
    #[cfg(feature = "tls-openssl")]
    #[error("metrics TLS: {0}")]
    MetricsTls(#[from] crate::metrics_tls::MetricsTlsError),
    #[cfg(not(feature = "tls-openssl"))]
    #[error(
        "{} is set but this build has no OpenSSL; metrics TLS needs --features openssl",
        telemetry::METRICS_TLS_DIR_ENV
    )]
    MetricsTlsUnsupported,
}

fn listen_addr(port: i32) -> Result<SocketAddr, RunError> {
    let addr = format!("0.0.0.0:{port}");
    addr.parse()
        .map_err(|source| RunError::Addr { addr, source })
}

/// Run the operator until a listener or the controller exits.
/// `default_server_image` serves CRs that leave spec.image unset, and
/// `tls_defaults` builds the TLS defaults source from the cluster client.
pub async fn run(
    default_server_image: Option<String>,
    tls_defaults: impl FnOnce(Client) -> Arc<dyn TlsDefaults>,
) -> Result<(), RunError> {
    telemetry::init_tracing(telemetry::LogFormat::from_env())?;

    let handle = telemetry::install_recorder()?;
    let health_addr = listen_addr(telemetry::HEALTH_PORT)?;
    let client = Client::try_default().await?;
    let tls_defaults = tls_defaults(client.clone());
    let tls_dir = std::env::var_os(telemetry::METRICS_TLS_DIR_ENV).map(PathBuf::from);

    let metrics = match tls_dir {
        Some(dir) => metrics_over_tls(&client, tls_defaults.as_ref(), handle, dir).await?,
        None => {
            let addr = listen_addr(telemetry::METRICS_PORT)?;
            tracing::info!(%addr, "metrics listener is plaintext and unauthenticated");
            Box::pin(telemetry::serve_plain(
                addr,
                telemetry::metrics_router(handle, None),
            ))
        }
    };

    tracing::info!(%health_addr, "modelexpress-operator starting");

    // either side exiting is fatal: a dead listener means dead probes or a
    // dead scrape target, which should restart the pod rather than linger
    // half-alive
    tokio::select! {
        res = telemetry::serve_plain(health_addr, telemetry::health_router()) => res?,
        res = metrics => res?,
        res = controller::run(client, tls_defaults, default_server_image) => res?,
    }
    Ok(())
}

type ServeFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<(), telemetry::TelemetryError>> + Send>,
>;

#[cfg(feature = "tls-openssl")]
async fn metrics_over_tls(
    client: &Client,
    tls_defaults: &dyn TlsDefaults,
    handle: metrics_exporter_prometheus::PrometheusHandle,
    dir: PathBuf,
) -> Result<ServeFuture, RunError> {
    use crate::metrics_auth::MetricsAuth;
    use crate::metrics_tls::{CertPaths, RELOAD_INTERVAL, config_with_reload};

    let settings = tls_defaults
        .current()
        .await
        .map_err(RunError::TlsDefaults)?;
    tracing::info!(
        min_version = settings.min_version.as_deref().unwrap_or("default"),
        ciphers = settings.ciphers.len(),
        groups = settings.groups.len(),
        "metrics listener TLS settings"
    );
    let updates = tls_defaults.updates().await;
    let config = config_with_reload(CertPaths::in_dir(&dir), settings, updates, RELOAD_INTERVAL)?;
    let addr = listen_addr(telemetry::METRICS_TLS_PORT)?;
    let router = telemetry::metrics_router(handle, Some(MetricsAuth::new(client.clone())));
    Ok(Box::pin(telemetry::serve_tls(addr, router, config)))
}

#[cfg(not(feature = "tls-openssl"))]
async fn metrics_over_tls(
    _client: &Client,
    _tls_defaults: &dyn TlsDefaults,
    _handle: metrics_exporter_prometheus::PrometheusHandle,
    _dir: PathBuf,
) -> Result<ServeFuture, RunError> {
    Err(RunError::MetricsTlsUnsupported)
}
