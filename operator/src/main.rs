// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use modelexpress_operator::{controller, telemetry, tls_profile};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
enum MainError {
    #[error("kubernetes client: {0}")]
    Client(#[from] kube::Error),
    #[error(transparent)]
    Telemetry(#[from] telemetry::TelemetryError),
    #[error("bad listen addr {addr}: {source}")]
    Addr {
        addr: String,
        source: std::net::AddrParseError,
    },
    #[error("cluster TLS profile: {0}")]
    TlsProfile(#[from] tls_profile::FetchError),
    #[cfg(feature = "tls-openssl")]
    #[error("metrics TLS: {0}")]
    MetricsTls(#[from] modelexpress_operator::metrics_tls::MetricsTlsError),
    #[cfg(not(feature = "tls-openssl"))]
    #[error(
        "{} is set but this build has no OpenSSL; metrics TLS needs --features openssl",
        telemetry::METRICS_TLS_DIR_ENV
    )]
    MetricsTlsUnsupported,
}

fn listen_addr(port: i32) -> Result<SocketAddr, MainError> {
    let addr = format!("0.0.0.0:{port}");
    addr.parse()
        .map_err(|source| MainError::Addr { addr, source })
}

#[tokio::main]
async fn main() -> Result<(), MainError> {
    telemetry::init_tracing(telemetry::LogFormat::from_env())?;

    let handle = telemetry::install_recorder()?;
    let health_addr = listen_addr(telemetry::HEALTH_PORT)?;
    let client = kube::Client::try_default().await?;
    let tls_dir = std::env::var_os(telemetry::METRICS_TLS_DIR_ENV).map(PathBuf::from);

    let metrics = match tls_dir {
        Some(dir) => metrics_over_tls(&client, handle, dir).await?,
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
        res = controller::run(client) => res?,
    }
    Ok(())
}

type ServeFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<(), telemetry::TelemetryError>> + Send>,
>;

#[cfg(feature = "tls-openssl")]
async fn metrics_over_tls(
    client: &kube::Client,
    handle: metrics_exporter_prometheus::PrometheusHandle,
    dir: PathBuf,
) -> Result<ServeFuture, MainError> {
    use modelexpress_operator::metrics_auth::MetricsAuth;
    use modelexpress_operator::metrics_tls::{CertPaths, config_with_reload};

    let profile = tls_profile::fetch(client).await?.unwrap_or_default();
    tracing::info!(
        min_version = %profile.min_version,
        ciphers = profile.ciphers.len(),
        groups = profile.groups.len(),
        "metrics listener follows the cluster TLS profile"
    );
    let config = config_with_reload(CertPaths::in_dir(&dir), profile.clone())?;
    tokio::spawn(tls_profile::exit_on_change(client.clone(), profile));
    let addr = listen_addr(telemetry::METRICS_TLS_PORT)?;
    let router = telemetry::metrics_router(handle, Some(MetricsAuth::new(client.clone())));
    Ok(Box::pin(telemetry::serve_tls(addr, router, config)))
}

#[cfg(not(feature = "tls-openssl"))]
async fn metrics_over_tls(
    _client: &kube::Client,
    _handle: metrics_exporter_prometheus::PrometheusHandle,
    _dir: PathBuf,
) -> Result<ServeFuture, MainError> {
    Err(MainError::MetricsTlsUnsupported)
}
