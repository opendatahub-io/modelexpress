// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Channel setup. An `https://` endpoint is negotiated with OpenSSL, since
//! tonic's built-in TLS is rustls-only and the FIPS build cannot link it.

use std::path::Path;

use modelexpress_common::Error;
use tonic::transport::{Channel, Endpoint};

type Result<T> = std::result::Result<T, Box<Error>>;

/// Open a channel to `endpoint`, over TLS when its scheme is `https`.
///
/// `tls_ca_file` is the PEM bundle that must have issued the server
/// certificate; the system trust store is used when it is `None`.
pub async fn connect(endpoint: Endpoint, tls_ca_file: Option<&Path>) -> Result<Channel> {
    if endpoint.uri().scheme_str() != Some("https") {
        return Ok(endpoint.connect().await?);
    }
    connect_tls(endpoint, tls_ca_file).await
}

#[cfg(feature = "tls-native")]
async fn connect_tls(endpoint: Endpoint, tls_ca_file: Option<&Path>) -> Result<Channel> {
    use std::pin::Pin;

    use hyper_util::rt::TokioIo;
    use openssl::ssl::{SslConnector, SslMethod};
    use tokio_openssl::SslStream;

    const ALPN_H2: &[u8] = b"\x02h2";
    const DEFAULT_HTTPS_PORT: u16 = 443;

    let transport = |message: String| Box::new(Error::Transport(message));
    let mut builder = SslConnector::builder(SslMethod::tls_client())
        .map_err(|e| transport(format!("openssl connector: {e}")))?;
    if let Some(ca_file) = tls_ca_file {
        builder
            .set_ca_file(ca_file)
            .map_err(|e| transport(format!("loading TLS CA bundle {}: {e}", ca_file.display())))?;
    }
    builder
        .set_alpn_protos(ALPN_H2)
        .map_err(|e| transport(format!("openssl alpn: {e}")))?;
    let connector = builder.build();

    let channel = endpoint
        .connect_with_connector(tower::service_fn(move |uri: http::Uri| {
            let connector = connector.clone();
            async move {
                let host = uri
                    .host()
                    .ok_or_else(|| format!("endpoint {uri} has no host"))?;
                let port = uri.port_u16().unwrap_or(DEFAULT_HTTPS_PORT);
                let tcp = tokio::net::TcpStream::connect((host, port)).await?;
                let ssl = connector.configure()?.into_ssl(host)?;
                let mut stream = SslStream::new(ssl, tcp)?;
                Pin::new(&mut stream).connect().await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(TokioIo::new(stream))
            }
        }))
        .await?;
    Ok(channel)
}

#[cfg(not(feature = "tls-native"))]
async fn connect_tls(endpoint: Endpoint, _tls_ca_file: Option<&Path>) -> Result<Channel> {
    Err(Box::new(Error::Transport(format!(
        "{} is an https endpoint, which needs the openssl build of the client",
        endpoint.uri()
    ))))
}
