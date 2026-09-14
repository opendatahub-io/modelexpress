// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! TLS termination for the gRPC listener, backed by OpenSSL.
//!
//! tonic's own TLS support is rustls-only, which the FIPS build cannot link, so
//! the listener is wrapped here and handed to tonic as a stream of already
//! negotiated connections.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use modelexpress_common::tls::{TlsVersion, split_cipher_suites};
use openssl::error::ErrorStack;
use openssl::ssl::{
    AlpnError, Ssl, SslContext, SslContextBuilder, SslFiletype, SslMethod, SslVersion,
    select_next_proto,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_openssl::SslStream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::server::{Connected, TcpConnectInfo};
use tracing::{debug, warn};

use crate::config::TlsConfig;

/// Bound on a single handshake so a client that connects and goes silent
/// cannot hold a task forever.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Negotiated connections buffered ahead of tonic's accept loop.
const ACCEPT_BACKLOG: usize = 64;

/// ALPN protocol list in OpenSSL wire format: one length-prefixed entry.
const ALPN_H2: &[u8] = b"\x02h2";

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("tls config: {0}")]
    Config(String),
    #[error("openssl: {0}")]
    OpenSsl(#[from] ErrorStack),
    #[error("bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        source: std::io::Error,
    },
}

/// A negotiated server-side TLS connection tonic can serve HTTP/2 over.
pub struct TlsConn {
    stream: SslStream<TcpStream>,
    info: TcpConnectInfo,
}

impl Connected for TlsConn {
    type ConnectInfo = TcpConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.info.clone()
    }
}

impl AsyncRead for TlsConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// Build the server context from the resolved config, or `None` when TLS is off.
pub fn build_context(config: &TlsConfig) -> Result<Option<SslContext>, TlsError> {
    let Some((cert, key)) = config.key_pair().map_err(TlsError::Config)? else {
        return Ok(None);
    };
    let mut builder = SslContextBuilder::new(SslMethod::tls_server())?;
    builder.set_certificate_chain_file(cert)?;
    builder.set_private_key_file(key, SslFiletype::PEM)?;
    builder.check_private_key()?;
    if let Some(version) = config.min_version {
        builder.set_min_proto_version(Some(ssl_version(version)))?;
    }
    let (tls12, tls13) = split_cipher_suites(&config.cipher_suites);
    if !tls12.is_empty() {
        builder.set_cipher_list(&tls12.join(":"))?;
    }
    if !tls13.is_empty() {
        builder.set_ciphersuites(&tls13.join(":"))?;
    }
    let groups = supported_groups(&config.groups)?;
    if !groups.is_empty() {
        builder.set_groups_list(&groups.join(":"))?;
    }
    builder.set_alpn_select_callback(|_ssl, client| {
        select_next_proto(ALPN_H2, client).ok_or(AlpnError::NOACK)
    });
    Ok(Some(builder.build()))
}

/// The subset of `groups` this OpenSSL can negotiate, in the order given.
///
/// A cluster profile lists post-quantum groups that OpenSSL before 3.5 does
/// not know, and `set_groups_list` rejects the whole list on one unknown
/// name. Each name is probed on a scratch context so the known ones still
/// apply, the way the Go library reports unsupported entries and moves on.
fn supported_groups(groups: &[String]) -> Result<Vec<String>, ErrorStack> {
    let mut probe = SslContextBuilder::new(SslMethod::tls_server())?;
    let mut supported = Vec::with_capacity(groups.len());
    for group in groups.iter().map(|g| g.trim()).filter(|g| !g.is_empty()) {
        if probe.set_groups_list(group).is_ok() {
            supported.push(group.to_string());
        } else {
            warn!("TLS group {group} is not supported by the linked OpenSSL; dropping it");
        }
    }
    Ok(supported)
}

fn ssl_version(version: TlsVersion) -> SslVersion {
    match version {
        TlsVersion::Tls10 => SslVersion::TLS1,
        TlsVersion::Tls11 => SslVersion::TLS1_1,
        TlsVersion::Tls12 => SslVersion::TLS1_2,
        TlsVersion::Tls13 => SslVersion::TLS1_3,
    }
}

/// Bind `addr` and return a stream of negotiated connections for
/// `serve_with_incoming_shutdown`.
///
/// Handshakes run on their own tasks so one slow client never blocks accepts.
/// A failed handshake is logged and dropped; tonic never sees it. The accept
/// task ends when the returned stream is dropped.
pub async fn incoming(
    addr: SocketAddr,
    context: SslContext,
) -> Result<ReceiverStream<Result<TlsConn, std::io::Error>>, TlsError> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| TlsError::Bind { addr, source })?;
    let (tx, rx) = tokio::sync::mpsc::channel(ACCEPT_BACKLOG);
    let context = Arc::new(context);
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                () = tx.closed() => break,
                accepted = listener.accept() => accepted,
            };
            let (tcp, peer) = match accepted {
                Ok(accepted) => accepted,
                Err(e) => {
                    warn!("TLS listener accept failed: {e}");
                    continue;
                }
            };
            let conn_tx = tx.clone();
            let context = Arc::clone(&context);
            tokio::spawn(async move {
                match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(&context, tcp)).await {
                    Ok(Ok(conn)) => {
                        // A closed receiver means the server is shutting down.
                        let _ = conn_tx.send(Ok(conn)).await;
                    }
                    Ok(Err(e)) => debug!("TLS handshake with {peer} failed: {e}"),
                    Err(_) => debug!(
                        "TLS handshake with {peer} timed out after {}s",
                        HANDSHAKE_TIMEOUT.as_secs()
                    ),
                }
            });
        }
    });
    Ok(ReceiverStream::new(rx))
}

async fn handshake(
    context: &SslContext,
    tcp: TcpStream,
) -> Result<TlsConn, Box<dyn std::error::Error + Send + Sync>> {
    let info = TcpConnectInfo {
        local_addr: tcp.local_addr().ok(),
        remote_addr: tcp.peer_addr().ok(),
    };
    let ssl = Ssl::new(context)?;
    let mut stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(TlsConn { stream, info })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::path::PathBuf;

    use modelexpress_common::tls::TlsVersion;
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
    use tempfile::TempDir;

    use crate::config::TlsConfig;
    use crate::tls::{ALPN_H2, TlsError, build_context};

    /// A throwaway CA-signed leaf for `localhost` written into `dir`.
    pub(crate) fn self_signed(dir: &TempDir) -> (PathBuf, PathBuf) {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::extension::SubjectAlternativeName;
        use openssl::x509::{X509, X509NameBuilder};

        let rsa = Rsa::generate(2048).expect("rsa");
        let key = PKey::from_rsa(rsa).expect("pkey");
        let mut name = X509NameBuilder::new().expect("name");
        name.append_entry_by_text("CN", "localhost").expect("cn");
        let name = name.build();
        let mut builder = X509::builder().expect("x509");
        builder.set_version(2).expect("version");
        builder.set_subject_name(&name).expect("subject");
        builder.set_issuer_name(&name).expect("issuer");
        builder.set_pubkey(&key).expect("pubkey");
        builder
            .set_not_before(&Asn1Time::days_from_now(0).expect("now"))
            .expect("not before");
        builder
            .set_not_after(&Asn1Time::days_from_now(1).expect("tomorrow"))
            .expect("not after");
        let san = SubjectAlternativeName::new()
            .dns("localhost")
            .ip("127.0.0.1")
            .build(&builder.x509v3_context(None, None))
            .expect("san");
        builder.append_extension(san).expect("append san");
        builder.sign(&key, MessageDigest::sha256()).expect("sign");
        let cert = builder.build();

        let cert_path = dir.path().join("tls.crt");
        let key_path = dir.path().join("tls.key");
        std::fs::write(&cert_path, cert.to_pem().expect("cert pem")).expect("write cert");
        std::fs::write(&key_path, key.private_key_to_pem_pkcs8().expect("key pem"))
            .expect("write key");
        (cert_path, key_path)
    }

    fn config(dir: &TempDir) -> TlsConfig {
        let (cert_file, key_file) = self_signed(dir);
        TlsConfig {
            cert_file: Some(cert_file),
            key_file: Some(key_file),
            ..TlsConfig::default()
        }
    }

    /// Run one handshake over loopback with a client pinned to `max` and report
    /// whether it negotiated, plus the ALPN protocol it got.
    fn handshake_with(
        context: &openssl::ssl::SslContext,
        max: SslVersion,
        cipher: Option<&str>,
    ) -> Result<Option<Vec<u8>>, String> {
        handshake_with_groups(context, max, cipher, None)
    }

    fn handshake_with_groups(
        context: &openssl::ssl::SslContext,
        max: SslVersion,
        cipher: Option<&str>,
        groups: Option<&str>,
    ) -> Result<Option<Vec<u8>>, String> {
        use openssl::ssl::Ssl;
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let context = context.clone();
        let server = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().expect("accept");
            let ssl = Ssl::new(&context).expect("ssl");
            let mut stream = match ssl.accept(tcp) {
                Ok(stream) => stream,
                Err(_) => return None,
            };
            let mut buf = [0_u8; 4];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"pong");
            Some(stream.ssl().selected_alpn_protocol().map(<[u8]>::to_vec))
        });

        let mut builder = SslConnector::builder(SslMethod::tls_client()).expect("connector");
        builder.set_verify(SslVerifyMode::NONE);
        builder.set_max_proto_version(Some(max)).expect("max");
        builder.set_alpn_protos(ALPN_H2).expect("alpn");
        if let Some(cipher) = cipher {
            builder.set_cipher_list(cipher).expect("cipher");
        }
        if let Some(groups) = groups {
            builder.set_groups_list(groups).expect("groups");
        }
        let connector = builder.build();
        let tcp = std::net::TcpStream::connect(addr).expect("connect");
        let result = connector
            .connect("localhost", tcp)
            .map_err(|e| e.to_string());
        match result {
            Ok(mut stream) => {
                let _ = stream.write_all(b"ping");
                let mut buf = [0_u8; 4];
                let _ = stream.read(&mut buf);
                Ok(server.join().expect("server thread").flatten())
            }
            Err(e) => {
                let _ = server.join();
                Err(e)
            }
        }
    }

    #[test]
    fn disabled_config_builds_no_context() {
        let ctx = build_context(&TlsConfig::default()).expect("build");
        assert!(ctx.is_none());
    }

    #[test]
    fn half_configured_key_pair_is_a_config_error() {
        let config = TlsConfig {
            cert_file: Some(PathBuf::from("/nonexistent/tls.crt")),
            ..TlsConfig::default()
        };
        assert!(matches!(build_context(&config), Err(TlsError::Config(_))));
    }

    #[test]
    fn missing_files_are_openssl_errors() {
        let config = TlsConfig {
            cert_file: Some(PathBuf::from("/nonexistent/tls.crt")),
            key_file: Some(PathBuf::from("/nonexistent/tls.key")),
            ..TlsConfig::default()
        };
        assert!(matches!(build_context(&config), Err(TlsError::OpenSsl(_))));
    }

    #[test]
    fn mismatched_key_is_rejected() {
        let a = TempDir::new().expect("tempdir");
        let b = TempDir::new().expect("tempdir");
        let (cert_file, _) = self_signed(&a);
        let (_, key_file) = self_signed(&b);
        let config = TlsConfig {
            cert_file: Some(cert_file),
            key_file: Some(key_file),
            ..TlsConfig::default()
        };
        assert!(matches!(build_context(&config), Err(TlsError::OpenSsl(_))));
    }

    #[test]
    fn negotiates_h2_over_tls13_by_default() {
        let dir = TempDir::new().expect("tempdir");
        let ctx = build_context(&config(&dir))
            .expect("build")
            .expect("enabled");
        let alpn = handshake_with(&ctx, SslVersion::TLS1_3, None).expect("handshake");
        assert_eq!(alpn.as_deref(), Some(&b"h2"[..]));
    }

    #[test]
    fn min_version_tls13_rejects_tls12_clients() {
        let dir = TempDir::new().expect("tempdir");
        let mut config = config(&dir);
        config.min_version = Some(TlsVersion::Tls13);
        let ctx = build_context(&config).expect("build").expect("enabled");
        assert!(handshake_with(&ctx, SslVersion::TLS1_2, None).is_err());
        assert!(handshake_with(&ctx, SslVersion::TLS1_3, None).is_ok());
    }

    #[test]
    fn min_version_tls12_accepts_tls12_clients() {
        let dir = TempDir::new().expect("tempdir");
        let mut config = config(&dir);
        config.min_version = Some(TlsVersion::Tls12);
        let ctx = build_context(&config).expect("build").expect("enabled");
        assert!(handshake_with(&ctx, SslVersion::TLS1_2, None).is_ok());
    }

    #[test]
    fn cipher_suites_restrict_tls12_negotiation() {
        let dir = TempDir::new().expect("tempdir");
        let mut config = config(&dir);
        config.min_version = Some(TlsVersion::Tls12);
        config.cipher_suites = vec![
            "ECDHE-RSA-AES256-GCM-SHA384".to_string(),
            "TLS_AES_256_GCM_SHA384".to_string(),
        ];
        let ctx = build_context(&config).expect("build").expect("enabled");
        assert!(
            handshake_with(
                &ctx,
                SslVersion::TLS1_2,
                Some("ECDHE-RSA-AES256-GCM-SHA384")
            )
            .is_ok()
        );
        assert!(
            handshake_with(
                &ctx,
                SslVersion::TLS1_2,
                Some("ECDHE-RSA-AES128-GCM-SHA256")
            )
            .is_err()
        );
    }

    #[test]
    fn groups_restrict_key_exchange() {
        let dir = TempDir::new().expect("tempdir");
        let mut config = config(&dir);
        config.groups = vec!["X25519".to_string()];
        let ctx = build_context(&config).expect("build").expect("enabled");
        assert!(handshake_with_groups(&ctx, SslVersion::TLS1_3, None, Some("X25519")).is_ok());
        assert!(handshake_with_groups(&ctx, SslVersion::TLS1_3, None, Some("secp384r1")).is_err());
    }

    #[test]
    fn unknown_groups_are_dropped_not_fatal() {
        let dir = TempDir::new().expect("tempdir");
        let mut config = config(&dir);
        config.groups = vec![
            "NOT_A_GROUP".to_string(),
            "X25519".to_string(),
            " secp256r1 ".to_string(),
        ];
        let ctx = build_context(&config).expect("build").expect("enabled");
        assert!(handshake_with_groups(&ctx, SslVersion::TLS1_3, None, Some("secp256r1")).is_ok());
        assert!(handshake_with_groups(&ctx, SslVersion::TLS1_3, None, Some("secp384r1")).is_err());
    }

    #[test]
    fn all_unknown_groups_leave_openssl_defaults() {
        let dir = TempDir::new().expect("tempdir");
        let mut config = config(&dir);
        config.groups = vec!["NOT_A_GROUP".to_string()];
        let ctx = build_context(&config).expect("build").expect("enabled");
        assert!(handshake_with_groups(&ctx, SslVersion::TLS1_3, None, Some("secp384r1")).is_ok());
    }

    #[test]
    fn unknown_cipher_name_is_rejected_at_build() {
        let dir = TempDir::new().expect("tempdir");
        let mut config = config(&dir);
        config.cipher_suites = vec!["NOT-A-CIPHER".to_string()];
        assert!(matches!(build_context(&config), Err(TlsError::OpenSsl(_))));
    }

    #[test]
    fn unknown_tls13_suite_is_rejected_at_build() {
        let dir = TempDir::new().expect("tempdir");
        let mut config = config(&dir);
        config.cipher_suites = vec!["TLS_NOT_A_SUITE".to_string()];
        assert!(matches!(build_context(&config), Err(TlsError::OpenSsl(_))));
    }
}
