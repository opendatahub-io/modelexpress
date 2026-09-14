// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The real server terminating TLS with OpenSSL, driven by the real client over
//! loopback. Gated behind `integration-tests` and `tls-openssl`:
//! `cargo test -p modelexpress-server --no-default-features --features openssl,integration-tests --test tls_e2e`.

#![allow(clippy::expect_used)]

use std::num::NonZeroU16;
use std::path::PathBuf;
use std::time::Duration;

use modelexpress_client::Client;
use modelexpress_common::client_config::ClientConfig;
use modelexpress_common::config::ConnectionConfig;
use modelexpress_common::tls::TlsVersion;
use modelexpress_server::backend_config::BackendConfig;
use modelexpress_server::config::{ServerConfig, TlsConfig};
use modelexpress_server::run_server;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{X509, X509NameBuilder};
use tempfile::TempDir;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

type ServerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

struct KeyPair {
    cert: PathBuf,
    key: PathBuf,
}

/// A self-signed leaf for 127.0.0.1, so the CA the client trusts is the cert itself.
fn self_signed(dir: &TempDir, stem: &str) -> KeyPair {
    let key: PKey<Private> = PKey::from_rsa(Rsa::generate(2048).expect("rsa")).expect("pkey");
    let mut name = X509NameBuilder::new().expect("name");
    name.append_entry_by_text("CN", stem).expect("cn");
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
        .ip("127.0.0.1")
        .build(&builder.x509v3_context(None, None))
        .expect("san");
    builder.append_extension(san).expect("append san");
    builder.sign(&key, MessageDigest::sha256()).expect("sign");
    let cert = builder.build();

    let pair = KeyPair {
        cert: dir.path().join(format!("{stem}.crt")),
        key: dir.path().join(format!("{stem}.key")),
    };
    std::fs::write(&pair.cert, cert.to_pem().expect("cert pem")).expect("write cert");
    std::fs::write(&pair.key, key.private_key_to_pem_pkcs8().expect("key pem")).expect("write key");
    pair
}

fn free_ports<const N: usize>() -> [u16; N] {
    let sockets: Vec<std::net::TcpListener> = (0..N)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port"))
        .collect();
    let mut ports = [0_u16; N];
    for (slot, socket) in ports.iter_mut().zip(&sockets) {
        *slot = socket.local_addr().expect("local addr").port();
    }
    ports
}

fn start_server(port: u16, tls: TlsConfig) -> (oneshot::Sender<()>, JoinHandle<ServerResult>) {
    let [metrics_port] = free_ports::<1>();
    let mut config = ServerConfig::default();
    config.server.host = "127.0.0.1".to_string();
    config.server.port = NonZeroU16::new(port).expect("port is non-zero");
    config.server.metrics_port = metrics_port;
    config.cache.eviction.enabled = false;
    config.tls = tls;

    let (tx, rx) = oneshot::channel::<()>();
    let shutdown = async move {
        let _ = rx.await;
    };
    let handle = tokio::spawn(run_server(config, BackendConfig::Memory, shutdown));
    (tx, handle)
}

fn client_config(scheme: &str, port: u16, ca: Option<&PathBuf>) -> ClientConfig {
    ClientConfig {
        connection: ConnectionConfig {
            tls_ca_file: ca.cloned(),
            ..ConnectionConfig::new(format!("{scheme}://127.0.0.1:{port}"))
        },
        ..Default::default()
    }
}

/// Retry until the listener is up, then return the last attempt's outcome.
async fn try_connect(config: &ClientConfig) -> Result<Client, Box<modelexpress_common::Error>> {
    let mut last = Err(Box::new(modelexpress_common::Error::Transport(
        "never attempted".to_string(),
    )));
    for _ in 0..100 {
        last = Client::new(config.clone()).await;
        if last.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    last
}

async fn wait_for_listener(port: u16) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("server never listened on {port}");
}

async fn stop(tx: oneshot::Sender<()>, handle: JoinHandle<ServerResult>) {
    tx.send(()).expect("server still running");
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("server shut down in time")
        .expect("server task")
        .expect("server exited cleanly");
}

#[tokio::test]
async fn client_with_the_right_ca_talks_to_a_tls_server() {
    let dir = TempDir::new().expect("tempdir");
    let server_pair = self_signed(&dir, "server");
    let [port] = free_ports::<1>();
    let (tx, handle) = start_server(
        port,
        TlsConfig {
            cert_file: Some(server_pair.cert.clone()),
            key_file: Some(server_pair.key.clone()),
            min_version: Some(TlsVersion::Tls12),
            ..TlsConfig::default()
        },
    );

    let mut client = try_connect(&client_config("https", port, Some(&server_pair.cert)))
        .await
        .expect("TLS client connects with the server cert as CA");
    client.health_check().await.expect("health check over TLS");

    stop(tx, handle).await;
}

#[tokio::test]
async fn plaintext_client_is_refused_by_a_tls_server() {
    let dir = TempDir::new().expect("tempdir");
    let server_pair = self_signed(&dir, "server");
    let [port] = free_ports::<1>();
    let (tx, handle) = start_server(
        port,
        TlsConfig {
            cert_file: Some(server_pair.cert.clone()),
            key_file: Some(server_pair.key.clone()),
            ..TlsConfig::default()
        },
    );
    wait_for_listener(port).await;

    // The TCP connect succeeds, so the client only learns on the first RPC that
    // the server never speaks h2c back.
    let outcome = match Client::new(client_config("http", port, None)).await {
        Ok(mut client) => client.health_check().await.map(|_| ()),
        Err(e) => Err(e),
    };
    assert!(
        outcome.is_err(),
        "plaintext client must not reach a TLS listener"
    );

    stop(tx, handle).await;
}

#[tokio::test]
async fn client_with_the_wrong_ca_is_refused() {
    let dir = TempDir::new().expect("tempdir");
    let server_pair = self_signed(&dir, "server");
    let other_pair = self_signed(&dir, "other");
    let [port] = free_ports::<1>();
    let (tx, handle) = start_server(
        port,
        TlsConfig {
            cert_file: Some(server_pair.cert.clone()),
            key_file: Some(server_pair.key.clone()),
            ..TlsConfig::default()
        },
    );
    wait_for_listener(port).await;

    let outcome = Client::new(client_config("https", port, Some(&other_pair.cert))).await;
    assert!(
        outcome.is_err(),
        "a CA that did not issue the server cert must fail verification"
    );

    stop(tx, handle).await;
}

#[tokio::test]
async fn modern_profile_is_honored_end_to_end() {
    let dir = TempDir::new().expect("tempdir");
    let server_pair = self_signed(&dir, "server");
    let [port] = free_ports::<1>();
    let (tx, handle) = start_server(
        port,
        TlsConfig {
            cert_file: Some(server_pair.cert.clone()),
            key_file: Some(server_pair.key.clone()),
            min_version: Some(TlsVersion::Tls13),
            cipher_suites: vec![
                "TLS_AES_128_GCM_SHA256".to_string(),
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_CHACHA20_POLY1305_SHA256".to_string(),
            ],
            groups: vec!["X25519MLKEM768".to_string(), "X25519".to_string()],
        },
    );

    let mut client = try_connect(&client_config("https", port, Some(&server_pair.cert)))
        .await
        .expect("TLS 1.3 client connects under the Modern profile");
    client
        .health_check()
        .await
        .expect("health check under Modern profile");

    stop(tx, handle).await;
}

#[tokio::test]
async fn plaintext_server_still_serves_plaintext_clients() {
    let [port] = free_ports::<1>();
    let (tx, handle) = start_server(port, TlsConfig::default());

    let mut client = try_connect(&client_config("http", port, None))
        .await
        .expect("plaintext client connects to a plaintext server");
    client.health_check().await.expect("plaintext health check");

    stop(tx, handle).await;
}

#[tokio::test]
async fn bad_certificate_paths_fail_startup() {
    let [port] = free_ports::<1>();
    let (_tx, handle) = start_server(
        port,
        TlsConfig {
            cert_file: Some(PathBuf::from("/nonexistent/tls.crt")),
            key_file: Some(PathBuf::from("/nonexistent/tls.key")),
            ..TlsConfig::default()
        },
    );
    let result = tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("server task ends")
        .expect("server task joins");
    assert!(result.is_err(), "unreadable cert must fail run_server");
}
