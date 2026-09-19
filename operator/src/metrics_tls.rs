// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! TLS for the operator's own metrics listener: an OpenSSL acceptor shaped by
//! the TLS defaults, serving a mounted certificate. Both are reloaded in
//! place, without a restart, when the certificate rotates or the defaults
//! change.

use crate::tls::TlsSettings;
use axum_server::tls_openssl::OpenSSLConfig;
use futures::{Stream, StreamExt};
use openssl::error::ErrorStack;
use openssl::ssl::{
    AlpnError, SslAcceptor, SslContextBuilder, SslFiletype, SslMethod, SslVersion,
    select_next_proto,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

pub const CERT_FILE: &str = "tls.crt";
pub const KEY_FILE: &str = "tls.key";

/// How often the certificate files are checked for rotation.
pub const RELOAD_INTERVAL: Duration = Duration::from_secs(60);

/// ALPN list in OpenSSL wire format: h2 first, then http/1.1.
const ALPN: &[u8] = b"\x02h2\x08http/1.1";

#[derive(Debug, thiserror::Error)]
pub enum MetricsTlsError {
    #[error("openssl: {0}")]
    OpenSsl(#[from] ErrorStack),
    #[error("unknown TLS version {0}")]
    Version(String),
}

/// Paths of the mounted serving certificate.
#[derive(Clone, Debug)]
pub struct CertPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl CertPaths {
    #[must_use]
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            cert: dir.join(CERT_FILE),
            key: dir.join(KEY_FILE),
        }
    }
}

fn ssl_version(name: &str) -> Result<SslVersion, MetricsTlsError> {
    let digits = name
        .trim()
        .to_ascii_lowercase()
        .replace("versiontls", "")
        .replace("tls", "")
        .replace('.', "");
    match digits.as_str() {
        "10" => Ok(SslVersion::TLS1),
        "11" => Ok(SslVersion::TLS1_1),
        "12" => Ok(SslVersion::TLS1_2),
        "13" => Ok(SslVersion::TLS1_3),
        _ => Err(MetricsTlsError::Version(name.to_string())),
    }
}

/// The subset of `groups` this OpenSSL can negotiate, in the order given.
/// Post-quantum names in a group list predate OpenSSL 3.5, and one unknown name
/// rejects the whole list, so each is probed on a scratch context.
fn supported_groups(groups: &[String]) -> Result<Vec<String>, ErrorStack> {
    let mut probe = SslContextBuilder::new(SslMethod::tls_server())?;
    let mut supported = Vec::with_capacity(groups.len());
    for group in groups.iter().map(|g| g.trim()).filter(|g| !g.is_empty()) {
        if probe.set_groups_list(group).is_ok() {
            supported.push(group.to_string());
        } else {
            tracing::warn!("TLS group {group} is not supported by the linked OpenSSL; dropping it");
        }
    }
    Ok(supported)
}

/// Build the acceptor for `paths` under `settings`.
pub fn acceptor(paths: &CertPaths, settings: &TlsSettings) -> Result<SslAcceptor, MetricsTlsError> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
    builder.set_certificate_chain_file(&paths.cert)?;
    builder.set_private_key_file(&paths.key, SslFiletype::PEM)?;
    builder.check_private_key()?;
    if let Some(min_version) = &settings.min_version {
        builder.set_min_proto_version(Some(ssl_version(min_version)?))?;
    }
    let (tls12, tls13): (Vec<&String>, Vec<&String>) = settings
        .ciphers
        .iter()
        .partition(|name| !name.starts_with("TLS_"));
    if !tls12.is_empty() {
        let list: Vec<&str> = tls12.iter().map(|s| s.as_str()).collect();
        builder.set_cipher_list(&list.join(":"))?;
    }
    if !tls13.is_empty() {
        let list: Vec<&str> = tls13.iter().map(|s| s.as_str()).collect();
        builder.set_ciphersuites(&list.join(":"))?;
    }
    let groups = supported_groups(&settings.groups)?;
    if !groups.is_empty() {
        builder.set_groups_list(&groups.join(":"))?;
    }
    builder.set_alpn_select_callback(|_ssl, client| {
        select_next_proto(ALPN, client).ok_or(AlpnError::NOACK)
    });
    Ok(builder.build())
}

/// The axum-server config, plus a task that swaps in a rebuilt acceptor when
/// the certificate files change on disk (checked every `interval`; issuers
/// rotate them in place) or `updates` yields new settings.
///
/// The swap applies to new handshakes; connections already open keep the
/// session they negotiated. A rebuild that fails keeps the previous acceptor.
pub fn config_with_reload<S>(
    paths: CertPaths,
    settings: TlsSettings,
    updates: S,
    interval: Duration,
) -> Result<OpenSSLConfig, MetricsTlsError>
where
    S: Stream<Item = TlsSettings> + Send + Unpin + 'static,
{
    let config = OpenSSLConfig::from_acceptor(Arc::new(acceptor(&paths, &settings)?));
    let reloading = config.clone();
    let mut reloader = Reloader::new(paths, settings);
    tokio::spawn(async move {
        let mut updates = updates.fuse();
        let mut ticker = tokio::time::interval(interval);
        loop {
            let trigger = tokio::select! {
                _ = ticker.tick() => Trigger::CertCheck,
                Some(settings) = updates.next() => Trigger::Settings(settings),
            };
            match reloader.rebuild(trigger) {
                None => {}
                Some(Ok(acceptor)) => {
                    reloading.reload_from_acceptor(Arc::new(acceptor));
                    tracing::info!(
                        min_version = reloader.settings.min_version.as_deref().unwrap_or("default"),
                        cert = %reloader.paths.cert.display(),
                        "metrics TLS acceptor reloaded"
                    );
                }
                Some(Err(e)) => {
                    tracing::warn!(
                        "metrics TLS acceptor not reloaded, keeping the previous one: {e}"
                    );
                }
            }
        }
    });
    Ok(config)
}

/// What woke the reload task.
#[derive(Debug)]
enum Trigger {
    CertCheck,
    Settings(TlsSettings),
}

/// Decides when the metrics acceptor has to be rebuilt, and rebuilds it.
struct Reloader {
    paths: CertPaths,
    /// The settings the listener should serve, even when building failed.
    settings: TlsSettings,
    /// Certificate mtimes of the last successful build. Left alone on a
    /// failed build, so a half-rotated key pair is retried on the next check.
    built_from: (Option<SystemTime>, Option<SystemTime>),
}

impl Reloader {
    fn new(paths: CertPaths, settings: TlsSettings) -> Self {
        let built_from = mtimes(&paths);
        Self {
            paths,
            settings,
            built_from,
        }
    }

    /// A rebuilt acceptor when `trigger` changed what the listener should
    /// serve, `None` when nothing did.
    fn rebuild(&mut self, trigger: Trigger) -> Option<Result<SslAcceptor, MetricsTlsError>> {
        let current = mtimes(&self.paths);
        match trigger {
            Trigger::CertCheck if current == self.built_from => return None,
            Trigger::CertCheck => {}
            Trigger::Settings(settings) if settings == self.settings => return None,
            Trigger::Settings(settings) => self.settings = settings,
        }
        let rebuilt = acceptor(&self.paths, &self.settings);
        if rebuilt.is_ok() {
            self.built_from = current;
        }
        Some(rebuilt)
    }
}

fn mtimes(paths: &CertPaths) -> (Option<SystemTime>, Option<SystemTime>) {
    let mtime = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    (mtime(&paths.cert), mtime(&paths.key))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
pub(crate) mod tests {
    use crate::metrics_tls::{
        CertPaths, Reloader, Trigger, acceptor, config_with_reload, mtimes, ssl_version,
    };
    use crate::tls::TlsSettings;
    use axum_server::tls_openssl::OpenSSLConfig;
    use openssl::ssl::{
        SslAcceptor, SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion,
    };
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::path::Path;
    use std::time::Duration;
    use tempfile::TempDir;

    pub(crate) fn self_signed(dir: &Path) -> CertPaths {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::extension::SubjectAlternativeName;
        use openssl::x509::{X509, X509NameBuilder};

        let key = PKey::from_rsa(Rsa::generate(2048).expect("rsa")).expect("pkey");
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
        builder.append_extension(san).expect("san ext");
        builder.sign(&key, MessageDigest::sha256()).expect("sign");
        let paths = CertPaths::in_dir(dir);
        std::fs::write(&paths.cert, builder.build().to_pem().expect("pem")).expect("write cert");
        std::fs::write(&paths.key, key.private_key_to_pem_pkcs8().expect("pem"))
            .expect("write key");
        paths
    }

    /// One loopback handshake against `acceptor` with a client pinned to
    /// `max`; returns the negotiated ALPN protocol.
    fn handshake(
        acceptor: &SslAcceptor,
        max: SslVersion,
        groups: Option<&str>,
    ) -> Result<Option<Vec<u8>>, String> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let acceptor = acceptor.clone();
        let server = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().expect("accept");
            let mut stream = acceptor.accept(tcp).ok()?;
            let mut buf = [0_u8; 4];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"pong");
            Some(stream.ssl().selected_alpn_protocol().map(<[u8]>::to_vec))
        });
        let mut builder = SslConnector::builder(SslMethod::tls_client()).expect("connector");
        builder.set_verify(SslVerifyMode::NONE);
        builder.set_max_proto_version(Some(max)).expect("max");
        builder.set_alpn_protos(b"\x02h2").expect("alpn");
        if let Some(groups) = groups {
            builder.set_groups_list(groups).expect("groups");
        }
        let tcp = std::net::TcpStream::connect(addr).expect("connect");
        match builder.build().connect("localhost", tcp) {
            Ok(mut stream) => {
                let _ = stream.write_all(b"ping");
                let mut buf = [0_u8; 4];
                let _ = stream.read(&mut buf);
                Ok(server.join().expect("server").flatten())
            }
            Err(e) => {
                let _ = server.join();
                Err(e.to_string())
            }
        }
    }

    #[test]
    fn version_names_parse_both_spellings() {
        assert_eq!(ssl_version("VersionTLS12").expect("v"), SslVersion::TLS1_2);
        assert_eq!(ssl_version("TLS1.3").expect("v"), SslVersion::TLS1_3);
        assert_eq!(ssl_version("VersionTLS10").expect("v"), SslVersion::TLS1);
        assert!(ssl_version("TLS2").is_err());
    }

    #[test]
    fn intermediate_settings_serve_h2_over_tls12_and_13() {
        let dir = TempDir::new().expect("tempdir");
        let acceptor = acceptor(&self_signed(dir.path()), &intermediate()).expect("acceptor");
        assert_eq!(
            handshake(&acceptor, SslVersion::TLS1_3, None)
                .expect("tls13")
                .as_deref(),
            Some(&b"h2"[..])
        );
        assert!(handshake(&acceptor, SslVersion::TLS1_2, None).is_ok());
    }

    #[test]
    fn modern_settings_reject_tls12() {
        let dir = TempDir::new().expect("tempdir");
        let acceptor = acceptor(&self_signed(dir.path()), &modern()).expect("acceptor");
        assert!(handshake(&acceptor, SslVersion::TLS1_2, None).is_err());
        assert!(handshake(&acceptor, SslVersion::TLS1_3, None).is_ok());
    }

    #[test]
    fn groups_apply_and_unknown_ones_are_dropped() {
        let dir = TempDir::new().expect("tempdir");
        let mut settings = modern();
        settings.groups = vec!["NOT_A_GROUP".into(), "X25519".into()];
        let acceptor = acceptor(&self_signed(dir.path()), &settings).expect("acceptor");
        assert!(handshake(&acceptor, SslVersion::TLS1_3, Some("X25519")).is_ok());
        assert!(handshake(&acceptor, SslVersion::TLS1_3, Some("secp384r1")).is_err());
    }

    #[test]
    fn missing_cert_fails() {
        let dir = TempDir::new().expect("tempdir");
        assert!(acceptor(&CertPaths::in_dir(dir.path()), &intermediate()).is_err());
    }

    #[test]
    fn mtimes_change_when_files_are_rewritten() {
        let dir = TempDir::new().expect("tempdir");
        let paths = self_signed(dir.path());
        let before = mtimes(&paths);
        assert!(before.0.is_some() && before.1.is_some());
        let later = std::time::SystemTime::now() + Duration::from_secs(5);
        std::fs::File::options()
            .write(true)
            .open(&paths.cert)
            .expect("open")
            .set_modified(later)
            .expect("touch");
        assert_ne!(mtimes(&paths), before);
    }

    /// Push both files' mtimes forward so a rewrite within the filesystem's
    /// timestamp granularity still reads as a change.
    fn bump_mtimes(paths: &CertPaths, by: Duration) {
        let later = std::time::SystemTime::now()
            .checked_add(by)
            .expect("time in range");
        for path in [&paths.cert, &paths.key] {
            std::fs::File::options()
                .write(true)
                .open(path)
                .expect("open")
                .set_modified(later)
                .expect("touch");
        }
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    /// Mozilla's Intermediate settings with a four-group preference list.
    fn intermediate() -> TlsSettings {
        TlsSettings {
            min_version: Some("VersionTLS12".to_string()),
            ciphers: strings(&[
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "ECDHE-ECDSA-AES128-GCM-SHA256",
                "ECDHE-RSA-AES128-GCM-SHA256",
                "ECDHE-ECDSA-AES256-GCM-SHA384",
                "ECDHE-RSA-AES256-GCM-SHA384",
                "ECDHE-ECDSA-CHACHA20-POLY1305",
                "ECDHE-RSA-CHACHA20-POLY1305",
            ]),
            groups: strings(&["X25519MLKEM768", "X25519", "secp256r1", "secp384r1"]),
        }
    }

    /// Mozilla's Modern settings: TLS 1.3 only.
    fn modern() -> TlsSettings {
        TlsSettings {
            min_version: Some("VersionTLS13".to_string()),
            ciphers: strings(&[
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
            ]),
            ..intermediate()
        }
    }

    fn broken_settings() -> TlsSettings {
        TlsSettings {
            min_version: Some("TLS9".to_string()),
            ..intermediate()
        }
    }

    #[test]
    fn reloader_ignores_unchanged_inputs() {
        let dir = TempDir::new().expect("tempdir");
        let mut reloader = Reloader::new(self_signed(dir.path()), intermediate());
        assert!(reloader.rebuild(Trigger::CertCheck).is_none());
        assert!(
            reloader
                .rebuild(Trigger::Settings(intermediate()))
                .is_none()
        );
    }

    #[test]
    fn reloader_rebuilds_once_per_settings_change() {
        let dir = TempDir::new().expect("tempdir");
        let mut reloader = Reloader::new(self_signed(dir.path()), intermediate());
        let rebuilt = reloader
            .rebuild(Trigger::Settings(modern()))
            .expect("settings changed")
            .expect("modern builds");
        assert!(handshake(&rebuilt, SslVersion::TLS1_2, None).is_err());
        assert!(reloader.rebuild(Trigger::Settings(modern())).is_none());
    }

    #[test]
    fn reloader_does_not_retry_settings_that_failed_to_build() {
        let dir = TempDir::new().expect("tempdir");
        let mut reloader = Reloader::new(self_signed(dir.path()), intermediate());
        assert!(matches!(
            reloader.rebuild(Trigger::Settings(broken_settings())),
            Some(Err(_))
        ));
        assert!(
            reloader
                .rebuild(Trigger::Settings(broken_settings()))
                .is_none()
        );
        assert!(reloader.rebuild(Trigger::CertCheck).is_none());
        assert!(matches!(
            reloader.rebuild(Trigger::Settings(intermediate())),
            Some(Ok(_))
        ));
    }

    #[test]
    fn reloader_retries_a_half_rotated_key_pair() {
        let dir = TempDir::new().expect("tempdir");
        let paths = self_signed(dir.path());
        let mut reloader = Reloader::new(paths.clone(), intermediate());

        let next = TempDir::new().expect("tempdir");
        let rotated = self_signed(next.path());
        std::fs::copy(&rotated.cert, &paths.cert).expect("new cert, old key");
        bump_mtimes(&paths, Duration::from_secs(5));
        assert!(matches!(reloader.rebuild(Trigger::CertCheck), Some(Err(_))));
        assert!(
            matches!(reloader.rebuild(Trigger::CertCheck), Some(Err(_))),
            "a failed load must be retried on the next check"
        );

        std::fs::copy(&rotated.key, &paths.key).expect("matching key");
        bump_mtimes(&paths, Duration::from_secs(10));
        assert!(matches!(reloader.rebuild(Trigger::CertCheck), Some(Ok(_))));
        assert!(reloader.rebuild(Trigger::CertCheck).is_none());
    }

    async fn serve(config: OpenSSLConfig) -> SocketAddr {
        let handle = axum_server::Handle::new();
        let app = axum::Router::new().route("/", axum::routing::get(|| async { "ok" }));
        let server = axum_server::bind_openssl("127.0.0.1:0".parse().expect("addr"), config)
            .handle(handle.clone());
        tokio::spawn(async move {
            let _ = server.serve(app.into_make_service()).await;
        });
        handle.listening().await.expect("listening")
    }

    fn connect(addr: SocketAddr, max: SslVersion) -> Result<SslStream<TcpStream>, String> {
        let mut builder = SslConnector::builder(SslMethod::tls_client()).expect("connector");
        builder.set_verify(SslVerifyMode::NONE);
        builder.set_max_proto_version(Some(max)).expect("max");
        builder.set_alpn_protos(b"\x08http/1.1").expect("alpn");
        let tcp = TcpStream::connect(addr).expect("tcp connect");
        builder
            .build()
            .connect("localhost", tcp)
            .map_err(|e| e.to_string())
    }

    /// One HTTP/1.1 keep-alive request on an open connection.
    fn get(stream: &mut SslStream<TcpStream>) -> String {
        stream
            .write_all(b"GET / HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .expect("write request");
        let mut response = Vec::new();
        let mut buf = [0_u8; 512];
        while !response.ends_with(b"ok") {
            let n = stream.read(&mut buf).expect("read response");
            assert!(n > 0, "connection closed mid-response");
            response.extend_from_slice(&buf[..n]);
        }
        String::from_utf8(response).expect("utf8")
    }

    async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        tokio::task::spawn_blocking(f).await.expect("blocking task")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn settings_change_applies_to_new_handshakes_without_a_restart() {
        let dir = TempDir::new().expect("tempdir");
        let (mut tx, rx) = futures::channel::mpsc::channel(1);
        let config = config_with_reload(
            self_signed(dir.path()),
            intermediate(),
            rx,
            Duration::from_secs(3600),
        )
        .expect("config");
        let addr = serve(config).await;

        let mut open = blocking(move || connect(addr, SslVersion::TLS1_2))
            .await
            .expect("TLS1.2 accepted under Intermediate");
        let (mut open, first) = blocking(move || {
            let response = get(&mut open);
            (open, response)
        })
        .await;
        assert!(first.starts_with("HTTP/1.1 200"), "{first}");

        futures::SinkExt::send(&mut tx, modern())
            .await
            .expect("send settings");
        let mut refused = false;
        for _ in 0..100 {
            if blocking(move || connect(addr, SslVersion::TLS1_2))
                .await
                .is_err()
            {
                refused = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            refused,
            "new TLS1.2 handshakes must be refused under Modern"
        );
        assert!(
            blocking(move || connect(addr, SslVersion::TLS1_3))
                .await
                .is_ok(),
            "TLS1.3 still accepted"
        );

        let second = blocking(move || get(&mut open)).await;
        assert!(
            second.starts_with("HTTP/1.1 200"),
            "a connection opened before the swap keeps working: {second}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rotated_certificate_is_served_without_a_restart() {
        let dir = TempDir::new().expect("tempdir");
        let paths = self_signed(dir.path());
        let config = config_with_reload(
            paths.clone(),
            intermediate(),
            futures::stream::pending(),
            Duration::from_millis(50),
        )
        .expect("config");
        let addr = serve(config).await;
        let served = move || {
            let stream = connect(addr, SslVersion::TLS1_3).expect("handshake");
            stream
                .ssl()
                .peer_certificate()
                .expect("peer cert")
                .to_der()
                .expect("der")
        };
        let before = blocking(served).await;

        let next = TempDir::new().expect("tempdir");
        let rotated = self_signed(next.path());
        std::fs::copy(&rotated.key, &paths.key).expect("rotate key");
        std::fs::copy(&rotated.cert, &paths.cert).expect("rotate cert");
        bump_mtimes(&paths, Duration::from_secs(5));
        let expected = std::fs::read(&paths.cert).expect("read rotated cert");
        let expected = openssl::x509::X509::from_pem(&expected)
            .expect("parse rotated cert")
            .to_der()
            .expect("der");
        assert_ne!(before, expected);

        let mut served_rotated = false;
        for _ in 0..100 {
            if blocking(served).await == expected {
                served_rotated = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(served_rotated, "the rotated certificate is served");
    }
}
