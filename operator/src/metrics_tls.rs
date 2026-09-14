// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! TLS for the operator's own metrics listener: an OpenSSL acceptor shaped by
//! the cluster TLS profile, serving a service-ca certificate that is reloaded
//! from disk when it rotates.

use crate::tls_profile::TlsProfile;
use axum_server::tls_openssl::OpenSSLConfig;
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
    #[error("unknown TLS version {0} in cluster profile")]
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
/// Post-quantum names in a profile predate OpenSSL 3.5, and one unknown name
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

/// Build the acceptor for `paths` under `profile`.
pub fn acceptor(paths: &CertPaths, profile: &TlsProfile) -> Result<SslAcceptor, MetricsTlsError> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
    builder.set_certificate_chain_file(&paths.cert)?;
    builder.set_private_key_file(&paths.key, SslFiletype::PEM)?;
    builder.check_private_key()?;
    builder.set_min_proto_version(Some(ssl_version(&profile.min_version)?))?;
    let (tls12, tls13): (Vec<&String>, Vec<&String>) = profile
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
    let groups = supported_groups(&profile.groups)?;
    if !groups.is_empty() {
        builder.set_groups_list(&groups.join(":"))?;
    }
    builder.set_alpn_select_callback(|_ssl, client| {
        select_next_proto(ALPN, client).ok_or(AlpnError::NOACK)
    });
    Ok(builder.build())
}

/// The axum-server config, plus a task that swaps in a rebuilt acceptor when
/// the certificate files change on disk (service-ca rotates them in place).
pub fn config_with_reload(
    paths: CertPaths,
    profile: TlsProfile,
) -> Result<OpenSSLConfig, MetricsTlsError> {
    let config = OpenSSLConfig::from_acceptor(Arc::new(acceptor(&paths, &profile)?));
    let reloading = config.clone();
    tokio::spawn(async move {
        let mut seen = mtimes(&paths);
        let mut ticker = tokio::time::interval(RELOAD_INTERVAL);
        loop {
            ticker.tick().await;
            let now = mtimes(&paths);
            if now == seen {
                continue;
            }
            match acceptor(&paths, &profile) {
                Ok(acceptor) => {
                    reloading.reload_from_acceptor(Arc::new(acceptor));
                    seen = now;
                    tracing::info!(
                        "metrics TLS certificate reloaded from {}",
                        paths.cert.display()
                    );
                }
                Err(e) => tracing::warn!("metrics TLS certificate changed but failed to load: {e}"),
            }
        }
    });
    Ok(config)
}

fn mtimes(paths: &CertPaths) -> (Option<SystemTime>, Option<SystemTime>) {
    let mtime = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    (mtime(&paths.cert), mtime(&paths.key))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
pub(crate) mod tests {
    use super::*;
    use openssl::ssl::{SslConnector, SslVerifyMode};
    use std::io::{Read, Write};
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
    fn intermediate_profile_serves_h2_over_tls12_and_13() {
        let dir = TempDir::new().expect("tempdir");
        let acceptor =
            acceptor(&self_signed(dir.path()), &TlsProfile::intermediate()).expect("acceptor");
        assert_eq!(
            handshake(&acceptor, SslVersion::TLS1_3, None)
                .expect("tls13")
                .as_deref(),
            Some(&b"h2"[..])
        );
        assert!(handshake(&acceptor, SslVersion::TLS1_2, None).is_ok());
    }

    #[test]
    fn modern_profile_rejects_tls12() {
        let dir = TempDir::new().expect("tempdir");
        let acceptor = acceptor(&self_signed(dir.path()), &TlsProfile::modern()).expect("acceptor");
        assert!(handshake(&acceptor, SslVersion::TLS1_2, None).is_err());
        assert!(handshake(&acceptor, SslVersion::TLS1_3, None).is_ok());
    }

    #[test]
    fn profile_groups_apply_and_unknown_ones_are_dropped() {
        let dir = TempDir::new().expect("tempdir");
        let mut profile = TlsProfile::modern();
        profile.groups = vec!["NOT_A_GROUP".into(), "X25519".into()];
        let acceptor = acceptor(&self_signed(dir.path()), &profile).expect("acceptor");
        assert!(handshake(&acceptor, SslVersion::TLS1_3, Some("X25519")).is_ok());
        assert!(handshake(&acceptor, SslVersion::TLS1_3, Some("secp384r1")).is_err());
    }

    #[test]
    fn missing_cert_fails() {
        let dir = TempDir::new().expect("tempdir");
        assert!(acceptor(&CertPaths::in_dir(dir.path()), &TlsProfile::intermediate()).is_err());
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
}
