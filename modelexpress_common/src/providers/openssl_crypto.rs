// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenSSL-backed request signing for `object_store` native-TLS builds.

use object_store::{
    Error, Result,
    client::{
        CryptoProvider, DigestAlgorithm, DigestContext, HmacContext, Signer, SigningAlgorithm,
    },
};
use openssl_crypto::{hash::MessageDigest, pkey::PKey};

const STORE: &str = "OpenSSL crypto provider";

fn openssl_error(source: openssl_crypto::error::ErrorStack) -> Error {
    Error::Generic {
        store: STORE,
        source: Box::new(source),
    }
}

fn unsupported(algorithm: &str) -> Error {
    Error::NotSupported {
        source: format!("OpenSSL request signing does not support {algorithm}").into(),
    }
}

#[derive(Debug, Clone, Copy)]
enum OpenSslDigestAlgorithm {
    Sha256,
}

impl OpenSslDigestAlgorithm {
    fn message_digest(self) -> MessageDigest {
        match self {
            Self::Sha256 => MessageDigest::sha256(),
        }
    }
}

fn digest_algorithm(algorithm: DigestAlgorithm) -> Result<OpenSslDigestAlgorithm> {
    match algorithm {
        DigestAlgorithm::Sha256 => Ok(OpenSslDigestAlgorithm::Sha256),
        _ => Err(unsupported("the requested digest algorithm")),
    }
}

/// Uses the system OpenSSL library for S3 request digests, HMAC, and signatures.
#[derive(Debug, Default)]
pub(crate) struct OpenSslCryptoProvider;

impl CryptoProvider for OpenSslCryptoProvider {
    fn digest(&self, algorithm: DigestAlgorithm) -> Result<Box<dyn DigestContext>> {
        Ok(Box::new(OpenSslDigestContext {
            algorithm: digest_algorithm(algorithm)?,
            input: Vec::new(),
            output: Vec::new(),
        }))
    }

    fn hmac(&self, algorithm: DigestAlgorithm, secret: &[u8]) -> Result<Box<dyn HmacContext>> {
        Ok(Box::new(OpenSslHmacContext {
            algorithm: digest_algorithm(algorithm)?,
            secret: secret.to_vec(),
            input: Vec::new(),
            output: Vec::new(),
        }))
    }

    fn sign(&self, algorithm: SigningAlgorithm, pem: &[u8]) -> Result<Box<dyn Signer>> {
        match algorithm {
            SigningAlgorithm::RS256 => Ok(Box::new(OpenSslRsaSigner {
                key: PKey::private_key_from_pem(pem).map_err(openssl_error)?,
            })),
            _ => Err(unsupported("the requested signing algorithm")),
        }
    }
}

#[derive(Debug)]
struct OpenSslDigestContext {
    algorithm: OpenSslDigestAlgorithm,
    input: Vec<u8>,
    output: Vec<u8>,
}

impl DigestContext for OpenSslDigestContext {
    fn update(&mut self, data: &[u8]) {
        self.input.extend_from_slice(data);
    }

    fn finish(&mut self) -> Result<&[u8]> {
        self.output = openssl_crypto::hash::hash(self.algorithm.message_digest(), &self.input)
            .map_err(openssl_error)?
            .to_vec();
        Ok(&self.output)
    }
}

#[derive(Debug)]
struct OpenSslHmacContext {
    algorithm: OpenSslDigestAlgorithm,
    secret: Vec<u8>,
    input: Vec<u8>,
    output: Vec<u8>,
}

impl HmacContext for OpenSslHmacContext {
    fn update(&mut self, data: &[u8]) {
        self.input.extend_from_slice(data);
    }

    fn finish(&mut self) -> Result<&[u8]> {
        let key = PKey::hmac(&self.secret).map_err(openssl_error)?;
        let mut signer = openssl_crypto::sign::Signer::new(self.algorithm.message_digest(), &key)
            .map_err(openssl_error)?;
        signer.update(&self.input).map_err(openssl_error)?;
        self.output = signer.sign_to_vec().map_err(openssl_error)?;
        Ok(&self.output)
    }
}

#[derive(Debug)]
struct OpenSslRsaSigner {
    key: PKey<openssl_crypto::pkey::Private>,
}

impl Signer for OpenSslRsaSigner {
    fn sign(&self, string_to_sign: &[u8]) -> Result<Vec<u8>> {
        let mut signer = openssl_crypto::sign::Signer::new(MessageDigest::sha256(), &self.key)
            .map_err(openssl_error)?;
        signer.update(string_to_sign).map_err(openssl_error)?;
        signer.sign_to_vec().map_err(openssl_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_digest_matches_known_value() -> Result<()> {
        let provider = OpenSslCryptoProvider;
        let mut digest = provider.digest(DigestAlgorithm::Sha256)?;
        digest.update(b"abc");
        assert_eq!(
            digest.finish()?,
            &[
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
        Ok(())
    }

    #[test]
    fn sha256_hmac_matches_known_value() -> Result<()> {
        let provider = OpenSslCryptoProvider;
        let mut hmac = provider.hmac(DigestAlgorithm::Sha256, b"key")?;
        hmac.update(b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            hmac.finish()?,
            &[
                0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24, 0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f,
                0xb1, 0x43, 0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59, 0x97, 0x47, 0x9d, 0xbc,
                0x2d, 0x1a, 0x3c, 0xd8,
            ]
        );
        Ok(())
    }
}
