// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SHA-256, from OpenSSL in the build that ships, so the validated library
//! does the hashing there.

#[cfg(feature = "tls-openssl")]
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    openssl::sha::sha256(bytes)
}

#[cfg(not(feature = "tls-openssl"))]
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

/// Lowercase hex, safe inside a Kubernetes object name.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, byte| {
        // writing to a String cannot fail
        let _ = write!(out, "{byte:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use crate::digest::{hex, sha256};

    #[test]
    fn known_vector() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hex_is_two_chars_per_byte() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
    }
}
