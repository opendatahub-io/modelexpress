#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Assert a built binary links no non-FIPS crypto. RHEL's openssl is the
# validated implementation; ring holds no certificate and aws-lc-rs qualifies
# only through aws-lc-fips-sys, not the aws-lc-sys rustls pulls.
#
# Reads the symbol table of the binary itself, so it sees exactly what was
# linked regardless of how cargo resolved features. If the binary carries
# cargo-auditable data, its runtime crates must not include check-payload's
# rust_denied_crypto list (pure-Rust primitives like sha2 leave no symbols).
# The Konflux Dockerfiles run it on the binary they ship.
#
# Usage: ci/check-fips-crypto.sh <binary>...

set -euo pipefail

if [[ $# -eq 0 ]]; then
    echo "usage: $0 <binary>..." >&2
    exit 2
fi

# Rust paths (ring::, rustls::, ...) and the prefixed C symbols ring and
# aws-lc build with. \b keeps string:: from matching ring::.
# rustc >= 1.97 uses v0 mangling by default. EL9 binutils 2.35 cannot
# demangle it, so match the raw v0 crate roots alongside legacy paths.
BANNED='\b(ring|rustls|aws_lc_rs|aws_lc_sys)::|\bring_core_[0-9]|\baws_lc_[0-9]|Cs[0-9A-Za-z]+_(4ring|6rustls|9aws_lc_rs|10aws_lc_sys)'

failed=0
for bin in "$@"; do
    echo "==> ${bin}"
    if [[ ! -f "${bin}" ]]; then
        echo "    FAIL: no such file"
        failed=1
        continue
    fi
    symbols=$(nm --demangle "${bin}" 2>/dev/null || true)

    if [[ -z "${symbols}" ]]; then
        echo "    FAIL: no symbol table; a stripped binary cannot be checked"
        failed=1
        continue
    fi

    banned=$(grep -oE "${BANNED}" <<<"${symbols}" | sort | uniq -c || true)
    if [[ -n "${banned}" ]]; then
        echo "    FAIL: non-FIPS crypto linked (symbol count per match):"
        sed 's/^/      /' <<<"${banned}"
        failed=1
    else
        echo "    ok: no ring, rustls or aws-lc symbols"
    fi

    if grep -qE '\bopenssl::|Cs[0-9A-Za-z]+_7openssl' <<<"${symbols}"; then
        echo "    ok: openssl linked"
    else
        echo "    FAIL: no openssl symbols; the openssl feature did not apply"
        failed=1
    fi

    if [[ "$(objdump -h "${bin}")" == *.dep-v0* ]]; then
        section=$(mktemp)
        copy=$(mktemp)
        objcopy --dump-section .dep-v0="${section}" "${bin}" "${copy}"
        rm -f "${copy}"
        stamped=$(python3 - "${section}" <<'EOF'
import json, sys, zlib
# Mirrors openshift/check-payload rust_denied_crypto, plus rustls. Like
# check-payload, build and dev deps only count for crates that bundle C crypto.
banned = {
    "rustls", "ring", "aws-lc-rs", "aws-lc-sys", "aws-lc-fips-sys",
    "boring", "boring-sys", "openssl-src",
    "sha1", "sha2", "sha3", "md-5", "hmac", "aes", "aes-gcm",
    "chacha20poly1305", "ctr", "cbc", "rsa", "ecdsa",
    "ed25519-dalek", "curve25519-dalek", "x25519-dalek", "p256", "p384",
}
native = {"openssl-src", "aws-lc-sys", "aws-lc-fips-sys", "boring-sys"}
with open(sys.argv[1], "rb") as f:
    packages = json.loads(zlib.decompress(f.read()))["packages"]
linked = {
    p["name"] for p in packages
    if p["name"] in native or p.get("kind", "runtime") == "runtime"
}
print(" ".join(sorted(linked & banned)))
EOF
)
        rm -f "${section}"
        if [[ -n "${stamped}" ]]; then
            echo "    FAIL: cargo-auditable data lists ${stamped}; build with -Z sbom"
            failed=1
        else
            echo "    ok: cargo-auditable data lists no denied crypto crates"
        fi
    fi
done

if [[ ${failed} -ne 0 ]]; then
    cat >&2 <<'EOF'

Non-FIPS crypto reached a shipped binary.

Build with --package <crate> --no-default-features --features openssl.
Without --package, cargo resolves features across the whole workspace and
rustls comes back through other members.

A new dependency that defaults to rustls needs default-features = false and
its native-tls/openssl backend, the way kube (openssl-tls) and reqwest
(native-tls) are wired in Cargo.toml.

The gcs feature can never be part of a FIPS build: google-cloud-auth
hardcodes rustls.
EOF
    exit 1
fi
