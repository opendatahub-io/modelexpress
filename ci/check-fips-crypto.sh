#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Assert the shipped binaries reach no non-FIPS crypto. RHEL's openssl is the
# validated implementation; ring holds no certificate and aws-lc-rs qualifies
# only through aws-lc-fips-sys, not the aws-lc-sys rustls pulls.
#
# Not cargo-deny: its --features flags apply to the whole virtual workspace, so
# feature unification drags rustls back in via workspace-tests and the default
# gcs feature regardless of how the product is built.

set -euo pipefail

# package:features pairs, matching how each image is built
TARGETS=(
    "modelexpress-server:openssl"
    "modelexpress-operator:openssl"
)
BANNED=(ring aws-lc-rs aws-lc-sys rustls)

failed=0
for target in "${TARGETS[@]}"; do
    pkg="${target%%:*}"
    features="${target##*:}"
    echo "==> ${pkg} (--no-default-features --features ${features})"

    for crate in "${BANNED[@]}"; do
        # Passing looks like two things: a non-zero exit when the crate is
        # absent, and an empty tree when it is reachable only over dev edges.
        tree=$(cargo tree --quiet --package "${pkg}" \
                 --no-default-features --features "${features}" \
                 --invert "${crate}" --edges normal 2>/dev/null) || tree=""
        if [[ -n "${tree//[[:space:]]/}" ]]; then
            echo "    FAIL: ${crate} reachable from ${pkg}"
            echo "${tree}" | head -20 | sed 's/^/      /'
            failed=1
        else
            echo "    ok: ${crate} not linked"
        fi
    done
done

if [[ ${failed} -ne 0 ]]; then
    cat >&2 <<'EOF'

Non-FIPS crypto reached a shipped binary.

Most likely a new dependency defaulted to rustls. Give it
default-features = false and select the native-tls/openssl backend, the way
kube (openssl-tls) and reqwest (native-tls) are wired in Cargo.toml.

Note that the gcs feature can never be part of a FIPS build:
google-cloud-auth hardcodes rustls.
EOF
    exit 1
fi

echo "all clear: no non-FIPS crypto in the shipped feature sets"
