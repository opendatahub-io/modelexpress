#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run the cluster TLS profile e2e on kind.
#
# kind stands in for OpenShift: the overlay in operator-openshift/tests/tls_kind
# installs the operator's OpenShift manifests plus the apiservers.config.openshift.io
# CRD, so the test can edit apiservers/cluster (tlsSecurityProfile, tlsAdherence)
# without touching a real cluster. The test logic lives in
# operator-openshift/tests/tls_kind.rs; this script only prepares the cluster.
#
# Prerequisites: docker (with buildx), kind, kubectl, cargo.
#
# Usage:
#   ./test_tls_kind.sh [--skip-build] [--delete] [-- extra cargo test args...]
#
#   --skip-build  reuse the mx-e2e/*:kind images already in the local docker
#   --delete      delete the kind cluster afterwards, pass or fail
#
# KIND_CLUSTER overrides the cluster name (default mx-tls-e2e). The test runs
# against a kubeconfig exported from kind, never the current kubectl context.

set -euo pipefail
cd "$(dirname "$0")"

CLUSTER="${KIND_CLUSTER:-mx-tls-e2e}"
IMAGES=(operator server-openssl server-rustls)
SKIP_BUILD=false
DELETE=false
TEST_ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-build) SKIP_BUILD=true; shift ;;
        --delete) DELETE=true; shift ;;
        --) shift; TEST_ARGS=("$@"); break ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

KUBECONFIG_FILE="$(mktemp)"
cleanup() {
    rm -f "${KUBECONFIG_FILE}"
    if [ "${DELETE}" = true ]; then
        kind delete cluster --name "${CLUSTER}"
    fi
}
trap cleanup EXIT

if ! kind get clusters | grep -qx "${CLUSTER}"; then
    echo "==> creating kind cluster ${CLUSTER}"
    kind create cluster --name "${CLUSTER}" --wait 120s
fi
kind get kubeconfig --name "${CLUSTER}" > "${KUBECONFIG_FILE}"
export KUBECONFIG="${KUBECONFIG_FILE}"

if [ "${SKIP_BUILD}" = false ]; then
    for image in "${IMAGES[@]}"; do
        echo "==> building mx-e2e/${image}:kind"
        docker build --load -f docker/Dockerfile.e2e --target "${image}" -t "mx-e2e/${image}:kind" .
    done
fi
for image in "${IMAGES[@]}"; do
    kind load docker-image --name "${CLUSTER}" "mx-e2e/${image}:kind"
done

echo "==> installing the operator (OpenShift overlay) and the APIServer CRD"
kubectl apply --server-side --force-conflicts -k operator-openshift/tests/tls_kind
kubectl wait --for=condition=Established --timeout=60s \
    crd/apiservers.config.openshift.io \
    crd/modelexpressservers.modelexpress.opendatahub.io

echo "==> running operator-openshift/tests/tls_kind.rs"
cargo test -p modelexpress-operator-openshift --test tls_kind -- --ignored --nocapture ${TEST_ARGS[@]+"${TEST_ARGS[@]}"}
