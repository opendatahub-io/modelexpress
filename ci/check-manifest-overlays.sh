#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Build every overlay under config/manifests, then treat config/manifests/odh
# the way a platform operator does: rewrite its params.env in place, force a
# namespace over the render, and apply the result into a namespace it owns.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifests="${root}/config/manifests"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

for overlay in default openshift odh; do
    echo "==> kustomize build ${overlay}"
    kustomize build "${manifests}/${overlay}" > "${work}/${overlay}.yaml"
done

echo "==> odh ships no Namespace"
if grep -q '^kind: Namespace$' "${work}/odh.yaml"; then
    fail "config/manifests/odh renders a Namespace; the platform owns it"
fi

echo "==> odh takes every image from its own params.env"
operator_image="registry.example/operator@sha256:1111"
server_image="registry.example/server@sha256:2222"
namespace="platform-applications"

cp -R "${manifests}" "${work}/bundle"
params="${work}/bundle/odh/params.env"
keys="$(cut -d= -f1 "${params}" | sort | tr '\n' ' ')"
[[ "${keys}" == "MODELEXPRESS_OPERATOR_IMAGE MODELEXPRESS_SERVER_IMAGE " ]] \
    || fail "unexpected keys in odh/params.env: ${keys}"
printf 'MODELEXPRESS_OPERATOR_IMAGE=%s\nMODELEXPRESS_SERVER_IMAGE=%s\n' \
    "${operator_image}" "${server_image}" > "${params}"

mkdir "${work}/platform"
cat > "${work}/platform/kustomization.yaml" <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: ${namespace}
resources:
  - ../bundle/odh
EOF
kustomize build "${work}/platform" > "${work}/platform.yaml"

grep -q "image: ${operator_image}\$" "${work}/platform.yaml" \
    || fail "the operator image did not reach the Deployment"
grep -q "value: ${server_image}\$" "${work}/platform.yaml" \
    || fail "the server image did not reach the operator's env"
if grep -n 'quay.io/opendatahub' "${work}/platform.yaml"; then
    fail "a default image survived substitution"
fi

echo "==> every namespaced object and binding subject follows the platform"
stray="$(grep -E '^  namespace: ' "${work}/platform.yaml" \
    | grep -v "^  namespace: ${namespace}\$" || true)"
[[ -z "${stray}" ]] || fail "objects outside ${namespace}: ${stray}"
bindings="$(grep -c '^kind: ClusterRoleBinding$' "${work}/platform.yaml")"
subjects="$(grep -A2 '^- kind: ServiceAccount$' "${work}/platform.yaml" \
    | grep -c "^  namespace: ${namespace}\$" || true)"
[[ "${bindings}" -gt 0 && "${subjects}" -eq "${bindings}" ]] \
    || fail "${subjects} of ${bindings} ClusterRoleBinding subjects were namespaced"

echo "all clear: overlays build and odh substitutes cleanly"
