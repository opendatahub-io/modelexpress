// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! config/manifests/odh: the operator as a platform operator deploys it on
//! Open Data Hub and RHOAI.

use crate::objects::{NAME, OPERATOR_IMAGE_PARAM, PARAMS_CONFIGMAP};
use crate::openshift::{
    COMPONENT_PATH, DEFAULT_SERVER_IMAGE, SERVER_IMAGE_PARAM, server_image_replacement,
};
use serde_json::json;

/// Every image the platform substitutes, in the one file it rewrites.
pub fn params_env(image: &str) -> String {
    format!("{OPERATOR_IMAGE_PARAM}={image}\n{SERVER_IMAGE_PARAM}={DEFAULT_SERVER_IMAGE}\n")
}

/// ODH overlay: the base plus the OpenShift component, with no namespace and
/// no Namespace object, since the platform installs into its own.
pub fn overlay() -> Vec<(&'static str, serde_json::Value)> {
    vec![(
        "kustomization.yaml",
        json!({
            "apiVersion": "kustomize.config.k8s.io/v1beta1",
            "kind": "Kustomization",
            "resources": ["../base"],
            "components": [COMPONENT_PATH],
            "generatorOptions": {"disableNameSuffixHash": true},
            "configMapGenerator": [{"name": PARAMS_CONFIGMAP, "behavior": "merge", "envs": ["params.env"]}],
            "replacements": [
                {
                    "source": {"kind": "ConfigMap", "name": PARAMS_CONFIGMAP, "fieldPath": format!("data.{OPERATOR_IMAGE_PARAM}")},
                    "targets": [{
                        "select": {"kind": "Deployment", "name": NAME},
                        "fieldPaths": ["spec.template.spec.containers.[name=operator].image"],
                    }],
                },
                server_image_replacement(PARAMS_CONFIGMAP),
            ],
        }),
    )]
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use crate::objects::{DEFAULT_IMAGE, OPERATOR_IMAGE_PARAM, PARAMS_CONFIGMAP};
    use crate::odh::{overlay, params_env};
    use crate::openshift::{SERVER_IMAGE_PARAM, component};

    fn kustomization() -> serde_json::Value {
        overlay()
            .into_iter()
            .find(|(file, _)| *file == "kustomization.yaml")
            .expect("overlay has a kustomization")
            .1
    }

    #[test]
    fn the_platform_owns_the_namespace() {
        let k = kustomization();
        assert!(
            k.get("namespace").is_none(),
            "overlay must not pin a namespace"
        );
        assert_eq!(
            k["resources"],
            serde_json::json!(["../base"]),
            "../default would bring a Namespace object along"
        );
        for (file, value) in overlay().into_iter().chain(component()) {
            assert_ne!(value["kind"], "Namespace", "{file} is a Namespace");
            assert!(
                value["metadata"].get("namespace").is_none(),
                "{file} pins metadata.namespace"
            );
        }
    }

    /// The platform rewrites one params.env, so a key read from anywhere else
    /// would silently keep its default image.
    #[test]
    fn every_replaced_image_comes_from_the_overlay_params() {
        let params = params_env(DEFAULT_IMAGE);
        let keys: Vec<&str> = params
            .lines()
            .map(|line| line.split_once('=').expect("KEY=value").0)
            .collect();
        assert_eq!(keys, [OPERATOR_IMAGE_PARAM, SERVER_IMAGE_PARAM]);

        let k = kustomization();
        let replacements = k["replacements"].as_array().expect("replacements");
        assert_eq!(replacements.len(), keys.len(), "one replacement per image");
        for (replacement, key) in replacements.iter().zip(&keys) {
            assert_eq!(replacement["source"]["name"], PARAMS_CONFIGMAP);
            assert_eq!(replacement["source"]["fieldPath"], format!("data.{key}"));
        }
    }

    #[test]
    fn params_carry_the_requested_operator_image() {
        let image = "registry.example/operator@sha256:abc";
        assert!(params_env(image).contains(&format!("{OPERATOR_IMAGE_PARAM}={image}\n")));
    }

    /// `behavior: merge` fails the build unless the base generates a
    /// ConfigMap of this exact name, and the base kustomization is
    /// hand-written.
    #[test]
    fn params_merge_into_the_configmap_the_base_generates() {
        let k = kustomization();
        let generator = &k["configMapGenerator"][0];
        assert_eq!(generator["name"], PARAMS_CONFIGMAP);
        assert_eq!(generator["behavior"], "merge");
        assert_eq!(k["generatorOptions"]["disableNameSuffixHash"], true);

        let base = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../config/manifests/base/kustomization.yaml"),
        )
        .expect("base kustomization");
        assert!(base.contains(&format!("name: {PARAMS_CONFIGMAP}")));
        assert!(base.contains(&format!("data.{OPERATOR_IMAGE_PARAM}")));
    }
}
