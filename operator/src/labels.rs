// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Labels shared by everything the operator creates.
//!
//! Load-bearing: the controller's owned watches filter on
//! [`MANAGED_BY_SELECTOR`], so an object rendered without [`managed_labels`]
//! never produces a watch event.

use std::collections::BTreeMap;

pub const NAME_LABEL: &str = "app.kubernetes.io/name";
pub const INSTANCE_LABEL: &str = "app.kubernetes.io/instance";
pub const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";

pub const SERVER_NAME: &str = "modelexpress-server";
pub const MANAGED_BY: &str = "modelexpress-operator";

pub const MANAGED_BY_SELECTOR: &str = "app.kubernetes.io/managed-by=modelexpress-operator";

/// Immutable subset used for the Deployment and Service selectors; changing
/// these on an existing CR would orphan its pods.
pub fn selector_labels(cr_name: &str) -> BTreeMap<String, String> {
    [
        (NAME_LABEL.to_string(), SERVER_NAME.to_string()),
        (INSTANCE_LABEL.to_string(), cr_name.to_string()),
    ]
    .into_iter()
    .collect()
}

/// What every operator-owned object carries.
pub fn managed_labels(cr_name: &str) -> BTreeMap<String, String> {
    let mut labels = selector_labels(cr_name);
    labels.insert(MANAGED_BY_LABEL.to_string(), MANAGED_BY.to_string());
    labels
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn managed_labels_satisfy_the_watch_selector() {
        let (key, value) = MANAGED_BY_SELECTOR
            .split_once('=')
            .expect("selector is key=value");
        assert_eq!(key, MANAGED_BY_LABEL);
        assert_eq!(
            managed_labels("mx").get(key).map(String::as_str),
            Some(value),
            "an object missing this label never reaches the controller"
        );
    }

    #[test]
    fn managed_labels_are_a_superset_of_the_selector() {
        let managed = managed_labels("mx");
        for (key, value) in selector_labels("mx") {
            assert_eq!(managed.get(&key), Some(&value));
        }
    }
}
