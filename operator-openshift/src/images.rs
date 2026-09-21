// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Operand images from the operator's environment. The ODH operator injects
//! `RELATED_IMAGE_*` variables into this Deployment; the OpenShift overlay
//! sets the same variables from params.env for installs it does not manage.

/// The default server image for CRs that leave spec.image unset.
pub const SERVER_IMAGE_ENV: &str = "RELATED_IMAGE_ODH_MODELEXPRESS_IMAGE";

/// The default server image from `value`, the content of [`SERVER_IMAGE_ENV`].
/// Unset and blank both mean no default.
#[must_use]
pub fn server_image(value: Option<String>) -> Option<String> {
    value
        .map(|image| image.trim().to_string())
        .filter(|image| !image.is_empty())
}

#[cfg(test)]
mod tests {
    use crate::images::server_image;

    #[test]
    fn set_value_is_the_default() {
        assert_eq!(
            server_image(Some(
                "quay.io/opendatahub/odh-modelexpress@sha256:abc".into()
            )),
            Some("quay.io/opendatahub/odh-modelexpress@sha256:abc".to_string())
        );
    }

    #[test]
    fn surrounding_whitespace_is_trimmed() {
        assert_eq!(
            server_image(Some("  registry/image:tag\n".into())),
            Some("registry/image:tag".to_string())
        );
    }

    #[test]
    fn unset_and_blank_mean_no_default() {
        assert_eq!(server_image(None), None);
        assert_eq!(server_image(Some(String::new())), None);
        assert_eq!(server_image(Some("   ".into())), None);
    }
}
