// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use modelexpress_operator::app::{self, RunError};
use modelexpress_operator_openshift::apiserver::ApiServerTlsDefaults;
use modelexpress_operator_openshift::images::{SERVER_IMAGE_ENV, server_image};
use modelexpress_operator_openshift::servicemonitor;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), RunError> {
    let default_server_image = server_image(std::env::var(SERVER_IMAGE_ENV).ok());
    app::run(
        default_server_image,
        |client| Arc::new(ApiServerTlsDefaults::new(client)),
        servicemonitor::ensure,
    )
    .await
}
