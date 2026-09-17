// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use modelexpress_operator::app::{self, RunError};
use modelexpress_operator::tls::NoDefaults;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), RunError> {
    app::run(None, |_| Arc::new(NoDefaults)).await
}
