// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::auth::CallerIdentity;
use crate::cache::manifest::DownloadManifest;
use crate::metrics::grpc::RpcOutcome;
use crate::metrics::registry::{DownloadMetrics, RegistryMetrics, StatusLabel};
use crate::registry::backend::ClaimOutcome;
use crate::registry::entry_key::{EntryKey, Tenant, partition};
use crate::registry::state::RegistryManager;
use modelexpress_common::{
    cache::{CacheConfig, resolve_model_path},
    constants, download,
    grpc::{
        api::{ApiRequest, ApiResponse, api_service_server::ApiService},
        health::{HealthRequest, HealthResponse, health_service_server::HealthService},
        model::{
            DeleteModelRequest, DeleteModelResponse, FileChunk, ModelDownloadRequest,
            ModelFileInfo, ModelFileList, ModelFileSelector, ModelFilesRequest,
            ModelProvider as GrpcModelProvider, ModelStatusUpdate,
            model_service_server::ModelService,
        },
    },
    models::{ModelProvider, ModelStatus},
    providers::{is_weight_file, validate_revision},
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::SystemTime,
};
use tokio::io::AsyncReadExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info, warn};

static START_TIME: std::sync::OnceLock<SystemTime> = std::sync::OnceLock::new();

/// Ceiling on resolving a revision with the provider. This is a metadata lookup, not a
/// download, so it should complete quickly or not at all.
const REVISION_RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Get the configured cache root for model downloads
fn get_server_cache_dir() -> Option<std::path::PathBuf> {
    // Try to get cache configuration
    if let Ok(config) = CacheConfig::discover() {
        Some(config.local_path)
    } else {
        // Fall back to environment variable
        modelexpress_common::envs::hf_hub_cache()
    }
}

/// True when every file recorded for `target` in this cache is still present. Without a
/// cache directory there is nothing to check, so this returns true.
async fn model_files_present(cache_dir: Option<PathBuf>, target: &DownloadTarget) -> bool {
    let Some(cache_dir) = cache_dir else {
        return true;
    };
    let Some(manifest) = DownloadManifest::read(&cache_dir, &target.entry_key()) else {
        return false;
    };
    download::get_provider(target.provider)
        .get_model_path_revision(&target.model_name, cache_dir, target.revision.as_deref())
        .await
        .is_ok_and(|snapshot| manifest.is_satisfied_by(&snapshot))
}

/// Writes the manifest of the files the download of `entry_key` left in `snapshot`.
fn record_download(
    cache_dir: Option<&Path>,
    entry_key: &str,
    snapshot: &Path,
    ignore_weights: bool,
) -> anyhow::Result<()> {
    let Some(cache_dir) = cache_dir else {
        return Ok(());
    };
    DownloadManifest::new(
        entry_key,
        collect_model_files(snapshot, snapshot, None, ignore_weights),
    )
    .write(cache_dir)
}

/// A model download request reduced to the identity the registry and the provider need.
///
/// `revision` is always the *resolved*, immutable revision (a commit SHA for Hugging
/// Face), never the branch or tag the caller typed, so cache and lease identity cannot
/// drift when a tag moves.
#[derive(Debug, Clone)]
pub struct DownloadTarget {
    pub tenant: Option<Tenant>,
    pub model_name: String,
    pub provider: ModelProvider,
    pub revision: Option<String>,
    pub ignore_weights: bool,
}

impl DownloadTarget {
    /// The single string every registry backend keys this download on.
    fn entry_key(&self) -> String {
        EntryKey::new(
            self.model_name.clone(),
            self.revision.clone(),
            self.ignore_weights,
        )
        .in_tenant(self.tenant.clone())
        .to_string()
    }
}

/// `tenant`'s cache partition, or the cache root when isolation is off.
fn cache_dir_for(tenant: Option<&Tenant>) -> Option<PathBuf> {
    get_server_cache_dir().map(|root| partition(&root, tenant))
}

/// The request's revision, rejected unless it is a commit or a ref name.
#[allow(clippy::result_large_err)] // tonic::Status grew past Clippy's Rust 1.98 threshold.
fn requested_revision(revision: Option<&str>) -> Result<Option<&str>, Status> {
    if let Some(revision) = revision {
        validate_revision(revision).map_err(|e| Status::invalid_argument(format!("{e:#}")))?;
    }
    Ok(revision)
}

/// The cached snapshot of `model_name` under `cache_dir`, and its commit for Hugging Face.
/// Fails unless the snapshot is where the provider's cache layout puts it.
#[allow(clippy::result_large_err)] // tonic::Status grew past Clippy's Rust 1.98 threshold.
async fn cached_snapshot(
    provider: ModelProvider,
    model_name: &str,
    cache_dir: &Path,
    revision: Option<&str>,
) -> Result<(PathBuf, Option<String>), Status> {
    // Get the model path using the provider from the request. A requested revision
    // selects that exact snapshot instead of whichever one is newest on disk.
    let model_path = download::get_provider(provider)
        .get_model_path_revision(model_name, cache_dir.to_path_buf(), revision)
        .await
        .map_err(|e| Status::not_found(format!("Model not found: {e}")))?;

    debug!("Model path resolved to: {:?}", model_path);

    let commit_hash = if provider == ModelProvider::HuggingFace {
        model_path
            .file_name()
            .and_then(|name| name.to_str())
            .map(String::from)
    } else {
        None
    };

    if provider == ModelProvider::HuggingFace && commit_hash.is_none() {
        return Err(Status::internal(
            "Resolved Hugging Face model path did not contain a revision",
        ));
    }

    let expected_model_path =
        resolve_model_path(cache_dir, provider, model_name, commit_hash.as_deref()).map_err(
            |e| Status::internal(format!("Failed to resolve expected cache layout: {e}")),
        )?;

    if model_path != expected_model_path {
        error!(
            "Resolved model path '{}' does not match expected cache layout '{}' for model '{}'",
            model_path.display(),
            expected_model_path.display(),
            model_name
        );
        return Err(Status::internal(
            "Resolved model path does not match expected cache layout",
        ));
    }

    Ok((model_path, commit_hash))
}

/// Resolve a requested revision to the immutable revision the download will use.
///
/// A revision the caller pinned explicitly must resolve or the request fails: silently
/// serving the default revision instead would hand back a different model than asked
/// for. For an unpinned request we fall back to whatever snapshot is already cached,
/// so a Hub outage still serves models the server has downloaded before.
#[allow(clippy::result_large_err)] // tonic::Status grew past Clippy's Rust 1.98 threshold.
async fn resolve_target_revision(
    model_name: &str,
    provider: ModelProvider,
    cache_dir: Option<PathBuf>,
    requested: Option<&str>,
) -> Result<Option<String>, Status> {
    let provider_impl = download::get_provider(provider);

    // Pinning a revision on a provider that has none is a malformed request, not a
    // revision that happens to be missing.
    if requested.is_some() && !provider_impl.supports_revisions() {
        return Err(Status::invalid_argument(format!(
            "Provider '{}' does not support pinned revisions",
            provider_impl.provider_name()
        )));
    }

    // Resolution runs before the download lease is claimed, so an unresponsive provider
    // would otherwise hold the RPC open indefinitely without any download in progress.
    let resolve = provider_impl.resolve_revision(model_name, cache_dir.clone(), requested);
    let error = match tokio::time::timeout(REVISION_RESOLVE_TIMEOUT, resolve).await {
        Ok(Ok(resolved)) => return Ok(resolved),
        Ok(Err(e)) => e,
        Err(_) => anyhow::anyhow!("timed out after {}s", REVISION_RESOLVE_TIMEOUT.as_secs()),
    };

    if requested.is_some() {
        return Err(Status::not_found(format!(
            "Failed to resolve revision for model '{model_name}': {error:#}"
        )));
    }

    warn!(
        "Failed to resolve the default revision for '{model_name}': {error:#}; \
         falling back to the cached snapshot"
    );

    match provider_impl
        .get_model_path_revision(model_name, cache_dir.unwrap_or_default(), None)
        .await
        .ok()
        .and_then(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(String::from)
        }) {
        Some(cached) => Ok(Some(cached)),
        None => Err(Status::not_found(format!(
            "Failed to resolve revision for model '{model_name}': {error:#}"
        ))),
    }
}

/// Health service implementation
#[derive(Debug, Default)]
pub struct HealthServiceImpl;

#[tonic::async_trait]
impl HealthService for HealthServiceImpl {
    async fn get_health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        let start_time = START_TIME.get_or_init(SystemTime::now);
        let uptime = SystemTime::now()
            .duration_since(*start_time)
            .unwrap_or_default()
            .as_secs();

        let response = HealthResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            status: "ok".to_string(),
            uptime,
        };

        Ok(Response::new(response))
    }
}

/// API service implementation
#[derive(Debug, Default)]
pub struct ApiServiceImpl;

/// Return `body` with the handler's own verdict attached.
///
/// See [`crate::metrics::grpc`]. Mirrors the helper in `p2p/service.rs`; kept
/// local to each module so a handler's outcome is stated next to the handler.
#[allow(clippy::result_large_err)] // Returns the handlers' own tonic::Status result type.
fn tagged<T>(body: T, outcome: RpcOutcome) -> Result<Response<T>, Status> {
    let mut response = Response::new(body);
    response.extensions_mut().insert(outcome);
    Ok(response)
}

#[tonic::async_trait]
impl ApiService for ApiServiceImpl {
    async fn send_request(
        &self,
        request: Request<ApiRequest>,
    ) -> Result<Response<ApiResponse>, Status> {
        let api_request = request.into_inner();
        info!("Received gRPC request: {:?}", api_request);

        // Process the request based on the action
        if api_request.action.as_str() == "ping" {
            info!("Processing ping request");
            let response_data = serde_json::json!({ "message": "pong" });
            let data_bytes = serde_json::to_vec(&response_data)
                .map_err(|e| Status::internal(format!("Serialization error: {e}")))?;

            tagged(
                ApiResponse {
                    success: true,
                    data: Some(data_bytes),
                    error: None,
                },
                RpcOutcome::Ok,
            )
        } else {
            error!("Unknown action: {}", api_request.action);
            // In band, like the P2P handlers: `Ok` on the wire with
            // `success: false` in the body, so the outcome has to be stated
            // rather than inferred from the status code.
            tagged(
                ApiResponse {
                    success: false,
                    data: None,
                    error: Some(format!("Unknown action: {}", api_request.action)),
                },
                RpcOutcome::InvalidArgument,
            )
        }
    }
}

/// Model service implementation
#[derive(Clone)]
pub struct ModelServiceImpl {
    tracker: Arc<ModelDownloadTracker>,
    /// Confine every request to the caller's cache partition.
    tenant_isolation: bool,
}

impl ModelServiceImpl {
    /// Each server owns its tracker, so multiple servers can run in one process.
    pub fn new(tracker: Arc<ModelDownloadTracker>) -> Self {
        Self::with_tenant_isolation(tracker, false)
    }

    pub fn with_tenant_isolation(
        tracker: Arc<ModelDownloadTracker>,
        tenant_isolation: bool,
    ) -> Self {
        Self {
            tracker,
            tenant_isolation,
        }
    }

    /// The cache partition a request is confined to, or `None` when isolation is off.
    /// Fails with `UNAUTHENTICATED` when isolation is on and the request carries no
    /// verified caller.
    #[allow(clippy::result_large_err)] // Returns the handlers' own tonic::Status result type.
    fn scope<T>(&self, request: &Request<T>) -> Result<Option<Tenant>, Status> {
        if !self.tenant_isolation {
            return Ok(None);
        }
        let Some(caller) = request.extensions().get::<CallerIdentity>() else {
            error!(
                "tenant isolation is enabled but the request carries no verified caller \
                 identity; rejecting"
            );
            return Err(Status::unauthenticated(
                "tenant isolation requires an authenticated caller",
            ));
        };
        Tenant::new(&caller.namespace).map(Some).ok_or_else(|| {
            error!(
                "caller namespace '{}' is not a DNS-1123 label; rejecting",
                caller.namespace
            );
            Status::permission_denied("caller namespace is not a valid namespace")
        })
    }
}

/// Helper function to collect all files in a model directory recursively
fn collect_model_files(
    base_path: &Path,
    current_path: &Path,
    file_selector: Option<&ModelFileSelector>,
    ignore_weights: bool,
) -> Vec<(PathBuf, u64)> {
    let mut files = Vec::new();

    if let Ok(entries) = std::fs::read_dir(current_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(metadata) = std::fs::metadata(&path) {
                    // Get relative path from base_path
                    if let Ok(relative) = path.strip_prefix(base_path) {
                        // Validate that the relative path does not contain any '..' components or is absolute
                        let mut is_safe = true;
                        for comp in relative.components() {
                            use std::path::Component;
                            match comp {
                                Component::ParentDir
                                | Component::RootDir
                                | Component::Prefix(_) => {
                                    is_safe = false;
                                    break;
                                }
                                _ => {}
                            }
                        }
                        if !is_safe {
                            tracing::warn!(
                                "Skipping potentially unsafe file path: {:?} (relative: {:?})",
                                path,
                                relative
                            );
                        } else if ignore_weights
                            && is_weight_file(relative.to_string_lossy().as_ref())
                        {
                            // Weight file skipped because ignore_weights is set.
                        } else if file_selector.is_none_or(|selector| {
                            selector
                                .paths
                                .iter()
                                .any(|selector_path| Path::new(selector_path) == relative)
                        }) {
                            files.push((relative.to_path_buf(), metadata.len()));
                        }
                    }
                }
            } else if path.is_dir() {
                files.extend(collect_model_files(
                    base_path,
                    &path,
                    file_selector,
                    ignore_weights,
                ));
            }
        }
    }

    files
}

fn ensure_selected_files_exist(
    files: &[(PathBuf, u64)],
    file_selector: Option<&ModelFileSelector>,
) -> Result<(), String> {
    let Some(selector) = file_selector else {
        return Ok(());
    };

    if let Some(missing_path) = selector.paths.iter().find(|selector_path| {
        !files
            .iter()
            .any(|(path, _)| Path::new(selector_path) == path.as_path())
    }) {
        Err(format!(
            "Selected file not found in model directory: {missing_path}"
        ))
    } else {
        Ok(())
    }
}

#[tonic::async_trait]
impl ModelService for ModelServiceImpl {
    type EnsureModelDownloadedStream = ReceiverStream<Result<ModelStatusUpdate, Status>>;
    type StreamModelFilesStream = ReceiverStream<Result<FileChunk, Status>>;

    async fn ensure_model_downloaded(
        &self,
        request: Request<ModelDownloadRequest>,
    ) -> Result<Response<Self::EnsureModelDownloadedStream>, Status> {
        info!("Starting model download stream");
        let tenant = self.scope(&request)?;
        let model_request = request.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(4);

        // Convert gRPC provider to our enum
        let grpc_provider = GrpcModelProvider::try_from(model_request.provider).map_err(|_| {
            Status::invalid_argument(format!(
                "Invalid provider value: {}",
                model_request.provider
            ))
        })?;
        let provider = ModelProvider::from(grpc_provider);
        let model_name = download::canonical_model_name(&model_request.model_name, provider)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let ignore_weights = model_request.ignore_weights;

        // Resolve before claiming: the registry keys the download lease on the resolved
        // revision, so two revisions of one model never coalesce onto a single claim.
        let revision = resolve_target_revision(
            &model_name,
            provider,
            cache_dir_for(tenant.as_ref()),
            requested_revision(model_request.revision.as_deref())?,
        )
        .await?;

        let target = DownloadTarget {
            tenant,
            model_name: model_name.clone(),
            provider,
            revision: revision.clone(),
            ignore_weights,
        };

        // Spawn a task to handle the streaming download updates
        let tracker = self.tracker.clone();
        tokio::spawn(async move {
            // Run the full claim + wait + retry flow. `ensure_model_downloaded` sends
            // its own initial status update (based on the `ClaimOutcome` returned by the
            // registry), so we don't do a pre-check here — a pre-check would either
            // duplicate that update or, worse, emit `status=ERROR` on a model we're
            // about to retry and trip the client-lib's terminal-error bailout before
            // the retry completion broadcast arrives.
            let final_status = tracker.ensure_model_downloaded(&target, &tx).await;

            // Send final status update
            let final_update = ModelStatusUpdate {
                model_name: model_name.clone(),
                status: modelexpress_common::grpc::model::ModelStatus::from(final_status) as i32,
                message: match final_status {
                    ModelStatus::DOWNLOADED => {
                        Some("Model download completed successfully".to_string())
                    }
                    ModelStatus::ERROR => Some("Model download failed".to_string()),
                    ModelStatus::DOWNLOADING => Some("Download still in progress".to_string()),
                },
                provider: grpc_provider as i32,
                resolved_revision: revision,
            };

            let _ = tx.send(Ok(final_update)).await;
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn stream_model_files(
        &self,
        request: Request<ModelFilesRequest>,
    ) -> Result<Response<Self::StreamModelFilesStream>, Status> {
        let tenant = self.scope(&request)?;
        let files_request = request.into_inner();
        let chunk_size = if files_request.chunk_size == 0 {
            constants::DEFAULT_TRANSFER_CHUNK_SIZE
        } else {
            files_request.chunk_size as usize
        };

        // Convert gRPC provider to our enum
        let grpc_provider = GrpcModelProvider::try_from(files_request.provider).map_err(|_| {
            Status::invalid_argument(format!(
                "Invalid provider value: {}",
                files_request.provider
            ))
        })?;
        let provider = ModelProvider::from(grpc_provider);
        let model_name = download::canonical_model_name(&files_request.model_name, provider)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let revision = requested_revision(files_request.revision.as_deref())?;

        info!(
            "Starting file stream for model: {} with chunk size: {} bytes",
            model_name, chunk_size
        );

        let cache_dir = cache_dir_for(tenant.as_ref())
            .ok_or_else(|| Status::internal("Server cache directory not configured"))?;
        let (model_path, commit_hash) =
            cached_snapshot(provider, &model_name, &cache_dir, revision).await?;

        // Collect all files to stream
        let files = collect_model_files(
            &model_path,
            &model_path,
            files_request.file_selector.as_ref(),
            files_request.ignore_weights,
        );
        ensure_selected_files_exist(&files, files_request.file_selector.as_ref())
            .map_err(Status::not_found)?;

        if files.is_empty() {
            return Err(Status::not_found("No files found in model directory"));
        }

        let total_files = files.len();
        info!(
            "Found {} files to stream for model {}",
            total_files, model_name
        );

        let (tx, rx) = tokio::sync::mpsc::channel(16);

        // Spawn a task to stream files
        tokio::spawn(async move {
            // Allocate buffer once and reuse across all files
            let mut buffer = vec![0u8; chunk_size];
            let mut is_first_chunk = true;

            for (file_idx, (relative_path, total_size)) in files.iter().enumerate() {
                let file_path = model_path.join(relative_path);
                let is_last_file = file_idx == total_files.saturating_sub(1);

                debug!("Streaming file: {:?} ({} bytes)", relative_path, total_size);

                // Open the file
                let file = match tokio::fs::File::open(&file_path).await {
                    Ok(f) => f,
                    Err(e) => {
                        error!("Failed to open file {:?}: {}", file_path, e);
                        let _ = tx
                            .send(Err(Status::internal(format!("Failed to open file: {e}"))))
                            .await;
                        return;
                    }
                };

                let mut reader = tokio::io::BufReader::new(file);
                let mut offset: u64 = 0;

                if *total_size == 0 {
                    let first_chunk = std::mem::replace(&mut is_first_chunk, false);
                    let chunk = FileChunk {
                        relative_path: relative_path.to_string_lossy().to_string(),
                        data: Vec::new(),
                        offset: 0,
                        total_size: 0,
                        is_last_chunk: true,
                        is_last_file,
                        commit_hash: if first_chunk {
                            commit_hash.clone()
                        } else {
                            None
                        },
                    };

                    if tx.send(Ok(chunk)).await.is_err() {
                        debug!("Client disconnected during file stream");
                        return;
                    }

                    continue;
                }

                loop {
                    let bytes_read = match reader.read(&mut buffer).await {
                        Ok(0) => break, // EOF
                        Ok(n) => n,
                        Err(e) => {
                            error!("Failed to read file {:?}: {}", file_path, e);
                            let _ = tx
                                .send(Err(Status::internal(format!("Failed to read file: {e}"))))
                                .await;
                            return;
                        }
                    };

                    let is_last_chunk = offset.saturating_add(bytes_read as u64) >= *total_size;

                    let first_chunk = std::mem::replace(&mut is_first_chunk, false);

                    let chunk = FileChunk {
                        relative_path: relative_path.to_string_lossy().to_string(),
                        data: buffer[..bytes_read].to_vec(),
                        offset,
                        total_size: *total_size,
                        is_last_chunk,
                        is_last_file: is_last_file && is_last_chunk,
                        commit_hash: if first_chunk {
                            commit_hash.clone()
                        } else {
                            None
                        },
                    };

                    if tx.send(Ok(chunk)).await.is_err() {
                        debug!("Client disconnected during file stream");
                        return;
                    }

                    offset = offset.saturating_add(bytes_read as u64);
                }
            }

            info!("File streaming completed for model");
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn list_model_files(
        &self,
        request: Request<ModelFilesRequest>,
    ) -> Result<Response<ModelFileList>, Status> {
        let tenant = self.scope(&request)?;
        let files_request = request.into_inner();

        // Convert gRPC provider to our enum
        let grpc_provider = GrpcModelProvider::try_from(files_request.provider).map_err(|_| {
            Status::invalid_argument(format!(
                "Invalid provider value: {}",
                files_request.provider
            ))
        })?;
        let provider = ModelProvider::from(grpc_provider);
        let model_name = download::canonical_model_name(&files_request.model_name, provider)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let revision = requested_revision(files_request.revision.as_deref())?;

        info!("Listing files for model: {}", model_name);

        let cache_dir = cache_dir_for(tenant.as_ref())
            .ok_or_else(|| Status::internal("Server cache directory not configured"))?;
        let (model_path, _) = cached_snapshot(provider, &model_name, &cache_dir, revision).await?;

        // Collect all files
        let files = collect_model_files(
            &model_path,
            &model_path,
            files_request.file_selector.as_ref(),
            files_request.ignore_weights,
        );
        ensure_selected_files_exist(&files, files_request.file_selector.as_ref())
            .map_err(Status::not_found)?;

        let file_infos: Vec<ModelFileInfo> = files
            .iter()
            .map(|(path, size)| ModelFileInfo {
                relative_path: path.to_string_lossy().to_string(),
                size: *size,
            })
            .collect();

        let total_size: u64 = files.iter().map(|(_, size)| size).sum();

        Ok(Response::new(ModelFileList {
            model_name,
            files: file_infos,
            total_size,
        }))
    }

    async fn delete_model(
        &self,
        request: Request<DeleteModelRequest>,
    ) -> Result<Response<DeleteModelResponse>, Status> {
        let tenant = self.scope(&request)?;
        let delete_request = request.into_inner();

        let grpc_provider = GrpcModelProvider::try_from(delete_request.provider).map_err(|_| {
            Status::invalid_argument(format!(
                "Invalid provider value: {}",
                delete_request.provider
            ))
        })?;
        let provider = ModelProvider::from(grpc_provider);
        let model_name = download::canonical_model_name(&delete_request.model_name, provider)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        // A model can hold several entries at once (one per revision, and separate ones
        // for metadata-only downloads). `model clear` means "forget this model", so drop
        // all of them rather than only the unpinned full-weight entry.
        let tracker = self.tracker.clone();
        let outcome = tracker
            .delete_model_entries(tenant.as_ref(), &model_name)
            .await;
        let removed = outcome.removed;
        info!("Deleted {removed} registry record(s) for model '{model_name}'");

        // The response stays `success: true` -- the fallback delete was still
        // attempted and callers depend on that shape. But a registry outage and a
        // model with no entries both return zero records here, so without the tag
        // the RPC would be recorded as a plain success during an outage. That is
        // the exact failure this layer exists to prevent.
        tagged(
            DeleteModelResponse {
                success: true,
                message: Some(format!(
                    "Model '{model_name}' removed from registry ({removed} record(s))"
                )),
            },
            if outcome.degraded {
                RpcOutcome::BackendError
            } else {
                RpcOutcome::Ok
            },
        )
    }
}

/// What clearing a model's registry entries actually achieved.
///
/// `removed` alone cannot distinguish "this model had no entries" from "the
/// registry was unreachable and only the fallback key was tried" -- both are
/// zero.
pub struct DeleteEntriesOutcome {
    /// How many records were removed.
    pub removed: usize,
    /// The registry listing failed, so `removed` is a floor rather than a count.
    pub degraded: bool,
}

/// Type alias for the complex waiting channels type
type WaitingChannels =
    Arc<Mutex<HashMap<String, Vec<tokio::sync::mpsc::Sender<Result<ModelStatusUpdate, Status>>>>>>;

/// What a status update is routed by and what it reports.
///
/// Waiters are registered under the registry entry key, which carries the revision and
/// weight mode, while the update itself reports the plain model name the caller asked
/// for plus the revision it resolved to.
struct UpdateIdentity<'a> {
    entry_key: &'a str,
    model_name: &'a str,
    provider: ModelProvider,
    resolved_revision: Option<&'a str>,
}

impl UpdateIdentity<'_> {
    fn status_update(&self, status: ModelStatus, message: Option<String>) -> ModelStatusUpdate {
        ModelStatusUpdate {
            model_name: self.model_name.to_string(),
            status: modelexpress_common::grpc::model::ModelStatus::from(status) as i32,
            message,
            provider: GrpcModelProvider::from(self.provider) as i32,
            resolved_revision: self.resolved_revision.map(String::from),
        }
    }
}

/// Tracks the status of model downloads through the distributed registry backend.
#[derive(Clone)]
pub struct ModelDownloadTracker {
    /// Distributed registry (Redis today, K8s CRDs in a follow-up).
    registry: Arc<RegistryManager>,
    /// Maps model names to list of channels waiting for updates on this server replica.
    waiting_channels: WaitingChannels,
    download_metrics: DownloadMetrics,
    registry_metrics: RegistryMetrics,
}

const DOWNLOAD_LEASE_DURATION: std::time::Duration = std::time::Duration::from_secs(30);
const DOWNLOAD_HEARTBEAT_INTERVAL: tokio::time::Duration = tokio::time::Duration::from_secs(10);

impl ModelDownloadTracker {
    pub fn new(
        registry: Arc<RegistryManager>,
        download_metrics: DownloadMetrics,
        registry_metrics: RegistryMetrics,
    ) -> Self {
        Self {
            registry,
            waiting_channels: Arc::new(Mutex::new(HashMap::new())),
            download_metrics,
            registry_metrics,
        }
    }

    /// Number of models with callers currently waiting on a download.
    ///
    /// This map is never evicted wholesale, so its size is the early warning for
    /// the leak that would eventually OOM the server. A poisoned lock reports the
    /// recovered length rather than failing: a metric read must not be able to
    /// take down the download path.
    pub fn waiting_count(&self) -> usize {
        match self.waiting_channels.lock() {
            Ok(waiting) => waiting.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }

    async fn touch_and_log(&self, model_name: &str) {
        if let Err(e) = self.registry.touch_model(model_name).await {
            error!("Failed to touch model {model_name}: {e}");
        }
    }

    /// Gets the status of a model from the registry, bumping `last_used_at` on hit.
    /// Returns None on lookup failure (error logged) or unknown model.
    pub async fn get_status(&self, model_name: &str) -> Option<ModelStatus> {
        match self.registry.get_status(model_name).await {
            Ok(Some(status)) => {
                self.touch_and_log(model_name).await;
                Some(status)
            }
            Ok(None) => None,
            Err(e) => {
                error!("Failed to get model status from registry: {e}");
                None
            }
        }
    }

    /// Sets the status of a model and notifies all waiting channels on this replica.
    pub async fn set_status_and_notify(
        &self,
        model_name: String,
        status: ModelStatus,
        provider: ModelProvider,
        message: Option<String>,
    ) {
        if let Err(e) = self
            .registry
            .set_status(&model_name, provider, status, message.clone())
            .await
        {
            error!("Failed to update model status in registry: {e}");
            return;
        }
        self.notify_waiters(
            UpdateIdentity {
                entry_key: &model_name,
                model_name: &model_name,
                provider,
                resolved_revision: None,
            },
            status,
            message,
        );
    }

    fn notify_waiters(
        &self,
        identity: UpdateIdentity<'_>,
        status: ModelStatus,
        message: Option<String>,
    ) {
        let mut waiting = match self.waiting_channels.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("Waiting channels mutex is poisoned, recovering");
                poisoned.into_inner()
            }
        };
        if let Some(channels) = waiting.get(identity.entry_key) {
            let update = identity.status_update(status, message);
            for channel in channels {
                let _ = channel.try_send(Ok(update.clone()));
            }
            if status == ModelStatus::DOWNLOADED || status == ModelStatus::ERROR {
                waiting.remove(identity.entry_key);
            }
        }
    }

    /// Adds a channel that wants updates on a specific model (server-replica-local).
    pub fn add_waiting_channel(
        &self,
        model_name: &str,
        tx: tokio::sync::mpsc::Sender<Result<ModelStatusUpdate, Status>>,
    ) {
        let mut waiting = match self.waiting_channels.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("Waiting channels mutex is poisoned, recovering");
                poisoned.into_inner()
            }
        };
        waiting.entry(model_name.to_string()).or_default().push(tx);
    }

    /// Deletes a model record from the registry and clears local waiters.
    /// Returns whether the registry record was actually removed.
    ///
    /// The error is still swallowed -- callers proceed to notify waiters either
    /// way -- but the outcome is reported, because a caller that records the
    /// removal as a lifecycle event must not do so when nothing was removed.
    pub async fn delete_status(&self, model_name: &str) -> bool {
        let deleted = match self.registry.delete_model(model_name).await {
            Ok(()) => true,
            Err(e) => {
                error!("Failed to delete model from registry: {e}");
                false
            }
        };
        let mut waiting = match self.waiting_channels.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("Waiting channels mutex is poisoned, recovering");
                poisoned.into_inner()
            }
        };
        waiting.remove(model_name);
        deleted
    }

    /// Deletes every registry entry belonging to `model_name` in `tenant`'s partition,
    /// whatever revision or weight mode each entry covers.
    ///
    /// The registry-listing failure is swallowed on purpose: the fallback still
    /// clears the common case, which is better than refusing outright. It is
    /// reported in the return value so the caller can say so, because otherwise a
    /// backend outage and a model with no entries are the same `0`.
    pub async fn delete_model_entries(
        &self,
        tenant: Option<&Tenant>,
        model_name: &str,
    ) -> DeleteEntriesOutcome {
        let records = match self.registry.get_models_by_last_used(None).await {
            Ok(records) => records,
            Err(e) => {
                error!("Failed to list registry records for '{model_name}': {e}");
                // Fall back to the unpinned full-weight key so the common case still
                // clears rather than failing outright.
                let fallback = EntryKey::new(model_name, None, false)
                    .in_tenant(tenant.cloned())
                    .to_string();
                self.delete_status(&fallback).await;
                return DeleteEntriesOutcome {
                    removed: 0,
                    degraded: true,
                };
            }
        };

        let mut removed: usize = 0;
        for record in records {
            if EntryKey::parse(&record.model_name).belongs_to(tenant, model_name) {
                // Deleting a record mid-download is a real exit from DOWNLOADING,
                // and the only one the claim lifecycle cannot see: once the key
                // is gone, finish_download_claim finds nothing to fence and
                // returns false, so it records no departure. Without this the
                // arrival booked by the claim is never matched and the flow
                // accounting stays permanently ahead. The status is already in
                // hand here, so this costs no extra read.
                // Only once the record is really gone. delete_model can fail and
                // is swallowed, and recording first would book a departure for an
                // entry still sitting in DOWNLOADING -- turning a backend outage
                // into a permanently understated flow count.
                let deleted = self.delete_status(&record.model_name).await;
                if deleted && record.status == ModelStatus::DOWNLOADING {
                    self.registry_metrics
                        .record_transition(StatusLabel::Downloading, StatusLabel::Absent);
                }
                removed = removed.saturating_add(1);
            }
        }
        DeleteEntriesOutcome {
            removed,
            degraded: false,
        }
    }

    /// Spawn a background task that actually downloads the model, updating the tracker on
    /// success or failure. Extracted here so the claim and retry paths share the code.
    fn spawn_download_task(&self, target: DownloadTarget, retry: bool, claim_id: String) {
        let tracker = self.clone();
        tokio::spawn(async move {
            let started = std::time::Instant::now();
            let entry_key = target.entry_key();
            let cache_dir = cache_dir_for(target.tenant.as_ref());
            let DownloadTarget {
                model_name,
                provider,
                revision,
                ignore_weights,
                ..
            } = target;
            let download = download::download_model_revision(
                &model_name,
                provider,
                cache_dir.clone(),
                ignore_weights,
                revision.as_deref(),
            );
            tokio::pin!(download);
            let start = tokio::time::Instant::now()
                .checked_add(DOWNLOAD_HEARTBEAT_INTERVAL)
                .unwrap_or_else(tokio::time::Instant::now);
            let mut heartbeat = tokio::time::interval_at(start, DOWNLOAD_HEARTBEAT_INTERVAL);
            let result = loop {
                tokio::select! {
                    result = &mut download => break result,
                    _ = heartbeat.tick() => {
                        match tracker
                            .registry
                            .refresh_download_claim(
                                &entry_key,
                                provider,
                                &claim_id,
                                DOWNLOAD_LEASE_DURATION,
                            )
                            .await
                        {
                            Ok(true) => {}
                            Ok(false) => {
                                warn!(
                                    "Stopping download for {model_name}: lease ownership was lost"
                                );
                                return;
                            }
                            Err(e) => {
                                warn!("Failed to refresh download lease for {model_name}: {e}");
                            }
                        }
                    }
                }
            };

            let result = result.and_then(|outcome| {
                record_download(
                    cache_dir.as_deref(),
                    &entry_key,
                    &outcome.path,
                    ignore_weights,
                )
            });
            let (status, message) = match result {
                Ok(()) => (
                    ModelStatus::DOWNLOADED,
                    Some("Model download completed successfully".to_string()),
                ),
                Err(e) => {
                    if retry {
                        error!("Failed to download model {model_name} on retry: {e}");
                    } else {
                        error!("Failed to download model {model_name}: {e}");
                    }
                    let msg = if retry {
                        format!("Download failed on retry: {e}")
                    } else {
                        format!("Download failed: {e}")
                    };
                    (ModelStatus::ERROR, Some(msg))
                }
            };

            // Timed from the top of the task, so this is the whole download
            // rather than the registry write below it. Observed before the fence
            // check: the bytes were fetched regardless of whether this replica
            // still owns the right to publish the result.
            tracker
                .download_metrics
                .observe(StatusLabel::from(status), started.elapsed().as_secs_f64());

            match tracker
                .registry
                .finish_download_claim(&entry_key, provider, &claim_id, status, message.clone())
                .await
            {
                Ok(true) => {
                    tracker.notify_waiters(
                        UpdateIdentity {
                            entry_key: &entry_key,
                            model_name: &model_name,
                            provider,
                            resolved_revision: revision.as_deref(),
                        },
                        status,
                        message,
                    );
                }
                Ok(false) => {
                    warn!("Ignoring completion for {model_name}: lease ownership was lost");
                }
                Err(e) => {
                    error!("Failed to finish download claim for {model_name}: {e}");
                }
            }
        });
    }

    /// Initiates a download for a model and streams status updates.
    ///
    /// All registry operations key on the target's entry key rather than its model name,
    /// so a second revision (or a full-weight request behind a metadata-only one) claims
    /// its own lease instead of coalescing onto an unrelated download.
    pub async fn ensure_model_downloaded(
        &self,
        target: &DownloadTarget,
        tx: &tokio::sync::mpsc::Sender<Result<ModelStatusUpdate, Status>>,
    ) -> ModelStatus {
        let entry_key = target.entry_key();
        let entry_key = entry_key.as_str();
        let model_name = target.model_name.as_str();
        let provider = target.provider;
        let identity = UpdateIdentity {
            entry_key,
            model_name,
            provider,
            resolved_revision: target.revision.as_deref(),
        };

        // Atomically try to claim this model for download. The `ClaimOutcome` tells us
        // whether THIS replica won the claim or is observing someone else's claim —
        // status alone (`DOWNLOADING`) can't distinguish those cases across replicas.
        // A claim may report an existing `DOWNLOADED` record whose files no longer exist
        // on disk (e.g. after a client-side `model clear` that only removed local files).
        // When that happens we drop the stale record and re-claim once, so the download
        // path runs instead of returning a false success. Bounded to two attempts to
        // avoid looping if the delete or a concurrent re-claim keeps the record around.
        const MAX_CLAIM_ATTEMPTS: usize = 2;
        let mut claim_id = uuid::Uuid::new_v4().to_string();
        let mut attempt: usize = 0;
        let (status, is_owner) = loop {
            attempt = attempt.saturating_add(1);
            match self
                .registry
                .try_claim_for_download(entry_key, provider, &claim_id, DOWNLOAD_LEASE_DURATION)
                .await
            {
                // Both outcomes mean this replica owns the download; they differ
                // only in cost, which the metrics layer records separately.
                Ok(ClaimOutcome::Claimed | ClaimOutcome::TookOver) => {
                    break (ModelStatus::DOWNLOADING, true);
                }
                Ok(ClaimOutcome::AlreadyExists(ModelStatus::DOWNLOADED)) => {
                    if model_files_present(cache_dir_for(target.tenant.as_ref()), target).await {
                        // Returning an existing downloaded model is a cache hit for LRU purposes.
                        self.touch_and_log(entry_key).await;
                        break (ModelStatus::DOWNLOADED, false);
                    }
                    if attempt >= MAX_CLAIM_ATTEMPTS {
                        error!(
                            "Registry still reports model '{model_name}' as DOWNLOADED after \
                             clearing it, but its files are missing from the cache"
                        );
                        let _ = tx
                            .send(Ok(identity.status_update(
                                ModelStatus::ERROR,
                                Some(
                                    "Registry reports the model as downloaded but its files \
                                     are missing from the server cache"
                                        .to_string(),
                                ),
                            )))
                            .await;
                        return ModelStatus::ERROR;
                    }
                    error!(
                        "Registry reports model '{model_name}' as DOWNLOADED but its files \
                         are missing from the cache; clearing the stale record and \
                         re-downloading"
                    );
                    self.delete_status(entry_key).await;
                }
                Ok(ClaimOutcome::AlreadyExists(existing)) => break (existing, false),
                Err(e) => {
                    error!("Failed to claim model for download: {e}");
                    let error_update = identity.status_update(
                        ModelStatus::ERROR,
                        Some("Registry error occurred".to_string()),
                    );
                    let _ = tx.send(Ok(error_update)).await;
                    return ModelStatus::ERROR;
                }
            }
        };

        // If we observed a previous ERROR, attempt the ERROR -> DOWNLOADING CAS up front.
        // Only the CAS winner spawns the retry download; observers fall through to the
        // wait loop. Doing this *before* the initial stream update keeps the reported
        // status honest: after this block, the record is DOWNLOADING (the record may
        // briefly have been ERROR, but the client should wait, not bail).
        let (effective_status, is_retry_owner) = if status == ModelStatus::ERROR {
            let won = match self
                .registry
                .try_reset_error_for_retry(entry_key, provider, &claim_id, DOWNLOAD_LEASE_DURATION)
                .await
            {
                Ok(won) => won,
                Err(e) => {
                    error!("Failed to CAS status for retry: {e}");
                    let _ = tx
                        .send(Ok(identity.status_update(
                            ModelStatus::ERROR,
                            Some("Registry error occurred during retry".to_string()),
                        )))
                        .await;
                    return ModelStatus::ERROR;
                }
            };
            (ModelStatus::DOWNLOADING, won)
        } else {
            (status, false)
        };

        let update = identity.status_update(
            effective_status,
            match (status, effective_status) {
                (_, ModelStatus::DOWNLOADED) => Some("Model already downloaded".to_string()),
                (ModelStatus::ERROR, _) => Some("Previous download failed, retrying".to_string()),
                (_, ModelStatus::DOWNLOADING) => Some("Model download in progress".to_string()),
                // effective can never be ERROR: ERROR observations are CAS'd above.
                (_, ModelStatus::ERROR) => Some("Download error".to_string()),
            },
        );
        let _ = tx.send(Ok(update)).await;

        if effective_status == ModelStatus::DOWNLOADING {
            // Every caller is a waiter — whether we own the download or not, we still
            // need a channel so the completion broadcast reaches this stream.
            self.add_waiting_channel(entry_key, tx.clone());

            // Spawn the download only on the replica that won the claim (fresh
            // download) or won the ERROR-retry CAS. Everyone else waits.
            if is_owner || is_retry_owner {
                let retry = status == ModelStatus::ERROR;
                self.spawn_download_task(target.clone(), retry, claim_id);
                claim_id = uuid::Uuid::new_v4().to_string();
            }

            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                match self
                    .registry
                    .try_claim_for_download(entry_key, provider, &claim_id, DOWNLOAD_LEASE_DURATION)
                    .await
                {
                    // A taken-over lease must be re-driven exactly like a fresh
                    // claim. Letting it fall through instead would leave the entry
                    // wedged in DOWNLOADING with no owner running.
                    Ok(ClaimOutcome::Claimed | ClaimOutcome::TookOver) => {
                        self.spawn_download_task(target.clone(), false, claim_id);
                        claim_id = uuid::Uuid::new_v4().to_string();
                    }
                    Ok(ClaimOutcome::AlreadyExists(current_status))
                        if current_status != ModelStatus::DOWNLOADING =>
                    {
                        return current_status;
                    }
                    Ok(ClaimOutcome::AlreadyExists(_)) => {}
                    Err(e) => warn!("Failed to poll download lease for {model_name}: {e}"),
                }
            }
        }

        effective_status
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use crate::services::*;
    use modelexpress_common::grpc::{api::ApiRequest, health::HealthRequest};
    use modelexpress_common::test_support::{EnvVarGuard, acquire_env_mutex};
    use tempfile::TempDir;
    use tokio_stream::StreamExt;
    use tonic::Request;

    #[cfg(feature = "memory-backend")]
    use crate::registry::backend::{RegistryBackend, memory::InMemoryRegistryBackend};

    #[tokio::test]
    async fn test_health_service() {
        let service = HealthServiceImpl;
        let request = Request::new(HealthRequest {});

        let response = service.get_health(request).await;
        assert!(response.is_ok());

        let health_response = response.expect("Health response should be ok").into_inner();
        assert_eq!(health_response.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(health_response.status, "ok");
        // uptime is u64, always >= 0, so just verify it exists
        let _uptime = health_response.uptime;
    }

    /// The unknown-action path is an in-band failure and must not read as `ok`.
    #[tokio::test]
    async fn unknown_action_is_tagged_invalid_argument() {
        let service = ApiServiceImpl;
        let response = service
            .send_request(Request::new(ApiRequest {
                id: "test-id".to_string(),
                action: "not-a-real-action".to_string(),
                payload: None,
            }))
            .await
            .expect("the RPC itself succeeds");

        assert_eq!(
            response.extensions().get::<RpcOutcome>(),
            Some(&RpcOutcome::InvalidArgument)
        );
        assert!(!response.into_inner().success);
    }

    #[tokio::test]
    async fn test_api_service_ping() {
        let service = ApiServiceImpl;
        let request = Request::new(ApiRequest {
            id: "test-id".to_string(),
            action: "ping".to_string(),
            payload: None,
        });

        let response = service.send_request(request).await;
        assert!(response.is_ok());

        let api_response = response.expect("API response should be ok").into_inner();
        assert!(api_response.success);
        assert!(api_response.data.is_some());
        assert!(api_response.error.is_none());

        // Check that the response data contains "pong"
        let data_bytes = api_response.data.expect("Data should be present");
        let data: serde_json::Value =
            serde_json::from_slice(&data_bytes).expect("Data should be valid JSON");
        assert_eq!(data["message"], "pong");
    }

    #[tokio::test]
    async fn test_api_service_unknown_action() {
        let service = ApiServiceImpl;
        let request = Request::new(ApiRequest {
            id: "test-id".to_string(),
            action: "unknown-action".to_string(),
            payload: None,
        });

        let response = service.send_request(request).await;
        assert!(response.is_ok());

        let api_response = response.expect("API response should be ok").into_inner();
        assert!(!api_response.success);
        assert!(api_response.data.is_none());
        assert!(api_response.error.is_some());

        let error_message = api_response.error.expect("Error should be present");
        assert!(error_message.contains("Unknown action"));
    }

    // Tracker tests exercise the ModelDownloadTracker's interaction with a mocked
    // RegistryBackend. The full backend semantics (claim atomicity, LRU ordering, etc.) are
    // covered by the per-backend unit tests in modelexpress_server::registry and by the
    // testcontainers-based integration tests.
    fn tracker_with_mock(
        mock: crate::registry::backend::MockRegistryBackend,
    ) -> ModelDownloadTracker {
        let registry = Arc::new(RegistryManager::with_backend(Arc::new(mock)));
        ModelDownloadTracker::new(
            registry,
            DownloadMetrics::register(&mut crate::metrics::new_registry()),
            RegistryMetrics::register(&mut crate::metrics::new_registry()),
        )
    }

    /// As [`tracker_with_mock`], but hands back the Prometheus registry the metric
    /// families were registered into.
    ///
    /// [`tracker_with_mock`] registers into a temporary registry that is dropped on
    /// the spot, so nothing recorded through it can ever be encoded. Any metric
    /// assertion against a tracker built that way would be vacuous by construction.
    fn tracker_with_mock_and_registry(
        mock: crate::registry::backend::MockRegistryBackend,
    ) -> (ModelDownloadTracker, prometheus_client::registry::Registry) {
        let mut metrics_registry = crate::metrics::new_registry();
        let download_metrics = DownloadMetrics::register(&mut metrics_registry);
        let registry_metrics = RegistryMetrics::register(&mut metrics_registry);
        let registry = Arc::new(RegistryManager::with_backend(Arc::new(mock)));
        (
            ModelDownloadTracker::new(registry, download_metrics, registry_metrics),
            metrics_registry,
        )
    }

    fn encoded_metrics(registry: &prometheus_client::registry::Registry) -> String {
        crate::metrics::encode_text(registry).unwrap_or_else(|_| String::from("<encode failed>"))
    }

    /// The `downloading -> absent` series, or 0 when it was never created.
    fn departures_from_downloading(encoded: &str) -> i64 {
        encoded
            .lines()
            .find_map(|line| {
                line.strip_prefix(
                    r#"mx_registry_status_transitions_total{from="downloading",to="absent"} "#,
                )
            })
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or_default()
    }

    fn record_with_status(
        model_name: &str,
        status: ModelStatus,
    ) -> crate::registry::backend::ModelRecord {
        let now = chrono::Utc::now();
        crate::registry::backend::ModelRecord {
            model_name: model_name.to_string(),
            provider: ModelProvider::HuggingFace,
            status,
            created_at: now,
            last_used_at: now,
            message: None,
        }
    }

    /// Unpinned, full-weight target: its entry key is the bare model name.
    fn test_target(model_name: &str) -> DownloadTarget {
        DownloadTarget {
            tenant: None,
            model_name: model_name.to_string(),
            provider: ModelProvider::HuggingFace,
            revision: None,
            ignore_weights: false,
        }
    }

    #[tokio::test]
    async fn test_tracker_get_status_missing_returns_none() {
        let mut mock = crate::registry::backend::MockRegistryBackend::new();
        mock.expect_get_status().once().returning(|_| Ok(None));
        // touch is NOT called when status is missing
        let tracker = tracker_with_mock(mock);
        assert!(tracker.get_status("unknown").await.is_none());
    }

    #[tokio::test]
    async fn test_tracker_get_status_hit_bumps_last_used_at() {
        let mut mock = crate::registry::backend::MockRegistryBackend::new();
        mock.expect_get_status()
            .once()
            .returning(|_| Ok(Some(ModelStatus::DOWNLOADED)));
        mock.expect_touch_model().once().returning(|_| Ok(()));
        let tracker = tracker_with_mock(mock);
        assert_eq!(tracker.get_status("m").await, Some(ModelStatus::DOWNLOADED));
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_tracker_downloaded_cache_hit_bumps_last_used_at() {
        let env_lock = acquire_env_mutex();
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let _cache_dir_guard = EnvVarGuard::set(
            &env_lock,
            "MODEL_EXPRESS_CACHE_DIRECTORY",
            temp_dir.path().to_str().expect("Expected temp dir path"),
        );
        let _offline_guard = EnvVarGuard::set(&env_lock, "HF_HUB_OFFLINE", "1");
        install(temp_dir.path(), &test_target("test/model"), &all_files());

        let mut mock = crate::registry::backend::MockRegistryBackend::new();
        mock.expect_try_claim_for_download()
            .with(
                mockall::predicate::eq("test/model"),
                mockall::predicate::eq(ModelProvider::HuggingFace),
                mockall::predicate::always(),
                mockall::predicate::always(),
            )
            .once()
            .returning(|_, _, _, _| Ok(ClaimOutcome::AlreadyExists(ModelStatus::DOWNLOADED)));
        mock.expect_touch_model()
            .with(mockall::predicate::eq("test/model"))
            .once()
            .returning(|_| Ok(()));
        let tracker = tracker_with_mock(mock);
        let (tx, _rx) = tokio::sync::mpsc::channel(1);

        assert_eq!(
            tracker
                .ensure_model_downloaded(&test_target("test/model"), &tx)
                .await,
            ModelStatus::DOWNLOADED
        );
    }

    /// Claim, touch, and report a cache hit for `target`, asserting the registry was
    /// keyed on the target's entry key rather than on the bare model name.
    async fn assert_claims_on_entry_key(target: DownloadTarget) {
        let expected_key = target.entry_key();
        assert_ne!(
            expected_key, target.model_name,
            "This target must not reduce to the bare model name, or the test proves nothing"
        );
        let mut mock = crate::registry::backend::MockRegistryBackend::new();
        mock.expect_try_claim_for_download()
            .with(
                mockall::predicate::eq(expected_key.clone()),
                mockall::predicate::eq(ModelProvider::HuggingFace),
                mockall::predicate::always(),
                mockall::predicate::always(),
            )
            .once()
            .returning(|_, _, _, _| Ok(ClaimOutcome::AlreadyExists(ModelStatus::DOWNLOADED)));
        mock.expect_touch_model()
            .with(mockall::predicate::eq(expected_key))
            .once()
            .returning(|_| Ok(()));

        let tracker = tracker_with_mock(mock);
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);

        assert_eq!(
            tracker.ensure_model_downloaded(&target, &tx).await,
            ModelStatus::DOWNLOADED
        );

        // Clients see the model name they asked for, not the internal registry key.
        let update = rx
            .recv()
            .await
            .expect("Expected a status update")
            .expect("Expected an ok status update");
        assert_eq!(update.model_name, target.model_name);
        assert_eq!(update.resolved_revision, target.revision);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_tracker_scopes_the_lease_to_the_resolved_revision() {
        let env_lock = acquire_env_mutex();
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let _cache_dir_guard = EnvVarGuard::set(
            &env_lock,
            "MODEL_EXPRESS_CACHE_DIRECTORY",
            temp_dir.path().to_str().expect("Expected temp dir path"),
        );
        let _offline_guard = EnvVarGuard::set(&env_lock, "HF_HUB_OFFLINE", "1");
        let target = pinned_target(false);
        install(temp_dir.path(), &target, &all_files());

        assert_claims_on_entry_key(target).await;
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_tracker_separates_metadata_only_from_full_weight_downloads() {
        let env_lock = acquire_env_mutex();
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let _cache_dir_guard = EnvVarGuard::set(
            &env_lock,
            "MODEL_EXPRESS_CACHE_DIRECTORY",
            temp_dir.path().to_str().expect("Expected temp dir path"),
        );
        let _offline_guard = EnvVarGuard::set(&env_lock, "HF_HUB_OFFLINE", "1");
        let target = DownloadTarget {
            ignore_weights: true,
            ..test_target("test/model")
        };
        install(temp_dir.path(), &target, METADATA_FILES);

        // A metadata-only entry must not be the same registry record as a full-weight
        // one, or a weightless snapshot would satisfy a request that needs weights.
        assert_claims_on_entry_key(target).await;
    }

    #[tokio::test]
    async fn test_tracker_set_status_notifies_waiting_channel() {
        let mut mock = crate::registry::backend::MockRegistryBackend::new();
        mock.expect_set_status()
            .once()
            .returning(|_, _, _, _| Ok(()));
        let tracker = tracker_with_mock(mock);

        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        tracker.add_waiting_channel("m", tx);

        tracker
            .set_status_and_notify(
                "m".to_string(),
                ModelStatus::DOWNLOADED,
                ModelProvider::HuggingFace,
                Some("done".to_string()),
            )
            .await;

        let update = rx.recv().await.expect("waiter should receive update");
        let update = update.expect("notify should send Ok");
        assert_eq!(update.model_name, "m");
        assert_eq!(
            update.status,
            modelexpress_common::grpc::model::ModelStatus::Downloaded as i32
        );
        assert_eq!(update.message.as_deref(), Some("done"));

        // Terminal status removes waiters.
        let waiters = tracker
            .waiting_channels
            .lock()
            .expect("waiters lock")
            .get("m")
            .map_or(0, std::vec::Vec::len);
        assert_eq!(waiters, 0);
    }

    #[tokio::test]
    async fn test_tracker_delete_status_clears_backend_and_waiters() {
        let mut mock = crate::registry::backend::MockRegistryBackend::new();
        mock.expect_delete_model().once().returning(|_| Ok(()));
        let tracker = tracker_with_mock(mock);

        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        tracker.add_waiting_channel("m", tx);
        tracker.delete_status("m").await;

        let waiters = tracker
            .waiting_channels
            .lock()
            .expect("waiters lock")
            .contains_key("m");
        assert!(!waiters);
    }

    /// The bool `delete_status` returns is the sole gate on the `downloading ->
    /// absent` departure, and no caller is forced to read it -- there is no
    /// `#[must_use]` and two of the three call sites discard it. So the contract
    /// is pinned here directly rather than only through the delete-path tests
    /// below, which would still pass if the two arms were swapped in step.
    #[tokio::test]
    async fn delete_status_reports_whether_the_backend_removed_the_record() {
        let mut removed = crate::registry::backend::MockRegistryBackend::new();
        removed.expect_delete_model().once().returning(|_| Ok(()));
        assert!(
            tracker_with_mock(removed).delete_status("m").await,
            "a successful delete must report true"
        );

        let mut failed = crate::registry::backend::MockRegistryBackend::new();
        failed
            .expect_delete_model()
            .once()
            .returning(|_| Err("backend unreachable".into()));
        assert!(
            !tracker_with_mock(failed).delete_status("m").await,
            "the error is still swallowed, but it must not report a removal"
        );
    }

    /// `model clear` on an entry that is still downloading is the third exit from
    /// `DOWNLOADING`, and the only one the claim lifecycle cannot observe for
    /// itself: once the record is gone `finish_download_claim` finds nothing to
    /// fence and records no departure, so the deleting side has to book it.
    /// Without this the arrival booked by the claim is never matched and the flow
    /// accounting stays permanently ahead by one per deleted download.
    #[tokio::test]
    async fn deleting_a_downloading_entry_books_a_departure() {
        let mut mock = crate::registry::backend::MockRegistryBackend::new();
        mock.expect_get_models_by_last_used()
            .once()
            .returning(|_| Ok(vec![record_with_status("m", ModelStatus::DOWNLOADING)]));
        mock.expect_delete_model().once().returning(|_| Ok(()));

        let (tracker, metrics_registry) = tracker_with_mock_and_registry(mock);
        let outcome = tracker.delete_model_entries(None, "m").await;
        assert_eq!(outcome.removed, 1);
        assert!(!outcome.degraded);

        let encoded = encoded_metrics(&metrics_registry);
        assert_eq!(
            departures_from_downloading(&encoded),
            1,
            "a deleted download must not stay counted as in flight: {encoded}"
        );
    }

    /// `delete_model` failing is swallowed so waiters are still notified, which is
    /// exactly why the departure has to be gated on the outcome. Booking it anyway
    /// would report a departure for an entry still sitting in `DOWNLOADING` and
    /// leave the flow count permanently short during a backend outage.
    #[tokio::test]
    async fn a_failed_delete_books_no_departure() {
        let mut mock = crate::registry::backend::MockRegistryBackend::new();
        mock.expect_get_models_by_last_used()
            .once()
            .returning(|_| Ok(vec![record_with_status("m", ModelStatus::DOWNLOADING)]));
        mock.expect_delete_model()
            .once()
            .returning(|_| Err("backend unreachable".into()));

        let (tracker, metrics_registry) = tracker_with_mock_and_registry(mock);
        tracker.delete_model_entries(None, "m").await;

        let encoded = encoded_metrics(&metrics_registry);
        assert_eq!(
            departures_from_downloading(&encoded),
            0,
            "a swallowed delete failure must not book a departure: {encoded}"
        );
    }

    /// Ordinary cache eviction clears `DOWNLOADED` entries. Those never occupied
    /// the in-flight level, so counting them as departures would drive the
    /// derivation negative on the most common delete there is.
    #[tokio::test]
    async fn deleting_a_downloaded_entry_books_no_departure() {
        let mut mock = crate::registry::backend::MockRegistryBackend::new();
        mock.expect_get_models_by_last_used()
            .once()
            .returning(|_| Ok(vec![record_with_status("m", ModelStatus::DOWNLOADED)]));
        mock.expect_delete_model().once().returning(|_| Ok(()));

        let (tracker, metrics_registry) = tracker_with_mock_and_registry(mock);
        let outcome = tracker.delete_model_entries(None, "m").await;
        assert_eq!(outcome.removed, 1, "the record is still removed");

        let encoded = encoded_metrics(&metrics_registry);
        assert_eq!(
            departures_from_downloading(&encoded),
            0,
            "a completed model was never in flight: {encoded}"
        );
    }

    /// `waiting_count` is the sole input to `mx_state_entries{map="download_waiters"}`,
    /// the gauge registered as "the OOM early warning". Stuck-at-zero is the failure
    /// mode that matters: the map leaks, the server heads for OOM, and the metric
    /// built to warn about it reads flat the whole way. The refresh task's own test
    /// substitutes a stub closure, so nothing else executes this function.
    #[tokio::test]
    async fn waiting_count_tracks_the_waiter_map() {
        let mut mock = crate::registry::backend::MockRegistryBackend::new();
        mock.expect_delete_model().once().returning(|_| Ok(()));
        let tracker = tracker_with_mock(mock);
        assert_eq!(tracker.waiting_count(), 0);

        let (tx_a, _rx_a) = tokio::sync::mpsc::channel(1);
        tracker.add_waiting_channel("a", tx_a);
        let (tx_b, _rx_b) = tokio::sync::mpsc::channel(1);
        tracker.add_waiting_channel("b", tx_b);
        // Keyed by model, so a second waiter on "a" does not add an entry.
        let (tx_a2, _rx_a2) = tokio::sync::mpsc::channel(1);
        tracker.add_waiting_channel("a", tx_a2);
        assert_eq!(tracker.waiting_count(), 2);

        tracker.delete_status("a").await;
        assert_eq!(tracker.waiting_count(), 1);
    }

    /// The download histogram registers and exports whether or not anything ever
    /// observes into it, so an empty series is the deceptive failure mode: the
    /// scrape looks healthy and simply reports zero downloads. This drives the
    /// real task to its terminal status and checks a sample landed.
    ///
    /// `finish_download_claim` returns `Ok(false)` on purpose -- this replica was
    /// fenced. The bytes were still fetched, so the observation has to happen
    /// before the fence check; returning `Ok(true)` here would leave that ordering
    /// unpinned.
    ///
    /// No network: the NGC provider rejects a model name that is not
    /// `org/name/version` before it opens a client or touches the filesystem, so
    /// the download future resolves to `Err` immediately and the task takes the
    /// `ERROR` outcome.
    #[tokio::test]
    async fn a_finished_download_is_observed_into_the_histogram_even_when_fenced() {
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let done_tx = Mutex::new(Some(done_tx));

        let mut mock = crate::registry::backend::MockRegistryBackend::new();
        mock.expect_finish_download_claim()
            .once()
            .returning(move |_, _, _, status, _| {
                assert_eq!(status, ModelStatus::ERROR);
                if let Ok(mut slot) = done_tx.lock()
                    && let Some(tx) = slot.take()
                {
                    let _ = tx.send(());
                }
                // Fenced: someone else owns the claim now.
                Ok(false)
            });

        let (tracker, metrics_registry) = tracker_with_mock_and_registry(mock);
        tracker.spawn_download_task(
            DownloadTarget {
                tenant: None,
                model_name: "not-a-valid-ngc-artifact".to_string(),
                provider: ModelProvider::Ngc,
                revision: None,
                ignore_weights: false,
            },
            false,
            "claim-1".to_string(),
        );
        done_rx.await.expect("the download task reaches the finish");

        let encoded = encoded_metrics(&metrics_registry);
        assert!(
            encoded.contains(r#"mx_download_seconds_count{outcome="error"} 1"#),
            "a failed download must be observed under its terminal status: {encoded}"
        );
    }

    #[tokio::test]
    async fn test_tracker_error_status_clears_waiters() {
        let mut mock = crate::registry::backend::MockRegistryBackend::new();
        mock.expect_set_status()
            .once()
            .returning(|_, _, _, _| Ok(()));
        let tracker = tracker_with_mock(mock);
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        tracker.add_waiting_channel("m", tx);
        tracker
            .set_status_and_notify(
                "m".to_string(),
                ModelStatus::ERROR,
                ModelProvider::HuggingFace,
                Some("fail".to_string()),
            )
            .await;
        let waiters = tracker
            .waiting_channels
            .lock()
            .expect("waiters lock")
            .get("m")
            .map_or(0, std::vec::Vec::len);
        assert_eq!(waiters, 0, "ERROR is terminal, waiters must be cleared");
    }

    #[tokio::test]
    async fn test_tracker_downloading_status_keeps_waiters() {
        let mut mock = crate::registry::backend::MockRegistryBackend::new();
        mock.expect_set_status()
            .once()
            .returning(|_, _, _, _| Ok(()));
        let tracker = tracker_with_mock(mock);
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        tracker.add_waiting_channel("m", tx);
        tracker
            .set_status_and_notify(
                "m".to_string(),
                ModelStatus::DOWNLOADING,
                ModelProvider::HuggingFace,
                None,
            )
            .await;
        let waiters = tracker
            .waiting_channels
            .lock()
            .expect("waiters lock")
            .get("m")
            .map_or(0, std::vec::Vec::len);
        assert_eq!(
            waiters, 1,
            "DOWNLOADING is non-terminal, waiter must remain"
        );
    }

    #[tokio::test]
    async fn test_tracker_set_status_swallows_backend_error() {
        let mut mock = crate::registry::backend::MockRegistryBackend::new();
        mock.expect_set_status()
            .once()
            .returning(|_, _, _, _| Err("redis down".into()));
        let tracker = tracker_with_mock(mock);
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        tracker.add_waiting_channel("m", tx);
        // Error is logged but set_status_and_notify returns ()
        tracker
            .set_status_and_notify(
                "m".to_string(),
                ModelStatus::DOWNLOADED,
                ModelProvider::HuggingFace,
                None,
            )
            .await;
        // Nothing should be notified on the channel because set_status failed early.
        assert!(
            rx.try_recv().is_err(),
            "waiter shouldn't receive on backend error"
        );
    }

    /// Model service for the file-serving tests, which don't touch the tracker. A
    /// no-expectation mock backend keeps them off the `memory-backend` feature.
    fn test_model_service() -> ModelServiceImpl {
        let registry = Arc::new(RegistryManager::with_backend(Arc::new(
            crate::registry::backend::MockRegistryBackend::new(),
        )));
        ModelServiceImpl::new(Arc::new(ModelDownloadTracker::new(
            registry,
            DownloadMetrics::register(&mut crate::metrics::new_registry()),
            RegistryMetrics::register(&mut crate::metrics::new_registry()),
        )))
    }

    #[test]
    fn test_collect_model_files_empty_dir() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let files = collect_model_files(temp_dir.path(), temp_dir.path(), None, false);
        assert!(files.is_empty());
    }

    #[test]
    fn test_collect_model_files_with_files() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        // Create some test files
        let file1_path = temp_dir.path().join("config.json");
        std::fs::write(&file1_path, r#"{"test": "data"}"#).expect("Failed to write file1");

        let file2_path = temp_dir.path().join("model.bin");
        std::fs::write(&file2_path, vec![0u8; 100]).expect("Failed to write file2");

        let files = collect_model_files(temp_dir.path(), temp_dir.path(), None, false);

        assert_eq!(files.len(), 2);

        // Check file sizes
        let total_size: u64 = files.iter().map(|(_, size)| size).sum();
        assert!(total_size > 0);

        // Check that relative paths are correct
        let paths: Vec<_> = files
            .iter()
            .map(|(p, _)| p.to_string_lossy().to_string())
            .collect();
        assert!(paths.contains(&"config.json".to_string()));
        assert!(paths.contains(&"model.bin".to_string()));
    }

    #[test]
    fn test_collect_model_files_ignore_weights() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        // Mix of non-weight and weight files, including a nested weight shard.
        std::fs::write(temp_dir.path().join("config.json"), "{}").expect("write config");
        std::fs::write(temp_dir.path().join("tokenizer.json"), "{}").expect("write tokenizer");
        std::fs::write(temp_dir.path().join("model.safetensors"), vec![0u8; 10])
            .expect("write safetensors");
        std::fs::write(temp_dir.path().join("pytorch_model.bin"), vec![0u8; 10])
            .expect("write bin");
        let subdir = temp_dir.path().join("subdir");
        std::fs::create_dir(&subdir).expect("create subdir");
        std::fs::write(
            subdir.join("model-00001-of-00002.safetensors"),
            vec![0u8; 10],
        )
        .expect("write nested shard");

        // ignore_weights = false streams everything.
        let all = collect_model_files(temp_dir.path(), temp_dir.path(), None, false);
        assert_eq!(all.len(), 5);

        // ignore_weights = true keeps only the non-weight files (config + tokenizer),
        // dropping weight shards at any depth.
        let no_weights = collect_model_files(temp_dir.path(), temp_dir.path(), None, true);
        let names: Vec<String> = no_weights
            .iter()
            .map(|(p, _)| p.to_string_lossy().to_string())
            .collect();
        assert_eq!(
            no_weights.len(),
            2,
            "expected only non-weight files: {names:?}"
        );
        assert!(names.contains(&"config.json".to_string()));
        assert!(names.contains(&"tokenizer.json".to_string()));
        assert!(
            names
                .iter()
                .all(|n| !n.ends_with(".safetensors") && !n.ends_with(".bin")),
            "weight files must be excluded: {names:?}"
        );
    }

    #[test]
    fn test_collect_model_files_nested() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");

        // Create nested directory structure
        let subdir = temp_dir.path().join("subdir");
        std::fs::create_dir(&subdir).expect("Failed to create subdir");

        let file1_path = temp_dir.path().join("root_file.txt");
        std::fs::write(&file1_path, "root content").expect("Failed to write file1");

        let file2_path = subdir.join("nested_file.txt");
        std::fs::write(&file2_path, "nested content").expect("Failed to write file2");

        let files = collect_model_files(temp_dir.path(), temp_dir.path(), None, false);

        assert_eq!(files.len(), 2);

        // Check that nested path is correct
        let paths: Vec<_> = files
            .iter()
            .map(|(p, _)| p.to_string_lossy().to_string())
            .collect();
        assert!(paths.iter().any(|p| p.contains("nested_file")));
    }

    #[test]
    fn test_collect_model_files_with_selector_filters_exact_paths() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let subdir = temp_dir.path().join("subdir");
        std::fs::create_dir(&subdir).expect("Failed to create subdir");
        std::fs::write(temp_dir.path().join("config.json"), "{}").expect("Failed to write config");
        std::fs::write(temp_dir.path().join("model.bin"), vec![0u8; 100])
            .expect("Failed to write model");
        std::fs::write(temp_dir.path().join("ignored.txt"), "ignore")
            .expect("Failed to write ignored");
        std::fs::write(subdir.join("nested.txt"), "nested").expect("Failed to write nested");

        let selector = ModelFileSelector {
            paths: vec!["config.json".to_string(), "subdir/nested.txt".to_string()],
        };
        let files = collect_model_files(temp_dir.path(), temp_dir.path(), Some(&selector), false);

        let mut paths: Vec<_> = files
            .iter()
            .map(|(p, _)| p.to_string_lossy().to_string())
            .collect();
        paths.sort();
        assert_eq!(
            paths,
            vec!["config.json".to_string(), "subdir/nested.txt".to_string()]
        );
    }

    #[test]
    fn test_collect_model_files_with_selector_empty_and_nonmatching_paths() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        std::fs::write(temp_dir.path().join("config.json"), "{}").expect("Failed to write config");

        let empty_selector = ModelFileSelector { paths: vec![] };
        assert!(
            collect_model_files(
                temp_dir.path(),
                temp_dir.path(),
                Some(&empty_selector),
                false
            )
            .is_empty()
        );

        let nonmatching_selector = ModelFileSelector {
            paths: vec!["missing.json".to_string(), "../config.json".to_string()],
        };
        assert!(
            collect_model_files(
                temp_dir.path(),
                temp_dir.path(),
                Some(&nonmatching_selector),
                false
            )
            .is_empty()
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_list_model_files_hf_honors_file_selector() {
        let env_lock = acquire_env_mutex();
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let _cache_dir_guard = EnvVarGuard::set(
            &env_lock,
            "MODEL_EXPRESS_CACHE_DIRECTORY",
            temp_dir.path().to_str().expect("Expected temp dir path"),
        );
        let _offline_guard = EnvVarGuard::set(&env_lock, "HF_HUB_OFFLINE", "1");

        let model_dir = temp_dir.path().join("models--test--model/snapshots/abc123");
        std::fs::create_dir_all(model_dir.join("subdir")).expect("Failed to create model dir");
        std::fs::write(model_dir.join("config.json"), br#"{"model":"test"}"#)
            .expect("Failed to write config");
        std::fs::write(model_dir.join("model.bin"), vec![0u8; 100]).expect("Failed to write model");
        std::fs::write(model_dir.join("subdir/nested.txt"), b"nested")
            .expect("Failed to write nested");

        let service = test_model_service();
        let request = Request::new(ModelFilesRequest {
            model_name: "test/model".to_string(),
            provider: modelexpress_common::grpc::model::ModelProvider::HuggingFace as i32,
            chunk_size: 0,
            file_selector: Some(ModelFileSelector {
                paths: vec!["config.json".to_string(), "subdir/nested.txt".to_string()],
            }),
            ignore_weights: false,
            revision: None,
        });

        let response = service
            .list_model_files(request)
            .await
            .expect("Expected file list")
            .into_inner();
        let mut paths: Vec<_> = response
            .files
            .iter()
            .map(|file| file.relative_path.clone())
            .collect();
        paths.sort();

        assert_eq!(
            paths,
            vec!["config.json".to_string(), "subdir/nested.txt".to_string()]
        );
        assert_eq!(
            response.total_size,
            br#"{"model":"test"}"#.len() as u64 + b"nested".len() as u64
        );
    }

    const REVISION: &str = "abc123";
    const METADATA_FILES: &[(&str, &[u8])] = &[
        ("config.json", b"{}"),
        ("tokenizer.json", b"{\"version\":\"1.0\"}"),
    ];
    const WEIGHT_FILES: &[(&str, &[u8])] = &[("model.safetensors", b"\x08\x00weights")];

    fn pinned_target(ignore_weights: bool) -> DownloadTarget {
        DownloadTarget {
            revision: Some(REVISION.to_string()),
            ignore_weights,
            ..test_target("test/model")
        }
    }

    fn snapshot_dir(cache_dir: &Path) -> PathBuf {
        cache_dir
            .join("models--test--model/snapshots")
            .join(REVISION)
    }

    fn write_snapshot(cache_dir: &Path, files: &[(&str, &[u8])]) -> PathBuf {
        let snapshot = snapshot_dir(cache_dir);
        std::fs::create_dir_all(&snapshot).expect("Failed to create snapshot dir");
        for (name, body) in files {
            std::fs::write(snapshot.join(name), body).expect("Failed to write snapshot file");
        }
        snapshot
    }

    fn install(cache_dir: &Path, target: &DownloadTarget, files: &[(&str, &[u8])]) {
        let snapshot = write_snapshot(cache_dir, files);
        record_download(
            Some(cache_dir),
            &target.entry_key(),
            &snapshot,
            target.ignore_weights,
        )
        .expect("Failed to record download");
    }

    fn all_files() -> Vec<(&'static str, &'static [u8])> {
        [METADATA_FILES, WEIGHT_FILES].concat()
    }

    #[tokio::test]
    async fn a_recorded_full_download_is_a_cache_hit() {
        let cache = TempDir::new().expect("Failed to create temp dir");
        let full = pinned_target(false);
        install(cache.path(), &full, &all_files());
        assert!(model_files_present(Some(cache.path().to_path_buf()), &full).await);
    }

    #[tokio::test]
    async fn a_snapshot_nobody_recorded_is_not_a_cache_hit() {
        let cache = TempDir::new().expect("Failed to create temp dir");
        write_snapshot(cache.path(), &all_files());
        assert!(
            !model_files_present(Some(cache.path().to_path_buf()), &pinned_target(false)).await
        );
    }

    #[tokio::test]
    async fn a_metadata_only_download_does_not_satisfy_a_full_weight_record() {
        let cache = TempDir::new().expect("Failed to create temp dir");
        let metadata = pinned_target(true);
        install(cache.path(), &metadata, METADATA_FILES);

        assert!(model_files_present(Some(cache.path().to_path_buf()), &metadata).await);
        assert!(
            !model_files_present(Some(cache.path().to_path_buf()), &pinned_target(false)).await
        );
    }

    #[tokio::test]
    async fn a_metadata_only_record_ignores_the_weights_beside_it() {
        let cache = TempDir::new().expect("Failed to create temp dir");
        let metadata = pinned_target(true);
        install(cache.path(), &metadata, &all_files());
        std::fs::remove_file(snapshot_dir(cache.path()).join("model.safetensors"))
            .expect("Failed to remove");

        assert!(model_files_present(Some(cache.path().to_path_buf()), &metadata).await);
    }

    #[tokio::test]
    async fn losing_a_recorded_file_invalidates_the_record() {
        let cache = TempDir::new().expect("Failed to create temp dir");
        let full = pinned_target(false);
        install(cache.path(), &full, &all_files());
        std::fs::remove_file(snapshot_dir(cache.path()).join("model.safetensors"))
            .expect("Failed to remove");

        assert!(!model_files_present(Some(cache.path().to_path_buf()), &full).await);
    }

    #[tokio::test]
    async fn a_replaced_cache_volume_invalidates_the_record_even_once_repopulated() {
        let cache = TempDir::new().expect("Failed to create temp dir");
        let full = pinned_target(false);
        install(cache.path(), &full, &all_files());

        std::fs::remove_dir_all(cache.path()).expect("Failed to wipe cache");
        std::fs::create_dir_all(cache.path()).expect("Failed to recreate cache");
        write_snapshot(cache.path(), &all_files());

        assert!(!model_files_present(Some(cache.path().to_path_buf()), &full).await);
    }

    #[tokio::test]
    async fn test_model_files_present_assumes_present_without_cache_dir() {
        // With no configured cache directory we cannot verify, so we must not force a
        // re-download loop: assume the files are present.
        assert!(model_files_present(None, &pinned_target(false)).await);
    }

    #[test]
    fn recording_without_a_cache_dir_is_a_no_op() {
        let missing = Path::new("/nonexistent/snapshot");
        record_download(None, &pinned_target(false).entry_key(), missing, false)
            .expect("Failed to record");
    }

    #[cfg(feature = "memory-backend")]
    fn unreachable_hub() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind");
        let port = listener.local_addr().expect("Failed to read addr").port();
        format!("http://127.0.0.1:{port}")
    }

    #[cfg(feature = "memory-backend")]
    fn tracker_over(backend: Arc<InMemoryRegistryBackend>) -> ModelDownloadTracker {
        ModelDownloadTracker::new(
            Arc::new(RegistryManager::with_backend(backend)),
            DownloadMetrics::register(&mut crate::metrics::new_registry()),
            RegistryMetrics::register(&mut crate::metrics::new_registry()),
        )
    }

    #[cfg(feature = "memory-backend")]
    async fn record_downloaded_before_restart(
        backend: &InMemoryRegistryBackend,
        target: &DownloadTarget,
    ) {
        let key = target.entry_key();
        let claim = backend
            .try_claim_for_download(
                &key,
                target.provider,
                "before-restart",
                DOWNLOAD_LEASE_DURATION,
            )
            .await
            .expect("Failed to claim");
        assert_eq!(claim, ClaimOutcome::Claimed);
        assert!(
            backend
                .finish_download_claim(
                    &key,
                    target.provider,
                    "before-restart",
                    ModelStatus::DOWNLOADED,
                    Some("Model download completed successfully".to_string()),
                )
                .await
                .expect("Failed to finish claim")
        );
    }

    #[cfg(feature = "memory-backend")]
    async fn drain_statuses(
        mut rx: tokio::sync::mpsc::Receiver<Result<ModelStatusUpdate, Status>>,
    ) -> Vec<i32> {
        let mut statuses = Vec::new();
        while let Some(update) = rx.recv().await {
            statuses.push(update.expect("Expected an ok status update").status);
        }
        statuses
    }

    #[cfg(feature = "memory-backend")]
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn a_restart_that_lost_the_weights_re_downloads_instead_of_reporting_a_hit() {
        let env_lock = acquire_env_mutex();
        let cache = TempDir::new().expect("Failed to create temp dir");
        let _cache_guard = EnvVarGuard::set(
            &env_lock,
            "MODEL_EXPRESS_CACHE_DIRECTORY",
            cache.path().to_str().expect("Expected temp dir path"),
        );
        let _online_guard = EnvVarGuard::remove(&env_lock, "HF_HUB_OFFLINE");
        let _hub_guard = EnvVarGuard::set(&env_lock, "HF_ENDPOINT", &unreachable_hub());

        let backend = Arc::new(InMemoryRegistryBackend::new());
        let full = pinned_target(false);
        record_downloaded_before_restart(&backend, &full).await;
        install(cache.path(), &pinned_target(true), METADATA_FILES);

        let tracker = tracker_over(Arc::clone(&backend));
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let status = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            tracker.ensure_model_downloaded(&full, &tx),
        )
        .await
        .expect("ensure_model_downloaded did not finish");
        drop(tx);

        assert_eq!(status, ModelStatus::ERROR);
        let downloaded = modelexpress_common::grpc::model::ModelStatus::Downloaded as i32;
        assert!(!drain_statuses(rx).await.contains(&downloaded));
        let record = backend
            .get_model_record(&full.entry_key())
            .await
            .expect("Failed to read record")
            .expect("Expected a record");
        assert_eq!(record.status, ModelStatus::ERROR);
        assert!(
            record
                .message
                .as_deref()
                .is_some_and(|m| m.starts_with("Download failed")),
            "unexpected message: {:?}",
            record.message
        );
    }

    #[cfg(feature = "memory-backend")]
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn a_recorded_download_is_served_after_a_restart_without_the_hub() {
        let env_lock = acquire_env_mutex();
        let cache = TempDir::new().expect("Failed to create temp dir");
        let _cache_guard = EnvVarGuard::set(
            &env_lock,
            "MODEL_EXPRESS_CACHE_DIRECTORY",
            cache.path().to_str().expect("Expected temp dir path"),
        );
        let _online_guard = EnvVarGuard::remove(&env_lock, "HF_HUB_OFFLINE");
        let _hub_guard = EnvVarGuard::set(&env_lock, "HF_ENDPOINT", &unreachable_hub());

        let backend = Arc::new(InMemoryRegistryBackend::new());
        let full = pinned_target(false);
        record_downloaded_before_restart(&backend, &full).await;
        install(cache.path(), &full, &all_files());
        let before = backend
            .get_model_record(&full.entry_key())
            .await
            .expect("Failed to read record")
            .expect("Expected a record");

        let tracker = tracker_over(Arc::clone(&backend));
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        assert_eq!(
            tracker.ensure_model_downloaded(&full, &tx).await,
            ModelStatus::DOWNLOADED
        );
        drop(tx);

        let downloaded = modelexpress_common::grpc::model::ModelStatus::Downloaded as i32;
        assert_eq!(drain_statuses(rx).await, vec![downloaded]);
        let after = backend
            .get_model_record(&full.entry_key())
            .await
            .expect("Failed to read record")
            .expect("Expected a record");
        assert_eq!(after.created_at, before.created_at);
        assert!(after.last_used_at >= before.last_used_at);
    }

    #[cfg(feature = "memory-backend")]
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn a_completed_download_records_what_it_left_in_the_cache() {
        let env_lock = acquire_env_mutex();
        let cache = TempDir::new().expect("Failed to create temp dir");
        let _cache_guard = EnvVarGuard::set(
            &env_lock,
            "MODEL_EXPRESS_CACHE_DIRECTORY",
            cache.path().to_str().expect("Expected temp dir path"),
        );
        let _offline_guard = EnvVarGuard::set(&env_lock, "HF_HUB_OFFLINE", "1");
        let snapshot = write_snapshot(cache.path(), &all_files());

        let backend = Arc::new(InMemoryRegistryBackend::new());
        let tracker = tracker_over(Arc::clone(&backend));
        let full = pinned_target(false);
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        assert_eq!(
            tracker.ensure_model_downloaded(&full, &tx).await,
            ModelStatus::DOWNLOADED
        );

        let manifest = DownloadManifest::read(cache.path(), &full.entry_key())
            .expect("Expected the download to be recorded");
        assert!(manifest.is_satisfied_by(&snapshot));
        assert!(model_files_present(Some(cache.path().to_path_buf()), &full).await);
        assert_eq!(
            DownloadManifest::read(cache.path(), &pinned_target(true).entry_key()),
            None
        );
    }

    #[cfg(feature = "memory-backend")]
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn a_download_that_leaves_no_files_is_not_reported_as_downloaded() {
        let env_lock = acquire_env_mutex();
        let cache = TempDir::new().expect("Failed to create temp dir");
        let _cache_guard = EnvVarGuard::set(
            &env_lock,
            "MODEL_EXPRESS_CACHE_DIRECTORY",
            cache.path().to_str().expect("Expected temp dir path"),
        );
        let _offline_guard = EnvVarGuard::set(&env_lock, "HF_HUB_OFFLINE", "1");
        write_snapshot(cache.path(), &[]);

        let backend = Arc::new(InMemoryRegistryBackend::new());
        let tracker = tracker_over(Arc::clone(&backend));
        let full = pinned_target(false);
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        assert_eq!(
            tracker.ensure_model_downloaded(&full, &tx).await,
            ModelStatus::ERROR
        );
        let record = backend
            .get_model_record(&full.entry_key())
            .await
            .expect("Failed to read record")
            .expect("Expected a record");
        assert_eq!(record.status, ModelStatus::ERROR);
        assert_eq!(
            DownloadManifest::read(cache.path(), &full.entry_key()),
            None
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_stream_model_files_hf_honors_file_selector() {
        let env_lock = acquire_env_mutex();
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let _cache_dir_guard = EnvVarGuard::set(
            &env_lock,
            "MODEL_EXPRESS_CACHE_DIRECTORY",
            temp_dir.path().to_str().expect("Expected temp dir path"),
        );
        let _offline_guard = EnvVarGuard::set(&env_lock, "HF_HUB_OFFLINE", "1");

        let model_dir = temp_dir.path().join("models--test--model/snapshots/abc123");
        std::fs::create_dir_all(&model_dir).expect("Failed to create model dir");
        std::fs::write(model_dir.join("config.json"), br#"{"model":"test"}"#)
            .expect("Failed to write config");
        std::fs::write(model_dir.join("model.bin"), vec![0u8; 100]).expect("Failed to write model");

        let service = test_model_service();
        let request = Request::new(ModelFilesRequest {
            model_name: "test/model".to_string(),
            provider: modelexpress_common::grpc::model::ModelProvider::HuggingFace as i32,
            chunk_size: 1024,
            file_selector: Some(ModelFileSelector {
                paths: vec!["config.json".to_string()],
            }),
            ignore_weights: false,
            revision: None,
        });

        let response = service
            .stream_model_files(request)
            .await
            .expect("Expected stream response");
        let chunks: Vec<_> = response
            .into_inner()
            .map(|chunk| chunk.expect("Expected chunk"))
            .collect()
            .await;

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].relative_path, "config.json");
        assert_eq!(chunks[0].commit_hash.as_deref(), Some("abc123"));
        assert!(chunks[0].is_last_file);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_stream_model_files_serves_the_requested_revision() {
        let env_lock = acquire_env_mutex();
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let _cache_dir_guard = EnvVarGuard::set(
            &env_lock,
            "MODEL_EXPRESS_CACHE_DIRECTORY",
            temp_dir.path().to_str().expect("Expected temp dir path"),
        );
        let _offline_guard = EnvVarGuard::set(&env_lock, "HF_HUB_OFFLINE", "1");

        // Two revisions cached side by side. Without a requested revision the newest
        // snapshot wins, so asking for the older one proves the request is honored.
        let write_snapshot = |commit: &str, body: &[u8]| {
            let model_dir = temp_dir
                .path()
                .join("models--test--model/snapshots")
                .join(commit);
            std::fs::create_dir_all(&model_dir).expect("Failed to create model dir");
            std::fs::write(model_dir.join("config.json"), body).expect("Failed to write config");
        };
        write_snapshot("older111", b"old");
        // Snapshot ordering is by directory timestamp, so the two have to be distinct.
        tokio::time::sleep(tokio::time::Duration::from_millis(1100)).await;
        write_snapshot("newer222", b"new");

        let stream_revision = async |revision: Option<&str>| {
            let request = Request::new(ModelFilesRequest {
                model_name: "test/model".to_string(),
                provider: modelexpress_common::grpc::model::ModelProvider::HuggingFace as i32,
                chunk_size: 1024,
                file_selector: None,
                ignore_weights: false,
                revision: revision.map(String::from),
            });
            let chunks: Vec<_> = test_model_service()
                .stream_model_files(request)
                .await
                .expect("Expected stream response")
                .into_inner()
                .map(|chunk| chunk.expect("Expected chunk"))
                .collect()
                .await;
            assert_eq!(chunks.len(), 1);
            (chunks[0].commit_hash.clone(), chunks[0].data.clone())
        };

        assert_eq!(
            stream_revision(Some("older111")).await,
            (Some("older111".to_string()), b"old".to_vec())
        );
        assert_eq!(
            stream_revision(None).await,
            (Some("newer222".to_string()), b"new".to_vec()),
            "Without a revision the newest snapshot is served, so the pinned request above \
             really did select a different one"
        );
    }

    #[tokio::test]
    async fn test_ensure_model_downloaded_rejects_a_revision_on_a_provider_without_revisions() {
        let service = test_model_service();
        let request = Request::new(ModelDownloadRequest {
            model_name: "gs://test-bucket/org/model/rev-1".to_string(),
            provider: modelexpress_common::grpc::model::ModelProvider::Gcs as i32,
            ignore_weights: false,
            revision: Some("v1.0".to_string()),
        });

        let status = service
            .ensure_model_downloaded(request)
            .await
            .map(|_| ())
            .expect_err("A provider without revisions must reject a pinned revision");
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(
            status
                .message()
                .contains("does not support pinned revisions"),
            "Unexpected message: {}",
            status.message()
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_stream_model_files_rejects_an_uncached_revision() {
        let env_lock = acquire_env_mutex();
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let _cache_dir_guard = EnvVarGuard::set(
            &env_lock,
            "MODEL_EXPRESS_CACHE_DIRECTORY",
            temp_dir.path().to_str().expect("Expected temp dir path"),
        );
        let _offline_guard = EnvVarGuard::set(&env_lock, "HF_HUB_OFFLINE", "1");

        let model_dir = temp_dir.path().join("models--test--model/snapshots/abc123");
        std::fs::create_dir_all(&model_dir).expect("Failed to create model dir");
        std::fs::write(model_dir.join("config.json"), b"{}").expect("Failed to write config");

        let service = test_model_service();
        let request = Request::new(ModelFilesRequest {
            model_name: "test/model".to_string(),
            provider: modelexpress_common::grpc::model::ModelProvider::HuggingFace as i32,
            chunk_size: 1024,
            file_selector: None,
            ignore_weights: false,
            revision: Some("not-cached".to_string()),
        });

        let status = service
            .stream_model_files(request)
            .await
            .map(|_| ())
            .expect_err("An uncached revision must not fall back to another snapshot");
        assert_eq!(status.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_stream_model_files_hf_returns_not_found_for_missing_selector_path() {
        let env_lock = acquire_env_mutex();
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let _cache_dir_guard = EnvVarGuard::set(
            &env_lock,
            "MODEL_EXPRESS_CACHE_DIRECTORY",
            temp_dir.path().to_str().expect("Expected temp dir path"),
        );
        let _offline_guard = EnvVarGuard::set(&env_lock, "HF_HUB_OFFLINE", "1");

        let model_dir = temp_dir.path().join("models--test--model/snapshots/abc123");
        std::fs::create_dir_all(&model_dir).expect("Failed to create model dir");
        std::fs::write(model_dir.join("config.json"), br#"{"model":"test"}"#)
            .expect("Failed to write config");

        let service = test_model_service();
        let request = Request::new(ModelFilesRequest {
            model_name: "test/model".to_string(),
            provider: modelexpress_common::grpc::model::ModelProvider::HuggingFace as i32,
            chunk_size: 1024,
            file_selector: Some(ModelFileSelector {
                paths: vec!["config.json".to_string(), "missing.json".to_string()],
            }),
            ignore_weights: false,
            revision: None,
        });

        let result = service.stream_model_files(request).await;
        let status = result.expect_err("Expected not found");
        assert_eq!(status.code(), tonic::Code::NotFound);
        assert_eq!(
            status.message(),
            "Selected file not found in model directory: missing.json"
        );
    }

    #[tokio::test]
    async fn test_list_model_files_not_found() {
        let service = test_model_service();

        let request = Request::new(ModelFilesRequest {
            model_name: "non-existent-model-12345".to_string(),
            provider: modelexpress_common::grpc::model::ModelProvider::HuggingFace as i32,
            chunk_size: 0,
            file_selector: None,
            ignore_weights: false,
            revision: None,
        });

        let result = service.list_model_files(request).await;
        assert!(result.is_err());
        let status = result.expect_err("Should return error");
        assert_eq!(status.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn test_stream_model_files_not_found() {
        let service = test_model_service();

        let request = Request::new(ModelFilesRequest {
            model_name: "non-existent-model-12345".to_string(),
            provider: modelexpress_common::grpc::model::ModelProvider::HuggingFace as i32,
            chunk_size: 1024,
            file_selector: None,
            ignore_weights: false,
            revision: None,
        });

        let result = service.stream_model_files(request).await;
        assert!(result.is_err());
        let status = result.expect_err("Should return error");
        assert_eq!(status.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn test_ensure_model_downloaded_rejects_invalid_provider() {
        let service = test_model_service();

        let request = Request::new(ModelDownloadRequest {
            model_name: "test/model".to_string(),
            provider: 99,
            ignore_weights: false,
            revision: None,
        });

        let result = service.ensure_model_downloaded(request).await;
        assert!(result.is_err());
        let status = result.expect_err("Should return error");
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(status.message().contains("Invalid provider value"));
    }

    #[tokio::test]
    async fn test_list_model_files_rejects_invalid_provider() {
        let service = test_model_service();

        let request = Request::new(ModelFilesRequest {
            model_name: "test/model".to_string(),
            provider: 99,
            chunk_size: 0,
            file_selector: None,
            ignore_weights: false,
            revision: None,
        });

        let result = service.list_model_files(request).await;
        assert!(result.is_err());
        let status = result.expect_err("Should return error");
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(status.message().contains("Invalid provider value"));
    }

    #[tokio::test]
    async fn test_stream_model_files_rejects_invalid_provider() {
        let service = test_model_service();

        let request = Request::new(ModelFilesRequest {
            model_name: "test/model".to_string(),
            provider: 99,
            chunk_size: 1024,
            file_selector: None,
            ignore_weights: false,
            revision: None,
        });

        let result = service.stream_model_files(request).await;
        assert!(result.is_err());
        let status = result.expect_err("Should return error");
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(status.message().contains("Invalid provider value"));
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_stream_model_files_hf_first_chunk_includes_commit_hash() {
        let env_lock = acquire_env_mutex();
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let _cache_dir_guard = EnvVarGuard::set(
            &env_lock,
            "MODEL_EXPRESS_CACHE_DIRECTORY",
            temp_dir.path().to_str().expect("Expected temp dir path"),
        );
        let _offline_guard = EnvVarGuard::set(&env_lock, "HF_HUB_OFFLINE", "1");

        let model_dir = temp_dir.path().join("models--test--model/snapshots/abc123");
        std::fs::create_dir_all(&model_dir).expect("Failed to create model dir");
        std::fs::write(model_dir.join("config.json"), br#"{"model":"test"}"#)
            .expect("Failed to write model file");

        let service = test_model_service();
        let request = Request::new(ModelFilesRequest {
            model_name: "test/model".to_string(),
            provider: modelexpress_common::grpc::model::ModelProvider::HuggingFace as i32,
            chunk_size: 1024,
            file_selector: None,
            ignore_weights: false,
            revision: None,
        });

        let response = service
            .stream_model_files(request)
            .await
            .expect("Expected stream response");
        let mut stream = response.into_inner();
        let first_chunk = stream
            .next()
            .await
            .expect("Expected stream item")
            .expect("Expected first chunk");

        assert_eq!(first_chunk.relative_path, "config.json");
        assert_eq!(first_chunk.commit_hash.as_deref(), Some("abc123"));
        assert!(first_chunk.is_last_chunk);
        assert!(first_chunk.is_last_file);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_stream_model_files_hf_emits_chunk_for_zero_byte_file() {
        let env_lock = acquire_env_mutex();
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let _cache_dir_guard = EnvVarGuard::set(
            &env_lock,
            "MODEL_EXPRESS_CACHE_DIRECTORY",
            temp_dir.path().to_str().expect("Expected temp dir path"),
        );
        let _offline_guard = EnvVarGuard::set(&env_lock, "HF_HUB_OFFLINE", "1");

        let model_dir = temp_dir.path().join("models--test--model/snapshots/abc123");
        std::fs::create_dir_all(&model_dir).expect("Failed to create model dir");
        std::fs::write(model_dir.join("empty.bin"), []).expect("Failed to write empty file");

        let service = test_model_service();
        let request = Request::new(ModelFilesRequest {
            model_name: "test/model".to_string(),
            provider: modelexpress_common::grpc::model::ModelProvider::HuggingFace as i32,
            chunk_size: 1024,
            file_selector: None,
            ignore_weights: false,
            revision: None,
        });

        let response = service
            .stream_model_files(request)
            .await
            .expect("Expected stream response");
        let mut stream = response.into_inner();
        let first_chunk = stream
            .next()
            .await
            .expect("Expected stream item")
            .expect("Expected first chunk");

        assert_eq!(first_chunk.relative_path, "empty.bin");
        assert_eq!(first_chunk.total_size, 0);
        assert_eq!(first_chunk.data.len(), 0);
        assert_eq!(first_chunk.offset, 0);
        assert_eq!(first_chunk.commit_hash.as_deref(), Some("abc123"));
        assert!(first_chunk.is_last_chunk);
        assert!(first_chunk.is_last_file);
    }

    fn tenant(namespace: &str) -> Tenant {
        Tenant::new(namespace).expect("valid namespace")
    }

    fn pinned_target_in(namespace: &str, ignore_weights: bool) -> DownloadTarget {
        DownloadTarget {
            tenant: Some(tenant(namespace)),
            ..pinned_target(ignore_weights)
        }
    }

    fn partition_of(cache: &Path, namespace: &str) -> PathBuf {
        partition(cache, Some(&tenant(namespace)))
    }

    fn as_caller<T>(message: T, namespace: &str) -> Request<T> {
        let mut request = Request::new(message);
        request.extensions_mut().insert(CallerIdentity {
            namespace: namespace.to_string(),
            service_account: "worker".to_string(),
            pod_name: None,
            pod_uid: None,
        });
        request
    }

    fn files_request() -> ModelFilesRequest {
        ModelFilesRequest {
            model_name: "test/model".to_string(),
            provider: GrpcModelProvider::HuggingFace as i32,
            chunk_size: 0,
            file_selector: None,
            ignore_weights: false,
            revision: Some(REVISION.to_string()),
        }
    }

    fn download_request() -> ModelDownloadRequest {
        ModelDownloadRequest {
            model_name: "test/model".to_string(),
            provider: GrpcModelProvider::HuggingFace as i32,
            ignore_weights: false,
            revision: Some(REVISION.to_string()),
        }
    }

    fn delete_request() -> DeleteModelRequest {
        DeleteModelRequest {
            model_name: "test/model".to_string(),
            provider: GrpcModelProvider::HuggingFace as i32,
        }
    }

    #[cfg(feature = "memory-backend")]
    async fn listed(
        service: &ModelServiceImpl,
        request: Request<ModelFilesRequest>,
    ) -> Result<Vec<String>, tonic::Code> {
        let mut files: Vec<String> = service
            .list_model_files(request)
            .await
            .map_err(|status| status.code())?
            .into_inner()
            .files
            .into_iter()
            .map(|file| file.relative_path)
            .collect();
        files.sort();
        Ok(files)
    }

    #[cfg(feature = "memory-backend")]
    async fn streamed(
        service: &ModelServiceImpl,
        request: Request<ModelFilesRequest>,
    ) -> Result<Vec<String>, tonic::Code> {
        let chunks: Vec<FileChunk> = service
            .stream_model_files(request)
            .await
            .map_err(|status| status.code())?
            .into_inner()
            .map(|chunk| chunk.expect("Expected chunk"))
            .collect()
            .await;
        let mut files: Vec<String> = chunks
            .into_iter()
            .map(|chunk| chunk.relative_path)
            .collect();
        files.sort();
        files.dedup();
        Ok(files)
    }

    #[cfg(feature = "memory-backend")]
    fn all_file_names() -> Vec<String> {
        let mut names: Vec<String> = all_files()
            .iter()
            .map(|(name, _)| (*name).to_string())
            .collect();
        names.sort();
        names
    }

    #[tokio::test]
    async fn requests_without_a_verified_caller_fail_closed_under_isolation() {
        let service = ModelServiceImpl::with_tenant_isolation(test_model_service().tracker, true);
        let code = |result: Result<_, Status>| result.err().map(|status| status.code());
        assert_eq!(
            code(
                service
                    .ensure_model_downloaded(Request::new(download_request()))
                    .await
                    .map(|_| ())
            ),
            Some(tonic::Code::Unauthenticated)
        );
        assert_eq!(
            code(
                service
                    .stream_model_files(Request::new(files_request()))
                    .await
                    .map(|_| ())
            ),
            Some(tonic::Code::Unauthenticated)
        );
        assert_eq!(
            code(
                service
                    .list_model_files(Request::new(files_request()))
                    .await
                    .map(|_| ())
            ),
            Some(tonic::Code::Unauthenticated)
        );
        assert_eq!(
            code(
                service
                    .delete_model(Request::new(delete_request()))
                    .await
                    .map(|_| ())
            ),
            Some(tonic::Code::Unauthenticated)
        );
    }

    #[tokio::test]
    async fn a_caller_namespace_that_is_not_a_namespace_is_rejected() {
        let service = ModelServiceImpl::with_tenant_isolation(test_model_service().tracker, true);
        for namespace in ["..", "a/b", ""] {
            let status = service
                .list_model_files(as_caller(files_request(), namespace))
                .await
                .expect_err("must be rejected");
            assert_eq!(
                status.code(),
                tonic::Code::PermissionDenied,
                "{namespace:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_tenant_record_is_satisfied_only_by_its_own_partition() {
        let cache = TempDir::new().expect("Failed to create temp dir");
        let a = pinned_target_in("tenant-a", false);
        let a_partition = partition_of(cache.path(), "tenant-a");

        install(cache.path(), &a, &all_files());
        install(&partition_of(cache.path(), "tenant-b"), &a, &all_files());
        assert!(!model_files_present(Some(a_partition.clone()), &a).await);

        install(&a_partition, &a, &all_files());
        assert!(model_files_present(Some(a_partition), &a).await);
    }

    #[cfg(feature = "memory-backend")]
    fn service_over(
        backend: Arc<crate::registry::backend::memory::InMemoryRegistryBackend>,
        tenant_isolation: bool,
    ) -> ModelServiceImpl {
        ModelServiceImpl::with_tenant_isolation(Arc::new(tracker_over(backend)), tenant_isolation)
    }

    #[cfg(feature = "memory-backend")]
    async fn final_status(
        service: &ModelServiceImpl,
        request: Request<ModelDownloadRequest>,
    ) -> Result<i32, tonic::Code> {
        let updates: Vec<ModelStatusUpdate> = service
            .ensure_model_downloaded(request)
            .await
            .map_err(|status| status.code())?
            .into_inner()
            .map(|update| update.expect("Expected an ok status update"))
            .collect()
            .await;
        Ok(updates.last().expect("at least one update").status)
    }

    #[cfg(feature = "memory-backend")]
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn isolation_off_keeps_the_existing_keys_and_cache_layout() {
        use crate::registry::backend::RegistryBackend;
        let env_lock = acquire_env_mutex();
        let cache = TempDir::new().expect("Failed to create temp dir");
        let _cache_guard = EnvVarGuard::set(
            &env_lock,
            "MODEL_EXPRESS_CACHE_DIRECTORY",
            cache.path().to_str().expect("Expected temp dir path"),
        );
        let _offline_guard = EnvVarGuard::set(&env_lock, "HF_HUB_OFFLINE", "1");
        let downloaded = modelexpress_common::grpc::model::ModelStatus::Downloaded as i32;

        let legacy_key = "mx1:abc123:-:test/model";
        let backend = Arc::new(crate::registry::backend::memory::InMemoryRegistryBackend::new());
        record_downloaded_before_restart(&backend, &pinned_target(false)).await;
        let before = backend
            .get_model_record(legacy_key)
            .await
            .expect("Failed to read record")
            .expect("an isolation-off entry key changed");
        let snapshot = write_snapshot(cache.path(), &all_files());
        DownloadManifest::new(
            legacy_key,
            collect_model_files(&snapshot, &snapshot, None, false),
        )
        .write(cache.path())
        .expect("Failed to write legacy manifest");
        assert!(cache.path().join(".modelexpress/downloads").is_dir());

        let service = service_over(Arc::clone(&backend), false);
        assert_eq!(
            final_status(&service, Request::new(download_request())).await,
            Ok(downloaded)
        );
        assert_eq!(
            listed(&service, Request::new(files_request())).await,
            Ok(all_file_names())
        );
        assert_eq!(
            streamed(&service, Request::new(files_request())).await,
            Ok(all_file_names())
        );
        assert!(!cache.path().join(".modelexpress/tenants").exists());
        let after = backend
            .get_model_record(legacy_key)
            .await
            .expect("Failed to read record")
            .expect("Expected the legacy record");
        assert_eq!(
            after.created_at, before.created_at,
            "the legacy record was re-downloaded instead of served"
        );
        assert_eq!(
            backend
                .get_models_by_last_used(None)
                .await
                .expect("Failed to list")
                .into_iter()
                .map(|record| record.model_name)
                .collect::<Vec<_>>(),
            vec![legacy_key.to_string()]
        );
    }

    #[cfg(feature = "memory-backend")]
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn a_tenant_download_lands_in_its_own_partition() {
        use crate::registry::backend::RegistryBackend;
        let env_lock = acquire_env_mutex();
        let cache = TempDir::new().expect("Failed to create temp dir");
        let _cache_guard = EnvVarGuard::set(
            &env_lock,
            "MODEL_EXPRESS_CACHE_DIRECTORY",
            cache.path().to_str().expect("Expected temp dir path"),
        );
        let _offline_guard = EnvVarGuard::set(&env_lock, "HF_HUB_OFFLINE", "1");
        let a_partition = partition_of(cache.path(), "tenant-a");
        let snapshot = write_snapshot(&a_partition, &all_files());

        let backend = Arc::new(crate::registry::backend::memory::InMemoryRegistryBackend::new());
        let service = service_over(Arc::clone(&backend), true);
        assert_eq!(
            final_status(&service, as_caller(download_request(), "tenant-a")).await,
            Ok(modelexpress_common::grpc::model::ModelStatus::Downloaded as i32)
        );

        let key = "mxt1:tenant-a:abc123:-:test/model";
        assert_eq!(key, pinned_target_in("tenant-a", false).entry_key());
        let record = backend
            .get_model_record(key)
            .await
            .expect("Failed to read record")
            .expect("Expected the tenant's record");
        assert_eq!(record.status, ModelStatus::DOWNLOADED);
        assert!(
            DownloadManifest::read(&a_partition, key)
                .expect("Expected the partition's manifest")
                .is_satisfied_by(&snapshot)
        );
        assert_eq!(DownloadManifest::read(cache.path(), key), None);
        assert!(!cache.path().join("models--test--model").exists());
    }

    #[cfg(feature = "memory-backend")]
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn tenants_cannot_download_list_or_stream_each_others_cache() {
        let env_lock = acquire_env_mutex();
        let cache = TempDir::new().expect("Failed to create temp dir");
        let _cache_guard = EnvVarGuard::set(
            &env_lock,
            "MODEL_EXPRESS_CACHE_DIRECTORY",
            cache.path().to_str().expect("Expected temp dir path"),
        );
        let _offline_guard = EnvVarGuard::set(&env_lock, "HF_HUB_OFFLINE", "1");
        install(
            &partition_of(cache.path(), "tenant-a"),
            &pinned_target_in("tenant-a", false),
            &all_files(),
        );

        let backend = Arc::new(crate::registry::backend::memory::InMemoryRegistryBackend::new());
        let service = service_over(Arc::clone(&backend), true);

        assert_eq!(
            listed(&service, as_caller(files_request(), "tenant-a")).await,
            Ok(all_file_names())
        );
        assert_eq!(
            streamed(&service, as_caller(files_request(), "tenant-a")).await,
            Ok(all_file_names())
        );
        assert_eq!(
            listed(&service, as_caller(files_request(), "tenant-b")).await,
            Err(tonic::Code::NotFound)
        );
        assert_eq!(
            streamed(&service, as_caller(files_request(), "tenant-b")).await,
            Err(tonic::Code::NotFound)
        );
        assert_eq!(
            final_status(&service, as_caller(download_request(), "tenant-b")).await,
            Err(tonic::Code::NotFound)
        );
        assert!(
            !partition_of(cache.path(), "tenant-b")
                .join("models--test--model")
                .exists()
        );
    }

    #[cfg(feature = "memory-backend")]
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn isolation_hides_the_unpartitioned_cache() {
        let env_lock = acquire_env_mutex();
        let cache = TempDir::new().expect("Failed to create temp dir");
        let _cache_guard = EnvVarGuard::set(
            &env_lock,
            "MODEL_EXPRESS_CACHE_DIRECTORY",
            cache.path().to_str().expect("Expected temp dir path"),
        );
        let _offline_guard = EnvVarGuard::set(&env_lock, "HF_HUB_OFFLINE", "1");
        install(cache.path(), &pinned_target(false), &all_files());

        let backend = Arc::new(crate::registry::backend::memory::InMemoryRegistryBackend::new());
        let service = service_over(backend, true);
        assert_eq!(
            listed(&service, as_caller(files_request(), "tenant-a")).await,
            Err(tonic::Code::NotFound)
        );
        assert_eq!(
            streamed(&service, as_caller(files_request(), "tenant-a")).await,
            Err(tonic::Code::NotFound)
        );
    }

    #[cfg(feature = "memory-backend")]
    #[tokio::test]
    async fn clearing_a_model_only_touches_the_callers_partition() {
        use crate::registry::backend::RegistryBackend;
        let backend = Arc::new(crate::registry::backend::memory::InMemoryRegistryBackend::new());
        let a = pinned_target_in("tenant-a", false);
        let a_metadata = pinned_target_in("tenant-a", true);
        let b = pinned_target_in("tenant-b", false);
        let open = pinned_target(false);
        for target in [&a, &a_metadata, &b, &open] {
            record_downloaded_before_restart(&backend, target).await;
        }
        let keys = async || {
            let mut keys: Vec<String> = backend
                .get_models_by_last_used(None)
                .await
                .expect("Failed to list")
                .into_iter()
                .map(|record| record.model_name)
                .collect();
            keys.sort();
            keys
        };

        let service = service_over(Arc::clone(&backend), true);
        let response = service
            .delete_model(as_caller(delete_request(), "tenant-b"))
            .await
            .expect("delete")
            .into_inner();
        assert!(response.success);
        assert!(
            response
                .message
                .as_deref()
                .is_some_and(|m| m.contains("1 record"))
        );
        let mut expected = vec![a.entry_key(), a_metadata.entry_key(), open.entry_key()];
        expected.sort();
        assert_eq!(keys().await, expected);

        service
            .delete_model(as_caller(delete_request(), "tenant-a"))
            .await
            .expect("delete");
        assert_eq!(keys().await, vec![open.entry_key()]);
    }

    #[cfg(feature = "memory-backend")]
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn a_partition_that_lost_its_weights_re_downloads_after_a_restart() {
        use crate::registry::backend::RegistryBackend;
        let env_lock = acquire_env_mutex();
        let cache = TempDir::new().expect("Failed to create temp dir");
        let _cache_guard = EnvVarGuard::set(
            &env_lock,
            "MODEL_EXPRESS_CACHE_DIRECTORY",
            cache.path().to_str().expect("Expected temp dir path"),
        );
        let _online_guard = EnvVarGuard::remove(&env_lock, "HF_HUB_OFFLINE");
        let _hub_guard = EnvVarGuard::set(&env_lock, "HF_ENDPOINT", &unreachable_hub());

        let backend = Arc::new(crate::registry::backend::memory::InMemoryRegistryBackend::new());
        let full = pinned_target_in("tenant-a", false);
        record_downloaded_before_restart(&backend, &full).await;
        install(
            &partition_of(cache.path(), "tenant-a"),
            &pinned_target_in("tenant-a", true),
            METADATA_FILES,
        );
        install(cache.path(), &full, &all_files());
        install(&partition_of(cache.path(), "tenant-b"), &full, &all_files());

        let tracker = tracker_over(Arc::clone(&backend));
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let status = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            tracker.ensure_model_downloaded(&full, &tx),
        )
        .await
        .expect("ensure_model_downloaded did not finish");
        drop(tx);

        assert_eq!(status, ModelStatus::ERROR);
        let downloaded = modelexpress_common::grpc::model::ModelStatus::Downloaded as i32;
        assert!(!drain_statuses(rx).await.contains(&downloaded));
        let record = backend
            .get_model_record(&full.entry_key())
            .await
            .expect("Failed to read record")
            .expect("Expected a record");
        assert_eq!(record.status, ModelStatus::ERROR);
        assert!(
            record
                .message
                .as_deref()
                .is_some_and(|m| m.starts_with("Download failed")),
            "unexpected message: {:?}",
            record.message
        );
    }

    #[cfg(feature = "memory-backend")]
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn a_recorded_partition_download_is_served_after_a_restart_without_the_hub() {
        use crate::registry::backend::RegistryBackend;
        let env_lock = acquire_env_mutex();
        let cache = TempDir::new().expect("Failed to create temp dir");
        let _cache_guard = EnvVarGuard::set(
            &env_lock,
            "MODEL_EXPRESS_CACHE_DIRECTORY",
            cache.path().to_str().expect("Expected temp dir path"),
        );
        let _offline_guard = EnvVarGuard::set(&env_lock, "HF_HUB_OFFLINE", "1");

        let backend = Arc::new(crate::registry::backend::memory::InMemoryRegistryBackend::new());
        let full = pinned_target_in("tenant-a", false);
        record_downloaded_before_restart(&backend, &full).await;
        install(&partition_of(cache.path(), "tenant-a"), &full, &all_files());
        let created_at = |record: Option<crate::registry::backend::ModelRecord>| {
            record.expect("Expected the tenant's record").created_at
        };
        let before = created_at(
            backend
                .get_model_record(&full.entry_key())
                .await
                .expect("Failed to read record"),
        );

        let service = service_over(Arc::clone(&backend), true);
        assert_eq!(
            final_status(&service, as_caller(download_request(), "tenant-a")).await,
            Ok(modelexpress_common::grpc::model::ModelStatus::Downloaded as i32)
        );
        assert_eq!(
            streamed(&service, as_caller(files_request(), "tenant-a")).await,
            Ok(all_file_names())
        );
        assert_eq!(
            created_at(
                backend
                    .get_model_record(&full.entry_key())
                    .await
                    .expect("Failed to read record")
            ),
            before,
            "the partition's record was re-downloaded instead of served"
        );
    }

    #[cfg(feature = "memory-backend")]
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn revisions_outside_the_snapshot_directory_are_invalid_arguments() {
        let env_lock = acquire_env_mutex();
        let cache = TempDir::new().expect("Failed to create temp dir");
        let _cache_guard = EnvVarGuard::set(
            &env_lock,
            "MODEL_EXPRESS_CACHE_DIRECTORY",
            cache.path().to_str().expect("Expected temp dir path"),
        );
        let _offline_guard = EnvVarGuard::set(&env_lock, "HF_HUB_OFFLINE", "1");
        install(
            &partition_of(cache.path(), "tenant-a"),
            &pinned_target_in("tenant-a", false),
            &all_files(),
        );
        std::fs::create_dir_all(
            partition_of(cache.path(), "tenant-b").join("models--test--model/snapshots/def456"),
        )
        .expect("Failed to create tenant-b snapshot");
        let service = service_over(Arc::new(InMemoryRegistryBackend::new()), true);
        let a_snapshot = snapshot_dir(&partition_of(cache.path(), "tenant-a"));

        for revision in [
            a_snapshot.to_str().expect("utf-8 path").to_string(),
            format!("../../../tenant-a/models--test--model/snapshots/{REVISION}"),
        ] {
            let files = ModelFilesRequest {
                revision: Some(revision.clone()),
                ..files_request()
            };
            assert_eq!(
                listed(&service, as_caller(files.clone(), "tenant-b")).await,
                Err(tonic::Code::InvalidArgument),
                "list {revision}"
            );
            assert_eq!(
                streamed(&service, as_caller(files, "tenant-b")).await,
                Err(tonic::Code::InvalidArgument),
                "stream {revision}"
            );
            let download = ModelDownloadRequest {
                revision: Some(revision.clone()),
                ..download_request()
            };
            assert_eq!(
                final_status(&service, as_caller(download, "tenant-b")).await,
                Err(tonic::Code::InvalidArgument),
                "ensure {revision}"
            );
        }
        assert_eq!(
            listed(&service, as_caller(files_request(), "tenant-a")).await,
            Ok(all_file_names())
        );
    }

    #[cfg(feature = "memory-backend")]
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn an_untenanted_list_cannot_name_a_directory_outside_the_cache() {
        let env_lock = acquire_env_mutex();
        let cache = TempDir::new().expect("Failed to create temp dir");
        let outside = TempDir::new().expect("Failed to create temp dir");
        std::fs::write(outside.path().join("data.txt"), b"keep").expect("Failed to write file");
        let _cache_guard = EnvVarGuard::set(
            &env_lock,
            "MODEL_EXPRESS_CACHE_DIRECTORY",
            cache.path().to_str().expect("Expected temp dir path"),
        );
        let service = service_over(Arc::new(InMemoryRegistryBackend::new()), false);
        let request = ModelFilesRequest {
            revision: Some(outside.path().to_str().expect("utf-8 path").to_string()),
            ..files_request()
        };
        assert_eq!(
            listed(&service, Request::new(request)).await,
            Err(tonic::Code::InvalidArgument)
        );
    }

    #[cfg(feature = "memory-backend")]
    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn a_ref_name_with_slashes_lists_its_snapshot() {
        let env_lock = acquire_env_mutex();
        let cache = TempDir::new().expect("Failed to create temp dir");
        let _cache_guard = EnvVarGuard::set(
            &env_lock,
            "MODEL_EXPRESS_CACHE_DIRECTORY",
            cache.path().to_str().expect("Expected temp dir path"),
        );
        install(cache.path(), &pinned_target(false), &all_files());
        let refs = cache.path().join("models--test--model/refs/refs/pr");
        std::fs::create_dir_all(&refs).expect("Failed to create refs");
        std::fs::write(refs.join("1"), REVISION).expect("Failed to write ref");
        let service = service_over(Arc::new(InMemoryRegistryBackend::new()), false);
        let request = ModelFilesRequest {
            revision: Some("refs/pr/1".to_string()),
            ..files_request()
        };
        assert_eq!(
            listed(&service, Request::new(request)).await,
            Ok(all_file_names())
        );
    }
}
