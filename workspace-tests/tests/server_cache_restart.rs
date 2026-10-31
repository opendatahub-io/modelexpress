// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for `DOWNLOADED` registry records whose files the serving server's
//! cache does not hold, such as after a restart that loses the cache while the Redis
//! registry survives.
//!
//! Run with a Redis 7 server and Hugging Face Hub access:
//!
//! ```sh
//! REDIS_URL=redis://localhost:6379 cargo test -p model-express-workspace-tests \
//!     --test server_cache_restart -- --include-ignored --test-threads=1
//! ```

#![allow(clippy::expect_used)]

use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use modelexpress_common::grpc::model::{
    DeleteModelRequest, ModelDownloadRequest, ModelFilesRequest, ModelProvider, ModelStatus,
    ModelStatusUpdate, model_service_client::ModelServiceClient,
};
use modelexpress_common::models::ModelProvider as Provider;
use modelexpress_common::models::ModelStatus as RecordStatus;
use modelexpress_common::providers::is_weight_file;
use modelexpress_server::backend_config::BackendConfig;
use modelexpress_server::config::ServerConfig;
use modelexpress_server::registry::backend::{
    ClaimOutcome, RegistryBackend, redis::RedisRegistryBackend,
};
use modelexpress_server::registry::entry_key::EntryKey;
use modelexpress_server::run_server;
use tempfile::TempDir;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tonic::transport::Channel;

type ServerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

const MODEL: &str = "hf-internal-testing/tiny-random-gpt2";
const REVISION: &str = "71034c5d8bde858ff824298bdedc65515b97d2b9";
const WEIGHTS: &str = "model.safetensors";
const WEIGHTS_SIZE: u64 = 453_864;

static ENV_MUTEX: Mutex<()> = Mutex::new(());

fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string())
}

fn entry_key(metadata_only: bool) -> String {
    EntryKey::new(MODEL, Some(REVISION.to_string()), metadata_only).to_string()
}

fn snapshot_dir(cache_dir: &Path) -> PathBuf {
    cache_dir
        .join("models--hf-internal-testing--tiny-random-gpt2/snapshots")
        .join(REVISION)
}

fn free_ports<const N: usize>() -> [u16; N] {
    let sockets: Vec<std::net::TcpListener> = (0..N)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port"))
        .collect();
    let mut ports = [0_u16; N];
    for (slot, socket) in ports.iter_mut().zip(&sockets) {
        *slot = socket.local_addr().expect("local addr").port();
    }
    ports
}

struct Server {
    port: u16,
    shutdown: oneshot::Sender<()>,
    handle: JoinHandle<ServerResult>,
}

impl Server {
    fn start(cache_dir: &Path, redis_url: &str) -> Self {
        let [port, metrics_port] = free_ports::<2>();
        let mut config = ServerConfig::default();
        config.server.host = "127.0.0.1".to_string();
        config.server.port = NonZeroU16::new(port).expect("port is non-zero");
        config.server.metrics_port = metrics_port;
        config.cache.directory = cache_dir.to_path_buf();
        config.cache.eviction.enabled = false;

        let backend = BackendConfig::Redis {
            url: redis_url.to_string(),
        };
        let (shutdown, rx) = oneshot::channel();
        let handle = tokio::spawn(run_server(config, backend, async move {
            let _ = rx.await;
        }));
        Self {
            port,
            shutdown,
            handle,
        }
    }

    async fn client(&self) -> ModelServiceClient<Channel> {
        let endpoint = format!("http://127.0.0.1:{}", self.port);
        for _ in 0..100 {
            if let Ok(client) = ModelServiceClient::connect(endpoint.clone()).await {
                return client;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("server on port {} never became reachable", self.port);
    }

    async fn stop(self) {
        let _ = self.shutdown.send(());
        tokio::time::timeout(Duration::from_secs(10), self.handle)
            .await
            .expect("server did not stop")
            .expect("server task panicked")
            .expect("server failed");
    }
}

struct Environment {
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl Environment {
    fn new(cache_dir: &Path, offline: bool) -> Self {
        let lock = ENV_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: every test in this binary holds ENV_MUTEX while it touches the environment.
        unsafe {
            std::env::set_var("MODEL_EXPRESS_CACHE_DIRECTORY", cache_dir);
            if offline {
                std::env::set_var("HF_HUB_OFFLINE", "1");
            } else {
                std::env::remove_var("HF_HUB_OFFLINE");
            }
        }
        Self { _lock: lock }
    }
}

impl Drop for Environment {
    fn drop(&mut self) {
        // SAFETY: still under ENV_MUTEX, which is released after this runs.
        unsafe {
            std::env::remove_var("MODEL_EXPRESS_CACHE_DIRECTORY");
            std::env::remove_var("HF_HUB_OFFLINE");
        }
    }
}

fn wipe(cache_dir: &Path) {
    std::fs::remove_dir_all(cache_dir).expect("wipe cache");
    std::fs::create_dir_all(cache_dir).expect("recreate cache");
}

async fn forget_model(redis_url: &str) {
    let backend = RedisRegistryBackend::new(redis_url);
    backend.connect().await.expect("connect to Redis");
    for metadata_only in [false, true] {
        backend
            .delete_model(&entry_key(metadata_only))
            .await
            .expect("delete registry entry");
    }
}

fn download_request(ignore_weights: bool) -> ModelDownloadRequest {
    ModelDownloadRequest {
        model_name: MODEL.to_string(),
        provider: ModelProvider::HuggingFace as i32,
        ignore_weights,
        revision: Some(REVISION.to_string()),
    }
}

async fn ensure(
    client: &mut ModelServiceClient<Channel>,
    ignore_weights: bool,
) -> Vec<ModelStatusUpdate> {
    let mut stream = tokio::time::timeout(
        Duration::from_secs(120),
        client.ensure_model_downloaded(download_request(ignore_weights)),
    )
    .await
    .expect("EnsureModelDownloaded did not answer")
    .expect("EnsureModelDownloaded failed")
    .into_inner();
    let mut updates = Vec::new();
    while let Some(update) = tokio::time::timeout(Duration::from_secs(300), stream.message())
        .await
        .expect("download stream stalled")
        .expect("status update")
    {
        updates.push(update);
    }
    updates
}

fn final_status(updates: &[ModelStatusUpdate]) -> ModelStatus {
    let last = updates.last().expect("at least one status update");
    ModelStatus::try_from(last.status).expect("known status")
}

fn files_request(ignore_weights: bool) -> ModelFilesRequest {
    ModelFilesRequest {
        model_name: MODEL.to_string(),
        provider: ModelProvider::HuggingFace as i32,
        chunk_size: 0,
        file_selector: None,
        ignore_weights,
        revision: Some(REVISION.to_string()),
    }
}

async fn list(
    client: &mut ModelServiceClient<Channel>,
    ignore_weights: bool,
) -> Vec<(String, u64)> {
    let mut files: Vec<(String, u64)> = client
        .list_model_files(files_request(ignore_weights))
        .await
        .expect("ListModelFiles failed")
        .into_inner()
        .files
        .into_iter()
        .map(|file| (file.relative_path, file.size))
        .collect();
    files.sort();
    files
}

async fn streamed_size(client: &mut ModelServiceClient<Channel>, path: &str) -> u64 {
    let mut request = files_request(false);
    request.file_selector = Some(modelexpress_common::grpc::model::ModelFileSelector {
        paths: vec![path.to_string()],
    });
    let mut stream = client
        .stream_model_files(request)
        .await
        .expect("StreamModelFiles failed")
        .into_inner();
    let mut total: u64 = 0;
    while let Some(chunk) = stream.message().await.expect("file chunk") {
        assert_eq!(chunk.relative_path, path);
        total = total
            .checked_add(chunk.data.len() as u64)
            .expect("size overflow");
    }
    total
}

#[tokio::test]
#[ignore = "requires Redis at REDIS_URL and Hugging Face Hub access"]
#[allow(clippy::await_holding_lock)]
async fn a_restart_that_loses_the_cache_serves_weights_again() {
    let cache = TempDir::new().expect("tempdir");
    let _env = Environment::new(cache.path(), false);
    let url = redis_url();
    forget_model(&url).await;

    let first = Server::start(cache.path(), &url);
    let mut client = first.client().await;
    assert_eq!(
        final_status(&ensure(&mut client, false).await),
        ModelStatus::Downloaded
    );
    assert!(
        list(&mut client, false)
            .await
            .contains(&(WEIGHTS.to_string(), WEIGHTS_SIZE))
    );
    first.stop().await;

    wipe(cache.path());
    let registry = RedisRegistryBackend::new(&url);
    registry.connect().await.expect("connect to Redis");
    let stale = registry
        .get_model_record(&entry_key(false))
        .await
        .expect("read registry")
        .expect("the full-weight entry outlives the cache");
    assert_eq!(stale.status, RecordStatus::DOWNLOADED);

    let second = Server::start(cache.path(), &url);
    let mut client = second.client().await;

    assert_eq!(
        final_status(&ensure(&mut client, true).await),
        ModelStatus::Downloaded
    );
    let metadata = list(&mut client, true).await;
    assert!(!metadata.is_empty());
    assert!(metadata.iter().all(|(path, _)| !is_weight_file(path)));

    let updates = ensure(&mut client, false).await;
    assert_eq!(final_status(&updates), ModelStatus::Downloaded);
    assert_ne!(
        ModelStatus::try_from(updates[0].status).expect("known status"),
        ModelStatus::Downloaded,
        "the stale full-weight entry was reported as a cache hit"
    );
    let full = list(&mut client, false).await;
    assert!(
        full.contains(&(WEIGHTS.to_string(), WEIGHTS_SIZE)),
        "weights missing after restart: {full:?}"
    );
    assert_eq!(streamed_size(&mut client, WEIGHTS).await, WEIGHTS_SIZE);

    let fresh = registry
        .get_model_record(&entry_key(false))
        .await
        .expect("read registry")
        .expect("the full-weight entry was re-recorded");
    assert_eq!(fresh.status, RecordStatus::DOWNLOADED);
    assert!(fresh.created_at > stale.created_at);

    let second_hit = ensure(&mut client, false).await;
    assert_eq!(
        second_hit
            .iter()
            .map(|update| ModelStatus::try_from(update.status).expect("known status"))
            .collect::<Vec<_>>(),
        vec![ModelStatus::Downloaded, ModelStatus::Downloaded],
        "a recorded download should be a cache hit"
    );

    client
        .delete_model(DeleteModelRequest {
            model_name: MODEL.to_string(),
            provider: ModelProvider::HuggingFace as i32,
        })
        .await
        .expect("DeleteModel failed");
    second.stop().await;
}

struct NoDeleteUser {
    admin: redis::aio::MultiplexedConnection,
    name: String,
}

impl NoDeleteUser {
    async fn create(admin_url: &str) -> (Self, String) {
        let client = redis::Client::open(admin_url).expect("parse REDIS_URL");
        let mut admin = client
            .get_multiplexed_async_connection()
            .await
            .expect("connect to Redis");
        let name = format!("mx-nodel-{}", std::process::id());
        let password = "mx-nodel-password";
        let _: () = redis::cmd("ACL")
            .arg("SETUSER")
            .arg(&name)
            .arg("reset")
            .arg("on")
            .arg(format!(">{password}"))
            .arg("~*")
            .arg("&*")
            .arg("+@all")
            .arg("-del")
            .arg("-unlink")
            .query_async(&mut admin)
            .await
            .expect("ACL SETUSER");
        let url = admin_url.replacen("redis://", &format!("redis://{name}:{password}@"), 1);
        (Self { admin, name }, url)
    }

    async fn drop_user(mut self) {
        let _: () = redis::cmd("ACL")
            .arg("DELUSER")
            .arg(&self.name)
            .query_async(&mut self.admin)
            .await
            .expect("ACL DELUSER");
    }
}

#[tokio::test]
#[ignore = "requires Redis at REDIS_URL"]
#[allow(clippy::await_holding_lock)]
async fn a_stale_entry_the_server_cannot_clear_is_an_error_not_a_hit() {
    let cache = TempDir::new().expect("tempdir");
    let _env = Environment::new(cache.path(), true);
    let url = redis_url();
    forget_model(&url).await;

    let admin = RedisRegistryBackend::new(&url);
    admin.connect().await.expect("connect to Redis");
    let key = entry_key(false);
    assert_eq!(
        admin
            .try_claim_for_download(
                &key,
                Provider::HuggingFace,
                "before-restart",
                Duration::from_secs(30)
            )
            .await
            .expect("claim"),
        ClaimOutcome::Claimed
    );
    assert!(
        admin
            .finish_download_claim(
                &key,
                Provider::HuggingFace,
                "before-restart",
                RecordStatus::DOWNLOADED,
                None
            )
            .await
            .expect("finish")
    );
    let snapshot = snapshot_dir(cache.path());
    std::fs::create_dir_all(&snapshot).expect("snapshot dir");
    std::fs::write(snapshot.join("config.json"), b"{}").expect("config");

    let (user, restricted_url) = NoDeleteUser::create(&url).await;
    let server = Server::start(cache.path(), &restricted_url);
    let mut client = server.client().await;

    let updates = ensure(&mut client, false).await;
    assert_eq!(final_status(&updates), ModelStatus::Error);
    assert!(
        updates
            .iter()
            .all(|update| update.status != ModelStatus::Downloaded as i32),
        "a stale entry was reported as downloaded: {updates:?}"
    );
    assert!(
        updates.iter().any(|update| update
            .message
            .as_deref()
            .is_some_and(|message| message.contains("missing from the server cache"))),
        "no update explained the failure: {updates:?}"
    );

    server.stop().await;
    user.drop_user().await;
    forget_model(&url).await;
}

#[tokio::test]
#[ignore = "requires Redis at REDIS_URL and Hugging Face Hub access"]
#[allow(clippy::await_holding_lock)]
async fn a_waiter_on_another_servers_download_fetches_the_weights_itself() {
    let cache = TempDir::new().expect("tempdir");
    let _env = Environment::new(cache.path(), false);
    let url = redis_url();
    forget_model(&url).await;

    let other_server = RedisRegistryBackend::new(&url);
    other_server.connect().await.expect("connect to Redis");
    let key = entry_key(false);
    assert_eq!(
        other_server
            .try_claim_for_download(
                &key,
                Provider::HuggingFace,
                "other-server",
                Duration::from_secs(60)
            )
            .await
            .expect("claim"),
        ClaimOutcome::Claimed
    );

    let server = Server::start(cache.path(), &url);
    let mut client = server.client().await;
    let mut stream = client
        .ensure_model_downloaded(download_request(false))
        .await
        .expect("EnsureModelDownloaded failed")
        .into_inner();
    let waiting = stream
        .message()
        .await
        .expect("status update")
        .expect("first update");
    assert_eq!(
        ModelStatus::try_from(waiting.status).expect("known status"),
        ModelStatus::Downloading
    );
    assert!(
        other_server
            .finish_download_claim(
                &key,
                Provider::HuggingFace,
                "other-server",
                RecordStatus::DOWNLOADED,
                None
            )
            .await
            .expect("finish")
    );

    let terminal = loop {
        let update = tokio::time::timeout(Duration::from_secs(300), stream.message())
            .await
            .expect("download stream stalled")
            .expect("status update")
            .expect("stream ended without a terminal status");
        let status = ModelStatus::try_from(update.status).expect("known status");
        if status != ModelStatus::Downloading {
            break status;
        }
    };
    drop(stream);
    assert_eq!(terminal, ModelStatus::Downloaded);
    let files = list(&mut client, false).await;
    assert!(
        files.contains(&(WEIGHTS.to_string(), WEIGHTS_SIZE)),
        "weights missing from this server's cache: {files:?}"
    );
    assert_eq!(streamed_size(&mut client, WEIGHTS).await, WEIGHTS_SIZE);

    drop(client);
    server.stop().await;
    forget_model(&url).await;
}

#[tokio::test]
#[ignore = "requires Redis at REDIS_URL and Hugging Face Hub access"]
#[allow(clippy::await_holding_lock)]
async fn a_truncated_weight_file_is_fetched_again() {
    let cache = TempDir::new().expect("tempdir");
    let _env = Environment::new(cache.path(), false);
    let url = redis_url();
    forget_model(&url).await;

    let server = Server::start(cache.path(), &url);
    let mut client = server.client().await;
    assert_eq!(
        final_status(&ensure(&mut client, false).await),
        ModelStatus::Downloaded
    );
    let weights = snapshot_dir(cache.path()).join(WEIGHTS);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&weights)
        .expect("open weights")
        .set_len(1024)
        .expect("truncate weights");

    assert_eq!(
        final_status(&ensure(&mut client, false).await),
        ModelStatus::Downloaded
    );
    let files = list(&mut client, false).await;
    assert!(
        files.contains(&(WEIGHTS.to_string(), WEIGHTS_SIZE)),
        "truncated weights were recorded instead of fetched again: {files:?}"
    );
    assert_eq!(
        std::fs::metadata(&weights).expect("weights").len(),
        WEIGHTS_SIZE
    );
    assert_eq!(streamed_size(&mut client, WEIGHTS).await, WEIGHTS_SIZE);
    assert_eq!(
        ensure(&mut client, false)
            .await
            .iter()
            .map(|update| ModelStatus::try_from(update.status).expect("known status"))
            .collect::<Vec<_>>(),
        vec![ModelStatus::Downloaded, ModelStatus::Downloaded],
        "the repaired download should be a cache hit"
    );

    drop(client);
    server.stop().await;
    forget_model(&url).await;
}
