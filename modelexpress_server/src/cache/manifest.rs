// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-volume record of the files a completed download left in the cache.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};
use modelexpress_common::digest::sha256_hex;
use serde::{Deserialize, Serialize};
use tracing::warn;

const MANIFEST_DIR: &str = ".modelexpress/downloads";

/// The files a completed download of one registry entry left in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadManifest {
    entry_key: String,
    files: Vec<ManifestFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ManifestFile {
    path: PathBuf,
    size: u64,
}

impl DownloadManifest {
    /// `files` are paths relative to the snapshot directory, with their sizes.
    pub fn new(
        entry_key: impl Into<String>,
        files: impl IntoIterator<Item = (PathBuf, u64)>,
    ) -> Self {
        let mut files: Vec<ManifestFile> = files
            .into_iter()
            .map(|(path, size)| ManifestFile { path, size })
            .collect();
        files.sort_by(|a, b| a.path.cmp(&b.path));
        Self {
            entry_key: entry_key.into(),
            files,
        }
    }

    /// Atomically replace this entry's manifest under `cache_dir`.
    pub fn write(&self, cache_dir: &Path) -> Result<()> {
        if self.files.is_empty() {
            bail!(
                "download of '{}' left no files in the cache",
                self.entry_key
            );
        }
        let dir = cache_dir.join(MANIFEST_DIR);
        fs::create_dir_all(&dir)
            .map_err(|e| anyhow!("failed to create '{}': {e}", dir.display()))?;
        let path = manifest_path(cache_dir, &self.entry_key)?;

        let body = serde_json::to_vec(self)
            .map_err(|e| anyhow!("failed to serialize download manifest: {e}"))?;
        let staging = dir.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
        if let Err(e) = fs::write(&staging, body).and_then(|()| fs::rename(&staging, &path)) {
            let _ = fs::remove_file(&staging);
            bail!("failed to write '{}': {e}", path.display());
        }
        Ok(())
    }

    /// The manifest recorded for `entry_key`, if one exists and is readable.
    pub fn read(cache_dir: &Path, entry_key: &str) -> Option<Self> {
        let path = manifest_path(cache_dir, entry_key).ok()?;
        let body = match fs::read(&path) {
            Ok(body) => body,
            Err(e) if e.kind() == ErrorKind::NotFound => return None,
            Err(e) => {
                warn!("Failed to read download manifest '{}': {e}", path.display());
                return None;
            }
        };
        match serde_json::from_slice::<Self>(&body) {
            Ok(manifest) if manifest.entry_key == entry_key => Some(manifest),
            Ok(manifest) => {
                warn!(
                    "Download manifest '{}' belongs to '{}', not '{entry_key}'",
                    path.display(),
                    manifest.entry_key
                );
                None
            }
            Err(e) => {
                warn!(
                    "Failed to parse download manifest '{}': {e}",
                    path.display()
                );
                None
            }
        }
    }

    /// True when every recorded file is in `snapshot_dir` at its recorded size.
    pub fn is_satisfied_by(&self, snapshot_dir: &Path) -> bool {
        self.files.iter().all(|file| {
            fs::metadata(snapshot_dir.join(&file.path))
                .is_ok_and(|meta| meta.is_file() && meta.len() == file.size)
        })
    }

    /// Delete the manifest for `entry_key`. A missing manifest is not an error.
    pub fn remove(cache_dir: &Path, entry_key: &str) -> Result<()> {
        let path = manifest_path(cache_dir, entry_key)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => bail!("failed to remove '{}': {e}", path.display()),
        }
    }
}

fn manifest_path(cache_dir: &Path, entry_key: &str) -> Result<PathBuf> {
    let digest = sha256_hex(entry_key.as_bytes())?;
    Ok(cache_dir.join(MANIFEST_DIR).join(format!("{digest}.json")))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use crate::cache::manifest::{DownloadManifest, MANIFEST_DIR, manifest_path};
    use std::fs;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    const KEY: &str = "mx1:abc123:-:org/model";

    fn snapshot_with(root: &Path, files: &[(&str, &[u8])]) -> PathBuf {
        let snapshot = root.join("models--org--model/snapshots/abc123");
        for (name, body) in files {
            let path = snapshot.join(name);
            fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            fs::write(path, body).expect("write file");
        }
        snapshot
    }

    fn manifest_of(files: &[(&str, &[u8])]) -> DownloadManifest {
        DownloadManifest::new(
            KEY,
            files
                .iter()
                .map(|(name, body)| (PathBuf::from(name), body.len() as u64)),
        )
    }

    const FILES: &[(&str, &[u8])] = &[
        ("config.json", b"{}"),
        ("model.safetensors", b"weights"),
        ("nested/tokenizer.json", b"tok"),
    ];

    #[test]
    fn a_written_manifest_reads_back_unchanged() {
        let cache = TempDir::new().expect("tempdir");
        let manifest = manifest_of(FILES);
        manifest.write(cache.path()).expect("write");
        assert_eq!(DownloadManifest::read(cache.path(), KEY), Some(manifest));
    }

    #[test]
    fn a_missing_manifest_reads_as_none() {
        let cache = TempDir::new().expect("tempdir");
        assert_eq!(DownloadManifest::read(cache.path(), KEY), None);
    }

    #[test]
    fn each_entry_key_gets_its_own_manifest() {
        let cache = TempDir::new().expect("tempdir");
        let full = manifest_of(FILES);
        full.write(cache.path()).expect("write full");

        let metadata_key = "mx1:abc123:m:org/model";
        assert_eq!(DownloadManifest::read(cache.path(), metadata_key), None);

        let metadata = DownloadManifest::new(metadata_key, [(PathBuf::from("config.json"), 2)]);
        metadata.write(cache.path()).expect("write metadata");
        assert_eq!(DownloadManifest::read(cache.path(), KEY), Some(full));
        assert_eq!(
            DownloadManifest::read(cache.path(), metadata_key),
            Some(metadata)
        );
    }

    #[test]
    fn rewriting_replaces_the_previous_manifest_and_leaves_no_staging_files() {
        let cache = TempDir::new().expect("tempdir");
        manifest_of(&FILES[..1]).write(cache.path()).expect("first");
        let second = manifest_of(FILES);
        second.write(cache.path()).expect("second");

        assert_eq!(DownloadManifest::read(cache.path(), KEY), Some(second));
        let entries: Vec<_> = fs::read_dir(cache.path().join(MANIFEST_DIR))
            .expect("read dir")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(entries.len(), 1, "unexpected files: {entries:?}");
    }

    #[test]
    fn an_empty_manifest_is_refused() {
        let cache = TempDir::new().expect("tempdir");
        let empty = DownloadManifest::new(KEY, Vec::new());
        assert!(empty.write(cache.path()).is_err());
        assert_eq!(DownloadManifest::read(cache.path(), KEY), None);
    }

    #[test]
    fn a_corrupt_manifest_reads_as_none() {
        let cache = TempDir::new().expect("tempdir");
        let path = manifest_path(cache.path(), KEY).expect("path");
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(&path, b"{not json").expect("write");
        assert_eq!(DownloadManifest::read(cache.path(), KEY), None);
    }

    #[test]
    fn a_manifest_recorded_for_another_key_is_not_trusted() {
        let cache = TempDir::new().expect("tempdir");
        let other = DownloadManifest::new("org/other", [(PathBuf::from("config.json"), 2)]);
        let body = serde_json::to_vec(&other).expect("serialize");
        let path = manifest_path(cache.path(), KEY).expect("path");
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(&path, body).expect("write");
        assert_eq!(DownloadManifest::read(cache.path(), KEY), None);
    }

    #[test]
    fn a_complete_snapshot_satisfies_its_manifest() {
        let cache = TempDir::new().expect("tempdir");
        let snapshot = snapshot_with(cache.path(), FILES);
        assert!(manifest_of(FILES).is_satisfied_by(&snapshot));
    }

    #[test]
    fn extra_files_in_the_snapshot_do_not_matter() {
        let cache = TempDir::new().expect("tempdir");
        let snapshot = snapshot_with(cache.path(), FILES);
        assert!(manifest_of(&FILES[..1]).is_satisfied_by(&snapshot));
    }

    #[test]
    fn a_missing_file_fails_the_manifest() {
        let cache = TempDir::new().expect("tempdir");
        let snapshot = snapshot_with(cache.path(), FILES);
        fs::remove_file(snapshot.join("model.safetensors")).expect("remove");
        assert!(!manifest_of(FILES).is_satisfied_by(&snapshot));
    }

    #[test]
    fn a_file_of_the_wrong_size_fails_the_manifest() {
        let cache = TempDir::new().expect("tempdir");
        let snapshot = snapshot_with(cache.path(), FILES);
        fs::write(snapshot.join("model.safetensors"), b"trunc").expect("truncate");
        assert!(!manifest_of(FILES).is_satisfied_by(&snapshot));
    }

    #[test]
    fn a_directory_where_a_file_belongs_fails_the_manifest() {
        let cache = TempDir::new().expect("tempdir");
        let snapshot = snapshot_with(cache.path(), &FILES[..1]);
        fs::create_dir_all(snapshot.join("model.safetensors")).expect("mkdir");
        assert!(!manifest_of(&FILES[..2]).is_satisfied_by(&snapshot));
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_fails_the_manifest() {
        let cache = TempDir::new().expect("tempdir");
        let snapshot = snapshot_with(cache.path(), &FILES[..1]);
        let blob = cache.path().join("models--org--model/blobs/deadbeef");
        fs::create_dir_all(blob.parent().expect("parent")).expect("mkdir");
        fs::write(&blob, b"weights").expect("write blob");
        std::os::unix::fs::symlink(&blob, snapshot.join("model.safetensors")).expect("symlink");
        assert!(manifest_of(&FILES[..2]).is_satisfied_by(&snapshot));

        fs::remove_file(&blob).expect("remove blob");
        assert!(!manifest_of(&FILES[..2]).is_satisfied_by(&snapshot));
    }

    #[test]
    fn removing_a_manifest_is_idempotent() {
        let cache = TempDir::new().expect("tempdir");
        manifest_of(FILES).write(cache.path()).expect("write");
        DownloadManifest::remove(cache.path(), KEY).expect("remove");
        assert_eq!(DownloadManifest::read(cache.path(), KEY), None);
        DownloadManifest::remove(cache.path(), KEY).expect("remove again");
    }

    #[test]
    fn manifests_stay_out_of_every_provider_layout() {
        let cache = TempDir::new().expect("tempdir");
        let path = manifest_path(cache.path(), "gs://bucket/../../escape").expect("path");
        assert_eq!(
            path.parent().expect("parent"),
            cache.path().join(MANIFEST_DIR)
        );
    }
}
