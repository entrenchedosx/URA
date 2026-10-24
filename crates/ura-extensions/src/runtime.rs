use crate::{invalid, Result};
use serde_json::Value;
use std::io::Read;
use std::{
    fs,
    path::{Path, PathBuf},
};

pub const PYTHON_VERSION: &str = "3.14.9";
#[derive(Clone)]
pub struct Runtime {
    pub directory: PathBuf,
}
impl Runtime {
    pub fn discover() -> Result<Self> {
        let parent = std::env::current_exe()
            .map_err(|e| e.to_string())?
            .parent()
            .ok_or("executable parent missing")?
            .to_path_buf();
        Self::new(&parent.join("runtime/python"))
    }
    pub fn new(directory: &Path) -> Result<Self> {
        let directory=directory.canonicalize().map_err(|_|"Bundled CPython runtime missing; extract the complete URA ZIP or configure its runtime directory".to_string())?;
        let manifest: Value =
            serde_json::from_slice(&read_bounded(&directory.join("URA-RUNTIME.json"), 65536)?)
                .map_err(|e| e.to_string())?;
        if manifest["version"] != PYTHON_VERSION || manifest["architecture"] != "amd64" {
            return invalid("Unsupported Python runtime identity");
        }
        let lock: Value =
            serde_json::from_str(include_str!("../../../scripts/python-runtime.lock.json"))
                .map_err(|e| e.to_string())?;
        if manifest["archiveSha256"] != lock["archiveSha256"] || manifest["files"] != lock["files"]
        {
            return invalid("Runtime archive/file identities differ from the locked distribution");
        }
        let files = manifest["files"]
            .as_object()
            .ok_or("Runtime file manifest required")?;
        if files.len() > 128
            || !files.contains_key("python.exe")
            || !files.contains_key("python314.dll")
            || !files.contains_key("python314.zip")
        {
            return invalid("Incomplete runtime distribution");
        }
        for (name, hash) in files {
            if name.is_empty() || name.contains(['/', '\\', ':']) || name == ".." {
                return invalid("Unsafe runtime member");
            }
            let path = directory.join(name);
            let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() > 64 * 1024 * 1024
                || ura_core::sha256_hex(&read_bounded(&path, 64 * 1024 * 1024)?)
                    != hash.as_str().unwrap_or("")
            {
                return invalid("Runtime member hash/type mismatch");
            }
        }
        Ok(Self { directory })
    }
    pub fn executable(&self) -> PathBuf {
        self.directory.join("python.exe")
    }
    pub fn worker_sources() -> Result<tempfile::TempDir> {
        let folder = tempfile::tempdir().map_err(|e| e.to_string())?;
        fs::create_dir(folder.path().join("ura")).map_err(|e| e.to_string())?;
        fs::write(
            folder.path().join("worker.py"),
            include_str!("../../../sdk/python/worker.py"),
        )
        .map_err(|e| e.to_string())?;
        fs::write(
            folder.path().join("ura/__init__.py"),
            include_str!("../../../sdk/python/ura/__init__.py"),
        )
        .map_err(|e| e.to_string())?;
        Ok(folder)
    }
}

pub(crate) fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(max + 1)
        .read_to_end(&mut b)
        .map_err(|e| e.to_string())?;
    if b.len() as u64 > max {
        invalid("File size limit exceeded")
    } else {
        Ok(b)
    }
}
