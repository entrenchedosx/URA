use crate::{invalid, Result, API_VERSION};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub const CAPABILITIES: &[&str] = &[
    "project.read",
    "analysis.read",
    "project.write",
    "analysis.symbolic",
    "emulation.execute",
    "debugger.read",
    "debugger.control",
    "files.export",
    "events.subscribe",
    "loader.register",
    "processor.register",
    "ui.commands",
];
pub const EVENTS: &[&str] = &[
    "binary.loaded",
    "project.closed",
    "analysis.started",
    "analysis.completed",
    "function.renamed",
    "comment.changed",
    "metadata.changed",
];
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Command {
    pub id: String,
    pub title: String,
    pub callback: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub license: String,
    pub entrypoint: String,
    pub api_version: u32,
    pub minimum_ura_version: String,
    pub required_capabilities: BTreeSet<String>,
    #[serde(default)]
    pub optional_capabilities: BTreeSet<String>,
    pub platforms: Vec<String>,
    pub architectures: Vec<String>,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub configuration_schema: Value,
    #[serde(default)]
    pub commands: Vec<Command>,
    #[serde(default)]
    pub events: BTreeMap<String, String>,
    #[serde(default)]
    pub analyzer: Option<String>,
    #[serde(default)]
    pub loader: Option<String>,
    #[serde(default)]
    pub processor: Option<String>,
}
fn identifier(value: &str) -> bool {
    value != "enabled.json"
        && safe_member(value).is_ok()
        && !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(&c))
        && !value.starts_with('.')
}
fn callback(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_')
        && !value.starts_with('_')
}
fn safe_member(value: &str) -> Result<PathBuf> {
    if value.split('/').count() > 16
        || value.is_empty()
        || value.len() > 240
        || value.contains(['\\', ':', '\0'])
        || value.starts_with('/')
    {
        return invalid("Unsafe package path");
    }
    let mut path = PathBuf::new();
    for part in value.split('/') {
        let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.ends_with([' ', '.'])
            || part.chars().any(char::is_control)
            || [
                "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
                "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
                "LPT9",
            ]
            .contains(&stem.as_str())
        {
            return invalid("Unsafe package member");
        }
        path.push(part);
    }
    Ok(path)
}
impl Manifest {
    pub fn validate(&self) -> Result<()> {
        let version = semver::Version::parse(&self.version).map_err(|e| e.to_string())?;
        let min = semver::Version::parse(&self.minimum_ura_version).map_err(|e| e.to_string())?;
        let host = semver::Version::parse(env!("CARGO_PKG_VERSION")).map_err(|e| e.to_string())?;
        if !identifier(&self.id)
            || self.api_version != API_VERSION
            || (min.major, min.minor, min.patch) > (host.major, host.minor, host.patch)
            || version.major > 10000
        {
            return invalid("Incompatible plugin ID/API/application version");
        }
        for text in [&self.name, &self.author, &self.description, &self.license] {
            if text.is_empty() || text.len() > 2048 || text.chars().any(|c| c == '\0') {
                return invalid("Invalid plugin metadata");
            }
        }
        if !self.platforms.iter().any(|v| v == "windows-x64")
            || self.platforms.len() > 8
            || self.architectures.is_empty()
            || self.architectures.len() > 16
            || self
                .architectures
                .iter()
                .any(|p| ura_core::processor::Processor::parse(p).is_none() && p != "toy8")
        {
            return invalid("Plugin platform/architecture incompatible");
        }
        if !self.dependencies.is_empty() {
            return invalid("Plugin dependency installation is not supported; vendor explicitly trusted pure-Python modules");
        }
        let entry = safe_member(&self.entrypoint)?;
        if entry.extension().is_none_or(|v| v != "py") {
            return invalid("Python entrypoint required");
        }
        if self
            .required_capabilities
            .iter()
            .chain(&self.optional_capabilities)
            .any(|v| !CAPABILITIES.contains(&v.as_str()))
        {
            return invalid("Unsupported plugin capability");
        }
        if self.commands.len() > 32
            || self.events.len() > 16
            || self.commands.iter().any(|c| {
                !identifier(&c.id)
                    || !callback(&c.callback)
                    || c.title.is_empty()
                    || c.title.len() > 128
            })
            || self
                .events
                .iter()
                .any(|(e, c)| !EVENTS.contains(&e.as_str()) || !callback(c))
            || [&self.analyzer, &self.loader, &self.processor]
                .iter()
                .any(|c| c.as_ref().is_some_and(|v| !callback(v)))
        {
            return invalid("Invalid plugin extension registration");
        }
        let mut ids = BTreeSet::new();
        if self.commands.iter().any(|c| !ids.insert(&c.id)) {
            return invalid("Duplicate plugin command ID");
        }
        validate_configuration(&self.configuration_schema, &json!({}), false)?;
        Ok(())
    }
}
pub fn validate_configuration(schema: &Value, config: &Value, require: bool) -> Result<()> {
    if serde_json::to_vec(config).map_err(|e| e.to_string())?.len() > 16384 {
        return invalid("Configuration exceeds16KiB");
    }
    if schema.is_null() {
        if !config.is_object() {
            return invalid("Configuration must be an object");
        }
        return Ok(());
    }
    if !schema.is_object()
        || schema["type"] != "object"
        || !config.is_object()
        || serde_json::to_vec(schema).map_err(|e| e.to_string())?.len() > 16384
        || serde_json::to_vec(config).map_err(|e| e.to_string())?.len() > 16384
    {
        return invalid("Only bounded object configuration schemas are supported");
    }
    let props = schema["properties"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    if props.len() > 32 {
        return invalid("Configuration property limit");
    }
    for (name, value) in config.as_object().unwrap() {
        let property = props
            .get(name)
            .ok_or("Unknown plugin configuration property")?;
        let valid = match property["type"].as_str() {
            Some("string") => value.as_str().is_some_and(|s| s.len() <= 4096),
            Some("integer") => value.as_i64().is_some(),
            Some("boolean") => value.is_boolean(),
            _ => false,
        };
        if !valid
            || property["enum"]
                .as_array()
                .is_some_and(|vs| !vs.contains(value))
        {
            return invalid("Configuration property type/enum mismatch");
        }
    }
    for property in props.values() {
        if !matches!(
            property["type"].as_str(),
            Some("string" | "integer" | "boolean")
        ) {
            return invalid("Unsupported configuration schema type");
        }
    }
    if require
        && schema["required"].as_array().is_some_and(|keys| {
            keys.iter()
                .any(|k| k.as_str().is_none_or(|k| config.get(k).is_none()))
        })
    {
        return invalid("Required plugin configuration missing");
    }
    Ok(())
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Grant {
    pub digest: String,
    pub capabilities: BTreeSet<String>,
    #[serde(default)]
    pub configuration: Value,
}
#[derive(Clone)]
pub struct Registry {
    pub root: PathBuf,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Installed {
    pub manifest: Manifest,
    pub digest: String,
    pub enabled: bool,
    pub grants: Option<Grant>,
    pub trust: String,
}
impl Registry {
    pub fn new(root: &Path) -> Result<Self> {
        fs::create_dir_all(root).map_err(|e| e.to_string())?;
        reject_link(root)?;
        let metadata = fs::symlink_metadata(root).map_err(|e| e.to_string())?;
        if metadata.file_type().is_symlink() {
            return invalid("Registry cannot be a symlink");
        }
        Ok(Self {
            root: root.canonicalize().map_err(|e| e.to_string())?,
        })
    }
    fn grants(&self) -> Result<BTreeMap<String, Grant>> {
        let p = self.root.join("enabled.json");
        if !p.exists() {
            return Ok(BTreeMap::new());
        }
        reject_link(&p)?;
        if fs::metadata(&p).map_err(|e| e.to_string())?.len() > 65536 {
            return invalid("Registry grant document too large");
        }
        serde_json::from_slice(&crate::runtime::read_bounded(&p, 65536)?).map_err(|e| e.to_string())
    }
    fn write_grants(&self, grants: &BTreeMap<String, Grant>) -> Result<()> {
        let data = serde_json::to_vec_pretty(grants).map_err(|e| e.to_string())?;
        if data.len() > 65536 {
            return invalid("Grant registry capacity exceeded; existing grants preserved");
        }
        let mut temp = tempfile::NamedTempFile::new_in(&self.root).map_err(|e| e.to_string())?;
        temp.write_all(&data).map_err(|e| e.to_string())?;
        temp.persist(self.root.join("enabled.json"))
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    pub fn inspect(&self, id: &str) -> Result<Installed> {
        if !identifier(id) {
            return invalid("Invalid plugin ID");
        }
        let folder = self.root.join(id);
        reject_link(&folder)?;
        let manifest = read_manifest(&folder)?;
        if manifest.id != id {
            return invalid("Directory and manifest identities differ");
        }
        let digest = tree_digest(&folder)?;
        let grant = self.grants()?.remove(id);
        let enabled = grant.as_ref().is_some_and(|g| g.digest == digest);
        Ok(Installed {
            manifest,
            digest,
            enabled,
            grants: grant,
            trust: "user-installed code; trusted only by explicit enablement; not sandboxed".into(),
        })
    }
    pub fn list(&self) -> Result<Value> {
        let mut rows = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || !entry.file_type().map_err(|e| e.to_string())?.is_dir() {
                continue;
            }
            if rows.len() >= 128 {
                return invalid("Installed plugin count exceeds128");
            }
            rows.push(match self.inspect(&name) {
                Ok(p) => json!(p),
                Err(e) => json!({"id":name,"enabled":false,"error":e}),
            });
        }
        Ok(json!({"plugins":rows}))
    }
    pub fn install(&self, archive: &Path) -> Result<Installed> {
        self.grants()?;
        if self.list()?["plugins"]
            .as_array()
            .is_some_and(|p| p.len() >= 128)
        {
            return invalid("Installed plugin capacity128 exceeded");
        }
        let archive = crate::runtime::read_bounded(archive, 16 * 1024 * 1024)?;
        let mut zip =
            zip::ZipArchive::new(std::io::Cursor::new(archive)).map_err(|e| e.to_string())?;
        if zip.len() > 128 {
            return invalid("Plugin member count exceeds128");
        }
        let staging = tempfile::Builder::new()
            .prefix(".install-")
            .tempdir_in(&self.root)
            .map_err(|e| e.to_string())?;
        let mut names = BTreeSet::new();
        let mut total = 0u64;
        for n in 0..zip.len() {
            let mut item = zip.by_index(n).map_err(|e| e.to_string())?;
            let name = safe_member(item.name().trim_end_matches('/'))?;
            if !names.insert(item.name().trim_end_matches('/').to_ascii_lowercase())
                || item.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000)
            {
                return invalid("Duplicate or symlink package member");
            }
            if item.is_dir() {
                continue;
            }
            total = total
                .checked_add(item.size())
                .ok_or("Package size overflow")?;
            if total > 16 * 1024 * 1024 || item.size() > 4 * 1024 * 1024 {
                return invalid("Expanded plugin size limit");
            }
            let destination = staging.path().join(name);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)
                .map_err(|e| e.to_string())?;
            let copied = std::io::copy(&mut Read::take(&mut item, 4 * 1024 * 1024 + 1), &mut file)
                .map_err(|e| e.to_string())?;
            if copied != item.size() {
                return invalid("Truncated/oversized package member");
            }
        }
        let manifest = read_manifest(staging.path())?;
        tree_digest(staging.path())?;
        let target = self.root.join(&manifest.id);
        if target.exists() {
            return invalid("Plugin ID already installed; explicit uninstall required");
        }
        fs::rename(staging.path(), &target).map_err(|e| e.to_string())?;
        self.inspect(&manifest.id)
    }
    pub fn snapshot(&self, id: &str) -> Result<(Installed, tempfile::TempDir)> {
        let plugin = self.inspect(id)?;
        if !plugin.enabled {
            return invalid("Plugin is disabled or changed");
        }
        let folder = tempfile::tempdir().map_err(|e| e.to_string())?;
        let source = self.root.join(id);
        let mut pending = vec![PathBuf::new()];
        let mut count = 0;
        while let Some(relative) = pending.pop() {
            for entry in fs::read_dir(source.join(&relative)).map_err(|e| e.to_string())? {
                let entry = entry.map_err(|e| e.to_string())?;
                count += 1;
                if count > 256 {
                    return invalid("Plugin snapshot count limit");
                }
                reject_link(&entry.path())?;
                let dest = relative.join(entry.file_name());
                if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
                    fs::create_dir(folder.path().join(&dest)).map_err(|e| e.to_string())?;
                    pending.push(dest);
                } else {
                    let bytes = crate::runtime::read_bounded(&entry.path(), 4 * 1024 * 1024)?;
                    fs::write(folder.path().join(dest), bytes).map_err(|e| e.to_string())?;
                }
            }
        }
        if tree_digest(folder.path())? != plugin.digest {
            return invalid("Plugin changed during snapshot; execution rejected");
        }
        Ok((plugin, folder))
    }
    pub fn enable(
        &self,
        id: &str,
        capabilities: BTreeSet<String>,
        configuration: Value,
    ) -> Result<Installed> {
        let plugin = self.inspect(id)?;
        let m = &plugin.manifest;
        if !m.required_capabilities.is_subset(&capabilities)
            || capabilities.iter().any(|c| {
                !m.required_capabilities.contains(c) && !m.optional_capabilities.contains(c)
            })
        {
            return invalid("Explicit grants must include required and only declared capabilities");
        }
        validate_configuration(&m.configuration_schema, &configuration, true)?;
        let mut grants = self.grants()?;
        grants.insert(
            id.into(),
            Grant {
                digest: plugin.digest,
                capabilities,
                configuration,
            },
        );
        self.write_grants(&grants)?;
        self.inspect(id)
    }
    pub fn disable(&self, id: &str) -> Result<()> {
        if !identifier(id) {
            return invalid("Invalid plugin ID");
        }
        reject_link(&self.root.join(id))?;
        let mut grants = self.grants()?;
        grants.remove(id);
        self.write_grants(&grants)
    }
    pub fn uninstall(&self, id: &str) -> Result<()> {
        self.disable(id)?;
        let folder = self.root.join(id);
        let resolved = folder.canonicalize().map_err(|e| e.to_string())?;
        if resolved.parent() != Some(self.root.as_path()) {
            return invalid("Plugin removal escaped registry");
        }
        fs::remove_dir_all(resolved).map_err(|e| e.to_string())
    }
}
fn read_manifest(folder: &Path) -> Result<Manifest> {
    let path = folder.join("ura-plugin.json");
    let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 32768 {
        return invalid("Invalid manifest type/size");
    }
    let m: Manifest = serde_json::from_slice(&crate::runtime::read_bounded(&path, 32768)?)
        .map_err(|e| e.to_string())?;
    m.validate()?;
    let entry = folder
        .join(safe_member(&m.entrypoint)?)
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let root = folder.canonicalize().map_err(|e| e.to_string())?;
    if !entry.starts_with(&root) || !entry.is_file() {
        return invalid("Entrypoint escapes plugin");
    }
    Ok(m)
}
fn tree_digest(folder: &Path) -> Result<String> {
    let mut pending = vec![folder.to_path_buf()];
    let mut files = BTreeMap::new();
    let mut bytes = 0;
    let mut nodes = 0;
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            nodes += 1;
            if nodes > 256 {
                return invalid("Plugin file/directory count exceeds256");
            }
            reject_link(&entry.path())?;
            let ty = entry.file_type().map_err(|e| e.to_string())?;
            if ty.is_symlink() {
                return invalid("Plugin symlinks are forbidden");
            }
            if ty.is_dir() {
                pending.push(entry.path());
                if pending.len() > 128 {
                    return invalid("Plugin directory limit");
                }
                continue;
            }
            if !ty.is_file() {
                return invalid("Plugin special files are forbidden");
            }
            let size = entry.metadata().map_err(|e| e.to_string())?.len();
            bytes += size;
            if bytes > 16 * 1024 * 1024 || files.len() >= 128 {
                return invalid("Plugin tree limit");
            }
            files.insert(
                entry
                    .path()
                    .strip_prefix(folder)
                    .map_err(|e| e.to_string())?
                    .to_string_lossy()
                    .replace('\\', "/"),
                ura_core::sha256_hex(&crate::runtime::read_bounded(
                    &entry.path(),
                    4 * 1024 * 1024,
                )?),
            );
        }
    }
    Ok(ura_core::sha256_hex(
        &serde_json::to_vec(&files).map_err(|e| e.to_string())?,
    ))
}

fn reject_link(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if m.file_type().is_symlink() {
        return invalid("Plugin links are forbidden");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if m.file_attributes() & 0x400 != 0 {
            return invalid("Plugin reparse points are forbidden");
        }
    }
    Ok(())
}
