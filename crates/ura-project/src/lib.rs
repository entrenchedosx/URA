use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::path::{Path, PathBuf};
use thiserror::Error;
use ura_core::{format_address, parse_address, sha256_hex};

pub const SCHEMA_VERSION: i64 = 3;
pub const MAX_VIEW_STATE_BYTES: usize = 512 * 1024;

#[derive(Debug, Error)]
pub enum ProjectError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("database error: {0}")]
    Database(String),
    #[error("not a URA project: {0}")]
    InvalidProject(String),
    #[error("project schema version {found} is newer than supported version {supported}")]
    UnsupportedSchema { found: i64, supported: i64 },
    #[error("project file already exists: {0}")]
    AlreadyExists(String),
    #[error("project file does not exist: {0}")]
    NotFound(String),
    #[error("address is invalid: {0}")]
    InvalidAddress(String),
    #[error("function name is invalid: {0}")]
    InvalidName(String),
    #[error("view state is invalid: {0}")]
    InvalidViewState(String),
    #[error("export destination is invalid: {0}")]
    InvalidExport(String),
}

impl From<std::io::Error> for ProjectError {
    fn from(value: std::io::Error) -> Self {
        ProjectError::Io(value.to_string())
    }
}

impl From<rusqlite::Error> for ProjectError {
    fn from(value: rusqlite::Error) -> Self {
        ProjectError::Database(value.to_string())
    }
}

pub type ProjectResult<T> = std::result::Result<T, ProjectError>;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BinaryIdentity {
    pub binary_path: String,
    pub binary_hash: String,
    pub file_size: u64,
    pub format: String,
    pub architecture: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectInfo {
    pub schema_version: i64,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
    pub binary_path: String,
    pub binary_hash: String,
    pub file_size: u64,
    pub format: String,
    pub architecture: String,
    pub selected_address: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Annotation {
    pub id: i64,
    pub address: String,
    pub label: Option<String>,
    pub note: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionNameEntry {
    pub address: String,
    pub name: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManualFunction {
    pub address: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectSnapshot {
    pub project: ProjectInfo,
    pub annotations: Vec<Annotation>,
    pub function_names: Vec<FunctionNameEntry>,
    pub manual_functions: Vec<ManualFunction>,
    pub view_state: Option<String>,
    pub binary_status: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportSummary {
    pub path: String,
    pub annotation_count: usize,
    pub function_name_count: usize,
    pub manual_function_count: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AnnotationExport {
    format: &'static str,
    version: u32,
    exported_at: String,
    binary: ExportBinary,
    project: ExportProject,
    annotations: Vec<Annotation>,
    function_names: Vec<FunctionNameEntry>,
    manual_functions: Vec<ManualFunction>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportBinary {
    path: String,
    sha256: String,
    file_size: u64,
    format: String,
    architecture: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportProject {
    name: String,
}

pub fn create_project(
    project_path: &Path,
    name: &str,
    binary: &BinaryIdentity,
) -> ProjectResult<ProjectInfo> {
    if project_path.exists() {
        return Err(ProjectError::AlreadyExists(
            project_path.to_string_lossy().to_string(),
        ));
    }
    let connection = Connection::open(project_path)?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    initialize_schema(&connection)?;
    let project_name = if name.trim().is_empty() {
        project_path
            .file_stem()
            .map(|stem| stem.to_string_lossy().to_string())
            .unwrap_or_else(|| "URA Project".to_string())
    } else {
        name.trim().to_string()
    };
    connection.execute(
        "INSERT INTO project \
         (id, name, created_at, updated_at, binary_path, binary_hash, file_size, format, architecture, selected_address) \
         VALUES (1, ?1, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?2, ?3, ?4, ?5, ?6, NULL)",
        params![
            project_name,
            binary.binary_path,
            binary.binary_hash,
            binary.file_size as i64,
            binary.format,
            binary.architecture
        ],
    )?;
    load_project(&connection)
}

pub fn open_project(project_path: &Path) -> ProjectResult<ProjectSnapshot> {
    if !project_path.exists() {
        return Err(ProjectError::NotFound(
            project_path.to_string_lossy().to_string(),
        ));
    }
    let connection = Connection::open(project_path)?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    migrate_schema(&connection)?;
    let project = load_project(&connection)?;
    let annotations = load_annotations(&connection)?;
    let function_names = load_function_names(&connection)?;
    let manual_functions = load_manual_functions(&connection)?;
    let view_state = load_view_state(&connection)?;
    let binary_status = binary_status(&project);
    Ok(ProjectSnapshot {
        project,
        annotations,
        function_names,
        manual_functions,
        view_state,
        binary_status,
    })
}

pub fn save_annotation(
    project_path: &Path,
    address: &str,
    label: Option<&str>,
    note: &str,
) -> ProjectResult<Annotation> {
    let normalized = normalize_address(address)?;
    let connection = open_existing(project_path)?;
    let transaction = connection.unchecked_transaction()?;
    let label = label
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let note = note.trim().to_string();
    transaction.execute(
        "INSERT INTO annotations (address, label, note, created_at, updated_at) \
         VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now')) \
         ON CONFLICT(address) DO UPDATE SET label = excluded.label, note = excluded.note, \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
        params![normalized, label, note],
    )?;
    transaction.execute(
        "UPDATE project SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = 1",
        [],
    )?;
    transaction.commit()?;
    connection
        .query_row(
            "SELECT id, address, label, note, created_at, updated_at FROM annotations WHERE address = ?1",
            params![normalized],
            map_annotation,
        )
        .map_err(ProjectError::from)
}

pub fn set_selected_address(project_path: &Path, address: &str) -> ProjectResult<String> {
    let normalized = normalize_address(address)?;
    let connection = open_existing(project_path)?;
    connection.execute(
        "UPDATE project SET selected_address = ?1, \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = 1",
        params![normalized],
    )?;
    Ok(normalized)
}

pub fn save_function_name(
    project_path: &Path,
    address: &str,
    name: &str,
) -> ProjectResult<FunctionNameEntry> {
    let normalized = normalize_address(address)?;
    let name = name.trim();
    if name.is_empty() {
        return Err(ProjectError::InvalidName(
            "function names cannot be empty".to_string(),
        ));
    }
    if name.chars().count() > 256 {
        return Err(ProjectError::InvalidName(
            "function names are limited to 256 characters".to_string(),
        ));
    }
    let connection = open_existing(project_path)?;
    let transaction = connection.unchecked_transaction()?;
    transaction.execute(
        "INSERT INTO function_names (address, name, updated_at) \
         VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ','now')) \
         ON CONFLICT(address) DO UPDATE SET name = excluded.name, \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
        params![normalized, name],
    )?;
    transaction.execute(
        "UPDATE project SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = 1",
        [],
    )?;
    transaction.commit()?;
    connection
        .query_row(
            "SELECT address, name, updated_at FROM function_names WHERE address = ?1",
            params![normalized],
            map_function_name,
        )
        .map_err(ProjectError::from)
}

pub fn delete_function_name(project_path: &Path, address: &str) -> ProjectResult<()> {
    let normalized = normalize_address(address)?;
    let connection = open_existing(project_path)?;
    let transaction = connection.unchecked_transaction()?;
    transaction.execute(
        "DELETE FROM function_names WHERE address = ?1",
        params![normalized],
    )?;
    transaction.execute(
        "UPDATE project SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = 1",
        [],
    )?;
    transaction.commit()?;
    Ok(())
}

pub fn load_function_names_for_path(project_path: &Path) -> ProjectResult<Vec<FunctionNameEntry>> {
    let connection = open_existing(project_path)?;
    load_function_names(&connection)
}

pub fn add_manual_function(project_path: &Path, address: &str) -> ProjectResult<ManualFunction> {
    let normalized = normalize_address(address)?;
    let connection = open_existing(project_path)?;
    let transaction = connection.unchecked_transaction()?;
    transaction.execute(
        "INSERT INTO manual_functions (address, created_at) \
         VALUES (?1, strftime('%Y-%m-%dT%H:%M:%fZ','now')) \
         ON CONFLICT(address) DO NOTHING",
        params![normalized],
    )?;
    transaction.execute(
        "UPDATE project SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = 1",
        [],
    )?;
    transaction.commit()?;
    connection
        .query_row(
            "SELECT address, created_at FROM manual_functions WHERE address = ?1",
            params![normalized],
            map_manual_function,
        )
        .map_err(ProjectError::from)
}

pub fn delete_manual_function(project_path: &Path, address: &str) -> ProjectResult<bool> {
    let normalized = normalize_address(address)?;
    let connection = open_existing(project_path)?;
    let transaction = connection.unchecked_transaction()?;
    let removed = transaction.execute(
        "DELETE FROM manual_functions WHERE address = ?1",
        params![normalized],
    )?;
    if removed > 0 {
        transaction.execute(
            "UPDATE project SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = 1",
            [],
        )?;
    }
    transaction.commit()?;
    Ok(removed > 0)
}

pub fn load_manual_functions_for_path(project_path: &Path) -> ProjectResult<Vec<ManualFunction>> {
    let connection = open_existing(project_path)?;
    load_manual_functions(&connection)
}

pub fn save_view_state(project_path: &Path, state: &str) -> ProjectResult<()> {
    if state.len() > MAX_VIEW_STATE_BYTES {
        return Err(ProjectError::InvalidViewState(
            "view state is too large".to_string(),
        ));
    }
    serde_json::from_str::<serde_json::Value>(state).map_err(|error| {
        ProjectError::InvalidViewState(format!("view state must be valid JSON: {error}"))
    })?;
    let connection = open_existing(project_path)?;
    let transaction = connection.unchecked_transaction()?;
    transaction.execute(
        "INSERT INTO view_state (id, state, updated_at) \
         VALUES (1, ?1, strftime('%Y-%m-%dT%H:%M:%fZ','now')) \
         ON CONFLICT(id) DO UPDATE SET state = excluded.state, \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
        params![state],
    )?;
    transaction.execute(
        "UPDATE project SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = 1",
        [],
    )?;
    transaction.commit()?;
    Ok(())
}

pub fn load_view_state_for_path(project_path: &Path) -> ProjectResult<Option<String>> {
    let connection = open_existing(project_path)?;
    load_view_state(&connection)
}

pub fn export_annotations(project_path: &Path, destination: &Path) -> ProjectResult<ExportSummary> {
    let connection = open_existing(project_path)?;
    let project = load_project(&connection)?;
    let annotations = load_annotations(&connection)?;
    let function_names = load_function_names(&connection)?;
    let manual_functions = load_manual_functions(&connection)?;
    let project_resolved = resolve_path(project_path);
    let binary_resolved = resolve_path(Path::new(&project.binary_path));
    let destination_resolved = resolve_path(destination);
    if paths_equal(&destination_resolved, &project_resolved) {
        return Err(ProjectError::InvalidExport(
            "export destination must not overwrite the project file".to_string(),
        ));
    }
    if paths_equal(&destination_resolved, &binary_resolved) {
        return Err(ProjectError::InvalidExport(
            "export destination must not overwrite the analyzed binary".to_string(),
        ));
    }
    let exported_at: String =
        connection.query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')", [], |row| {
            row.get(0)
        })?;
    let document = AnnotationExport {
        format: "ura-annotations",
        version: 1,
        exported_at,
        binary: ExportBinary {
            path: project.binary_path.clone(),
            sha256: project.binary_hash.clone(),
            file_size: project.file_size,
            format: project.format.clone(),
            architecture: project.architecture.clone(),
        },
        project: ExportProject {
            name: project.name.clone(),
        },
        annotations: annotations.clone(),
        function_names: function_names.clone(),
        manual_functions: manual_functions.clone(),
    };
    let json = serde_json::to_string_pretty(&document)
        .map_err(|error| ProjectError::InvalidExport(error.to_string()))?;
    std::fs::write(destination, format!("{json}\n"))?;
    let written = std::fs::read_to_string(destination)?;
    let valid = serde_json::from_str::<serde_json::Value>(&written)
        .ok()
        .filter(|value| {
            value.get("format").is_some()
                && value.get("binary").is_some()
                && value.get("annotations").is_some()
        })
        .is_some();
    if !valid {
        let _ = std::fs::remove_file(destination);
        return Err(ProjectError::InvalidExport(
            "exported file failed validation".to_string(),
        ));
    }
    Ok(ExportSummary {
        path: destination.to_string_lossy().to_string(),
        annotation_count: annotations.len(),
        function_name_count: function_names.len(),
        manual_function_count: manual_functions.len(),
    })
}

pub fn delete_annotation(project_path: &Path, annotation_id: i64) -> ProjectResult<()> {
    let connection = open_existing(project_path)?;
    let transaction = connection.unchecked_transaction()?;
    transaction.execute(
        "DELETE FROM annotations WHERE id = ?1",
        params![annotation_id],
    )?;
    transaction.execute(
        "UPDATE project SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = 1",
        [],
    )?;
    transaction.commit()?;
    Ok(())
}

pub fn load_annotations_for_path(project_path: &Path) -> ProjectResult<Vec<Annotation>> {
    let connection = open_existing(project_path)?;
    load_annotations(&connection)
}

fn open_existing(project_path: &Path) -> ProjectResult<Connection> {
    if !project_path.exists() {
        return Err(ProjectError::NotFound(
            project_path.to_string_lossy().to_string(),
        ));
    }
    let connection = Connection::open(project_path)?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    migrate_schema(&connection)?;
    Ok(connection)
}

fn migrate_schema(connection: &Connection) -> ProjectResult<()> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(ProjectError::UnsupportedSchema {
            found: version,
            supported: SCHEMA_VERSION,
        });
    }
    if version == SCHEMA_VERSION {
        return Ok(());
    }
    if version == 1 {
        connection.execute_batch(
            "BEGIN;
             CREATE TABLE IF NOT EXISTS function_names (
                 address TEXT PRIMARY KEY NOT NULL,
                 name TEXT NOT NULL,
                 updated_at TEXT NOT NULL
             );
             PRAGMA user_version = 2;
             COMMIT;",
        )?;
    }
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == 2 {
        connection.execute_batch(
            "BEGIN;
             CREATE TABLE IF NOT EXISTS manual_functions (
                 address TEXT PRIMARY KEY NOT NULL,
                 created_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS view_state (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 state TEXT NOT NULL,
                 updated_at TEXT NOT NULL
             );
             PRAGMA user_version = 3;
             COMMIT;",
        )?;
        return Ok(());
    }
    if version != SCHEMA_VERSION {
        return Err(ProjectError::InvalidProject(format!(
            "expected schema version {}, found {}",
            SCHEMA_VERSION, version
        )));
    }
    Ok(())
}

fn initialize_schema(connection: &Connection) -> ProjectResult<()> {
    connection.execute_batch(
        "BEGIN;
         CREATE TABLE project (
             id INTEGER PRIMARY KEY CHECK (id = 1),
             name TEXT NOT NULL,
             created_at TEXT NOT NULL,
             updated_at TEXT NOT NULL,
             binary_path TEXT NOT NULL,
             binary_hash TEXT NOT NULL,
             file_size INTEGER NOT NULL,
             format TEXT NOT NULL,
             architecture TEXT NOT NULL,
             selected_address TEXT
         );
         CREATE TABLE annotations (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             address TEXT NOT NULL UNIQUE,
             label TEXT,
             note TEXT NOT NULL DEFAULT '',
             created_at TEXT NOT NULL,
             updated_at TEXT NOT NULL
         );
         CREATE TABLE function_names (
             address TEXT PRIMARY KEY NOT NULL,
             name TEXT NOT NULL,
             updated_at TEXT NOT NULL
         );
         CREATE TABLE manual_functions (
             address TEXT PRIMARY KEY NOT NULL,
             created_at TEXT NOT NULL
         );
         CREATE TABLE view_state (
             id INTEGER PRIMARY KEY CHECK (id = 1),
             state TEXT NOT NULL,
             updated_at TEXT NOT NULL
         );
         PRAGMA user_version = 3;
         COMMIT;",
    )?;
    Ok(())
}

fn load_project(connection: &Connection) -> ProjectResult<ProjectInfo> {
    let row = connection
        .query_row(
            "SELECT name, created_at, updated_at, binary_path, binary_hash, file_size, format, architecture, selected_address \
             FROM project WHERE id = 1",
            [],
            |row| {
                Ok(ProjectInfo {
                    schema_version: SCHEMA_VERSION,
                    name: row.get(0)?,
                    created_at: row.get(1)?,
                    updated_at: row.get(2)?,
                    binary_path: row.get(3)?,
                    binary_hash: row.get(4)?,
                    file_size: row.get::<_, i64>(5)? as u64,
                    format: row.get(6)?,
                    architecture: row.get(7)?,
                    selected_address: row.get(8)?,
                })
            },
        )
        .optional()?;
    row.ok_or_else(|| ProjectError::InvalidProject("project metadata is missing".to_string()))
}

fn load_annotations(connection: &Connection) -> ProjectResult<Vec<Annotation>> {
    let mut statement = connection.prepare(
        "SELECT id, address, label, note, created_at, updated_at FROM annotations ORDER BY id",
    )?;
    let rows = statement.query_map([], map_annotation)?;
    let mut annotations = Vec::new();
    for row in rows {
        annotations.push(row?);
    }
    Ok(annotations)
}

fn load_function_names(connection: &Connection) -> ProjectResult<Vec<FunctionNameEntry>> {
    let mut statement = connection.prepare(
        "SELECT address, name, updated_at FROM function_names ORDER BY updated_at, address",
    )?;
    let rows = statement.query_map([], map_function_name)?;
    let mut names = Vec::new();
    for row in rows {
        names.push(row?);
    }
    names.sort_by_key(|entry| parse_address(&entry.address).unwrap_or(u64::MAX));
    Ok(names)
}

fn load_manual_functions(connection: &Connection) -> ProjectResult<Vec<ManualFunction>> {
    let mut statement = connection.prepare("SELECT address, created_at FROM manual_functions")?;
    let rows = statement.query_map([], map_manual_function)?;
    let mut functions = Vec::new();
    for row in rows {
        functions.push(row?);
    }
    functions.sort_by_key(|entry| parse_address(&entry.address).unwrap_or(u64::MAX));
    Ok(functions)
}

fn map_manual_function(row: &rusqlite::Row<'_>) -> rusqlite::Result<ManualFunction> {
    Ok(ManualFunction {
        address: row.get(0)?,
        created_at: row.get(1)?,
    })
}

fn load_view_state(connection: &Connection) -> ProjectResult<Option<String>> {
    connection
        .query_row("SELECT state FROM view_state WHERE id = 1", [], |row| {
            row.get(0)
        })
        .optional()
        .map_err(ProjectError::from)
}

fn resolve_path(path: &Path) -> PathBuf {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return canonical;
    }
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
        if let Ok(canonical) = std::fs::canonicalize(parent) {
            return canonical.join(name);
        }
    }
    path.to_path_buf()
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

fn map_function_name(row: &rusqlite::Row<'_>) -> rusqlite::Result<FunctionNameEntry> {
    Ok(FunctionNameEntry {
        address: row.get(0)?,
        name: row.get(1)?,
        updated_at: row.get(2)?,
    })
}

fn map_annotation(row: &rusqlite::Row<'_>) -> rusqlite::Result<Annotation> {
    Ok(Annotation {
        id: row.get(0)?,
        address: row.get(1)?,
        label: row.get(2)?,
        note: row.get(3)?,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
    })
}

fn normalize_address(address: &str) -> ProjectResult<String> {
    parse_address(address)
        .map(format_address)
        .map_err(|_| ProjectError::InvalidAddress(address.to_string()))
}

fn binary_status(project: &ProjectInfo) -> String {
    let path = PathBuf::from(&project.binary_path);
    if !path.exists() {
        return "missing".to_string();
    }
    match std::fs::metadata(&path) {
        Ok(metadata) if metadata.len() != project.file_size => "modified".to_string(),
        Ok(_) => match std::fs::read(&path) {
            Ok(bytes) if sha256_hex(&bytes) == project.binary_hash => "unchanged".to_string(),
            Ok(_) => "modified".to_string(),
            Err(_) => "missing".to_string(),
        },
        Err(_) => "missing".to_string(),
    }
}
