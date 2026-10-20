use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::path::{Path, PathBuf};
use thiserror::Error;
use ura_core::{format_address, parse_address, sha256_hex};

pub const SCHEMA_VERSION: i64 = 1;

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
pub struct ProjectSnapshot {
    pub project: ProjectInfo,
    pub annotations: Vec<Annotation>,
    pub binary_status: String,
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
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(ProjectError::UnsupportedSchema {
            found: version,
            supported: SCHEMA_VERSION,
        });
    }
    if version != SCHEMA_VERSION {
        return Err(ProjectError::InvalidProject(format!(
            "expected schema version {}, found {}",
            SCHEMA_VERSION, version
        )));
    }
    let project = load_project(&connection)?;
    let annotations = load_annotations(&connection)?;
    let binary_status = binary_status(&project);
    Ok(ProjectSnapshot {
        project,
        annotations,
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
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version != SCHEMA_VERSION {
        if version > SCHEMA_VERSION {
            return Err(ProjectError::UnsupportedSchema {
                found: version,
                supported: SCHEMA_VERSION,
            });
        }
        return Err(ProjectError::InvalidProject(format!(
            "expected schema version {}, found {}",
            SCHEMA_VERSION, version
        )));
    }
    Ok(connection)
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
         PRAGMA user_version = 1;
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
