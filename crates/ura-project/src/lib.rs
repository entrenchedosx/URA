mod debugger;
pub use debugger::{load_debug_breakpoints_for_path, save_debug_breakpoints, DebugBreakpoint};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;
use ura_core::decomp::signature::SignatureOverride;
use ura_core::decomp::types::{TypeDatabase, TypeRef};
use ura_core::{format_address, parse_address, sha256_hex};

pub const SCHEMA_VERSION: i64 = 8;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionSignatureEntry {
    pub address: String,
    pub signature: SignatureOverride,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StackVariableOverride {
    pub function: String,
    pub offset: i64,
    pub name: Option<String>,
    pub ty: Option<TypeRef>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectSnapshot {
    pub debug_breakpoints: Vec<DebugBreakpoint>,
    pub project: ProjectInfo,
    pub annotations: Vec<Annotation>,
    pub function_names: Vec<FunctionNameEntry>,
    pub manual_functions: Vec<ManualFunction>,
    pub function_signatures: Vec<FunctionSignatureEntry>,
    pub stack_variables: Vec<StackVariableOverride>,
    pub type_library: Option<TypeDatabase>,
    pub patch_state: Option<ura_core::patch::PatchState>,
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
    function_signatures: Vec<FunctionSignatureEntry>,
    stack_variables: Vec<StackVariableOverride>,
    type_library: Option<TypeDatabase>,
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
    let function_signatures = load_function_signatures(&connection)?;
    let stack_variables = load_stack_variables(&connection)?;
    let view_state = load_view_state(&connection)?;
    let binary_status = binary_status(&project);
    Ok(ProjectSnapshot {
        debug_breakpoints: debugger::load_debug_breakpoints(&connection)?,
        project,
        annotations,
        function_names,
        manual_functions,
        function_signatures,
        stack_variables,
        type_library: load_type_library(&connection)?,
        patch_state: load_patch_state(&connection)?,
        view_state,
        binary_status,
    })
}

/// Read a supported project without migrating it or touching its recorded binary path.
/// Callers that already opened a binary must compare its hash themselves.
pub fn read_project(project_path: &Path) -> ProjectResult<ProjectSnapshot> {
    if !project_path.exists() {
        return Err(ProjectError::NotFound(
            project_path.to_string_lossy().into_owned(),
        ));
    }
    let connection =
        Connection::open_with_flags(project_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(ProjectError::UnsupportedSchema {
            found: version,
            supported: SCHEMA_VERSION,
        });
    }
    if !(1..=SCHEMA_VERSION).contains(&version) {
        return Err(ProjectError::InvalidProject(format!(
            "unsupported schema version {version}"
        )));
    }
    let mut project = load_project(&connection)?;
    project.schema_version = version;
    Ok(ProjectSnapshot {
        debug_breakpoints: if version >= 7 {
            debugger::load_debug_breakpoints(&connection)?
        } else {
            vec![]
        },
        project,
        annotations: load_annotations(&connection)?,
        function_names: if version >= 2 {
            load_function_names(&connection)?
        } else {
            vec![]
        },
        manual_functions: if version >= 3 {
            load_manual_functions(&connection)?
        } else {
            vec![]
        },
        function_signatures: if version >= 4 {
            load_function_signatures(&connection)?
        } else {
            vec![]
        },
        stack_variables: if version >= 4 {
            load_stack_variables(&connection)?
        } else {
            vec![]
        },
        type_library: if version >= 5 {
            load_type_library(&connection)?
        } else {
            None
        },
        patch_state: if version >= 6 {
            load_patch_state(&connection)?
        } else {
            None
        },
        view_state: if version >= 3 {
            load_view_state(&connection)?
        } else {
            None
        },
        binary_status: "unchecked".into(),
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

pub fn save_function_signature(
    project_path: &Path,
    address: &str,
    signature: &SignatureOverride,
) -> ProjectResult<FunctionSignatureEntry> {
    let normalized = normalize_address(address)?;
    let errors = signature.validate();
    if !errors.is_empty() {
        return Err(ProjectError::InvalidName(format!(
            "function signature is invalid: {}",
            errors.join("; ")
        )));
    }
    let json = serde_json::to_string(signature)
        .map_err(|error| ProjectError::InvalidProject(error.to_string()))?;
    let connection = open_existing(project_path)?;
    let transaction = connection.unchecked_transaction()?;
    transaction.execute(
        "INSERT INTO function_signatures (address, signature_json, updated_at) \
         VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ','now')) \
         ON CONFLICT(address) DO UPDATE SET signature_json = excluded.signature_json, \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
        params![normalized, json],
    )?;
    transaction.execute(
        "UPDATE project SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = 1",
        [],
    )?;
    transaction.commit()?;
    connection
        .query_row(
            "SELECT address, signature_json, updated_at FROM function_signatures WHERE address = ?1",
            params![normalized],
            map_function_signature,
        )
        .map_err(ProjectError::from)
}

pub fn delete_function_signature(project_path: &Path, address: &str) -> ProjectResult<bool> {
    let normalized = normalize_address(address)?;
    let connection = open_existing(project_path)?;
    let removed = connection.execute(
        "DELETE FROM function_signatures WHERE address = ?1",
        params![normalized],
    )?;
    Ok(removed > 0)
}

pub fn load_function_signatures_for_path(
    project_path: &Path,
) -> ProjectResult<Vec<FunctionSignatureEntry>> {
    let connection = open_existing(project_path)?;
    load_function_signatures(&connection)
}

pub fn save_stack_variable(
    project_path: &Path,
    function: &str,
    offset: i64,
    name: Option<&str>,
    ty: Option<&TypeRef>,
) -> ProjectResult<StackVariableOverride> {
    let function = normalize_address(function)?;
    let name = name
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    if name.is_none() && ty.is_none() {
        return Err(ProjectError::InvalidName(
            "a stack variable override needs a name or a type".to_string(),
        ));
    }
    if name.as_ref().is_some_and(|name| name.chars().count() > 256) {
        return Err(ProjectError::InvalidName(
            "stack variable names are limited to 256 characters".to_string(),
        ));
    }
    if ty.is_some_and(|ty| !ty.valid()) {
        return Err(ProjectError::InvalidName(
            "stack variable type is invalid".to_string(),
        ));
    }
    let type_json = ty
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| ProjectError::InvalidProject(error.to_string()))?;
    let connection = open_existing(project_path)?;
    let transaction = connection.unchecked_transaction()?;
    transaction.execute(
        "INSERT INTO stack_variables (function_address, slot_offset, name, type_json, updated_at) \
         VALUES (?1, ?2, ?3, ?4, strftime('%Y-%m-%dT%H:%M:%fZ','now')) \
         ON CONFLICT(function_address, slot_offset) DO UPDATE SET name = excluded.name, \
         type_json = excluded.type_json, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
        params![function, offset, name, type_json],
    )?;
    transaction.execute(
        "UPDATE project SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = 1",
        [],
    )?;
    transaction.commit()?;
    connection
        .query_row(
            "SELECT function_address, slot_offset, name, type_json, updated_at \
             FROM stack_variables WHERE function_address = ?1 AND slot_offset = ?2",
            params![function, offset],
            map_stack_variable,
        )
        .map_err(ProjectError::from)
}

pub fn delete_stack_variable(
    project_path: &Path,
    function: &str,
    offset: i64,
) -> ProjectResult<bool> {
    let function = normalize_address(function)?;
    let connection = open_existing(project_path)?;
    let removed = connection.execute(
        "DELETE FROM stack_variables WHERE function_address = ?1 AND slot_offset = ?2",
        params![function, offset],
    )?;
    Ok(removed > 0)
}

pub fn load_stack_variables_for_path(
    project_path: &Path,
) -> ProjectResult<Vec<StackVariableOverride>> {
    let connection = open_existing(project_path)?;
    load_stack_variables(&connection)
}

pub fn save_type_library(project_path: &Path, library: &TypeDatabase) -> ProjectResult<()> {
    let errors = library.validation_errors();
    if !errors.is_empty() {
        return Err(ProjectError::InvalidProject(errors.join("; ")));
    }
    let json =
        serde_json::to_string(library).map_err(|e| ProjectError::InvalidProject(e.to_string()))?;
    if json.len() > 1024 * 1024 {
        return Err(ProjectError::InvalidProject(
            "type library exceeds 1 MiB".into(),
        ));
    }
    let connection = open_existing(project_path)?;
    let transaction = connection.unchecked_transaction()?;
    transaction.execute("INSERT INTO type_library (id, library_json) VALUES (1, ?1) ON CONFLICT(id) DO UPDATE SET library_json = excluded.library_json", params![json])?;
    transaction.execute(
        "UPDATE project SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = 1",
        [],
    )?;
    transaction.commit()?;
    Ok(())
}

pub fn load_type_library_for_path(project_path: &Path) -> ProjectResult<Option<TypeDatabase>> {
    load_type_library(&open_existing(project_path)?)
}

/// Commit a patch revision with an optimistic concurrency precondition. The
/// original identity stays attached to the project, never to exported bytes.
pub fn save_patch_state(
    project_path: &Path,
    state: &ura_core::patch::PatchState,
    expected_revision: u64,
) -> ProjectResult<()> {
    let mut connection = Connection::open(project_path)?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    migrate_schema(&connection)?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let project = load_project(&transaction)?;
    if project.binary_hash != state.original_sha256 || project.file_size != state.file_size {
        return Err(ProjectError::InvalidProject(
            "patch original identity differs from project".into(),
        ));
    }
    if (project.format == "raw") != state.raw_bitness.is_some()
        || (project.format != "raw" && state.raw_base.is_some())
    {
        return Err(ProjectError::InvalidProject(
            "patch mode/base metadata differs from project format".into(),
        ));
    }
    let previous = load_patch_state(&transaction)?;
    if previous.as_ref().map_or(0, |s| s.revision) != expected_revision
        || state.revision < expected_revision
    {
        return Err(ProjectError::InvalidProject(
            "patch project changed since this handle opened; reopen it before editing".into(),
        ));
    }
    let json =
        serde_json::to_string(state).map_err(|e| ProjectError::InvalidProject(e.to_string()))?;
    if json.len() > MAX_PATCH_STATE_JSON_BYTES {
        return Err(ProjectError::InvalidProject(
            "patch state exceeds storage budget".into(),
        ));
    }
    transaction.execute("INSERT INTO patch_state(id,state_json) VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET state_json=excluded.state_json",params![json])?;
    transaction.commit()?;
    Ok(())
}
const MAX_PATCH_STATE_JSON_BYTES: usize = ura_core::patch::MAX_HISTORY_BYTES * 4 + 2 * 1024 * 1024;
fn load_patch_state(connection: &Connection) -> ProjectResult<Option<ura_core::patch::PatchState>> {
    let length: Option<i64> = connection
        .query_row(
            "SELECT length(CAST(state_json AS BLOB)) FROM patch_state WHERE id=1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if length.is_some_and(|n| n < 0 || n as u64 > MAX_PATCH_STATE_JSON_BYTES as u64) {
        return Err(ProjectError::InvalidProject(
            "patch state exceeds storage budget".into(),
        ));
    }
    let json: Option<String> = connection
        .query_row("SELECT state_json FROM patch_state WHERE id=1", [], |r| {
            r.get(0)
        })
        .optional()?;
    json.map(|s| {
        serde_json::from_str(&s)
            .map_err(|e| ProjectError::InvalidProject(format!("invalid patch metadata: {e}")))
    })
    .transpose()
}

fn load_type_library(connection: &Connection) -> ProjectResult<Option<TypeDatabase>> {
    let json: Option<String> = connection
        .query_row(
            "SELECT library_json FROM type_library WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    json.map(|json| {
        if json.len() > 1024 * 1024 {
            return Err(ProjectError::InvalidProject(
                "type library exceeds 1 MiB".into(),
            ));
        }
        let library: TypeDatabase =
            serde_json::from_str(&json).map_err(|e| ProjectError::InvalidProject(e.to_string()))?;
        let errors = library.validation_errors();
        if !errors.is_empty() {
            return Err(ProjectError::InvalidProject(errors.join("; ")));
        }
        Ok(library)
    })
    .transpose()
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
    let function_signatures = load_function_signatures(&connection)?;
    let stack_variables = load_stack_variables(&connection)?;
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
        function_signatures: function_signatures.clone(),
        stack_variables: stack_variables.clone(),
        type_library: load_type_library(&connection)?,
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
    }
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == 3 {
        connection.execute_batch(
            "BEGIN;
             CREATE TABLE IF NOT EXISTS function_signatures (
                 address TEXT PRIMARY KEY NOT NULL,
                 signature_json TEXT NOT NULL,
                 updated_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS stack_variables (
                 function_address TEXT NOT NULL,
                 slot_offset INTEGER NOT NULL,
                 name TEXT,
                 type_json TEXT,
                 updated_at TEXT NOT NULL,
                 PRIMARY KEY (function_address, slot_offset)
             );
             PRAGMA user_version = 4;
             COMMIT;",
        )?;
    }
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == 4 {
        connection.execute_batch("BEGIN; CREATE TABLE IF NOT EXISTS type_library (id INTEGER PRIMARY KEY CHECK (id = 1), library_json TEXT NOT NULL); PRAGMA user_version = 5; COMMIT;")?;
    }
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == 5 {
        connection.execute_batch("BEGIN; CREATE TABLE IF NOT EXISTS patch_state (id INTEGER PRIMARY KEY CHECK (id = 1), state_json TEXT NOT NULL); PRAGMA user_version = 6; COMMIT;")?;
    }
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == 6 {
        connection.execute_batch("BEGIN; CREATE TABLE IF NOT EXISTS debug_breakpoints (id INTEGER PRIMARY KEY CHECK (id=1), definitions_json TEXT NOT NULL); PRAGMA user_version=7; COMMIT;")?;
    }
    let version: i64 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version == 7 {
        connection.execute_batch("PRAGMA user_version=8;")?;
    }
    let version: i64 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
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
         CREATE TABLE function_signatures (
             address TEXT PRIMARY KEY NOT NULL,
             signature_json TEXT NOT NULL,
             updated_at TEXT NOT NULL
         );
         CREATE TABLE stack_variables (
             function_address TEXT NOT NULL,
             slot_offset INTEGER NOT NULL,
             name TEXT,
             type_json TEXT,
             updated_at TEXT NOT NULL,
             PRIMARY KEY (function_address, slot_offset)
         );
         CREATE TABLE type_library (id INTEGER PRIMARY KEY CHECK (id = 1), library_json TEXT NOT NULL);
         CREATE TABLE patch_state (id INTEGER PRIMARY KEY CHECK (id = 1), state_json TEXT NOT NULL);
         CREATE TABLE debug_breakpoints (id INTEGER PRIMARY KEY CHECK (id=1), definitions_json TEXT NOT NULL);
         PRAGMA user_version = 8;
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

fn load_function_signatures(connection: &Connection) -> ProjectResult<Vec<FunctionSignatureEntry>> {
    let mut statement = connection
        .prepare("SELECT address, signature_json, updated_at FROM function_signatures")?;
    let rows = statement.query_map([], map_function_signature)?;
    let mut signatures = Vec::new();
    for row in rows {
        signatures.push(row?);
    }
    signatures.sort_by_key(|entry| parse_address(&entry.address).unwrap_or(u64::MAX));
    Ok(signatures)
}

fn load_stack_variables(connection: &Connection) -> ProjectResult<Vec<StackVariableOverride>> {
    let mut statement = connection.prepare(
        "SELECT function_address, slot_offset, name, type_json, updated_at FROM stack_variables",
    )?;
    let rows = statement.query_map([], map_stack_variable)?;
    let mut variables = Vec::new();
    for row in rows {
        variables.push(row?);
    }
    variables.sort_by_key(|variable| {
        (
            parse_address(&variable.function).unwrap_or(u64::MAX),
            variable.offset,
        )
    });
    Ok(variables)
}

fn map_function_signature(row: &rusqlite::Row<'_>) -> rusqlite::Result<FunctionSignatureEntry> {
    let json: String = row.get(1)?;
    let signature = serde_json::from_str(&json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(FunctionSignatureEntry {
        address: row.get(0)?,
        signature,
        updated_at: row.get(2)?,
    })
}

fn map_stack_variable(row: &rusqlite::Row<'_>) -> rusqlite::Result<StackVariableOverride> {
    let type_json: Option<String> = row.get(3)?;
    let ty = type_json
        .map(|json| {
            serde_json::from_str(&json).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    3,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        })
        .transpose()?;
    Ok(StackVariableOverride {
        function: row.get(0)?,
        offset: row.get(1)?,
        name: row.get(2)?,
        ty,
        updated_at: row.get(4)?,
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
