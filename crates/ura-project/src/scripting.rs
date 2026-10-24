//! Atomic, compare-and-swap project metadata edits. No executable-byte writes.
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum MetadataEdit {
    Signature {
        address: String,
        signature: ura_core::decomp::signature::SignatureOverride,
    },
    StackVariable {
        address: String,
        offset: i64,
        name: Option<String>,
        ty: Option<ura_core::decomp::types::TypeRef>,
    },
    TypeLibrary {
        library: ura_core::decomp::types::TypeDatabase,
    },
    Rename {
        address: String,
        name: String,
    },
    Comment {
        address: String,
        label: Option<String>,
        note: String,
    },
}
fn revision(connection: &Connection) -> ProjectResult<String> {
    let names = load_function_names(connection)?;
    let notes = load_annotations(connection)?;
    let info = load_project(connection)?;
    Ok(sha256_hex(
        &serde_json::to_vec(&(
            info.binary_hash,
            info.name,
            info.created_at,
            info.format,
            info.architecture,
            names,
            notes,
            load_manual_functions(connection)?,
            load_function_signatures(connection)?,
            load_stack_variables(connection)?,
            load_type_library(connection)?,
            load_patch_state(connection)?,
        ))
        .map_err(|e| ProjectError::InvalidProject(e.to_string()))?,
    ))
}
pub fn metadata_revision(path: &Path) -> ProjectResult<String> {
    let connection = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    revision(&connection)
}
pub fn apply(
    path: &Path,
    binary_hash: &str,
    expected: &str,
    edits: &[MetadataEdit],
) -> ProjectResult<String> {
    if edits.is_empty() || edits.len() > 128 {
        return Err(ProjectError::InvalidProject(
            "transaction requires1..128 edits".into(),
        ));
    }
    let mut connection = open_existing(path)?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    if !load_project(&transaction)?
        .binary_hash
        .eq_ignore_ascii_case(binary_hash)
        || revision(&transaction)? != expected
    {
        return Err(ProjectError::InvalidProject(
            "stale project transaction identity".into(),
        ));
    }
    for edit in edits {
        match edit {
            MetadataEdit::Signature { address, signature } => {
                let address = normalize_address(address)?;
                let errors = signature.validate();
                if !errors.is_empty() {
                    return Err(ProjectError::InvalidProject(errors.join("; ")));
                }
                let json = serde_json::to_string(signature)
                    .map_err(|e| ProjectError::InvalidProject(e.to_string()))?;
                transaction.execute("INSERT INTO function_signatures(address,signature_json,updated_at) VALUES(?1,?2,strftime('%Y-%m-%dT%H:%M:%fZ','now')) ON CONFLICT(address) DO UPDATE SET signature_json=excluded.signature_json,updated_at=excluded.updated_at",params![address,json])?;
            }
            MetadataEdit::StackVariable {
                address,
                offset,
                name,
                ty,
            } => {
                let address = normalize_address(address)?;
                if offset.unsigned_abs() > (1 << 30)
                    || name.as_ref().is_some_and(|n| {
                        n.trim().is_empty()
                            || n.chars().count() > 256
                            || n.chars().any(char::is_control)
                    })
                    || ty.as_ref().is_some_and(|t| !t.valid())
                {
                    return Err(ProjectError::InvalidProject(
                        "Invalid stack-variable override".into(),
                    ));
                }
                if name.is_none() && ty.is_none() {
                    transaction.execute(
                        "DELETE FROM stack_variables WHERE function_address=?1 AND slot_offset=?2",
                        params![address, offset],
                    )?;
                } else {
                    let type_json = ty
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()
                        .map_err(|e| ProjectError::InvalidProject(e.to_string()))?;
                    transaction.execute("INSERT INTO stack_variables(function_address,slot_offset,name,type_json,updated_at) VALUES(?1,?2,?3,?4,strftime('%Y-%m-%dT%H:%M:%fZ','now')) ON CONFLICT(function_address,slot_offset) DO UPDATE SET name=excluded.name,type_json=excluded.type_json,updated_at=excluded.updated_at",params![address,offset,name.as_ref().map(|n|n.trim()),type_json])?;
                }
            }
            MetadataEdit::TypeLibrary { library } => {
                let errors = library.validation_errors();
                if !errors.is_empty() {
                    return Err(ProjectError::InvalidProject(errors.join("; ")));
                }
                let json = serde_json::to_string(library)
                    .map_err(|e| ProjectError::InvalidProject(e.to_string()))?;
                if json.len() > 1024 * 1024 {
                    return Err(ProjectError::InvalidProject(
                        "Type library size limit".into(),
                    ));
                }
                transaction.execute("INSERT INTO type_library(id,library_json) VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET library_json=excluded.library_json",params![json])?;
            }
            MetadataEdit::Rename { address, name } => {
                let address = normalize_address(address)?;
                let name = name.trim();
                if name.is_empty()
                    || name.chars().count() > 256
                    || name.chars().any(char::is_control)
                {
                    return Err(ProjectError::InvalidName(
                        "name must be1..256 printable characters".into(),
                    ));
                }
                transaction.execute("INSERT INTO function_names(address,name,updated_at) VALUES(?1,?2,strftime('%Y-%m-%dT%H:%M:%fZ','now')) ON CONFLICT(address) DO UPDATE SET name=excluded.name,updated_at=excluded.updated_at",params![address,name])?;
            }
            MetadataEdit::Comment {
                address,
                label,
                note,
            } => {
                let address = normalize_address(address)?;
                if note.len() > 16384 || label.as_ref().is_some_and(|v| v.len() > 256) {
                    return Err(ProjectError::InvalidProject("annotation size limit".into()));
                }
                transaction.execute("INSERT INTO annotations(address,label,note,created_at,updated_at) VALUES(?1,?2,?3,strftime('%Y-%m-%dT%H:%M:%fZ','now'),strftime('%Y-%m-%dT%H:%M:%fZ','now')) ON CONFLICT(address) DO UPDATE SET label=excluded.label,note=excluded.note,updated_at=excluded.updated_at",params![address,label,note])?;
            }
        }
    }
    transaction.execute(
        "UPDATE project SET updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=1",
        [],
    )?;
    let updated = revision(&transaction)?;
    transaction.commit()?;
    Ok(updated)
}
