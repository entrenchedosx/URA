use super::*;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DebugBreakpoint {
    pub module_sha256: String,
    pub rva: String,
    pub enabled: bool,
}
pub fn load_debug_breakpoints_for_path(path: &Path) -> ProjectResult<Vec<DebugBreakpoint>> {
    let connection = open_existing(path)?;
    load_debug_breakpoints(&connection)
}
fn validate(definitions: &[DebugBreakpoint]) -> ProjectResult<()> {
    if definitions.len() > 1024 {
        return Err(ProjectError::InvalidProject(
            "too many debugger breakpoints".into(),
        ));
    }
    let mut keys = std::collections::BTreeSet::new();
    for definition in definitions {
        if definition.module_sha256.len() != 64
            || !definition
                .module_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
            || definition.rva.len() > 18
            || parse_address(&definition.rva).is_err()
            || !keys.insert((
                definition.module_sha256.to_lowercase(),
                parse_address(&definition.rva).unwrap(),
            ))
        {
            return Err(ProjectError::InvalidProject(
                "invalid or duplicate module/RVA breakpoint definition".into(),
            ));
        }
    }
    Ok(())
}
pub fn save_debug_breakpoints(path: &Path, definitions: &[DebugBreakpoint]) -> ProjectResult<()> {
    validate(definitions)?;
    let connection = open_existing(path)?;
    let transaction = connection.unchecked_transaction()?;
    let project = load_project(&transaction)?;
    if definitions
        .iter()
        .any(|d| !d.module_sha256.eq_ignore_ascii_case(&project.binary_hash))
    {
        return Err(ProjectError::InvalidProject(
            "only breakpoints for the project's original main image may be persisted".into(),
        ));
    }
    let text = serde_json::to_string(definitions)
        .map_err(|e| ProjectError::InvalidProject(e.to_string()))?;
    transaction.execute("INSERT INTO debug_breakpoints(id,definitions_json) VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET definitions_json=excluded.definitions_json",params![text])?;
    transaction.commit()?;
    Ok(())
}
pub(super) fn load_debug_breakpoints(
    connection: &Connection,
) -> ProjectResult<Vec<DebugBreakpoint>> {
    let size: Option<i64> = connection
        .query_row(
            "SELECT length(CAST(definitions_json AS BLOB)) FROM debug_breakpoints WHERE id=1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if size.is_some_and(|s| !(0..=256 * 1024).contains(&s)) {
        return Err(ProjectError::InvalidProject(
            "debug definitions exceed 256KiB".into(),
        ));
    }
    let text: Option<String> = connection
        .query_row(
            "SELECT definitions_json FROM debug_breakpoints WHERE id=1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let result = match text {
        None => Vec::new(),
        Some(t) => {
            serde_json::from_str(&t).map_err(|e| ProjectError::InvalidProject(e.to_string()))?
        }
    };
    validate(&result)?;
    Ok(result)
}
