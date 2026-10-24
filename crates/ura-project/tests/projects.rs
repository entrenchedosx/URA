use std::path::{Path, PathBuf};
use tempfile::TempDir;
use ura_core::analyze_path;
use ura_project::{
    add_manual_function, create_project, delete_annotation, delete_function_name,
    delete_manual_function, export_annotations, load_view_state_for_path, open_project,
    save_annotation, save_function_name, save_view_state, BinaryIdentity, ProjectError,
    SCHEMA_VERSION,
};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn identity(path: &Path) -> BinaryIdentity {
    let binary = analyze_path(path).expect("fixture should analyze");
    let view = binary.view();
    BinaryIdentity {
        binary_path: view.path,
        binary_hash: view.sha256,
        file_size: view.file_size,
        format: view.format,
        architecture: view.architecture,
    }
}

fn setup() -> (TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let project_path = directory.path().join("analysis.ura");
    (directory, project_path)
}

#[test]
fn externally_edited_oversized_view_state_is_rejected_on_read_and_preserved() {
    let (_dir, path) = setup();
    create_project(
        &path,
        "untrusted metadata",
        &identity(&fixture("ura64.exe")),
    )
    .unwrap();
    let text = format!(
        r#"{{"uraSymbolic":"{}"}}"#,
        "é".repeat(ura_project::MAX_VIEW_STATE_BYTES / 2 + 1)
    );
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute(
            "INSERT INTO view_state(id,state,updated_at) VALUES(1,?1,'test')",
            [&text],
        )
        .unwrap();
    assert!(matches!(
        load_view_state_for_path(&path),
        Err(ProjectError::InvalidViewState(_))
    ));
    assert!(matches!(
        ura_project::read_project(&path),
        Err(ProjectError::InvalidViewState(_))
    ));
    assert!(
        ura_project::merge_view_state_fields(&path, &serde_json::json!({"uraSymbolic":{}}))
            .is_err()
    );
    let after: String = connection
        .query_row("SELECT state FROM view_state WHERE id=1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(after, text);
}

#[test]
fn additive_analysis_metadata_preserves_layout_unknown_keys_and_rolls_back_invalid_merges() {
    let (_dir, path) = setup();
    create_project(&path, "symbolic metadata", &identity(&fixture("ura64.exe"))).unwrap();
    save_view_state(
        &path,
        r#"{"native":{"panel":"graph"},"foreignKey":{"keep":17}}"#,
    )
    .unwrap();
    ura_project::merge_view_state_fields(
        &path,
        &serde_json::json!({"uraSymbolic":{"authoritative":false,"identity":"historical"}}),
    )
    .unwrap();
    let root: serde_json::Value =
        serde_json::from_str(&load_view_state_for_path(&path).unwrap().unwrap()).unwrap();
    assert_eq!(root["native"]["panel"], "graph");
    assert_eq!(root["foreignKey"]["keep"], 17);
    assert_eq!(root["uraSymbolic"]["authoritative"], false);
    let before = load_view_state_for_path(&path).unwrap();
    let oversized = serde_json::json!({"oversized":"x".repeat(ura_project::MAX_VIEW_STATE_BYTES)});
    assert!(ura_project::merge_view_state_fields(&path, &oversized).is_err());
    assert_eq!(load_view_state_for_path(&path).unwrap(), before);
    save_view_state(&path, "[1,2,3]").unwrap();
    assert!(
        ura_project::merge_view_state_fields(&path, &serde_json::json!({"native":{}})).is_err()
    );
    assert_eq!(
        load_view_state_for_path(&path).unwrap().as_deref(),
        Some("[1,2,3]")
    );
}

#[test]
fn v6_debug_definition_migration_is_explicit_bounded_and_preserves_data() {
    let (_dir, path) = setup();
    let sample = fixture("ura64.exe");
    let identity = identity(&sample);
    create_project(&path, "debug definitions", &identity).unwrap();
    save_annotation(&path, "140001020", None, "retained").unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch("DROP TABLE debug_breakpoints; PRAGMA user_version=6;")
        .unwrap();
    let old = ura_project::read_project(&path).unwrap();
    assert_eq!(old.project.schema_version, 6);
    assert!(old.debug_breakpoints.is_empty());
    assert_eq!(
        connection
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        6
    );
    let migrated = open_project(&path).unwrap();
    assert_eq!(migrated.project.schema_version, 8);
    assert_eq!(migrated.annotations[0].note, "retained");
    let definition = ura_project::DebugBreakpoint {
        module_sha256: identity.binary_hash.clone(),
        rva: "0x1020".into(),
        enabled: true,
        ..Default::default()
    };
    ura_project::save_debug_breakpoints(&path, std::slice::from_ref(&definition)).unwrap();
    assert_eq!(
        ura_project::read_project(&path).unwrap().debug_breakpoints[0].rva,
        "0x1020"
    );
    let mut invalid = definition;
    invalid.module_sha256 = "0".repeat(64);
    assert!(ura_project::save_debug_breakpoints(&path, &[invalid]).is_err());
    connection
        .execute(
            "UPDATE debug_breakpoints SET definitions_json=?1",
            ["x".repeat(256 * 1024 + 1)],
        )
        .unwrap();
    assert!(ura_project::read_project(&path).is_err());
}
#[test]
fn v7_breakpoint_json_defaults_read_without_migration_and_v8_keeps_conditions() {
    let (_dir, path) = setup();
    let sample = fixture("ura64.exe");
    let id = identity(&sample);
    create_project(&path, "legacy debug", &id).unwrap();
    let c = rusqlite::Connection::open(&path).unwrap();
    let old = serde_json::json!([{"moduleSha256":id.binary_hash,"rva":"0x1020","enabled":true}])
        .to_string();
    c.execute(
        "INSERT INTO debug_breakpoints(id,definitions_json) VALUES(1,?1)",
        [old],
    )
    .unwrap();
    c.execute_batch("PRAGMA user_version=7;").unwrap();
    drop(c);
    let before = std::fs::read(&path).unwrap();
    let read = ura_project::read_project(&path).unwrap();
    assert_eq!(read.project.schema_version, 7);
    assert_eq!(read.debug_breakpoints[0].kind, "software");
    assert_eq!(read.debug_breakpoints[0].hit_after, 1);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    open_project(&path).unwrap();
    let mut definition = read.debug_breakpoints[0].clone();
    definition.condition = Some("rcx == 2".into());
    definition.hit_every = 10;
    ura_project::save_debug_breakpoints(&path, &[definition]).unwrap();
    let read = ura_project::read_project(&path).unwrap();
    assert_eq!(read.project.schema_version, 8);
    assert_eq!(read.debug_breakpoints[0].hit_every, 10);
    assert_eq!(
        read.debug_breakpoints[0].condition.as_deref(),
        Some("rcx == 2")
    );
}

#[test]
fn v5_patch_migration_revision_history_and_corrupt_metadata_are_checked() {
    use ura_core::patch::{Address, PatchDocument};
    let (_dir, path) = setup();
    let sample = fixture("ura64.exe");
    create_project(&path, "patches", &identity(&sample)).unwrap();
    save_annotation(&path, "140001020", None, "preserved").unwrap();
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute_batch("DROP TABLE patch_state; PRAGMA user_version=5;")
        .unwrap();
    drop(c);
    let before = std::fs::read(&path).unwrap();
    assert!(ura_project::read_project(&path)
        .unwrap()
        .patch_state
        .is_none());
    assert_eq!(before, std::fs::read(&path).unwrap());
    assert_eq!(open_project(&path).unwrap().project.schema_version, 8);
    let mut doc = PatchDocument::new(std::fs::read(sample).unwrap()).unwrap();
    let p = doc
        .preview(Address::FileOffset(0x220), &[0x55], &[0xc3], "return early")
        .unwrap();
    doc.apply(&p).unwrap();
    ura_project::save_patch_state(&path, doc.state(), 0).unwrap();
    let reopened = ura_project::read_project(&path).unwrap();
    assert_eq!(reopened.annotations[0].note, "preserved");
    assert_eq!(reopened.patch_state.as_ref().unwrap(), doc.state());
    doc.undo().unwrap();
    assert!(ura_project::save_patch_state(&path, doc.state(), 0).is_err());
    ura_project::save_patch_state(&path, doc.state(), 1).unwrap();
    let mut invalid = doc.state().clone();
    invalid.original_sha256 = "0".repeat(64);
    assert!(ura_project::save_patch_state(&path, &invalid, 2).is_err());
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute("UPDATE patch_state SET state_json=?1", ["{bad json}"])
        .unwrap();
    drop(c);
    assert!(ura_project::read_project(&path).is_err());
}

#[test]
fn migrates_v4_and_persists_validated_type_libraries_without_losing_user_data() {
    use ura_core::decomp::{StructField, Structure, TypeDatabase, TypeRef};
    let (_dir, path) = setup();
    create_project(&path, "Types", &identity(&fixture("ura64.exe"))).unwrap();
    save_annotation(&path, "140001000", None, "keep me").unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("DROP TABLE type_library; PRAGMA user_version=4;")
        .unwrap();
    drop(conn);
    let before = std::fs::read(&path).unwrap();
    assert!(ura_project::read_project(&path)
        .unwrap()
        .type_library
        .is_none());
    assert_eq!(before, std::fs::read(&path).unwrap());
    let migrated = open_project(&path).unwrap();
    assert_eq!(migrated.project.schema_version, 8);
    assert_eq!(migrated.annotations[0].note, "keep me");
    let mut db = TypeDatabase::new(64);
    db.structures.insert(
        "Record".into(),
        Structure {
            name: "Record".into(),
            size: Some(8),
            alignment: Some(4),
            union: false,
            source: "user".into(),
            fields: vec![StructField {
                name: "count".into(),
                offset: 0,
                ty: TypeRef::uint(32),
                size: None,
                source: "user".into(),
            }],
        },
    );
    db.typedefs.insert("Count".into(), TypeRef::uint(32));
    ura_project::save_type_library(&path, &db).unwrap();
    let reopened = open_project(&path).unwrap();
    assert_eq!(
        serde_json::to_value(reopened.type_library.unwrap()).unwrap(),
        serde_json::to_value(&db).unwrap()
    );
    assert_eq!(reopened.annotations[0].note, "keep me");
    let mut invalid = db.clone();
    invalid.typedefs.insert(
        "Cycle".into(),
        TypeRef::Named {
            name: "Cycle".into(),
        },
    );
    assert!(ura_project::save_type_library(&path, &invalid).is_err());
    assert_eq!(
        serde_json::to_value(
            ura_project::read_project(&path)
                .unwrap()
                .type_library
                .unwrap()
        )
        .unwrap(),
        serde_json::to_value(db).unwrap()
    );
}

#[test]
fn read_only_snapshots_preserve_legacy_schema_and_skip_binary_access() {
    let (_directory, path) = setup();
    create_project(&path, "Legacy", &identity(&fixture("ura64.exe"))).unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch("DROP TABLE function_names; DROP TABLE manual_functions; DROP TABLE view_state; PRAGMA user_version=1;").unwrap();
    connection
        .execute(
            "UPDATE project SET binary_path=?1",
            ["outside-allowed-root.exe"],
        )
        .unwrap();
    drop(connection);
    let before = std::fs::read(&path).unwrap();
    let snapshot = ura_project::read_project(&path).unwrap();
    assert_eq!(snapshot.project.schema_version, 1);
    assert_eq!(snapshot.binary_status, "unchecked");
    assert!(snapshot.function_names.is_empty());
    assert!(snapshot.manual_functions.is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(
        open_project(&path).unwrap().project.schema_version,
        SCHEMA_VERSION
    );
}

#[test]
fn creates_saves_and_reloads_annotations() {
    let (_directory, project_path) = setup();
    let binary_path = fixture("ura64.exe");
    let info = create_project(&project_path, "Fixture Analysis", &identity(&binary_path)).unwrap();
    assert_eq!(info.schema_version, SCHEMA_VERSION);
    assert_eq!(info.name, "Fixture Analysis");
    assert_eq!(info.format, "PE");

    let annotation = save_annotation(
        &project_path,
        "0x140001000",
        Some("entry_point"),
        "Primary entry point",
    )
    .unwrap();
    assert_eq!(annotation.address, "0x140001000");
    assert_eq!(annotation.label.as_deref(), Some("entry_point"));

    let snapshot = open_project(&project_path).unwrap();
    assert_eq!(snapshot.binary_status, "unchanged");
    assert_eq!(snapshot.annotations.len(), 1);
    assert_eq!(snapshot.annotations[0].note, "Primary entry point");

    let updated = save_annotation(
        &project_path,
        "0x140001000",
        Some("main"),
        "Updated annotation",
    )
    .unwrap();
    assert_eq!(updated.id, annotation.id);
    let snapshot = open_project(&project_path).unwrap();
    assert_eq!(snapshot.annotations.len(), 1);
    assert_eq!(snapshot.annotations[0].note, "Updated annotation");
    assert_eq!(snapshot.annotations[0].label.as_deref(), Some("main"));

    delete_annotation(&project_path, annotation.id).unwrap();
    let snapshot = open_project(&project_path).unwrap();
    assert!(snapshot.annotations.is_empty());
}

#[test]
fn detects_modified_and_missing_binaries() {
    let directory = tempfile::tempdir().unwrap();
    let binary_path = directory.path().join("sample.exe");
    std::fs::copy(fixture("ura64.exe"), &binary_path).unwrap();
    let project_path = directory.path().join("changed.ura");
    let original_identity = identity(&binary_path);
    create_project(&project_path, "Changed", &original_identity).unwrap();
    assert_eq!(
        open_project(&project_path).unwrap().binary_status,
        "unchanged"
    );

    let mut bytes = std::fs::read(&binary_path).unwrap();
    bytes.push(0);
    std::fs::write(&binary_path, bytes).unwrap();
    assert_eq!(
        open_project(&project_path).unwrap().binary_status,
        "modified"
    );

    std::fs::remove_file(&binary_path).unwrap();
    assert_eq!(
        open_project(&project_path).unwrap().binary_status,
        "missing"
    );
}

#[test]
fn rejects_existing_projects_and_future_schemas() {
    let (_directory, project_path) = setup();
    let binary_path = fixture("ura64.elf");
    create_project(&project_path, "One", &identity(&binary_path)).unwrap();
    let error = create_project(&project_path, "Two", &identity(&binary_path)).unwrap_err();
    assert!(matches!(error, ProjectError::AlreadyExists(_)));

    let connection = rusqlite::Connection::open(&project_path).unwrap();
    connection
        .execute_batch("PRAGMA user_version = 99;")
        .unwrap();
    drop(connection);
    let error = open_project(&project_path).unwrap_err();
    assert!(matches!(
        error,
        ProjectError::UnsupportedSchema {
            found: 99,
            supported: SCHEMA_VERSION
        }
    ));
}

#[test]
fn persists_and_deletes_function_names() {
    let (_directory, project_path) = setup();
    let binary_path = fixture("ura64.exe");
    create_project(&project_path, "Names", &identity(&binary_path)).unwrap();

    let saved = save_function_name(&project_path, "0x140001020", "  loop_counter  ").unwrap();
    assert_eq!(saved.address, "0x140001020");
    assert_eq!(saved.name, "loop_counter");

    let updated = save_function_name(&project_path, "0x140001020", "counter_loop").unwrap();
    assert_eq!(updated.name, "counter_loop");

    let snapshot = open_project(&project_path).unwrap();
    assert_eq!(snapshot.function_names.len(), 1);
    assert_eq!(snapshot.function_names[0].name, "counter_loop");

    assert!(save_function_name(&project_path, "0x140001020", "   ").is_err());
    assert!(save_function_name(&project_path, "not-an-address", "name").is_err());

    delete_function_name(&project_path, "0x140001020").unwrap();
    let snapshot = open_project(&project_path).unwrap();
    assert!(snapshot.function_names.is_empty());
}

#[test]
fn persists_manual_functions_and_view_state() {
    let (_directory, project_path) = setup();
    let binary_path = fixture("ura64.exe");
    create_project(&project_path, "Manual", &identity(&binary_path)).unwrap();

    add_manual_function(&project_path, "0x140001020").unwrap();
    add_manual_function(&project_path, "0x140001000").unwrap();
    add_manual_function(&project_path, "0x140001020").unwrap();
    let snapshot = open_project(&project_path).unwrap();
    assert_eq!(snapshot.manual_functions.len(), 2);
    assert_eq!(snapshot.manual_functions[0].address, "0x140001000");
    assert_eq!(snapshot.manual_functions[1].address, "0x140001020");
    assert!(snapshot.view_state.is_none());

    let state = r#"{"version":1,"address":"0x140001020","history":[]}"#;
    save_view_state(&project_path, state).unwrap();
    assert_eq!(
        load_view_state_for_path(&project_path).unwrap().as_deref(),
        Some(state)
    );
    let snapshot = open_project(&project_path).unwrap();
    assert_eq!(snapshot.view_state.as_deref(), Some(state));

    assert!(save_view_state(&project_path, "not json").is_err());
    assert!(save_view_state(&project_path, &"x".repeat(600 * 1024)).is_err());

    assert!(delete_manual_function(&project_path, "0x140001020").unwrap());
    assert!(!delete_manual_function(&project_path, "0x140001020").unwrap());
    let snapshot = open_project(&project_path).unwrap();
    assert_eq!(snapshot.manual_functions.len(), 1);
}

#[test]
fn exports_annotations_with_binary_identity_and_counts() {
    let (directory, project_path) = setup();
    let binary_path = fixture("ura64.elf");
    create_project(&project_path, "Export", &identity(&binary_path)).unwrap();
    save_annotation(&project_path, "0x401000", Some("entry"), "Entry note").unwrap();
    save_function_name(&project_path, "0x401020", "loop").unwrap();
    add_manual_function(&project_path, "0x401020").unwrap();

    let destination = directory.path().join("annotations.json");
    let summary = export_annotations(&project_path, &destination).unwrap();
    assert_eq!(summary.annotation_count, 1);
    assert_eq!(summary.function_name_count, 1);
    assert_eq!(summary.manual_function_count, 1);

    let raw = std::fs::read_to_string(&destination).unwrap();
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(value["format"], "ura-annotations");
    assert_eq!(value["version"], 1);
    assert_eq!(value["binary"]["architecture"], "x86-64");
    assert_eq!(value["annotations"][0]["address"], "0x401000");
    assert_eq!(value["functionNames"][0]["name"], "loop");
    assert_eq!(value["manualFunctions"][0]["address"], "0x401020");

    let error = export_annotations(&project_path, &project_path).unwrap_err();
    assert!(matches!(error, ProjectError::InvalidExport(_)));
    let error = export_annotations(&project_path, &binary_path).unwrap_err();
    assert!(matches!(error, ProjectError::InvalidExport(_)));
}

#[test]
fn migrates_version_two_projects_to_manual_functions_and_view_state() {
    let (_directory, project_path) = setup();
    let binary_path = fixture("ura64.elf");
    create_project(&project_path, "Legacy v2", &identity(&binary_path)).unwrap();

    let connection = rusqlite::Connection::open(&project_path).unwrap();
    connection
        .execute_batch(
            "DROP TABLE manual_functions; \
             DROP TABLE view_state; \
             PRAGMA user_version = 2;",
        )
        .unwrap();
    drop(connection);

    let snapshot = open_project(&project_path).unwrap();
    assert_eq!(snapshot.project.schema_version, SCHEMA_VERSION);
    assert!(snapshot.manual_functions.is_empty());
    assert!(snapshot.view_state.is_none());

    add_manual_function(&project_path, "0x401020").unwrap();
    save_view_state(&project_path, "{\"version\":1}").unwrap();
    let snapshot = open_project(&project_path).unwrap();
    assert_eq!(snapshot.manual_functions.len(), 1);
    assert!(snapshot.view_state.is_some());
}

#[test]
fn migrates_version_one_projects_to_function_names() {
    let (_directory, project_path) = setup();
    let binary_path = fixture("ura64.elf");
    create_project(&project_path, "Legacy", &identity(&binary_path)).unwrap();

    let connection = rusqlite::Connection::open(&project_path).unwrap();
    connection
        .execute_batch(
            "DROP TABLE function_names; \
             PRAGMA user_version = 1;",
        )
        .unwrap();
    drop(connection);

    let snapshot = open_project(&project_path).unwrap();
    assert_eq!(snapshot.project.schema_version, SCHEMA_VERSION);
    assert!(snapshot.function_names.is_empty());

    let saved = save_function_name(&project_path, "0x401020", "legacy_loop").unwrap();
    assert_eq!(saved.name, "legacy_loop");
    let snapshot = open_project(&project_path).unwrap();
    assert_eq!(snapshot.function_names.len(), 1);
    assert_eq!(snapshot.function_names[0].address, "0x401020");
}

#[test]
fn persists_function_signatures_and_stack_variable_overrides() {
    use ura_core::decomp::signature::{
        CallingConvention, Location, SignatureOverride, SignatureParameterInput,
    };
    use ura_core::decomp::types::TypeRef;

    let (_directory, project_path) = setup();
    let binary_path = fixture("ura64.exe");
    create_project(&project_path, "Signature", &identity(&binary_path)).unwrap();

    let signature = SignatureOverride {
        convention: CallingConvention::Win64,
        return_type: TypeRef::uint(64),
        parameters: vec![SignatureParameterInput {
            name: "count".into(),
            location: Location::Register { name: "rcx".into() },
            ty: TypeRef::uint(64),
        }],
        variadic: Some(false),
    };
    let saved =
        ura_project::save_function_signature(&project_path, "0x140001020", &signature).unwrap();
    assert_eq!(saved.address, "0x140001020");
    assert_eq!(saved.signature.parameters.len(), 1);

    let variable = ura_project::save_stack_variable(
        &project_path,
        "0x140001020",
        -8,
        Some("counter"),
        Some(&TypeRef::uint(32)),
    )
    .unwrap();
    assert_eq!(variable.offset, -8);
    assert_eq!(variable.name.as_deref(), Some("counter"));
    assert_eq!(
        variable.ty.as_ref().map(TypeRef::display),
        Some("u32".into())
    );

    ura_project::save_function_signature(&project_path, "0x140001020", &signature).unwrap();
    ura_project::save_stack_variable(&project_path, "0x140001020", -8, Some("renamed"), None)
        .unwrap();
    let snapshot = open_project(&project_path).unwrap();
    assert_eq!(snapshot.function_signatures.len(), 1);
    assert_eq!(snapshot.stack_variables.len(), 1);
    assert_eq!(snapshot.stack_variables[0].name.as_deref(), Some("renamed"));
    assert!(snapshot.stack_variables[0].ty.is_none());

    let invalid = SignatureOverride {
        parameters: vec![SignatureParameterInput {
            name: "bad name".into(),
            location: Location::Unknown {
                reason: "test".into(),
            },
            ty: TypeRef::uint(8),
        }],
        ..signature.clone()
    };
    assert!(ura_project::save_function_signature(&project_path, "0x140001020", &invalid).is_err());
    assert!(
        ura_project::save_stack_variable(&project_path, "0x140001020", -16, None, None).is_err()
    );
    assert!(ura_project::save_stack_variable(
        &project_path,
        "0x140001020",
        -16,
        Some(""),
        Some(&TypeRef::Named {
            name: String::new()
        })
    )
    .is_err());

    assert!(ura_project::delete_function_signature(&project_path, "0x140001020").unwrap());
    assert!(ura_project::delete_stack_variable(&project_path, "0x140001020", -8).unwrap());
    let snapshot = open_project(&project_path).unwrap();
    assert!(snapshot.function_signatures.is_empty());
    assert!(snapshot.stack_variables.is_empty());
}

#[test]
fn migrates_version_three_projects_to_decompiler_overrides() {
    use ura_core::decomp::signature::CallingConvention;
    use ura_core::decomp::signature::SignatureOverride;
    use ura_core::decomp::types::TypeRef;

    let (_directory, project_path) = setup();
    let binary_path = fixture("ura64.elf");
    create_project(&project_path, "Legacy v3", &identity(&binary_path)).unwrap();

    let connection = rusqlite::Connection::open(&project_path).unwrap();
    connection
        .execute_batch(
            "DROP TABLE function_signatures; \
             DROP TABLE stack_variables; \
             PRAGMA user_version = 3;",
        )
        .unwrap();
    drop(connection);

    let snapshot = open_project(&project_path).unwrap();
    assert_eq!(snapshot.project.schema_version, SCHEMA_VERSION);
    assert!(snapshot.function_signatures.is_empty());
    assert!(snapshot.stack_variables.is_empty());

    ura_project::save_function_signature(
        &project_path,
        "0x401020",
        &SignatureOverride {
            convention: CallingConvention::SysV64,
            return_type: TypeRef::uint(64),
            parameters: vec![],
            variadic: None,
        },
    )
    .unwrap();
    let snapshot = open_project(&project_path).unwrap();
    assert_eq!(snapshot.function_signatures.len(), 1);
}
