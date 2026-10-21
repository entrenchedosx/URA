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
    assert_eq!(migrated.project.schema_version, 5);
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
