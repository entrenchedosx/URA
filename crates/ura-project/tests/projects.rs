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
