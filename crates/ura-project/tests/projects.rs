use std::path::{Path, PathBuf};
use tempfile::TempDir;
use ura_core::analyze_path;
use ura_project::{
    create_project, delete_annotation, open_project, save_annotation, BinaryIdentity, ProjectError,
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
            supported: 1
        }
    ));
}
