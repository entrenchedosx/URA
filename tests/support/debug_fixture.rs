//! Compile only repository-owned source before any debugger test executes it.
//! Per-test-process outputs prevent races with other test executables/targets.
pub fn fixture() -> std::path::PathBuf {
    static FIXTURE: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .canonicalize()
                .unwrap();
            let folder = root.join("target/debug-fixtures");
            std::fs::create_dir_all(&folder).unwrap();
            let output = folder.join(format!("ura-debuggee-test-{}.exe", std::process::id()));
            let mut command = std::process::Command::new(
                std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()),
            );
            command
                .args([
                    "--edition=2021",
                    "-C",
                    "opt-level=1",
                    "-C",
                    "debuginfo=2",
                    "-C",
                    "link-arg=/EXPORT:ura_marker",
                    "-C",
                    "link-arg=/EXPORT:ura_nested",
                    "-C",
                    "link-arg=/EXPORT:ura_existing_int3,DATA",
                    "-C",
                    "link-arg=/EXPORT:ura_watch,DATA",
                    "-C",
                    "link-arg=/EXPORT:ura_store",
                    "-C",
                    "link-arg=/EXPORT:ura_step_wait",
                ])
                .arg(root.join("tests/fixtures/debuggee.rs"))
                .arg("-o")
                .arg(&output);
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                command.creation_flags(0x08000000);
            }
            let result = command.output().expect("compile owned Rust debug fixture");
            assert!(
                result.status.success(),
                "fixture compilation: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            output.canonicalize().unwrap()
        })
        .clone()
}
