//! Local headless patch timings. Does not launch the native UI or inspected code.
use std::time::Instant;
use ura_core::patch::{Address, PatchDocument};
fn timed<T>(f: impl FnOnce() -> T) -> (T, f64) {
    let started = Instant::now();
    let result = f();
    (result, started.elapsed().as_secs_f64() * 1000.0)
}
fn main() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("original.bin");
    let bytes = vec![0x90; 16 * 1024 * 1024];
    std::fs::write(&source, &bytes).unwrap();
    let mut observations = Vec::new();
    for run in 0..3 {
        let mut document = PatchDocument::raw(bytes.clone(), Some(0x1000), 64).unwrap();
        let (_, single) = timed(|| {
            let preview = document
                .preview(Address::FileOffset(16), &[0x90], &[0xc3], "")
                .unwrap();
            document.apply(&preview).unwrap();
        });
        let (_, undo) = timed(|| document.undo().unwrap());
        let (_, redo) = timed(|| document.redo().unwrap());
        let replacement = vec![0x42; 1024 * 1024];
        let expected = vec![0x90; replacement.len()];
        document.undo().unwrap();
        let (_, large) = timed(|| {
            let preview = document
                .preview(Address::FileOffset(1024), &expected, &replacement, "")
                .unwrap();
            document.apply(&preview).unwrap();
        });
        let (_, conflicts) = timed(|| document.revert_conflicts());
        let destination = directory.path().join(format!("patched-{run}.bin"));
        let (export, export_ms) = timed(|| document.export(&source, &destination, &()).unwrap());
        let (_, restore) = timed(|| {
            let mut reopened = PatchDocument::raw(bytes.clone(), Some(0x1000), 64).unwrap();
            reopened.restore(document.state()).unwrap();
            assert_eq!(reopened.changed_bytes(), replacement.len());
        });
        observations.push(serde_json::json!({"run":run,"singleBytePreviewApplyMs":single,"undoMs":undo,"redoMs":redo,"oneMiBPreviewApplyMs":large,"conflictSummaryMs":conflicts,"restoreIncludingOriginalHashMs":restore,"export16MiBMs":export_ms,"exportMiBPerSecond":16000.0/export_ms,"overlayChangedBytes":document.changed_bytes(),"exportBytes":export.bytes}));
    }
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/ura64.exe");
    let binary = ura_core::analyze_path(&fixture).unwrap();
    let mut doc = PatchDocument::from_shared(binary.shared_bytes()).unwrap();
    let preview = doc
        .preview_instruction(Address::VirtualAddress(0x140001020), 1, "ret", false, "")
        .unwrap();
    doc.apply(&preview.patch).unwrap();
    let (_, reanalysis) = timed(|| {
        let effective = doc.effective_binary(&fixture).unwrap();
        let cfg = ura_core::analyze_functions(&effective, &Default::default(), &());
        ura_core::decomp::analyze_function(
            &effective,
            &cfg,
            0x140001020,
            &ura_core::decomp::DecompContext::new(64),
            &(),
        )
        .unwrap();
    });
    let project = directory.path().join("patches.ura");
    let info = binary.view();
    let identity = ura_project::BinaryIdentity {
        binary_path: fixture.to_string_lossy().into_owned(),
        binary_hash: info.sha256,
        file_size: info.file_size,
        format: info.format,
        architecture: info.architecture,
    };
    ura_project::create_project(&project, "benchmark", &identity).unwrap();
    let (_, save) = timed(|| ura_project::save_patch_state(&project, doc.state(), 0).unwrap());
    let (_, reopen) = timed(|| ura_project::read_project(&project).unwrap());
    println!("{}",serde_json::to_string_pretty(&serde_json::json!({"version":"0.10.0-dev","profile":"Release","repetitions":3,"rawOriginalMiB":16,"rawPatchMiB":1,"observations":observations,"fixtureReparseCfgAndPseudocodeMs":reanalysis,"fixturePatchProjectSaveMs":save,"fixtureProjectReadMs":reopen,"guiInteractionMeasured":false,"sampleExecuted":false})).unwrap());
}
