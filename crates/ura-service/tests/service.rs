use std::path::{Path, PathBuf};
use std::str::FromStr;

use ura_core::{AnalysisOptions, StringScanOptions};
use ura_service::{ErrorView, FunctionSort, PathPolicy, Service, XrefDirection};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn fixture(name: &str) -> PathBuf {
    fixtures().join(name)
}

fn service() -> Service {
    Service::new(PathPolicy::allow_all(), false)
}

#[test]
fn c_decompile_pages_match_core_and_export_is_explicit_complete_and_non_overwriting() {
    let mut reader = service();
    let handle = analyzed(&mut reader, &fixture("ura64.exe"));
    let first = reader.decompile(&handle, "140001020", 0, 3, true).unwrap();
    assert_eq!(first.syntax, "c-like");
    assert_eq!(first.returned, 3);
    assert_eq!(first.ast.as_ref().unwrap()["address"], "0x140001020");
    assert!(first.ast.as_ref().unwrap()["body"].is_array());
    let second = reader
        .decompile(&handle, "140001020", 3, 2000, false)
        .unwrap();
    assert_eq!(first.returned + second.returned, first.total);
    assert!(second.ast.is_none());
    assert!(reader.decompile(&handle, "140001020", 0, 0, false).is_err());
    assert!(reader
        .decompile(&handle, "140001020", 0, 2001, false)
        .is_err());
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("function.c");
    assert!(matches!(
        reader.export_decompiled_function(&handle, "140001020", &path),
        Err(ura_service::ServiceError::WriteDisabled)
    ));
    assert!(!path.exists());
    let mut writer = writer_service();
    let handle = analyzed(&mut writer, &fixture("ura64.exe"));
    let exported = writer
        .export_decompiled_function(&handle, "140001020", &path)
        .unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.len(), exported.bytes);
    assert!(text.contains("return"));
    assert!(writer
        .export_decompiled_function(&handle, "140001020", &path)
        .is_err());
    assert_eq!(text, std::fs::read_to_string(&path).unwrap());
}

#[test]
fn handle_budget_rejects_excess_without_poisoning_existing_sessions() {
    let mut s = service();
    let mut handles = Vec::new();
    for _ in 0..8 {
        handles.push(s.open_binary(&fixture("ura64.exe"), None).unwrap().handle);
    }
    assert_eq!(
        s.open_binary(&fixture("ura64.exe"), None)
            .unwrap_err()
            .code(),
        "limit_exceeded"
    );
    assert_eq!(s.info(&handles[0]).unwrap().info.format, "PE");
    s.close_binary(&handles[0]).unwrap();
    assert!(s.open_binary(&fixture("ura64.exe"), None).is_ok());
}

#[test]
fn cfg_reports_table_uncertainty_and_separately_seeded_tail_targets() {
    let mut s = service();
    let h = analyzed(&mut s, &fixture("switch-O2.exe"));
    let info = s.info(&h).unwrap();
    let entry = info.info.entry_point.unwrap();
    let cfg = s.cfg(&h, &entry, 200).unwrap();
    let dispatch = cfg.blocks.iter().find(|b| b.jump_table.is_some()).unwrap();
    let table = dispatch.jump_table.as_ref().unwrap();
    assert!(dispatch.indirect_unresolved);
    assert!(!table.exhaustive);
    assert_eq!(table.confidence, "guardedPatternHeuristic");
    assert_eq!(table.targets.len(), 6);
    assert_eq!(cfg.function.tail_call_candidates, 6);
    assert!(!cfg.function.thunk_candidate);
    let diagnostics = s.analysis_diagnostics(&h, &entry, 0, 50).unwrap();
    assert_eq!(diagnostics.jump_table_candidates, 1);
    assert_eq!(diagnostics.unresolved_indirect_transfers, 1);
}

#[test]
fn address_reads_do_not_leak_across_section_boundaries() {
    let mut service = service();
    let opened = service.open_binary(&fixture("ura64.exe"), None).unwrap();
    let section = opened.sections.iter().find(|s| s.executable).unwrap();
    let address = ura_core::parse_address(&section.address).unwrap()
        + section.file_size.min(section.size)
        - 1;
    assert!(service
        .read_bytes(&opened.handle, Some(&format!("{address:#x}")), None, 2)
        .is_err());
    assert!(service
        .read_bytes(&opened.handle, Some(&format!("{address:#x}")), None, 1)
        .is_ok());
}

fn writer_service() -> Service {
    Service::new(PathPolicy::allow_all(), true)
}

fn analyzed(service: &mut Service, path: &Path) -> String {
    let handle = service
        .open_binary(path, None)
        .expect("binary should open")
        .handle;
    service
        .analyze(&handle, &AnalysisOptions::default())
        .expect("analysis should complete");
    handle
}

#[test]
fn opens_the_pe_fixture_and_reports_identity() {
    let mut service = service();
    let opened = service
        .open_binary(&fixture("ura64.exe"), None)
        .expect("fixture should open");
    assert_eq!(opened.schema_version, 1);
    assert_eq!(opened.handle, "bin1");
    assert!(opened.attached_project.is_none());
    assert_eq!(opened.info.format, "PE");
    assert_eq!(opened.info.architecture, "x86-64");
    assert_eq!(opened.info.entry_point.as_deref(), Some("0x140001000"));
    assert_eq!(opened.info.image_base, "0x140000000");
    assert!(opened.info.path.ends_with("ura64.exe"));
    assert!(!opened.info.path.starts_with(r"\\?\"));
    assert!(opened
        .sections
        .iter()
        .any(|section| section.name == ".text" && section.executable));

    let info = service.info(&opened.handle).unwrap();
    assert!(!info.analyzed);
    assert!(info.function_count.is_none());

    let closed = service.close_binary(&opened.handle).unwrap();
    assert!(closed.closed);
    assert_eq!(
        service.info(&opened.handle).unwrap_err().code(),
        "unknown_handle"
    );
}

#[test]
fn analyzes_functions_and_supports_query_sort_and_paging() {
    let mut service = service();
    let handle = service
        .open_binary(&fixture("ura64.exe"), None)
        .unwrap()
        .handle;

    assert_eq!(
        service
            .functions(&handle, None, 0, 10, FunctionSort::Address)
            .unwrap_err()
            .code(),
        "analysis_required"
    );

    let analyzed = service
        .analyze(&handle, &AnalysisOptions::default())
        .unwrap();
    assert_eq!(analyzed.report.function_count, 2);
    assert!(analyzed.report.block_count >= 3);
    assert!(!analyzed.report.truncated);
    assert!(analyzed.report.diagnostics.is_empty());
    assert!(analyzed.options.follow_calls);

    let all = service
        .functions(&handle, None, 0, 10, FunctionSort::Address)
        .unwrap();
    assert_eq!(all.total, 2);
    assert_eq!(all.functions.len(), 2);
    assert_eq!(all.functions[0].address, "0x140001000");
    assert_eq!(all.functions[0].origin, "entryPoint");
    assert_eq!(all.functions[1].address, "0x140001020");
    assert_eq!(all.functions[1].name, "sub_140001020");
    assert_eq!(all.functions[1].origin, "callTarget");
    assert!(!all.functions[1].verified);

    let query = service
        .functions(&handle, Some("140001020"), 0, 10, FunctionSort::Address)
        .unwrap();
    assert_eq!(query.total, 1);
    assert_eq!(query.functions[0].address, "0x140001020");

    let paged = service
        .functions(&handle, None, 1, 1, FunctionSort::Name)
        .unwrap();
    assert_eq!(paged.offset, 1);
    assert_eq!(paged.limit, 1);
    assert_eq!(paged.returned, 1);

    assert_eq!(
        service
            .functions(&handle, None, 0, 0, FunctionSort::Address)
            .unwrap_err()
            .code(),
        "limit_exceeded"
    );

    let info = service.info(&handle).unwrap();
    assert!(info.analyzed);
    assert_eq!(info.function_count, Some(2));
}

#[test]
fn returns_function_detail_and_bounded_cfg() {
    let mut service = service();
    let handle = analyzed(&mut service, &fixture("ura64.exe"));

    let detail = service.function(&handle, "0x140001020", 500).unwrap();
    assert_eq!(detail.max_blocks, 500);
    assert!(!detail.blocks_truncated);
    assert!(!detail.callers_truncated);
    assert!(!detail.callees_truncated);
    assert_eq!(detail.function.address, "0x140001020");
    assert_eq!(detail.function.name, "sub_140001020");
    assert_eq!(detail.function.block_count, 3);
    assert_eq!(detail.function.caller_count, 1);
    assert_eq!(detail.callers[0].address, "0x140001000");
    assert!(detail.callees.is_empty());
    assert_eq!(
        detail
            .blocks
            .iter()
            .map(|block| block.address.as_str())
            .collect::<Vec<_>>(),
        vec!["0x140001020", "0x140001026", "0x14000102E"]
    );

    let inside = service.function(&handle, "0x140001027", 500).unwrap();
    assert_eq!(inside.function.address, "0x140001020");

    let bounded_function = service.function(&handle, "0x140001020", 2).unwrap();
    assert!(bounded_function.blocks_truncated);
    assert_eq!(bounded_function.blocks.len(), 2);

    let cfg = service.cfg(&handle, "0x140001020", 200).unwrap();
    assert!(!cfg.truncated);
    assert_eq!(cfg.blocks.len(), 3);
    let loop_block = cfg
        .blocks
        .iter()
        .find(|block| block.address == "0x140001026")
        .expect("loop block");
    assert!(loop_block
        .successors
        .iter()
        .any(|edge| edge.target == "0x140001026" && edge.kind == "taken"));
    assert!(loop_block
        .successors
        .iter()
        .any(|edge| edge.target == "0x14000102E" && edge.kind == "fallthrough"));

    let bounded = service.cfg(&handle, "0x140001020", 2).unwrap();
    assert!(bounded.truncated);
    assert_eq!(bounded.blocks.len(), 2);

    assert_eq!(
        service
            .function(&handle, "0x140001100", 500)
            .unwrap_err()
            .code(),
        "function_not_found"
    );
    assert_eq!(
        service
            .cfg(&handle, "0x140001020", 5000)
            .unwrap_err()
            .code(),
        "limit_exceeded"
    );
}

#[test]
fn disassembles_reads_bytes_extracts_strings_and_lists_xrefs() {
    let mut service = service();
    let handle = analyzed(&mut service, &fixture("ura64.exe"));

    let page = service.disassembly(&handle, "0x140001000", 20).unwrap();
    assert_eq!(page.page.start_address, "0x140001000");
    assert_eq!(page.page.instructions[0].text, "push rbp");
    assert_eq!(page.page.instructions[0].bytes, "55");
    assert!(page.page.has_more);
    assert_eq!(
        service
            .disassembly(&handle, "0x140001000", 0)
            .unwrap_err()
            .code(),
        "limit_exceeded"
    );

    let by_address = service
        .read_bytes(&handle, Some("0x140001000"), None, 16)
        .unwrap();
    assert_eq!(by_address.offset, "0x200");
    assert_eq!(by_address.address.as_deref(), Some("0x140001000"));
    assert_eq!(by_address.section.as_deref(), Some(".text"));
    assert_eq!(by_address.returned_length, 16);
    assert!(by_address.hex.starts_with("55 48"));

    let by_offset = service
        .read_bytes(&handle, None, Some("0x400"), 16)
        .unwrap();
    assert_eq!(by_offset.address.as_deref(), Some("0x140002000"));
    assert!(by_offset.ascii.starts_with("URA fixture"));

    assert_eq!(
        service
            .read_bytes(&handle, Some("0x140001000"), Some("0x200"), 16)
            .unwrap_err()
            .code(),
        "invalid_argument"
    );
    assert_eq!(
        service
            .read_bytes(&handle, None, None, 16)
            .unwrap_err()
            .code(),
        "invalid_argument"
    );
    assert_eq!(
        service
            .read_bytes(&handle, None, Some("0x200"), ura_core::MAX_HEX_READ + 1)
            .unwrap_err()
            .code(),
        "limit_exceeded"
    );

    let strings = service
        .strings(&handle, &StringScanOptions::default(), 0, 2_000)
        .unwrap();
    assert!(!strings.scan_truncated);
    assert!(strings
        .strings
        .iter()
        .any(|entry| entry.value == "URA fixture string" && entry.offset == "0x400"));
    assert!(strings
        .strings
        .iter()
        .any(|entry| entry.encoding == "UTF-16LE" && entry.value == "Wide URA"));

    let paged = service
        .strings(&handle, &StringScanOptions::default(), 0, 1)
        .unwrap();
    assert_eq!(paged.returned, 1);
    assert!(paged.has_more);

    let xrefs = service
        .xrefs(&handle, "0x140001020", XrefDirection::To, None, 100)
        .unwrap();
    assert!(xrefs.total >= 1);
    assert!(xrefs.xrefs.iter().any(|xref| {
        xref.from == "0x140001004"
            && xref.kind == "call"
            && xref.to_function.as_deref() == Some("0x140001020")
    }));

    let from = service
        .xrefs(
            &handle,
            "0x140001004",
            XrefDirection::From,
            Some("call"),
            100,
        )
        .unwrap();
    assert!(from
        .xrefs
        .iter()
        .any(|xref| xref.to == "0x140001020" && xref.kind == "call"));

    let filtered = service
        .xrefs(&handle, "0x140001020", XrefDirection::To, Some("data"), 100)
        .unwrap();
    assert_eq!(filtered.total, 0);

    assert_eq!(
        service
            .xrefs(
                &handle,
                "0x140001020",
                XrefDirection::To,
                Some("bogus"),
                100
            )
            .unwrap_err()
            .code(),
        "invalid_argument"
    );
    assert_eq!(
        XrefDirection::from_str("from").unwrap(),
        XrefDirection::From
    );
    assert_eq!(
        FunctionSort::from_str("references").unwrap(),
        FunctionSort::References
    );
}

#[test]
fn enforces_allowed_roots_and_reports_structured_errors() {
    let policy = PathPolicy::new([fixtures()]).unwrap();
    let mut service = Service::new(policy, false);
    assert!(service.open_binary(&fixture("ura64.exe"), None).is_ok());

    let directory = tempfile::tempdir().unwrap();
    let copy = directory.path().join("copy.exe");
    std::fs::copy(fixture("ura64.exe"), &copy).unwrap();
    let denied = service.open_binary(&copy, None).unwrap_err();
    assert_eq!(denied.code(), "path_denied");

    let missing = service
        .open_binary(&fixtures().join("missing.exe"), None)
        .unwrap_err();
    assert_eq!(missing.code(), "io_error");

    let view = ErrorView::new(&denied);
    let json = serde_json::to_value(&view).unwrap();
    assert_eq!(json["schemaVersion"], 1);
    assert_eq!(json["error"]["code"], "path_denied");
}

#[test]
fn project_writes_are_gated_and_persist_names_comments_and_exports() {
    let directory = tempfile::tempdir().unwrap();
    let project_path = directory.path().join("fixture.ura");
    let export_path = directory.path().join("annotations.json");

    let mut disabled = service();
    let handle = disabled
        .open_binary(&fixture("ura64.exe"), None)
        .unwrap()
        .handle;
    disabled
        .analyze(&handle, &AnalysisOptions::default())
        .unwrap();
    let denied = disabled
        .save_project(&handle, &project_path, Some("Fixture"))
        .unwrap_err();
    assert_eq!(denied.code(), "write_disabled");
    assert!(!project_path.exists());

    let mut service = writer_service();
    let opened = service.open_binary(&fixture("ura64.exe"), None).unwrap();
    let handle = opened.handle.clone();
    service
        .analyze(&handle, &AnalysisOptions::default())
        .unwrap();

    let created = service
        .save_project(&handle, &project_path, Some("Fixture"))
        .unwrap();
    assert!(created.created);
    assert_eq!(created.project.schema_version, ura_project::SCHEMA_VERSION);
    assert_eq!(created.project.binary_hash, opened.info.sha256);

    let reopened = service
        .save_project(&handle, &project_path, Some("Ignored"))
        .unwrap();
    assert!(!reopened.created);
    assert_eq!(reopened.project.name, "Fixture");

    let renamed = service
        .rename_function(&handle, &project_path, "0x140001020", "loop_fn")
        .unwrap();
    assert_eq!(renamed.function.address, "0x140001020");
    assert_eq!(renamed.function.name, "loop_fn");
    let listed = service
        .functions(&handle, Some("loop_fn"), 0, 10, FunctionSort::Address)
        .unwrap();
    assert_eq!(listed.total, 1);

    let comment = service
        .add_comment(
            &handle,
            &project_path,
            "0x140001004",
            Some("call site"),
            "calls the loop helper",
        )
        .unwrap();
    assert_eq!(comment.annotation.address, "0x140001004");
    assert_eq!(comment.annotation.note, "calls the loop helper");

    let snapshot = ura_project::open_project(&project_path).unwrap();
    assert_eq!(snapshot.function_names.len(), 1);
    assert_eq!(snapshot.function_names[0].name, "loop_fn");
    assert_eq!(snapshot.annotations.len(), 1);

    let exported = service
        .export_analysis(&project_path, &export_path)
        .unwrap();
    assert_eq!(exported.export.annotation_count, 1);
    assert_eq!(exported.export.function_name_count, 1);
    assert!(export_path.exists());

    let mut other = writer_service();
    let elf = other.open_binary(&fixture("ura64.elf"), None).unwrap();
    let mismatch = other
        .save_project(&elf.handle, &project_path, None)
        .unwrap_err();
    assert_eq!(mismatch.code(), "project_binary_mismatch");
}

#[test]
fn project_writes_cannot_escape_through_dangling_symlinks_or_data_streams() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("escaped.ura");
    let link = root.path().join("project.ura");

    #[cfg(windows)]
    let created = std::os::windows::fs::symlink_file(&target, &link).is_ok();
    #[cfg(not(windows))]
    let created = std::os::unix::fs::symlink(&target, &link).is_ok();
    if created {
        let mut service = Service::new(PathPolicy::new([root.path().to_path_buf()]).unwrap(), true);
        let handle = service
            .open_binary(&fixture("ura64.exe"), None)
            .unwrap()
            .handle;
        service
            .analyze(&handle, &AnalysisOptions::default())
            .unwrap();
        let error = service
            .save_project(&handle, &link, Some("Escape"))
            .unwrap_err();
        assert_eq!(error.code(), "path_denied");
        assert!(!target.exists());
    }

    #[cfg(windows)]
    {
        let policy = PathPolicy::new([root.path().to_path_buf()]).unwrap();
        let ads = root.path().join("project.ura:payload");
        assert_eq!(
            policy.allow_write(&ads).unwrap_err().code(),
            "invalid_argument"
        );
    }
}

#[test]
fn rejects_unknown_handles_and_invalid_project_paths() {
    let mut service = writer_service();
    assert_eq!(service.info("bin99").unwrap_err().code(), "unknown_handle");
    assert_eq!(
        service.close_binary("bin99").unwrap_err().code(),
        "unknown_handle"
    );

    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("missing.ura");
    let handle = service
        .open_binary(&fixture("ura64.exe"), None)
        .unwrap()
        .handle;
    service
        .analyze(&handle, &AnalysisOptions::default())
        .unwrap();
    assert_eq!(
        service
            .rename_function(&handle, &project, "0x140001020", "name")
            .unwrap_err()
            .code(),
        "project_not_found"
    );
    assert_eq!(
        service
            .add_comment(&handle, &project, "0x140001004", None, "note")
            .unwrap_err()
            .code(),
        "project_not_found"
    );
    assert_eq!(
        service
            .export_analysis(&project, &directory.path().join("out.json"))
            .unwrap_err()
            .code(),
        "project_not_found"
    );
}
