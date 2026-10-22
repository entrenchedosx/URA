use ura_core::{patch::*, *};
fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[test]
fn review_regressions_cover_sparse_reset_malformed_headers_and_untrusted_assembly() {
    let mut p = PatchDocument::raw(vec![0x90; 1024], Some(0x1000), 64).unwrap();
    for offset in (0..514).step_by(2) {
        let preview = p
            .preview(Address::FileOffset(offset), &[0x90], &[1], "")
            .unwrap();
        p.apply(&preview).unwrap();
    }
    p.revert_all().unwrap();
    assert_eq!(p.changed_bytes(), 0);
    let saved = p.state().clone();
    p.undo().unwrap();
    assert_eq!(p.changed_bytes(), 257);
    p.redo().unwrap();
    assert_eq!(p.changed_bytes(), 0);
    let mut restored = PatchDocument::raw(vec![0x90; 1024], Some(0x1000), 64).unwrap();
    restored.restore(&saved).unwrap();
    assert_eq!(restored.changed_bytes(), 0);
    let bytes = std::fs::read(fixture("ura64.exe")).unwrap();
    let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    for size in [0u32, 64] {
        let mut bad = bytes.clone();
        bad[pe + 24 + 60..pe + 24 + 64].copy_from_slice(&size.to_le_bytes());
        assert!(PatchDocument::new(bad).is_err());
    }
    let p = raw();
    let text = format!("mov eax, {}1", "-".repeat(15000));
    assert!(p
        .preview_instruction(Address::FileOffset(0), 5, &text, false, "")
        .is_err());
    assert!(PatchDocument::raw(vec![0x90; 2], Some(0xffff_ffff), 32).is_err());
    let p = PatchDocument::raw(vec![0x90; 8], Some(0xffff_ffff_8000_1001), 64).unwrap();
    let json = serde_json::to_value(
        p.preview_instruction(Address::FileOffset(0), 1, "ret", false, "")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(json["address"], "0xFFFFFFFF80001001");
}

#[test]
fn export_cancellation_after_writing_never_publishes_a_partial_destination() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct CancelAfter(AtomicUsize);
    impl AnalysisControl for CancelAfter {
        fn is_cancelled(&self) -> bool {
            self.0.fetch_add(1, Ordering::Relaxed) > 5
        }
        fn report(&self, _: AnalysisProgress) {}
    }
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("raw.bin");
    let bytes = vec![0x90; 1024 * 1024];
    std::fs::write(&source, &bytes).unwrap();
    let p = PatchDocument::raw(bytes, None, 32).unwrap();
    let destination = dir.path().join("result.bin");
    assert!(p
        .export(&source, &destination, &CancelAfter(AtomicUsize::new(0)))
        .is_err());
    assert!(!destination.exists());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}
fn raw() -> PatchDocument {
    PatchDocument::raw(vec![0x90; 64], Some(0x1000), 64).unwrap()
}

#[test]
fn overlapping_edits_require_current_bytes_and_history_is_deterministic() {
    let mut p = raw();
    let first = p
        .preview(Address::FileOffset(4), &[0x90; 3], &[1, 2, 3], "first")
        .unwrap();
    p.apply(&first).unwrap();
    assert!(p.apply(&first).is_err());
    assert!(p
        .preview(Address::FileOffset(5), &[0x90; 2], &[4, 5], "")
        .is_err());
    let second = p
        .preview(
            Address::FileOffset(5),
            &[2, 3],
            &[4, 5],
            "intentional overlap",
        )
        .unwrap();
    p.apply(&second).unwrap();
    assert_eq!(
        p.read(Address::VirtualAddress(0x1004), 3).unwrap(),
        [1, 4, 5]
    );
    assert!(p.revert(1).is_err());
    assert_eq!(
        p.revert_conflicts().into_iter().collect::<Vec<_>>(),
        vec![1]
    );
    p.undo().unwrap();
    assert_eq!(p.read(Address::FileOffset(4), 3).unwrap(), [1, 2, 3]);
    p.redo().unwrap();
    assert_eq!(p.read(Address::FileOffset(4), 3).unwrap(), [1, 4, 5]);
    p.undo().unwrap();
    p.revert(1).unwrap();
    assert_eq!(p.changed_bytes(), 0);
    assert!(p.redo().is_err());
    assert_eq!(p.original(), vec![0x90; 64]);
}
#[test]
fn transaction_validation_rolls_back_every_edit_and_rejects_internal_overlap() {
    let mut p = raw();
    let mut preview = p
        .preview(Address::FileOffset(0), &[0x90], &[1], "")
        .unwrap();
    preview.edits.push(Edit {
        offset: 8,
        before: vec![0],
        after: vec![2],
    });
    let before = p.state().clone();
    assert!(p.apply(&preview).is_err());
    assert_eq!(p.state(), &before);
    assert_eq!(p.changed_bytes(), 0);
    preview.edits[1] = Edit {
        offset: 0,
        before: vec![0x90],
        after: vec![2],
    };
    assert!(p.apply(&preview).is_err());
    assert_eq!(p.changed_bytes(), 0);
    assert!(p
        .preview(Address::FileOffset(u64::MAX), &[0x90], &[1], "")
        .is_err());
    assert!(p
        .preview(Address::FileOffset(63), &[0x90; 2], &[1, 2], "")
        .is_err());
    assert!(p.read(Address::FileOffset(0), MAX_PATCH_BYTES + 1).is_err());
}
#[test]
fn persisted_history_checks_identity_bytes_counters_and_redo_tail() {
    let mut p = raw();
    let v = p
        .preview(Address::FileOffset(2), &[0x90], &[1], "")
        .unwrap();
    p.apply(&v).unwrap();
    p.undo().unwrap();
    let saved = p.state().clone();
    let mut reopened = raw();
    reopened.restore(&saved).unwrap();
    reopened.redo().unwrap();
    assert_eq!(reopened.read(Address::FileOffset(2), 1).unwrap(), [1]);
    let unchanged = reopened.state().clone();
    for n in 0..4 {
        let mut bad = saved.clone();
        match n {
            0 => bad.original_sha256 = "0".repeat(64),
            1 => bad.transactions[0].edits[0].before[0] = 0,
            2 => bad.cursor = 2,
            _ => bad.next_id = 1,
        };
        assert!(reopened.restore(&bad).is_err());
        assert_eq!(reopened.state(), &unchanged);
    }
}
#[test]
fn reverting_all_is_undoable_and_keeps_unrelated_patch_history() {
    let mut p = raw();
    for o in [2, 8] {
        let v = p
            .preview(Address::FileOffset(o), &[0x90], &[0xc3], "")
            .unwrap();
        p.apply(&v).unwrap();
    }
    let expected = p.materialize();
    p.revert(1).unwrap();
    assert_eq!(p.read(Address::FileOffset(8), 1).unwrap(), [0xc3]);
    p.undo().unwrap();
    assert_eq!(p.materialize(), expected);
    p.revert_all().unwrap();
    assert_eq!(p.changed_bytes(), 0);
    p.undo().unwrap();
    assert_eq!(p.materialize(), expected);
}
#[test]
fn raw_address_base_is_explicit_and_hex_input_is_strict() {
    let a = raw();
    let preview = a
        .preview_instruction(Address::FileOffset(0), 2, "jmp 1010", false, "")
        .unwrap();
    for (base, bits) in [(0x2000, 64), (0x1000, 32)] {
        let mut b = PatchDocument::raw(vec![0x90; 64], Some(base), bits).unwrap();
        assert!(b.apply(&preview.patch).is_err());
        assert_eq!(b.changed_bytes(), 0);
    }
    let p = PatchDocument::raw(vec![0; 4], None, 32).unwrap();
    assert!(p.read(Address::VirtualAddress(0), 1).is_err());
    assert!(p.read(Address::Rva(0), 1).is_err());
    assert!(PatchDocument::raw(vec![0; 4], Some(u64::MAX), 64).is_err());
    assert_eq!(parse_hex("90 c3\n00").unwrap(), [0x90, 0xc3, 0]);
    for s in ["", "0", "0x90", "gg", "90é"] {
        assert!(parse_hex(s).is_err());
    }
}
#[test]
fn pe_and_elf_mappings_protect_headers_and_reject_unbacked_or_crossing_ranges() {
    for name in ["ura64.exe", "ura64.elf", "patch32.exe", "patch32.elf"] {
        let bytes = std::fs::read(fixture(name)).unwrap();
        let p = PatchDocument::new(bytes).unwrap();
        let binary = analyze_path(&fixture(name)).unwrap();
        let entry = binary.analysis().entry_point.unwrap();
        let offset = p.offset(Address::VirtualAddress(entry), 1).unwrap();
        assert_eq!(p.virtual_address(offset, 1), Some(entry));
        assert_eq!(
            p.read(Address::VirtualAddress(entry), 1).unwrap(),
            p.read(Address::FileOffset(offset), 1).unwrap()
        );
        assert!(p
            .preview(Address::FileOffset(0), &p.original()[0..1], &[0], "")
            .is_err());
        for m in p.mappings() {
            if m.memory_size > m.file_size {
                assert!(p
                    .offset(Address::VirtualAddress(m.address + m.file_size), 1)
                    .is_err());
            }
        }
        assert!(p.offset(Address::VirtualAddress(u64::MAX), 2).is_err());
        if name.ends_with("exe") {
            assert_eq!(
                p.offset(Address::Rva(entry - binary.analysis().image_base), 1)
                    .unwrap(),
                offset
            );
        }
    }
}
#[test]
fn x86_pe_elf_instruction_patches_match_independently_assembled_fixture_bytes() {
    for name in ["patch32.exe", "patch32.elf"] {
        let binary = analyze_path(&fixture(name)).unwrap();
        let entry = binary.analysis().entry_point.unwrap();
        let doc = PatchDocument::new(binary.bytes().to_vec()).unwrap();
        assert_eq!(doc.bitness(), 32);
        let preview = doc
            .preview_instruction(Address::VirtualAddress(entry), 5, "mov eax, 2a", false, "")
            .unwrap();
        assert_eq!(
            preview.patch.edits[0].after,
            doc.read(Address::VirtualAddress(entry + 6), 5).unwrap()
        );
        assert_eq!(preview.patch.edits[0].after, [0xb8, 42, 0, 0, 0]);
    }
}
#[test]
fn instruction_encoding_checks_origin_lengths_padding_and_decoder_operands() {
    let p = raw();
    for (text, size, expected) in [
        ("mov eax, 12345678", 5, vec![0xb8, 0x78, 0x56, 0x34, 0x12]),
        ("ret", 1, vec![0xc3]),
        ("jmp 1010", 2, vec![0xeb, 0x0e]),
        ("jne 1010", 2, vec![0x75, 0x0e]),
        ("call 1010", 5, vec![0xe8, 0x0b, 0, 0, 0]),
    ] {
        let v = p
            .preview_instruction(Address::VirtualAddress(0x1000), size, text, false, "")
            .unwrap();
        assert_eq!(v.patch.edits[0].after, expected, "{text}");
    }
    let padded = p
        .preview_instruction(Address::FileOffset(0), 8, "mov eax, 2a", true, "")
        .unwrap();
    assert_eq!(padded.padding_bytes, 3);
    assert_eq!(&padded.patch.edits[0].after[5..], &[0x90; 3]);
    assert!(p
        .preview_instruction(Address::FileOffset(0), 8, "ret", false, "")
        .is_err());
    assert!(p
        .preview_instruction(Address::FileOffset(0), 1, "mov rax, 1", true, "")
        .is_err());
    assert!(p
        .preview_instruction(Address::FileOffset(0), 5, "mov rax, [rsp]", false, "")
        .is_err());
    assert!(p
        .preview_instruction(Address::FileOffset(0), 5, "call 10000000000", false, "")
        .is_err());
    let x86 = PatchDocument::raw(vec![0x90; 32], Some(0x1000), 32).unwrap();
    assert!(x86
        .preview_instruction(Address::FileOffset(0), 10, "mov rax, 1", true, "")
        .is_err());
    assert_eq!(
        x86.preview_instruction(Address::FileOffset(0), 5, "mov eax, 1", false, "")
            .unwrap()
            .patch
            .edits[0]
            .after,
        [0xb8, 1, 0, 0, 0]
    );
}
#[test]
fn instruction_region_cannot_end_inside_an_original_instruction() {
    let p = PatchDocument::raw(vec![0x48, 0x89, 0xc8, 0x90], Some(0x1000), 64).unwrap();
    assert!(p
        .preview_instruction(Address::VirtualAddress(0x1000), 2, "nop", true, "")
        .is_err());
    assert!(p
        .preview_instruction(Address::VirtualAddress(0x1000), 3, "xor eax, ecx", true, "")
        .is_ok());
}
#[test]
fn export_is_exact_new_file_only_reimported_and_cancellable() {
    struct Cancel;
    impl AnalysisControl for Cancel {
        fn is_cancelled(&self) -> bool {
            true
        }
        fn report(&self, _: AnalysisProgress) {}
    }
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.exe");
    std::fs::copy(fixture("ura64.exe"), &source).unwrap();
    let original = std::fs::read(&source).unwrap();
    let mut p = PatchDocument::new(original.clone()).unwrap();
    let v = p
        .preview_instruction(Address::VirtualAddress(0x140001020), 1, "ret", false, "")
        .unwrap();
    p.apply(&v.patch).unwrap();
    let out = dir.path().join("patched.exe");
    assert!(p.export(&source, &out, &Cancel).is_err());
    assert!(!out.exists());
    let report = p.export(&source, &out, &()).unwrap();
    let actual = std::fs::read(&out).unwrap();
    assert_eq!(actual, p.materialize());
    assert_eq!(report.sha256, sha256_hex(&actual));
    assert_eq!(std::fs::read(&source).unwrap(), original);
    assert!(analyze_path(&out).is_ok());
    assert!(p.export(&source, &out, &()).is_err());
    assert!(p.export(&source, &source, &()).is_err());
    std::fs::write(&source, b"changed").unwrap();
    assert!(p
        .export(&source, &dir.path().join("other.exe"), &())
        .is_err());
}
#[test]
fn patched_return_changes_cfg_ir_and_pseudocode_after_fresh_analysis() {
    let path = fixture("ura64.exe");
    let before = analyze_path(&path).unwrap();
    let cfg = analyze_functions(&before, &Default::default(), &());
    let old = decomp::analyze_function(
        &before,
        &cfg,
        0x140001020,
        &decomp::DecompContext::new(64),
        &(),
    )
    .unwrap();
    let mut p = PatchDocument::new(before.bytes().to_vec()).unwrap();
    let v = p
        .preview_instruction(Address::VirtualAddress(0x140001020), 1, "ret", false, "")
        .unwrap();
    p.apply(&v.patch).unwrap();
    let after = binary::analyze_bytes(&path, p.materialize()).unwrap();
    let new_cfg = analyze_functions(&after, &Default::default(), &());
    assert_eq!(
        new_cfg
            .function_by_start(0x140001020)
            .unwrap()
            .instruction_count,
        1
    );
    let new = decomp::analyze_function(
        &after,
        &new_cfg,
        0x140001020,
        &decomp::DecompContext::new(64),
        &(),
    )
    .unwrap();
    assert!(new.pseudocode.lines.len() < old.pseudocode.lines.len());
    assert_eq!(
        after.disassemble(0x140001020, 1).unwrap().instructions[0].mnemonic,
        "ret"
    );
    assert!(ir::inspect::analyze(&after, &new_cfg, 0x140001020, &()).is_ok());
}
