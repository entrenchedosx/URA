//! Trusted import binding regressions. The PE sample is an in-memory linked
//! image whose own import table is the only evidence source; nothing runs.
use std::path::Path;

use ura_core::binary::analyze_bytes;
use ura_core::decomp::{
    self, abi::SignatureHints, imports, CallingConvention, DecompContext, Location,
};
use ura_core::{analyze_functions, AnalysisOptions, LoadedBinary, ProgramAnalysis};

struct Image {
    bytes: Vec<u8>,
    slot: u64,
    entry: u64,
}

/// Minimal PE32+ image: one `.text` section holding
/// `call qword ptr [MessageBoxA]; ret`, and an import table binding the IAT
/// slot to USER32.dll!MessageBoxA. The layout is deliberately simple and
/// disjoint so each region can be asserted independently.
fn image() -> Image {
    const IMAGE_BASE: u64 = 0x140000000;
    const IMPORT_DIR_RVA: u32 = 0x2000;
    const IAT_RVA: u32 = 0x2090;
    const NAME_THUNK_RVA: u32 = 0x2078;
    const IMPORT_BY_NAME_RVA: u32 = 0x20B0;
    const LIBRARY_NAME_RVA: u32 = 0x2100;

    let mut bytes = vec![0u8; 0x1500];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    bytes[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
    bytes[0x96..0x98].copy_from_slice(&0x0022u16.to_le_bytes());
    let optional = 0x98;
    bytes[optional..optional + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
    bytes[optional + 2] = 6;
    bytes[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[optional + 20..optional + 24].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[optional + 24..optional + 32].copy_from_slice(&IMAGE_BASE.to_le_bytes());
    bytes[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[optional + 56..optional + 60].copy_from_slice(&0x3000u32.to_le_bytes());
    bytes[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[optional + 68..optional + 70].copy_from_slice(&2u16.to_le_bytes());
    bytes[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
    bytes[optional + 120..optional + 124].copy_from_slice(&IMPORT_DIR_RVA.to_le_bytes());
    bytes[optional + 124..optional + 128].copy_from_slice(&28u32.to_le_bytes());
    let section = optional + 240;
    bytes[section..section + 7].copy_from_slice(b".text\0\0");
    bytes[section + 8..section + 12].copy_from_slice(&0x3000u32.to_le_bytes());
    bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[section + 16..section + 20].copy_from_slice(&0x1300u32.to_le_bytes());
    bytes[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[section + 36..section + 40].copy_from_slice(&0x60000020u32.to_le_bytes());

    bytes[0x200..0x204].copy_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
    let code = 0x204;
    let next = 0x100Au32;
    bytes[code..code + 2].copy_from_slice(&[0xFF, 0x15]);
    bytes[code + 2..code + 6].copy_from_slice(&(IAT_RVA - next).to_le_bytes());
    bytes[code + 6..code + 10].copy_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
    bytes[code + 10] = 0xC3;
    let import_dir_offset = 0x200 + (IMPORT_DIR_RVA - 0x1000) as usize;
    bytes[code + 11..import_dir_offset].fill(0xCC);

    let descriptor = 0x200 + (IMPORT_DIR_RVA - 0x1000) as usize;
    bytes[descriptor..descriptor + 4].copy_from_slice(&NAME_THUNK_RVA.to_le_bytes());
    bytes[descriptor + 12..descriptor + 16].copy_from_slice(&LIBRARY_NAME_RVA.to_le_bytes());
    bytes[descriptor + 16..descriptor + 20].copy_from_slice(&IAT_RVA.to_le_bytes());

    let rva = |address: u32, size: usize| -> (usize, usize) {
        (
            0x200 + (address - 0x1000) as usize,
            0x200 + (address - 0x1000) as usize + size,
        )
    };
    let (byname, byname_end) = rva(IMPORT_BY_NAME_RVA, 14);
    bytes[byname..byname + 2].copy_from_slice(&1u16.to_le_bytes());
    bytes[byname + 2..byname_end - 1].copy_from_slice(b"MessageBoxA");
    let (name_thunk, _name_thunk_end) = rva(NAME_THUNK_RVA, 8);
    bytes[name_thunk..name_thunk + 8].copy_from_slice(&(IMPORT_BY_NAME_RVA as u64).to_le_bytes());
    let (iat, _iat_end) = rva(IAT_RVA, 16);
    bytes[iat..iat + 8].copy_from_slice(&(IMPORT_BY_NAME_RVA as u64).to_le_bytes());
    let (library, library_end) = rva(LIBRARY_NAME_RVA, 11);
    bytes[library..library_end].copy_from_slice(b"USER32.dll\0");

    let binary = analyze_bytes(Path::new("imports64.exe"), bytes.clone())
        .expect("crafted PE should analyze");
    let entry = binary.analysis().entry_point.unwrap();
    Image {
        bytes,
        slot: IMAGE_BASE + u64::from(IAT_RVA),
        entry,
    }
}

fn model(binary: &LoadedBinary) -> (ProgramAnalysis, u64) {
    let entry = binary.analysis().entry_point.unwrap();
    let analysis = analyze_functions(
        binary,
        &AnalysisOptions {
            seed_symbols: false,
            ..Default::default()
        },
        &(),
    );
    (analysis, entry)
}

fn analyze() -> (LoadedBinary, ProgramAnalysis, u64, Image) {
    let crafted = image();
    let binary = analyze_bytes(Path::new("imports64.exe"), crafted.bytes.clone()).unwrap();
    let (analysis, entry) = model(&binary);
    (binary, analysis, entry, crafted)
}

#[test]
fn pe_import_slots_bind_to_their_tables() {
    let (binary, _, _, crafted) = analyze();
    let bound = imports::bindings(&binary).unwrap();
    assert_eq!(bound[0].address.0, crafted.slot);
    assert_eq!(binary.analysis().entry_point, Some(crafted.entry));
    assert_eq!(bound.len(), 1, "{bound:#?}");
    assert_eq!(bound[0].name, "MessageBoxA");
    assert_eq!(bound[0].library.as_deref(), Some("USER32.dll"));
}

#[test]
fn external_graph_has_exact_site_identity_and_trusted_signature() {
    let (binary, analysis, entry, crafted) = analyze();
    let graph = decomp::callgraph::build_with_imports(&binary, &analysis, &()).unwrap();
    let external = graph.node(crafted.slot).unwrap();
    assert!(external.external);
    let import = external.import.as_ref().unwrap();
    assert_eq!(import.binding.library.as_deref(), Some("USER32.dll"));
    assert_eq!(
        import.signature.as_ref().unwrap().convention,
        CallingConvention::Win64
    );
    let sites: Vec<_> = graph
        .edges
        .iter()
        .filter(|edge| edge.to == crafted.slot)
        .collect();
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].from, entry);
    assert_eq!(sites[0].instruction, Some(entry + 4));
    assert_eq!(graph.unresolved_indirect, 0);
}

#[test]
fn import_thunk_keeps_internal_call_and_separate_external_jump() {
    let mut crafted = image();
    // caller: sub rsp,28; call entry+40; add rsp,28; ret
    crafted.bytes[0x204..0x209].copy_from_slice(&[0xe8, 0x37, 0, 0, 0]);
    crafted.bytes[0x209..0x20e].copy_from_slice(&[0x48, 0x83, 0xc4, 0x28, 0xc3]);
    crafted.bytes[0x20e..0x240].fill(0xcc);
    crafted.bytes[0x240..0x242].copy_from_slice(&[0xff, 0x25]);
    crafted.bytes[0x242..0x246].copy_from_slice(&(0x2090u32 - 0x1046).to_le_bytes());
    let binary = analyze_bytes(Path::new("thunk.exe"), crafted.bytes).unwrap();
    let (analysis, entry) = model(&binary);
    let graph = decomp::callgraph::build_with_imports(&binary, &analysis, &()).unwrap();
    assert!(graph
        .edges
        .iter()
        .any(|edge| edge.from == entry && edge.to == entry + 0x40));
    assert!(graph.edges.iter().any(|edge| edge.from == entry + 0x40
        && edge.to == crafted.slot
        && edge.kind == "importThunk"));
    assert_eq!(
        graph
            .edges
            .iter()
            .filter(|edge| edge.instruction == Some(entry + 4))
            .count(),
        1
    );
    let result =
        decomp::analyze_function(&binary, &analysis, entry, &DecompContext::new(64), &()).unwrap();
    assert!(result
        .high_level
        .lines
        .iter()
        .any(|line| line.text.starts_with("MessageBoxA(")));
}

#[test]
fn register_call_uses_the_shared_ssa_import_proof_and_exact_call_address() {
    let mut crafted = image();
    crafted.bytes[0x204..0x207].copy_from_slice(&[0x48, 0x8b, 0x05]);
    crafted.bytes[0x207..0x20b].copy_from_slice(&(0x2090u32 - 0x100b).to_le_bytes());
    crafted.bytes[0x20b..0x212].copy_from_slice(&[0xff, 0xd0, 0x48, 0x83, 0xc4, 0x28, 0xc3]);
    let binary = analyze_bytes(Path::new("register-import.exe"), crafted.bytes).unwrap();
    let (analysis, entry) = model(&binary);
    let graph = decomp::callgraph::build_with_imports(&binary, &analysis, &()).unwrap();
    assert!(graph
        .edges
        .iter()
        .any(|edge| edge.to == crafted.slot && edge.instruction == Some(entry + 11)));
    assert_eq!(graph.unresolved_indirect, 0);
}

#[test]
fn hydrate_has_precedence_for_user_hints() {
    let (binary, _, _, _) = analyze();
    let bound = imports::bindings(&binary).unwrap();
    let slot = bound[0].address.0;
    let mut hints = SignatureHints::default();
    let (notes, _) = imports::hydrate(&binary, &mut hints);
    assert_eq!(notes.len(), 1, "{notes:?}");
    let mut custom = hints.get(slot).unwrap().clone();
    custom.name = "user!".into();
    hints.insert(custom);
    let (_, hydrated) = imports::hydrate(&binary, &mut hints);
    assert_eq!(hydrated, 0);
    assert_eq!(hints.get(slot).unwrap().name, "user!");
}

#[test]
fn slot_call_resolves_the_imported_signature() {
    let (binary, analysis, entry, _) = analyze();
    let context = DecompContext::new(64);
    let result = decomp::analyze_function(&binary, &analysis, entry, &context, &()).unwrap();
    assert!(
        result.diagnostics.iter().any(
            |note| note.contains("MessageBoxA") && note.contains("hydrated from import tables")
        ),
        "{:#?}",
        result.diagnostics
    );
    let call = result
        .high_level
        .lines
        .iter()
        .find(|line| line.text.contains("MessageBoxA"))
        .map(|line| line.text.clone())
        .unwrap_or_else(|| format!("{:#?}", result.high_level.lines));
    assert!(call.starts_with("MessageBoxA("), "{call}");
    assert_eq!(result.signature.convention, CallingConvention::Win64);
    assert!(
        result
            .signature
            .parameters
            .iter()
            .all(|parameter| matches!(parameter.location, Location::Register { .. })),
        "{:#?}",
        result.signature.parameters
    );
}

#[test]
fn elf_slots_come_from_dynamic_relocations() {
    let binary = analyze_bytes(
        Path::new("ura64.elf"),
        include_bytes!("../../../tests/fixtures/ura64.elf").to_vec(),
    )
    .unwrap();
    assert!(imports::bindings(&binary).is_ok());
}

#[test]
fn wrong_library_and_unknown_library_do_not_receive_prototypes() {
    for library in [b"otherx.dll\0".as_slice(), b"user33.dll\0".as_slice()] {
        let mut crafted = image();
        crafted.bytes[0x1300..0x130b].copy_from_slice(library);
        let binary = analyze_bytes(Path::new("wrong-library.exe"), crafted.bytes).unwrap();
        assert_eq!(imports::bindings(&binary).unwrap()[0].name, "MessageBoxA");
        let mut hints = SignatureHints::default();
        assert_eq!(imports::hydrate(&binary, &mut hints).1, 0);
        assert!(hints.get(crafted.slot).is_none());
    }
}

#[test]
fn ordinal_imports_keep_their_identity_without_inventing_a_name() {
    let mut crafted = image();
    crafted.bytes[0x1278..0x1280].copy_from_slice(&(0x8000000000000000u64 | 123).to_le_bytes());
    crafted.bytes[0x1290..0x1298].copy_from_slice(&(0x8000000000000000u64 | 123).to_le_bytes());
    let binary = analyze_bytes(Path::new("ordinal.exe"), crafted.bytes).unwrap();
    let bound = imports::bindings(&binary).unwrap();
    assert_eq!(bound[0].ordinal, Some(123));
    assert_eq!(bound[0].name, "#123");
    assert_eq!(
        imports::hydrate(&binary, &mut SignatureHints::default()).1,
        0
    );
}

#[test]
fn malformed_lookup_is_reported_and_does_not_guess_a_prototype() {
    let mut crafted = image();
    crafted.bytes[0x1200..0x1204].copy_from_slice(&0x70000000u32.to_le_bytes());
    let binary = analyze_bytes(Path::new("bad-import.exe"), crafted.bytes).unwrap();
    assert!(imports::bindings(&binary).is_err());
    let (notes, count) = imports::hydrate(&binary, &mut SignatureHints::default());
    assert_eq!(count, 0);
    assert!(notes[0].contains("unavailable"));
}

#[test]
fn pe_crt_uses_windows_abi_and_original_thunk_fallback_is_supported() {
    let mut crafted = image();
    crafted.bytes[0x1200..0x1204].fill(0); // OriginalFirstThunk absent
    crafted.bytes[0x1300..0x130b].copy_from_slice(b"msvcrt.dll\0");
    crafted.bytes[0x12b2..0x12be].fill(0);
    crafted.bytes[0x12b2..0x12b9].copy_from_slice(b"memcpy\0");
    let binary = analyze_bytes(Path::new("crt.exe"), crafted.bytes).unwrap();
    let mut hints = SignatureHints::default();
    assert_eq!(imports::hydrate(&binary, &mut hints).1, 1);
    assert_eq!(
        hints.get(crafted.slot).unwrap().convention,
        CallingConvention::Win64
    );
}

#[test]
fn cancellation_is_checked_before_parsing_imports() {
    struct Cancel;
    impl ura_core::AnalysisControl for Cancel {
        fn is_cancelled(&self) -> bool {
            true
        }
        fn report(&self, _: ura_core::AnalysisProgress) {}
    }
    let (binary, _, _, _) = analyze();
    assert!(imports::analyze_with_control(&binary, &Cancel)
        .unwrap_err()
        .contains("cancelled"));
}

#[test]
fn pe32_slots_and_stdcall_prototypes_use_target_width() {
    let mut crafted = image();
    let optional = 0x98;
    crafted
        .bytes
        .copy_within(optional + 240..optional + 280, optional + 224);
    crafted.bytes[0x84..0x86].copy_from_slice(&0x14cu16.to_le_bytes());
    crafted.bytes[0x94..0x96].copy_from_slice(&224u16.to_le_bytes());
    crafted.bytes[optional..optional + 2].copy_from_slice(&0x10bu16.to_le_bytes());
    crafted.bytes[optional + 24..optional + 28].copy_from_slice(&0x1000u32.to_le_bytes());
    crafted.bytes[optional + 28..optional + 32].copy_from_slice(&0x400000u32.to_le_bytes());
    crafted.bytes[optional + 96..optional + 112].fill(0);
    crafted.bytes[optional + 92..optional + 96].copy_from_slice(&16u32.to_le_bytes());
    crafted.bytes[optional + 104..optional + 108].copy_from_slice(&0x2000u32.to_le_bytes());
    crafted.bytes[optional + 108..optional + 112].copy_from_slice(&40u32.to_le_bytes());
    let binary = analyze_bytes(Path::new("imports32.exe"), crafted.bytes).unwrap();
    let bound = imports::bindings(&binary).unwrap();
    assert_eq!(bound[0].address.0, 0x402090);
    let mut hints = SignatureHints::default();
    assert_eq!(imports::hydrate(&binary, &mut hints).1, 1);
    let signature = hints.get(0x402090).unwrap();
    assert_eq!(signature.convention, CallingConvention::Stdcall);
    assert_eq!(signature.parameters[0].width, 32);
    assert!(matches!(
        signature.parameters[0].location,
        Location::Stack { offset: 4, .. }
    ));
}

#[test]
fn duplicate_iat_slot_with_conflicting_identity_is_rejected() {
    let mut crafted = image();
    crafted.bytes.copy_within(0x1200..0x1214, 0x1214);
    // Second descriptor has the same IAT but a different library.
    crafted.bytes[0x1220..0x1224].copy_from_slice(&0x2120u32.to_le_bytes());
    crafted.bytes[0x1320..0x132b].copy_from_slice(b"otherx.dll\0");
    let binary = analyze_bytes(Path::new("ambiguous.exe"), crafted.bytes).unwrap();
    assert!(imports::bindings(&binary)
        .unwrap_err()
        .contains("ambiguous"));
}

#[test]
fn undecodable_import_names_mark_the_report_incomplete_and_cannot_bind_a_prototype() {
    let mut crafted = image();
    crafted.bytes[0x12b2] = 0xff;
    let binary = analyze_bytes(Path::new("invalid-name.exe"), crafted.bytes).unwrap();
    let report = imports::analyze_with_control(&binary, &()).unwrap();
    assert!(report.truncated);
    assert!(report.bindings.is_empty());
    assert!(imports::bindings(&binary).is_err());
    let (notes, count) = imports::hydrate(&binary, &mut SignatureHints::default());
    assert_eq!(count, 0);
    assert!(notes.iter().any(|note| note.contains("incomplete")));
}

/// Independent ELF64 byte layout: defined dynsym #1 must be ignored;
/// undefined `puts` is dynsym #2. This catches enumeration-index mistakes.
fn dynamic_elf(relocation_type: u32) -> LoadedBinary {
    fn u16_at(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn u32_at(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn u64_at(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    let mut bytes = vec![0u8; 0x800];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    u16_at(&mut bytes, 16, 2);
    u16_at(&mut bytes, 18, 62);
    u32_at(&mut bytes, 20, 1);
    u64_at(&mut bytes, 24, 0x401000);
    u64_at(&mut bytes, 32, 64);
    u64_at(&mut bytes, 40, 0x400);
    u16_at(&mut bytes, 52, 64);
    u16_at(&mut bytes, 54, 56);
    u16_at(&mut bytes, 56, 1);
    u16_at(&mut bytes, 58, 64);
    u16_at(&mut bytes, 60, 6);
    u16_at(&mut bytes, 62, 5);
    u32_at(&mut bytes, 64, 1);
    u32_at(&mut bytes, 68, 5);
    u64_at(&mut bytes, 80, 0x400000);
    u64_at(&mut bytes, 96, 0x800);
    u64_at(&mut bytes, 104, 0x800);
    u64_at(&mut bytes, 112, 0x1000);
    bytes[0x100] = 0xc3;
    bytes[0x200..0x20c].copy_from_slice(b"\0local\0puts\0");
    u32_at(&mut bytes, 0x258, 1); // symbol #1, defined in .text
    bytes[0x25c] = 0x12;
    u16_at(&mut bytes, 0x25e, 1);
    u64_at(&mut bytes, 0x260, 0x401000);
    u32_at(&mut bytes, 0x270, 7); // symbol #2, undefined
    bytes[0x274] = 0x12;
    u64_at(&mut bytes, 0x300, 0x403000);
    u64_at(&mut bytes, 0x308, (2u64 << 32) | u64::from(relocation_type));
    u64_at(&mut bytes, 0x318, 0x403008);
    u64_at(&mut bytes, 0x320, (1u64 << 32) | u64::from(relocation_type));
    let names = b"\0.text\0.dynstr\0.dynsym\0.rela.plt\0.shstrtab\0";
    bytes[0x380..0x380 + names.len()].copy_from_slice(names);
    for (index, (name, kind, address, offset, size, link, entry)) in [
        (1, 1, 0x401000, 0x100, 64, 0, 0),
        (7, 3, 0x402000, 0x200, 12, 0, 0),
        (15, 11, 0x402100, 0x240, 72, 2, 24),
        (23, 4, 0x402200, 0x300, 48, 3, 24),
        (33, 3, 0, 0x380, names.len() as u64, 0, 0),
    ]
    .into_iter()
    .enumerate()
    {
        let header = 0x440 + index * 64;
        u32_at(&mut bytes, header, name);
        u32_at(&mut bytes, header + 4, kind);
        u64_at(&mut bytes, header + 8, if index == 0 { 6 } else { 2 });
        u64_at(&mut bytes, header + 16, address);
        u64_at(&mut bytes, header + 24, offset);
        u64_at(&mut bytes, header + 32, size);
        u32_at(&mut bytes, header + 40, link);
        u64_at(&mut bytes, header + 48, 8);
        u64_at(&mut bytes, header + 56, entry);
    }
    analyze_bytes(Path::new("imports.elf"), bytes).unwrap()
}

#[test]
fn elf_undefined_symbol_slots_use_actual_indices_and_do_not_guess_library_ownership() {
    let binary = dynamic_elf(7);
    let bound = imports::bindings(&binary).unwrap();
    assert_eq!(bound.len(), 1);
    assert_eq!(bound[0].address.0, 0x403000);
    assert_eq!(bound[0].name, "puts");
    assert_eq!(bound[0].library, None);
    assert_eq!(
        imports::hydrate(&binary, &mut SignatureHints::default()).1,
        0
    );
    assert!(imports::bindings(&dynamic_elf(1026)).unwrap().is_empty());
}

#[test]
fn elf_got_call_is_an_external_identity_without_an_unproved_libc_signature() {
    let mut bytes = dynamic_elf(7).bytes().to_vec();
    bytes[0x100..0x107].copy_from_slice(&[0xff, 0x15, 0xfa, 0x1f, 0, 0, 0xc3]);
    let binary = analyze_bytes(Path::new("got-call.elf"), bytes).unwrap();
    let (analysis, entry) = model(&binary);
    let graph = decomp::callgraph::build_with_imports(&binary, &analysis, &()).unwrap();
    let node = graph.node(0x403000).unwrap();
    let imported = node.import.as_ref().unwrap();
    assert!(node.external);
    assert_eq!(imported.binding.name, "puts");
    assert!(imported.signature.is_none());
    assert!(graph
        .edges
        .iter()
        .any(|edge| edge.from == entry && edge.instruction == Some(entry) && edge.to == 0x403000));
    assert_eq!(graph.unresolved_indirect, 0);
}
