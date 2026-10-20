use std::path::{Path, PathBuf};
use ura_core::disasm::InstructionDecoder;
use ura_core::{analyze_path, parse_address, CpuArchitecture, StringScanOptions, X86Decoder};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[test]
fn recognizes_pe_and_maps_addresses() {
    let binary = analyze_path(&fixture("ura64.exe")).expect("fixture should parse");
    let analysis = binary.analysis();
    assert_eq!(analysis.format, "PE");
    assert_eq!(analysis.architecture, CpuArchitecture::X86_64);
    assert_eq!(analysis.bitness, 64);
    assert_eq!(analysis.image_base, 0x140000000);
    assert_eq!(analysis.entry_point, Some(0x140001000));

    let text = analysis
        .sections
        .iter()
        .find(|section| section.name == ".text")
        .expect("text section");
    assert!(text.executable);
    assert_eq!(text.address, 0x140001000);
    assert_eq!(text.file_offset, Some(0x200));
    assert_eq!(analysis.address_to_file_offset(0x140001000), Some(0x200));
    assert_eq!(analysis.file_offset_to_address(0x200), Some(0x140001000));
    assert_eq!(analysis.address_to_rva(0x140001000), Some(0x1000));

    let rdata = analysis
        .sections
        .iter()
        .find(|section| section.name == ".rdata")
        .expect("rdata section");
    assert!(!rdata.executable);
    assert_eq!(analysis.file_offset_to_address(0x400), Some(0x140002000));
}

#[test]
fn recognizes_elf_and_maps_addresses() {
    let binary = analyze_path(&fixture("ura64.elf")).expect("fixture should parse");
    let analysis = binary.analysis();
    assert_eq!(analysis.format, "ELF");
    assert_eq!(analysis.architecture, CpuArchitecture::X86_64);
    assert_eq!(analysis.bitness, 64);
    assert_eq!(analysis.image_base, 0x400000);
    assert_eq!(analysis.entry_point, Some(0x401000));
    assert_eq!(analysis.address_to_file_offset(0x401000), Some(0x1000));
    assert_eq!(analysis.file_offset_to_address(0x2000), Some(0x402000));
}

#[test]
fn decodes_real_x86_64_instructions() {
    let binary = analyze_path(&fixture("ura64.exe")).unwrap();
    let entry = binary.analysis().entry_point.unwrap();
    let page = binary.disassemble(entry, 20).unwrap();
    assert_eq!(page.start_address, "0x140001000");
    let first = &page.instructions[0];
    assert_eq!(first.mnemonic, "push");
    assert_eq!(first.text, "push rbp");
    assert_eq!(first.bytes, "55");
    assert_eq!(first.length, 1);
    assert_eq!(first.file_offset.as_deref(), Some("0x200"));
    assert_eq!(page.instructions[1].mnemonic, "mov");
    let call = page
        .instructions
        .iter()
        .find(|instruction| instruction.flow == "call")
        .expect("call instruction");
    assert_eq!(call.target.as_deref(), Some("0x14000100E"));
    assert!(page.has_more);
}

#[test]
fn returns_invalid_instructions_without_panicking() {
    let batch = X86Decoder
        .decode(&[0x06, 0x90, 0xC3], 0x1000, 64, None, 3)
        .unwrap();
    assert!(batch.instructions.len() >= 2);
    assert!(batch.instructions[0].invalid);
    assert_eq!(batch.instructions.last().unwrap().mnemonic, "ret");
}

#[test]
fn extracts_ascii_and_utf16_strings_with_mappings() {
    let binary = analyze_path(&fixture("ura64.exe")).unwrap();
    let result = binary
        .extract_strings(&StringScanOptions::default())
        .unwrap();
    assert!(!result.truncated);
    let ascii = result
        .strings
        .iter()
        .find(|entry| entry.encoding == "ASCII" && entry.value == "URA fixture string")
        .expect("ascii string");
    assert_eq!(ascii.offset, "0x400");
    assert_eq!(ascii.address.as_deref(), Some("0x140002000"));
    assert_eq!(ascii.section.as_deref(), Some(".rdata"));
    let wide = result
        .strings
        .iter()
        .find(|entry| entry.encoding == "UTF-16LE" && entry.value == "Wide URA")
        .expect("wide string");
    assert_eq!(wide.offset, "0x460");
}

#[test]
fn reads_hex_pages_with_virtual_addresses() {
    let binary = analyze_path(&fixture("ura64.exe")).unwrap();
    let page = binary.read_hex(0x200, 16).unwrap();
    assert_eq!(page.data.len(), 16);
    assert_eq!(page.data[0], 0x55);
    assert_eq!(page.address.as_deref(), Some("0x140001000"));
    assert_eq!(page.section.as_deref(), Some(".text"));
    assert!(binary.read_hex(0x5000, 16).is_err());
}

#[test]
fn rejects_corrupt_and_truncated_files() {
    let empty = analyze_path(Path::new("missing-file")).is_err();
    assert!(empty);
    let truncated = &std::fs::read(fixture("ura64.exe")).unwrap()[..0x90];
    let err = ura_core::binary::analyze_bytes(Path::new("truncated.exe"), truncated.to_vec());
    assert!(err.is_err());
    let junk = vec![0xDE, 0xAD, 0xBE, 0xEF];
    assert!(ura_core::binary::analyze_bytes(Path::new("junk.bin"), junk).is_err());
}

#[test]
fn parses_hex_addresses() {
    assert_eq!(parse_address("0x140001000").unwrap(), 0x140001000);
    assert_eq!(parse_address("140001000").unwrap(), 0x140001000);
    assert_eq!(parse_address("0x0040_1000").unwrap(), 0x401000);
    assert!(parse_address("").is_err());
    assert!(parse_address("xyz").is_err());
}
