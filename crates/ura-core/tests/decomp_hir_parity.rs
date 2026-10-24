//! Rendered high-level IR is locked byte-for-byte against snapshot files
//! before the typed-HIR refactor. Any change to the emitted structure or the
//! text renderer must either reproduce these snapshots exactly or update them
//! deliberately with a documented reason.
use std::path::Path;

use ura_core::binary::analyze_bytes;
use ura_core::decomp::signature::{
    CallingConvention, Location, SignatureOverride, SignatureParameterInput,
};
use ura_core::decomp::{self, types::TypeRef, DecompContext};
use ura_core::{analyze_functions, AnalysisOptions, LoadedBinary, ProgramAnalysis};

fn image(code: &[u8], bits: u8, elf: bool) -> (LoadedBinary, ProgramAnalysis, u64) {
    let (name, mut bytes) = if bits == 32 {
        let mut bytes = vec![0u8; 1024];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x14cu16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&224u16.to_le_bytes());
        bytes[0x96..0x98].copy_from_slice(&0x102u16.to_le_bytes());
        let optional = 0x98;
        bytes[optional..optional + 2].copy_from_slice(&0x10bu16.to_le_bytes());
        bytes[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 28..optional + 32].copy_from_slice(&0x400000u32.to_le_bytes());
        bytes[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
        let section = optional + 224;
        bytes[section..section + 5].copy_from_slice(b".text");
        bytes[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&0x60000020u32.to_le_bytes());
        ("parity32.exe", bytes)
    } else if elf {
        (
            "parity64.elf",
            include_bytes!("../../../tests/fixtures/ura64.elf").to_vec(),
        )
    } else {
        (
            "parity64.exe",
            include_bytes!("../../../tests/fixtures/ura64.exe").to_vec(),
        )
    };
    let original = analyze_bytes(Path::new(name), bytes.clone()).unwrap();
    let entry = original.analysis().entry_point.unwrap();
    let section = original
        .analysis()
        .section_containing_address(entry)
        .unwrap();
    let offset = section.file_offset_for_address(entry).unwrap() as usize;
    let available = (section.file_size - (entry - section.address)) as usize;
    assert!(code.len() <= available);
    bytes[offset..offset + available].fill(0xcc);
    bytes[offset..offset + code.len()].copy_from_slice(code);
    let binary = analyze_bytes(Path::new(name), bytes).unwrap();
    let analysis = analyze_functions(
        &binary,
        &AnalysisOptions {
            seed_symbols: false,
            ..Default::default()
        },
        &(),
    );
    (binary, analysis, entry)
}

const STRAIGHT_LINE: &[u8] = &[
    0x48, 0x89, 0xc8, 0x48, 0x01, 0xd0, 0x48, 0x83, 0xe8, 0x08, 0x48, 0xf7, 0xd0, 0xc3,
];
const LOGIC_SHIFT: &[u8] = &[
    0x09, 0xca, 0x21, 0xd0, 0x31, 0xc0, 0xc1, 0xe0, 0x03, 0xc1, 0xe8, 0x01, 0xc3,
];
const IF_TWO_RETS: &[u8] = &[
    0x85, 0xc0, 0x74, 0x06, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3,
];
const IF_ELSE_JOIN: &[u8] = &[
    0x85, 0xc9, 0x75, 0x04, 0x89, 0xc8, 0xeb, 0x02, 0x89, 0xd0, 0x8b, 0xc0, 0xc3,
];
const WHILE_LOOP_CODE: &[u8] = &[0xb1, 0x03, 0x48, 0x83, 0xe9, 0x01, 0x75, 0xfb, 0xc3];
const MULTI_EXIT_LOOP_CODE: &[u8] = &[
    0xb1, 0x03, 0x85, 0xc9, 0x74, 0x05, 0x48, 0xff, 0xc9, 0x75, 0xf7, 0xf6, 0xc1, 0x04, 0x75, 0x08,
    0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3,
];
const CALL_DIRECT_CODE: &[u8] = &[0xe8, 0x04, 0x00, 0x00, 0x00, 0xc3, 0x90, 0x90, 0x90, 0xc3];
const CALL_INDIRECT_CODE: &[u8] = &[0xff, 0xd0, 0xc3];
const JMP_INDIRECT_CODE: &[u8] = &[0xff, 0xe0, 0xc3];
const MEMORY_OPS_CODE: &[u8] = &[0x48, 0x8b, 0x04, 0x31, 0x48, 0x89, 0x02, 0xc3];
const SIGN_EXTEND_CODE: &[u8] = &[0x48, 0x0f, 0xbe, 0xc1, 0xc3];
const ZEROING_CODE: &[u8] = &[0x31, 0xc9, 0x31, 0xc0, 0xc3];
const X86_32_FRAME: &[u8] = &[
    0x55, 0x89, 0xe5, 0x83, 0xec, 16, 0x8b, 0x45, 8, 0x89, 0x04, 0x24, 0xc9, 0xc3,
];
const VARIADIC_CALL_CODE: &[u8] = &[0xe8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0xc3];
const FLOAT_RETURN_CODE: &[u8] = &[0x31, 0xc0, 0xc3];

fn resolved_hint(context: &mut DecompContext, entry: u64) {
    context.hints.insert(decomp::signature::describe_override(
        entry + 9,
        "callee_fn",
        &SignatureOverride {
            convention: CallingConvention::Win64,
            return_type: TypeRef::Void,
            parameters: vec![SignatureParameterInput {
                name: "value".into(),
                location: Location::Register { name: "rcx".into() },
                ty: TypeRef::uint(64),
            }],
            variadic: Some(false),
        },
    ));
}

fn variadic_hint(context: &mut DecompContext, entry: u64) {
    context.hints.insert(decomp::signature::describe_override(
        entry + 6,
        "variadic_callee",
        &SignatureOverride {
            convention: CallingConvention::Win64,
            return_type: TypeRef::Void,
            parameters: vec![
                SignatureParameterInput {
                    name: "stack_value".into(),
                    location: Location::Stack {
                        offset: 0x28,
                        width: 64,
                    },
                    ty: TypeRef::uint(64),
                },
                SignatureParameterInput {
                    name: "unknown_location".into(),
                    location: Location::Unknown {
                        reason: "unresolved ABI location".into(),
                    },
                    ty: TypeRef::uint(64),
                },
            ],
            variadic: Some(true),
        },
    ));
}

fn float_return(context: &mut DecompContext, _entry: u64) {
    context.override_signature = Some(SignatureOverride {
        convention: CallingConvention::Win64,
        return_type: TypeRef::Float { bits: 64 },
        parameters: vec![],
        variadic: None,
    });
}

fn parity(
    code: &[u8],
    bits: u8,
    elf: bool,
    decorate: Option<fn(&mut DecompContext, u64)>,
) -> ura_core::decomp::FunctionDecompilation {
    let (binary, analysis, entry) = image(code, bits, elf);
    let mut context = DecompContext::new(if bits == 32 { 32 } else { 64 });
    if let Some(decorate) = decorate {
        decorate(&mut context, entry);
    }
    decomp::analyze_function(&binary, &analysis, entry, &context, &()).unwrap()
}

fn assert_parity(
    name: &str,
    code: &[u8],
    bits: u8,
    elf: bool,
    decorate: Option<fn(&mut DecompContext, u64)>,
) {
    let decompilation = parity(code, bits, elf, decorate);
    let function = decompilation.high_level;
    let serialized = serde_json::to_string(&function).unwrap();
    let expected = match name {
        "straight_line_arithmetic" => {
            include_str!("fixtures/hir_parity/straight_line_arithmetic.json")
        }
        "logic_shift_compare" => include_str!("fixtures/hir_parity/logic_shift_compare.json"),
        "if_branch_two_rets" => include_str!("fixtures/hir_parity/if_branch_two_rets.json"),
        "if_else_join_phi" => include_str!("fixtures/hir_parity/if_else_join_phi.json"),
        "while_loop_back_edge" => include_str!("fixtures/hir_parity/while_loop_back_edge.json"),
        "multi_exit_loop" => include_str!("fixtures/hir_parity/multi_exit_loop.json"),
        "call_direct_unresolved" => include_str!("fixtures/hir_parity/call_direct_unresolved.json"),
        "call_direct_resolved_hint" => {
            include_str!("fixtures/hir_parity/call_direct_resolved_hint.json")
        }
        "call_indirect" => include_str!("fixtures/hir_parity/call_indirect.json"),
        "jmp_indirect" => include_str!("fixtures/hir_parity/jmp_indirect.json"),
        "memory_ops" => include_str!("fixtures/hir_parity/memory_ops.json"),
        "sign_extend" => include_str!("fixtures/hir_parity/sign_extend.json"),
        "zeroing_body" => include_str!("fixtures/hir_parity/zeroing_body.json"),
        "x86_32_frame_pointer" => include_str!("fixtures/hir_parity/x86_32_frame_pointer.json"),
        "variadic_stack_call" => include_str!("fixtures/hir_parity/variadic_stack_call.json"),
        "float_return_override" => include_str!("fixtures/hir_parity/float_return_override.json"),
        other => panic!("unknown parity fixture {other}"),
    };
    let expected = expected.trim_end();
    if serialized != expected {
        let folder = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/hir-parity-diff");
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(
            folder.join(format!("{name}.json")),
            format!("{serialized}\n"),
        )
        .unwrap();
    }
    assert!(
        serialized == expected,
        "fixture {name} diverged from the locked high-level IR snapshot"
    );
    // The legacy renderer contract: two-space indent and trailing newline.
    let text = function.text();
    assert!(text.ends_with("}\n") == (function.lines.len() > 1));
    assert!(text.contains("recovered high-level IR"));
}

#[test]
fn straight_line_arithmetic_output_matches_snapshot() {
    // v0.15 deliberately replaces the historical NOT barrier with its verified
    // fixed-width complement. Flag-preservation truth tables and the independent
    // compiler/Unicorn corpus cover this newly supported instruction.
    assert_parity("straight_line_arithmetic", STRAIGHT_LINE, 64, false, None);
}

#[test]
fn logic_shift_compare_output_matches_snapshot() {
    assert_parity("logic_shift_compare", LOGIC_SHIFT, 64, false, None);
}

#[test]
fn if_branch_two_rets_output_matches_snapshot() {
    assert_parity("if_branch_two_rets", IF_TWO_RETS, 64, false, None);
}

#[test]
fn if_else_join_phi_output_matches_snapshot() {
    assert_parity("if_else_join_phi", IF_ELSE_JOIN, 64, false, None);
}

#[test]
fn while_loop_back_edge_output_matches_snapshot() {
    assert_parity("while_loop_back_edge", WHILE_LOOP_CODE, 64, false, None);
}

#[test]
fn multi_exit_loop_output_matches_snapshot() {
    assert_parity("multi_exit_loop", MULTI_EXIT_LOOP_CODE, 64, false, None);
}

#[test]
fn call_direct_unresolved_output_matches_snapshot() {
    assert_parity("call_direct_unresolved", CALL_DIRECT_CODE, 64, false, None);
}

#[test]
fn call_direct_resolved_hint_output_matches_snapshot() {
    assert_parity(
        "call_direct_resolved_hint",
        CALL_DIRECT_CODE,
        64,
        false,
        Some(resolved_hint),
    );
}

#[test]
fn call_indirect_output_matches_snapshot() {
    assert_parity("call_indirect", CALL_INDIRECT_CODE, 64, false, None);
}

#[test]
fn jmp_indirect_output_matches_snapshot() {
    assert_parity("jmp_indirect", JMP_INDIRECT_CODE, 64, false, None);
}

#[test]
fn memory_ops_output_matches_snapshot() {
    assert_parity("memory_ops", MEMORY_OPS_CODE, 64, false, None);
}

#[test]
fn sign_extend_output_matches_snapshot() {
    assert_parity("sign_extend", SIGN_EXTEND_CODE, 64, false, None);
}

#[test]
fn zeroing_body_output_matches_snapshot() {
    assert_parity("zeroing_body", ZEROING_CODE, 64, false, None);
}

#[test]
fn x86_32_frame_pointer_output_matches_snapshot() {
    assert_parity("x86_32_frame_pointer", X86_32_FRAME, 32, false, None);
}

#[test]
fn variadic_stack_call_output_matches_snapshot() {
    assert_parity(
        "variadic_stack_call",
        VARIADIC_CALL_CODE,
        64,
        false,
        Some(variadic_hint),
    );
}

#[test]
fn float_return_override_output_matches_snapshot() {
    assert_parity(
        "float_return_override",
        FLOAT_RETURN_CODE,
        64,
        false,
        Some(float_return),
    );
}

#[test]
fn parity_entry_addresses_are_reported() {
    let decompilation = parity(STRAIGHT_LINE, 64, false, None);
    assert_eq!(decompilation.high_level.function, decompilation.function);
    assert_eq!(
        decompilation.high_level.lines[1].address,
        Some(decompilation.function)
    );
}
