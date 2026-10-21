//! Semantic regressions found by the independent v0.8 review. All samples are
//! in-memory linked images assembled from original byte sequences; none run.
use std::path::Path;

use ura_core::binary::analyze_bytes;
use ura_core::decomp::{self, stack, types::TypeRef, CallingConvention, DecompContext};
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
        ("review32.exe", bytes)
    } else if elf {
        (
            "review64.elf",
            include_bytes!("../../../tests/fixtures/ura64.elf").to_vec(),
        )
    } else {
        (
            "review64.exe",
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

fn frame(code: &[u8], bits: u8) -> stack::StackFrame {
    let (binary, analysis, entry) = image(code, bits, false);
    stack::recover(&binary, &analysis, entry, None).unwrap()
}

#[test]
fn stack_changing_back_edge_converges_to_unknown() {
    let result = frame(&[0x48, 0x83, 0xec, 8, 0xeb, 0xfa], 64);
    assert!(result.slots.is_empty());
}

#[test]
fn stack_join_disagreement_is_not_a_proven_slot() {
    let result = frame(
        &[
            0x85, 0xc0, 0x74, 6, 0x48, 0x83, 0xec, 8, 0xeb, 4, 0x48, 0x83, 0xec, 16, 0x48, 0x8b, 4,
            0x24, 0xc3,
        ],
        64,
    );
    assert!(result.slots.is_empty());
    assert!(result.unknown_access_candidates > 0);
}

#[test]
fn frame_pointer_is_local_to_each_control_flow_path() {
    let result = frame(
        &[
            0x85, 0xc0, 0x74, 5, 0x48, 0x89, 0xe5, 0xeb, 4, 0x48, 0x31, 0xed, 0x90, 0x48, 0x8b,
            0x45, 0, 0xc3,
        ],
        64,
    );
    assert!(
        result.slots.iter().all(|slot| slot.kind == "returnAddress"),
        "{result:#?}"
    );
    assert!(result.unknown_access_candidates > 0);
}

#[test]
fn overwritten_frame_and_stack_registers_invalidate_offsets() {
    for code in [
        &[0x48, 0x89, 0xe5, 0x31, 0xed, 0x8b, 0x45, 0xfc, 0xc3][..],
        &[0x48, 0x89, 0xc4, 0x48, 0x8b, 0x44, 0x24, 8, 0xc3][..],
        &[0x5c, 0x48, 0x8b, 0x44, 0x24, 8, 0xc3][..],
    ] {
        let result = frame(code, 64);
        assert!(
            result.slots.iter().all(|slot| slot.kind == "returnAddress"
                || slot.accesses.iter().all(|access| access.mnemonic == "pop")),
            "{result:#?}"
        );
        assert!(result.unknown_access_candidates > 0);
    }
}

#[test]
fn indexed_segmented_and_narrow_addresses_are_not_fixed_stack_slots() {
    for code in [
        &[0x48, 0x8b, 0x44, 0xc4, 8, 0xc3][..],
        &[0x64, 0x48, 0x8b, 0x44, 0x24, 8, 0xc3][..],
        &[0x67, 0x48, 0x8b, 0x44, 0x24, 8, 0xc3][..],
    ] {
        let result = frame(code, 64);
        assert!(
            result.slots.iter().all(|slot| slot.kind == "returnAddress"),
            "{result:#?}"
        );
        assert!(result.unknown_access_candidates > 0);
    }
}

#[test]
fn x86_frame_pointer_and_negative_displacements_use_x86_registers() {
    let result = frame(
        &[
            0x55, 0x89, 0xe5, 0x83, 0xec, 16, 0x8b, 0x45, 8, 0x89, 4, 0x24, 0xc9, 0xc3,
        ],
        32,
    );
    assert_eq!(result.frame_size, 20);
    assert_eq!(result.local_bytes, 20);
    assert!(result
        .slots
        .iter()
        .any(|slot| slot.offset == 4 && slot.reads == 1));
    assert!(result
        .slots
        .iter()
        .any(|slot| slot.offset == -20 && slot.writes == 1));
    assert!(result.slots.iter().any(|slot| slot.offset == -4));
    assert!(result.uses_frame_pointer);
}

#[test]
fn frame_size_includes_allocation_without_accesses() {
    let result = frame(&[0x48, 0x83, 0xec, 32, 0x48, 0x83, 0xc4, 32, 0xc3], 64);
    assert_eq!(result.frame_size, 32);
    assert_eq!(result.local_bytes, 0);
    assert_eq!(result.alignment, 1);
}

#[test]
fn stack_widths_do_not_imply_pointer_types_or_shadow_arguments() {
    let (binary, analysis, entry) = image(
        &[
            0x48, 0x8b, 0x44, 0x24, 8, 0x48, 0x03, 0x44, 0x24, 0x28, 0xc3,
        ],
        64,
        false,
    );
    let result =
        decomp::analyze_function(&binary, &analysis, entry, &DecompContext::new(64), &()).unwrap();
    assert!(result
        .frame
        .slots
        .iter()
        .any(|slot| slot.offset == 8 && slot.kind == "shadowSpace"));
    let slot = result
        .frame
        .slots
        .iter()
        .find(|slot| slot.offset == 0x28)
        .unwrap();
    assert!(matches!(slot.ty, TypeRef::Int { .. }));
    assert!(result
        .signature
        .parameters
        .iter()
        .all(|parameter| !matches!(
            &parameter.location,
            decomp::Location::Stack { offset: 8, .. }
        )));
}

#[test]
fn sysv_common_registers_do_not_select_the_windows_abi() {
    let (binary, analysis, entry) = image(&[0x89, 0xc8, 0xc3], 64, true);
    let result =
        decomp::analyze_function(&binary, &analysis, entry, &DecompContext::new(64), &()).unwrap();
    assert_eq!(result.signature.convention, CallingConvention::SysV64);
    assert_eq!(
        result
            .signature
            .parameters
            .iter()
            .find(|p| p.uses > 0)
            .unwrap()
            .index,
        3
    );
}

#[test]
fn zero_comparison_is_not_pointer_evidence_and_untouched_return_is_unknown() {
    let (binary, analysis, entry) = image(&[0x85, 0xc9, 0xc3], 64, false);
    let result =
        decomp::analyze_function(&binary, &analysis, entry, &DecompContext::new(64), &()).unwrap();
    assert!(matches!(
        result.signature.parameters[0].ty,
        TypeRef::Int { .. }
    ));
    assert!(matches!(
        result.signature.return_value.ty,
        TypeRef::Unknown { .. }
    ));
}

#[test]
fn zeroing_argument_register_does_not_read_a_parameter() {
    let (binary, analysis, entry) = image(&[0x31, 0xc9, 0x31, 0xc0, 0xc3], 64, false);
    let result =
        decomp::analyze_function(&binary, &analysis, entry, &DecompContext::new(64), &()).unwrap();
    assert!(
        result.signature.parameters.is_empty(),
        "{:#?}",
        result.signature
    );
    assert!(matches!(
        result.signature.return_value.ty,
        TypeRef::Int { .. }
    ));
}

#[test]
fn copied_call_effect_is_not_a_proven_integer_return() {
    // CALL local RET; preserve the untracked RAX through RBX and a second copy.
    let (binary, analysis, entry) = image(
        &[
            0xe8, 8, 0, 0, 0, 0x48, 0x89, 0xc3, 0x48, 0x89, 0xd8, 0xc3, 0x90, 0xc3,
        ],
        64,
        false,
    );
    let result =
        decomp::analyze_function(&binary, &analysis, entry, &DecompContext::new(64), &()).unwrap();
    assert!(matches!(
        result.signature.return_value.ty,
        TypeRef::Unknown { .. }
    ));
}

#[test]
fn cancelled_stack_pass_exits_before_work() {
    struct Cancel;
    impl ura_core::AnalysisControl for Cancel {
        fn is_cancelled(&self) -> bool {
            true
        }
        fn report(&self, _: ura_core::AnalysisProgress) {}
    }
    let (binary, analysis, entry) = image(&[0xc3], 64, false);
    assert!(
        stack::recover_with_control(&binary, &analysis, entry, None, &Cancel)
            .unwrap_err()
            .contains("cancelled")
    );
}

#[test]
fn sysv_first_argument_has_positive_entry_value_evidence() {
    let (binary, analysis, entry) = image(&[0x48, 0x89, 0xf8, 0xc3], 64, true);
    let result =
        decomp::analyze_function(&binary, &analysis, entry, &DecompContext::new(64), &()).unwrap();
    assert_eq!(result.signature.convention, CallingConvention::SysV64);
    assert_eq!(result.signature.parameters.len(), 1);
    assert_eq!(
        result.signature.parameters[0].location,
        decomp::Location::Register { name: "rdi".into() }
    );
    assert!(result.signature.parameters[0].uses > 0);
}

#[test]
fn preserving_windows_nonvolatile_registers_does_not_invent_sysv_arguments() {
    let (binary, analysis, entry) = image(&[0x57, 0x56, 0x5e, 0x5f, 0xc3], 64, false);
    let result =
        decomp::analyze_function(&binary, &analysis, entry, &DecompContext::new(64), &()).unwrap();
    assert_eq!(result.signature.convention, CallingConvention::Win64);
    assert!(result.signature.parameters.is_empty());
    assert_eq!(result.frame.saved_registers, vec!["rdi", "rsi"]);
}

#[test]
fn writing_a_nonvolatile_register_before_storing_it_is_not_an_entry_save() {
    let (binary, analysis, entry) = image(&[0x31, 0xdb, 0x53, 0x5b, 0xc3], 64, false);
    let result =
        decomp::analyze_function(&binary, &analysis, entry, &DecompContext::new(64), &()).unwrap();
    assert!(result.frame.saved_registers.is_empty());
    assert!(result
        .frame
        .slots
        .iter()
        .all(|slot| slot.kind != "savedRegister"));
}

#[test]
fn repeated_direct_calls_keep_each_source_address() {
    let (binary, analysis, entry) = image(
        &[0xe8, 7, 0, 0, 0, 0xe8, 2, 0, 0, 0, 0xc3, 0x90, 0xc3],
        64,
        false,
    );
    let _ = binary;
    let graph = decomp::build_call_graph(&analysis);
    let sites = graph
        .edges
        .iter()
        .filter(|edge| edge.from == entry && edge.to == entry + 12)
        .map(|edge| edge.instruction.unwrap())
        .collect::<Vec<_>>();
    assert_eq!(sites, vec![entry, entry + 5]);
    assert_eq!(graph.node(entry).unwrap().callees, 1);
    assert_eq!(graph.node(entry + 12).unwrap().callers, 1);
}

#[test]
fn dynamic_address_indexes_do_not_turn_every_argument_into_a_pointer() {
    let (binary, analysis, entry) = image(&[0x48, 0x8b, 0x04, 0x91, 0xc3], 64, false);
    let result =
        decomp::analyze_function(&binary, &analysis, entry, &DecompContext::new(64), &()).unwrap();
    assert_eq!(result.signature.parameters.len(), 2);
    assert!(result
        .signature
        .parameters
        .iter()
        .all(|parameter| matches!(parameter.ty, TypeRef::Int { .. })));
    let (binary, analysis, entry) = image(&[0x48, 0x8b, 0x01, 0xc3], 64, false);
    let result =
        decomp::analyze_function(&binary, &analysis, entry, &DecompContext::new(64), &()).unwrap();
    assert!(matches!(
        result.signature.parameters[0].ty,
        TypeRef::Pointer { .. }
    ));
}

#[test]
fn stack_writes_do_not_read_an_incoming_argument() {
    let (binary, analysis, entry) = image(&[0x89, 0x44, 0x24, 0x28, 0xc3], 64, false);
    let result =
        decomp::analyze_function(&binary, &analysis, entry, &DecompContext::new(64), &()).unwrap();
    assert!(result.signature.parameters.is_empty());
}

#[test]
fn mixed_defined_and_untouched_return_paths_keep_unknown_type() {
    let (binary, analysis, entry) = image(
        &[0x85, 0xc9, 0x74, 1, 0xc3, 0xb8, 1, 0, 0, 0, 0xc3],
        64,
        false,
    );
    let result =
        decomp::analyze_function(&binary, &analysis, entry, &DecompContext::new(64), &()).unwrap();
    assert!(matches!(
        result.signature.return_value.ty,
        TypeRef::Unknown { .. }
    ));
}

#[test]
fn conflicting_callee_types_remain_unknown_with_conflict_evidence() {
    let (binary, analysis, entry) = image(
        &[
            0x85, 0xc0, 0x74, 7, 0xe8, 11, 0, 0, 0, 0xeb, 5, 0xe8, 5, 0, 0, 0, 0xc3, 0x90, 0x90,
            0x90, 0xc3, 0xc3,
        ],
        64,
        false,
    );
    let mut context = DecompContext::new(64);
    for (offset, ty) in [
        (20, TypeRef::uint(32)),
        (21, TypeRef::pointer_to(TypeRef::uint(8), 64)),
    ] {
        context.hints.insert(decomp::signature::describe_override(
            entry + offset,
            "callee",
            &decomp::SignatureOverride {
                convention: CallingConvention::Win64,
                return_type: TypeRef::Void,
                parameters: vec![decomp::SignatureParameterInput {
                    name: "value".into(),
                    location: decomp::Location::Register { name: "rcx".into() },
                    ty,
                }],
                variadic: Some(false),
            },
        ));
    }
    let result = decomp::analyze_function(&binary, &analysis, entry, &context, &()).unwrap();
    assert!(matches!(
        result.signature.parameters[0].ty,
        TypeRef::Unknown { .. }
    ));
    assert!(result
        .signature
        .conflicts
        .iter()
        .any(|conflict| conflict.contains("callee parameter type evidence conflicts")));
}

#[test]
fn stack_cancellation_is_checked_during_decoding() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct CancelAfter(AtomicUsize);
    impl ura_core::AnalysisControl for CancelAfter {
        fn is_cancelled(&self) -> bool {
            self.0.fetch_add(1, Ordering::Relaxed) > 10
        }
        fn report(&self, _: ura_core::AnalysisProgress) {}
    }
    let mut code = vec![0x90; 100];
    code.push(0xc3);
    let (binary, analysis, entry) = image(&code, 64, false);
    let control = CancelAfter(AtomicUsize::new(0));
    assert!(
        stack::recover_with_control(&binary, &analysis, entry, None, &control)
            .unwrap_err()
            .contains("cancelled")
    );
    assert!(control.0.load(Ordering::Relaxed) > 10);
}

#[test]
fn high_level_sign_extension_retains_the_source_width() {
    let (binary, analysis, entry) = image(&[0x48, 0x0f, 0xbe, 0xc1, 0xc3], 64, false);
    let result =
        decomp::analyze_function(&binary, &analysis, entry, &DecompContext::new(64), &()).unwrap();
    assert!(result.high_level.text().contains("sign_extend<8, 64>"));
}

#[test]
fn high_level_marks_incomplete_known_call_arguments_unresolved() {
    let (binary, analysis, entry) = image(&[0xe8, 1, 0, 0, 0, 0xc3, 0xc3], 64, false);
    let mut context = DecompContext::new(64);
    let mut signature = decomp::SignatureOverride {
        convention: CallingConvention::Win64,
        return_type: TypeRef::Void,
        parameters: vec![],
        variadic: Some(false),
    };
    context.hints.insert(decomp::signature::describe_override(
        entry + 6,
        "callee",
        &signature,
    ));
    let complete = decomp::analyze_function(&binary, &analysis, entry, &context, &()).unwrap();
    signature.parameters = vec![
        decomp::SignatureParameterInput {
            name: "stack_value".into(),
            location: decomp::Location::Stack {
                offset: 0x28,
                width: 64,
            },
            ty: TypeRef::uint(64),
        },
        decomp::SignatureParameterInput {
            name: "unknown_location".into(),
            location: decomp::Location::Unknown {
                reason: "unresolved ABI location".into(),
            },
            ty: TypeRef::uint(64),
        },
    ];
    signature.variadic = Some(true);
    context.hints.insert(decomp::signature::describe_override(
        entry + 6,
        "callee",
        &signature,
    ));
    let incomplete = decomp::analyze_function(&binary, &analysis, entry, &context, &()).unwrap();
    assert_eq!(
        incomplete.high_level.unresolved,
        complete.high_level.unresolved + 1
    );
    assert!(incomplete
        .high_level
        .text()
        .contains("stack arguments not shown"));
}

#[test]
fn indirect_calls_are_counted_without_inventing_callees() {
    let (_, analysis, entry) = image(&[0xff, 0xd0, 0xc3], 64, false);
    let graph = decomp::build_call_graph(&analysis);
    assert!(graph.node(entry).is_some());
    assert!(graph.edges.is_empty());
    assert_eq!(graph.unresolved_indirect, 1);
}

#[test]
fn floating_return_override_does_not_render_a_general_register_return() {
    let (binary, analysis, entry) = image(&[0x31, 0xc0, 0xc3], 64, false);
    let mut context = DecompContext::new(64);
    context.override_signature = Some(decomp::SignatureOverride {
        convention: CallingConvention::Win64,
        return_type: TypeRef::Float { bits: 64 },
        parameters: vec![],
        variadic: None,
    });
    let result = decomp::analyze_function(&binary, &analysis, entry, &context, &()).unwrap();
    assert!(result.signature.return_value.location.is_none());
    assert!(result
        .high_level
        .text()
        .contains("return <unresolved return location>;"));
    assert!(!result.high_level.text().contains("return rax"));
    assert!(result.high_level.unresolved > 0);
}
