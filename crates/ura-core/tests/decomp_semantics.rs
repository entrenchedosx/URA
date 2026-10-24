//! The original raw-IR interpreter and the semantic-HIR executor have separate
//! arithmetic, memory and control implementations. Neither runs native code.
use ura_core::decomp::{
    execute::{self, Exit},
    semantic, types,
};
use ura_core::ir::{self, dataflow, evaluate::Machine, ssa, VariableKind};
use ura_core::{AnalysisOptions, CodeImage, CodeRegion};

fn lift(code: &[u8]) -> ir::Function {
    lift_bits(code, 64)
}
fn lift_bits(code: &[u8], bits: u8) -> ir::Function {
    let image = CodeImage::new(vec![CodeRegion {
        start: 0x1000,
        bytes: code,
    }]);
    let analysis = ura_core::analyze_image(
        &image,
        bits,
        Some(0x1000),
        &[],
        &AnalysisOptions::default(),
        &(),
    );
    ir::lift_image(&image, bits, &analysis, 0x1000, &()).unwrap()
}
fn compare(code: &[u8], inputs: &[(String, u64)], limit: usize) {
    compare_raw(lift(code), code, inputs, limit);
}
fn compare_raw(
    raw: ir::Function,
    code: &[u8],
    inputs: &[(String, u64)],
    limit: usize,
) -> execute::State {
    let ssa = ssa::construct(&raw).unwrap();
    let (types, _) = types::infer_ssa_types(&ssa, &()).unwrap();
    let hir = semantic::lower(&ssa, &types, &()).unwrap();
    // Constant propagation is deliberately not used to execute either model.
    let facts = dataflow::analyze(&ssa).unwrap();
    let mut reference = Machine::default();
    for variable in &raw.variables {
        if variable.kind != VariableKind::Temporary && variable.ty.width().is_some() {
            reference.values.insert(variable.name.clone(), 0);
        }
    }
    for (name, value) in inputs {
        reference.values.insert(name.clone(), *value);
    }
    reference.values.insert(
        if raw.address_width == 32 {
            "esp"
        } else {
            "rsp"
        }
        .into(),
        0x8000,
    );
    for offset in 0..16 {
        reference.memory.insert(0x8000 + offset, 0);
    }
    reference.memory.insert(0x8000, 0x42);
    for offset in 0..16 {
        reference.memory.insert(0x9000 + offset, (offset * 7) as u8);
    }
    let mut actual = execute::State {
        registers: reference.values.clone(),
        memory: reference.memory.clone(),
        trace: Vec::new(),
    };
    let reconstructed = ura_core::decomp::source::build_with_facts(
        &hir,
        "fixture",
        &Default::default(),
        None,
        &Default::default(),
        &facts.constants,
        &(),
    )
    .unwrap();
    let mut source_state = ura_core::decomp::source::evaluate::State::default();
    source_state.registers = reference.values.clone();
    source_state.memory = reference.memory.clone();
    let source_result = source_state.run(&reconstructed.ast, 100_000);
    let expected = reference.run(&raw, limit);
    let reference_exit = expected.clone();
    let result = actual.run(&hir, limit);
    let complete = expected.is_ok() && result.is_ok();
    if let Err(error) = &expected {
        let source_error = source_result
            .as_ref()
            .expect_err("C-like output must preserve a non-concrete exit");
        if error.contains("budget") {
            assert!(source_error.contains("budget"));
        }
        if error.contains("unknown") {
            assert!(source_error.contains("unknown"));
        }
    }
    if !code.starts_with(&[0xff, 0xd0]) && code != [0xeb, 0xfe] {
        assert!(
            complete,
            "supported fixture did not execute: {expected:?} vs {result:?}; bytes={code:x?}"
        );
    }
    match (expected, result) {
        (Ok(expected), Ok(Exit::Return(value) | Exit::Indirect(value))) => {
            assert_eq!(value, expected)
        }
        (Ok(expected), Ok(Exit::External(value))) => assert_eq!(Some(value.0), expected),
        (Err(expected), Err(actual)) if expected.contains("budget") => {
            assert!(actual.contains("budget"), "{actual}")
        }
        (Err(expected), Err(actual)) if expected.contains("unknown") => {
            assert!(actual.contains("unknown"), "{actual}")
        }
        (expected, actual) => {
            panic!("different outcomes: {expected:?} vs {actual:?}; bytes={code:x?}")
        }
    }
    // Compare state only after successful termination; an unknown effect stops
    // before either interpreter has a concrete complete state.
    if complete {
        match source_result {
            Ok(ura_core::decomp::source::evaluate::Exit::Return {
                result,
                destination,
            }) => {
                assert_eq!(
                    destination,
                    *reference_exit.as_ref().unwrap(),
                    "C-like return destination"
                );
                assert_eq!(
                    result,
                    reference
                        .values
                        .get(if raw.address_width == 32 {
                            "eax"
                        } else {
                            "rax"
                        })
                        .copied(),
                    "C-like ABI result"
                );
            }
            Ok(ura_core::decomp::source::evaluate::Exit::External(address)) => {
                assert_eq!(Some(address.0), *reference_exit.as_ref().unwrap())
            }
            Ok(ura_core::decomp::source::evaluate::Exit::Indirect(destination)) => {
                assert_eq!(destination, *reference_exit.as_ref().unwrap())
            }
            other => panic!("C-like reconstruction failed: {other:?}; bytes={code:x?}"),
        }
        assert_eq!(
            source_state.memory, reference.memory,
            "C-like memory for {code:x?}"
        );
        assert_eq!(
            source_state.trace, reference.trace,
            "C-like control path for {code:x?}"
        );
        assert_eq!(
            actual.registers, reference.values,
            "registers for {code:x?} inputs={inputs:?}"
        );
        assert_eq!(actual.memory, reference.memory, "memory for {code:x?}");
        assert_eq!(actual.trace, reference.trace, "control path differs");
    }
    actual
}
fn input(rcx: u64, rdx: u64) -> Vec<(String, u64)> {
    vec![("rcx".into(), rcx), ("rdx".into(), rdx)]
}

fn condition_oracle(code: u8, a: u64, b: u64, width: u16) -> bool {
    let mask = u64::MAX >> (64 - width);
    let a = a & mask;
    let b = b & mask;
    let result = a.wrapping_sub(b) & mask;
    let sign = 1u64 << (width - 1);
    let carry = a < b;
    let zero = result == 0;
    let negative = result & sign != 0;
    let overflow = (a ^ b) & (a ^ result) & sign != 0;
    let parity = (result as u8).count_ones() % 2 == 0;
    [
        overflow,
        !overflow,
        carry,
        !carry,
        zero,
        !zero,
        carry || zero,
        !carry && !zero,
        negative,
        !negative,
        parity,
        !parity,
        negative != overflow,
        negative == overflow,
        zero || negative != overflow,
        !zero && negative == overflow,
    ][usize::from(code)]
}

#[test]
fn all_setcc_and_cmov_conditions_match_known_integer_results() {
    let boundaries = [
        0,
        1,
        0x7fff,
        0x8000,
        0x7fff_ffff,
        0x8000_0000,
        0x7fff_ffff_ffff_ffff,
        0x8000_0000_0000_0000,
        u64::MAX,
    ];
    for width in [16, 32, 64] {
        let prefix: &[u8] = match width {
            16 => &[0x66],
            32 => &[],
            _ => &[0x48],
        };
        for cc in 0..16 {
            let mut mov = prefix.to_vec();
            mov.extend([0x39, 0xd1]); // cmp cx/ecx/rcx,dx/edx/rdx
                                      // These moves preserve flags and overwrite the compared registers.
            mov.extend([0xb9, 0, 0, 0, 0, 0xba, 0, 0, 0, 0]);
            mov.extend(prefix);
            mov.extend([0x0f, 0x40 + cc, 0xc3, 0xc3]); // cmovcc ax/eax/rax,bx/ebx/rbx; ret
            for &a in &boundaries {
                for &b in &boundaries {
                    let old = 0xa5a5_1234_8765_4321;
                    let new = 0x5a5a_5678_1234_9876;
                    let mask = u64::MAX >> (64 - width);
                    let selected = if condition_oracle(cc, a, b, width) {
                        new
                    } else {
                        old
                    };
                    let expected = if width == 16 {
                        (old & !mask) | (selected & mask)
                    } else {
                        selected & mask
                    };
                    let mut inputs = input(a, b);
                    inputs.extend([("rax".into(), old), ("rbx".into(), new)]);
                    let state = compare_raw(lift(&mov), &mov, &inputs, 8);
                    assert_eq!(
                        state.registers.get("rax"),
                        Some(&expected),
                        "CMOV cc={cc} width={width} a={a:x} b={b:x}"
                    );
                    if width == 64 {
                        let set = vec![0x48, 0x39, 0xd1, 0x0f, 0x90 + cc, 0xc0, 0xc3];
                        let expected = (old & !255) | u64::from(condition_oracle(cc, a, b, width));
                        let state = compare_raw(lift(&set), &set, &inputs, 8);
                        assert_eq!(state.registers.get("rax"), Some(&expected), "SET cc={cc}");
                    }
                }
            }
        }
    }
}

#[test]
fn multiply_forms_match_full_products_and_defined_overflow_flags() {
    for width in [8, 16, 32, 64] {
        let mask = u64::MAX >> (64 - width);
        let boundary = [0, 1, 2, mask >> 1, (mask >> 1) + 1, mask - 1, mask];
        for signed in [false, true] {
            let prefix: &[u8] = match width {
                8 | 32 => &[],
                16 => &[0x66],
                _ => &[0x48],
            };
            let mut code = prefix.to_vec();
            code.extend([
                if width == 8 { 0xf6 } else { 0xf7 },
                if signed { 0xeb } else { 0xe3 },
                0xc3,
            ]); // imul/mul bl/bx/ebx/rbx
            for &a in &boundary {
                for &b in &boundary {
                    let mut inputs = input(0, 0);
                    inputs.extend([("rax".into(), a), ("rbx".into(), b)]);
                    let state = compare_raw(lift(&code), &code, &inputs, 8);
                    let sign = |v: u64| (i128::from(v) << (128 - width)) >> (128 - width);
                    let product = if signed {
                        (sign(a) * sign(b)) as u128
                    } else {
                        u128::from(a) * u128::from(b)
                    };
                    let low = product as u64 & mask;
                    let high = (product >> width) as u64 & mask;
                    let overflow = if signed {
                        sign(low) != product as i128
                    } else {
                        high != 0
                    };
                    let actual_low = state.registers["rax"];
                    if width == 8 {
                        assert_eq!(actual_low & 65535, (high << 8) | low);
                    } else {
                        assert_eq!(actual_low & mask, low);
                        assert_eq!(state.registers["rdx"] & mask, high);
                    }
                    assert_eq!(state.registers["cf"], u64::from(overflow));
                    assert_eq!(state.registers["of"], u64::from(overflow));
                    for flag in ["pf", "af", "zf", "sf"] {
                        assert!(!state.registers.contains_key(flag));
                    }
                }
            }
        }
        if width != 8 {
            for &a in &boundary {
                for &b in &boundary {
                    let prefix: &[u8] = match width {
                        16 => &[0x66],
                        32 => &[],
                        _ => &[0x48],
                    };
                    let mut code = prefix.to_vec();
                    code.extend([0x0f, 0xaf, 0xc3, 0xc3]);
                    let state = compare_raw(
                        lift(&code),
                        &code,
                        &[("rax".into(), a), ("rbx".into(), b)],
                        8,
                    );
                    assert_eq!(state.registers["rax"] & mask, a.wrapping_mul(b) & mask);
                }
            }
            let prefix: &[u8] = match width {
                16 => &[0x66],
                32 => &[],
                _ => &[0x48],
            };
            let mut code = prefix.to_vec();
            code.extend([0x6b, 0xc3, 0xfd, 0xc3]); // imul ax/eax/rax,bx/ebx/rbx,-3
            let state = compare_raw(lift(&code), &code, &[("rbx".into(), 7)], 8);
            assert_eq!(state.registers["rax"] & mask, (-21i64) as u64 & mask);
        }
    }
}

#[test]
fn rotates_mask_counts_preserve_zero_flags_and_leave_multibit_overflow_unknown() {
    for width in [8u16, 16, 32, 64] {
        let mask = u64::MAX >> (64 - width);
        let prefix: &[u8] = match width {
            8 | 32 => &[],
            16 => &[0x66],
            _ => &[0x48],
        };
        for left in [false, true] {
            let mut code = prefix.to_vec();
            code.extend([
                if width == 8 { 0xd2 } else { 0xd3 },
                if left { 0xc0 } else { 0xc8 },
                0xc3,
            ]);
            for value in [0, 1, mask >> 1, (mask >> 1) + 1, mask] {
                for count in 0..=255 {
                    let state = compare_raw(
                        lift(&code),
                        &code,
                        &[
                            ("rax".into(), value),
                            ("rcx".into(), count),
                            ("cf".into(), 1),
                            ("of".into(), 1),
                        ],
                        8,
                    );
                    let masked = count & if width == 64 { 63 } else { 31 };
                    let mut expected = value;
                    for _ in 0..masked % u64::from(width) {
                        expected = if left {
                            ((expected << 1) | (expected >> (width - 1))) & mask
                        } else {
                            (expected >> 1) | ((expected & 1) << (width - 1))
                        };
                    }
                    assert_eq!(
                        state.registers["rax"] & mask,
                        expected,
                        "rotate width={width} count={count}"
                    );
                    let cf = if masked == 0 {
                        1
                    } else if left {
                        expected & 1
                    } else {
                        expected >> (width - 1)
                    };
                    assert_eq!(state.registers["cf"], cf);
                    if masked == 0 {
                        assert_eq!(state.registers["of"], 1);
                    } else if masked == 1 {
                        let of = (expected >> (width - 1))
                            ^ if left {
                                cf
                            } else {
                                (expected >> (width - 2)) & 1
                            };
                        assert_eq!(state.registers["of"], of);
                    } else {
                        assert!(!state.registers.contains_key("of"));
                    }
                }
            }
        }
    }
}

#[test]
fn division_recovers_quotients_remainders_and_preserves_defined_widths() {
    for width in [8u16, 16, 32, 64] {
        let mask = u64::MAX >> (64 - width);
        let boundary = [0, 1, 2, mask >> 1, (mask >> 1) + 1, mask];
        for signed in [false, true] {
            let prefix: &[u8] = match width {
                8 | 32 => &[],
                16 => &[0x66],
                _ => &[0x48],
            };
            let mut code = prefix.to_vec();
            code.extend([
                if width == 8 { 0xf6 } else { 0xf7 },
                if signed { 0xfb } else { 0xf3 },
                0xc3,
            ]);
            for high in boundary {
                for low in boundary {
                    for divisor in boundary {
                        let pair = (u128::from(high) << width) | u128::from(low);
                        let expected = if signed {
                            let dividend =
                                ((pair << (128 - 2 * width)) as i128) >> (128 - 2 * width);
                            let denominator =
                                (i128::from(divisor) << (128 - width)) >> (128 - width);
                            dividend.checked_div(denominator).and_then(|q| {
                                let bound = 1i128 << (width - 1);
                                if q < -bound || q >= bound {
                                    None
                                } else {
                                    dividend
                                        .checked_rem(denominator)
                                        .map(|r| (q as u64 & mask, r as u64 & mask))
                                }
                            })
                        } else {
                            pair.checked_div(u128::from(divisor))
                                .filter(|q| *q <= u128::from(mask))
                                .and_then(|q| {
                                    pair.checked_rem(u128::from(divisor))
                                        .map(|r| (q as u64, r as u64))
                                })
                        };
                        let Some((quotient, remainder)) = expected else {
                            continue;
                        };
                        let rax = if width == 8 { (high << 8) | low } else { low };
                        let inputs = [
                            ("rax".into(), rax),
                            ("rdx".into(), high),
                            ("rbx".into(), divisor),
                        ];
                        let state = compare_raw(lift(&code), &code, &inputs, 8);
                        assert_eq!(
                            state.registers["rax"] & mask,
                            quotient,
                            "divide width={width} signed={signed}"
                        );
                        let actual_remainder = if width == 8 {
                            (state.registers["rax"] >> 8) & mask
                        } else {
                            state.registers["rdx"] & mask
                        };
                        assert_eq!(actual_remainder, remainder);
                        for flag in ["cf", "pf", "af", "zf", "sf", "of"] {
                            assert!(!state.registers.contains_key(flag));
                        }
                    }
                }
            }
        }
    }
    // Common compiler preparation: CQO; IDIV RBX, and CDQ; IDIV EBX.
    for (code, expected) in [
        (&[0x48, 0x99, 0x48, 0xf7, 0xfb, 0xc3][..], (-7i64) as u64),
        (&[0x99, 0xf7, 0xfb, 0xc3][..], u64::from((-7i32) as u32)),
    ] {
        let state = compare_raw(
            lift(code),
            code,
            &[("rax".into(), (-22i64) as u64), ("rbx".into(), 3)],
            8,
        );
        assert_eq!(state.registers["rax"], expected);
    }
}

#[test]
fn division_faults_stop_before_following_memory_effects_in_all_models() {
    for signed in [false, true] {
        let code = [
            0x48,
            0xf7,
            if signed { 0xfb } else { 0xf3 },
            0x48,
            0x89,
            0x06,
            0xc3,
        ];
        let raw = lift(&code);
        let ssa = ssa::construct(&raw).unwrap();
        let (types, _) = types::infer_ssa_types(&ssa, &()).unwrap();
        let hir = semantic::lower(&ssa, &types, &()).unwrap();
        let facts = dataflow::analyze(&ssa).unwrap();
        let output = ura_core::decomp::source::build_with_facts(
            &hir,
            "fault",
            &Default::default(),
            None,
            &Default::default(),
            &facts.constants,
            &(),
        )
        .unwrap();
        assert!(output.text().contains("ura_trap"));
        for (high, low, divisor) in if signed {
            vec![
                (0, 1, 0),
                (u64::MAX, 0x8000_0000_0000_0000, u64::MAX),
                (1, 0, 1),
            ]
        } else {
            vec![(0, 1, 0), (1, 0, 1), (u64::MAX, u64::MAX, 2)]
        } {
            let registers = [
                ("rax".into(), low),
                ("rdx".into(), high),
                ("rbx".into(), divisor),
                ("rsi".into(), 0x9000),
            ]
            .into_iter()
            .collect::<std::collections::BTreeMap<_, _>>();
            let memory = [(0x9000, 0x5a)]
                .into_iter()
                .collect::<std::collections::BTreeMap<_, _>>();
            let mut raw_state = Machine {
                values: registers.clone(),
                memory: memory.clone(),
                trace: Vec::new(),
            };
            let mut semantic_state = execute::State {
                registers: registers.clone(),
                memory: memory.clone(),
                trace: Vec::new(),
            };
            let mut source_state = ura_core::decomp::source::evaluate::State::default();
            source_state.registers = registers;
            source_state.memory = memory.clone();
            for result in [
                raw_state.run(&raw, 8).map(|_| ()),
                semantic_state.run(&hir, 8).map(|_| ()),
                source_state.run(&output.ast, 1000).map(|_| ()),
            ] {
                assert!(result.unwrap_err().contains("machine fault"));
            }
            assert_eq!(raw_state.memory, memory);
            assert_eq!(semantic_state.memory, memory);
            assert_eq!(source_state.memory, memory);
        }
    }
}

#[test]
fn x86_condition_multiply_rotate_and_divide_forms_have_known_results() {
    type IntegerCase<'a> = (&'a [u8], &'a [(&'a str, u64)], u64);
    let cases: &[IntegerCase<'_>] = &[
        (
            &[0x39, 0xd1, 0x0f, 0x9c, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3],
            &[("ecx", u64::from(u32::MAX)), ("edx", 1)],
            1,
        ),
        (
            &[0x39, 0xd1, 0x0f, 0x4c, 0xc3, 0xc3],
            &[
                ("eax", 9),
                ("ebx", 4),
                ("ecx", u64::from(u32::MAX)),
                ("edx", 1),
            ],
            4,
        ),
        (&[0x0f, 0xaf, 0xc3, 0xc3], &[("eax", 6), ("ebx", 7)], 42),
        (&[0xc1, 0xc0, 1, 0xc3], &[("eax", 0x8000_0000)], 1),
        (
            &[0x99, 0xf7, 0xfb, 0xc3],
            &[("eax", u64::from((-22i32) as u32)), ("ebx", 3)],
            u64::from((-7i32) as u32),
        ),
        (
            &[0x39, 0xd1, 0x0f, 0x94, 0x06, 0xc3],
            &[("eax", 7), ("ecx", 1), ("edx", 1), ("esi", 0x9000)],
            7,
        ),
    ];
    for (code, inputs, expected) in cases {
        let inputs = inputs
            .iter()
            .map(|(name, value)| (name.to_string(), *value))
            .collect::<Vec<_>>();
        let state = compare_raw(lift_bits(code, 32), code, &inputs, 8);
        assert_eq!(state.registers["eax"], *expected);
    }
}

#[test]
fn false_cmov_memory_source_is_read_before_selection_in_all_models() {
    let raw = lift(&[0x48, 0x39, 0xd1, 0x48, 0x0f, 0x44, 0x03, 0xc3]);
    let ssa = ssa::construct(&raw).unwrap();
    let (types, _) = types::infer_ssa_types(&ssa, &()).unwrap();
    let hir = semantic::lower(&ssa, &types, &()).unwrap();
    let facts = dataflow::analyze(&ssa).unwrap();
    let output = ura_core::decomp::source::build_with_facts(
        &hir,
        "cmov",
        &Default::default(),
        None,
        &Default::default(),
        &facts.constants,
        &(),
    )
    .unwrap();
    let registers = [
        ("rcx".into(), 1),
        ("rdx".into(), 2),
        ("rbx".into(), 0x9000),
        ("rax".into(), 7),
        ("rsp".into(), 0x8000),
    ]
    .into_iter()
    .collect::<std::collections::BTreeMap<_, _>>();
    let memory = (0..8)
        .map(|i| (0x8000 + i, 0))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut raw_state = Machine {
        values: registers.clone(),
        memory: memory.clone(),
        trace: Vec::new(),
    };
    let mut semantic_state = execute::State {
        registers: registers.clone(),
        memory: memory.clone(),
        trace: Vec::new(),
    };
    let mut source_state = ura_core::decomp::source::evaluate::State::default();
    source_state.registers = registers;
    source_state.memory = memory;
    for result in [
        raw_state.run(&raw, 8).map(|_| ()),
        semantic_state.run(&hir, 8).map(|_| ()),
        source_state.run(&output.ast, 1000).map(|_| ()),
    ] {
        assert!(result.unwrap_err().contains("unmapped"));
    }
}

#[test]
fn bounded_exhaustive_integer_and_partial_register_semantics() {
    let programs: &[&[u8]] = &[
        &[
            0x48, 0x89, 0xc8, 0x48, 0x01, 0xd0, 0x48, 0x83, 0xe8, 3, 0xc3,
        ],
        &[0x48, 0x89, 0xc8, 0xb0, 0xa5, 0x88, 0xd4, 0xc3], // AL/AH inserts preserve unrelated bits
        &[0x48, 0x0f, 0xbe, 0xc1, 0xc3],                   // signed byte extension
        &[0x48, 0x89, 0xc8, 0x48, 0x31, 0xd0, 0xc3],
        &[
            0x48, 0x39, 0xd1, 0x72, 6, 0xb8, 0, 0, 0, 0, 0xc3, 0xb8, 1, 0, 0, 0, 0xc3,
        ],
    ];
    for code in programs {
        for a in 0..16 {
            for b in 0..16 {
                compare(code, &input(a * 17, b * 0x111111111111111), 64);
            }
        }
    }
}

#[test]
fn diamonds_multiple_returns_and_loop_phis_agree() {
    let programs: &[&[u8]] = &[
        &[
            0x85, 0xc9, 0x75, 4, 0x89, 0xc8, 0xeb, 2, 0x89, 0xd0, 0x8b, 0xc0, 0xc3,
        ],
        &[
            0x85, 0xc9, 0x74, 6, 0xb8, 1, 0, 0, 0, 0xc3, 0xb8, 2, 0, 0, 0, 0xc3,
        ],
        &[
            0x31, 0xc0, 0x48, 0x83, 0xf9, 0, 0x74, 9, 0x48, 0x01, 0xc8, 0x48, 0x83, 0xe9, 1, 0xeb,
            0xf1, 0xc3,
        ],
    ];
    for code in programs {
        for a in 0..16 {
            for b in 0..8 {
                compare(code, &input(a, b), 512);
            }
        }
    }
}

#[test]
fn nested_loop_execution_and_phi_selection_agree() {
    let code = [
        0x31, 0xc0, 0x49, 0x89, 0xd0, 0x48, 0x85, 0xc9, 0x74, 0x18, 0x4c, 0x89, 0xc2, 0x48, 0x85,
        0xd2, 0x74, 0x0a, 0x48, 0x83, 0xc0, 1, 0x48, 0x83, 0xea, 1, 0xeb, 0xf1, 0x48, 0x83, 0xe9,
        1, 0xeb, 0xe3, 0xc3,
    ];
    for a in 0..8 {
        for b in 0..8 {
            compare(&code, &input(a, b), 512);
        }
    }
}

#[test]
fn irreducible_two_entry_cycle_retains_explicit_control_semantics() {
    let code = [
        0x48, 0x85, 0xc9, 0x74, 8, 0x48, 0x83, 0xea, 1, 0x74, 8, 0xeb, 0, 0x48, 0x83, 0xe9, 1,
        0x75, 0xf2, 0xc3,
    ];
    for a in 0..8 {
        for b in 1..8 {
            compare(&code, &input(a, b), 512);
        }
    }
}

#[test]
fn memory_and_address_casts_agree() {
    // mov rax,[rcx]; add rax,rdx; mov [rcx+8],rax; ret
    let code = [
        0x48, 0x8b, 0x01, 0x48, 0x01, 0xd0, 0x48, 0x89, 0x41, 8, 0xc3,
    ];
    for value in 0..64 {
        compare(&code, &input(0x9000, value), 64);
    }
}

#[test]
fn infinite_external_indirect_and_unknown_paths_are_explicit() {
    compare(&[0xeb, 0xfe], &[], 64);
    compare(&[0xe9, 0xfb, 0x0f, 0, 0], &[], 64);
    compare(&[0xff, 0xe0], &[("rax".into(), 0x1234)], 64);
    compare(&[0xff, 0xd0, 0xc3], &[("rax".into(), 0x1234)], 64);
}

#[test]
fn stable_ids_exact_operands_synthetic_provenance_and_ssa_types() {
    // RAX's first value is used as a load address; a later unrelated version
    // holds an integer. A legacy register summary must not merge these types.
    let raw = lift(&[0x48, 0x89, 0xc8, 0x48, 0x8b, 0x10, 0xb8, 7, 0, 0, 0, 0xc3]);
    let ssa = ssa::construct(&raw).unwrap();
    let (types, partial) = types::infer_ssa_types(&ssa, &()).unwrap();
    assert!(!partial);
    let rax = ssa.variables.iter().position(|v| v.name == "rax").unwrap();
    let entries: Vec<_> = types.iter().filter(|ty| ty.value.variable == rax).collect();
    assert!(entries
        .iter()
        .any(|ty| matches!(ty.ty, types::TypeRef::Pointer { .. })));
    assert!(entries
        .iter()
        .any(|ty| matches!(ty.ty, types::TypeRef::Int { .. })));
    let hir = semantic::lower(&ssa, &types, &()).unwrap();
    let again = semantic::lower(&ssa, &types, &()).unwrap();
    assert_eq!(
        serde_json::to_value(&hir).unwrap(),
        serde_json::to_value(again).unwrap()
    );
    assert_eq!(
        hir.nodes.len(),
        ssa.blocks
            .iter()
            .map(|b| b.statements.len() + b.phis.len())
            .sum::<usize>()
    );
    for node in &hir.nodes {
        let source = &hir.sources[node.source];
        assert_eq!(source.synthetic, source.instruction.is_none());
    }
    let mut malformed = hir;
    malformed.values[0].storage = ir::Type::Bits(0);
    assert!(execute::State::default().run(&malformed, 64).is_err());
}

#[test]
fn clang_pe_and_elf_o0_o1_o2_o3_match_reference_execution_and_known_c_results() {
    use std::path::Path;
    for (name, bytes) in [
        (
            "semantic-O1.exe",
            include_bytes!("../../../tests/fixtures/semantic-O1.exe").as_slice(),
        ),
        (
            "semantic-O3.exe",
            include_bytes!("../../../tests/fixtures/semantic-O3.exe").as_slice(),
        ),
        (
            "semantic-O1.elf",
            include_bytes!("../../../tests/fixtures/semantic-O1.elf").as_slice(),
        ),
        (
            "semantic-O3.elf",
            include_bytes!("../../../tests/fixtures/semantic-O3.elf").as_slice(),
        ),
        (
            "semantic-O0.exe",
            include_bytes!("../../../tests/fixtures/semantic-O0.exe").as_slice(),
        ),
        (
            "semantic-O2.exe",
            include_bytes!("../../../tests/fixtures/semantic-O2.exe").as_slice(),
        ),
        (
            "semantic-O0.elf",
            include_bytes!("../../../tests/fixtures/semantic-O0.elf").as_slice(),
        ),
        (
            "semantic-O2.elf",
            include_bytes!("../../../tests/fixtures/semantic-O2.elf").as_slice(),
        ),
    ] {
        let binary = ura_core::binary::analyze_bytes(Path::new(name), bytes.to_vec()).unwrap();
        let analysis = ura_core::analyze_functions(&binary, &AnalysisOptions::default(), &());
        let (a, b) = if name.ends_with(".exe") {
            ("rcx", "rdx")
        } else {
            ("rdi", "rsi")
        };
        for function_name in ["semantic_sum", "semantic_memory", "semantic_loop"] {
            let function = analysis
                .functions
                .iter()
                .find(|function| {
                    analysis.function_name(function.address).as_deref() == Some(function_name)
                })
                .unwrap_or_else(|| panic!("missing {function_name} in {name}"));
            for value in 0..8u64 {
                let first = if function_name == "semantic_memory" {
                    0x9000
                } else if function_name == "semantic_loop" {
                    value * 3
                } else {
                    value
                };
                let raw = ir::lift_function(&binary, &analysis, function.address, &()).unwrap();
                let actual =
                    compare_raw(raw, &[], &[(a.into(), first), (b.into(), value + 7)], 512);
                let expected = match function_name {
                    "semantic_sum" => value.wrapping_add(value + 7).wrapping_add(3),
                    "semantic_loop" => 3 * value * (value + 1) / 2,
                    _ => u64::from_le_bytes([0, 7, 14, 21, 28, 35, 42, 49]).wrapping_add(value + 7),
                };
                assert_eq!(
                    actual.registers["rax"], expected,
                    "{name} {function_name} input={value}"
                );
            }
        }
    }
}

#[test]
fn cancellation_is_observed_by_semantic_lowering_and_ssa_type_passes() {
    struct Cancel;
    impl ura_core::AnalysisControl for Cancel {
        fn is_cancelled(&self) -> bool {
            true
        }
        fn report(&self, _: ura_core::AnalysisProgress) {}
    }
    let ssa = ssa::construct(&lift(&[0x48, 0x89, 0xc8, 0xc3])).unwrap();
    assert!(semantic::lower(&ssa, &[], &Cancel)
        .unwrap_err()
        .contains("cancelled"));
    assert!(types::infer_ssa_types(&ssa, &Cancel)
        .unwrap_err()
        .contains("cancelled"));
}

#[test]
fn clang_cpp_corpus_checks_known_behavior_and_honest_partial_classes_at_all_levels() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    for level in 0..=3 {
        for extension in ["exe", "elf"] {
            let path = root.join(format!("decompiler-O{level}.{extension}"));
            let binary = ura_core::analyze_path(&path).unwrap();
            let analysis = ura_core::analyze_functions(&binary, &AnalysisOptions::default(), &());
            let (a, b) = if extension == "exe" {
                ("rcx", "rdx")
            } else {
                ("rdi", "rsi")
            };
            for name in [
                "cpp_scalar",
                "cpp_record",
                "cpp_branch",
                "cpp_nested",
                "cpp_switch",
                "cpp_member",
            ] {
                let function = analysis
                    .functions
                    .iter()
                    .find(|f| analysis.function_name(f.address).as_deref() == Some(name))
                    .unwrap();
                let raw = ir::lift_function(&binary, &analysis, function.address, &()).unwrap();
                let ssa = ssa::construct(&raw).unwrap();
                let (types, _) = types::infer_ssa_types(&ssa, &()).unwrap();
                let hir = semantic::lower(&ssa, &types, &()).unwrap();
                let output =
                    ura_core::decomp::source::build(&hir, name, &Default::default(), None, &())
                        .unwrap();
                assert!(!output.lines.is_empty());
                if raw.blocks.iter().flat_map(|b| &b.statements).any(|o| {
                    matches!(o.op, ir::Operation::Barrier { .. })
                        || matches!(o.op, ir::Operation::Unknown { .. })
                            && o.output
                                .is_none_or(|v| raw.variables[v].ty == ir::Type::Memory)
                }) {
                    assert!(output.unresolved > 0, "{name} O{level}.{extension}");
                }
                if matches!(name, "cpp_scalar" | "cpp_record") {
                    for value in [0, 1, 127, u64::MAX] {
                        let first = if name == "cpp_record" { 0x9000 } else { value };
                        let second = value.rotate_left(17) ^ 7;
                        let actual = compare_raw(
                            raw.clone(),
                            &[],
                            &[(a.into(), first), (b.into(), second)],
                            1024,
                        );
                        let expected = if name == "cpp_scalar" {
                            (value ^ second).wrapping_add(7) & 255
                        } else {
                            u64::from_le_bytes([56, 63, 70, 77, 84, 91, 98, 105])
                                .wrapping_add(second)
                        };
                        assert_eq!(
                            actual.registers["rax"], expected,
                            "{name} O{level}.{extension}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn opaque_memory_does_not_reuse_stale_concrete_bytes() {
    let mut raw = lift(&[0x48, 0x8b, 0x01, 0xc3]);
    let memory = raw
        .variables
        .iter()
        .position(|variable| variable.kind == VariableKind::Memory)
        .unwrap();
    raw.blocks[0].statements.insert(
        0,
        ir::Statement {
            source: raw.entry,
            output: Some(memory),
            op: ir::Operation::Unknown {
                reason: "opaque memory mutation".into(),
            },
            args: vec![],
        },
    );
    let ssa = ssa::construct(&raw).unwrap();
    let hir = semantic::lower(&ssa, &[], &()).unwrap();
    let mut original = Machine::default();
    original.values.insert("rcx".into(), 0x9000);
    original
        .memory
        .extend((0..8).map(|offset| (0x9000 + offset, 7)));
    let mut actual = execute::State {
        registers: original.values.clone(),
        memory: original.memory.clone(),
        trace: vec![],
    };
    assert!(original
        .run(&raw, 64)
        .unwrap_err()
        .contains("unknown memory"));
    assert!(actual.run(&hir, 64).unwrap_err().contains("unknown memory"));
}
