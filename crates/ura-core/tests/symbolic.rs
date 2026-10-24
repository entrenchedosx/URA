use std::collections::BTreeMap;
use ura_core::{
    ir::{self, Address, Operation},
    symbolic::{
        self,
        expr::{Arena, Kind, Sort},
        solver::{Backend, DirectZ3, Limits, Query, Status},
        Options, PredicateStatus,
    },
};

fn query(
    arena: Arena,
    assertions: Vec<usize>,
    observables: BTreeMap<String, usize>,
) -> symbolic::solver::Outcome {
    DirectZ3.query(
        Query {
            arena,
            assertions,
            observables,
            limits: Limits {
                timeout_ms: 2000,
                ..Limits::default()
            },
        },
        &(),
    )
}
fn arena() -> Arena {
    Arena::new(4000, 128)
}

fn variable(name: &str, ty: ir::Type, kind: ir::VariableKind) -> ir::Variable {
    ir::Variable {
        name: name.into(),
        ty,
        kind,
    }
}
fn statement(address: u64, output: usize, op: Operation, args: Vec<ir::Operand>) -> ir::Statement {
    ir::Statement {
        source: Address(address),
        output: Some(output),
        op,
        args,
    }
}
fn constant(width: u16, value: u64) -> ir::Operand {
    ir::Operand::Constant(ir::Constant::bits(width, value))
}
fn flow(
    address: u64,
    kind: ir::FlowKind,
    successors: &[u64],
    value: Option<ir::Operand>,
    variables: usize,
) -> ir::Terminator {
    ir::Terminator {
        source: Address(address),
        kind,
        value,
        successors: successors.iter().map(|a| Address(*a)).collect(),
        exits: Vec::new(),
        taken: (kind == ir::FlowKind::Branch).then(|| Address(successors[0])),
        fallthrough: (kind == ir::FlowKind::Branch).then(|| Address(successors[1])),
        state: (0..variables).map(ir::Operand::Variable).collect(),
    }
}
fn block(address: u64, statements: Vec<ir::Statement>, terminator: ir::Terminator) -> ir::Block {
    ir::Block {
        address: Address(address),
        end: Address(address + 1),
        function: Address(0x1000),
        statements,
        terminator,
    }
}
#[test]
fn dispatcher_recovers_state_transitions_with_prefix_proofs() {
    use ir::{FlowKind::*, Operand::Variable as V, Type::Bits, VariableKind::*};
    let raw = ir::Function {
        ir_version: ir::IR_VERSION,
        entry: Address(0x1000),
        address_width: 64,
        variables: vec![
            variable("state", Bits(32), Register),
            variable("condition", Bits(1), Flag),
            variable("memory", ir::Type::Memory, ir::VariableKind::Memory),
        ],
        blocks: vec![
            block(
                0x1000,
                vec![statement(0x1000, 0, Operation::Copy, vec![constant(32, 1)])],
                flow(0x1000, Jump, &[0x1010], None, 3),
            ),
            block(
                0x1010,
                vec![statement(
                    0x1010,
                    1,
                    Operation::Equal,
                    vec![V(0), constant(32, 1)],
                )],
                flow(0x1010, Branch, &[0x1020, 0x1030], Some(V(1)), 3),
            ),
            block(
                0x1020,
                vec![statement(0x1020, 0, Operation::Copy, vec![constant(32, 2)])],
                flow(0x1020, Jump, &[0x1010], None, 3),
            ),
            block(
                0x1030,
                vec![statement(
                    0x1030,
                    1,
                    Operation::Equal,
                    vec![V(0), constant(32, 2)],
                )],
                flow(0x1030, Branch, &[0x1040, 0x1050], Some(V(1)), 3),
            ),
            block(
                0x1040,
                vec![statement(0x1040, 0, Operation::Copy, vec![constant(32, 3)])],
                flow(0x1040, Jump, &[0x1010], None, 3),
            ),
            block(0x1050, vec![], flow(0x1050, Return, &[], None, 3)),
        ],
        diagnostics: Vec::new(),
        source_instructions: 6,
    };
    let report = symbolic::analyze(&raw, &Options::default(), &DirectZ3, &()).unwrap();
    assert_eq!(report.dispatchers.len(), 1);
    let transitions = &report.dispatchers[0].transitions;
    assert_eq!(transitions.len(), 2, "{report:#?}");
    assert_eq!(
        (transitions[0].from, transitions[0].next.clone()),
        (Address(1), vec![Address(2)])
    );
    assert_eq!(
        (transitions[1].from, transitions[1].next.clone()),
        (Address(2), vec![Address(3)])
    );
    assert!(transitions.iter().all(|t| t.exhaustive_under_prefix));
    assert!(report.complete); // finite owned state machine; every feasible path reaches return
    assert!(report.removed_edges.is_empty()); // prefix-only facts never globally remove dispatch cases
}
#[test]
fn full_path_buffer_never_claims_complete_when_fault_or_return_is_omitted() {
    use ir::{FlowKind::Return, Operand::Variable as V, Type::Bits, VariableKind::*};
    let raw = ir::Function {
        ir_version: ir::IR_VERSION,
        entry: Address(0x1000),
        address_width: 64,
        variables: vec![
            variable("memory", ir::Type::Memory, ir::VariableKind::Memory),
            variable("pointer", ir::Type::Address(64), Register),
            variable("rax", Bits(64), Register),
        ],
        blocks: vec![block(
            0x1000,
            vec![statement(0x1000, 2, Operation::Load, vec![V(0), V(1)])],
            flow(0x1000, Return, &[], None, 3),
        )],
        diagnostics: Vec::new(),
        source_instructions: 1,
    };
    let options = Options {
        max_paths: 1,
        regions: vec![symbolic::Region {
            start: Address(0x2000),
            size: 8,
            read: true,
            write: false,
        }],
        ..Options::default()
    };
    let report = symbolic::analyze(&raw, &options, &DirectZ3, &()).unwrap();
    assert_eq!(report.paths.len(), 1);
    assert!(!report.complete);
}
#[test]
fn finite_indirect_target_set_requires_unsat_blocking_query() {
    use ir::{FlowKind::Indirect, Operand::Variable as V, Type::Bits, VariableKind::*};
    let target = |value| {
        ir::Operand::Constant(ir::Constant {
            ty: ir::Type::Address(64),
            value: Address(value),
        })
    };
    let raw = ir::Function {
        ir_version: ir::IR_VERSION,
        entry: Address(0x1000),
        address_width: 64,
        variables: vec![
            variable("condition", Bits(1), Flag),
            variable("target", ir::Type::Address(64), Register),
            variable("memory", ir::Type::Memory, ir::VariableKind::Memory),
        ],
        blocks: vec![block(
            0x1000,
            vec![statement(
                0x1000,
                1,
                Operation::Select,
                vec![V(0), target(0x2000), target(0x3000)],
            )],
            flow(0x1000, Indirect, &[], Some(V(1)), 3),
        )],
        diagnostics: Vec::new(),
        source_instructions: 1,
    };
    let report = symbolic::analyze(&raw, &Options::default(), &DirectZ3, &()).unwrap();
    assert_eq!(
        report.indirect_targets[0].candidates,
        vec![Address(0x2000), Address(0x3000)]
    );
    assert!(report.indirect_targets[0].exhaustive);
    let last = *report.indirect_targets[0].evidence.last().unwrap();
    assert_eq!(report.queries[last].outcome.status, Status::Unsat);
    assert!(!report.complete); // path exploration stops at an indirect-transfer boundary
    let mut call = raw.clone();
    call.blocks[0].statements.push(ir::Statement {
        source: Address(0x1000),
        output: None,
        op: Operation::Call,
        args: vec![V(1), V(2)],
    });
    call.blocks[0].terminator.kind = ir::FlowKind::Return;
    call.blocks[0].terminator.value = None;
    let report = symbolic::analyze(&call, &Options::default(), &DirectZ3, &()).unwrap();
    assert_eq!(report.indirect_targets[0].transfer_kind, "indirectCall");
    assert_eq!(
        report.indirect_targets[0].value_set_seeds,
        vec![Address(0x2000), Address(0x3000)]
    );
    assert!(report.indirect_targets[0].exhaustive);
    assert!(!report.complete);
}
#[test]
fn expression_deserialization_rebuilds_checked_builder_state() {
    let mut a = arena();
    let x = a.symbol("x", Sort::Bits(8), None).unwrap();
    let text = serde_json::to_string(&a).unwrap();
    let mut restored: Arena = serde_json::from_str(&text).unwrap();
    let y = restored.pure(Operation::Not, 8, vec![x]).unwrap();
    assert_eq!(
        query(restored, Vec::new(), BTreeMap::from([("y".into(), y)])).status,
        Status::Sat
    );
    let mut malformed: serde_json::Value = serde_json::from_str(&text).unwrap();
    malformed["nodes"].as_array_mut().unwrap().push(serde_json::json!({"sort":{"kind":"bits","width":8},"kind":{"kind":"pure","operation":{"kind":"add"},"inputs":[0,0,0,0]}}));
    assert!(serde_json::from_value::<Arena>(malformed).is_err());
}
fn lift(bytes: &[u8]) -> ir::Function {
    let image = ura_core::CodeImage::new(vec![ura_core::CodeRegion {
        start: 0x1000,
        bytes,
    }]);
    let analysis = ura_core::analyze_image(
        &image,
        64,
        Some(0x1000),
        &[],
        &ura_core::AnalysisOptions::default(),
        &(),
    );
    ir::lift_image(&image, 64, &analysis, 0x1000, &()).unwrap()
}
#[test]
fn genuine_solver_proves_polynomial_identity_for_bitvectors() {
    for width in [8, 16, 32, 64] {
        let mut a = arena();
        let x = a.symbol("x", Sort::Bits(width), None).unwrap();
        let one = a.constant(width, 1).unwrap();
        let plus = a.pure(Operation::Add, width, vec![x, one]).unwrap();
        let product = a.pure(Operation::Mul, width, vec![x, plus]).unwrap();
        let bit = a.pure(Operation::And, width, vec![product, one]).unwrap();
        let zero = a.constant(width, 0).unwrap();
        let eq = a.pure(Operation::Equal, 1, vec![bit, zero]).unwrap();
        let false_case = a.condition(eq, false).unwrap();
        assert_eq!(
            query(a, vec![false_case], BTreeMap::new()).status,
            Status::Unsat,
            "width {width}"
        );
    }
}
#[test]
fn wraparound_is_not_unbounded_integer_arithmetic() {
    let mut a = arena();
    let x = a.symbol("x", Sort::Bits(8), None).unwrap();
    let one = a.constant(8, 1).unwrap();
    let next = a.pure(Operation::Add, 8, vec![x, one]).unwrap();
    let smaller = a.pure(Operation::UnsignedLess, 1, vec![next, x]).unwrap();
    let result = query(
        a,
        vec![smaller],
        BTreeMap::from([("x".into(), x), ("next".into(), next)]),
    );
    assert_eq!(result.status, Status::Sat);
    assert_eq!(result.model["x"], Address(255));
    assert_eq!(result.model["next"], Address(0));
}
#[test]
fn signed_comparisons_shift_extensions_concat_and_partial_writes() {
    let mut a = arena();
    let x = a.symbol("x", Sort::Bits(8), None).unwrap();
    let high = a.constant(8, 0x80).unwrap();
    let same = a.pure(Operation::Equal, 1, vec![x, high]).unwrap();
    let zero = a.constant(8, 0).unwrap();
    let negative = a.pure(Operation::SignedLess, 1, vec![x, zero]).unwrap();
    let count = a.constant(8, 7).unwrap();
    let shifted = a
        .add(
            Sort::Bits(8),
            Kind::ArithmeticShiftRight { value: x, count },
        )
        .unwrap();
    let extended = a.pure(Operation::SignExtend, 16, vec![x]).unwrap();
    let concat = a
        .add(
            Sort::Bits(16),
            Kind::Concat {
                high: x,
                low: shifted,
            },
        )
        .unwrap();
    let inserted = a
        .pure(Operation::Insert { offset: 8 }, 16, vec![extended, shifted])
        .unwrap();
    let result = query(
        a,
        vec![same, negative],
        BTreeMap::from([
            ("sar".into(), shifted),
            ("sext".into(), extended),
            ("concat".into(), concat),
            ("insert".into(), inserted),
        ]),
    );
    assert_eq!(result.status, Status::Sat);
    assert_eq!(result.model["sar"], Address(255));
    assert_eq!(result.model["sext"], Address(0xff80));
    assert_eq!(result.model["concat"], Address(0x80ff));
    assert_eq!(result.model["insert"], Address(0xff80));
}
#[test]
fn persistent_symbolic_memory_preserves_potential_aliases() {
    let mut a = arena();
    let mem = a.symbol("m", Sort::Memory(64), None).unwrap();
    let p = a.symbol("p", Sort::Bits(64), None).unwrap();
    let q = a.symbol("q", Sort::Bits(64), None).unwrap();
    let value = a.constant(32, 0x12345678).unwrap();
    let updated = a
        .add(
            Sort::Memory(64),
            Kind::Store {
                memory: mem,
                address: p,
                value,
            },
        )
        .unwrap();
    let read = a
        .add(
            Sort::Bits(32),
            Kind::Load {
                memory: updated,
                address: q,
            },
        )
        .unwrap();
    let aliases = a.pure(Operation::Equal, 1, vec![p, q]).unwrap();
    let equal_value = a.pure(Operation::Equal, 1, vec![read, value]).unwrap();
    let wrong = a.condition(equal_value, false).unwrap();
    assert_eq!(
        query(a.clone(), vec![aliases, wrong], BTreeMap::new()).status,
        Status::Unsat
    );
    // Without address equality, an unrelated load is allowed to differ.
    assert_eq!(query(a, vec![wrong], BTreeMap::new()).status, Status::Sat);
}
#[test]
fn undefined_input_never_becomes_a_proof() {
    let mut a = arena();
    let flag = a
        .symbol(
            "undefined_flag",
            Sort::Bits(1),
            Some("undefined machine flag".into()),
        )
        .unwrap();
    assert_eq!(
        query(a, vec![flag], BTreeMap::new()).status,
        Status::Unsupported
    );
}
#[test]
fn rejects_malformed_graph_and_limits_without_native_solver_calls() {
    let mut a = arena();
    let x = a.constant(8, 1).unwrap();
    assert!(a.pure(Operation::Add, 32, vec![x, x]).is_err());
    assert!(a
        .add(
            Sort::Bits(8),
            Kind::Pure {
                operation: Operation::Unknown {
                    reason: "bad".into()
                },
                inputs: Vec::new()
            }
        )
        .is_err());
    let before = a.nodes.len();
    a.symbol("duplicate", Sort::Bits(8), None).unwrap();
    assert!(a
        .add(
            Sort::Bits(8),
            Kind::Symbol {
                name: "duplicate".into(),
                poison: None
            }
        )
        .is_err());
    assert_eq!(a.nodes.len(), before + 1);
    a.rebuild().unwrap();
    let q = Query {
        arena: a,
        assertions: vec![9999],
        observables: BTreeMap::new(),
        limits: Limits::default(),
    };
    assert_eq!(DirectZ3.query(q, &()).status, Status::Error);
    let options = Options {
        max_states: usize::MAX,
        ..Options::default()
    };
    assert!(options.validate().is_err());
    // Recursive predicate dependency construction must honor the same operation
    // budget as forward path execution, before an expensive proof is submitted.
    let raw = lift(&[
        0x89, 0xc8, 0x8d, 0x51, 1, 0x0f, 0xaf, 0xc2, 0xa8, 1, 0x75, 1, 0xc3, 0xc3,
    ]);
    let report = symbolic::analyze(
        &raw,
        &Options {
            max_operations: 1,
            recover_dispatchers: false,
            ..Options::default()
        },
        &DirectZ3,
        &(),
    )
    .unwrap();
    assert!(report.operations <= 1);
    assert!(!report.complete);
    assert!(report.removed_edges.is_empty());
    assert!(report.queries.is_empty());
}
#[test]
fn machine_branch_is_proved_and_derived_rewrite_is_revalidated() {
    // xor eax,eax; test eax,eax; jne unreachable; mov eax,1; ret; mov eax,2; ret
    let raw = lift(&[
        0x31, 0xc0, 0x85, 0xc0, 0x75, 6, 0xb8, 1, 0, 0, 0, 0xc3, 0xb8, 2, 0, 0, 0, 0xc3,
    ]);
    let report = symbolic::analyze(&raw, &Options::default(), &DirectZ3, &()).unwrap();
    assert_eq!(report.predicates.len(), 1);
    assert_eq!(
        report.predicates[0].classification,
        PredicateStatus::AlwaysFalse
    );
    assert_eq!(report.removed_edges.len(), 1);
    let proof = report.predicates[0].validation_evidence.unwrap();
    assert_eq!(
        DirectZ3
            .query(report.replay_query(proof).unwrap(), &())
            .status,
        Status::Unsat
    );
    assert!(report.paths.iter().any(|p| p.outcome == "return (Sat)"));
}
#[test]
fn input_dependent_branch_keeps_both_outcomes_and_user_constraints_are_scoped() {
    let raw = lift(&[
        0x85, 0xc0, 0x75, 6, 0xb8, 1, 0, 0, 0, 0xc3, 0xb8, 2, 0, 0, 0, 0xc3,
    ]);
    let options = Options {
        concrete_inputs: BTreeMap::from([("rax".into(), Address(0))]),
        ..Options::default()
    };
    let report = symbolic::analyze(&raw, &options, &DirectZ3, &()).unwrap();
    assert_eq!(
        report.predicates[0].classification,
        PredicateStatus::BothFeasible
    );
    assert!(report.removed_edges.is_empty());
    let branches: Vec<_> = report
        .paths
        .iter()
        .filter(|p| p.outcome == "return (Sat)")
        .collect();
    assert_eq!(branches.len(), 1);
    for proof in &report.queries {
        if let Some(value) = proof.outcome.model.get("rax") {
            assert_eq!(*value, Address(0));
        }
    }
}
#[test]
fn external_unknown_effects_are_not_nops() {
    let raw = lift(&[0x0f, 0xa2, 0x85, 0xc0, 0x75, 1, 0xc3, 0xc3]); // cpuid
    let report = symbolic::analyze(&raw, &Options::default(), &DirectZ3, &()).unwrap();
    assert!(report.removed_edges.is_empty());
    assert!(!report.complete);
    assert!(report
        .paths
        .iter()
        .any(|p| p.outcome.contains("unsupported")));
}
#[test]
fn path_explosion_and_query_exhaustion_are_incomplete_not_proofs() {
    let raw = lift(&[
        0x85, 0xc0, 0x75, 6, 0xb8, 1, 0, 0, 0, 0xc3, 0xb8, 2, 0, 0, 0, 0xc3,
    ]);
    let options = Options {
        max_queries: 1,
        max_states: 1,
        max_paths: 1,
        ..Options::default()
    };
    let report = symbolic::analyze(&raw, &options, &DirectZ3, &()).unwrap();
    assert!(!report.complete);
    assert!(report.removed_edges.is_empty());
    assert_eq!(report.queries.len(), 1);
}
#[test]
fn solver_resource_exhaustion_remains_unknown() {
    let mut a = arena();
    let x = a.symbol("x", Sort::Bits(64), None).unwrap();
    let y = a.symbol("y", Sort::Bits(64), None).unwrap();
    let product = a.pure(Operation::Mul, 64, vec![x, y]).unwrap();
    let n = a.constant(64, 0x7fff_ffff_ffff_ffc5).unwrap();
    let eq = a.pure(Operation::Equal, 1, vec![product, n]).unwrap();
    let q = Query {
        arena: a,
        assertions: vec![eq],
        observables: BTreeMap::new(),
        limits: Limits {
            resource_limit: 1,
            ..Limits::default()
        },
    };
    assert!(matches!(
        DirectZ3.query(q, &()).status,
        Status::Unknown | Status::Timeout
    ));
}

#[test]
fn real_solver_timeout_is_not_unsat() {
    let mut a = arena();
    let x = a.symbol("factor_x", Sort::Bits(64), None).unwrap();
    let y = a.symbol("factor_y", Sort::Bits(64), None).unwrap();
    let low = a.pure(Operation::Mul, 64, vec![x, y]).unwrap();
    let high = a.pure(Operation::UnsignedMulHigh, 64, vec![x, y]).unwrap();
    let prime = a.constant(64, 0xffff_ffff_ffff_ffc5).unwrap();
    let zero = a.constant(64, 0).unwrap();
    let one = a.constant(64, 1).unwrap();
    let assertions = vec![
        a.pure(Operation::Equal, 1, vec![low, prime]).unwrap(),
        a.pure(Operation::Equal, 1, vec![high, zero]).unwrap(),
        a.pure(Operation::UnsignedLess, 1, vec![one, x]).unwrap(),
        a.pure(Operation::UnsignedLess, 1, vec![one, y]).unwrap(),
    ];
    let outcome = DirectZ3.query(
        Query {
            arena: a,
            assertions,
            observables: BTreeMap::new(),
            limits: Limits {
                timeout_ms: 1,
                resource_limit: 50_000_000,
                ..Limits::default()
            },
        },
        &(),
    );
    assert_eq!(outcome.status, Status::Timeout, "{outcome:?}");
}

#[test]
fn live_smt_models_match_independent_integer_arithmetic_across_widths() {
    for width in [1u16, 8, 16, 32, 64] {
        let mask = ir::mask(width);
        let sign = 1u64 << (width - 1);
        let signed = |value: u64| (i128::from(value) << (128 - width)) >> (128 - width);
        for (a, b, c) in [
            (0, 0, 0),
            (1, 2, 3),
            (mask, mask, mask),
            (sign, 1, mask),
            (0, mask, 3),
            (mask, sign, 2),
            (7, 64, 5),
            (sign - 1, 255, 1),
        ] {
            let (a, b, c) = (a & mask, b & mask, c & mask);
            let mut arena = arena();
            let x = arena.symbol("x", Sort::Bits(width), None).unwrap();
            let y = arena.symbol("y", Sort::Bits(width), None).unwrap();
            let z = arena.symbol("z", Sort::Bits(width), None).unwrap();
            let mut assertions = Vec::new();
            for (input, value) in [(x, a), (y, b), (z, c)] {
                let constant = arena.constant(width, value).unwrap();
                assertions.push(
                    arena
                        .pure(Operation::Equal, 1, vec![input, constant])
                        .unwrap(),
                );
            }
            let mut observables = BTreeMap::new();
            let mut expected = BTreeMap::new();
            for (name, op, value) in [
                ("add", Operation::Add, a.wrapping_add(b) & mask),
                ("sub", Operation::Sub, a.wrapping_sub(b) & mask),
                ("mul", Operation::Mul, a.wrapping_mul(b) & mask),
                ("and", Operation::And, a & b),
                ("or", Operation::Or, a | b),
                ("xor", Operation::Xor, a ^ b),
                (
                    "shl",
                    Operation::Shl,
                    if b >= u64::from(width) {
                        0
                    } else {
                        (a << b) & mask
                    },
                ),
                (
                    "shr",
                    Operation::Shr,
                    if b >= u64::from(width) { 0 } else { a >> b },
                ),
                (
                    "umulh",
                    Operation::UnsignedMulHigh,
                    ((u128::from(a) * u128::from(b)) >> width) as u64 & mask,
                ),
                (
                    "smulh",
                    Operation::SignedMulHigh,
                    ((signed(a) * signed(b)) >> width) as u64 & mask,
                ),
            ] {
                observables.insert(name.into(), arena.pure(op, width, vec![x, y]).unwrap());
                expected.insert(name, value);
            }
            for (name, op, value) in [
                ("eq", Operation::Equal, a == b),
                ("ult", Operation::UnsignedLess, a < b),
                ("slt", Operation::SignedLess, signed(a) < signed(b)),
            ] {
                observables.insert(name.into(), arena.pure(op, 1, vec![x, y]).unwrap());
                expected.insert(name, u64::from(value));
            }
            observables.insert(
                "not".into(),
                arena.pure(Operation::Not, width, vec![x]).unwrap(),
            );
            expected.insert("not", !a & mask);
            observables.insert(
                "sar".into(),
                arena
                    .add(
                        Sort::Bits(width),
                        Kind::ArithmeticShiftRight { value: x, count: y },
                    )
                    .unwrap(),
            );
            expected.insert(
                "sar",
                if b >= u64::from(width) {
                    if a & sign != 0 {
                        mask
                    } else {
                        0
                    }
                } else {
                    (signed(a) >> b) as u64 & mask
                },
            );
            let count = b % u64::from(width);
            for (name, op, value) in [
                (
                    "rol",
                    Operation::RotateLeft,
                    if count == 0 {
                        a
                    } else {
                        ((a << count) | (a >> (u64::from(width) - count))) & mask
                    },
                ),
                (
                    "ror",
                    Operation::RotateRight,
                    if count == 0 {
                        a
                    } else {
                        ((a >> count) | (a << (u64::from(width) - count))) & mask
                    },
                ),
            ] {
                observables.insert(name.into(), arena.pure(op, width, vec![x, y]).unwrap());
                expected.insert(name, value);
            }
            let condition = arena.pure(Operation::UnsignedLess, 1, vec![x, y]).unwrap();
            observables.insert(
                "select".into(),
                arena
                    .pure(Operation::Select, width, vec![condition, y, z])
                    .unwrap(),
            );
            expected.insert("select", if a < b { b } else { c });
            if width >= 8 {
                observables.insert(
                    "parity".into(),
                    arena.pure(Operation::Parity, 1, vec![x]).unwrap(),
                );
                expected.insert("parity", u64::from((a as u8).count_ones() % 2 == 0));
            }
            if width < 64 {
                observables.insert(
                    "zext".into(),
                    arena.pure(Operation::ZeroExtend, 64, vec![x]).unwrap(),
                );
                expected.insert("zext", a);
                observables.insert(
                    "sext".into(),
                    arena.pure(Operation::SignExtend, 64, vec![x]).unwrap(),
                );
                expected.insert("sext", signed(a) as u64);
            }
            if width <= 32 {
                observables.insert(
                    "concat".into(),
                    arena
                        .add(Sort::Bits(width * 2), Kind::Concat { high: x, low: y })
                        .unwrap(),
                );
                expected.insert("concat", (a << width) | b);
            }
            if width > 1 {
                let narrow = (width / 2).min(8);
                let small = arena.pure(Operation::Truncate, narrow, vec![y]).unwrap();
                observables.insert(
                    "extract".into(),
                    arena
                        .pure(Operation::Extract { offset: width / 2 }, narrow, vec![x])
                        .unwrap(),
                );
                expected.insert("extract", (a >> (width / 2)) & ir::mask(narrow));
                observables.insert(
                    "insert".into(),
                    arena
                        .pure(
                            Operation::Insert { offset: width / 2 },
                            width,
                            vec![x, small],
                        )
                        .unwrap(),
                );
                let region = ir::mask(narrow) << (width / 2);
                expected.insert(
                    "insert",
                    (a & !region) | ((b & ir::mask(narrow)) << (width / 2)),
                );
            }
            let wide = (u128::from(a) << width) | u128::from(b);
            for is_signed in [false, true] {
                let valid = if is_signed {
                    let dividend = ((wide << (128 - width * 2)) as i128) >> (128 - width * 2);
                    dividend.checked_div(signed(c)).and_then(|q| {
                        let bound = 1i128 << (width - 1);
                        (q >= -bound && q < bound).then(|| {
                            (
                                q as u64 & mask,
                                dividend.checked_rem(signed(c)).unwrap() as u64 & mask,
                            )
                        })
                    })
                } else {
                    wide.checked_div(u128::from(c))
                        .filter(|q| *q <= u128::from(mask))
                        .map(|q| (q as u64, (wide % u128::from(c)) as u64))
                };
                let name = if is_signed { "sdivfault" } else { "udivfault" };
                observables.insert(
                    name.into(),
                    arena
                        .pure(
                            Operation::DivideFault { signed: is_signed },
                            1,
                            vec![x, y, z],
                        )
                        .unwrap(),
                );
                expected.insert(name, u64::from(valid.is_none()));
                if let Some((quotient, remainder)) = valid {
                    for (name, is_remainder, value) in [
                        (if is_signed { "sdiv" } else { "udiv" }, false, quotient),
                        (if is_signed { "srem" } else { "urem" }, true, remainder),
                    ] {
                        observables.insert(
                            name.into(),
                            arena
                                .pure(
                                    Operation::Divide {
                                        signed: is_signed,
                                        remainder: is_remainder,
                                    },
                                    width,
                                    vec![x, y, z],
                                )
                                .unwrap(),
                        );
                        expected.insert(name, value);
                    }
                }
            }
            let result = query(arena, assertions, observables);
            assert_eq!(result.status, Status::Sat, "{result:?}");
            for (name, value) in expected {
                assert_eq!(
                    result.model[name],
                    Address(value),
                    "{name}, width {width}, inputs {a:#x}/{b:#x}/{c:#x}"
                );
            }
        }
    }
}
#[test]
fn cancelled_query_never_reports_unsat() {
    struct Cancelled;
    impl ura_core::AnalysisControl for Cancelled {
        fn is_cancelled(&self) -> bool {
            true
        }
        fn report(&self, _: ura_core::AnalysisProgress) {}
    }
    let q = Query {
        arena: arena(),
        assertions: Vec::new(),
        observables: BTreeMap::new(),
        limits: Limits::default(),
    };
    assert_eq!(DirectZ3.query(q, &Cancelled).status, Status::Cancelled);
}

#[test]
fn alias_classification_uses_ranges_not_just_unequal_pointers() {
    use symbolic::alias::{classify, Classification};
    let mut a = arena();
    let p = a.constant(64, 0x1000).unwrap();
    let q = a.constant(64, 0x1004).unwrap();
    let r = a.constant(64, 0x1008).unwrap();
    assert_eq!(
        classify(
            a.clone(),
            (p, 8),
            (p, 8),
            &[],
            Limits::default(),
            &DirectZ3,
            &()
        )
        .unwrap()
        .classification,
        Classification::Same
    );
    assert_eq!(
        classify(
            a.clone(),
            (p, 8),
            (q, 8),
            &[],
            Limits::default(),
            &DirectZ3,
            &()
        )
        .unwrap()
        .classification,
        Classification::PotentialAlias
    );
    assert_eq!(
        classify(
            a.clone(),
            (p, 8),
            (r, 8),
            &[],
            Limits::default(),
            &DirectZ3,
            &()
        )
        .unwrap()
        .classification,
        Classification::Disjoint
    );
    let wrap = a.constant(64, u64::MAX).unwrap();
    assert_eq!(
        classify(a, (wrap, 8), (r, 8), &[], Limits::default(), &DirectZ3, &())
            .unwrap()
            .classification,
        Classification::Unknown
    );
}

#[test]
fn lifted_multiply_identity_is_proved_without_a_pattern_detector() {
    let raw = lift(&[
        0x89, 0xc8, 0x8d, 0x51, 1, 0x0f, 0xaf, 0xc2, 0xa8, 1, 0x75, 6, 0xb8, 1, 0, 0, 0, 0xc3,
        0xb8, 2, 0, 0, 0, 0xc3,
    ]);
    let report = symbolic::analyze(&raw, &Options::default(), &DirectZ3, &()).unwrap();
    assert_eq!(
        report.predicates[0].classification,
        PredicateStatus::AlwaysFalse,
        "{report:#?}"
    );
    assert_eq!(report.removed_edges.len(), 1);
}
