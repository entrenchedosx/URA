use super::*;
use std::collections::BTreeSet;

pub(crate) fn signature(op: &Operation, out: Option<Type>, args: &[Type]) -> bool {
    use Operation::*;
    let bits = |t: Type| matches!(t,Type::Bits(w) if (1..=64).contains(&w));
    match op {
        Copy => args.len() == 1 && out == Some(args[0]),
        Add | Sub | Mul | UnsignedMulHigh | SignedMulHigh | And | Or | Xor | Shl | Shr
        | RotateLeft | RotateRight => {
            args.len() == 2 && bits(args[0]) && args[0] == args[1] && out == Some(args[0])
        }
        Not => args.len() == 1 && bits(args[0]) && out == Some(args[0]),
        Divide { .. } | DivideFault { .. } => {
            args.len() == 3
                && bits(args[0])
                && args.iter().all(|a| *a == args[0])
                && out
                    == Some(if matches!(op, DivideFault { .. }) {
                        Type::Bits(1)
                    } else {
                        args[0]
                    })
        }
        Guard { .. } => out.is_none() && args == [Type::Bits(1)],
        Equal | UnsignedLess | SignedLess => {
            args.len() == 2 && bits(args[0]) && args[0] == args[1] && out == Some(Type::Bits(1))
        }
        ZeroExtend | SignExtend => {
            args.len() == 1
                && bits(args[0])
                && out.is_some_and(|t| bits(t) && t.width() > args[0].width())
        }
        Truncate => {
            args.len() == 1
                && bits(args[0])
                && out.is_some_and(|t| bits(t) && t.width() < args[0].width())
        }
        Extract { offset } => {
            args.len() == 1
                && bits(args[0])
                && out.is_some_and(|t| {
                    bits(t)
                        && (*offset as u32 + t.width().unwrap() as u32)
                            <= args[0].width().unwrap() as u32
                })
        }
        Insert { offset } => {
            args.len() == 2
                && bits(args[0])
                && bits(args[1])
                && out == Some(args[0])
                && (*offset as u32 + args[1].width().unwrap() as u32)
                    <= args[0].width().unwrap() as u32
        }
        Select => {
            args.len() == 3
                && args[0] == Type::Bits(1)
                && args[1] == args[2]
                && out == Some(args[1])
        }
        Parity => {
            args.len() == 1 && matches!(args[0],Type::Bits(w) if w>=8) && out == Some(Type::Bits(1))
        }
        ToAddress => {
            args.len() == 1
                && matches!((args[0],out),(Type::Bits(a),Some(Type::Address(b))) if a==b)
        }
        ToBits => {
            args.len() == 1
                && matches!((args[0],out),(Type::Address(a),Some(Type::Bits(b))) if a==b)
        }
        Load => {
            args.len() == 2
                && args[0] == Type::Memory
                && matches!(args[1], Type::Address(_))
                && matches!(out, Some(Type::Bits(8 | 16 | 32 | 64)))
        }
        Store => {
            args.len() == 3
                && args[0] == Type::Memory
                && matches!(args[1], Type::Address(_))
                && matches!(args[2], Type::Bits(8 | 16 | 32 | 64))
                && out == Some(Type::Memory)
        }
        Call => {
            out.is_none()
                && matches!(args.first(), Some(Type::Address(_)))
                && args.contains(&Type::Memory)
        }
        Barrier { .. } => out.is_none() && args.contains(&Type::Memory),
        Unknown { .. } => args.is_empty() && out.is_some(),
    }
}

pub fn verify(function: &Function) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    if function.ir_version != IR_VERSION || !matches!(function.address_width, 32 | 64) {
        errors.push("invalid IR version/address width".into());
    }
    if function.blocks.len() > MAX_IR_BLOCKS
        || function.variables.len() > MAX_IR_OPERATIONS + 64
        || function
            .blocks
            .iter()
            .map(|b| b.statements.len())
            .sum::<usize>()
            > MAX_IR_OPERATIONS
        || function
            .blocks
            .iter()
            .map(|b| b.terminator.successors.len() + b.terminator.exits.len())
            .sum::<usize>()
            > MAX_IR_EDGES
    {
        errors.push("IR exceeds verification budget".into());
        return Err(errors);
    }
    for (id, v) in function.variables.iter().enumerate() {
        if !v.valid() {
            errors.push(format!("invalid variable type v{id}"));
        }
    }
    let blocks: BTreeSet<_> = function.blocks.iter().map(|b| b.address).collect();
    if blocks.len() != function.blocks.len() || !blocks.contains(&function.entry) {
        errors.push("duplicate blocks or missing entry".into());
    }
    let mut temporary_defs = BTreeSet::new();
    let expected_state: BTreeSet<_> = function
        .variables
        .iter()
        .enumerate()
        .filter(|(_, v)| v.kind != VariableKind::Temporary)
        .map(|(i, _)| i)
        .collect();
    let mut ranges: Vec<_> = function.blocks.iter().map(|b| (b.address, b.end)).collect();
    ranges.sort_unstable();
    if ranges.windows(2).any(|p| p[0].1 > p[1].0) {
        errors.push("overlapping source blocks".into());
    }
    let mut total = 0usize;
    for block in &function.blocks {
        if block.address >= block.end
            || block.end.0.saturating_sub(1) > mask(function.address_width)
            || block.terminator.source < block.address
            || block.terminator.source >= block.end
        {
            errors.push("invalid source block/terminator range".into());
        }
        if block.function != function.entry {
            errors.push(format!("wrong block owner {}", block.address));
        }
        total += block.statements.len();
        let mut defined = BTreeSet::new();
        let mut previous = block.address;
        for statement in &block.statements {
            if statement.source < previous || statement.source > block.terminator.source {
                errors.push("operation provenance is outside source block/order".into());
            }
            previous = statement.source;
            for arg in &statement.args {
                check_operand(function, *arg, &defined, &mut errors);
            }
            let types: Option<Vec<_>> = statement
                .args
                .iter()
                .map(|a| function.operand_type(*a))
                .collect();
            let output = statement
                .output
                .and_then(|v| function.variables.get(v).map(|v| v.ty));
            if statement.output.is_some() && output.is_none() {
                errors.push("invalid output variable".into());
            }
            if types
                .as_ref()
                .is_none_or(|args| !signature(&statement.op, output, args))
            {
                errors.push(format!(
                    "operation type invariant at {}: {:?}",
                    statement.source, statement.op
                ));
            } else if matches!(statement.op, Operation::Load | Operation::Store)
                && types.as_ref().and_then(|args| args.get(1))
                    != Some(&Type::Address(function.address_width))
            {
                errors.push(format!(
                    "operation address width invariant at {}: {:?}",
                    statement.source, statement.op
                ));
            }
            if let Some(id) = statement.output {
                if let Some(var) = function.variables.get(id) {
                    if var.kind == VariableKind::Temporary {
                        if !temporary_defs.insert(id) {
                            errors.push(format!("temporary v{id} defined twice"));
                        }
                        defined.insert(id);
                    }
                }
            }
        }
        if errors.len() > 250 {
            return Err(errors);
        }
        let t = &block.terminator;
        if t.kind == FlowKind::Branch
            && function.operand_type(t.value.unwrap_or(Operand::Variable(usize::MAX)))
                != Some(Type::Bits(1))
        {
            errors.push(format!("branch requires a boolean at {}", t.source));
        }
        if matches!(
            t.kind,
            FlowKind::Return | FlowKind::Indirect | FlowKind::Jump | FlowKind::Unresolved
        ) && t.value.is_some()
            && t.value.and_then(|v| function.operand_type(v))
                != Some(Type::Address(function.address_width))
        {
            errors.push("transfer target is not an address".into());
        }
        for arg in t.state.iter().chain(t.value.iter()) {
            check_operand(function, *arg, &defined, &mut errors);
        }
        let mut targets = BTreeSet::new();
        for target in &t.successors {
            if !blocks.contains(target) || !targets.insert(target) {
                errors.push(format!(
                    "invalid/duplicate CFG edge {} -> {target}",
                    block.address
                ));
            }
        }
        if t.kind == FlowKind::Branch {
            if t.taken.is_none() || t.fallthrough.is_none() {
                errors.push("branch destinations missing".into());
            }
            for target in t.taken.iter().chain(t.fallthrough.iter()) {
                if !t.successors.contains(target) && !t.exits.contains(target) {
                    errors.push("branch target missing from CFG/exits".into());
                }
            }
            if t.successors
                .iter()
                .chain(&t.exits)
                .any(|target| Some(*target) != t.taken && Some(*target) != t.fallthrough)
            {
                errors.push("unexpected branch destination".into());
            }
        }
        if t.kind != FlowKind::Branch && (t.taken.is_some() || t.fallthrough.is_some()) {
            errors.push("branch destinations on non-branch".into());
        }
        if t.kind == FlowKind::Return && !t.successors.is_empty() {
            errors.push("return has internal successor".into());
        }
        if t.kind == FlowKind::Jump && t.successors.len() + t.exits.len() != 1 {
            errors.push("jump must have one destination".into());
        }
        if t.kind == FlowKind::Jump {
            if let Some(Operand::Constant(c)) = t.value {
                if !t
                    .successors
                    .iter()
                    .chain(&t.exits)
                    .any(|a| a.0 == c.value.0)
                {
                    errors.push("constant jump target disagrees with CFG".into());
                }
            }
        }
        if (t.successors.is_empty()
            || !t.exits.is_empty()
            || matches!(
                t.kind,
                FlowKind::Return | FlowKind::Indirect | FlowKind::Unresolved
            ))
            && t.state.is_empty()
        {
            errors.push("exit must preserve observable state".into());
        }
        if t.successors.is_empty()
            || !t.exits.is_empty()
            || matches!(
                t.kind,
                FlowKind::Return | FlowKind::Indirect | FlowKind::Unresolved
            )
        {
            let actual: Option<BTreeSet<_>> = t
                .state
                .iter()
                .map(|v| {
                    if let Operand::Variable(v) = v {
                        Some(*v)
                    } else {
                        None
                    }
                })
                .collect();
            if actual.as_ref() != Some(&expected_state) || t.state.len() != expected_state.len() {
                errors.push("exit state does not cover architectural variables exactly".into());
            }
        }
        let exits: BTreeSet<_> = t.exits.iter().copied().collect();
        if exits.len() != t.exits.len() || exits.iter().any(|e| blocks.contains(e)) {
            errors.push("invalid exit destination".into());
        }
        if errors.len() > 250 {
            break;
        }
    }
    if total > MAX_IR_OPERATIONS {
        errors.push("operation budget exceeded".into());
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}
fn check_operand(f: &Function, arg: Operand, defined: &BTreeSet<usize>, errors: &mut Vec<String>) {
    match arg {
        Operand::Variable(id) => match f.variables.get(id) {
            None => errors.push(format!("invalid variable v{id}")),
            Some(v) if v.kind == VariableKind::Temporary && !defined.contains(&id) => {
                errors.push(format!("temporary v{id} used before local definition"))
            }
            _ => {}
        },
        Operand::Constant(c) => {
            if !c.ty.valid()
                || c.ty == Type::Memory
                || c.ty.width().is_some_and(|w| c.value.0 & !mask(w) != 0)
            {
                errors.push("invalid constant".into());
            }
        }
    }
}
