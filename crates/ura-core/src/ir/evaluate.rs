//! Bit-accurate pure operations and an IR interpreter for semantic regression
//! tests. This interprets IR; it never executes the inspected executable.
use super::*;

pub fn pure(op: &Operation, ty: Type, args: &[Constant]) -> Option<Constant> {
    if !ty.valid() || args.iter().any(|c| !c.valid()) {
        return None;
    }
    if !super::verify::signature(op, Some(ty), &args.iter().map(|c| c.ty).collect::<Vec<_>>()) {
        return None;
    }
    let width = ty.width()?;
    let a = args.first().map(|c| c.value.0).unwrap_or(0);
    let b = args.get(1).map(|c| c.value.0).unwrap_or(0);
    let input_width = args.first().and_then(|c| c.ty.width()).unwrap_or(width);
    use Operation::*;
    let value = match op {
        Copy | ZeroExtend | Truncate | ToAddress | ToBits => a,
        SignExtend => {
            if input_width < 64 && a & (1u64 << (input_width - 1)) != 0 {
                a | !mask(input_width)
            } else {
                a
            }
        }
        Add => a.wrapping_add(b),
        Sub => a.wrapping_sub(b),
        And => a & b,
        Or => a | b,
        Xor => a ^ b,
        Not => !a,
        Shl => {
            if b >= input_width as u64 {
                0
            } else {
                a << b
            }
        }
        Shr => {
            if b >= input_width as u64 {
                0
            } else {
                a >> b
            }
        }
        Equal => u64::from(a == b),
        UnsignedLess => u64::from(a < b),
        Extract { offset } => a >> offset,
        Insert { offset } => {
            let w = args[1].ty.width()?;
            let region = mask(w) << offset;
            (a & !region) | ((b & mask(w)) << offset)
        }
        Select => {
            if a != 0 {
                b
            } else {
                args[2].value.0
            }
        }
        Parity => u64::from((a as u8).count_ones() % 2 == 0),
        _ => return None,
    };
    Some(Constant {
        ty,
        value: Address(value & mask(width)),
    })
}

#[derive(Clone, Debug, Default)]
pub struct Machine {
    pub values: BTreeMap<String, u64>,
    pub memory: BTreeMap<u64, u8>,
}
impl Machine {
    pub fn run(&mut self, function: &Function, max_blocks: usize) -> Result<Option<u64>, String> {
        verify(function).map_err(|e| e.join("; "))?;
        let mut values: Vec<Option<Constant>> = function
            .variables
            .iter()
            .map(|v| {
                self.values.get(&v.name).and_then(|n| {
                    v.ty.width().map(|w| Constant {
                        ty: v.ty,
                        value: Address(*n & mask(w)),
                    })
                })
            })
            .collect();
        let index: BTreeMap<_, _> = function.blocks.iter().map(|b| (b.address, b)).collect();
        let mut current = function.entry;
        for _ in 0..max_blocks {
            let block = index
                .get(&current)
                .ok_or("IR control flow leaves this function")?;
            for stmt in &block.statements {
                let arg = |i: usize| {
                    operand(stmt.args[i], &values)
                        .ok_or_else(|| format!("unknown input at {}", stmt.source))
                };
                let value = match stmt.op {
                    Operation::Load => {
                        let address = arg(1)?.value.0;
                        let ty = function.variables[stmt.output.unwrap()].ty;
                        let mut bits = 0u64;
                        for n in 0..ty.width().unwrap() / 8 {
                            let a = address.checked_add(n as u64).ok_or("address overflow")?;
                            bits |= (*self.memory.get(&a).ok_or("unmapped test memory")? as u64)
                                << (n * 8);
                        }
                        Some(Constant {
                            ty,
                            value: Address(bits),
                        })
                    }
                    Operation::Store => {
                        let address = arg(1)?.value.0;
                        let value = arg(2)?;
                        for n in 0..value.ty.width().unwrap() / 8 {
                            let a = address.checked_add(n as u64).ok_or("address overflow")?;
                            self.memory.insert(a, (value.value.0 >> (n * 8)) as u8);
                        }
                        None
                    }
                    Operation::Call | Operation::Barrier { .. } => {
                        return Err(format!(
                            "cannot concretely execute unknown effects at {}",
                            stmt.source
                        ))
                    }
                    Operation::Unknown { .. } => None,
                    _ => {
                        let args: Option<Vec<_>> =
                            stmt.args.iter().map(|a| operand(*a, &values)).collect();
                        args.and_then(|args| {
                            pure(&stmt.op, function.variables[stmt.output.unwrap()].ty, &args)
                        })
                    }
                };
                if let Some(id) = stmt.output {
                    values[id] = value;
                }
            }
            for (id, var) in function.variables.iter().enumerate() {
                if var.kind != VariableKind::Temporary {
                    if let Some(value) = values[id] {
                        self.values.insert(var.name.clone(), value.value.0);
                    } else {
                        self.values.remove(&var.name);
                    }
                }
            }
            let t = &block.terminator;
            match t.kind {
                FlowKind::Return => {
                    return Ok(t.value.and_then(|v| operand(v, &values)).map(|c| c.value.0))
                }
                FlowKind::Branch => {
                    let condition = operand(t.value.ok_or("missing condition")?, &values)
                        .ok_or("unknown condition")?;
                    current = if condition.value.0 != 0 {
                        t.taken
                    } else {
                        t.fallthrough
                    }
                    .ok_or("unresolved branch")?;
                }
                FlowKind::Jump => {
                    if let Some(s) = t.successors.first() {
                        current = *s;
                    } else {
                        return Ok(t.exits.first().map(|a| a.0));
                    }
                }
                FlowKind::Indirect => {
                    return Ok(t.value.and_then(|v| operand(v, &values)).map(|c| c.value.0))
                }
                FlowKind::Unresolved => return Err("unresolved control flow".into()),
            }
        }
        Err("IR interpreter step budget exceeded".into())
    }
}
fn operand(arg: Operand, values: &[Option<Constant>]) -> Option<Constant> {
    match arg {
        Operand::Constant(c) => Some(c),
        Operand::Variable(v) => values.get(v).copied().flatten(),
    }
}
