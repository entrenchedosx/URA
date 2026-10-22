//! Bounded semantic-HIR evaluator. Intentionally independent of the original
//! IR interpreter and constant-folder; no inspected native code is executed.
use super::semantic::*;
use crate::ir::Address;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default)]
pub struct State {
    pub registers: BTreeMap<String, u64>,
    pub memory: BTreeMap<u64, u8>,
    pub trace: Vec<Address>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Exit {
    Return(Option<u64>),
    External(Address),
    Indirect(Option<u64>),
}

impl State {
    pub fn run(&mut self, function: &SemanticFunction, max_blocks: usize) -> Result<Exit, String> {
        validate(function)?;
        if max_blocks == 0 || max_blocks > 100_000 {
            return Err("semantic execution block budget must be 1..100000".into());
        }
        let mut values: Vec<_> = function
            .values
            .iter()
            .map(|value| {
                (value.ssa.version == 0)
                    .then(|| {
                        value
                            .register
                            .as_ref()
                            .and_then(|name| self.registers.get(name).copied())
                    })
                    .flatten()
                    .map(|bits| bits & bitmask(value.storage.width().unwrap_or(64)))
            })
            .collect();
        let blocks: BTreeMap<_, _> = function
            .blocks
            .iter()
            .map(|block| (block.address, block))
            .collect();
        let read = |input: Input, values: &[Option<u64>]| match input {
            Input::Value(id) => values.get(id).copied().flatten(),
            Input::Constant(c) => Some(c.value.0),
        };
        let input_width = |input: Input| match input {
            Input::Value(id) => function.values.get(id).and_then(|v| v.storage.width()),
            Input::Constant(c) => c.ty.width(),
        };
        let mut current = function.entry;
        let mut previous = None;
        let mut operations = 0usize;
        for _ in 0..max_blocks {
            let block = blocks
                .get(&current)
                .ok_or("semantic transfer outside function")?;
            self.trace.push(current);
            let mut assignments = Vec::new();
            for id in &block.phis {
                operations += 1;
                if operations > 100_000 {
                    return Err("semantic execution operation budget exceeded".into());
                }
                let node = function
                    .nodes
                    .get(*id)
                    .ok_or("invalid semantic phi reference")?;
                let NodeKind::Phi { initial, incoming } = &node.kind else {
                    return Err("invalid semantic phi node".into());
                };
                let selected = if let Some(predecessor) = previous {
                    incoming
                        .iter()
                        .find(|edge| edge.predecessor == predecessor)
                        .map(|edge| edge.value)
                } else {
                    *initial
                };
                assignments.push((
                    node.output.ok_or("phi has no result")?,
                    selected.and_then(|id| values.get(id).copied().flatten()),
                ));
            }
            for (id, value) in assignments {
                *values.get_mut(id).ok_or("invalid phi output")? = value;
            }
            for id in &block.operations {
                operations += 1;
                if operations > 100_000 {
                    return Err("semantic execution operation budget exceeded".into());
                }
                let node = function
                    .nodes
                    .get(*id)
                    .ok_or("invalid semantic operation reference")?;
                let width = node
                    .output
                    .and_then(|id| function.values.get(id))
                    .and_then(|v| v.storage.width())
                    .unwrap_or(64);
                let args: Option<Vec<_>> = node
                    .inputs
                    .iter()
                    .map(|input| read(*input, &values))
                    .collect();
                let result = match &node.kind {
                    NodeKind::Scalar {
                        operator: ScalarOp::Select,
                    } => node
                        .inputs
                        .first()
                        .and_then(|v| read(*v, &values))
                        .and_then(|condition| {
                            node.inputs
                                .get(if condition != 0 { 1 } else { 2 })
                                .and_then(|v| read(*v, &values))
                        }),
                    NodeKind::Scalar { operator } => args.and_then(|args| {
                        scalar(
                            *operator,
                            width,
                            node.inputs
                                .first()
                                .and_then(|arg| input_width(*arg))
                                .unwrap_or(width),
                            node.inputs.get(1).and_then(|arg| input_width(*arg)),
                            &args,
                        )
                    }),
                    NodeKind::ReadMemory => {
                        let address = node
                            .inputs
                            .get(1)
                            .and_then(|input| read(*input, &values))
                            .ok_or("unknown memory address")?;
                        let mut value = 0;
                        for index in 0..width.div_ceil(8) {
                            let address = address
                                .checked_add(u64::from(index))
                                .ok_or("address overflow")?;
                            value |= u64::from(
                                *self
                                    .memory
                                    .get(&address)
                                    .ok_or("unmapped semantic memory")?,
                            ) << (index * 8);
                        }
                        Some(value & bitmask(width))
                    }
                    NodeKind::WriteMemory => {
                        let address = node
                            .inputs
                            .get(1)
                            .and_then(|input| read(*input, &values))
                            .ok_or("unknown memory address")?;
                        let input = *node.inputs.get(2).ok_or("store value absent")?;
                        let value = read(input, &values).ok_or("unknown store value")?;
                        let stored_width = input_width(input).ok_or("store width absent")?;
                        for index in 0..stored_width.div_ceil(8) {
                            self.memory.insert(
                                address
                                    .checked_add(u64::from(index))
                                    .ok_or("address overflow")?,
                                (value >> (index * 8)) as u8,
                            );
                        }
                        None
                    }
                    NodeKind::Invoke | NodeKind::Barrier => {
                        return Err("unknown effects cannot be concretely executed".into())
                    }
                    NodeKind::Guard => {
                        if node
                            .inputs
                            .first()
                            .and_then(|v| read(*v, &values))
                            .ok_or("unknown machine fault condition")?
                            != 0
                        {
                            return Err("machine fault: divide error (#DE)".into());
                        }
                        None
                    }
                    NodeKind::UnknownEffect => {
                        if node.output.map_or(true, |id| {
                            function.values[id].storage == crate::ir::Type::Memory
                        }) {
                            return Err(
                                "unknown memory effects cannot be concretely executed".into()
                            );
                        }
                        None
                    }
                    NodeKind::Phi { .. } => return Err("phi outside block entry".into()),
                };
                if let Some(output) = node.output {
                    *values.get_mut(output).ok_or("invalid semantic output")? = result;
                }
            }
            for (register, input) in &block.transfer.registers {
                if let Some(value) = read(*input, &values) {
                    self.registers.insert(register.clone(), value);
                } else {
                    self.registers.remove(register);
                }
            }
            let target = match block.transfer.kind {
                TransferKind::Branch {
                    condition,
                    taken,
                    fallthrough,
                } => {
                    if condition
                        .and_then(|input| read(input, &values))
                        .ok_or("unknown branch condition")?
                        != 0
                    {
                        taken
                    } else {
                        fallthrough
                    }
                }
                TransferKind::Jump { target } => target,
                TransferKind::Return { destination, .. } => {
                    return Ok(Exit::Return(
                        destination.and_then(|input| read(input, &values)),
                    ))
                }
                TransferKind::Indirect { destination } => {
                    return Ok(Exit::Indirect(
                        destination.and_then(|input| read(input, &values)),
                    ))
                }
                TransferKind::Unresolved => return Err("unresolved semantic transfer".into()),
            }
            .ok_or("unresolved semantic destination")?;
            if !blocks.contains_key(&target) {
                return Ok(Exit::External(target));
            }
            previous = Some(current);
            current = target;
        }
        Err("semantic execution block budget exceeded".into())
    }
}

fn bitmask(width: u16) -> u64 {
    if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    }
}
fn scalar(
    op: ScalarOp,
    width: u16,
    input_width: u16,
    second_width: Option<u16>,
    args: &[u64],
) -> Option<u64> {
    use ScalarOp::*;
    let a = *args.first()?;
    let b = args.get(1).copied().unwrap_or(0);
    let result = match op {
        Move | ZeroExtend | Truncate | AddressCast | BitsCast => a,
        Add => a.wrapping_add(b),
        Subtract => a.wrapping_sub(b),
        Multiply => a.wrapping_mul(b),
        Divide { signed, remainder } => {
            let (quotient, rest) = division_oracle(input_width, args, signed)?;
            if remainder {
                rest
            } else {
                quotient
            }
        }
        DivideFault { signed } => u64::from(division_oracle(input_width, args, signed).is_none()),
        UnsignedMultiplyHigh | SignedMultiplyHigh => {
            // Separate shift-and-add oracle: do not reuse raw IR arithmetic.
            let mut product = 0u128;
            for bit in 0..input_width {
                if (b >> bit) & 1 != 0 {
                    product = product.wrapping_add(u128::from(a) << bit);
                }
            }
            let mut high = (product >> input_width) as u64;
            if matches!(op, SignedMultiplyHigh) {
                if a & (1u64 << (input_width - 1)) != 0 {
                    high = high.wrapping_sub(b);
                }
                if b & (1u64 << (input_width - 1)) != 0 {
                    high = high.wrapping_sub(a);
                }
            }
            high
        }
        And => a & b,
        Or => a | b,
        Xor => a ^ b,
        Complement => !a,
        ShiftLeft => {
            if b >= u64::from(input_width) {
                0
            } else {
                a << b
            }
        }
        ShiftRight => {
            if b >= u64::from(input_width) {
                0
            } else {
                a >> b
            }
        }
        Equal => u64::from(a == b),
        RotateLeft | RotateRight => {
            let mut result = a;
            for _ in 0..b % u64::from(width) {
                result = if matches!(op, RotateLeft) {
                    ((result << 1) | (result >> (width - 1))) & bitmask(width)
                } else {
                    (result >> 1) | ((result & 1) << (width - 1))
                };
            }
            result
        }
        UnsignedLess => u64::from(a < b),
        SignedLess => {
            let signed = |v: u64| ((v << (64 - input_width)) as i64) >> (64 - input_width);
            u64::from(signed(a) < signed(b))
        }
        SignExtend => {
            let signed = if input_width >= 64 {
                a as i64
            } else {
                ((a << (64 - input_width)) as i64) >> (64 - input_width)
            };
            signed as u64
        }
        Extract { offset } => a.checked_shr(u32::from(offset))?,
        Insert { offset } => {
            let insert_width = second_width?;
            if offset >= 64 || insert_width + offset > width {
                return None;
            }
            let mask = bitmask(insert_width) << offset;
            (a & !mask) | ((b << offset) & mask)
        }
        Select => {
            if a != 0 {
                b
            } else {
                *args.get(2)?
            }
        }
        Parity => u64::from((a & 255).count_ones() & 1 == 0),
    };
    Some(result & bitmask(width))
}

// Independent unsigned long division with signed magnitude conversion. It does
// not call the IR evaluator or use its host-wide division implementation.
fn division_oracle(width: u16, args: &[u64], signed: bool) -> Option<(u64, u64)> {
    let word_mask = bitmask(width);
    let pair_mask = if width == 64 {
        u128::MAX
    } else {
        (1u128 << (2 * width)) - 1
    };
    let raw = (u128::from(*args.first()?) << width) | u128::from(*args.get(1)?);
    let divisor = *args.get(2)?;
    if divisor == 0 {
        return None;
    }
    let negative_dividend = signed && (args[0] >> (width - 1)) != 0;
    let negative_divisor = signed && (divisor >> (width - 1)) != 0;
    let magnitude = if negative_dividend {
        raw.wrapping_neg() & pair_mask
    } else {
        raw
    };
    let denominator = u128::from(if negative_divisor {
        divisor.wrapping_neg() & word_mask
    } else {
        divisor
    });
    let (mut quotient, mut rest) = (0u128, 0u128);
    for bit in (0..2 * width).rev() {
        rest = (rest << 1) | ((magnitude >> bit) & 1);
        if rest >= denominator {
            rest -= denominator;
            quotient |= 1u128 << bit;
        }
    }
    let negative = negative_dividend != negative_divisor;
    let bound = if signed {
        (1u128 << (width - 1)) - u128::from(!negative)
    } else {
        u128::from(word_mask)
    };
    if quotient > bound {
        return None;
    }
    let quotient = if negative {
        quotient.wrapping_neg()
    } else {
        quotient
    };
    let rest = if negative_dividend {
        rest.wrapping_neg()
    } else {
        rest
    };
    Some((quotient as u64 & word_mask, rest as u64 & word_mask))
}

fn validate(function: &SemanticFunction) -> Result<(), String> {
    if function.version != VERSION
        || function.blocks.len() > crate::ir::MAX_IR_BLOCKS
        || function.nodes.len() > crate::ir::MAX_IR_OPERATIONS
        || function.values.len() > crate::ir::MAX_IR_OPERATIONS * 2
    {
        return Err("invalid or over-budget semantic program".into());
    }
    for (id, value) in function.values.iter().enumerate() {
        if value.id != id || !value.storage.valid() {
            return Err("invalid semantic value type/identity".into());
        }
    }
    for (id, node) in function.nodes.iter().enumerate() {
        if node.id != id
            || node.source >= function.sources.len()
            || node.output.is_some_and(|id| id >= function.values.len())
        {
            return Err("invalid semantic node reference".into());
        }
        for input in &node.inputs {
            match input {
                Input::Value(id) if *id >= function.values.len() => {
                    return Err("invalid semantic operand".into())
                }
                Input::Constant(value) if !value.valid() => {
                    return Err("invalid semantic constant".into())
                }
                _ => {}
            }
        }
        if let NodeKind::Scalar {
            operator: ScalarOp::Extract { offset } | ScalarOp::Insert { offset },
        } = node.kind
        {
            if offset >= 64 {
                return Err("invalid semantic bit offset".into());
            }
        }
    }
    Ok(())
}
