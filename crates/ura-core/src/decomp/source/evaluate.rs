//! Bounded executor of the reconstructed AST. Does not call either the raw IR
//! interpreter or semantic-HIR executor, and does not run inspected native code.
use super::*;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default)]
pub struct State {
    pub registers: BTreeMap<String, u64>,
    pub memory: BTreeMap<u64, u8>,
    pub trace: Vec<Address>,
    values: Vec<Option<u64>>,
    steps: usize,
    limit: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Exit {
    Return {
        result: Option<u64>,
        destination: Option<u64>,
    },
    External(Address),
    Indirect(Option<u64>),
}
enum Flow {
    Next,
    Goto(Address),
    Return(Exit),
    Break,
    Continue,
}
impl State {
    pub fn value(&self, id: VariableId) -> Option<u64> {
        self.values.get(id).copied().flatten()
    }
    pub fn run(&mut self, f: &Function, limit: usize) -> Result<Exit, String> {
        if limit == 0 || limit > 100_000 || f.version != VERSION {
            return Err("invalid C-like execution budget/version".into());
        }
        self.limit = limit;
        self.steps = 0;
        self.values = f
            .variables
            .iter()
            .enumerate()
            .map(|(id, v)| {
                if v.id != id || !v.storage.valid() {
                    return Err("invalid C-like variable".to_string());
                }
                Ok(v.entry_register
                    .as_ref()
                    .and_then(|r| self.registers.get(r).copied())
                    .map(|n| bits(n, v.storage)))
            })
            .collect::<Result<_, _>>()?;
        let labels: BTreeMap<_, _> = f
            .body
            .iter()
            .enumerate()
            .filter_map(|(i, s)| match s.kind {
                StatementKind::Label { address } => Some((address, i)),
                _ => None,
            })
            .collect();
        let mut start = 0;
        loop {
            match self.sequence(&f.body[start..], 0)? {
                Flow::Return(exit) => return Ok(exit),
                Flow::Goto(target) => match labels.get(&target) {
                    Some(index) => start = *index,
                    None => return Ok(Exit::External(target)),
                },
                Flow::Next => return Err("C-like function fell off its body".into()),
                _ => return Err("loop transfer outside loop".into()),
            }
        }
    }
    fn tick(&mut self) -> Result<(), String> {
        self.steps += 1;
        if self.steps > self.limit {
            Err("C-like execution operation budget exceeded".into())
        } else {
            Ok(())
        }
    }
    fn sequence(&mut self, body: &[Statement], depth: usize) -> Result<Flow, String> {
        if depth > 64 {
            return Err("C-like execution nesting budget exceeded".into());
        }
        for s in body {
            self.tick()?;
            let flow = match &s.kind {
                StatementKind::Assign { variable, value } => {
                    let value = self.expression(value, 0)?;
                    *self
                        .values
                        .get_mut(*variable)
                        .ok_or("invalid assignment variable")? = value;
                    Flow::Next
                }
                StatementKind::Store { address, value, .. } => {
                    let address = self
                        .expression(address, 0)?
                        .ok_or("unknown C-like memory address")?;
                    let number = self
                        .expression(value, 0)?
                        .ok_or("unknown C-like store value")?;
                    let width = value.storage.width().ok_or("invalid C-like store width")?;
                    for i in 0..width.div_ceil(8) {
                        self.memory.insert(
                            address
                                .checked_add(u64::from(i))
                                .ok_or("address overflow")?,
                            (number >> (8 * i)) as u8,
                        );
                    }
                    Flow::Next
                }
                StatementKind::Call { .. } => {
                    return Err("unknown call effects cannot be concretely executed".into())
                }
                StatementKind::Guard { condition, reason } => {
                    if self
                        .expression(condition, 0)?
                        .ok_or("unknown C-like fault condition")?
                        != 0
                    {
                        return Err(format!("machine fault: {reason}"));
                    }
                    Flow::Next
                }
                StatementKind::Unknown {
                    variable, memory, ..
                } => {
                    if *memory || variable.is_none() {
                        return Err("unknown memory effects cannot be concretely executed".into());
                    }
                    *self
                        .values
                        .get_mut(variable.unwrap())
                        .ok_or("invalid unknown variable")? = None;
                    Flow::Next
                }
                StatementKind::Block { address } => {
                    self.trace.push(*address);
                    Flow::Next
                }
                StatementKind::Label { .. } | StatementKind::Provenance => Flow::Next,
                StatementKind::Goto { target } => Flow::Goto(*target),
                StatementKind::If {
                    condition,
                    taken,
                    otherwise,
                } => {
                    let value = self
                        .expression(condition, 0)?
                        .ok_or("unknown C-like branch condition")?;
                    self.sequence(if value != 0 { taken } else { otherwise }, depth + 1)?
                }
                StatementKind::Loop { body } => loop {
                    self.tick()?;
                    match self.sequence(body, depth + 1)? {
                        Flow::Break => break Flow::Next,
                        Flow::Continue | Flow::Next => {}
                        other => break other,
                    }
                },
                StatementKind::Break => Flow::Break,
                StatementKind::Continue => Flow::Continue,
                StatementKind::Return {
                    result,
                    destination,
                } => Flow::Return(Exit::Return {
                    result: result
                        .as_ref()
                        .map(|e| self.expression(e, 0))
                        .transpose()?
                        .flatten(),
                    destination: destination
                        .as_ref()
                        .map(|e| self.expression(e, 0))
                        .transpose()?
                        .flatten(),
                }),
                StatementKind::Exit { destination, .. } => Flow::Return(Exit::Indirect(
                    destination
                        .as_ref()
                        .map(|e| self.expression(e, 0))
                        .transpose()?
                        .flatten(),
                )),
            };
            if !matches!(flow, Flow::Next) {
                return Ok(flow);
            }
        }
        Ok(Flow::Next)
    }
    fn expression(&mut self, e: &Expr, depth: usize) -> Result<Option<u64>, String> {
        self.tick()?;
        if depth > 64 || !e.storage.valid() {
            return Err("invalid C-like expression".into());
        }
        let result = match &e.kind {
            ExprKind::Variable { id } => *self
                .values
                .get(*id)
                .ok_or("invalid C-like expression variable")?,
            ExprKind::Parameter { register, .. } => self
                .registers
                .get(register)
                .copied()
                .map(|n| bits(n, e.storage)),
            ExprKind::Constant { constant } => {
                if !constant.valid() {
                    return Err("invalid C-like constant".into());
                }
                Some(constant.value.0)
            }
            ExprKind::Unknown { .. } => None,
            ExprKind::Load { address } => {
                let base = self
                    .expression(address, depth + 1)?
                    .ok_or("unknown C-like load address")?;
                let width = e.storage.width().ok_or("invalid C-like load width")?;
                let mut n = 0;
                for i in 0..width.div_ceil(8) {
                    n |= u64::from(
                        *self
                            .memory
                            .get(&base.checked_add(u64::from(i)).ok_or("address overflow")?)
                            .ok_or("unmapped C-like memory")?,
                    ) << (8 * i);
                }
                Some(n)
            }
            ExprKind::Scalar {
                operator: semantic::ScalarOp::Select,
                arguments,
            } => {
                let condition = self.expression(
                    arguments.first().ok_or("missing C-like select condition")?,
                    depth + 1,
                )?;
                match condition {
                    Some(value) => self.expression(
                        arguments
                            .get(if value != 0 { 1 } else { 2 })
                            .ok_or("missing C-like select arm")?,
                        depth + 1,
                    )?,
                    None => None,
                }
            }
            ExprKind::Scalar {
                operator,
                arguments,
            } => {
                let values: Option<Vec<_>> = arguments
                    .iter()
                    .map(|e| self.expression(e, depth + 1))
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .collect();
                match values {
                    Some(values) => self.scalar(*operator, e.storage, arguments, &values)?,
                    None => None,
                }
            }
        };
        Ok(result.map(|n| bits(n, e.storage)))
    }
    fn scalar(
        &self,
        op: semantic::ScalarOp,
        storage: Type,
        args: &[Expr],
        v: &[u64],
    ) -> Result<Option<u64>, String> {
        use semantic::ScalarOp as S;
        let Some(&a) = v.first() else {
            return Err("missing C-like scalar operand".into());
        };
        let b = v.get(1).copied().unwrap_or(0);
        let width = args
            .first()
            .and_then(|e| e.storage.width())
            .ok_or("invalid C-like scalar width")?;
        Ok(Some(match op {
            S::Move | S::AddressCast | S::BitsCast | S::Truncate | S::ZeroExtend => a,
            S::Add => ((u128::from(a) + u128::from(b)) & u128::from(u64::MAX)) as u64,
            S::Subtract => a.overflowing_sub(b).0,
            S::Multiply => a.overflowing_mul(b).0,
            S::Divide { signed, .. } | S::DivideFault { signed } => {
                let low = *v.get(1).ok_or("missing dividend low word")?;
                let divisor = *v.get(2).ok_or("missing divisor")?;
                let pair = (u128::from(a) << width) | u128::from(low);
                let parts = if signed {
                    let numerator = ((pair << (128 - 2 * width)) as i128) >> (128 - 2 * width);
                    let denominator = (i128::from(divisor) << (128 - width)) >> (128 - width);
                    numerator.checked_div(denominator).and_then(|q| {
                        let bound = 1i128 << (width - 1);
                        if q < -bound || q >= bound {
                            None
                        } else {
                            numerator
                                .checked_rem(denominator)
                                .map(|r| (q as u64, r as u64))
                        }
                    })
                } else {
                    pair.checked_div(u128::from(divisor)).and_then(|q| {
                        if q > u128::from(bits(u64::MAX, Type::Bits(width))) {
                            None
                        } else {
                            pair.checked_rem(u128::from(divisor))
                                .map(|r| (q as u64, r as u64))
                        }
                    })
                };
                match op {
                    S::DivideFault { .. } => u64::from(parts.is_none()),
                    S::Divide { remainder, .. } => match parts {
                        Some((q, r)) => {
                            if remainder {
                                r
                            } else {
                                q
                            }
                        }
                        None => return Ok(None),
                    },
                    _ => return Err("invalid divide operator".into()),
                }
            }
            S::UnsignedMultiplyHigh => ((u128::from(a) * u128::from(b)) >> width) as u64,
            S::SignedMultiplyHigh => {
                let sign = |v: u64| (i128::from(v) << (128 - width)) >> (128 - width);
                ((sign(a) * sign(b)) >> width) as u64
            }
            S::And => a & b,
            S::Or => a | b,
            S::Xor => a ^ b,
            S::Complement => !a,
            S::Equal => {
                if a == b {
                    1
                } else {
                    0
                }
            }
            S::UnsignedLess => {
                if a < b {
                    1
                } else {
                    0
                }
            }
            S::SignedLess => {
                let sign = |v: u64| (i128::from(v) << (128 - width)) >> (128 - width);
                u64::from(sign(a) < sign(b))
            }
            S::RotateLeft | S::RotateRight => {
                let count = (b % u64::from(width)) as u32;
                let wide = u128::from(a);
                if count == 0 {
                    a
                } else if matches!(op, S::RotateLeft) {
                    ((wide << count) | (wide >> (u32::from(width) - count))) as u64
                } else {
                    ((wide >> count) | (wide << (u32::from(width) - count))) as u64
                }
            }
            S::ShiftLeft => {
                if b >= u64::from(width) {
                    0
                } else {
                    a.wrapping_shl(b as u32)
                }
            }
            S::ShiftRight => {
                if b >= u64::from(width) {
                    0
                } else {
                    a.wrapping_shr(b as u32)
                }
            }
            S::SignExtend => {
                if width < 64 && a & (1u64 << (width - 1)) != 0 {
                    a | (!0u64 << width)
                } else {
                    a
                }
            }
            S::Extract { offset } => a
                .checked_shr(u32::from(offset))
                .ok_or("invalid C-like extract")?,
            S::Insert { offset } => {
                let size = args
                    .get(1)
                    .and_then(|e| e.storage.width())
                    .ok_or("invalid C-like insert")?;
                if size + offset > storage.width().unwrap_or(0) || offset >= 64 {
                    return Err("invalid C-like insert range".into());
                }
                let field = bits(u64::MAX, Type::Bits(size)) << offset;
                (a & !field) | ((b << offset) & field)
            }
            S::Select => {
                if a != 0 {
                    b
                } else {
                    *v.get(2).ok_or("missing C-like select arm")?
                }
            }
            S::Parity => {
                let mut x = a as u8;
                let mut count = 0;
                while x != 0 {
                    count += x & 1;
                    x >>= 1;
                }
                u64::from(count % 2 == 0)
            }
        }))
    }
}
fn bits(n: u64, ty: Type) -> u64 {
    match ty.width() {
        Some(1..=63) => n & ((1u64 << ty.width().unwrap()) - 1),
        _ => n,
    }
}
