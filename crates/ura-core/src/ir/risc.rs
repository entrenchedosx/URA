//! Architecture-specific scalar semantics over the shared typed IR.
use super::*;
use crate::{
    processor::{self, Arg, Decoded, Extend, Processor, ScalarArg, Shift},
    AnalysisControl, CodeImage, InstructionFlow, ProgramAnalysis,
};
use capstone::arch::arm64::Arm64Insn::*;
use std::collections::BTreeMap;
type Result<T> = std::result::Result<T, String>;
struct Builder {
    p: Processor,
    f: Function,
    roots: BTreeMap<String, usize>,
    arch: usize,
    memory: usize,
    source: Address,
    ops: Vec<Statement>,
    transfer: Option<Operand>,
    concrete: bool,
    predicate: Option<Operand>,
}
impl Builder {
    fn new(p: Processor, entry: u64, concrete: bool) -> Self {
        let mut vars = vec![];
        let mut roots = BTreeMap::new();
        for name in p.roots() {
            let flag = ["n", "z", "c", "v"].contains(&name.as_str());
            roots.insert(name.clone(), vars.len());
            vars.push(Variable {
                name,
                ty: Type::Bits(if flag { 1 } else { u16::from(p.bits()) }),
                kind: if flag {
                    VariableKind::Flag
                } else {
                    VariableKind::Register
                },
            });
        }
        let memory = vars.len();
        vars.push(Variable {
            name: "memory".into(),
            ty: Type::Memory,
            kind: VariableKind::Memory,
        });
        let arch = vars.len();
        Self {
            p,
            f: Function {
                ir_version: IR_VERSION,
                entry: Address(entry),
                address_width: u16::from(p.bits()),
                variables: vars,
                blocks: vec![],
                diagnostics: vec![],
                source_instructions: 0,
            },
            roots,
            arch,
            memory,
            source: Address(entry),
            ops: vec![],
            transfer: None,
            concrete,
            predicate: None,
        }
    }
    fn k(w: u16, n: u64) -> Operand {
        Operand::Constant(Constant::bits(w, n))
    }
    fn width(&self, v: Operand) -> u16 {
        self.f.operand_type(v).unwrap().width().unwrap()
    }
    fn emit(&mut self, ty: Type, op: Operation, args: Vec<Operand>) -> Operand {
        let id = self.f.variables.len();
        self.f.variables.push(Variable {
            name: format!("t{id}"),
            ty,
            kind: VariableKind::Temporary,
        });
        self.ops.push(Statement {
            source: self.source,
            output: Some(id),
            op,
            args,
        });
        Operand::Variable(id)
    }
    fn op(&mut self, op: Operation, a: Operand, b: Operand) -> Operand {
        let w = self.width(a);
        self.emit(Type::Bits(w), op, vec![a, b])
    }
    fn cmp(&mut self, op: Operation, a: Operand, b: Operand) -> Operand {
        self.emit(Type::Bits(1), op, vec![a, b])
    }
    fn not(&mut self, v: Operand) -> Operand {
        self.emit(Type::Bits(self.width(v)), Operation::Not, vec![v])
    }
    fn cast(&mut self, v: Operand, w: u16, signed: bool) -> Operand {
        let old = self.width(v);
        if old == w {
            v
        } else {
            self.emit(
                Type::Bits(w),
                if w < old {
                    Operation::Truncate
                } else if signed {
                    Operation::SignExtend
                } else {
                    Operation::ZeroExtend
                },
                vec![v],
            )
        }
    }
    fn set(&mut self, id: usize, v: Operand) {
        let v = if let Some(c) = self.predicate {
            self.select(c, v, Operand::Variable(id))
        } else {
            v
        };
        self.ops.push(Statement {
            source: self.source,
            output: Some(id),
            op: Operation::Copy,
            args: vec![v],
        });
    }
    fn select(&mut self, c: Operand, a: Operand, b: Operand) -> Operand {
        self.emit(Type::Bits(self.width(a)), Operation::Select, vec![c, a, b])
    }
    fn reg(&self, name: &str) -> Result<Operand> {
        if name == "xzr" {
            return Ok(Self::k(64, 0));
        }
        if name == "wzr" {
            return Ok(Self::k(32, 0));
        }
        if name == "zero" {
            return Ok(Self::k(u16::from(self.p.bits()), 0));
        }
        self.roots
            .get(name)
            .copied()
            .map(Operand::Variable)
            .ok_or_else(|| format!("scalar register {name} unsupported"))
    }
    fn read_reg(&mut self, name: &str) -> Result<Operand> {
        if self.p == Processor::Aarch64 && (name.starts_with('w') && name != "wzr") {
            let root = if name == "wsp" {
                "sp".into()
            } else {
                format!("x{}", &name[1..])
            };
            let v = self.reg(&root)?;
            return Ok(self.cast(v, 32, false));
        }
        if matches!(self.p, Processor::Arm | Processor::Thumb) && name == "r15" {
            return Ok(Self::k(
                32,
                self.source.0 + if self.p == Processor::Thumb { 4 } else { 8 },
            ));
        }
        self.reg(name)
    }
    fn write(&mut self, name: &str, v: Operand) -> Result<()> {
        if matches!(name, "xzr" | "wzr" | "zero") {
            return Ok(());
        }
        let root = if self.p == Processor::Aarch64 && name.starts_with('w') {
            if name == "wsp" {
                "sp".into()
            } else {
                format!("x{}", &name[1..])
            }
        } else {
            name.into()
        };
        let id = *self
            .roots
            .get(&root)
            .ok_or_else(|| format!("write to unsupported scalar register {name}"))?;
        let w = self.f.variables[id].ty.width().unwrap();
        let v = self.cast(v, w, false);
        self.set(id, v);
        Ok(())
    }
    fn reg_name(d: &Decoded, i: usize) -> Result<&str> {
        match d.args.get(i).map(|a| &a.value) {
            Some(Arg::Reg(r)) => Ok(r),
            _ => Err("register operand required".into()),
        }
    }
    fn root_name(name: &str) -> String {
        if let Some(n) = name.strip_prefix('w') {
            if n == "sp" {
                "sp".into()
            } else {
                format!("x{n}")
            }
        } else {
            name.into()
        }
    }
    fn dest_width(&self, d: &Decoded) -> Result<u16> {
        let r = Self::reg_name(d, 0)?;
        Ok(if self.p == Processor::Aarch64 && r.starts_with('w') {
            32
        } else {
            u16::from(self.p.bits())
        })
    }
    fn arg(&mut self, a: &ScalarArg, w: u16) -> Result<Operand> {
        let mut v = match &a.value {
            Arg::Reg(r) => self.read_reg(r)?,
            Arg::Imm(n) => Self::k(w, *n as u64),
            _ => return Err("scalar register/immediate operand required".into()),
        };
        match a.extend {
            Extend::None => {}
            Extend::Unsigned(n) => {
                v = self.cast(v, n, false);
                v = self.cast(v, w, false);
            }
            Extend::Signed(n) => {
                v = self.cast(v, n, false);
                v = self.cast(v, w, true);
            }
            Extend::Unsupported => return Err("operand extension is unsupported".into()),
        }
        v = self.cast(v, w, false);
        self.shift(v, a.shift)
    }
    fn read(&mut self, d: &Decoded, i: usize, w: u16) -> Result<Operand> {
        self.arg(d.args.get(i).ok_or("missing operand")?, w)
    }
    fn shift(&mut self, v: Operand, s: Shift) -> Result<Operand> {
        let w = self.width(v);
        let n = match s {
            Shift::None => return Ok(v),
            Shift::Lsl(n) | Shift::Lsr(n) | Shift::Asr(n) | Shift::Ror(n) => n,
            Shift::Unsupported => return Err("shift form unsupported".into()),
        };
        if n >= u32::from(w) {
            return Err("shift exceeds scalar width".into());
        }
        let k = Self::k(w, u64::from(n));
        Ok(match s {
            Shift::Lsl(_) => self.op(Operation::Shl, v, k),
            Shift::Lsr(_) => self.op(Operation::Shr, v, k),
            Shift::Ror(_) => self.op(Operation::RotateRight, v, k),
            Shift::Asr(_) => self.sar(v, k),
            _ => unreachable!(),
        })
    }
    fn sar(&mut self, v: Operand, count: Operand) -> Operand {
        let w = self.width(v);
        let sign = self.op(Operation::Shr, v, Self::k(w, u64::from(w - 1)));
        let fill = self.op(Operation::Sub, Self::k(w, 0), sign);
        let inverted = self.op(Operation::Xor, v, fill);
        let shifted = self.op(Operation::Shr, inverted, count);
        self.op(Operation::Xor, shifted, fill)
    }
    fn flag(&self, name: &str) -> Operand {
        Operand::Variable(self.roots[name])
    }
    fn flags(&mut self, a: Operand, b: Operand, result: Operand, sub: bool, logical: bool) {
        let w = self.width(result);
        let z = self.cmp(Operation::Equal, result, Self::k(w, 0));
        let n0 = self.op(Operation::Shr, result, Self::k(w, u64::from(w - 1)));
        let n = self.cast(n0, 1, false);
        let (c, v) = if logical {
            if self.p == Processor::Aarch64 {
                (Self::k(1, 0), Self::k(1, 0))
            } else {
                (self.flag("c"), self.flag("v"))
            }
        } else {
            let c = if sub {
                let less = self.cmp(Operation::UnsignedLess, a, b);
                self.op(Operation::Xor, less, Self::k(1, 1))
            } else {
                self.cmp(Operation::UnsignedLess, result, a)
            };
            let axb = self.op(Operation::Xor, a, b);
            let axr = self.op(Operation::Xor, a, result);
            let axb = if sub { axb } else { self.not(axb) };
            let ov = self.op(Operation::And, axb, axr);
            let ov = self.op(Operation::Shr, ov, Self::k(w, u64::from(w - 1)));
            (c, self.cast(ov, 1, false))
        };
        for (name, value) in [("n", n), ("z", z), ("c", c), ("v", v)] {
            self.set(self.roots[name], value);
        }
    }
    fn condition(&mut self, c: u8) -> Result<Operand> {
        let n = self.flag("n");
        let z = self.flag("z");
        let carry = self.flag("c");
        let v = self.flag("v");
        let inv = |b: &mut Self, x| b.op(Operation::Xor, x, Self::k(1, 1));
        Ok(match c {
            0 | 15 | 16 => Self::k(1, 1),
            1 => z,
            2 => inv(self, z),
            3 => carry,
            4 => inv(self, carry),
            5 => n,
            6 => inv(self, n),
            7 => v,
            8 => inv(self, v),
            9 => {
                let nz = inv(self, z);
                self.op(Operation::And, carry, nz)
            }
            10 => {
                let nc = inv(self, carry);
                self.op(Operation::Or, nc, z)
            }
            11 => self.cmp(Operation::Equal, n, v),
            12 => self.op(Operation::Xor, n, v),
            13 => {
                let eq = self.cmp(Operation::Equal, n, v);
                let nz = inv(self, z);
                self.op(Operation::And, eq, nz)
            }
            14 => {
                let nv = self.op(Operation::Xor, n, v);
                self.op(Operation::Or, z, nv)
            }
            _ => return Err("condition encoding unsupported".into()),
        })
    }
    fn address(&mut self, d: &Decoded, i: usize) -> Result<(Operand, Option<(String, Operand)>)> {
        let a = d.args.get(i).ok_or("missing memory operand")?;
        if let Arg::Imm(n) = a.value {
            return Ok((Self::k(u16::from(self.p.bits()), n as u64), None));
        }
        let Arg::Mem { base, index, disp } = &a.value else {
            return Err("memory operand required".into());
        };
        let w = u16::from(self.p.bits());
        let mut baseval = self.read_reg(base)?;
        if self.p == Processor::Thumb && base == "r15" {
            baseval = self.op(Operation::And, baseval, Self::k(w, !3));
        }
        if self.p == Processor::Aarch64 && base == "sp" {
            let low = self.op(Operation::And, baseval, Self::k(w, 15));
            let ok = self.cmp(Operation::Equal, low, Self::k(w, 0));
            let bad = self.op(Operation::Xor, ok, Self::k(1, 1));
            self.ops.push(Statement {
                source: self.source,
                output: None,
                op: Operation::Guard {
                    reason: "misaligned AArch64 stack pointer".into(),
                },
                args: vec![bad],
            });
        }
        let mut offset = Self::k(w, *disp as u64);
        if !index.is_empty() {
            let ia = ScalarArg {
                value: Arg::Reg(index.clone()),
                shift: a.shift,
                extend: a.extend,
            };
            let ix = self.arg(&ia, w)?;
            offset = self.op(Operation::Add, offset, ix);
        }
        let address = self.op(Operation::Add, baseval, offset);
        let wb = if d.writeback {
            let next = if let Some(offset) = d.args.get(i + 1) {
                let offset = self.arg(offset, w)?;
                self.op(Operation::Add, baseval, offset)
            } else {
                address
            };
            Some((base.clone(), next))
        } else {
            None
        };
        Ok((address, wb))
    }
    fn load(&mut self, address: Operand, w: u16) -> Operand {
        let a = self.emit(
            Type::Address(u16::from(self.p.bits())),
            Operation::ToAddress,
            vec![address],
        );
        self.emit(
            Type::Bits(w),
            Operation::Load,
            vec![Operand::Variable(self.memory), a],
        )
    }
    fn store(&mut self, address: Operand, value: Operand) {
        let a = self.emit(
            Type::Address(u16::from(self.p.bits())),
            Operation::ToAddress,
            vec![address],
        );
        self.ops.push(Statement {
            source: self.source,
            output: Some(self.memory),
            op: Operation::Store,
            args: vec![Operand::Variable(self.memory), a, value],
        });
    }
    fn call(&mut self, target: Operand, _next: u64) -> Result<()> {
        self.transfer = Some(target);
        if !self.concrete {
            let call_target = self.emit(
                Type::Address(u16::from(self.p.bits())),
                Operation::ToAddress,
                vec![target],
            );
            let mut values = vec![call_target];
            values.extend((0..self.arch).map(Operand::Variable));
            self.ops.push(Statement {
                source: self.source,
                output: None,
                op: Operation::Call,
                args: values,
            });
            // A call's memory and caller-saved state are unknown, never guessed preserved.
            let names = self.roots.keys().cloned().collect::<Vec<_>>();
            for name in names {
                let saved = match self.p {
                    Processor::Aarch64 => {
                        name == "sp"
                            || name
                                .strip_prefix('x')
                                .and_then(|n| n.parse::<u8>().ok())
                                .is_some_and(|n| (19..=29).contains(&n))
                    }
                    Processor::Arm | Processor::Thumb => name
                        .strip_prefix('r')
                        .and_then(|n| n.parse::<u8>().ok())
                        .is_some_and(|n| ((4..=11).contains(&n) && n != 9) || n == 13),
                    _ => name == "sp" || name.starts_with('s'),
                };
                if !saved {
                    let id = self.roots[&name];
                    self.ops.push(Statement {
                        source: self.source,
                        output: Some(id),
                        op: Operation::Unknown {
                            reason: "ABI caller-saved value after call".into(),
                        },
                        args: vec![],
                    });
                }
            }
            self.ops.push(Statement {
                source: self.source,
                output: Some(self.memory),
                op: Operation::Unknown {
                    reason: "callee memory effects".into(),
                },
                args: vec![],
            });
        }
        Ok(())
    }
    fn instruction(&mut self, d: &Decoded) -> Result<CpuFlow> {
        self.source = Address(d.address);
        self.transfer = None;
        match self.p {
            Processor::Aarch64 => self.arm64(d),
            Processor::Riscv32 | Processor::Riscv64 => self.riscv(d),
            Processor::Arm | Processor::Thumb => self.arm32(d),
            _ => Err("processor scalar semantics pending".into()),
        }
    }
    fn arm32(&mut self, d: &Decoded) -> Result<CpuFlow> {
        use capstone::arch::arm::ArmInsn::*;
        let id = d.id;
        let k = Self::k;
        if [ARM_INS_IT as u32, ARM_INS_BLX as u32].contains(&id)
            || d.flow == InstructionFlow::Exception
        {
            return Err(
                "ARM IT/interworking/system semantics unsupported; analysis stops at this boundary"
                    .into(),
            );
        }
        if id == ARM_INS_NOP as u32 || (id == ARM_INS_HINT as u32 && d.arm_hint_nop) {
            return Ok(CpuFlow::Next);
        }
        if d.flow == InstructionFlow::ConditionalJump {
            let c = if [ARM_INS_CBZ as u32, ARM_INS_CBNZ as u32].contains(&id) {
                let v = self.read(d, 0, 32)?;
                let c = self.cmp(Operation::Equal, v, k(32, 0));
                if id == ARM_INS_CBNZ as u32 {
                    self.op(Operation::Xor, c, k(1, 1))
                } else {
                    c
                }
            } else {
                self.condition(d.condition)?
            };
            self.transfer = Some(c);
            return Ok(CpuFlow::Branch);
        }
        let pred = !matches!(d.condition, 0 | 15);
        self.predicate = None;
        if pred {
            if ![
                ARM_INS_MOV as u32,
                ARM_INS_ADD as u32,
                ARM_INS_SUB as u32,
                ARM_INS_AND as u32,
                ARM_INS_ORR as u32,
                ARM_INS_EOR as u32,
                ARM_INS_CMP as u32,
            ]
            .contains(&id)
            {
                return Err("predicated ARM instruction form unsupported".into());
            }
            let c = self.condition(d.condition)?;
            self.predicate = Some(self.emit(Type::Bits(1), Operation::Copy, vec![c]));
        }
        let result = self.arm32_body(d);
        self.predicate = None;
        result
    }
    fn arm32_body(&mut self, d: &Decoded) -> Result<CpuFlow> {
        use capstone::arch::arm::ArmInsn::*;
        let id = d.id;
        let k = Self::k;
        if d.flow == InstructionFlow::Call {
            self.call(
                k(32, d.target.ok_or("ARM call target absent")?),
                d.address + d.length as u64,
            )?;
            return Ok(CpuFlow::Call);
        }
        if id == ARM_INS_BX as u32 {
            let target = self.read(d, 0, 32)?;
            self.arm_target(target)?;
            return Ok(if d.flow == InstructionFlow::Return {
                CpuFlow::Return
            } else {
                CpuFlow::Jump
            });
        }
        if d.flow == InstructionFlow::Jump {
            self.transfer = Some(k(32, d.target.ok_or("ARM branch target absent")?));
            return Ok(CpuFlow::Jump);
        }
        if [ARM_INS_PUSH as u32, ARM_INS_POP as u32].contains(&id) {
            let pop = id == ARM_INS_POP as u32;
            let sp = self.reg("r13")?;
            let count = d.args.len();
            if count == 0 || count > 15 {
                return Err("invalid ARM register list".into());
            }
            let base = if pop {
                self.emit(Type::Bits(32), Operation::Copy, vec![sp])
            } else {
                self.op(Operation::Sub, sp, k(32, (count * 4) as u64))
            };
            // Snapshot the original base before any loaded register can change.
            let mut values = vec![];
            for i in 0..count {
                let name = Self::reg_name(d, i)?;
                if name == "r13" || (!pop && name == "r15") {
                    return Err("unpredictable ARM stack register list".into());
                }
                let a = self.op(Operation::Add, base, k(32, (i * 4) as u64));
                if pop {
                    let value = self.load(a, 32);
                    values.push((name.to_string(), value));
                } else {
                    let value = self.read(d, i, 32)?;
                    self.store(a, value);
                }
            }
            let next = if pop {
                self.op(Operation::Add, base, k(32, (count * 4) as u64))
            } else {
                base
            };
            self.write("r13", next)?;
            let mut returns = false;
            for (name, value) in values {
                if name == "r15" {
                    self.arm_target(value)?;
                    returns = true;
                } else {
                    self.write(&name, value)?;
                }
            }
            return Ok(if returns {
                CpuFlow::Return
            } else {
                CpuFlow::Next
            });
        }
        let dest = || Self::reg_name(d, 0);
        if [
            ARM_INS_MOV as u32,
            ARM_INS_MOVW as u32,
            ARM_INS_MOVT as u32,
            ARM_INS_MVN as u32,
        ]
        .contains(&id)
        {
            if dest()? == "r15" {
                return Err("ARM PC assignment form unsupported".into());
            }
            let mut value = self.read(d, 1, 32)?;
            if id == ARM_INS_MOVT as u32 {
                let old = self.read(d, 0, 32)?;
                let old = self.op(Operation::And, old, k(32, 0xffff));
                value = self.op(Operation::Shl, value, k(32, 16));
                value = self.op(Operation::Or, old, value);
            } else if id == ARM_INS_MVN as u32 {
                value = self.not(value);
            }
            if d.flags {
                self.arm_logical_flags(d, value)?;
            }
            self.write(dest()?, value)?;
        } else if [
            ARM_INS_ADD as u32,
            ARM_INS_SUB as u32,
            ARM_INS_RSB as u32,
            ARM_INS_CMP as u32,
            ARM_INS_CMN as u32,
        ]
        .contains(&id)
        {
            let compare = [ARM_INS_CMP as u32, ARM_INS_CMN as u32].contains(&id);
            let short = d.args.len() == 2 && !compare;
            let ai = if compare || short { 0 } else { 1 };
            let bi = if compare || short { 1 } else { 2 };
            let mut a = self.read(d, ai, 32)?;
            let mut b = self.read(d, bi, 32)?;
            if id == ARM_INS_RSB as u32 {
                std::mem::swap(&mut a, &mut b);
            }
            let sub = [ARM_INS_SUB as u32, ARM_INS_RSB as u32, ARM_INS_CMP as u32].contains(&id);
            let r = self.op(if sub { Operation::Sub } else { Operation::Add }, a, b);
            if d.flags || compare {
                self.flags(a, b, r, sub, false);
            }
            if !compare {
                if dest()? == "r15" {
                    return Err("ARM PC assignment unsupported".into());
                }
                self.write(dest()?, r)?;
            }
        } else if [
            ARM_INS_AND as u32,
            ARM_INS_ORR as u32,
            ARM_INS_EOR as u32,
            ARM_INS_BIC as u32,
            ARM_INS_TST as u32,
        ]
        .contains(&id)
        {
            let test = id == ARM_INS_TST as u32;
            let short = d.args.len() == 2 && !test;
            let a = self.read(d, if test || short { 0 } else { 1 }, 32)?;
            let mut b = self.read(d, if test || short { 1 } else { 2 }, 32)?;
            if id == ARM_INS_BIC as u32 {
                b = self.not(b);
            }
            let r = self.op(
                if id == ARM_INS_ORR as u32 {
                    Operation::Or
                } else if id == ARM_INS_EOR as u32 {
                    Operation::Xor
                } else {
                    Operation::And
                },
                a,
                b,
            );
            if d.flags || test {
                self.arm_logical_flags(d, r)?;
            }
            if !test {
                self.write(dest()?, r)?;
            }
        } else if [ARM_INS_LSL as u32, ARM_INS_LSR as u32, ARM_INS_ASR as u32].contains(&id) {
            if d.flags {
                return Err("flag-setting ARM standalone shift carry semantics unsupported".into());
            }
            let short = d.args.len() == 2;
            let a = self.read(d, if short { 0 } else { 1 }, 32)?;
            let c = self.read(d, if short { 1 } else { 2 }, 32)?;
            let c = self.op(Operation::And, c, k(32, 255));
            let r = if id == ARM_INS_ASR as u32 {
                let less = self.cmp(Operation::UnsignedLess, c, k(32, 32));
                let c = self.select(less, c, k(32, 31));
                self.sar(a, c)
            } else {
                let shifted = self.op(
                    if id == ARM_INS_LSL as u32 {
                        Operation::Shl
                    } else {
                        Operation::Shr
                    },
                    a,
                    c,
                );
                let less = self.cmp(Operation::UnsignedLess, c, k(32, 32));
                self.select(less, shifted, k(32, 0))
            };
            self.write(dest()?, r)?;
        } else if [ARM_INS_MUL as u32, ARM_INS_MLA as u32].contains(&id) {
            if d.flags {
                return Err("flag-setting ARM multiply unsupported".into());
            }
            let short = d.args.len() == 2;
            let a = self.read(d, if short { 0 } else { 1 }, 32)?;
            let b = self.read(d, if short { 1 } else { 2 }, 32)?;
            let mut r = self.op(Operation::Mul, a, b);
            if id == ARM_INS_MLA as u32 {
                let c = self.read(d, 3, 32)?;
                r = self.op(Operation::Add, r, c);
            }
            self.write(dest()?, r)?;
        } else if [
            ARM_INS_LDR as u32,
            ARM_INS_LDRB as u32,
            ARM_INS_LDRH as u32,
            ARM_INS_LDRSB as u32,
            ARM_INS_LDRSH as u32,
            ARM_INS_STR as u32,
            ARM_INS_STRB as u32,
            ARM_INS_STRH as u32,
        ]
        .contains(&id)
        {
            if dest()? == "r15" {
                return Err("ARM load to PC interworking unsupported".into());
            }
            let mw = if [
                ARM_INS_LDRB as u32,
                ARM_INS_LDRSB as u32,
                ARM_INS_STRB as u32,
            ]
            .contains(&id)
            {
                8
            } else if [
                ARM_INS_LDRH as u32,
                ARM_INS_LDRSH as u32,
                ARM_INS_STRH as u32,
            ]
            .contains(&id)
            {
                16
            } else {
                32
            };
            let (address, wb) = self.address(d, 1)?;
            if wb
                .as_ref()
                .is_some_and(|(base, _)| Some(base.as_str()) == dest().ok())
            {
                return Err("ARM writeback overlaps transfer register".into());
            }
            if [ARM_INS_STR as u32, ARM_INS_STRB as u32, ARM_INS_STRH as u32].contains(&id) {
                let v = self.read(d, 0, mw)?;
                self.store(address, v);
            } else {
                let v = self.load(address, mw);
                let v = self.cast(
                    v,
                    32,
                    [ARM_INS_LDRSB as u32, ARM_INS_LDRSH as u32].contains(&id),
                );
                self.write(dest()?, v)?;
            }
            if let Some((base, next)) = wb {
                self.write(&base, next)?;
            }
        } else {
            return Err(format!("ARM scalar semantics unsupported: {}", d.mnemonic));
        }
        Ok(CpuFlow::Next)
    }
    fn arm_logical_flags(&mut self, d: &Decoded, value: Operand) -> Result<()> {
        // The verified initial subset preserves C/V only for unshifted register
        // operands and Thumb narrow immediates. Other shifter-carry forms fault.
        if d.args.iter().any(|a| a.shift != Shift::None)
            || d.args.iter().any(|a| matches!(a.value, Arg::Imm(_)))
                && !(self.p == Processor::Thumb && d.length == 2)
        {
            return Err("ARM modified-immediate/shifter carry effects unsupported".into());
        }
        self.flags(value, Self::k(32, 0), value, false, true);
        Ok(())
    }
    fn arm_target(&mut self, target: Operand) -> Result<()> {
        let low = self.op(Operation::And, target, Self::k(32, 1));
        let expected = Self::k(32, u64::from(self.p == Processor::Thumb));
        let matches = self.cmp(Operation::Equal, low, expected);
        let root = self.cmp(Operation::Equal, target, Self::k(32, 0));
        let allowed = self.op(Operation::Or, matches, root);
        let bad = self.op(Operation::Xor, allowed, Self::k(1, 1));
        self.ops.push(Statement {
            source: self.source,
            output: None,
            op: Operation::Guard {
                reason: "ARM/Thumb mode transition unsupported".into(),
            },
            args: vec![bad],
        });
        self.transfer = Some(self.op(Operation::And, target, Self::k(32, !1)));
        Ok(())
    }
    fn riscv(&mut self, d: &Decoded) -> Result<CpuFlow> {
        use capstone::arch::riscv::RiscVInsn::*;
        if d.length != 4 {
            return Err("RISC-V compressed instruction semantics unsupported".into());
        }
        let id = d.id;
        let w = u16::from(self.p.bits());
        let k = Self::k;
        if d.flow == InstructionFlow::Exception {
            return Err("RISC-V system/CSR effects unsupported; no host syscall".into());
        }
        if [RISCV_INS_JAL as u32, RISCV_INS_JALR as u32].contains(&id) {
            let dest = Self::reg_name(d, 0)?;
            if dest != "zero" && dest != "ra" {
                return Err("RISC-V alternate link register transfers unsupported".into());
            }
            let target = if id == RISCV_INS_JAL as u32 {
                k(w, d.target.ok_or("missing JAL target")?)
            } else {
                let base = self.read(d, 1, w)?;
                let offset = self.read(d, 2, w)?;
                let sum = self.op(Operation::Add, base, offset);
                self.op(Operation::And, sum, k(w, !1))
            };
            if dest == "ra" {
                self.call(target, d.address + 4)?;
                return Ok(CpuFlow::Call);
            }
            self.transfer = Some(target);
            return Ok(if d.flow == InstructionFlow::Return {
                CpuFlow::Return
            } else {
                CpuFlow::Jump
            });
        }
        if d.flow == InstructionFlow::ConditionalJump {
            let a = self.read(d, 0, w)?;
            let b = self.read(d, 1, w)?;
            let (op, invert) = if [RISCV_INS_BEQ as u32, RISCV_INS_BNE as u32].contains(&id) {
                (Operation::Equal, id == RISCV_INS_BNE as u32)
            } else if [RISCV_INS_BLT as u32, RISCV_INS_BGE as u32].contains(&id) {
                (Operation::SignedLess, id == RISCV_INS_BGE as u32)
            } else if [RISCV_INS_BLTU as u32, RISCV_INS_BGEU as u32].contains(&id) {
                (Operation::UnsignedLess, id == RISCV_INS_BGEU as u32)
            } else {
                return Err("unsupported RISC-V branch".into());
            };
            let mut c = self.cmp(op, a, b);
            if invert {
                c = self.op(Operation::Xor, c, k(1, 1));
            }
            self.transfer = Some(c);
            return Ok(CpuFlow::Branch);
        }
        let dest = || Self::reg_name(d, 0);
        if [RISCV_INS_LUI as u32, RISCV_INS_AUIPC as u32].contains(&id) {
            let imm = self.read(d, 1, w)?;
            let imm = self.op(Operation::Shl, imm, k(w, 12));
            let imm = self.cast(imm, 32, false);
            let mut v = self.cast(imm, w, true);
            if id == RISCV_INS_AUIPC as u32 {
                v = self.op(Operation::Add, v, k(w, d.address));
            }
            self.write(dest()?, v)?;
        } else if [
            RISCV_INS_LB as u32,
            RISCV_INS_LBU as u32,
            RISCV_INS_LH as u32,
            RISCV_INS_LHU as u32,
            RISCV_INS_LW as u32,
            RISCV_INS_LWU as u32,
            RISCV_INS_LD as u32,
            RISCV_INS_SB as u32,
            RISCV_INS_SH as u32,
            RISCV_INS_SW as u32,
            RISCV_INS_SD as u32,
        ]
        .contains(&id)
        {
            let mw = if [
                RISCV_INS_LB as u32,
                RISCV_INS_LBU as u32,
                RISCV_INS_SB as u32,
            ]
            .contains(&id)
            {
                8
            } else if [
                RISCV_INS_LH as u32,
                RISCV_INS_LHU as u32,
                RISCV_INS_SH as u32,
            ]
            .contains(&id)
            {
                16
            } else if [
                RISCV_INS_LW as u32,
                RISCV_INS_LWU as u32,
                RISCV_INS_SW as u32,
            ]
            .contains(&id)
            {
                32
            } else {
                64
            };
            if mw > w {
                return Err("memory width exceeds processor mode".into());
            }
            let (address, _) = self.address(d, 1)?;
            let low = self.op(Operation::And, address, k(w, u64::from(mw / 8 - 1)));
            let bad = self.cmp(Operation::Equal, low, k(w, 0));
            let bad = self.op(Operation::Xor, bad, k(1, 1));
            self.ops.push(Statement {
                source: self.source,
                output: None,
                op: Operation::Guard {
                    reason: "misaligned RISC-V scalar access is unsupported".into(),
                },
                args: vec![bad],
            });
            if [
                RISCV_INS_SB as u32,
                RISCV_INS_SH as u32,
                RISCV_INS_SW as u32,
                RISCV_INS_SD as u32,
            ]
            .contains(&id)
            {
                let v = self.read(d, 0, mw)?;
                self.store(address, v);
            } else {
                let v = self.load(address, mw);
                let signed = ![
                    RISCV_INS_LBU as u32,
                    RISCV_INS_LHU as u32,
                    RISCV_INS_LWU as u32,
                ]
                .contains(&id);
                let v = self.cast(v, w, signed);
                self.write(dest()?, v)?;
            }
        } else {
            let word = [
                RISCV_INS_ADDW as u32,
                RISCV_INS_ADDIW as u32,
                RISCV_INS_SUBW as u32,
                RISCV_INS_SLLW as u32,
                RISCV_INS_SLLIW as u32,
                RISCV_INS_SRLW as u32,
                RISCV_INS_SRLIW as u32,
                RISCV_INS_SRAW as u32,
                RISCV_INS_SRAIW as u32,
            ]
            .contains(&id);
            if word && w != 64 {
                return Err("RV64 word operation in RV32 mode".into());
            }
            let n = if word { 32 } else { w };
            let a = self.read(d, 1, n)?;
            let b = self.read(d, 2, n)?;
            let v = if [
                RISCV_INS_ADD as u32,
                RISCV_INS_ADDI as u32,
                RISCV_INS_ADDW as u32,
                RISCV_INS_ADDIW as u32,
            ]
            .contains(&id)
            {
                self.op(Operation::Add, a, b)
            } else if [RISCV_INS_SUB as u32, RISCV_INS_SUBW as u32].contains(&id) {
                self.op(Operation::Sub, a, b)
            } else if [RISCV_INS_AND as u32, RISCV_INS_ANDI as u32].contains(&id) {
                self.op(Operation::And, a, b)
            } else if [RISCV_INS_OR as u32, RISCV_INS_ORI as u32].contains(&id) {
                self.op(Operation::Or, a, b)
            } else if [RISCV_INS_XOR as u32, RISCV_INS_XORI as u32].contains(&id) {
                self.op(Operation::Xor, a, b)
            } else if [
                RISCV_INS_SLT as u32,
                RISCV_INS_SLTI as u32,
                RISCV_INS_SLTU as u32,
                RISCV_INS_SLTIU as u32,
            ]
            .contains(&id)
            {
                let op = if [RISCV_INS_SLT as u32, RISCV_INS_SLTI as u32].contains(&id) {
                    Operation::SignedLess
                } else {
                    Operation::UnsignedLess
                };
                let c = self.cmp(op, a, b);
                self.cast(c, n, false)
            } else if [
                RISCV_INS_SLL as u32,
                RISCV_INS_SLLI as u32,
                RISCV_INS_SLLW as u32,
                RISCV_INS_SLLIW as u32,
                RISCV_INS_SRL as u32,
                RISCV_INS_SRLI as u32,
                RISCV_INS_SRLW as u32,
                RISCV_INS_SRLIW as u32,
                RISCV_INS_SRA as u32,
                RISCV_INS_SRAI as u32,
                RISCV_INS_SRAW as u32,
                RISCV_INS_SRAIW as u32,
            ]
            .contains(&id)
            {
                let c = self.op(Operation::And, b, k(n, u64::from(n - 1)));
                if [
                    RISCV_INS_SRA as u32,
                    RISCV_INS_SRAI as u32,
                    RISCV_INS_SRAW as u32,
                    RISCV_INS_SRAIW as u32,
                ]
                .contains(&id)
                {
                    self.sar(a, c)
                } else {
                    self.op(
                        if [
                            RISCV_INS_SLL as u32,
                            RISCV_INS_SLLI as u32,
                            RISCV_INS_SLLW as u32,
                            RISCV_INS_SLLIW as u32,
                        ]
                        .contains(&id)
                        {
                            Operation::Shl
                        } else {
                            Operation::Shr
                        },
                        a,
                        c,
                    )
                }
            } else {
                return Err(format!(
                    "RISC-V scalar semantics unsupported: {}",
                    d.mnemonic
                ));
            };
            let v = self.cast(v, w, word);
            self.write(dest()?, v)?;
        }
        Ok(CpuFlow::Next)
    }
    fn arm64(&mut self, d: &Decoded) -> Result<CpuFlow> {
        let id = d.id;
        if d.flow != InstructionFlow::Next
            && ![
                ARM64_INS_B as u32,
                ARM64_INS_BR as u32,
                ARM64_INS_BL as u32,
                ARM64_INS_BLR as u32,
                ARM64_INS_RET as u32,
                ARM64_INS_CBZ as u32,
                ARM64_INS_CBNZ as u32,
                ARM64_INS_TBZ as u32,
                ARM64_INS_TBNZ as u32,
            ]
            .contains(&id)
        {
            return Err(
                "AArch64 authenticated/system/extended control transfer unsupported".into(),
            );
        }
        let w = self.dest_width(d).unwrap_or(64);
        let k = Self::k;
        if id == ARM64_INS_NOP as u32 {
            return Ok(CpuFlow::Next);
        }
        if matches!(
            d.flow,
            InstructionFlow::Call | InstructionFlow::IndirectCall
        ) {
            let target = if let Some(t) = d.target {
                k(64, t)
            } else {
                self.read(d, 0, 64)?
            };
            self.call(target, d.address + 4)?;
            return Ok(CpuFlow::Call);
        }
        if d.flow == InstructionFlow::Return {
            self.transfer = Some(if d.args.is_empty() {
                self.reg("x30")?
            } else {
                self.read(d, 0, 64)?
            });
            return Ok(CpuFlow::Return);
        }
        if d.flow == InstructionFlow::IndirectJump {
            self.transfer = Some(self.read(d, 0, 64)?);
            return Ok(CpuFlow::Jump);
        }
        if d.flow == InstructionFlow::Jump {
            self.transfer = Some(k(64, d.target.ok_or("branch target missing")?));
            return Ok(CpuFlow::Jump);
        }
        if d.flow == InstructionFlow::ConditionalJump {
            let c = if [ARM64_INS_CBZ as u32, ARM64_INS_CBNZ as u32].contains(&id) {
                let a = self.read(d, 0, w)?;
                let mut c = self.cmp(Operation::Equal, a, k(w, 0));
                if id == ARM64_INS_CBNZ as u32 {
                    c = self.op(Operation::Xor, c, k(1, 1));
                }
                c
            } else if [ARM64_INS_TBZ as u32, ARM64_INS_TBNZ as u32].contains(&id) {
                let a = self.read(d, 0, w)?;
                let bit = self.read(d, 1, w)?;
                let b = self.op(Operation::Shr, a, bit);
                let b = self.op(Operation::And, b, k(w, 1));
                let mut c = self.cmp(Operation::Equal, b, k(w, 0));
                if id == ARM64_INS_TBNZ as u32 {
                    c = self.op(Operation::Xor, c, k(1, 1));
                }
                c
            } else {
                self.condition(d.condition)?
            };
            self.transfer = Some(c);
            return Ok(CpuFlow::Branch);
        }
        let dest = || Self::reg_name(d, 0);
        if [
            ARM64_INS_MOV as u32,
            ARM64_INS_MOVZ as u32,
            ARM64_INS_MOVN as u32,
            ARM64_INS_MOVK as u32,
            ARM64_INS_ADR as u32,
            ARM64_INS_ADRP as u32,
        ]
        .contains(&id)
        {
            let mut v = self.read(d, 1, w)?;
            if id == ARM64_INS_MOVN as u32 {
                v = self.not(v);
            }
            if id == ARM64_INS_MOVK as u32 {
                let shift = match d.args[1].shift {
                    Shift::None => 0,
                    Shift::Lsl(n) => n,
                    _ => return Err("MOVK shift invalid".into()),
                };
                let old = self.read(d, 0, w)?;
                let mask = !(0xffffu64 << shift);
                let old = self.op(Operation::And, old, k(w, mask));
                v = self.op(Operation::Or, old, v);
            }
            self.write(dest()?, v)?;
        } else if [
            ARM64_INS_ADD as u32,
            ARM64_INS_ADDS as u32,
            ARM64_INS_SUB as u32,
            ARM64_INS_SUBS as u32,
            ARM64_INS_CMP as u32,
            ARM64_INS_CMN as u32,
            ARM64_INS_NEG as u32,
            ARM64_INS_NEGS as u32,
        ]
        .contains(&id)
        {
            let compare = [ARM64_INS_CMP as u32, ARM64_INS_CMN as u32].contains(&id);
            let neg = [ARM64_INS_NEG as u32, ARM64_INS_NEGS as u32].contains(&id);
            let sub = [
                ARM64_INS_SUB as u32,
                ARM64_INS_SUBS as u32,
                ARM64_INS_CMP as u32,
                ARM64_INS_NEG as u32,
                ARM64_INS_NEGS as u32,
            ]
            .contains(&id);
            let a = if neg {
                k(w, 0)
            } else {
                self.read(d, usize::from(!compare), w)?
            };
            let b = self.read(d, if compare || neg { 1 } else { 2 }, w)?;
            let result = self.op(if sub { Operation::Sub } else { Operation::Add }, a, b);
            if d.flags || compare {
                self.flags(a, b, result, sub, false);
            }
            if !compare {
                self.write(dest()?, result)?;
            }
        } else if [
            ARM64_INS_AND as u32,
            ARM64_INS_ANDS as u32,
            ARM64_INS_ORR as u32,
            ARM64_INS_EOR as u32,
            ARM64_INS_BIC as u32,
            ARM64_INS_BICS as u32,
            ARM64_INS_ORN as u32,
            ARM64_INS_EON as u32,
            ARM64_INS_TST as u32,
            ARM64_INS_MVN as u32,
        ]
        .contains(&id)
        {
            let test = id == ARM64_INS_TST as u32;
            let mvn = id == ARM64_INS_MVN as u32;
            let a = if mvn {
                k(w, 0)
            } else {
                self.read(d, usize::from(!test), w)?
            };
            let mut b = self.read(d, if test || mvn { 1 } else { 2 }, w)?;
            if [
                ARM64_INS_BIC as u32,
                ARM64_INS_BICS as u32,
                ARM64_INS_ORN as u32,
                ARM64_INS_EON as u32,
                ARM64_INS_MVN as u32,
            ]
            .contains(&id)
            {
                b = self.not(b);
            }
            let op = if [
                ARM64_INS_ORR as u32,
                ARM64_INS_ORN as u32,
                ARM64_INS_MVN as u32,
            ]
            .contains(&id)
            {
                Operation::Or
            } else if [ARM64_INS_EOR as u32, ARM64_INS_EON as u32].contains(&id) {
                Operation::Xor
            } else {
                Operation::And
            };
            let r = self.op(op, a, b);
            if d.flags || test {
                self.flags(a, b, r, false, true);
            }
            if !test {
                self.write(dest()?, r)?;
            }
        } else if [
            ARM64_INS_LSL as u32,
            ARM64_INS_LSR as u32,
            ARM64_INS_ASR as u32,
            ARM64_INS_ROR as u32,
        ]
        .contains(&id)
        {
            let a = self.read(d, 1, w)?;
            let c = self.read(d, 2, w)?;
            let c = self.op(Operation::And, c, k(w, u64::from(w - 1)));
            let r = if id == ARM64_INS_ASR as u32 {
                self.sar(a, c)
            } else {
                self.op(
                    if id == ARM64_INS_LSL as u32 {
                        Operation::Shl
                    } else if id == ARM64_INS_LSR as u32 {
                        Operation::Shr
                    } else {
                        Operation::RotateRight
                    },
                    a,
                    c,
                )
            };
            self.write(dest()?, r)?;
        } else if [
            ARM64_INS_SXTB as u32,
            ARM64_INS_SXTH as u32,
            ARM64_INS_SXTW as u32,
            ARM64_INS_UXTB as u32,
            ARM64_INS_UXTH as u32,
        ]
        .contains(&id)
        {
            let n = if [ARM64_INS_SXTB as u32, ARM64_INS_UXTB as u32].contains(&id) {
                8
            } else if id == ARM64_INS_SXTW as u32 {
                32
            } else {
                16
            };
            let a = self.read(d, 1, w)?;
            let a = self.cast(a, n, false);
            let a = self.cast(
                a,
                w,
                [
                    ARM64_INS_SXTB as u32,
                    ARM64_INS_SXTH as u32,
                    ARM64_INS_SXTW as u32,
                ]
                .contains(&id),
            );
            self.write(dest()?, a)?;
        } else if [
            ARM64_INS_CSEL as u32,
            ARM64_INS_CSINC as u32,
            ARM64_INS_CSINV as u32,
            ARM64_INS_CSNEG as u32,
            ARM64_INS_CSET as u32,
            ARM64_INS_CSETM as u32,
            ARM64_INS_CINC as u32,
            ARM64_INS_CINV as u32,
            ARM64_INS_CNEG as u32,
        ]
        .contains(&id)
        {
            let cond = self.condition(d.condition)?;
            let (a, b) = if [ARM64_INS_CSET as u32, ARM64_INS_CSETM as u32].contains(&id) {
                (
                    k(
                        w,
                        if id == ARM64_INS_CSETM as u32 {
                            mask(w)
                        } else {
                            1
                        },
                    ),
                    k(w, 0),
                )
            } else {
                let a = self.read(d, 1, w)?;
                let b = if d.args.len() > 2 {
                    self.read(d, 2, w)?
                } else {
                    a
                };
                let mut other = b;
                if [ARM64_INS_CSINC as u32, ARM64_INS_CINC as u32].contains(&id) {
                    other = self.op(Operation::Add, b, k(w, 1));
                }
                if [ARM64_INS_CSINV as u32, ARM64_INS_CINV as u32].contains(&id) {
                    other = self.not(b);
                }
                if [ARM64_INS_CSNEG as u32, ARM64_INS_CNEG as u32].contains(&id) {
                    other = self.op(Operation::Sub, k(w, 0), b);
                }
                if [
                    ARM64_INS_CINC as u32,
                    ARM64_INS_CINV as u32,
                    ARM64_INS_CNEG as u32,
                ]
                .contains(&id)
                {
                    (other, a)
                } else {
                    (a, other)
                }
            };
            let r = self.select(cond, a, b);
            self.write(dest()?, r)?;
        } else if [
            ARM64_INS_MUL as u32,
            ARM64_INS_MADD as u32,
            ARM64_INS_MSUB as u32,
            ARM64_INS_MNEG as u32,
            ARM64_INS_SMULH as u32,
            ARM64_INS_UMULH as u32,
            ARM64_INS_SMULL as u32,
            ARM64_INS_UMULL as u32,
        ]
        .contains(&id)
        {
            let a = self.read(d, 1, w)?;
            let b = self.read(d, 2, w)?;
            let mut a = a;
            let mut b = b;
            if [ARM64_INS_SMULL as u32, ARM64_INS_UMULL as u32].contains(&id) {
                a = self.cast(a, 32, false);
                b = self.cast(b, 32, false);
                a = self.cast(a, 64, id == ARM64_INS_SMULL as u32);
                b = self.cast(b, 64, id == ARM64_INS_SMULL as u32);
            }
            let product = self.op(
                if id == ARM64_INS_SMULH as u32 {
                    Operation::SignedMulHigh
                } else if id == ARM64_INS_UMULH as u32 {
                    Operation::UnsignedMulHigh
                } else {
                    Operation::Mul
                },
                a,
                b,
            );
            let r = if [ARM64_INS_MADD as u32, ARM64_INS_MSUB as u32].contains(&id) {
                let c = self.read(d, 3, w)?;
                if id == ARM64_INS_MSUB as u32 {
                    self.op(Operation::Sub, c, product)
                } else {
                    self.op(Operation::Add, product, c)
                }
            } else if id == ARM64_INS_MNEG as u32 {
                self.op(Operation::Sub, k(w, 0), product)
            } else {
                product
            };
            self.write(dest()?, r)?;
        } else if [ARM64_INS_UDIV as u32, ARM64_INS_SDIV as u32].contains(&id) {
            let a = self.read(d, 1, w)?;
            let b = self.read(d, 2, w)?;
            let signed = id == ARM64_INS_SDIV as u32;
            let high = if signed {
                let s = self.op(Operation::Shr, a, k(w, u64::from(w - 1)));
                self.op(Operation::Sub, k(w, 0), s)
            } else {
                k(w, 0)
            };
            let q = self.emit(
                Type::Bits(w),
                Operation::Divide {
                    signed,
                    remainder: false,
                },
                vec![high, a, b],
            );
            let zero = self.cmp(Operation::Equal, b, k(w, 0));
            let mut r = self.select(zero, k(w, 0), q);
            if signed {
                let min = self.cmp(Operation::Equal, a, k(w, 1u64 << (w - 1)));
                let minus = self.cmp(Operation::Equal, b, k(w, mask(w)));
                let ov = self.op(Operation::And, min, minus);
                r = self.select(ov, a, r);
            }
            self.write(dest()?, r)?;
        } else if [
            ARM64_INS_LDR as u32,
            ARM64_INS_LDRB as u32,
            ARM64_INS_LDRH as u32,
            ARM64_INS_LDRSB as u32,
            ARM64_INS_LDRSH as u32,
            ARM64_INS_LDRSW as u32,
            ARM64_INS_LDUR as u32,
            ARM64_INS_LDURB as u32,
            ARM64_INS_LDURH as u32,
            ARM64_INS_LDURSB as u32,
            ARM64_INS_LDURSH as u32,
            ARM64_INS_LDURSW as u32,
            ARM64_INS_STR as u32,
            ARM64_INS_STRB as u32,
            ARM64_INS_STRH as u32,
            ARM64_INS_STUR as u32,
            ARM64_INS_STURB as u32,
            ARM64_INS_STURH as u32,
            ARM64_INS_LDP as u32,
            ARM64_INS_STP as u32,
            ARM64_INS_LDPSW as u32,
        ]
        .contains(&id)
        {
            let pair = [
                ARM64_INS_LDP as u32,
                ARM64_INS_STP as u32,
                ARM64_INS_LDPSW as u32,
            ]
            .contains(&id);
            let store = [
                ARM64_INS_STR as u32,
                ARM64_INS_STRB as u32,
                ARM64_INS_STRH as u32,
                ARM64_INS_STUR as u32,
                ARM64_INS_STURB as u32,
                ARM64_INS_STURH as u32,
                ARM64_INS_STP as u32,
            ]
            .contains(&id);
            let signed = [
                ARM64_INS_LDRSB as u32,
                ARM64_INS_LDRSH as u32,
                ARM64_INS_LDRSW as u32,
                ARM64_INS_LDURSB as u32,
                ARM64_INS_LDURSH as u32,
                ARM64_INS_LDURSW as u32,
                ARM64_INS_LDPSW as u32,
            ]
            .contains(&id);
            let mw = if [
                ARM64_INS_LDRB as u32,
                ARM64_INS_LDRSB as u32,
                ARM64_INS_LDURB as u32,
                ARM64_INS_LDURSB as u32,
                ARM64_INS_STRB as u32,
                ARM64_INS_STURB as u32,
            ]
            .contains(&id)
            {
                8
            } else if [
                ARM64_INS_LDRH as u32,
                ARM64_INS_LDRSH as u32,
                ARM64_INS_LDURH as u32,
                ARM64_INS_LDURSH as u32,
                ARM64_INS_STRH as u32,
                ARM64_INS_STURH as u32,
            ]
            .contains(&id)
            {
                16
            } else if [
                ARM64_INS_LDRSW as u32,
                ARM64_INS_LDURSW as u32,
                ARM64_INS_LDPSW as u32,
            ]
            .contains(&id)
            {
                32
            } else {
                w
            };
            if pair
                && !store
                && Self::root_name(Self::reg_name(d, 0)?) == Self::root_name(Self::reg_name(d, 1)?)
            {
                return Err(
                    "duplicate AArch64 load-pair destination is constrained/unpredictable".into(),
                );
            }
            let (address, wb) = self.address(d, if pair { 2 } else { 1 })?;
            if let Some((base, _)) = &wb {
                if (0..if pair { 2 } else { 1 }).any(|n| {
                    Self::reg_name(d, n).is_ok_and(|r| Self::root_name(r) == Self::root_name(base))
                }) {
                    return Err("writeback overlaps a transfer register; constrained/unpredictable form rejected".into());
                }
            }
            for n in 0..if pair { 2 } else { 1 } {
                let a = if n == 0 {
                    address
                } else {
                    self.op(Operation::Add, address, k(64, u64::from(mw / 8)))
                };
                if store {
                    let v = self.read(d, n, mw)?;
                    self.store(a, v);
                } else {
                    let v = self.load(a, mw);
                    let v = self.cast(v, w, signed);
                    self.write(Self::reg_name(d, n)?, v)?;
                }
            }
            if let Some((base, value)) = wb {
                self.write(&base, value)?;
            }
        } else {
            return Err(format!("AArch64 semantics unsupported: {}", d.mnemonic));
        }
        Ok(CpuFlow::Next)
    }
    fn barrier(&mut self, reason: String) {
        self.f.diagnostics.push(Diagnostic {
            source: self.source,
            message: reason.clone(),
        });
        self.ops.push(Statement {
            source: self.source,
            output: None,
            op: Operation::Barrier {
                reason: reason.clone(),
            },
            args: (0..self.arch).map(Operand::Variable).collect(),
        });
        for id in 0..self.arch {
            self.ops.push(Statement {
                source: self.source,
                output: Some(id),
                op: Operation::Unknown {
                    reason: reason.clone(),
                },
                args: vec![],
            });
        }
        self.transfer = None;
    }
}
pub(crate) fn lift_cpu(bytes: &[u8], address: u64, p: Processor) -> Result<CpuInstruction> {
    let d = processor::decode(p, bytes, address)?;
    let mut b = Builder::new(p, address, true);
    let flow = b.instruction(&d)?;
    Ok(CpuInstruction {
        variables: b.f.variables,
        statements: b.ops,
        transfer: b.transfer,
        flow,
        next: address.wrapping_add(d.length as u64) & mask(u16::from(p.bits())),
        target: d.target.unwrap_or(0),
        bytes: bytes[..d.length].to_vec(),
    })
}
pub(super) fn lift(
    image: &CodeImage<'_>,
    p: Processor,
    analysis: &ProgramAnalysis,
    address: u64,
    control: &dyn AnalysisControl,
) -> Result<Function> {
    let f = analysis
        .function_by_start(address)
        .ok_or("IR requires discovered function start")?;
    if f.blocks.len() > MAX_IR_BLOCKS || f.instruction_count > MAX_IR_INSTRUCTIONS {
        return Err("IR budget exceeded".into());
    }
    let mut b = Builder::new(p, address, false);
    let mut total = 0;
    for start in &f.blocks {
        if control.is_cancelled() {
            return Err("IR lifting cancelled".into());
        }
        let block = &analysis.blocks[start];
        b.ops.clear();
        b.transfer = None;
        for ip in &block.instructions {
            if control.is_cancelled() {
                return Err("IR lifting cancelled".into());
            }
            let raw = &analysis.instructions[ip];
            let bytes = image
                .read(*ip, usize::from(raw.length))
                .ok_or("missing executable bytes")?;
            let decoded = processor::decode(p, bytes, *ip)?;
            let ops = b.ops.len();
            let vars = b.f.variables.len();
            b.source = Address(*ip);
            if let Err(e) = b.instruction(&decoded) {
                b.ops.truncate(ops);
                b.f.variables.truncate(vars);
                b.barrier(e);
            }
            b.f.source_instructions += 1;
            if total + b.ops.len() > MAX_IR_OPERATIONS {
                return Err("IR operation budget exceeded".into());
            }
        }
        let last = &analysis.instructions[block.instructions.last().unwrap()];
        let successors = block
            .successors
            .iter()
            .filter(|e| f.blocks.binary_search(&e.target).is_ok())
            .map(|e| Address(e.target))
            .collect::<Vec<_>>();
        let kind = match last.flow {
            InstructionFlow::Return => FlowKind::Return,
            InstructionFlow::ConditionalJump => FlowKind::Branch,
            InstructionFlow::Jump => FlowKind::Jump,
            InstructionFlow::IndirectJump => FlowKind::Indirect,
            _ => {
                if successors.len() == 1 {
                    FlowKind::Jump
                } else {
                    FlowKind::Unresolved
                }
            }
        };
        let target = if matches!(
            last.flow,
            InstructionFlow::Jump | InstructionFlow::ConditionalJump
        ) {
            last.target.map(Address)
        } else {
            None
        };
        let fallthrough = (kind == FlowKind::Branch).then_some(Address(last.end()));
        let mut exits = vec![];
        for target in target.into_iter().chain(fallthrough) {
            if !successors.contains(&target) {
                exits.push(target);
            }
        }
        exits.sort_unstable();
        exits.dedup();
        let taken = if kind == FlowKind::Branch {
            target
        } else {
            None
        };
        let value = if kind == FlowKind::Branch {
            Some(b.transfer.unwrap_or_else(|| {
                b.emit(
                    Type::Bits(1),
                    Operation::Unknown {
                        reason: "unsupported branch condition".into(),
                    },
                    vec![],
                )
            }))
        } else if matches!(
            last.flow,
            InstructionFlow::Call | InstructionFlow::IndirectCall
        ) {
            None
        } else {
            b.transfer.map(|v| {
                b.emit(
                    Type::Address(u16::from(p.bits())),
                    Operation::ToAddress,
                    vec![v],
                )
            })
        };
        let state = if matches!(
            kind,
            FlowKind::Return | FlowKind::Indirect | FlowKind::Unresolved
        ) || !exits.is_empty()
            || successors.is_empty()
        {
            (0..b.arch).map(Operand::Variable).collect()
        } else {
            vec![]
        };
        total += b.ops.len();
        b.f.blocks.push(Block {
            address: Address(*start),
            end: Address(block.end),
            function: Address(address),
            statements: std::mem::take(&mut b.ops),
            terminator: Terminator {
                source: Address(last.address),
                kind,
                value,
                successors,
                exits,
                taken,
                fallthrough,
                state,
            },
        });
    }
    verify(&b.f).map_err(|e| format!("processor IR verification: {}", e.join("; ")))?;
    Ok(b.f)
}
