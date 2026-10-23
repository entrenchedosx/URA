use super::*;
use crate::{
    analysis::{AnalysisControl, CodeImage, InstructionFlow},
    LoadedBinary, ProgramAnalysis,
};
use iced_x86::{
    ConditionCode as C, Decoder, DecoderOptions, Instruction, Mnemonic as M, OpKind, Register as R,
};

const GPRS: [R; 16] = [
    R::RAX,
    R::RBX,
    R::RCX,
    R::RDX,
    R::RSP,
    R::RBP,
    R::RSI,
    R::RDI,
    R::R8,
    R::R9,
    R::R10,
    R::R11,
    R::R12,
    R::R13,
    R::R14,
    R::R15,
];
const FLAGS: [&str; 6] = ["cf", "pf", "af", "zf", "sf", "of"];

pub fn lift_function(
    binary: &LoadedBinary,
    analysis: &ProgramAnalysis,
    address: u64,
    control: &dyn AnalysisControl,
) -> Result<Function, String> {
    let image = CodeImage::from_binary(binary);
    lift_image(
        &image,
        binary.analysis().bitness,
        analysis,
        address,
        control,
    )
}

pub fn lift_image(
    image: &CodeImage<'_>,
    bitness: u8,
    analysis: &ProgramAnalysis,
    address: u64,
    control: &dyn AnalysisControl,
) -> Result<Function, String> {
    if !matches!(bitness, 32 | 64) {
        return Err("IR lifting supports x86/x64 only".into());
    }
    let function = analysis
        .function_by_start(address)
        .ok_or("IR requires a discovered function start")?;
    if function.blocks.len() > MAX_IR_BLOCKS || function.instruction_count > MAX_IR_INSTRUCTIONS {
        return Err("function exceeds IR block/instruction budget".into());
    }
    let mut builder = Builder::new(bitness as u16, address);
    for address in &function.blocks {
        if control.is_cancelled() {
            return Err("IR lifting cancelled".into());
        }
        let block = analysis
            .blocks
            .get(address)
            .ok_or("missing source CFG block")?;
        if block.function != function.address || block.instructions.is_empty() {
            return Err("invalid source CFG block ownership".into());
        }
        builder.ops.clear();
        builder.transfer = None;
        builder.comparison = None;
        for address in &block.instructions {
            if control.is_cancelled() {
                return Err("IR lifting cancelled".into());
            }
            let original = analysis
                .instructions
                .get(address)
                .ok_or("missing source instruction")?;
            let bytes = image
                .read(*address, original.length as usize)
                .ok_or("source instruction is not file-backed")?;
            let instruction =
                Decoder::with_ip(bitness as u32, bytes, *address, DecoderOptions::NONE).decode();
            if instruction.len() != original.length as usize || instruction.is_invalid() {
                return Err("invalid or inconsistent source instruction boundary".into());
            }
            builder.source = Address(*address);
            let start = builder.ops.len();
            let variables = builder.function.variables.len();
            if let Err(reason) = builder.instruction(&instruction, bytes) {
                builder.ops.truncate(start);
                builder.function.variables.truncate(variables);
                builder.barrier(reason);
            }
            builder.function.source_instructions += 1;
            if builder.total_ops + builder.ops.len() > MAX_IR_OPERATIONS {
                return Err("function exceeds IR operation budget".into());
            }
        }
        let last = analysis.instructions[block.instructions.last().unwrap()].clone();
        let successors: Vec<_> = block
            .successors
            .iter()
            .filter(|e| function.blocks.binary_search(&e.target).is_ok())
            .map(|e| Address(e.target))
            .collect();
        let mut exits = Vec::new();
        // Decode targets independently of formatted operand text. Targets absent
        // from the source CFG remain explicit exits, never fabricated blocks.
        if matches!(
            last.flow,
            InstructionFlow::Jump | InstructionFlow::ConditionalJump
        ) {
            if let Some(target) = last.target {
                if !successors.contains(&Address(target)) {
                    exits.push(Address(target));
                }
            }
        }
        let kind = match last.flow {
            InstructionFlow::Return => FlowKind::Return,
            InstructionFlow::Jump => {
                if last.target.is_some() || !successors.is_empty() {
                    FlowKind::Jump
                } else {
                    FlowKind::Unresolved
                }
            }
            InstructionFlow::ConditionalJump => FlowKind::Branch,
            InstructionFlow::IndirectJump => FlowKind::Indirect,
            _ => {
                if successors.len() == 1 {
                    FlowKind::Jump
                } else {
                    FlowKind::Unresolved
                }
            }
        };
        if kind == FlowKind::Branch && !successors.contains(&Address(last.end())) {
            exits.push(Address(last.end()));
        }
        exits.sort_unstable();
        exits.dedup();
        let value =
            if kind == FlowKind::Branch {
                Some(builder.transfer.take().unwrap_or_else(|| {
                    builder.unknown(Type::Bits(1), "unsupported branch condition")
                }))
            } else {
                builder.transfer.take()
            };
        let state = if matches!(
            kind,
            FlowKind::Return | FlowKind::Indirect | FlowKind::Unresolved
        ) || !exits.is_empty()
            || successors.is_empty()
        {
            builder.state()
        } else {
            vec![]
        };
        builder.total_ops += builder.ops.len();
        builder.function.blocks.push(Block {
            address: Address(block.address),
            end: Address(block.end),
            function: builder.function.entry,
            statements: std::mem::take(&mut builder.ops),
            terminator: Terminator {
                source: Address(last.address),
                kind,
                value,
                successors,
                exits,
                state,
                taken: if kind == FlowKind::Branch {
                    last.target.map(Address)
                } else {
                    None
                },
                fallthrough: if kind == FlowKind::Branch {
                    Some(Address(last.end()))
                } else {
                    None
                },
            },
        });
    }
    verify(&builder.function)
        .map_err(|errors| format!("IR verification: {}", errors.join("; ")))?;
    Ok(builder.function)
}

/// One decoded machine instruction, using the same scalar lifter as static IR.
/// Calls retain architectural state here: ABI clobber inference is not CPU execution.
pub(crate) struct CpuInstruction {
    pub variables: Vec<Variable>,
    pub statements: Vec<Statement>,
    pub transfer: Option<Operand>,
    pub flow: CpuFlow,
    pub next: u64,
    pub target: u64,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Copy, Debug)]
pub(crate) enum CpuFlow {
    Next,
    Branch,
    Jump,
    Call,
    Return,
}
pub(crate) fn lift_cpu_instruction(
    bytes: &[u8],
    address: u64,
    bits: u8,
) -> Result<CpuInstruction, String> {
    if !matches!(bits, 32 | 64) {
        return Err("CPU mode must be32 or64".into());
    }
    let i = Decoder::with_ip(u32::from(bits), bytes, address, DecoderOptions::NONE).decode();
    if i.is_invalid() {
        return Err("invalid or incomplete executable instruction".into());
    }
    let mut b = Builder::new(u16::from(bits), address);
    let flow = match i.mnemonic() {
        M::Call => {
            let (address_bits, operand_override) = prefix_modes(&bytes[..i.len()], u16::from(bits));
            b.address_bits = address_bits;
            if i.has_lock_prefix() || i.has_rep_prefix() || i.has_repne_prefix() {
                return Err("atomic/repeat call prefixes unsupported".into());
            }
            if i.is_call_far() || i.is_call_far_indirect() || operand_override && bits == 32 {
                return Err("far/16-bit call is not emulated".into());
            }
            let target = b.read(&i, 0, u16::from(bits))?;
            b.transfer = Some(target);
            CpuFlow::Call
        }
        _ => {
            b.instruction(&i, &bytes[..i.len()])?;
            if i.mnemonic() == M::Ret {
                CpuFlow::Return
            } else if i.mnemonic() == M::Jmp {
                CpuFlow::Jump
            } else if i.is_jcc_short_or_near() {
                CpuFlow::Branch
            } else {
                CpuFlow::Next
            }
        }
    };
    Ok(CpuInstruction {
        variables: b.function.variables,
        statements: b.ops,
        transfer: b.transfer,
        flow,
        next: i.next_ip(),
        target: i.near_branch_target(),
        bytes: bytes[..i.len()].to_vec(),
    })
}

fn prefix_modes(bytes: &[u8], bits: u16) -> (u16, bool) {
    let mut address_override = false;
    let mut operand_override = false;
    for &b in bytes {
        match b {
            0x67 => address_override = true,
            0x66 => operand_override = true,
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0xf0 | 0xf2 | 0xf3 => {}
            0x40..=0x4f if bits == 64 => {}
            _ => break,
        }
    }
    (
        if address_override {
            if bits == 64 {
                32
            } else {
                16
            }
        } else {
            bits
        },
        operand_override,
    )
}

struct Builder {
    function: Function,
    bits: u16,
    registers: usize,
    arch_count: usize,
    memory: usize,
    source: Address,
    ops: Vec<Statement>,
    transfer: Option<Operand>,
    total_ops: usize,
    address_bits: u16,
    comparison: Option<(Operand, Operand)>,
}
impl Builder {
    fn new(bits: u16, entry: u64) -> Self {
        let registers = if bits == 64 { 16 } else { 8 };
        let mut variables = Vec::new();
        for r in &GPRS[..registers] {
            variables.push(Variable {
                name: format!("{:?}", if bits == 32 { r.full_register32() } else { *r })
                    .to_lowercase(),
                ty: Type::Bits(bits),
                kind: VariableKind::Register,
            });
        }
        for f in FLAGS {
            variables.push(Variable {
                name: f.into(),
                ty: Type::Bits(1),
                kind: VariableKind::Flag,
            });
        }
        let memory = variables.len();
        variables.push(Variable {
            name: "memory".into(),
            ty: Type::Memory,
            kind: VariableKind::Memory,
        });
        for segment in if bits == 64 {
            &["fs", "gs"][..]
        } else {
            &["es", "cs", "ss", "ds", "fs", "gs"][..]
        } {
            variables.push(Variable {
                name: format!("{segment}_base"),
                ty: Type::Address(bits),
                kind: VariableKind::Register,
            });
        }
        let arch_count = variables.len();
        Self {
            function: Function {
                ir_version: IR_VERSION,
                entry: Address(entry),
                address_width: bits,
                variables,
                blocks: vec![],
                diagnostics: vec![],
                source_instructions: 0,
            },
            bits,
            registers,
            arch_count,
            memory,
            source: Address(entry),
            ops: vec![],
            transfer: None,
            total_ops: 0,
            address_bits: bits,
            comparison: None,
        }
    }
    fn constant(&self, w: u16, v: u64) -> Operand {
        Operand::Constant(Constant::bits(w, v))
    }
    fn ty(&self, v: Operand) -> Type {
        self.function.operand_type(v).expect("builder operand")
    }
    fn emit(&mut self, ty: Type, op: Operation, args: Vec<Operand>) -> Operand {
        let id = self.function.variables.len();
        self.function.variables.push(Variable {
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
    fn assign(&mut self, v: usize, value: Operand) {
        self.ops.push(Statement {
            source: self.source,
            output: Some(v),
            op: Operation::Copy,
            args: vec![value],
        });
    }
    fn unknown(&mut self, ty: Type, why: &str) -> Operand {
        self.emit(ty, Operation::Unknown { reason: why.into() }, vec![])
    }
    fn state(&self) -> Vec<Operand> {
        (0..self.arch_count).map(Operand::Variable).collect()
    }
    fn barrier(&mut self, reason: String) {
        self.comparison = None;
        self.function.diagnostics.push(Diagnostic {
            source: self.source,
            message: reason.clone(),
        });
        self.ops.push(Statement {
            source: self.source,
            output: None,
            op: Operation::Barrier {
                reason: reason.clone(),
            },
            args: self.state(),
        });
        for id in 0..self.arch_count {
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
    fn flag(&self, index: usize) -> Operand {
        Operand::Variable(self.registers + index)
    }
    fn set_flag(&mut self, index: usize, value: Operand) {
        self.assign(self.registers + index, value);
    }
    fn unary(&mut self, op: Operation, v: Operand, ty: Type) -> Operand {
        self.emit(ty, op, vec![v])
    }
    fn binary(&mut self, op: Operation, a: Operand, b: Operand) -> Operand {
        let ty = self.ty(a);
        self.emit(ty, op, vec![a, b])
    }
    fn compare(&mut self, op: Operation, a: Operand, b: Operand) -> Operand {
        self.emit(Type::Bits(1), op, vec![a, b])
    }
    fn resize(&mut self, value: Operand, width: u16, signed: bool) -> Operand {
        let old = self.ty(value).width().unwrap();
        if old == width {
            value
        } else {
            self.unary(
                if old > width {
                    Operation::Truncate
                } else if signed {
                    Operation::SignExtend
                } else {
                    Operation::ZeroExtend
                },
                value,
                Type::Bits(width),
            )
        }
    }
    fn register(&mut self, r: R) -> Result<Operand, String> {
        let full = r.full_register();
        let id = GPRS[..self.registers]
            .iter()
            .position(|v| *v == full)
            .ok_or_else(|| format!("unsupported register {r:?}"))?;
        let width = (r.size() * 8) as u16;
        let root = Operand::Variable(id);
        if width == self.bits {
            Ok(root)
        } else {
            Ok(self.unary(
                Operation::Extract {
                    offset: if matches!(r, R::AH | R::BH | R::CH | R::DH) {
                        8
                    } else {
                        0
                    },
                },
                root,
                Type::Bits(width),
            ))
        }
    }
    fn write_register(&mut self, r: R, value: Operand) -> Result<(), String> {
        let id = GPRS[..self.registers]
            .iter()
            .position(|v| *v == r.full_register())
            .ok_or("unsupported destination register")?;
        let width = (r.size() * 8) as u16;
        if self.ty(value) != Type::Bits(width) {
            return Err("destination width mismatch".into());
        }
        let result = if width == self.bits {
            value
        } else if width == 32 && self.bits == 64 {
            self.unary(Operation::ZeroExtend, value, Type::Bits(64))
        } else {
            self.emit(
                Type::Bits(self.bits),
                Operation::Insert {
                    offset: if matches!(r, R::AH | R::BH | R::CH | R::DH) {
                        8
                    } else {
                        0
                    },
                },
                vec![Operand::Variable(id), value],
            )
        };
        self.assign(id, result);
        Ok(())
    }
    fn address(&mut self, i: &Instruction) -> Result<Operand, String> {
        let aw = self.address_bits;
        let mut offset = if i.is_ip_rel_memory_operand() {
            self.constant(aw, i.ip_rel_memory_address())
        } else {
            let base = if i.memory_base() == R::None {
                self.constant(aw, 0)
            } else {
                let v = self.register(i.memory_base())?;
                self.resize(v, aw, false)
            };
            let index = if i.memory_index() == R::None {
                self.constant(aw, 0)
            } else {
                let v = self.register(i.memory_index())?;
                let v = self.resize(v, aw, false);
                self.binary(
                    Operation::Shl,
                    v,
                    self.constant(aw, i.memory_index_scale().trailing_zeros() as u64),
                )
            };
            let sum = self.binary(Operation::Add, base, index);
            self.binary(
                Operation::Add,
                sum,
                self.constant(aw, i.memory_displacement64()),
            )
        };
        offset = self.resize(offset, self.bits, false);
        let segment = i.memory_segment();
        if i.mnemonic() != M::Lea && (self.bits == 32 || matches!(segment, R::FS | R::GS)) {
            let name = format!("{:?}_base", segment).to_lowercase();
            let id = self
                .function
                .variables
                .iter()
                .take(self.arch_count)
                .position(|v| v.name == name)
                .ok_or("unknown segment base")?;
            let base = self.unary(
                Operation::ToBits,
                Operand::Variable(id),
                Type::Bits(self.bits),
            );
            offset = self.binary(Operation::Add, offset, base);
        }
        Ok(self.unary(Operation::ToAddress, offset, Type::Address(self.bits)))
    }
    fn width(&self, i: &Instruction, n: u32) -> Result<u16, String> {
        match i.op_kind(n) {
            OpKind::Register => Ok((i.op_register(n).size() * 8) as u16),
            OpKind::Memory => {
                let w = (i.memory_size().size() * 8) as u16;
                if matches!(w, 8 | 16 | 32 | 64) {
                    Ok(w)
                } else {
                    Err("unsupported memory width".into())
                }
            }
            _ => Err("operand has no scalar width".into()),
        }
    }
    fn read(&mut self, i: &Instruction, n: u32, width: u16) -> Result<Operand, String> {
        match i.op_kind(n) {
            OpKind::Register => self.register(i.op_register(n)),
            OpKind::Memory => {
                let address = self.address(i)?;
                Ok(self.emit(
                    Type::Bits(width),
                    Operation::Load,
                    vec![Operand::Variable(self.memory), address],
                ))
            }
            OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => Ok(self.constant(width, i.immediate(n))),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                Ok(Operand::Constant(Constant {
                    ty: Type::Address(self.bits),
                    value: Address(i.near_branch_target()),
                }))
            }
            _ => Err("unsupported operand kind".into()),
        }
    }
    fn write(
        &mut self,
        i: &Instruction,
        value: Operand,
        address: Option<Operand>,
    ) -> Result<(), String> {
        match i.op0_kind() {
            OpKind::Register => self.write_register(i.op0_register(), value),
            OpKind::Memory => {
                let address = if let Some(a) = address {
                    a
                } else {
                    self.address(i)?
                };
                self.ops.push(Statement {
                    source: self.source,
                    output: Some(self.memory),
                    op: Operation::Store,
                    args: vec![Operand::Variable(self.memory), address, value],
                });
                Ok(())
            }
            _ => Err("unsupported destination".into()),
        }
    }
    fn flags(&mut self, m: M, left: Operand, right: Operand, result: Operand) {
        self.comparison = None;
        let width = self.ty(result).width().unwrap();
        let zero = self.compare(Operation::Equal, result, self.constant(width, 0));
        self.set_flag(3, zero);
        let sign = self.unary(
            Operation::Extract { offset: width - 1 },
            result,
            Type::Bits(1),
        );
        self.set_flag(4, sign);
        let parity = self.unary(Operation::Parity, result, Type::Bits(1));
        self.set_flag(1, parity);
        if matches!(m, M::Add | M::Sub | M::Cmp) {
            let carry = if m == M::Add {
                self.compare(Operation::UnsignedLess, result, left)
            } else {
                self.compare(Operation::UnsignedLess, left, right)
            };
            self.set_flag(0, carry);
            let x = self.binary(Operation::Xor, left, right);
            let y = self.binary(Operation::Xor, left, result);
            let x = if m == M::Add {
                let ty = self.ty(x);
                self.unary(Operation::Not, x, ty)
            } else {
                x
            };
            let overflow = self.binary(Operation::And, x, y);
            let overflow = self.unary(
                Operation::Extract { offset: width - 1 },
                overflow,
                Type::Bits(1),
            );
            self.set_flag(5, overflow);
            let x = self.binary(Operation::Xor, left, right);
            let x = self.binary(Operation::Xor, x, result);
            let adjust = self.unary(Operation::Extract { offset: 4 }, x, Type::Bits(1));
            self.set_flag(2, adjust);
        } else {
            self.set_flag(0, self.constant(1, 0));
            self.set_flag(5, self.constant(1, 0));
            let unknown = self.unknown(Type::Bits(1), "logical instruction leaves AF undefined");
            self.set_flag(2, unknown);
        }
    }
    fn condition(&mut self, c: C) -> Result<Operand, String> {
        let invert = |b: &mut Self, v: Operand| b.binary(Operation::Xor, v, b.constant(1, 1));
        // CMP operands are immutable snapshots, not aliases to registers that
        // a flag-preserving instruction may overwrite before Jcc/CMOV/SETcc.
        // Across blocks or after flag writes, retain the architectural flags.
        if let Some((left, right)) = self.comparison {
            let (op, a, b, negate) = match c {
                C::e => (Operation::Equal, left, right, false),
                C::ne => (Operation::Equal, left, right, true),
                C::b => (Operation::UnsignedLess, left, right, false),
                C::ae => (Operation::UnsignedLess, left, right, true),
                C::a => (Operation::UnsignedLess, right, left, false),
                C::be => (Operation::UnsignedLess, right, left, true),
                C::l => (Operation::SignedLess, left, right, false),
                C::ge => (Operation::SignedLess, left, right, true),
                C::g => (Operation::SignedLess, right, left, false),
                C::le => (Operation::SignedLess, right, left, true),
                _ => return self.flag_condition(c),
            };
            let value = self.compare(op, a, b);
            return Ok(if negate { invert(self, value) } else { value });
        }
        self.flag_condition(c)
    }
    fn flag_condition(&mut self, c: C) -> Result<Operand, String> {
        let invert = |b: &mut Self, v: Operand| b.binary(Operation::Xor, v, b.constant(1, 1));
        Ok(match c {
            C::o => self.flag(5),
            C::no => invert(self, self.flag(5)),
            C::b => self.flag(0),
            C::ae => invert(self, self.flag(0)),
            C::e => self.flag(3),
            C::ne => invert(self, self.flag(3)),
            C::be => self.binary(Operation::Or, self.flag(0), self.flag(3)),
            C::a => {
                let v = self.binary(Operation::Or, self.flag(0), self.flag(3));
                invert(self, v)
            }
            C::s => self.flag(4),
            C::ns => invert(self, self.flag(4)),
            C::p => self.flag(1),
            C::np => invert(self, self.flag(1)),
            C::l => self.binary(Operation::Xor, self.flag(4), self.flag(5)),
            C::ge => {
                let v = self.binary(Operation::Xor, self.flag(4), self.flag(5));
                invert(self, v)
            }
            C::le => {
                let v = self.binary(Operation::Xor, self.flag(4), self.flag(5));
                self.binary(Operation::Or, self.flag(3), v)
            }
            C::g => {
                let v = self.binary(Operation::Xor, self.flag(4), self.flag(5));
                let v = self.binary(Operation::Or, self.flag(3), v);
                invert(self, v)
            }
            _ => return Err("unsupported condition (including counter/loop branches)".into()),
        })
    }
    fn divide(&mut self, i: &Instruction) -> Result<(), String> {
        self.comparison = None;
        let width = self.width(i, 0)?;
        let signed = i.mnemonic() == M::Idiv;
        let (low_register, high_register) = match width {
            8 => (R::AL, R::AH),
            16 => (R::AX, R::DX),
            32 => (R::EAX, R::EDX),
            64 => (R::RAX, R::RDX),
            _ => return Err("unsupported divide width".into()),
        };
        let divisor = self.read(i, 0, width)?;
        let low = self.register(low_register)?;
        let high = self.register(high_register)?;
        let args = vec![high, low, divisor];
        let fault = self.emit(
            Type::Bits(1),
            Operation::DivideFault { signed },
            args.clone(),
        );
        self.ops.push(Statement {
            source: self.source,
            output: None,
            op: Operation::Guard {
                reason: "divide error (#DE)".into(),
            },
            args: vec![fault],
        });
        let quotient = self.emit(
            Type::Bits(width),
            Operation::Divide {
                signed,
                remainder: false,
            },
            args.clone(),
        );
        let remainder = self.emit(
            Type::Bits(width),
            Operation::Divide {
                signed,
                remainder: true,
            },
            args,
        );
        self.write_register(low_register, quotient)?;
        self.write_register(high_register, remainder)?;
        for flag in 0..FLAGS.len() {
            let value = self.unknown(Type::Bits(1), "divide leaves arithmetic flags undefined");
            self.set_flag(flag, value);
        }
        Ok(())
    }
    fn rotate(&mut self, i: &Instruction) -> Result<(), String> {
        self.comparison = None;
        let width = self.width(i, 0)?;
        let address = if i.op0_kind() == OpKind::Memory {
            Some(self.address(i)?)
        } else {
            None
        };
        let value = self.read(i, 0, width)?;
        let count = self.read(i, 1, 8)?;
        let count = self.resize(count, width, false);
        let count = self.binary(
            Operation::And,
            count,
            self.constant(width, if width == 64 { 63 } else { 31 }),
        );
        let result = self.binary(
            if i.mnemonic() == M::Rol {
                Operation::RotateLeft
            } else {
                Operation::RotateRight
            },
            value,
            count,
        );
        let zero = self.compare(Operation::Equal, count, self.constant(width, 0));
        let one = self.compare(Operation::Equal, count, self.constant(width, 1));
        let carry = self.unary(
            Operation::Extract {
                offset: if i.mnemonic() == M::Rol { 0 } else { width - 1 },
            },
            result,
            Type::Bits(1),
        );
        let carry_out = self.emit(
            Type::Bits(1),
            Operation::Select,
            vec![zero, self.flag(0), carry],
        );
        let sign = self.unary(
            Operation::Extract { offset: width - 1 },
            result,
            Type::Bits(1),
        );
        let other = if i.mnemonic() == M::Rol {
            carry
        } else {
            self.unary(
                Operation::Extract { offset: width - 2 },
                result,
                Type::Bits(1),
            )
        };
        let overflow = self.binary(Operation::Xor, sign, other);
        let undefined = self.unknown(
            Type::Bits(1),
            "rotate overflow is undefined for masked counts above one",
        );
        let overflow = self.emit(
            Type::Bits(1),
            Operation::Select,
            vec![one, overflow, undefined],
        );
        let overflow = self.emit(
            Type::Bits(1),
            Operation::Select,
            vec![zero, self.flag(5), overflow],
        );
        self.set_flag(0, carry_out);
        self.set_flag(5, overflow);
        self.write(i, result, address)
    }
    fn multiply(&mut self, i: &Instruction) -> Result<(), String> {
        self.comparison = None;
        let width = self.width(i, 0)?;
        let one = i.op_count() == 1;
        let signed = i.mnemonic() == M::Imul;
        let accumulator = match width {
            8 => R::AL,
            16 => R::AX,
            32 => R::EAX,
            64 => R::RAX,
            _ => return Err("unsupported multiply width".into()),
        };
        let (left, right) = if one {
            (self.register(accumulator)?, self.read(i, 0, width)?)
        } else {
            let first = u32::from(i.op_count() == 3);
            (self.read(i, first, width)?, self.read(i, first + 1, width)?)
        };
        let low = self.binary(Operation::Mul, left, right);
        let high = self.binary(
            if signed {
                Operation::SignedMulHigh
            } else {
                Operation::UnsignedMulHigh
            },
            left,
            right,
        );
        let expected = if signed {
            let sign = self.unary(Operation::Extract { offset: width - 1 }, low, Type::Bits(1));
            self.resize(sign, width, true)
        } else {
            self.constant(width, 0)
        };
        let fits = self.compare(Operation::Equal, high, expected);
        let overflow = self.binary(Operation::Xor, fits, self.constant(1, 1));
        self.set_flag(0, overflow);
        self.set_flag(5, overflow);
        for flag in [1, 2, 3, 4] {
            let value = self.unknown(Type::Bits(1), "multiply leaves this flag undefined");
            self.set_flag(flag, value);
        }
        if one {
            if width == 8 {
                let low = self.resize(low, 16, false);
                let full = self.emit(
                    Type::Bits(16),
                    Operation::Insert { offset: 8 },
                    vec![low, high],
                );
                self.write_register(R::AX, full)?;
            } else {
                self.write_register(accumulator, low)?;
                self.write_register(
                    match width {
                        16 => R::DX,
                        32 => R::EDX,
                        _ => R::RDX,
                    },
                    high,
                )?;
            }
        } else {
            self.write(i, low, None)?;
        }
        Ok(())
    }
    fn stack_address(&mut self, sp: Operand) -> Operand {
        let mut bits = sp;
        if self.bits == 32 {
            let id = self
                .function
                .variables
                .iter()
                .take(self.arch_count)
                .position(|v| v.name == "ss_base")
                .unwrap();
            let base = self.unary(
                Operation::ToBits,
                Operand::Variable(id),
                Type::Bits(self.bits),
            );
            bits = self.binary(Operation::Add, bits, base);
        }
        self.unary(Operation::ToAddress, bits, Type::Address(self.bits))
    }
    fn shift(&mut self, i: &Instruction) -> Result<(), String> {
        self.comparison = None;
        let width = self.width(i, 0)?;
        let address = if i.op0_kind() == OpKind::Memory {
            Some(self.address(i)?)
        } else {
            None
        };
        let left = self.read(i, 0, width)?;
        let raw = self.read(i, 1, 8)?;
        let count = self.binary(
            Operation::And,
            raw,
            self.constant(8, if width == 64 { 63 } else { 31 }),
        );
        let count = self.resize(count, width, false);
        let zero = self.compare(Operation::Equal, count, self.constant(width, 0));
        let one = self.compare(Operation::Equal, count, self.constant(width, 1));
        let old: Vec<_> = (0..6)
            .map(|n| self.emit(Type::Bits(1), Operation::Copy, vec![self.flag(n)]))
            .collect();
        let right = i.mnemonic() != M::Shl;
        let mut result = self.binary(
            if right {
                Operation::Shr
            } else {
                Operation::Shl
            },
            left,
            count,
        );
        let sign = self.unary(
            Operation::Extract { offset: width - 1 },
            left,
            Type::Bits(1),
        );
        if i.mnemonic() == M::Sar {
            let sign = self.resize(sign, width, false);
            let signmask = self.binary(Operation::Sub, self.constant(width, 0), sign);
            let missing = self.binary(Operation::Shr, self.constant(width, mask(width)), count);
            let missing = self.unary(Operation::Not, missing, Type::Bits(width));
            let fill = self.binary(Operation::And, signmask, missing);
            result = self.binary(Operation::Or, result, fill);
        }
        let valid = self.compare(
            Operation::UnsignedLess,
            count,
            self.constant(width, width as u64),
        );
        let carry_count = if right {
            let capped = self.emit(
                Type::Bits(width),
                Operation::Select,
                vec![valid, count, self.constant(width, width as u64)],
            );
            self.binary(Operation::Sub, capped, self.constant(width, 1))
        } else {
            self.binary(Operation::Sub, self.constant(width, width as u64), count)
        };
        let carry = self.binary(Operation::Shr, left, carry_count);
        let carry = self.unary(Operation::Extract { offset: 0 }, carry, Type::Bits(1));
        let undefined = self.unknown(
            Type::Bits(1),
            "shift flag undefined for this effective count",
        );
        let carry = if i.mnemonic() == M::Sar {
            carry
        } else {
            self.emit(
                Type::Bits(1),
                Operation::Select,
                vec![valid, carry, undefined],
            )
        };
        let sf = self.unary(
            Operation::Extract { offset: width - 1 },
            result,
            Type::Bits(1),
        );
        let of = match i.mnemonic() {
            M::Shl => self.binary(Operation::Xor, sf, carry),
            M::Shr => sign,
            _ => self.constant(1, 0),
        };
        let of = self.emit(Type::Bits(1), Operation::Select, vec![one, of, undefined]);
        let zf = self.compare(Operation::Equal, result, self.constant(width, 0));
        let pf = self.unary(Operation::Parity, result, Type::Bits(1));
        for (n, new) in [carry, pf, undefined, zf, sf, of].into_iter().enumerate() {
            let v = self.emit(Type::Bits(1), Operation::Select, vec![zero, old[n], new]);
            self.set_flag(n, v);
        }
        self.write(i, result, address)
    }
    fn instruction(&mut self, i: &Instruction, bytes: &[u8]) -> Result<(), String> {
        if i.has_lock_prefix() || i.has_rep_prefix() || i.has_repne_prefix() {
            return Err("atomic/repeat prefixes are not lifted".into());
        }
        let (address_bits, operand_override) = prefix_modes(bytes, self.bits);
        self.address_bits = address_bits;
        match i.mnemonic() {
            M::Nop => {}
            M::Mov | M::Movzx | M::Movsx | M::Movsxd => {
                let dst = self.width(i, 0)?;
                let src = if i.op1_kind() == OpKind::Register || i.op1_kind() == OpKind::Memory {
                    self.width(i, 1)?
                } else {
                    dst
                };
                let value = self.read(i, 1, src)?;
                let value = self.resize(value, dst, matches!(i.mnemonic(), M::Movsx | M::Movsxd));
                self.write(i, value, None)?;
            }
            M::Lea => {
                if i.op1_kind() != OpKind::Memory {
                    return Err("LEA requires memory-form address".into());
                }
                let address = self.address(i)?;
                let value = self.unary(Operation::ToBits, address, Type::Bits(self.bits));
                let value = self.resize(value, self.width(i, 0)?, false);
                self.write(i, value, None)?;
            }
            M::Add | M::Sub | M::And | M::Or | M::Xor | M::Cmp | M::Test => {
                let width = self.width(i, 0)?;
                let address = if i.op0_kind() == OpKind::Memory {
                    Some(self.address(i)?)
                } else {
                    None
                };
                let left = self.read(i, 0, width)?;
                let right = if i.op0_kind() == OpKind::Register
                    && i.op1_kind() == OpKind::Register
                    && i.op0_register() == i.op1_register()
                {
                    left
                } else {
                    self.read(i, 1, width)?
                };
                if self.ty(right) != Type::Bits(width) {
                    return Err("binary operand width mismatch".into());
                }
                let op = match i.mnemonic() {
                    M::Add => Operation::Add,
                    M::Sub | M::Cmp => Operation::Sub,
                    M::And | M::Test => Operation::And,
                    M::Or => Operation::Or,
                    _ => Operation::Xor,
                };
                let result = self.binary(op, left, right);
                self.flags(i.mnemonic(), left, right, result);
                if i.mnemonic() == M::Cmp {
                    let left = self.emit(self.ty(left), Operation::Copy, vec![left]);
                    let right = self.emit(self.ty(right), Operation::Copy, vec![right]);
                    self.comparison = Some((left, right));
                }
                if !matches!(i.mnemonic(), M::Cmp | M::Test) {
                    self.write(i, result, address)?;
                }
            }
            M::Inc | M::Dec => {
                let width = self.width(i, 0)?;
                let address = if i.op0_kind() == OpKind::Memory {
                    Some(self.address(i)?)
                } else {
                    None
                };
                let left = self.read(i, 0, width)?;
                let carry = self.emit(Type::Bits(1), Operation::Copy, vec![self.flag(0)]);
                let one = self.constant(width, 1);
                let add = i.mnemonic() == M::Inc;
                let result =
                    self.binary(if add { Operation::Add } else { Operation::Sub }, left, one);
                self.flags(if add { M::Add } else { M::Sub }, left, one, result);
                self.set_flag(0, carry);
                self.write(i, result, address)?;
            }
            M::Push => {
                let width = if operand_override { 16 } else { self.bits };
                let value = self.read(i, 0, width)?;
                let value = self.emit(self.ty(value), Operation::Copy, vec![value]);
                if self.ty(value) != Type::Bits(width) {
                    return Err("unsupported push width".into());
                }
                let old = Operand::Variable(4);
                let sp = self.binary(
                    Operation::Sub,
                    old,
                    self.constant(self.bits, (width / 8) as u64),
                );
                self.assign(4, sp);
                let address = self.stack_address(sp);
                self.ops.push(Statement {
                    source: self.source,
                    output: Some(self.memory),
                    op: Operation::Store,
                    args: vec![Operand::Variable(self.memory), address, value],
                });
            }
            M::Pop => {
                if i.op0_kind() != OpKind::Register {
                    return Err("POP memory form is not lifted".into());
                }
                let width = self.width(i, 0)?;
                let old = Operand::Variable(4);
                let address = self.stack_address(old);
                let value = self.emit(
                    Type::Bits(width),
                    Operation::Load,
                    vec![Operand::Variable(self.memory), address],
                );
                let sp = self.binary(
                    Operation::Add,
                    old,
                    self.constant(self.bits, (width / 8) as u64),
                );
                self.assign(4, sp);
                self.write(i, value, None)?;
            }
            M::Jmp => {
                let w = if i.op0_kind() == OpKind::Register || i.op0_kind() == OpKind::Memory {
                    self.width(i, 0)?
                } else {
                    self.bits
                };
                let target = self.read(i, 0, w)?;
                self.transfer = Some(if matches!(self.ty(target), Type::Address(_)) {
                    target
                } else {
                    let v = self.resize(target, self.bits, false);
                    self.unary(Operation::ToAddress, v, Type::Address(self.bits))
                });
            }
            M::Call => {
                self.comparison = None;
                let width = if matches!(i.op0_kind(), OpKind::Register | OpKind::Memory) {
                    self.width(i, 0)?
                } else {
                    self.bits
                };
                let target = self.read(i, 0, width)?;
                let target = if matches!(self.ty(target), Type::Address(_)) {
                    target
                } else {
                    let value = self.resize(target, self.bits, false);
                    self.unary(Operation::ToAddress, value, Type::Address(self.bits))
                };
                let mut args = vec![target];
                args.extend(self.state());
                self.ops.push(Statement {
                    source: self.source,
                    output: None,
                    op: Operation::Call,
                    args,
                });
                for v in 0..self.arch_count {
                    self.ops.push(Statement {
                        source: self.source,
                        output: Some(v),
                        op: Operation::Unknown {
                            reason: "call effects: no assumed ABI or memory preservation".into(),
                        },
                        args: vec![],
                    });
                }
            }
            M::Ret => {
                if operand_override {
                    return Err("16-bit near return semantics are not lifted".into());
                }
                let width = if operand_override { 16 } else { self.bits };
                let old = Operand::Variable(4);
                let address = self.stack_address(old);
                let target = self.emit(
                    Type::Bits(width),
                    Operation::Load,
                    vec![Operand::Variable(self.memory), address],
                );
                let extra = if i.op_count() == 1 {
                    i.immediate16() as u64
                } else {
                    0
                };
                let sp = self.binary(
                    Operation::Add,
                    old,
                    self.constant(self.bits, (width / 8) as u64 + extra),
                );
                self.assign(4, sp);
                let target = self.resize(target, self.bits, false);
                self.transfer =
                    Some(self.unary(Operation::ToAddress, target, Type::Address(self.bits)));
            }
            M::Mul | M::Imul => self.multiply(i)?,
            M::Div | M::Idiv => self.divide(i)?,
            M::Cbw | M::Cwde | M::Cdqe => {
                let (from, to) = match i.mnemonic() {
                    M::Cbw => (R::AL, R::AX),
                    M::Cwde => (R::AX, R::EAX),
                    _ => (R::EAX, R::RAX),
                };
                let value = self.register(from)?;
                let value = self.resize(value, (to.size() * 8) as u16, true);
                self.write_register(to, value)?;
            }
            M::Cwd | M::Cdq | M::Cqo => {
                let (from, to, width) = match i.mnemonic() {
                    M::Cwd => (R::AX, R::DX, 16),
                    M::Cdq => (R::EAX, R::EDX, 32),
                    _ => (R::RAX, R::RDX, 64),
                };
                let value = self.register(from)?;
                let sign = self.unary(
                    Operation::Extract { offset: width - 1 },
                    value,
                    Type::Bits(1),
                );
                let value = self.resize(sign, width, true);
                self.write_register(to, value)?;
            }
            M::Rol | M::Ror => self.rotate(i)?,
            M::Shl | M::Shr | M::Sar => self.shift(i)?,
            M::Seto
            | M::Setno
            | M::Setb
            | M::Setae
            | M::Sete
            | M::Setne
            | M::Setbe
            | M::Seta
            | M::Sets
            | M::Setns
            | M::Setp
            | M::Setnp
            | M::Setl
            | M::Setge
            | M::Setle
            | M::Setg => {
                let condition = self.condition(i.condition_code())?;
                let value = self.resize(condition, 8, false);
                self.write(i, value, None)?;
            }
            M::Cmovo
            | M::Cmovno
            | M::Cmovb
            | M::Cmovae
            | M::Cmove
            | M::Cmovne
            | M::Cmovbe
            | M::Cmova
            | M::Cmovs
            | M::Cmovns
            | M::Cmovp
            | M::Cmovnp
            | M::Cmovl
            | M::Cmovge
            | M::Cmovle
            | M::Cmovg => {
                let width = self.width(i, 0)?;
                let old = self.read(i, 0, width)?;
                // The source memory read is unconditional, even when false.
                let new = self.read(i, 1, width)?;
                let condition = self.condition(i.condition_code())?;
                let value = self.emit(
                    Type::Bits(width),
                    Operation::Select,
                    vec![condition, new, old],
                );
                self.write(i, value, None)?;
            }
            _ if i.is_jcc_short_or_near() => {
                self.transfer = Some(self.condition(i.condition_code())?);
            }
            _ => return Err(format!("unsupported semantics: {:?}", i.mnemonic())),
        }
        Ok(())
    }
}
