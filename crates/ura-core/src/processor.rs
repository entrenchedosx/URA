//! Processor identity, scalar register/ABI metadata and mature typed decoders.
//! Decoding never establishes semantic, debugger or assembler support.
use crate::{
    binary::{Analysis, CpuArchitecture, Endianness},
    InstructionFlow,
};
use capstone::{
    arch::{arm::*, arm64::*, riscv::*},
    prelude::*,
    RegId,
};
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, collections::BTreeMap};
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Processor {
    X86,
    #[serde(rename = "x86-64", alias = "x86_64", alias = "x64")]
    X86_64,
    #[serde(alias = "arm64")]
    Aarch64,
    #[serde(alias = "arm32")]
    Arm,
    Thumb,
    #[serde(alias = "rv32")]
    Riscv32,
    #[serde(alias = "rv64")]
    Riscv64,
}
impl Processor {
    pub fn name(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86-64",
            Self::Aarch64 => "aarch64",
            Self::Arm => "arm",
            Self::Thumb => "thumb",
            Self::Riscv32 => "riscv32",
            Self::Riscv64 => "riscv64",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "x86" => Some(Self::X86),
            "x86-64" | "x86_64" | "x64" => Some(Self::X86_64),
            "aarch64" | "arm64" => Some(Self::Aarch64),
            "arm" | "arm32" => Some(Self::Arm),
            "thumb" => Some(Self::Thumb),
            "riscv32" | "rv32" => Some(Self::Riscv32),
            "riscv64" | "rv64" => Some(Self::Riscv64),
            _ => None,
        }
    }
    pub fn bits(self) -> u8 {
        if matches!(self, Self::X86_64 | Self::Aarch64 | Self::Riscv64) {
            64
        } else {
            32
        }
    }
    pub fn alignment(self) -> u64 {
        match self {
            Self::X86 | Self::X86_64 => 1,
            Self::Aarch64 | Self::Arm => 4,
            _ => 2,
        }
    }
    pub fn x86(self) -> bool {
        matches!(self, Self::X86 | Self::X86_64)
    }
    pub fn stack(self) -> &'static str {
        match self {
            Self::X86 => "esp",
            Self::X86_64 => "rsp",
            Self::Aarch64 => "sp",
            Self::Arm | Self::Thumb => "r13",
            _ => "sp",
        }
    }
    pub fn link(self) -> Option<&'static str> {
        match self {
            Self::Aarch64 => Some("x30"),
            Self::Arm | Self::Thumb => Some("r14"),
            Self::Riscv32 | Self::Riscv64 => Some("ra"),
            _ => None,
        }
    }
    pub fn result(self) -> &'static str {
        match self {
            Self::X86 => "eax",
            Self::X86_64 => "rax",
            Self::Aarch64 => "x0",
            Self::Arm | Self::Thumb => "r0",
            _ => "a0",
        }
    }
    pub fn architecture(self) -> CpuArchitecture {
        match self {
            Self::X86 => CpuArchitecture::X86,
            Self::X86_64 => CpuArchitecture::X86_64,
            Self::Aarch64 => CpuArchitecture::Aarch64,
            Self::Arm | Self::Thumb => CpuArchitecture::Arm,
            Self::Riscv32 => CpuArchitecture::Riscv32,
            Self::Riscv64 => CpuArchitecture::Riscv64,
        }
    }
    pub fn for_analysis(a: &Analysis) -> Result<Self, String> {
        if a.endianness != Endianness::Little {
            return Err("semantic decoding currently requires little-endian code".into());
        }
        let mut thumb_mapping = false;
        if a.architecture == CpuArchitecture::Arm {
            if a.format == "PE" {
                return Err("ARM32 PE execution-mode selection is not qualified; use ARM/Thumb ELF or explicit raw mode".into());
            }
            let arm = a
                .symbols
                .iter()
                .any(|s| s.name == "$a" || s.name.starts_with("$a."));
            let thumb = a
                .symbols
                .iter()
                .any(|s| s.name == "$t" || s.name.starts_with("$t."));
            thumb_mapping = thumb;
            let odd_function = a
                .symbols
                .iter()
                .any(|s| s.kind == "function" && s.address.is_some_and(|v| v & 1 != 0));
            let even_function = a
                .symbols
                .iter()
                .any(|s| s.kind == "function" && s.address.is_some_and(|v| v & 1 == 0));
            let entry_arm = a.entry_point.is_some_and(|v| v != 0 && v & 1 == 0);
            let entry_thumb = a.entry_point.is_some_and(|v| v & 1 != 0);
            if a.format != "raw"
                && !(arm || thumb || odd_function || even_function || entry_arm || entry_thumb)
            {
                return Err(
                    "ARM execution mode is ambiguous; select an explicit raw processor".into(),
                );
            }
            if (arm || even_function || entry_arm) && (thumb || odd_function || entry_thumb) {
                return Err(
                    "mixed ARM/Thumb code requires mode-aware mapping transitions; not implemented"
                        .into(),
                );
            }
        }
        let p = match a.architecture {
            CpuArchitecture::X86 => Self::X86,
            CpuArchitecture::X86_64 => Self::X86_64,
            CpuArchitecture::Aarch64 => Self::Aarch64,
            CpuArchitecture::Arm => {
                if a.object_kind.contains("thumb")
                    || thumb_mapping
                    || a.entry_point.is_some_and(|a| a & 1 != 0)
                {
                    Self::Thumb
                } else {
                    Self::Arm
                }
            }
            CpuArchitecture::Riscv32 => Self::Riscv32,
            CpuArchitecture::Riscv64 => Self::Riscv64,
            _ => {
                return Err(format!(
                    "processor {} is not implemented",
                    a.architecture.name()
                ))
            }
        };
        if p.bits() != a.bitness {
            return Err("processor identity/bitness mismatch".into());
        }
        Ok(p)
    }
    pub fn roots(self) -> Vec<String> {
        match self {
            Self::Aarch64 => (0..31)
                .map(|n| format!("x{n}"))
                .chain(["sp", "n", "z", "c", "v"].map(str::to_owned))
                .collect(),
            Self::Arm | Self::Thumb => (0..15)
                .map(|n| format!("r{n}"))
                .chain(["n", "z", "c", "v"].map(str::to_owned))
                .collect(),
            Self::Riscv32 | Self::Riscv64 => {
                RISCV_NAMES[1..].iter().map(|s| s.to_string()).collect()
            }
            _ => vec![],
        }
    }
    pub fn metadata(self) -> serde_json::Value {
        serde_json::json!({"processor":self,"bitness":self.bits(),"endianness":"little","instructionAlignment":self.alignment(),"maxInstructionBytes":if self.x86(){15}else{4},"variableLength":self.x86()||matches!(self,Self::Thumb|Self::Riscv32|Self::Riscv64),"stackRegister":self.stack(),"linkRegister":self.link(),"returnRegister":self.result(),"scalarRoots":self.roots(),"vectorRegisters":if self==Self::Aarch64{(0..32).map(|n|format!("v{n}:128 (metadata only)")).collect::<Vec<_>>()}else{vec![]},"liveDebugger":if self==Self::X86_64{"Windows x64 scoped backend"}else{"unsupported"},"instructionAssembly":if self.x86(){"scoped x86 assembler"}else{"unsupported"}})
    }
}
pub const RISCV_NAMES: [&str; 32] = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
    "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
    "t5", "t6",
];
#[derive(Clone, Debug)]
pub enum Arg {
    Reg(String),
    Imm(i64),
    Mem {
        base: String,
        index: String,
        disp: i64,
    },
    Unsupported,
}
#[derive(Clone, Debug)]
pub struct ScalarArg {
    pub value: Arg,
    pub shift: Shift,
    pub extend: Extend,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shift {
    None,
    Lsl(u32),
    Lsr(u32),
    Asr(u32),
    Ror(u32),
    Unsupported,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Extend {
    None,
    Unsigned(u16),
    Signed(u16),
    Unsupported,
}
#[derive(Clone, Debug)]
pub struct Decoded {
    pub arm_hint_nop: bool,
    pub privileged: bool,
    pub id: u32,
    pub address: u64,
    pub length: usize,
    pub mnemonic: String,
    pub text: String,
    pub args: Vec<ScalarArg>,
    pub flow: InstructionFlow,
    pub target: Option<u64>,
    pub condition: u8,
    pub flags: bool,
    pub writeback: bool,
}
thread_local! {static ENGINES:RefCell<BTreeMap<Processor,Capstone>>=const{RefCell::new(BTreeMap::new())};}
fn engine(p: Processor) -> Result<Capstone, String> {
    let b = match p {
        Processor::Aarch64 => Capstone::new()
            .arm64()
            .mode(capstone::arch::arm64::ArchMode::Arm)
            .detail(true)
            .build(),
        Processor::Arm => Capstone::new()
            .arm()
            .mode(capstone::arch::arm::ArchMode::Arm)
            .detail(true)
            .build(),
        Processor::Thumb => Capstone::new()
            .arm()
            .mode(capstone::arch::arm::ArchMode::Thumb)
            .detail(true)
            .build(),
        Processor::Riscv32 => Capstone::new()
            .riscv()
            .mode(capstone::arch::riscv::ArchMode::RiscV32)
            .extra_mode([capstone::arch::riscv::ArchExtraMode::RiscVC].into_iter())
            .detail(true)
            .build(),
        Processor::Riscv64 => Capstone::new()
            .riscv()
            .mode(capstone::arch::riscv::ArchMode::RiscV64)
            .extra_mode([capstone::arch::riscv::ArchExtraMode::RiscVC].into_iter())
            .detail(true)
            .build(),
        _ => return Err("use established x86 decoder".into()),
    };
    b.map_err(|e| e.to_string())
}
fn reg(cs: &Capstone, p: Processor, r: RegId) -> String {
    let s = cs.reg_name(r).unwrap_or_default();
    match (p, s.as_str()) {
        (Processor::Aarch64, "fp") => "x29".into(),
        (Processor::Aarch64, "lr") => "x30".into(),
        (Processor::Arm | Processor::Thumb, "sp") => "r13".into(),
        (Processor::Arm | Processor::Thumb, "lr") => "r14".into(),
        (Processor::Arm | Processor::Thumb, "pc") => "r15".into(),
        (Processor::Arm | Processor::Thumb, "fp") => "r11".into(),
        (Processor::Arm | Processor::Thumb, "ip") => "r12".into(),
        (Processor::Arm | Processor::Thumb, "sb") => "r9".into(),
        (Processor::Arm | Processor::Thumb, "sl") => "r10".into(),
        _ => s,
    }
}
fn plain(value: Arg) -> ScalarArg {
    ScalarArg {
        value,
        shift: Shift::None,
        extend: Extend::None,
    }
}
pub fn decode(p: Processor, bytes: &[u8], address: u64) -> Result<Decoded, String> {
    if address % p.alignment() != 0 {
        return Err("instruction address is misaligned for selected processor".into());
    }
    ENGINES.with(|engines| {
        let mut engines = engines.borrow_mut();
        if let std::collections::btree_map::Entry::Vacant(entry) = engines.entry(p) {
            entry.insert(engine(p)?);
        }
        let cs = &engines[&p];
        let instructions = cs
            .disasm_count(bytes, address, 1)
            .map_err(|e| e.to_string())?;
        let i = instructions
            .iter()
            .next()
            .ok_or("invalid/truncated processor instruction")?;
        let detail = cs.insn_detail(i).map_err(|e| e.to_string())?;
        let a = detail.arch_detail();
        let mut out = Decoded {
            privileged: detail
                .groups()
                .iter()
                .any(|g| g.0 == capstone::InsnGroupType::CS_GRP_PRIVILEGE as u8),
            arm_hint_nop: match p {
                Processor::Arm => bytes.get(..4).is_some_and(|b| {
                    u32::from_le_bytes(b.try_into().unwrap()) & 0x0fffffff == 0x0320f000
                }),
                Processor::Thumb => {
                    bytes.starts_with(&[0x00, 0xbf]) || bytes.starts_with(&[0xaf, 0xf3, 0x00, 0x80])
                }
                _ => false,
            },
            id: i.id().0,
            address,
            length: i.bytes().len(),
            mnemonic: i.mnemonic().unwrap_or("invalid").into(),
            text: i.op_str().unwrap_or("").into(),
            args: vec![],
            flow: InstructionFlow::Next,
            target: None,
            condition: 0,
            flags: false,
            writeback: false,
        };
        if let Some(a) = a.arm64() {
            out.condition = a.cc() as u8;
            out.flags = a.update_flags();
            out.writeback = a.writeback();
            for op in a.operands() {
                out.args.push(ScalarArg {
                    value: match op.op_type {
                        Arm64OperandType::Reg(r) => Arg::Reg(reg(cs, p, r)),
                        Arm64OperandType::Imm(n) => Arg::Imm(n),
                        Arm64OperandType::Mem(m) => Arg::Mem {
                            base: reg(cs, p, m.base()),
                            index: reg(cs, p, m.index()),
                            disp: i64::from(m.disp()),
                        },
                        _ => Arg::Unsupported,
                    },
                    shift: match op.shift {
                        Arm64Shift::Invalid => Shift::None,
                        Arm64Shift::Lsl(n) => Shift::Lsl(n),
                        Arm64Shift::Lsr(n) => Shift::Lsr(n),
                        Arm64Shift::Asr(n) => Shift::Asr(n),
                        Arm64Shift::Ror(n) => Shift::Ror(n),
                        _ => Shift::Unsupported,
                    },
                    extend: match op.ext {
                        Arm64Extender::ARM64_EXT_INVALID => Extend::None,
                        Arm64Extender::ARM64_EXT_UXTB => Extend::Unsigned(8),
                        Arm64Extender::ARM64_EXT_UXTH => Extend::Unsigned(16),
                        Arm64Extender::ARM64_EXT_UXTW => Extend::Unsigned(32),
                        Arm64Extender::ARM64_EXT_UXTX => Extend::Unsigned(64),
                        Arm64Extender::ARM64_EXT_SXTB => Extend::Signed(8),
                        Arm64Extender::ARM64_EXT_SXTH => Extend::Signed(16),
                        Arm64Extender::ARM64_EXT_SXTW => Extend::Signed(32),
                        Arm64Extender::ARM64_EXT_SXTX => Extend::Signed(64),
                    },
                });
            }
            use Arm64Insn::*;
            out.flow = match out.id {
                n if n == ARM64_INS_BL as u32 => InstructionFlow::Call,
                n if n == ARM64_INS_BLR as u32 => InstructionFlow::IndirectCall,
                n if n == ARM64_INS_BR as u32 => InstructionFlow::IndirectJump,
                n if n == ARM64_INS_RET as u32 => InstructionFlow::Return,
                n if n == ARM64_INS_B as u32 => {
                    if matches!(out.condition, 0 | 15 | 16) {
                        InstructionFlow::Jump
                    } else {
                        InstructionFlow::ConditionalJump
                    }
                }
                n if [
                    ARM64_INS_CBZ as u32,
                    ARM64_INS_CBNZ as u32,
                    ARM64_INS_TBZ as u32,
                    ARM64_INS_TBNZ as u32,
                ]
                .contains(&n) =>
                {
                    InstructionFlow::ConditionalJump
                }
                n if [
                    ARM64_INS_SVC as u32,
                    ARM64_INS_BRK as u32,
                    ARM64_INS_HLT as u32,
                ]
                .contains(&n) =>
                {
                    InstructionFlow::Exception
                }
                _ => InstructionFlow::Next,
            };
        } else if let Some(a) = a.arm() {
            out.condition = a.cc() as u8;
            out.flags = a.update_flags();
            out.writeback = a.writeback();
            for op in a.operands() {
                let value = match op.op_type {
                    ArmOperandType::Reg(r) => Arg::Reg(reg(cs, p, r)),
                    ArmOperandType::Imm(n) => Arg::Imm(i64::from(n)),
                    ArmOperandType::Mem(m) => Arg::Mem {
                        base: reg(cs, p, m.base()),
                        index: reg(cs, p, m.index()),
                        disp: i64::from(m.disp()),
                    },
                    _ => Arg::Unsupported,
                };
                out.args.push(ScalarArg {
                    value,
                    shift: match op.shift {
                        ArmShift::Invalid => Shift::None,
                        ArmShift::Lsl(n) => Shift::Lsl(n),
                        ArmShift::Lsr(n) => Shift::Lsr(n),
                        ArmShift::Asr(n) => Shift::Asr(n),
                        ArmShift::Ror(n) => Shift::Ror(n),
                        _ => Shift::Unsupported,
                    },
                    extend: if op.subtracted {
                        Extend::Unsupported
                    } else {
                        Extend::None
                    },
                });
            }
            use ArmInsn::*;
            out.flow = match out.id {
                n if n == ARM_INS_B as u32 => {
                    if out.condition == 15 || out.condition == 0 {
                        InstructionFlow::Jump
                    } else {
                        InstructionFlow::ConditionalJump
                    }
                }
                n if [ARM_INS_CBZ as u32, ARM_INS_CBNZ as u32].contains(&n) => {
                    InstructionFlow::ConditionalJump
                }
                n if n == ARM_INS_BLX as u32 => InstructionFlow::IndirectCall,
                n if n == ARM_INS_IT as u32 => InstructionFlow::Exception,
                n if n == ARM_INS_BX as u32 && !matches!(out.condition, 0 | 15) => {
                    InstructionFlow::Exception
                }
                n if n == ARM_INS_BL as u32 => {
                    if matches!(out.args.first().map(|a| &a.value), Some(Arg::Imm(_))) {
                        InstructionFlow::Call
                    } else {
                        InstructionFlow::IndirectCall
                    }
                }
                n if n == ARM_INS_BX as u32 => {
                    if matches!(out.args.first().map(|a|&a.value),Some(Arg::Reg(r)) if r=="r14") {
                        InstructionFlow::Return
                    } else {
                        InstructionFlow::IndirectJump
                    }
                }
                n if n == ARM_INS_POP as u32
                    && out
                        .args
                        .iter()
                        .any(|a| matches!(&a.value,Arg::Reg(r)if r=="r15")) =>
                {
                    InstructionFlow::Return
                }
                n if [ARM_INS_SVC as u32, ARM_INS_BKPT as u32, ARM_INS_UDF as u32].contains(&n) => {
                    InstructionFlow::Exception
                }
                _ => InstructionFlow::Next,
            };
        } else if let Some(a) = a.riscv() {
            for op in a.operands() {
                out.args.push(plain(match op {
                    RiscVOperand::Reg(r) => Arg::Reg(reg(cs, p, r)),
                    RiscVOperand::Imm(n) => Arg::Imm(n),
                    RiscVOperand::Mem(m) => Arg::Mem {
                        base: reg(cs, p, m.base()),
                        index: String::new(),
                        disp: m.disp(),
                    },
                    _ => Arg::Unsupported,
                }));
            }
            // Base instruction fields avoid alias spellings and preserve JAL x0 tails.
            let word = if bytes.len() >= 4 {
                u32::from_le_bytes(bytes[..4].try_into().unwrap())
            } else {
                0
            };
            let opcode = word & 127;
            let rd = (word >> 7) & 31;
            // Capstone renders certain aliases with implicit operands (ret,
            // mv, nop, j, jal). Restore only those base scalar operands after
            // its successful typed decode; instruction identity stays Capstone's.
            if out.length == 4 {
                let rr = |n: u32| plain(Arg::Reg(RISCV_NAMES[n as usize].into()));
                let imm = |n: i64| plain(Arg::Imm(n));
                let rs1 = (word >> 15) & 31;
                if opcode == 0x13 && out.args.len() < 3 {
                    out.args = vec![rr(rd), rr(rs1), imm(i64::from((word as i32) >> 20))];
                }
                if opcode == 0x6f {
                    let offset = out.args.iter().find_map(|a| {
                        if let Arg::Imm(n) = a.value {
                            Some(n)
                        } else {
                            None
                        }
                    });
                    if let Some(offset) = offset {
                        out.args = vec![rr(rd), imm(offset)];
                    }
                }
                if opcode == 0x67 {
                    out.args = vec![rr(rd), rr(rs1), imm(i64::from((word as i32) >> 20))];
                }
                if opcode == 0x63 && out.args.len() < 3 {
                    if let Some(last) = out.args.last().cloned() {
                        out.args = vec![rr(rs1), rr((word >> 20) & 31), last];
                    }
                }
            }
            out.flow = if out.length == 4 {
                match opcode {
                    0x63 => InstructionFlow::ConditionalJump,
                    0x6f => {
                        if rd == 1 || rd == 5 {
                            InstructionFlow::Call
                        } else {
                            InstructionFlow::Jump
                        }
                    }
                    0x67 => {
                        if rd == 0 && (word >> 15) & 31 == 1 && (word >> 20) == 0 {
                            InstructionFlow::Return
                        } else if rd == 1 || rd == 5 {
                            InstructionFlow::IndirectCall
                        } else {
                            InstructionFlow::IndirectJump
                        }
                    }
                    0x73 => InstructionFlow::Exception,
                    _ => InstructionFlow::Next,
                }
            } else {
                use RiscVInsn::*;
                match out.id {
                    n if [RISCV_INS_C_BEQZ as u32, RISCV_INS_C_BNEZ as u32].contains(&n) => {
                        InstructionFlow::ConditionalJump
                    }
                    n if n == RISCV_INS_C_J as u32 => InstructionFlow::Jump,
                    n if n == RISCV_INS_C_EBREAK as u32 => InstructionFlow::Exception,
                    n if n == RISCV_INS_C_JALR as u32 => InstructionFlow::IndirectCall,
                    n if n == RISCV_INS_C_JAL as u32 => InstructionFlow::Call,
                    n if n == RISCV_INS_C_JR as u32 => {
                        if matches!(out.args.first().map(|a|&a.value),Some(Arg::Reg(r))if r=="ra") {
                            InstructionFlow::Return
                        } else {
                            InstructionFlow::IndirectJump
                        }
                    }
                    _ => InstructionFlow::Next,
                }
            };
        }
        if out.flow == InstructionFlow::Next {
            let has = |group: u32| detail.groups().iter().any(|g| u32::from(g.0) == group);
            use capstone::InsnGroupType::*;
            if has(CS_GRP_RET) || has(CS_GRP_IRET) {
                out.flow = InstructionFlow::Return;
            } else if has(CS_GRP_CALL) {
                out.flow = InstructionFlow::IndirectCall;
            } else if has(CS_GRP_JUMP) {
                out.flow = InstructionFlow::IndirectJump;
            } else if has(CS_GRP_INT) {
                out.flow = InstructionFlow::Exception;
            }
        }
        if matches!(p, Processor::Arm | Processor::Thumb)
            && out.flow == InstructionFlow::Next
            && matches!(out.args.first().map(|a|&a.value),Some(Arg::Reg(r))if r=="r15")
            && ![
                ArmInsn::ARM_INS_CMP as u32,
                ArmInsn::ARM_INS_CMN as u32,
                ArmInsn::ARM_INS_TST as u32,
                ArmInsn::ARM_INS_TEQ as u32,
            ]
            .contains(&out.id)
        {
            out.flow = InstructionFlow::Exception;
        }
        if matches!(
            out.flow,
            InstructionFlow::Call | InstructionFlow::Jump | InstructionFlow::ConditionalJump
        ) {
            out.target = out.args.iter().rev().find_map(|a| {
                if let Arg::Imm(n) = a.value {
                    Some(n as u64)
                } else {
                    None
                }
            });
            if matches!(p, Processor::Riscv32 | Processor::Riscv64) {
                out.target = out
                    .target
                    .map(|n| address.wrapping_add(n) & crate::ir::mask(u16::from(p.bits())));
            }
        }
        Ok(out)
    })
}
