//! Versioned, architecture-neutral bit-vector IR. No GUI or decoder types escape
//! the x86 lifter. Unknown effects are explicit state barriers.
pub mod dataflow;
pub mod evaluate;
pub mod inspect;
mod lift;
pub mod ssa;
mod verify;

pub(crate) use lift::{lift_cpu_instruction, CpuFlow};
pub use lift::{lift_function, lift_image};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
pub use verify::verify;

pub const IR_VERSION: u32 = 1;
pub const MAX_IR_BLOCKS: usize = 1024;
pub const MAX_IR_INSTRUCTIONS: usize = 10_000;
pub const MAX_IR_OPERATIONS: usize = 80_000;
pub const MAX_IR_EDGES: usize = 4096;
pub type VariableId = usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(pub u64);
impl Serialize for Address {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::format_address(self.0))
    }
}
impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        crate::parse_address(&String::deserialize(d)?)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}
impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "width", rename_all = "camelCase")]
pub enum Type {
    Bits(u16),
    Address(u16),
    Memory,
}
impl Type {
    pub fn width(self) -> Option<u16> {
        match self {
            Self::Bits(w) | Self::Address(w) => Some(w),
            Self::Memory => None,
        }
    }
    pub fn valid(self) -> bool {
        match self {
            Self::Bits(w) => (1..=64).contains(&w),
            Self::Address(w) => matches!(w, 16 | 32 | 64),
            Self::Memory => true,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Constant {
    pub ty: Type,
    pub value: Address,
}
impl Constant {
    pub fn valid(self) -> bool {
        self.ty.valid()
            && self.ty != Type::Memory
            && self.value.0 & !mask(self.ty.width().unwrap()) == 0
    }
    pub fn bits(width: u16, value: u64) -> Self {
        Self {
            ty: Type::Bits(width),
            value: Address(value & mask(width)),
        }
    }
}
pub fn mask(width: u16) -> u64 {
    if width >= 64 {
        u64::MAX
    } else if width == 0 {
        0
    } else {
        (1u64 << width) - 1
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum VariableKind {
    Register,
    Flag,
    Memory,
    Temporary,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Variable {
    pub name: String,
    pub ty: Type,
    pub kind: VariableKind,
}
impl Variable {
    pub fn valid(&self) -> bool {
        self.ty.valid()
            && match self.kind {
                VariableKind::Flag => self.ty == Type::Bits(1),
                VariableKind::Memory => self.ty == Type::Memory,
                VariableKind::Register => self.ty != Type::Memory,
                VariableKind::Temporary => true,
            }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
pub enum Operand {
    Variable(VariableId),
    Constant(Constant),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Operation {
    Copy,
    Add,
    Sub,
    Mul,
    UnsignedMulHigh,
    SignedMulHigh,
    Divide {
        signed: bool,
        remainder: bool,
    },
    DivideFault {
        signed: bool,
    },
    /// Stop before subsequent effects when the one-bit condition is true.
    Guard {
        reason: String,
    },
    And,
    Or,
    Xor,
    Not,
    Shl,
    Shr,
    RotateLeft,
    RotateRight,
    Equal,
    UnsignedLess,
    SignedLess,
    ZeroExtend,
    SignExtend,
    Truncate,
    Extract {
        offset: u16,
    },
    Insert {
        offset: u16,
    },
    Select,
    Parity,
    ToAddress,
    ToBits,
    Load,
    Store,
    Call,
    Barrier {
        reason: String,
    },
    Unknown {
        reason: String,
    },
}
impl Operation {
    pub fn observable(&self) -> bool {
        matches!(
            self,
            Self::Load
                | Self::Store
                | Self::Call
                | Self::Barrier { .. }
                | Self::Guard { .. }
                | Self::Unknown { .. }
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Statement {
    pub source: Address,
    pub output: Option<VariableId>,
    pub op: Operation,
    pub args: Vec<Operand>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FlowKind {
    Jump,
    Branch,
    Return,
    Indirect,
    Unresolved,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Terminator {
    pub source: Address,
    pub kind: FlowKind,
    /// Condition for Branch; computed destination for Return/Indirect.
    pub value: Option<Operand>,
    /// Internal edges only. Missing/external destinations are explicit exits.
    pub successors: Vec<Address>,
    pub exits: Vec<Address>,
    pub taken: Option<Address>,
    pub fallthrough: Option<Address>,
    /// Conservatively observable machine state on exits (no assumed ABI).
    pub state: Vec<Operand>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub address: Address,
    pub end: Address,
    pub function: Address,
    pub statements: Vec<Statement>,
    pub terminator: Terminator,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Diagnostic {
    pub source: Address,
    pub message: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Function {
    pub ir_version: u32,
    pub entry: Address,
    pub address_width: u16,
    pub variables: Vec<Variable>,
    pub blocks: Vec<Block>,
    pub diagnostics: Vec<Diagnostic>,
    pub source_instructions: usize,
}
impl Function {
    pub fn predecessors(&self) -> BTreeMap<Address, Vec<Address>> {
        let mut result: BTreeMap<_, Vec<_>> =
            self.blocks.iter().map(|b| (b.address, vec![])).collect();
        for b in &self.blocks {
            for s in &b.terminator.successors {
                if let Some(p) = result.get_mut(s) {
                    p.push(b.address);
                }
            }
        }
        for p in result.values_mut() {
            p.sort_unstable();
            p.dedup();
        }
        result
    }
    pub fn operand_type(&self, value: Operand) -> Option<Type> {
        match value {
            Operand::Variable(v) => self.variables.get(v).map(|v| v.ty),
            Operand::Constant(c) => Some(c.ty),
        }
    }
}
