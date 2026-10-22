//! Deterministic C-like reconstruction from semantic HIR, never from text.
//! Machine memory operations remain ordered. Edge copies destroy SSA before
//! control structuring; the C-like AST has no phi-expression variant.
mod build;
pub mod evaluate;
mod print;

use super::{semantic, types::TypeRef};
use crate::ir::{Address, Constant, Type};
pub use build::{build, build_with_calls, parallel_copies};
pub use print::{identifier, render};
use serde::{Deserialize, Serialize};

pub const VERSION: u32 = 1;
pub const MAX_LINES: usize = 20_000;
pub const MAX_EXPRESSION_DEPTH: usize = 8;
pub const MAX_EXPRESSION_NODES: usize = 24;
pub type VariableId = usize;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Variable {
    pub id: VariableId,
    pub name: String,
    pub storage: Type,
    pub inferred_type: TypeRef,
    pub ssa: Option<crate::ir::ssa::Value>,
    pub entry_register: Option<String>,
    pub parameter: Option<usize>,
    pub scratch: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Expr {
    pub storage: Type,
    pub source: Option<usize>,
    pub kind: ExprKind,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ExprKind {
    Variable {
        id: VariableId,
    },
    /// A proved low-width entry ABI register, without assuming its high bits.
    Parameter {
        index: usize,
        register: String,
    },
    Constant {
        constant: Constant,
    },
    Scalar {
        operator: semantic::ScalarOp,
        arguments: Vec<Expr>,
    },
    Load {
        address: Box<Expr>,
    },
    Unknown {
        reason: String,
    },
}
impl Expr {
    pub fn variable(id: usize, storage: Type) -> Self {
        Self {
            storage,
            source: None,
            kind: ExprKind::Variable { id },
        }
    }
    pub fn variables(&self, result: &mut Vec<usize>) {
        match &self.kind {
            ExprKind::Variable { id } => result.push(*id),
            ExprKind::Scalar { arguments, .. } => {
                for arg in arguments {
                    arg.variables(result);
                }
            }
            ExprKind::Load { address } => address.variables(result),
            _ => {}
        }
    }
    pub fn size(&self) -> (usize, usize) {
        let children: Vec<_> = match &self.kind {
            ExprKind::Scalar { arguments, .. } => arguments.iter().map(Self::size).collect(),
            ExprKind::Load { address } => vec![address.size()],
            _ => Vec::new(),
        };
        (
            1 + children.iter().map(|v| v.0).sum::<usize>(),
            1 + children.iter().map(|v| v.1).max().unwrap_or(0),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Statement {
    pub source: Option<usize>,
    pub synthetic: bool,
    pub kind: StatementKind,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum StatementKind {
    Assign {
        variable: VariableId,
        value: Expr,
    },
    Store {
        address: Expr,
        value: Expr,
        stack_name: Option<String>,
    },
    Call {
        target: Expr,
        callee: Option<Address>,
        name: Option<String>,
        arguments: Vec<Expr>,
        unknown_arguments: bool,
    },
    Unknown {
        variable: Option<VariableId>,
        memory: bool,
        reason: String,
    },
    Label {
        address: Address,
    },
    /// Trace marker has no machine effect and is separate from a goto label.
    Block {
        address: Address,
    },
    /// Removed structural transfer, retained for assembly/source navigation.
    Provenance,
    Goto {
        target: Address,
    },
    If {
        condition: Expr,
        taken: Vec<Statement>,
        otherwise: Vec<Statement>,
    },
    Loop {
        body: Vec<Statement>,
    },
    Break,
    Continue,
    Return {
        result: Option<Expr>,
        destination: Option<Expr>,
    },
    Exit {
        destination: Option<Expr>,
        reason: String,
    },
}
impl Statement {
    pub(crate) fn synthetic(kind: StatementKind) -> Self {
        Self {
            source: None,
            synthetic: true,
            kind,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Function {
    pub version: u32,
    pub address: Address,
    pub name: String,
    pub address_width: u16,
    pub signature: Option<semantic::SemanticSignature>,
    pub variables: Vec<Variable>,
    pub body: Vec<Statement>,
    pub sources: Vec<semantic::Source>,
    pub diagnostics: Vec<String>,
    pub unresolved: usize,
    pub truncated: bool,
    pub types_partial: bool,
    pub eliminated_temporaries: usize,
    pub phi_copies: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Line {
    pub number: usize,
    pub indent: usize,
    pub text: String,
    pub addresses: Vec<Address>,
    pub variables: Vec<VariableId>,
    pub callee: Option<Address>,
    pub synthetic: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Output {
    pub function: Address,
    pub syntax: String,
    pub status: String,
    pub lines: Vec<Line>,
    pub unresolved: usize,
    pub truncated: bool,
    pub diagnostics: Vec<String>,
    pub ast: Function,
}
impl Output {
    pub fn text(&self) -> String {
        self.lines
            .iter()
            .map(|l| format!("{}{}\n", "    ".repeat(l.indent), l.text))
            .collect()
    }
}
