//! Executable semantic HIR. Values, operations and provenance are indexed once;
//! no node contains C syntax, display names or a pretty-printer instruction.
//! Control stays as explicit block transfers until a region rewrite is verified.
use super::types::{SsaInferredType, TypeRef};
use crate::ir::{
    self,
    ssa::{SsaFunction, Use, Value},
    Address, Constant, FlowKind, Operation, Type, VariableKind,
};
use crate::AnalysisControl;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const VERSION: u32 = 1;
pub type ValueId = usize;
pub type NodeId = usize;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticFunction {
    pub version: u32,
    pub entry: Address,
    pub address_width: u16,
    pub values: Vec<SemanticValue>,
    pub sources: Vec<Source>,
    pub nodes: Vec<Node>,
    pub blocks: Vec<Block>,
    pub types_partial: bool,
    pub signature: Option<SemanticSignature>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticSignature {
    pub convention: super::CallingConvention,
    pub parameters: Vec<SemanticParameter>,
    pub return_type: TypeRef,
    pub return_location: Option<super::Location>,
    pub return_confidence: super::Confidence,
    pub user_override: bool,
    pub conflicts: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SemanticParameter {
    pub index: usize,
    pub name: String,
    pub location: super::Location,
    pub ty: TypeRef,
    pub width: u16,
    pub confidence: super::Confidence,
}
impl SemanticFunction {
    pub fn attach_signature(&mut self, signature: &super::FunctionSignature) {
        self.signature = Some(SemanticSignature {
            convention: signature.convention,
            parameters: signature
                .parameters
                .iter()
                .map(|parameter| SemanticParameter {
                    index: parameter.index,
                    name: parameter.name.clone(),
                    location: parameter.location.clone(),
                    ty: parameter.ty.clone(),
                    width: parameter.width,
                    confidence: parameter.confidence,
                })
                .collect(),
            return_type: signature.return_value.ty.clone(),
            return_location: signature.return_value.location.clone(),
            return_confidence: signature.return_value.confidence,
            user_override: signature.user_override,
            conflicts: signature.conflicts.clone(),
        });
        for block in &mut self.blocks {
            if let TransferKind::Return { result, .. } = &mut block.transfer.kind {
                *result = match &signature.return_value.location {
                    Some(super::Location::Register { name }) => block
                        .transfer
                        .registers
                        .iter()
                        .find(|(register, _)| register == name)
                        .map(|(_, value)| *value),
                    _ => None,
                };
            }
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticValue {
    pub id: ValueId,
    pub ssa: Value,
    pub storage: Type,
    pub inferred_type: TypeRef,
    pub kind: VariableKind,
    pub register: Option<String>,
    pub definition: Option<NodeId>,
    pub type_evidence: Vec<TypeEvidence>,
    pub conflicts: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TypeEvidence {
    pub kind: String,
    pub source: Option<Address>,
    pub detail: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    pub block: Address,
    pub ordinal: Option<usize>,
    pub instruction: Option<Address>,
    pub synthetic: bool,
    pub original_operation: Option<Operation>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
pub enum Input {
    Value(ValueId),
    Constant(Constant),
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ScalarOp {
    Move,
    Add,
    Subtract,
    And,
    Or,
    Xor,
    Complement,
    ShiftLeft,
    ShiftRight,
    Equal,
    UnsignedLess,
    ZeroExtend,
    SignExtend,
    Truncate,
    AddressCast,
    BitsCast,
    Select,
    Parity,
    Extract { offset: u16 },
    Insert { offset: u16 },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum NodeKind {
    Scalar {
        operator: ScalarOp,
    },
    Phi {
        initial: Option<ValueId>,
        incoming: Vec<PhiInput>,
    },
    ReadMemory,
    WriteMemory,
    Invoke,
    UnknownEffect,
    Barrier,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PhiInput {
    pub predecessor: Address,
    pub value: ValueId,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub source: usize,
    pub output: Option<ValueId>,
    pub kind: NodeKind,
    pub inputs: Vec<Input>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub address: Address,
    pub phis: Vec<NodeId>,
    pub operations: Vec<NodeId>,
    pub transfer: Transfer,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transfer {
    pub source: usize,
    pub kind: TransferKind,
    pub registers: Vec<(String, Input)>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum TransferKind {
    Branch {
        condition: Option<Input>,
        taken: Option<Address>,
        fallthrough: Option<Address>,
    },
    Jump {
        target: Option<Address>,
    },
    Return {
        destination: Option<Input>,
        result: Option<Input>,
    },
    Indirect {
        destination: Option<Input>,
    },
    Unresolved,
}

pub fn lower(
    ssa: &SsaFunction,
    types: &[SsaInferredType],
    control: &dyn AnalysisControl,
) -> Result<SemanticFunction, String> {
    if ssa.blocks.len() > ir::MAX_IR_BLOCKS
        || ssa
            .blocks
            .iter()
            .map(|b| b.statements.len() + b.phis.len())
            .sum::<usize>()
            > ir::MAX_IR_OPERATIONS
    {
        return Err("semantic HIR source exceeds block/operation limits".into());
    }
    let mut all = BTreeSet::new();
    for block in &ssa.blocks {
        if control.is_cancelled() {
            return Err("semantic HIR lowering cancelled".into());
        }
        for phi in &block.phis {
            all.insert(phi.output);
            all.extend(phi.incoming.values().copied());
            all.extend(phi.initial);
        }
        for statement in &block.statements {
            all.extend(statement.output);
            all.extend(statement.args.iter().filter_map(|arg| {
                if let Use::Value(value) = arg {
                    Some(*value)
                } else {
                    None
                }
            }));
        }
        all.extend(
            block
                .terminator
                .state
                .iter()
                .chain(block.terminator.value.iter())
                .filter_map(|arg| {
                    if let Use::Value(value) = arg {
                        Some(*value)
                    } else {
                        None
                    }
                }),
        );
    }
    let ids: BTreeMap<_, _> = all
        .iter()
        .copied()
        .enumerate()
        .map(|(id, value)| (value, id))
        .collect();
    let evidence: BTreeMap<_, _> = types.iter().map(|ty| (ty.value, ty)).collect();
    let mut values = Vec::with_capacity(all.len());
    for value in all {
        let variable = ssa
            .variables
            .get(value.variable)
            .ok_or("semantic HIR has an invalid variable reference")?;
        let ty = evidence.get(&value);
        values.push(SemanticValue {
            id: ids[&value],
            ssa: value,
            storage: variable.ty,
            inferred_type: ty.map_or_else(
                || TypeRef::unknown(variable.ty.width(), "no version-specific type evidence"),
                |ty| ty.ty.clone(),
            ),
            kind: variable.kind.clone(),
            register: (variable.kind == VariableKind::Register
                || variable.kind == VariableKind::Flag)
                .then(|| variable.name.clone()),
            definition: None,
            type_evidence: ty.map_or_else(Vec::new, |ty| {
                ty.constraints
                    .iter()
                    .map(|claim| TypeEvidence {
                        kind: claim.kind.clone(),
                        source: claim.source.map(Address),
                        detail: claim.detail.clone(),
                    })
                    .collect()
            }),
            conflicts: ty.map_or_else(Vec::new, |ty| ty.conflicts.clone()),
        });
    }
    let input = |arg: Use| match arg {
        Use::Value(value) => Input::Value(ids[&value]),
        Use::Constant(value) => Input::Constant(value),
    };
    let mut function = SemanticFunction {
        version: VERSION,
        entry: ssa.entry,
        address_width: ssa.address_width,
        values,
        sources: Vec::new(),
        nodes: Vec::new(),
        blocks: Vec::new(),
        types_partial: evidence.len() < ids.len(),
        signature: None,
    };
    let mut ordered: Vec<_> = ssa.blocks.iter().collect();
    ordered.sort_by_key(|block| block.address);
    for block in ordered {
        if control.is_cancelled() {
            return Err("semantic HIR lowering cancelled".into());
        }
        let mut phis = Vec::new();
        let mut operations = Vec::new();
        for phi in &block.phis {
            let source = function.sources.len();
            function.sources.push(Source {
                block: block.address,
                ordinal: None,
                instruction: None,
                synthetic: true,
                original_operation: None,
            });
            let id = function.nodes.len();
            let output = ids[&phi.output];
            function.values[output].definition = Some(id);
            function.nodes.push(Node {
                id,
                source,
                output: Some(output),
                kind: NodeKind::Phi {
                    initial: phi.initial.map(|v| ids[&v]),
                    incoming: phi
                        .incoming
                        .iter()
                        .map(|(predecessor, value)| PhiInput {
                            predecessor: *predecessor,
                            value: ids[value],
                        })
                        .collect(),
                },
                inputs: Vec::new(),
            });
            phis.push(id);
        }
        for (ordinal, statement) in block.statements.iter().enumerate() {
            if ordinal % 256 == 0 && control.is_cancelled() {
                return Err("semantic HIR lowering cancelled".into());
            }
            let source = function.sources.len();
            function.sources.push(Source {
                block: block.address,
                ordinal: Some(ordinal),
                instruction: Some(statement.source),
                synthetic: false,
                original_operation: Some(statement.op.clone()),
            });
            let id = function.nodes.len();
            let output = statement.output.map(|v| ids[&v]);
            if let Some(output) = output {
                function.values[output].definition = Some(id);
            }
            function.nodes.push(Node {
                id,
                source,
                output,
                kind: kind(&statement.op),
                inputs: statement.args.iter().copied().map(&input).collect(),
            });
            operations.push(id);
        }
        let flow = &block.terminator.flow;
        let source = function.sources.len();
        function.sources.push(Source {
            block: block.address,
            ordinal: None,
            instruction: Some(flow.source),
            synthetic: false,
            original_operation: None,
        });
        let operand = block.terminator.value.map(input);
        let kind = match flow.kind {
            FlowKind::Branch => TransferKind::Branch {
                condition: operand,
                taken: flow.taken,
                fallthrough: flow.fallthrough,
            },
            FlowKind::Jump => TransferKind::Jump {
                target: flow.successors.first().or(flow.exits.first()).copied(),
            },
            FlowKind::Return => TransferKind::Return {
                destination: operand,
                result: None,
            },
            FlowKind::Indirect => TransferKind::Indirect {
                destination: operand,
            },
            FlowKind::Unresolved => TransferKind::Unresolved,
        };
        let registers = ssa
            .variables
            .iter()
            .enumerate()
            .filter(|(_, v)| matches!(v.kind, VariableKind::Register | VariableKind::Flag))
            .filter_map(|(id, variable)| {
                block
                    .terminator
                    .state
                    .get(id)
                    .map(|arg| (variable.name.clone(), input(*arg)))
            })
            .collect();
        function.blocks.push(Block {
            address: block.address,
            phis,
            operations,
            transfer: Transfer {
                source,
                kind,
                registers,
            },
        });
    }
    Ok(function)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    pub version: u32,
    pub function: Address,
    pub entry: Address,
    pub address_width: u16,
    pub complete: bool,
    pub total_blocks: usize,
    pub total_nodes: usize,
    pub total_values: usize,
    pub blocks: Vec<Block>,
    pub nodes: Vec<Node>,
    pub values: Vec<SemanticValue>,
    pub sources: Vec<IndexedSource>,
    pub external_definitions: Vec<NodeId>,
    pub signature: Option<SemanticSignature>,
    pub types_partial: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexedSource {
    pub id: usize,
    pub source: Source,
}

/// Partial selections preserve global IDs and explicitly list definitions in
/// other blocks. A page is never advertised as a complete executable function.
pub fn page(function: &SemanticFunction, block: Option<Address>) -> Result<Page, String> {
    let blocks: Vec<_> = function
        .blocks
        .iter()
        .filter(|candidate| block.map_or(true, |address| candidate.address == address))
        .cloned()
        .collect();
    if blocks.is_empty() {
        return Err("semantic block is not present in this function".into());
    }
    let ids: BTreeSet<_> = blocks
        .iter()
        .flat_map(|block| block.phis.iter().chain(&block.operations))
        .copied()
        .collect();
    let mut value_ids = BTreeSet::new();
    let mut source_ids: BTreeSet<_> = blocks.iter().map(|block| block.transfer.source).collect();
    let mut input = |arg: Input| {
        if let Input::Value(id) = arg {
            value_ids.insert(id);
        }
    };
    for block in &blocks {
        for (_, arg) in &block.transfer.registers {
            input(*arg);
        }
        match block.transfer.kind {
            TransferKind::Branch {
                condition: Some(arg),
                ..
            }
            | TransferKind::Return {
                destination: Some(arg),
                ..
            }
            | TransferKind::Indirect {
                destination: Some(arg),
            } => input(arg),
            _ => {}
        }
    }
    for id in &ids {
        let node = &function.nodes[*id];
        source_ids.insert(node.source);
        value_ids.extend(node.output);
        for arg in &node.inputs {
            if let Input::Value(id) = arg {
                value_ids.insert(*id);
            }
        }
        if let NodeKind::Phi { initial, incoming } = &node.kind {
            value_ids.extend(initial);
            value_ids.extend(incoming.iter().map(|edge| edge.value));
        }
    }
    let values: Vec<_> = value_ids
        .iter()
        .filter_map(|id| function.values.get(*id).cloned())
        .collect();
    let external_definitions = values
        .iter()
        .filter_map(|value| value.definition.filter(|id| !ids.contains(id)))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(Page {
        version: VERSION,
        function: function.entry,
        entry: function.entry,
        address_width: function.address_width,
        complete: block.is_none(),
        total_blocks: function.blocks.len(),
        total_nodes: function.nodes.len(),
        total_values: function.values.len(),
        blocks,
        nodes: ids
            .into_iter()
            .map(|id| function.nodes[id].clone())
            .collect(),
        values,
        sources: source_ids
            .into_iter()
            .map(|id| IndexedSource {
                id,
                source: function.sources[id].clone(),
            })
            .collect(),
        external_definitions,
        signature: function.signature.clone(),
        types_partial: function.types_partial,
    })
}

fn kind(op: &Operation) -> NodeKind {
    use Operation::*;
    use ScalarOp as S;
    let operator = match op {
        Copy => S::Move,
        Add => S::Add,
        Sub => S::Subtract,
        And => S::And,
        Or => S::Or,
        Xor => S::Xor,
        Not => S::Complement,
        Shl => S::ShiftLeft,
        Shr => S::ShiftRight,
        Equal => S::Equal,
        UnsignedLess => S::UnsignedLess,
        ZeroExtend => S::ZeroExtend,
        SignExtend => S::SignExtend,
        Truncate => S::Truncate,
        ToAddress => S::AddressCast,
        ToBits => S::BitsCast,
        Extract { offset } => S::Extract { offset: *offset },
        Insert { offset } => S::Insert { offset: *offset },
        Select => S::Select,
        Parity => S::Parity,
        Load => return NodeKind::ReadMemory,
        Store => return NodeKind::WriteMemory,
        Call => return NodeKind::Invoke,
        Unknown { .. } => return NodeKind::UnknownEffect,
        Barrier { .. } => return NodeKind::Barrier,
    };
    NodeKind::Scalar { operator }
}
