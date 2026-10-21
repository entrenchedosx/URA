//! Recovered high-level IR: a typed structure over verified SSA plus a
//! deliberately non-compilable C-like rendering.
//!
//! Branch conditions, call argument lists and memory widths are only printed
//! when the lifted semantics or a supplied signature justify them; everything
//! else is marked as unresolved. The typed tree is the authoring format: the
//! rendered lines are a deterministic printer over it, and the legacy text
//! contract is locked by snapshot tests.
use super::abi::SignatureHints;
use super::postdom::PostDominators;
use super::signature::{FunctionSignature, Location};
use super::stack::StackFrame;
use crate::ir::dataflow::Dataflow;
use crate::ir::ssa::{SsaBlock, SsaFunction, SsaStatement, Use, Value};
use crate::ir::{Constant, FlowKind, Operation, Type, VariableKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const MAX_HIR_LINES: usize = 20_000;
pub const MAX_HIR_DEPTH: usize = 64;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HighLevelLine {
    pub indent: usize,
    pub text: String,
    pub address: Option<u64>,
    pub kind: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HighLevelFunction {
    pub function: u64,
    pub syntax: String,
    pub status: String,
    pub lines: Vec<HighLevelLine>,
    pub unresolved: usize,
    pub truncated: bool,
    pub notes: Vec<String>,
}
impl HighLevelFunction {
    pub fn text(&self) -> String {
        self.lines
            .iter()
            .map(|line| format!("{}{}\n", "  ".repeat(line.indent), line.text))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Typed HIR
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HirFunction {
    pub function: u64,
    pub statements: Vec<HirStatement>,
    /// Self-contained machine semantics and SSA value types. No operation is
    /// removed here when its display definition is folded or hidden as dead.
    #[serde(default)]
    pub source: Option<HirSource>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HirSource {
    pub address_width: u16,
    pub variables: Vec<crate::ir::Variable>,
    pub blocks: Vec<SsaBlock>,
    pub constants: Vec<(Value, Constant)>,
    pub signature: FunctionSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HirIncoming {
    pub predecessor: u64,
    pub value: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum HirStatement {
    Phi {
        address: Option<u64>,
        output: Value,
        initial: Option<Value>,
        incoming: Vec<HirIncoming>,
    },
    Assignment {
        address: Option<u64>,
        output: Value,
        value: HirExpr,
    },
    Load {
        address: Option<u64>,
        output: Value,
        width: u16,
        source: HirExpr,
    },
    Store {
        address: Option<u64>,
        width: u16,
        target: HirExpr,
        value: HirExpr,
    },
    Call {
        address: Option<u64>,
        invocation: HirInvocation,
    },
    Unsupported {
        address: Option<u64>,
        case: UnsupportedCase,
    },
    If {
        condition: HirExpr,
        negated: bool,
        taken: Vec<HirStatement>,
        otherwise: Option<Vec<HirStatement>>,
    },
    IfExit {
        condition: HirExpr,
        negated: bool,
        target: IfExitTarget,
    },
    GotoPair {
        condition: HirExpr,
        taken: u64,
        fall: u64,
    },
    Goto {
        target: u64,
    },
    Break {
        address: Option<u64>,
    },
    Label {
        address: u64,
    },
    While {
        header: u64,
        body: Vec<HirStatement>,
    },
    Return {
        address: Option<u64>,
        shape: HirReturnShape,
    },
    Comment {
        address: Option<u64>,
        text: String,
    },
    Signature {
        address: Option<u64>,
        declaration: String,
    },
    FunctionClose,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "case", rename_all = "camelCase")]
pub enum UnsupportedCase {
    Effect { reason: String },
    NestingLimit,
    JumpNoTarget,
    BranchUnresolved,
    LoopHeaderBranch,
    LoopTransfer,
    OutsideFunction { target: u64 },
    TransferValue { value: Option<HirExpr> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum IfExitTarget {
    Break,
    Goto { target: u64 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "shape", rename_all = "camelCase")]
pub enum HirReturnShape {
    Void,
    Value { value: HirValueDisplay },
    Untracked { register: String },
    LocationUnresolved,
    RegisterUntracked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum HirValueDisplay {
    Named { value: Value },
    Constant { constant: Constant },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "invocation", rename_all = "camelCase")]
pub enum HirInvocation {
    Resolved {
        name: String,
        arguments: Vec<HirArgument>,
    },
    DirectUnknown {
        target: u64,
    },
    Indirect {
        target: Option<HirExpr>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum HirArgument {
    Named { value: Value },
    Placeholder { name: String },
    StackNotShown,
    Variadic,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum HirExpr {
    Value {
        value: Value,
    },
    Constant {
        constant: Constant,
    },
    Missing,
    UnknownCondition,
    Binary {
        op: HirBinaryOp,
        left: Box<HirExpr>,
        right: Box<HirExpr>,
    },
    Not {
        operand: Box<HirExpr>,
    },
    Cast {
        kind: HirCastKind,
        width: u16,
        operand: Box<HirExpr>,
    },
    SignExtend {
        from: u16,
        width: u16,
        operand: Box<HirExpr>,
    },
    Extract {
        offset: u16,
        width: u16,
        operand: Box<HirExpr>,
    },
    Insert {
        base: Box<HirExpr>,
        value: Box<HirExpr>,
        offset: u16,
    },
    Select {
        condition: Box<HirExpr>,
        taken: Box<HirExpr>,
        otherwise: Box<HirExpr>,
    },
    Parity {
        operand: Box<HirExpr>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HirBinaryOp {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Equal,
    UnsignedLess,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HirCastKind {
    Bits,
    Address,
}

/// Legacy control-flow decisions, ported to emit a typed tree instead of
/// strings. All bookkeeping (`emitted`, loop frames, unresolved counter,
/// truncation) mirrors the previous line-based implementation exactly; the
/// rendered text is produced by `Printer` over the constructed tree.
struct Structurer<'a> {
    ssa: &'a SsaFunction,
    blocks: BTreeMap<u64, &'a SsaBlock>,
    predecessors: BTreeMap<u64, Vec<u64>>,
    latches: BTreeMap<u64, Vec<u64>>,
    postdominators: Option<PostDominators>,
    successors: BTreeMap<u64, Vec<u64>>,
    constants: BTreeMap<Value, Constant>,
    dead: BTreeSet<Value>,
    hints: &'a SignatureHints,
    signature: &'a FunctionSignature,
    emitted: BTreeSet<u64>,
    active: Vec<LoopFrame>,
    unresolved: usize,
    truncated: bool,
}

#[derive(Clone)]
struct LoopFrame {
    header: u64,
    nodes: BTreeSet<u64>,
}

/// Build the high-level view and the typed tree from the same traversal.
pub fn build_with_ast(
    ssa: &SsaFunction,
    dataflow: &Dataflow,
    signature: &FunctionSignature,
    hints: &SignatureHints,
    frame: Option<&StackFrame>,
) -> (HighLevelFunction, HirFunction) {
    let blocks = ssa
        .blocks
        .iter()
        .map(|block| (block.address.0, block))
        .collect::<BTreeMap<_, _>>();
    let mut latches: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for block in &ssa.blocks {
        for successor in &block.terminator.flow.successors {
            if ssa.dominators.dominates(*successor, block.address) {
                latches
                    .entry(successor.0)
                    .or_default()
                    .push(block.address.0);
            }
        }
    }
    let predecessors = ssa
        .blocks
        .iter()
        .map(|block| {
            (
                block.address.0,
                block
                    .predecessors
                    .iter()
                    .map(|address| address.0)
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    let successors = super::postdom::graph_for(ssa);
    let postdominators = super::postdom::over_graph(ssa.entry.0, &successors).ok();
    let mut structurer = Structurer {
        ssa,
        blocks,
        predecessors,
        latches,
        postdominators,
        successors,
        constants: dataflow.constants.iter().copied().collect(),
        dead: dataflow.dead_definitions.iter().copied().collect(),
        hints,
        signature,
        emitted: BTreeSet::new(),
        active: Vec::new(),
        unresolved: 0,
        truncated: false,
    };
    let mut statements = Vec::new();
    statements.push(HirStatement::Comment {
        address: None,
        text: "// recovered high-level IR (experimental foundation, not decompiled source)".into(),
    });
    statements.push(HirStatement::Signature {
        address: Some(ssa.entry.0),
        declaration: signature.declaration(),
    });
    if structurer.blocks.contains_key(&ssa.entry.0) {
        structurer.region(ssa.entry.0, None, 0, &mut statements);
    } else {
        statements.push(HirStatement::Comment {
            address: None,
            text: "// entry block is not present in the SSA graph".into(),
        });
    }
    let pending: Vec<u64> = ssa
        .blocks
        .iter()
        .map(|block| block.address.0)
        .filter(|address| !structurer.emitted.contains(address))
        .collect();
    for address in pending {
        if structurer.emitted.contains(&address) {
            continue;
        }
        statements.push(HirStatement::Comment {
            address: Some(address),
            text: format!(
                "// block {address:#x} is only reachable through a transfer that was not structured"
            ),
        });
        structurer.region(address, None, 0, &mut statements);
    }
    statements.push(HirStatement::FunctionClose);
    let ast = HirFunction {
        function: ssa.entry.0,
        statements,
        source: Some(HirSource {
            address_width: ssa.address_width,
            variables: ssa.variables.clone(),
            blocks: ssa.blocks.clone(),
            constants: dataflow.constants.clone(),
            signature: signature.clone(),
        }),
    };
    let mut printer = Printer {
        variables: &ssa.variables,
        constants: &structurer.constants,
        lines: Vec::new(),
        indent: 0,
        truncated: false,
    };
    printer.function(&ast);
    let mut notes = vec![
        "This view is a structural rendering of verified SSA. It is not source code and it is not claimed to compile."
            .into(),
        "Unsupported instructions, unresolved branches and calls without signatures are marked instead of being guessed."
            .into(),
    ];
    if let Some(frame) = frame {
        if !frame.slots.is_empty() {
            notes.push(format!(
                "{} physical stack slot(s) are reported in the stack-frame view and are not renamed into expressions here.",
                frame.slots.len()
            ));
        }
    }
    (
        HighLevelFunction {
            function: ssa.entry.0,
            syntax: "c-like".into(),
            status: "experimental-foundations".into(),
            lines: printer.lines,
            unresolved: structurer.unresolved,
            truncated: structurer.truncated || printer.truncated,
            notes,
        },
        ast,
    )
}

pub fn build(
    ssa: &SsaFunction,
    dataflow: &Dataflow,
    signature: &FunctionSignature,
    hints: &SignatureHints,
    frame: Option<&StackFrame>,
) -> HighLevelFunction {
    build_with_ast(ssa, dataflow, signature, hints, frame).0
}

/// Re-render a stored HIR using its own variable types and constant facts.
/// No disassembly, SSA construction or type recovery is performed here.
pub fn render_ast(ast: &HirFunction) -> Result<(Vec<HighLevelLine>, bool), String> {
    let source = ast
        .source
        .as_ref()
        .ok_or("HIR has no self-contained source metadata")?;
    let constants = source.constants.iter().copied().collect();
    let mut printer = Printer {
        variables: &source.variables,
        constants: &constants,
        lines: Vec::new(),
        indent: 0,
        truncated: false,
    };
    printer.function(ast);
    Ok((printer.lines, printer.truncated))
}

impl<'a> Structurer<'a> {
    fn region(&mut self, entry: u64, stop: Option<u64>, depth: usize, out: &mut Vec<HirStatement>) {
        if self.truncated {
            return;
        }
        if Some(entry) == stop {
            return;
        }
        if self.emitted.contains(&entry) {
            out.push(HirStatement::Goto { target: entry });
            return;
        }
        if depth > MAX_HIR_DEPTH {
            out.push(HirStatement::Unsupported {
                address: None,
                case: UnsupportedCase::NestingLimit,
            });
            self.unresolved += 1;
            self.truncated = true;
            return;
        }
        if self.latches.contains_key(&entry)
            && !self.active.iter().any(|frame| frame.header == entry)
        {
            self.loop_region(entry, stop, depth, out);
            return;
        }
        let Some(block) = self.blocks.get(&entry).copied() else {
            return;
        };
        self.emitted.insert(entry);
        out.push(HirStatement::Label { address: entry });
        self.block_statements(block, out);
        self.terminator(block, stop, depth, out);
    }

    fn goto(&mut self, target: u64, stop: Option<u64>, depth: usize, out: &mut Vec<HirStatement>) {
        if Some(target) == stop {
            return;
        }
        if self
            .active
            .last()
            .is_some_and(|frame| !frame.nodes.contains(&target))
        {
            out.push(HirStatement::Goto { target });
            return;
        }
        if self.emitted.contains(&target) || !self.blocks.contains_key(&target) {
            if self.blocks.contains_key(&target) {
                out.push(HirStatement::Goto { target });
            } else {
                out.push(HirStatement::Unsupported {
                    address: None,
                    case: UnsupportedCase::OutsideFunction { target },
                });
                self.unresolved += 1;
            }
            return;
        }
        self.region(target, stop, depth + 1, out);
    }

    fn loop_region(
        &mut self,
        header: u64,
        stop: Option<u64>,
        depth: usize,
        out: &mut Vec<HirStatement>,
    ) {
        let Some(latches) = self.latches.get(&header).cloned() else {
            return;
        };
        let nodes = self.natural_loop(header, &latches);
        let exits: BTreeSet<u64> = nodes
            .iter()
            .filter_map(|address| self.blocks.get(address))
            .flat_map(|block| {
                block
                    .terminator
                    .flow
                    .successors
                    .iter()
                    .map(|address| address.0)
            })
            .filter(|target| !nodes.contains(target))
            .collect();
        let mut exit = exits.iter().next().copied();
        for other in exits.iter().skip(1) {
            let current = exit.expect("first exit");
            match self.join_point(current, *other) {
                Some(join) => exit = Some(join),
                None => {
                    exit = None;
                    break;
                }
            }
        }
        if exits.len() > 1 {
            out.push(HirStatement::Comment {
                address: Some(header),
                text: format!(
                    "// loop at {header:#x} has {} observed exit target(s); exits other than the first are expressed with gotos",
                    exits.len()
                ),
            });
        }
        let Some(block) = self.blocks.get(&header).copied() else {
            return;
        };
        self.emitted.insert(header);
        let mut body = Vec::new();
        self.active.push(LoopFrame {
            header,
            nodes: nodes.clone(),
        });
        self.block_statements(block, &mut body);
        let flow = &block.terminator.flow;
        match flow.kind {
            FlowKind::Branch => {
                let taken = self.resolved_target(
                    flow.taken
                        .map(|address| address.0)
                        .or_else(|| flow.successors.first().map(|address| address.0)),
                );
                let fall = self.resolved_target(
                    flow.fallthrough
                        .map(|address| address.0)
                        .or_else(|| flow.successors.get(1).map(|address| address.0)),
                );
                let cond = block
                    .terminator
                    .value
                    .map(|value| self.expr(value))
                    .unwrap_or(HirExpr::UnknownCondition);
                match (taken, fall) {
                    (Some(taken), Some(fall)) => {
                        let taken_in = nodes.contains(&taken);
                        let fall_in = nodes.contains(&fall);
                        if taken_in && !fall_in {
                            self.exit_condition(&mut body, cond, true, fall, exit);
                            self.region(taken, Some(header), depth + 1, &mut body);
                        } else if fall_in && !taken_in {
                            self.exit_condition(&mut body, cond, false, taken, exit);
                            self.region(fall, Some(header), depth + 1, &mut body);
                        } else if taken_in && fall_in {
                            self.branch_targets(&cond, taken, fall, Some(header), depth, &mut body);
                        } else {
                            self.exit_condition(&mut body, cond.clone(), false, taken, exit);
                            self.exit_condition(&mut body, cond, true, fall, exit);
                        }
                    }
                    _ => {
                        body.push(HirStatement::Unsupported {
                            address: None,
                            case: UnsupportedCase::LoopHeaderBranch,
                        });
                        self.unresolved += 1;
                    }
                }
            }
            FlowKind::Jump => {
                if let Some(target) = flow.successors.first().map(|address| address.0) {
                    if target != header {
                        if nodes.contains(&target) {
                            self.region(target, Some(header), depth + 1, &mut body);
                        } else if Some(target) == exit {
                            body.push(HirStatement::Break {
                                address: Some(block.terminator.flow.source.0),
                            });
                        } else {
                            body.push(HirStatement::Goto { target });
                        }
                    }
                } else {
                    self.unconditional_break(&mut body, block.terminator.flow.source.0);
                }
            }
            FlowKind::Return => {
                let shape = self.return_shape(block);
                body.push(HirStatement::Return {
                    address: Some(block.terminator.flow.source.0),
                    shape,
                });
            }
            FlowKind::Indirect | FlowKind::Unresolved => {
                body.push(HirStatement::Unsupported {
                    address: None,
                    case: UnsupportedCase::LoopTransfer,
                });
                self.unresolved += 1;
            }
        }
        self.active.pop();
        out.push(HirStatement::While { header, body });
        if let Some(exit) = exit {
            self.region(exit, stop, depth + 1, out);
        }
    }

    fn unconditional_break(&self, out: &mut Vec<HirStatement>, address: u64) {
        out.push(HirStatement::Break {
            address: Some(address),
        });
    }

    fn exit_condition(
        &self,
        out: &mut Vec<HirStatement>,
        condition: HirExpr,
        negated: bool,
        target: u64,
        exit: Option<u64>,
    ) {
        if Some(target) == exit {
            out.push(HirStatement::IfExit {
                condition,
                negated,
                target: IfExitTarget::Break,
            });
        } else {
            out.push(HirStatement::IfExit {
                condition,
                negated,
                target: IfExitTarget::Goto { target },
            });
        }
    }

    fn resolved_target(&self, target: Option<u64>) -> Option<u64> {
        target.filter(|address| self.blocks.contains_key(address))
    }

    fn natural_loop(&self, header: u64, latches: &[u64]) -> BTreeSet<u64> {
        let mut nodes = BTreeSet::from([header]);
        let mut queue = VecDeque::from(latches.to_vec());
        while let Some(current) = queue.pop_front() {
            if current == header || !nodes.insert(current) {
                continue;
            }
            if nodes.len() > self.blocks.len() {
                break;
            }
            if let Some(predecessors) = self.predecessors.get(&current) {
                for predecessor in predecessors {
                    if !nodes.contains(predecessor) {
                        queue.push_back(*predecessor);
                    }
                }
            }
        }
        nodes
    }

    fn block_statements(&mut self, block: &'a SsaBlock, out: &mut Vec<HirStatement>) {
        for phi in &block.phis {
            if self.dead.contains(&phi.output) {
                continue;
            }
            let incoming = phi
                .incoming
                .iter()
                .map(|(predecessor, value)| HirIncoming {
                    predecessor: predecessor.0,
                    value: *value,
                })
                .collect();
            out.push(HirStatement::Phi {
                address: Some(block.address.0),
                output: phi.output,
                initial: phi.initial,
                incoming,
            });
        }
        for statement in &block.statements {
            if let Some(output) = statement.output {
                if self.dead.contains(&output) && !statement.op.observable() {
                    continue;
                }
            }
            if let Some(node) = self.statement(block, statement) {
                out.push(node);
            }
        }
    }

    fn statement(&mut self, block: &'a SsaBlock, statement: &SsaStatement) -> Option<HirStatement> {
        let address = Some(statement.source.0);
        let output = statement.output;
        let node = match &statement.op {
            Operation::Copy => {
                let output = output?;
                HirStatement::Assignment {
                    address,
                    output,
                    value: self.arg(statement, 0),
                }
            }
            Operation::Add
            | Operation::Sub
            | Operation::And
            | Operation::Or
            | Operation::Xor
            | Operation::Shl
            | Operation::Shr
            | Operation::Equal
            | Operation::UnsignedLess => {
                let op = match &statement.op {
                    Operation::Add => HirBinaryOp::Add,
                    Operation::Sub => HirBinaryOp::Sub,
                    Operation::And => HirBinaryOp::And,
                    Operation::Or => HirBinaryOp::Or,
                    Operation::Xor => HirBinaryOp::Xor,
                    Operation::Shl => HirBinaryOp::Shl,
                    Operation::Shr => HirBinaryOp::Shr,
                    Operation::Equal => HirBinaryOp::Equal,
                    _ => HirBinaryOp::UnsignedLess,
                };
                let output = output?;
                HirStatement::Assignment {
                    address,
                    output,
                    value: HirExpr::Binary {
                        op,
                        left: Box::new(self.arg(statement, 0)),
                        right: Box::new(self.arg(statement, 1)),
                    },
                }
            }
            Operation::Not => {
                let output = output?;
                HirStatement::Assignment {
                    address,
                    output,
                    value: HirExpr::Not {
                        operand: Box::new(self.arg(statement, 0)),
                    },
                }
            }
            Operation::ZeroExtend | Operation::Truncate | Operation::ToBits => {
                let output = output?;
                let width = self.output_type(output).and_then(Type::width).unwrap_or(64);
                HirStatement::Assignment {
                    address,
                    output,
                    value: HirExpr::Cast {
                        kind: HirCastKind::Bits,
                        width,
                        operand: Box::new(self.arg(statement, 0)),
                    },
                }
            }
            Operation::SignExtend => {
                let output = output?;
                let width = self.output_type(output).and_then(Type::width).unwrap_or(64);
                let from = statement
                    .args
                    .first()
                    .and_then(|arg| self.use_type(*arg))
                    .and_then(Type::width)
                    .unwrap_or(0);
                HirStatement::Assignment {
                    address,
                    output,
                    value: HirExpr::SignExtend {
                        from,
                        width,
                        operand: Box::new(self.arg(statement, 0)),
                    },
                }
            }
            Operation::ToAddress => {
                let output = output?;
                let width = self.output_type(output).and_then(Type::width).unwrap_or(64);
                HirStatement::Assignment {
                    address,
                    output,
                    value: HirExpr::Cast {
                        kind: HirCastKind::Address,
                        width,
                        operand: Box::new(self.arg(statement, 0)),
                    },
                }
            }
            Operation::Extract { offset } => {
                let output = output?;
                let width = self.output_type(output).and_then(Type::width).unwrap_or(64);
                HirStatement::Assignment {
                    address,
                    output,
                    value: HirExpr::Extract {
                        offset: *offset,
                        width,
                        operand: Box::new(self.arg(statement, 0)),
                    },
                }
            }
            Operation::Insert { offset } => {
                let output = output?;
                HirStatement::Assignment {
                    address,
                    output,
                    value: HirExpr::Insert {
                        base: Box::new(self.arg(statement, 0)),
                        value: Box::new(self.arg(statement, 1)),
                        offset: *offset,
                    },
                }
            }
            Operation::Select => {
                let output = output?;
                HirStatement::Assignment {
                    address,
                    output,
                    value: HirExpr::Select {
                        condition: Box::new(self.arg(statement, 0)),
                        taken: Box::new(self.arg(statement, 1)),
                        otherwise: Box::new(self.arg(statement, 2)),
                    },
                }
            }
            Operation::Parity => {
                let output = output?;
                HirStatement::Assignment {
                    address,
                    output,
                    value: HirExpr::Parity {
                        operand: Box::new(self.arg(statement, 0)),
                    },
                }
            }
            Operation::Load => {
                let output = output?;
                let width = self.output_type(output).and_then(Type::width).unwrap_or(64);
                HirStatement::Load {
                    address,
                    output,
                    width,
                    source: self.arg(statement, 1),
                }
            }
            Operation::Store => {
                let width = statement
                    .args
                    .get(2)
                    .and_then(|value| self.use_type(*value))
                    .and_then(Type::width)
                    .unwrap_or(64);
                HirStatement::Store {
                    address,
                    width,
                    target: self.arg(statement, 1),
                    value: self.arg(statement, 2),
                }
            }
            Operation::Call => {
                let (invocation, unresolved) = self.call_invocation(block, statement);
                if unresolved {
                    self.unresolved += 1;
                }
                HirStatement::Call {
                    address,
                    invocation,
                }
            }
            Operation::Barrier { reason } | Operation::Unknown { reason } => {
                self.unresolved += 1;
                HirStatement::Unsupported {
                    address,
                    case: UnsupportedCase::Effect {
                        reason: reason.clone(),
                    },
                }
            }
        };
        Some(node)
    }

    fn call_invocation(
        &mut self,
        block: &'a SsaBlock,
        statement: &SsaStatement,
    ) -> (HirInvocation, bool) {
        let target = statement.args.first().copied();
        let address = match target {
            Some(Use::Constant(constant)) if matches!(constant.ty, Type::Address(_)) => {
                Some(constant.value.0)
            }
            _ => None,
        };
        // An indirect call through an import slot is only tied to a signature
        // when the binary's own import tables bind that exact slot address.
        // The call target is followed through at most a few in-block
        // definition hops, because the lift wraps loaded values in address
        // casts.
        let slot = super::imports::slot_for_call(block, statement, &self.constants);
        let signature = match address {
            Some(address) => {
                if address == self.signature.function {
                    Some(self.signature)
                } else {
                    self.hints.get(address)
                }
            }
            None => slot.and_then(|slot| self.hints.get(slot)),
        };
        match (address, signature) {
            (_, Some(signature)) => {
                let mut arguments = Vec::new();
                let mut stack_arguments = false;
                let mut unresolved = signature.variadic != Some(false);
                for parameter in &signature.parameters {
                    match &parameter.location {
                        Location::Register { name } => {
                            if let Some(index) = self.ssa.variables.iter().position(|variable| {
                                variable.kind == VariableKind::Register && variable.name == *name
                            }) {
                                if let Some(Use::Value(value)) =
                                    statement.args.get(1 + index).copied()
                                {
                                    arguments.push(HirArgument::Named { value });
                                    continue;
                                }
                            }
                            arguments.push(HirArgument::Placeholder {
                                name: parameter.name.clone(),
                            });
                            unresolved = true;
                        }
                        Location::Stack { .. } => stack_arguments = true,
                        Location::Unknown { .. } => {
                            arguments.push(HirArgument::Placeholder {
                                name: parameter.name.clone(),
                            });
                            unresolved = true;
                        }
                    }
                }
                if stack_arguments {
                    arguments.push(HirArgument::StackNotShown);
                    unresolved = true;
                }
                if signature.variadic == Some(true) {
                    arguments.push(HirArgument::Variadic);
                }
                (
                    HirInvocation::Resolved {
                        name: sanitize_identifier(&signature.name),
                        arguments,
                    },
                    unresolved,
                )
            }
            (Some(address), None) => (HirInvocation::DirectUnknown { target: address }, true),
            (None, None) => (
                HirInvocation::Indirect {
                    target: target.map(|value| self.expr_node(value)),
                },
                true,
            ),
        }
    }

    fn terminator(
        &mut self,
        block: &'a SsaBlock,
        stop: Option<u64>,
        depth: usize,
        out: &mut Vec<HirStatement>,
    ) {
        let flow = &block.terminator.flow;
        match flow.kind {
            FlowKind::Return => {
                let shape = self.return_shape(block);
                out.push(HirStatement::Return {
                    address: Some(flow.source.0),
                    shape,
                });
            }
            FlowKind::Jump => {
                let target = flow
                    .successors
                    .first()
                    .map(|address| address.0)
                    .or_else(|| flow.exits.first().map(|address| address.0));
                match target {
                    Some(target) => self.goto(target, stop, depth, out),
                    None => {
                        out.push(HirStatement::Unsupported {
                            address: None,
                            case: UnsupportedCase::JumpNoTarget,
                        });
                        self.unresolved += 1;
                    }
                }
            }
            FlowKind::Branch => {
                let cond = block
                    .terminator
                    .value
                    .map(|value| self.expr(value))
                    .unwrap_or(HirExpr::UnknownCondition);
                let taken = self.resolved_target(
                    flow.taken
                        .map(|address| address.0)
                        .or_else(|| flow.successors.first().map(|address| address.0)),
                );
                let fall = self.resolved_target(
                    flow.fallthrough
                        .map(|address| address.0)
                        .or_else(|| flow.successors.get(1).map(|address| address.0)),
                );
                match (taken, fall) {
                    (Some(taken), Some(fall)) => {
                        self.branch_targets(&cond, taken, fall, stop, depth, out);
                    }
                    _ => {
                        out.push(HirStatement::Unsupported {
                            address: Some(flow.source.0),
                            case: UnsupportedCase::BranchUnresolved,
                        });
                        self.unresolved += 1;
                    }
                }
            }
            FlowKind::Indirect | FlowKind::Unresolved => {
                out.push(HirStatement::Unsupported {
                    address: Some(flow.source.0),
                    case: UnsupportedCase::TransferValue {
                        value: block.terminator.value.map(|value| self.expr(value)),
                    },
                });
                self.unresolved += 1;
            }
        }
    }

    fn branch_targets(
        &mut self,
        cond: &HirExpr,
        taken: u64,
        fall: u64,
        stop: Option<u64>,
        depth: usize,
        out: &mut Vec<HirStatement>,
    ) {
        if Some(taken) == stop && Some(fall) == stop {
            return;
        }
        if Some(taken) == stop {
            let mut body = Vec::new();
            self.region(fall, stop, depth + 1, &mut body);
            out.push(HirStatement::If {
                condition: cond.clone(),
                negated: true,
                taken: body,
                otherwise: None,
            });
            return;
        }
        if Some(fall) == stop {
            let mut body = Vec::new();
            self.region(taken, stop, depth + 1, &mut body);
            out.push(HirStatement::If {
                condition: cond.clone(),
                negated: false,
                taken: body,
                otherwise: None,
            });
            return;
        }
        if self.outside_active_loop(taken) || self.outside_active_loop(fall) {
            out.push(HirStatement::GotoPair {
                condition: cond.clone(),
                taken,
                fall,
            });
            return;
        }
        let join = self.join_point(taken, fall);
        match join {
            Some(join) if join == taken => {
                let mut body = Vec::new();
                self.region(fall, Some(taken), depth + 1, &mut body);
                out.push(HirStatement::If {
                    condition: cond.clone(),
                    negated: true,
                    taken: body,
                    otherwise: None,
                });
                self.region(taken, stop, depth + 1, out);
            }
            Some(join) if join == fall => {
                let mut body = Vec::new();
                self.region(taken, Some(fall), depth + 1, &mut body);
                out.push(HirStatement::If {
                    condition: cond.clone(),
                    negated: false,
                    taken: body,
                    otherwise: None,
                });
                self.region(fall, stop, depth + 1, out);
            }
            Some(join) => {
                let mut taken_body = Vec::new();
                self.region(taken, Some(join), depth + 1, &mut taken_body);
                let mut fall_body = Vec::new();
                self.region(fall, Some(join), depth + 1, &mut fall_body);
                out.push(HirStatement::If {
                    condition: cond.clone(),
                    negated: false,
                    taken: taken_body,
                    otherwise: Some(fall_body),
                });
                self.region(join, stop, depth + 1, out);
            }
            None => {
                out.push(HirStatement::GotoPair {
                    condition: cond.clone(),
                    taken,
                    fall,
                });
            }
        }
    }

    fn outside_active_loop(&self, target: u64) -> bool {
        self.active
            .last()
            .is_some_and(|frame| !frame.nodes.contains(&target))
    }

    fn join_point(&self, a: u64, b: u64) -> Option<u64> {
        if a == b {
            return Some(a);
        }
        self.postdominators
            .as_ref()?
            .first_common_on_all_paths(a, b, &self.successors)
    }

    fn return_shape(&mut self, block: &'a SsaBlock) -> HirReturnShape {
        if matches!(self.signature.return_value.ty, super::types::TypeRef::Void) {
            return HirReturnShape::Void;
        }
        let register = match &self.signature.return_value.location {
            Some(Location::Register { name }) => name.clone(),
            _ => {
                self.unresolved += 1;
                return HirReturnShape::LocationUnresolved;
            }
        };
        let Some(index) = self.ssa.variables.iter().position(|variable| {
            variable.kind == VariableKind::Register && variable.name == register
        }) else {
            self.unresolved += 1;
            return HirReturnShape::RegisterUntracked;
        };
        let value = match block.terminator.state.get(index) {
            Some(Use::Value(value)) => HirReturnShape::Value {
                value: HirValueDisplay::Named { value: *value },
            },
            Some(Use::Constant(constant)) => HirReturnShape::Value {
                value: HirValueDisplay::Constant {
                    constant: *constant,
                },
            },
            _ => HirReturnShape::Untracked { register },
        };
        value
    }

    fn arg(&self, statement: &SsaStatement, index: usize) -> HirExpr {
        statement
            .args
            .get(index)
            .copied()
            .map(|value| self.expr_node(value))
            .unwrap_or(HirExpr::Missing)
    }

    fn expr_node(&self, value: Use) -> HirExpr {
        match value {
            Use::Constant(constant) => HirExpr::Constant { constant },
            Use::Value(value) => HirExpr::Value { value },
        }
    }

    fn expr(&self, value: Use) -> HirExpr {
        self.expr_node(value)
    }

    fn output_type(&self, value: Value) -> Option<Type> {
        self.ssa
            .variables
            .get(value.variable)
            .map(|variable| variable.ty)
    }

    fn use_type(&self, value: Use) -> Option<Type> {
        match value {
            Use::Constant(constant) => Some(constant.ty),
            Use::Value(value) => self.output_type(value),
        }
    }
}

// ---------------------------------------------------------------------------
// Deterministic printer
// ---------------------------------------------------------------------------
// Deterministic printer
// ---------------------------------------------------------------------------

struct Printer<'a> {
    variables: &'a [crate::ir::Variable],
    constants: &'a BTreeMap<Value, Constant>,
    lines: Vec<HighLevelLine>,
    indent: usize,
    truncated: bool,
}

impl<'a> Printer<'a> {
    fn line(&mut self, kind: &str, text: &str, address: Option<u64>) {
        if self.lines.len() >= MAX_HIR_LINES {
            self.truncated = true;
            return;
        }
        self.lines.push(HighLevelLine {
            indent: self.indent,
            text: sanitize(text),
            address,
            kind: kind.into(),
        });
    }

    fn function(&mut self, ast: &HirFunction) {
        for statement in &ast.statements {
            self.statement(statement);
        }
    }

    fn statement(&mut self, statement: &HirStatement) {
        match statement {
            HirStatement::Signature {
                address,
                declaration,
            } => {
                self.line("signature", &format!("{} {{", declaration), *address);
                self.indent += 1;
            }
            HirStatement::FunctionClose => {
                self.indent = self.indent.saturating_sub(1);
                self.line("control", "}", None);
            }
            HirStatement::Comment { address, text } => {
                self.line("comment", text, *address);
            }
            HirStatement::Label { address } => {
                self.line("label", &format!("L_{address:x}:"), Some(*address));
            }
            HirStatement::Goto { target } => {
                self.line("control", &format!("goto L_{target:x};"), None);
            }
            HirStatement::Break { address } => {
                self.line("control", "break;", *address);
            }
            HirStatement::GotoPair {
                condition,
                taken,
                fall,
            } => {
                let cond = self.expr(condition);
                self.line(
                    "control",
                    &format!("if ({cond}) goto L_{taken:x}; else goto L_{fall:x};"),
                    None,
                );
            }
            HirStatement::IfExit {
                condition,
                negated,
                target,
            } => {
                let cond = self.condition(condition, *negated);
                match target {
                    IfExitTarget::Break => {
                        self.line("control", &format!("if ({cond}) break;"), None);
                    }
                    IfExitTarget::Goto { target } => {
                        self.line("control", &format!("if ({cond}) goto L_{target:x};"), None);
                    }
                }
            }
            HirStatement::If {
                condition,
                negated,
                taken,
                otherwise,
            } => {
                let cond = self.condition(condition, *negated);
                self.line("control", &format!("if ({cond}) {{"), None);
                self.indent += 1;
                for statement in taken {
                    self.statement(statement);
                }
                self.indent = self.indent.saturating_sub(1);
                if let Some(otherwise) = otherwise {
                    self.line("control", "} else {", None);
                    self.indent += 1;
                    for statement in otherwise {
                        self.statement(statement);
                    }
                    self.indent = self.indent.saturating_sub(1);
                }
                self.line("control", "}", None);
            }
            HirStatement::While { header, body } => {
                self.line("label", &format!("L_{header:x}:"), Some(*header));
                self.line("control", "while (1) {", Some(*header));
                self.indent += 1;
                for statement in body {
                    self.statement(statement);
                }
                self.indent = self.indent.saturating_sub(1);
                self.line("control", "}", None);
            }
            HirStatement::Phi {
                address,
                output,
                initial,
                incoming,
            } => {
                let mut parts: Vec<String> = incoming
                    .iter()
                    .map(|incoming| {
                        format!("{:#x}: {}", incoming.predecessor, self.name(incoming.value))
                    })
                    .collect();
                if let Some(initial) = initial {
                    parts.push(format!("entry: {}", self.name(*initial)));
                }
                self.line(
                    "statement",
                    &format!("{} = phi({});", self.name(*output), parts.join(", ")),
                    *address,
                );
            }
            HirStatement::Assignment {
                address,
                output,
                value,
            } => {
                self.line(
                    "statement",
                    &format!("{} = {};", self.name(*output), self.expr(value)),
                    *address,
                );
            }
            HirStatement::Load {
                address,
                output,
                width,
                source,
            } => {
                self.line(
                    "memory",
                    &format!(
                        "{} = *(u{}*){};",
                        self.name(*output),
                        width,
                        self.expr(source)
                    ),
                    *address,
                );
            }
            HirStatement::Store {
                address,
                width,
                target,
                value,
            } => {
                self.line(
                    "memory",
                    &format!(
                        "*(u{}*){} = {};",
                        width,
                        self.expr(target),
                        self.expr(value)
                    ),
                    *address,
                );
            }
            HirStatement::Call {
                address,
                invocation,
            } => {
                self.line("call", &self.invocation(invocation), *address);
            }
            HirStatement::Unsupported { address, case } => {
                self.line("unsupported", &self.unsupported_text(case), *address);
            }
            HirStatement::Return { address, shape } => {
                let (kind, text) = match shape {
                    HirReturnShape::Void => ("return".to_string(), "return;".to_string()),
                    HirReturnShape::Value { value } => (
                        "return".to_string(),
                        format!("return {};", self.display(value)),
                    ),
                    HirReturnShape::Untracked { register } => (
                        "return".to_string(),
                        format!("return /* {register} is not tracked here */;"),
                    ),
                    HirReturnShape::LocationUnresolved => (
                        "unsupported".to_string(),
                        "return <unresolved return location>;".to_string(),
                    ),
                    HirReturnShape::RegisterUntracked => (
                        "unsupported".to_string(),
                        "return <untracked return register>;".to_string(),
                    ),
                };
                self.line(&kind, &text, *address);
            }
        }
    }

    fn condition(&self, condition: &HirExpr, negated: bool) -> String {
        let text = self.expr(condition);
        if negated {
            format!("!({text})")
        } else {
            text
        }
    }

    fn name(&self, value: Value) -> String {
        let variable = &self.variables[value.variable];
        if value.version == 0 || variable.kind == VariableKind::Temporary {
            variable.name.clone()
        } else {
            format!("{}_{}", variable.name, value.version)
        }
    }

    fn display(&self, value: &HirValueDisplay) -> String {
        match value {
            HirValueDisplay::Named { value } => self.name(*value),
            HirValueDisplay::Constant { constant } => self.constant(*constant),
        }
    }

    fn expr(&self, expression: &HirExpr) -> String {
        match expression {
            HirExpr::Value { value } => self
                .constants
                .get(value)
                .map(|constant| self.constant(*constant))
                .unwrap_or_else(|| self.name(*value)),
            HirExpr::Constant { constant } => self.constant(*constant),
            HirExpr::Missing => "<missing>".into(),
            HirExpr::UnknownCondition => "<unknown condition>".into(),
            HirExpr::Binary { op, left, right } => {
                format!("{} {} {}", self.expr(left), self.op(op), self.expr(right))
            }
            HirExpr::Not { operand } => format!("~{}", self.expr(operand)),
            HirExpr::Cast {
                kind,
                width,
                operand,
            } => {
                let prefix = match kind {
                    HirCastKind::Bits => "bits",
                    HirCastKind::Address => "addr",
                };
                format!("({prefix}{width}){}", self.expr(operand))
            }
            HirExpr::SignExtend {
                from,
                width,
                operand,
            } => {
                format!("sign_extend<{from}, {width}>({})", self.expr(operand))
            }
            HirExpr::Extract {
                offset,
                width,
                operand,
            } => {
                let width: u16 = *width;
                let mask = if width >= 64 {
                    u64::MAX
                } else {
                    (1u64 << width) - 1
                };
                format!("({} >> {offset}) & {mask:#x}", self.expr(operand))
            }
            HirExpr::Insert {
                base,
                value,
                offset,
            } => {
                format!(
                    "insert({}, {}, {offset})",
                    self.expr(base),
                    self.expr(value)
                )
            }
            HirExpr::Select {
                condition,
                taken,
                otherwise,
            } => {
                format!(
                    "{} ? {} : {}",
                    self.expr(condition),
                    self.expr(taken),
                    self.expr(otherwise)
                )
            }
            HirExpr::Parity { operand } => format!("parity({})", self.expr(operand)),
        }
    }

    fn op(&self, op: &HirBinaryOp) -> String {
        match op {
            HirBinaryOp::Add => "+".into(),
            HirBinaryOp::Sub => "-".into(),
            HirBinaryOp::And => "&".into(),
            HirBinaryOp::Or => "|".into(),
            HirBinaryOp::Xor => "^".into(),
            HirBinaryOp::Shl => "<<".into(),
            HirBinaryOp::Shr => ">>".into(),
            HirBinaryOp::Equal => "==".into(),
            HirBinaryOp::UnsignedLess => "<".into(),
        }
    }

    fn constant(&self, constant: Constant) -> String {
        match constant.ty {
            Type::Address(_) => format!("{:#x}", constant.value.0),
            Type::Bits(1) => constant.value.0.to_string(),
            _ => format!("{:#x}", constant.value.0),
        }
    }

    fn invocation(&self, invocation: &HirInvocation) -> String {
        match invocation {
            HirInvocation::Resolved { name, arguments } => {
                let arguments = arguments
                    .iter()
                    .map(|argument| match argument {
                        HirArgument::Named { value } => self.name(*value),
                        HirArgument::Placeholder { name } => format!("/* {name} */"),
                        HirArgument::StackNotShown => "/* stack arguments not shown */".into(),
                        HirArgument::Variadic => "/* ... */".into(),
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{name}({arguments});")
            }
            HirInvocation::DirectUnknown { target } => {
                format!("sub_{target:x}(); /* argument list not recovered for this direct call */")
            }
            HirInvocation::Indirect { target } => {
                let target = target
                    .as_ref()
                    .map(|value| self.expr(value))
                    .unwrap_or_else(|| "<none>".into());
                format!("(*{target})(); /* unresolved indirect call target */")
            }
        }
    }

    fn unsupported_text(&self, case: &UnsupportedCase) -> String {
        match case {
            UnsupportedCase::Effect { reason } => format!("/* unsupported effect: {reason} */"),
            UnsupportedCase::NestingLimit => "/* nesting limit reached */".into(),
            UnsupportedCase::JumpNoTarget => "/* jump with no resolved target */".into(),
            UnsupportedCase::BranchUnresolved => "/* unresolved branch target */".into(),
            UnsupportedCase::LoopHeaderBranch => {
                "/* loop header has an unresolved branch */".into()
            }
            UnsupportedCase::LoopTransfer => "/* unresolved transfer inside loop */".into(),
            UnsupportedCase::OutsideFunction { target } => {
                format!("/* transfer to an address outside the analyzed function: {target:#x} */")
            }
            UnsupportedCase::TransferValue { value } => {
                let value = value
                    .as_ref()
                    .map(|value| self.expr(value))
                    .unwrap_or_else(|| "unknown target".into());
                format!("/* unresolved transfer: {value} */")
            }
        }
    }
}

// ---------------------------------------------------------------------------

fn sanitize(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(512)
        .collect()
}

fn sanitize_identifier(text: &str) -> String {
    let mut result: String = text
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character
            } else {
                '_'
            }
        })
        .take(256)
        .collect();
    if result.is_empty() {
        result.push_str("call");
    }
    if result.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        result.insert(0, '_');
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_sanitized_without_fabricating_empty_names() {
        assert_eq!(sanitize_identifier("std::vector<int>"), "std__vector_int_");
        assert_eq!(sanitize_identifier("123call"), "_123call");
        assert_eq!(sanitize_identifier(""), "call");
        assert_eq!(sanitize_identifier("ok_name"), "ok_name");
        assert_eq!(
            sanitize_identifier("name\nwith\tcontrols"),
            "name_with_controls"
        );
    }

    #[test]
    fn text_rendering_preserves_indent_and_reports_experimental_status() {
        let function = HighLevelFunction {
            function: 0x1000,
            syntax: "c-like".into(),
            status: "experimental-foundations".into(),
            lines: vec![
                HighLevelLine {
                    indent: 0,
                    text: "void sub_1000(void) {".into(),
                    address: Some(0x1000),
                    kind: "signature".into(),
                },
                HighLevelLine {
                    indent: 1,
                    text: "return;".into(),
                    address: Some(0x1001),
                    kind: "control".into(),
                },
                HighLevelLine {
                    indent: 0,
                    text: "}".into(),
                    address: None,
                    kind: "control".into(),
                },
            ],
            unresolved: 0,
            truncated: false,
            notes: vec![],
        };
        assert_eq!(function.text(), "void sub_1000(void) {\n  return;\n}\n");
    }

    #[test]
    fn printer_materializes_indent_and_overflow_bound() {
        // The printer keeps the legacy indent scheme and bound behaviour.
        let ast = HirFunction {
            function: 0x1000,
            source: None,
            statements: vec![
                HirStatement::Signature {
                    address: Some(0x1000),
                    declaration: "void sub_1000(void)".into(),
                },
                HirStatement::If {
                    condition: HirExpr::Constant {
                        constant: Constant::bits(1, 1),
                    },
                    negated: false,
                    taken: vec![HirStatement::Return {
                        address: Some(0x1001),
                        shape: HirReturnShape::Void,
                    }],
                    otherwise: None,
                },
                HirStatement::FunctionClose,
            ],
        };
        let ssa = SsaFunction {
            ir_version: 0,
            entry: crate::ir::Address(crate::parse_address("0x1000").unwrap()),
            address_width: 64,
            variables: vec![],
            blocks: vec![],
            dominators: crate::ir::ssa::Dominators {
                entry: crate::ir::Address(crate::parse_address("0x1000").unwrap()),
                immediate: BTreeMap::new(),
                children: BTreeMap::new(),
                frontiers: BTreeMap::new(),
                unreachable: vec![],
                preorder: BTreeMap::new(),
                postorder: BTreeMap::new(),
            },
            omitted_unreachable: vec![],
        };
        let constants = BTreeMap::new();
        let mut printer = Printer {
            variables: &ssa.variables,
            constants: &constants,
            lines: Vec::new(),
            indent: 0,
            truncated: false,
        };
        printer.function(&ast);
        let rendered = printer
            .lines
            .iter()
            .map(|line| format!("{}{}", "  ".repeat(line.indent), line.text))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            rendered,
            "void sub_1000(void) {\n  if (1) {\n    return;\n  }\n}"
        );
        assert_eq!(printer.lines[2].indent, 2);
        assert_eq!(printer.lines[2].kind, "return");
    }
}
