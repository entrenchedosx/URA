//! Recovered high-level IR and a deliberately non-compilable C-like rendering.
//!
//! This is a structural view over verified SSA, not decompiled source. Branch
//! conditions, call argument lists and memory widths are only printed when the
//! lifted semantics or a supplied signature justify them; everything else is
//! marked as unresolved.
use super::abi::SignatureHints;
use super::signature::{FunctionSignature, Location};
use super::stack::StackFrame;
use crate::ir::dataflow::Dataflow;
use crate::ir::ssa::{SsaBlock, SsaFunction, SsaStatement, Use, Value};
use crate::ir::{Constant, FlowKind, Operation, Type, VariableKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const MAX_HIR_LINES: usize = 20_000;
pub const MAX_HIR_DEPTH: usize = 64;
const MAX_JOIN_NODES: usize = 2_048;

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

#[derive(Clone)]
struct LoopFrame {
    header: u64,
    nodes: BTreeSet<u64>,
}

struct Structurer<'a> {
    ssa: &'a SsaFunction,
    blocks: BTreeMap<u64, &'a SsaBlock>,
    predecessors: BTreeMap<u64, Vec<u64>>,
    latches: BTreeMap<u64, Vec<u64>>,
    constants: BTreeMap<Value, Constant>,
    dead: BTreeSet<Value>,
    hints: &'a SignatureHints,
    signature: &'a FunctionSignature,
    lines: Vec<HighLevelLine>,
    emitted: BTreeSet<u64>,
    active: Vec<LoopFrame>,
    unresolved: usize,
    truncated: bool,
    indent: usize,
}

pub fn build(
    ssa: &SsaFunction,
    dataflow: &Dataflow,
    signature: &FunctionSignature,
    hints: &SignatureHints,
    frame: Option<&StackFrame>,
) -> HighLevelFunction {
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
    let mut structurer = Structurer {
        ssa,
        blocks,
        predecessors,
        latches,
        constants: dataflow.constants.iter().copied().collect(),
        dead: dataflow.dead_definitions.iter().copied().collect(),
        hints,
        signature,
        lines: Vec::new(),
        emitted: BTreeSet::new(),
        active: Vec::new(),
        unresolved: 0,
        truncated: false,
        indent: 0,
    };
    structurer.line(
        "comment",
        "// recovered high-level IR (experimental foundation, not decompiled source)",
        None,
    );
    structurer.line(
        "signature",
        &format!("{} {{", signature.declaration()),
        Some(ssa.entry.0),
    );
    structurer.indent += 1;
    if structurer.blocks.contains_key(&ssa.entry.0) {
        structurer.region(ssa.entry.0, None, 0);
    } else {
        structurer.line(
            "comment",
            "// entry block is not present in the SSA graph",
            None,
        );
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
        structurer.line(
            "comment",
            &format!("// block {address:#x} is only reachable through a transfer that was not structured"),
            Some(address),
        );
        structurer.region(address, None, 0);
    }
    structurer.indent = structurer.indent.saturating_sub(1);
    structurer.line("control", "}", None);
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
    HighLevelFunction {
        function: ssa.entry.0,
        syntax: "c-like".into(),
        status: "experimental-foundations".into(),
        lines: structurer.lines,
        unresolved: structurer.unresolved,
        truncated: structurer.truncated,
        notes,
    }
}

impl<'a> Structurer<'a> {
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

    fn goto(&mut self, target: u64, stop: Option<u64>, depth: usize) {
        if Some(target) == stop {
            return;
        }
        if self
            .active
            .last()
            .is_some_and(|frame| !frame.nodes.contains(&target))
        {
            self.line("control", &format!("goto L_{target:x};"), None);
            return;
        }
        if self.emitted.contains(&target) || !self.blocks.contains_key(&target) {
            if self.blocks.contains_key(&target) {
                self.line("control", &format!("goto L_{target:x};"), None);
            } else {
                self.line(
                    "unsupported",
                    &format!(
                        "/* transfer to an address outside the analyzed function: {target:#x} */"
                    ),
                    None,
                );
                self.unresolved += 1;
            }
            return;
        }
        self.region(target, stop, depth + 1);
    }

    fn region(&mut self, entry: u64, stop: Option<u64>, depth: usize) {
        if self.truncated || self.lines.len() >= MAX_HIR_LINES {
            self.truncated = true;
            return;
        }
        if Some(entry) == stop {
            return;
        }
        if self.emitted.contains(&entry) {
            self.line("control", &format!("goto L_{entry:x};"), None);
            return;
        }
        if depth > MAX_HIR_DEPTH {
            self.line("unsupported", "/* nesting limit reached */", None);
            self.unresolved += 1;
            self.truncated = true;
            return;
        }
        if self.latches.contains_key(&entry)
            && !self.active.iter().any(|frame| frame.header == entry)
        {
            self.loop_region(entry, stop, depth);
            return;
        }
        let Some(block) = self.blocks.get(&entry).copied() else {
            return;
        };
        self.emitted.insert(entry);
        self.line("label", &format!("L_{entry:x}:"), Some(entry));
        self.block_statements(block);
        self.terminator(block, stop, depth);
    }

    fn loop_region(&mut self, header: u64, stop: Option<u64>, depth: usize) {
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
            self.line(
                "comment",
                &format!(
                    "// loop at {header:#x} has {} observed exit target(s); exits other than the first are expressed with gotos",
                    exits.len()
                ),
                Some(header),
            );
        }
        let Some(block) = self.blocks.get(&header).copied() else {
            return;
        };
        self.emitted.insert(header);
        self.line("label", &format!("L_{header:x}:"), Some(header));
        self.line("control", "while (1) {", Some(header));
        self.indent += 1;
        self.active.push(LoopFrame {
            header,
            nodes: nodes.clone(),
        });
        self.block_statements(block);
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
                    .unwrap_or_else(|| "<unknown condition>".into());
                match (taken, fall) {
                    (Some(taken), Some(fall)) => {
                        let taken_in = nodes.contains(&taken);
                        let fall_in = nodes.contains(&fall);
                        if taken_in && !fall_in {
                            self.exit_condition(&format!("!({cond})"), fall, exit);
                            self.region(taken, Some(header), depth + 1);
                        } else if fall_in && !taken_in {
                            self.exit_condition(&cond, taken, exit);
                            self.region(fall, Some(header), depth + 1);
                        } else if taken_in && fall_in {
                            self.branch_targets(block, &cond, taken, fall, Some(header), depth);
                        } else {
                            self.exit_condition(&cond, taken, exit);
                            self.exit_condition(&format!("!({cond})"), fall, exit);
                        }
                    }
                    _ => {
                        self.line(
                            "unsupported",
                            "/* loop header has an unresolved branch */",
                            None,
                        );
                        self.unresolved += 1;
                    }
                }
            }
            FlowKind::Jump => {
                if let Some(target) = flow.successors.first().map(|address| address.0) {
                    if target != header {
                        if nodes.contains(&target) {
                            self.region(target, Some(header), depth + 1);
                        } else if Some(target) == exit {
                            self.line("control", "break;", None);
                        } else {
                            self.line("control", &format!("goto L_{target:x};"), None);
                        }
                    }
                } else {
                    self.line("control", "break;", None);
                }
            }
            FlowKind::Return => self.return_line(block),
            FlowKind::Indirect | FlowKind::Unresolved => {
                self.line("unsupported", "/* unresolved transfer inside loop */", None);
                self.unresolved += 1;
            }
        }
        self.active.pop();
        self.indent = self.indent.saturating_sub(1);
        self.line("control", "}", None);
        if let Some(exit) = exit {
            self.region(exit, stop, depth + 1);
        }
    }

    fn exit_condition(&mut self, condition: &str, target: u64, exit: Option<u64>) {
        if Some(target) == exit {
            self.line("control", &format!("if ({condition}) break;"), None);
        } else {
            self.line(
                "control",
                &format!("if ({condition}) goto L_{target:x};"),
                None,
            );
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

    fn block_statements(&mut self, block: &'a SsaBlock) {
        for phi in &block.phis {
            if self.dead.contains(&phi.output) {
                continue;
            }
            let incoming = phi
                .incoming
                .iter()
                .map(|(predecessor, value)| {
                    format!("{:#x}: {}", predecessor.0, self.value_name(*value))
                })
                .chain(
                    phi.initial
                        .map(|value| format!("entry: {}", self.value_name(value))),
                )
                .collect::<Vec<_>>()
                .join(", ");
            let output = self.value_name(phi.output);
            self.line(
                "statement",
                &format!("{output} = phi({incoming});"),
                Some(block.address.0),
            );
        }
        for statement in &block.statements {
            if let Some(output) = statement.output {
                if self.dead.contains(&output) && !statement.op.observable() {
                    continue;
                }
            }
            if let Some((text, kind)) = self.statement(statement) {
                self.line(kind, &text, Some(statement.source.0));
            }
        }
    }

    fn statement(&mut self, statement: &SsaStatement) -> Option<(String, &'static str)> {
        let output = statement.output.map(|value| self.value_name(value));
        let text = match &statement.op {
            Operation::Copy => format!("{} = {};", output?, self.arg(statement, 0)),
            Operation::Add => format!(
                "{} = {} + {};",
                output?,
                self.arg(statement, 0),
                self.arg(statement, 1)
            ),
            Operation::Sub => format!(
                "{} = {} - {};",
                output?,
                self.arg(statement, 0),
                self.arg(statement, 1)
            ),
            Operation::And => format!(
                "{} = {} & {};",
                output?,
                self.arg(statement, 0),
                self.arg(statement, 1)
            ),
            Operation::Or => format!(
                "{} = {} | {};",
                output?,
                self.arg(statement, 0),
                self.arg(statement, 1)
            ),
            Operation::Xor => format!(
                "{} = {} ^ {};",
                output?,
                self.arg(statement, 0),
                self.arg(statement, 1)
            ),
            Operation::Not => format!("{} = ~{};", output?, self.arg(statement, 0)),
            Operation::Shl => format!(
                "{} = {} << {};",
                output?,
                self.arg(statement, 0),
                self.arg(statement, 1)
            ),
            Operation::Shr => format!(
                "{} = {} >> {};",
                output?,
                self.arg(statement, 0),
                self.arg(statement, 1)
            ),
            Operation::Equal => format!(
                "{} = {} == {};",
                output?,
                self.arg(statement, 0),
                self.arg(statement, 1)
            ),
            Operation::UnsignedLess => format!(
                "{} = {} < {};",
                output?,
                self.arg(statement, 0),
                self.arg(statement, 1)
            ),
            Operation::ZeroExtend | Operation::Truncate | Operation::ToBits => {
                let width = self
                    .output_type(statement.output?)
                    .and_then(Type::width)
                    .unwrap_or(64);
                format!("{} = (bits{width}){};", output?, self.arg(statement, 0))
            }
            Operation::SignExtend => {
                let width = self
                    .output_type(statement.output?)
                    .and_then(Type::width)
                    .unwrap_or(64);
                let from = statement
                    .args
                    .first()
                    .and_then(|arg| self.use_type(*arg))
                    .and_then(Type::width)
                    .unwrap_or(0);
                format!(
                    "{} = sign_extend<{from}, {width}>({});",
                    output?,
                    self.arg(statement, 0)
                )
            }
            Operation::ToAddress => {
                let width = self
                    .output_type(statement.output?)
                    .and_then(Type::width)
                    .unwrap_or(64);
                format!("{} = (addr{width}){};", output?, self.arg(statement, 0))
            }
            Operation::Extract { offset } => {
                let width = self
                    .output_type(statement.output?)
                    .and_then(Type::width)
                    .unwrap_or(64);
                let mask = if width >= 64 {
                    u64::MAX
                } else {
                    (1u64 << width) - 1
                };
                format!(
                    "{} = ({} >> {}) & {mask:#x};",
                    output?,
                    self.arg(statement, 0),
                    offset
                )
            }
            Operation::Insert { offset } => {
                format!(
                    "{} = insert({}, {}, {});",
                    output?,
                    self.arg(statement, 0),
                    self.arg(statement, 1),
                    offset
                )
            }
            Operation::Select => format!(
                "{} = {} ? {} : {};",
                output?,
                self.arg(statement, 0),
                self.arg(statement, 1),
                self.arg(statement, 2)
            ),
            Operation::Parity => format!("{} = parity({});", output?, self.arg(statement, 0)),
            Operation::Load => {
                let width = self
                    .output_type(statement.output?)
                    .and_then(Type::width)
                    .unwrap_or(64);
                format!("{} = *(u{width}*){};", output?, self.arg(statement, 1))
            }
            Operation::Store => {
                let width = statement
                    .args
                    .get(2)
                    .and_then(|value| self.use_type(*value))
                    .and_then(Type::width)
                    .unwrap_or(64);
                format!(
                    "*(u{width}*){} = {};",
                    self.arg(statement, 1),
                    self.arg(statement, 2)
                )
            }
            Operation::Call => {
                let (text, unresolved) = self.call_text(statement);
                if unresolved {
                    self.unresolved += 1;
                }
                text
            }
            Operation::Barrier { reason } | Operation::Unknown { reason } => {
                self.unresolved += 1;
                format!("/* unsupported effect: {reason} */")
            }
        };
        let kind = match statement.op {
            Operation::Barrier { .. } | Operation::Unknown { .. } => "unsupported",
            Operation::Call => "call",
            Operation::Load | Operation::Store => "memory",
            _ => "statement",
        };
        Some((text, kind))
    }

    fn arg(&self, statement: &SsaStatement, index: usize) -> String {
        statement
            .args
            .get(index)
            .copied()
            .map(|value| self.expr(value))
            .unwrap_or_else(|| "<missing>".into())
    }

    fn call_text(&self, statement: &SsaStatement) -> (String, bool) {
        let target = statement.args.first().copied();
        let address = match target {
            Some(Use::Constant(constant)) if matches!(constant.ty, Type::Address(_)) => {
                Some(constant.value.0)
            }
            _ => None,
        };
        let signature = address.and_then(|address| {
            if address == self.signature.function {
                Some(self.signature)
            } else {
                self.hints.get(address)
            }
        });
        match (address, signature) {
            (Some(_address), Some(signature)) => {
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
                                    arguments.push(self.value_name(value));
                                    continue;
                                }
                            }
                            arguments.push(format!("/* {} */", parameter.name));
                            unresolved = true;
                        }
                        Location::Stack { .. } => stack_arguments = true,
                        Location::Unknown { .. } => {
                            arguments.push(format!("/* {} */", parameter.name));
                            unresolved = true;
                        }
                    }
                }
                if stack_arguments {
                    arguments.push("/* stack arguments not shown */".into());
                    unresolved = true;
                }
                if signature.variadic == Some(true) {
                    arguments.push("/* ... */".into());
                }
                (
                    format!(
                        "{}({});",
                        sanitize_identifier(&signature.name),
                        arguments.join(", ")
                    ),
                    unresolved,
                )
            }
            (Some(address), None) => (
                format!(
                    "sub_{address:x}(); /* argument list not recovered for this direct call */"
                ),
                true,
            ),
            (None, _) => (
                format!(
                    "(*{})(); /* unresolved indirect call target */",
                    target
                        .map(|value| self.expr(value))
                        .unwrap_or_else(|| "<none>".into())
                ),
                true,
            ),
        }
    }

    fn terminator(&mut self, block: &'a SsaBlock, stop: Option<u64>, depth: usize) {
        let flow = &block.terminator.flow;
        match flow.kind {
            FlowKind::Return => self.return_line(block),
            FlowKind::Jump => {
                let target = flow
                    .successors
                    .first()
                    .map(|address| address.0)
                    .or_else(|| flow.exits.first().map(|address| address.0));
                match target {
                    Some(target) => self.goto(target, stop, depth),
                    None => {
                        self.line("unsupported", "/* jump with no resolved target */", None);
                        self.unresolved += 1;
                    }
                }
            }
            FlowKind::Branch => {
                let cond = block
                    .terminator
                    .value
                    .map(|value| self.expr(value))
                    .unwrap_or_else(|| "<unknown condition>".into());
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
                        self.branch_targets(block, &cond, taken, fall, stop, depth);
                    }
                    _ => {
                        self.line(
                            "unsupported",
                            "/* unresolved branch target */",
                            Some(block.terminator.flow.source.0),
                        );
                        self.unresolved += 1;
                    }
                }
            }
            FlowKind::Indirect | FlowKind::Unresolved => {
                self.line(
                    "unsupported",
                    &format!(
                        "/* unresolved transfer: {} */",
                        block
                            .terminator
                            .value
                            .map(|value| self.expr(value))
                            .unwrap_or_else(|| "unknown target".into())
                    ),
                    Some(block.terminator.flow.source.0),
                );
                self.unresolved += 1;
            }
        }
    }

    fn branch_targets(
        &mut self,
        _block: &'a SsaBlock,
        cond: &str,
        taken: u64,
        fall: u64,
        stop: Option<u64>,
        depth: usize,
    ) {
        if Some(taken) == stop && Some(fall) == stop {
            return;
        }
        if Some(taken) == stop {
            self.line("control", &format!("if (!({cond})) {{"), None);
            self.indent += 1;
            self.region(fall, stop, depth + 1);
            self.indent = self.indent.saturating_sub(1);
            self.line("control", "}", None);
            return;
        }
        if Some(fall) == stop {
            self.line("control", &format!("if ({cond}) {{"), None);
            self.indent += 1;
            self.region(taken, stop, depth + 1);
            self.indent = self.indent.saturating_sub(1);
            self.line("control", "}", None);
            return;
        }
        if self.outside_active_loop(taken) || self.outside_active_loop(fall) {
            self.line(
                "control",
                &format!("if ({cond}) goto L_{taken:x}; else goto L_{fall:x};"),
                None,
            );
            return;
        }
        let join = self.join_point(taken, fall);
        match join {
            Some(join) if join == taken => {
                self.line("control", &format!("if (!({cond})) {{"), None);
                self.indent += 1;
                self.region(fall, Some(taken), depth + 1);
                self.indent = self.indent.saturating_sub(1);
                self.line("control", "}", None);
                self.region(taken, stop, depth + 1);
            }
            Some(join) if join == fall => {
                self.line("control", &format!("if ({cond}) {{"), None);
                self.indent += 1;
                self.region(taken, Some(fall), depth + 1);
                self.indent = self.indent.saturating_sub(1);
                self.line("control", "}", None);
                self.region(fall, stop, depth + 1);
            }
            Some(join) => {
                self.line("control", &format!("if ({cond}) {{"), None);
                self.indent += 1;
                self.region(taken, Some(join), depth + 1);
                self.indent = self.indent.saturating_sub(1);
                self.line("control", "} else {", None);
                self.indent += 1;
                self.region(fall, Some(join), depth + 1);
                self.indent = self.indent.saturating_sub(1);
                self.line("control", "}", None);
                self.region(join, stop, depth + 1);
            }
            None => {
                self.line(
                    "control",
                    &format!("if ({cond}) goto L_{taken:x}; else goto L_{fall:x};"),
                    None,
                );
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
        let mut from_a = BTreeMap::from([(a, 0usize)]);
        let mut queue = VecDeque::from([a]);
        let mut visited = 0usize;
        while let Some(current) = queue.pop_front() {
            visited += 1;
            if visited > MAX_JOIN_NODES {
                break;
            }
            let distance = from_a[&current];
            if let Some(block) = self.blocks.get(&current) {
                for successor in &block.terminator.flow.successors {
                    let successor = successor.0;
                    if let std::collections::btree_map::Entry::Vacant(entry) =
                        from_a.entry(successor)
                    {
                        entry.insert(distance + 1);
                        queue.push_back(successor);
                    }
                }
            }
        }
        let mut from_b = BTreeMap::from([(b, 0usize)]);
        let mut queue = VecDeque::from([b]);
        let mut best: Option<(usize, u64)> = None;
        let mut visited = 0usize;
        while let Some(current) = queue.pop_front() {
            visited += 1;
            if visited > MAX_JOIN_NODES {
                break;
            }
            let distance = from_b[&current];
            if let Some(other) = from_a.get(&current) {
                let score = other + distance;
                if best.map_or(true, |(best_score, best_address)| {
                    score < best_score || (score == best_score && current < best_address)
                }) {
                    best = Some((score, current));
                }
            }
            if let Some(block) = self.blocks.get(&current) {
                for successor in &block.terminator.flow.successors {
                    let successor = successor.0;
                    if let std::collections::btree_map::Entry::Vacant(entry) =
                        from_b.entry(successor)
                    {
                        entry.insert(distance + 1);
                        queue.push_back(successor);
                    }
                }
            }
        }
        best.map(|(_, address)| address)
    }

    fn return_line(&mut self, block: &'a SsaBlock) {
        if matches!(self.signature.return_value.ty, super::types::TypeRef::Void) {
            self.line("return", "return;", Some(block.terminator.flow.source.0));
            return;
        }
        let register = match &self.signature.return_value.location {
            Some(Location::Register { name }) => name.clone(),
            _ => {
                self.unresolved += 1;
                self.line(
                    "unsupported",
                    "return <unresolved return location>;",
                    Some(block.terminator.flow.source.0),
                );
                return;
            }
        };
        let Some(index) = self.ssa.variables.iter().position(|variable| {
            variable.kind == VariableKind::Register && variable.name == register
        }) else {
            self.unresolved += 1;
            self.line(
                "unsupported",
                "return <untracked return register>;",
                Some(block.terminator.flow.source.0),
            );
            return;
        };
        let value = block
            .terminator
            .state
            .get(index)
            .map(|value| match value {
                Use::Value(value) => self.value_name(*value),
                Use::Constant(constant) => self.format_constant(*constant),
            })
            .unwrap_or_else(|| format!("/* {register} is not tracked here */"));
        self.line(
            "return",
            &format!("return {value};"),
            Some(block.terminator.flow.source.0),
        );
    }

    fn value_name(&self, value: Value) -> String {
        let variable = &self.ssa.variables[value.variable];
        if value.version == 0 || variable.kind == VariableKind::Temporary {
            variable.name.clone()
        } else {
            format!("{}_{}", variable.name, value.version)
        }
    }

    fn expr(&self, value: Use) -> String {
        match value {
            Use::Constant(constant) => self.format_constant(constant),
            Use::Value(value) => self
                .constants
                .get(&value)
                .map(|constant| self.format_constant(*constant))
                .unwrap_or_else(|| self.value_name(value)),
        }
    }

    fn format_constant(&self, constant: Constant) -> String {
        match constant.ty {
            Type::Address(_) => format!("{:#x}", constant.value.0),
            Type::Bits(1) => constant.value.0.to_string(),
            _ => format!("{:#x}", constant.value.0),
        }
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
}
