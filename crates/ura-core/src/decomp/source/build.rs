use super::*;
use crate::{
    decomp::{Location, SignatureHints, StackFrame},
    AnalysisControl,
};
use semantic::{Input, NodeKind, ScalarOp, TransferKind};
use std::collections::{BTreeMap, BTreeSet};

/// Schedule edge-specific parallel assignments. Saving one old source breaks
/// a cycle; every remaining use of that source is replaced, including fan-out.
/// Scratch values have the source width, not the architecture's default width.
pub fn parallel_copies(
    variables: &mut Vec<Variable>,
    mut moves: Vec<(VariableId, Expr)>,
) -> Result<Vec<Statement>, String> {
    let mut destinations = BTreeSet::new();
    for (id, value) in &moves {
        if !matches!(
            value.kind,
            ExprKind::Variable { .. } | ExprKind::Constant { .. } | ExprKind::Unknown { .. }
        ) {
            return Err("parallel copies require evaluated source values".into());
        }
        if !destinations.insert(*id) || variables.get(*id).map(|v| v.storage) != Some(value.storage)
        {
            return Err("invalid parallel-copy destination or width".into());
        }
        if let ExprKind::Variable { id } = value.kind {
            if variables.get(id).map(|v| v.storage) != Some(value.storage) {
                return Err("invalid parallel-copy source or width".into());
            }
        }
    }
    moves.retain(|(d, s)| !matches!(s.kind, ExprKind::Variable {id} if id==*d));
    let mut statements = Vec::new();
    while !moves.is_empty() {
        let sources: BTreeSet<_> = moves
            .iter()
            .filter_map(|(_, e)| match e.kind {
                ExprKind::Variable { id } => Some(id),
                _ => None,
            })
            .collect();
        if let Some(index) = moves.iter().position(|(d, _)| !sources.contains(d)) {
            let (variable, value) = moves.remove(index);
            statements.push(Statement::synthetic(StatementKind::Assign {
                variable,
                value,
            }));
        } else {
            let source = match moves[0].1.kind {
                ExprKind::Variable { id } => id,
                _ => return Err("invalid cyclic parallel copy".into()),
            };
            let id = variables.len();
            let old = variables[source].clone();
            variables.push(Variable {
                id,
                name: format!("edge_tmp_{id}"),
                ssa: None,
                entry_register: None,
                parameter: None,
                scratch: true,
                ..old
            });
            statements.push(Statement::synthetic(StatementKind::Assign {
                variable: id,
                value: Expr::variable(source, variables[source].storage),
            }));
            for (_, value) in &mut moves {
                if matches!(value.kind,ExprKind::Variable {id} if id==source) {
                    value.kind = ExprKind::Variable { id };
                }
            }
        }
    }
    Ok(statements)
}

struct Lowered {
    operations: Vec<Statement>,
    transfer: End,
}
enum End {
    Closed,
    Jump(Edge),
    Branch {
        condition: Expr,
        taken: Edge,
        otherwise: Edge,
        source: usize,
    },
    Stop(Statement),
}
#[derive(Clone)]
struct Edge {
    target: Option<Address>,
    copies: Vec<Statement>,
    source: Option<usize>,
}
struct Builder<'a> {
    hir: &'a semantic::SemanticFunction,
    variables: Vec<Variable>,
    uses: Vec<usize>,
    use_blocks: Vec<BTreeSet<Address>>,
    live: BTreeSet<usize>,
    phi_inputs: BTreeSet<usize>,
    inline: BTreeMap<usize, Expr>,
    constants: BTreeMap<usize, Constant>,
    eliminated: usize,
    phi_copies: usize,
    unresolved: usize,
    diagnostics: Vec<String>,
    hints: &'a SignatureHints,
    call_bindings: &'a BTreeMap<usize, u64>,
    frame: Option<&'a StackFrame>,
}

pub fn build(
    hir: &semantic::SemanticFunction,
    name: &str,
    hints: &SignatureHints,
    frame: Option<&StackFrame>,
    control: &dyn AnalysisControl,
) -> Result<Output, String> {
    build_with_calls(hir, name, hints, frame, &BTreeMap::new(), control)
}
/// Bindings refer to exact semantic source IDs and must come from the verified
/// binary import-slot resolver. They annotate signatures without changing targets.
pub fn build_with_calls(
    hir: &semantic::SemanticFunction,
    name: &str,
    hints: &SignatureHints,
    frame: Option<&StackFrame>,
    call_bindings: &BTreeMap<usize, u64>,
    control: &dyn AnalysisControl,
) -> Result<Output, String> {
    build_with_facts(hir, name, hints, frame, call_bindings, &[], control)
}

/// Constants must be produced by dataflow analysis of the same verified SSA
/// program as `hir`. Memory effects are never folded or moved by this pass.
pub fn build_with_facts(
    hir: &semantic::SemanticFunction,
    name: &str,
    hints: &SignatureHints,
    frame: Option<&StackFrame>,
    call_bindings: &BTreeMap<usize, u64>,
    constant_facts: &[(crate::ir::ssa::Value, Constant)],
    control: &dyn AnalysisControl,
) -> Result<Output, String> {
    if control.is_cancelled() {
        return Err("C-like reconstruction cancelled".into());
    }
    if hir.nodes.len() > crate::ir::MAX_IR_OPERATIONS || hir.blocks.len() > crate::ir::MAX_IR_BLOCKS
    {
        return Err("C-like reconstruction exceeds semantic bounds".into());
    }
    let mut signature = hir.signature.clone();
    let mut names = BTreeSet::new();
    names.insert(identifier(name));
    if let Some(signature) = &mut signature {
        for parameter in &mut signature.parameters {
            let preferred = identifier(&parameter.name);
            let mut candidate = preferred.clone();
            let mut suffix = parameter.index;
            while !names.insert(candidate.clone()) {
                candidate = format!("{preferred}_{suffix}");
                suffix += 1;
            }
            parameter.name = candidate;
        }
    }
    let variables =
        hir.values
            .iter()
            .map(|value| {
                let parameter =
                    hir.signature.as_ref().and_then(|s| {
                        s.parameters
                            .iter()
                            .find(|p| {
                                value.ssa.version==0 && value.register.as_ref().is_some_and(|r|
                matches!(&p.location,Location::Register {name} if name==r))
                && scalar_parameter(&p.ty) && p.width==value.storage.width().unwrap_or(0)
                            })
                            .map(|p| p.index)
                    });
                let preferred = parameter
                    .and_then(|index| {
                        signature
                            .as_ref()?
                            .parameters
                            .iter()
                            .find(|p| p.index == index)
                    })
                    .map(|p| identifier(&p.name))
                    .unwrap_or_else(|| {
                        if value.ssa.version == 0 {
                            value
                                .register
                                .as_ref()
                                .map(|r| format!("in_{}", identifier(r)))
                                .unwrap_or_else(|| format!("v{}", value.id))
                        } else {
                            format!("v{}", value.id)
                        }
                    });
                let mut name = preferred.clone();
                let mut suffix = value.id;
                if parameter.is_none() {
                    while !names.insert(name.clone()) {
                        name = format!("{preferred}_{suffix}");
                        suffix += 1;
                    }
                }
                Variable {
                    id: value.id,
                    name,
                    storage: value.storage,
                    inferred_type: value.inferred_type.clone(),
                    ssa: Some(value.ssa),
                    entry_register: if value.ssa.version == 0 {
                        value.register.clone()
                    } else {
                        None
                    },
                    parameter,
                    scratch: false,
                }
            })
            .collect();
    let facts: BTreeMap<_, _> = constant_facts.iter().copied().collect();
    let constants = hir
        .values
        .iter()
        .filter_map(|value| {
            facts
                .get(&value.ssa)
                .filter(|c| c.ty == value.storage && c.valid())
                .map(|c| (value.id, *c))
        })
        .collect();
    let mut b = Builder {
        hir,
        variables,
        uses: vec![0; hir.values.len()],
        use_blocks: vec![BTreeSet::new(); hir.values.len()],
        live: BTreeSet::new(),
        phi_inputs: BTreeSet::new(),
        inline: BTreeMap::new(),
        constants,
        eliminated: 0,
        phi_copies: 0,
        unresolved: 0,
        diagnostics: Vec::new(),
        hints,
        call_bindings,
        frame,
    };
    b.liveness();
    let mut blocks = BTreeMap::new();
    for block in &hir.blocks {
        if control.is_cancelled() {
            return Err("C-like reconstruction cancelled".into());
        }
        let mut statements = vec![Statement::synthetic(StatementKind::Block {
            address: block.address,
        })];
        let mut elided_instructions = BTreeSet::new();
        for id in &block.operations {
            let node = &hir.nodes[*id];
            if matches!(node.kind, NodeKind::Scalar { .. })
                && node
                    .output
                    .is_some_and(|v| !b.live.contains(&v) || b.constants.contains_key(&v))
            {
                // One compact marker per instruction keeps navigation through
                // folded/dead pure operations without printing a comment line.
                if let Some(address) = hir.sources[node.source].instruction {
                    if elided_instructions.insert(address) {
                        statements.push(Statement {
                            source: Some(node.source),
                            synthetic: false,
                            kind: StatementKind::Provenance,
                        });
                    }
                }
                continue;
            }
            if matches!(node.kind, NodeKind::UnknownEffect)
                && node
                    .output
                    .is_some_and(|v| !b.live.contains(&v) && hir.values[v].storage != Type::Memory)
            {
                continue;
            }
            let mut value = b.node_expression(node);
            if let Some(expr) = &mut value {
                expr.source = Some(node.source);
            }
            match &node.kind {
                NodeKind::Guard => {
                    let reason = match &hir.sources[node.source].original_operation {
                        Some(crate::ir::Operation::Guard { reason }) => reason.clone(),
                        _ => "machine fault".into(),
                    };
                    statements.push(Statement {
                        source: Some(node.source),
                        synthetic: false,
                        kind: StatementKind::Guard {
                            condition: b.argument(node, 0),
                            reason,
                        },
                    });
                }
                NodeKind::Scalar { .. } => {
                    if let (Some(variable), Some(value)) = (node.output, value) {
                        let (size, depth) = value.size();
                        if !b.phi_inputs.contains(&variable)
                            && b.uses[variable] == 1
                            && b.use_blocks[variable].len() == 1
                            && b.use_blocks[variable].contains(&block.address)
                            && size <= MAX_EXPRESSION_NODES
                            && depth <= MAX_EXPRESSION_DEPTH
                        {
                            b.inline.insert(variable, value);
                            b.eliminated += 1;
                        } else {
                            statements.push(Statement {
                                source: Some(node.source),
                                synthetic: false,
                                kind: StatementKind::Assign { variable, value },
                            });
                        }
                    }
                }
                NodeKind::ReadMemory => {
                    if let (Some(variable), Some(value)) = (node.output, value) {
                        statements.push(Statement {
                            source: Some(node.source),
                            synthetic: false,
                            kind: StatementKind::Assign { variable, value },
                        });
                    }
                }
                NodeKind::WriteMemory => {
                    let address = b.argument(node, 1);
                    let value = b.argument(node, 2);
                    let instruction = hir.sources[node.source].instruction;
                    let stack_name = b
                        .frame
                        .and_then(|frame| {
                            frame.slots.iter().find(|slot| {
                                slot.accesses.iter().any(|a| {
                                    Some(Address(a.instruction)) == instruction
                                        && a.write
                                        && a.width == value.storage.width().unwrap_or(0)
                                })
                            })
                        })
                        .map(|slot| slot.user_name.as_ref().unwrap_or(&slot.name).clone());
                    statements.push(Statement {
                        source: Some(node.source),
                        synthetic: false,
                        kind: StatementKind::Store {
                            address,
                            value,
                            stack_name,
                        },
                    });
                }
                NodeKind::Invoke => {
                    let call = b.call(node);
                    statements.push(Statement {
                        source: Some(node.source),
                        synthetic: false,
                        kind: call,
                    });
                }
                NodeKind::UnknownEffect | NodeKind::Barrier => {
                    let reason = match &hir.sources[node.source].original_operation {
                        Some(
                            crate::ir::Operation::Unknown { reason }
                            | crate::ir::Operation::Barrier { reason },
                        ) => reason.clone(),
                        _ => "unsupported machine effect".into(),
                    };
                    let memory = node
                        .output
                        .map_or(true, |v| hir.values[v].storage == Type::Memory);
                    b.unresolved += 1;
                    statements.push(Statement {
                        source: Some(node.source),
                        synthetic: false,
                        kind: StatementKind::Unknown {
                            variable: node.output,
                            memory,
                            reason,
                        },
                    });
                }
                NodeKind::Phi { .. } => return Err("phi outside block entry".into()),
            }
        }
        let source = block.transfer.source;
        let transfer = match block.transfer.kind {
            TransferKind::Branch {
                condition,
                taken,
                fallthrough,
            } => {
                let condition = condition
                    .map(|v| b.expr(v))
                    .unwrap_or_else(|| b.unknown(Type::Bits(1), "unknown branch condition"));
                End::Branch {
                    condition,
                    taken: b.edge(block.address, taken)?,
                    otherwise: b.edge(block.address, fallthrough)?,
                    source,
                }
            }
            TransferKind::Jump { target } => {
                let mut edge = b.edge(block.address, target)?;
                edge.source = Some(source);
                End::Jump(edge)
            }
            TransferKind::Return { destination, .. } => {
                let mut result = b.result(block).map(|v| b.expr(v));
                if let Some(signature) = &hir.signature {
                    if !matches!(signature.return_type, TypeRef::Void)
                        && !scalar_parameter(&signature.return_type)
                    {
                        b.unresolved += 1;
                        result = Some(
                            b.unknown(Type::Bits(hir.address_width), "unsupported return ABI/type"),
                        );
                    } else if let (Some(value), Some(width)) = (
                        result.as_ref(),
                        signature
                            .return_type
                            .bits(&super::super::types::TypeDatabase::new(hir.address_width)),
                    ) {
                        if width > 0 && width <= 64 && value.storage.width() != Some(width as u16) {
                            result = Some(Expr {
                                storage: Type::Bits(width as u16),
                                source: Some(source),
                                kind: ExprKind::Scalar {
                                    operator: ScalarOp::Truncate,
                                    arguments: vec![value.clone()],
                                },
                            });
                        }
                    }
                }
                End::Stop(Statement {
                    source: Some(source),
                    synthetic: false,
                    kind: StatementKind::Return {
                        result,
                        destination: destination.map(|v| b.expr(v)),
                    },
                })
            }
            TransferKind::Indirect { destination } => {
                b.unresolved += 1;
                End::Stop(Statement {
                    source: Some(source),
                    synthetic: false,
                    kind: StatementKind::Exit {
                        destination: destination.map(|v| b.expr(v)),
                        reason: "unresolved indirect transfer".into(),
                    },
                })
            }
            TransferKind::Unresolved => {
                b.unresolved += 1;
                End::Stop(Statement {
                    source: Some(source),
                    synthetic: false,
                    kind: StatementKind::Exit {
                        destination: None,
                        reason: "unresolved control flow".into(),
                    },
                })
            }
        };
        blocks.insert(
            block.address,
            Lowered {
                operations: statements,
                transfer,
            },
        );
    }
    reduce_regions(&mut blocks, hir.entry, &mut b.unresolved, control)?;
    let mut body = b.edge_initial()?;
    let mut order = vec![hir.entry];
    order.extend(blocks.keys().copied().filter(|a| *a != hir.entry));
    for address in order {
        if control.is_cancelled() {
            return Err("C-like structuring cancelled".into());
        }
        body.push(Statement::synthetic(StatementKind::Label { address }));
        body.extend(plain(
            blocks.remove(&address).ok_or("missing lowered block")?,
            &mut b.unresolved,
        ));
    }
    b.diagnostics.push("Reconstructed C-like pseudocode: ABI result, ordered memory effects and explicit exits; not original source or guaranteed recompilable C.".into());
    if b.unresolved > 0 {
        b.diagnostics.push(format!(
            "{} unresolved machine effects or transfers remain explicit.",
            b.unresolved
        ));
    }
    let mut reserved: BTreeSet<_> = signature
        .iter()
        .flat_map(|s| s.parameters.iter().map(|p| p.name.clone()))
        .collect();
    reserved.insert(identifier(name));
    for variable in &mut b.variables {
        if variable.parameter.is_some() {
            continue;
        }
        let preferred = variable.name.clone();
        let mut suffix = variable.id;
        while !reserved.insert(variable.name.clone()) {
            variable.name = format!("{preferred}_{suffix}");
            suffix += 1;
        }
    }
    let ast = Function {
        version: VERSION,
        address: hir.entry,
        name: identifier(name),
        address_width: hir.address_width,
        signature,
        variables: b.variables,
        body,
        sources: hir.sources.clone(),
        diagnostics: b.diagnostics,
        unresolved: b.unresolved,
        truncated: false,
        types_partial: hir.types_partial,
        eliminated_temporaries: b.eliminated,
        phi_copies: b.phi_copies,
    };
    render(ast, control)
}

impl Builder<'_> {
    fn result(&self, block: &semantic::Block) -> Option<Input> {
        if let TransferKind::Return {
            result: Some(value),
            ..
        } = block.transfer.kind
        {
            return Some(value);
        }
        if self
            .hir
            .signature
            .as_ref()
            .is_some_and(|s| matches!(s.return_type, TypeRef::Void))
        {
            return None;
        }
        // A displayed ABI candidate is not a claim that a void/unknown function
        // has an established source return type.
        block
            .transfer
            .registers
            .iter()
            .find(|(name, _)| {
                name == if self.hir.address_width == 64 {
                    "rax"
                } else {
                    "eax"
                }
            })
            .map(|(_, v)| *v)
    }
    fn liveness(&mut self) {
        let mut roots = Vec::new();
        for block in &self.hir.blocks {
            let mut flow_inputs = Vec::new();
            match block.transfer.kind {
                TransferKind::Branch { condition, .. } => flow_inputs.extend(condition),
                TransferKind::Return { destination, .. } => {
                    flow_inputs.extend(destination);
                    flow_inputs.extend(self.result(block));
                }
                TransferKind::Indirect { destination } => flow_inputs.extend(destination),
                _ => {}
            }
            for input in flow_inputs {
                if let Input::Value(id) = input {
                    self.uses[id] += 1;
                    self.use_blocks[id].insert(block.address);
                    roots.push(id);
                }
            }
        }
        for node in &self.hir.nodes {
            if matches!(
                node.kind,
                NodeKind::ReadMemory
                    | NodeKind::WriteMemory
                    | NodeKind::Invoke
                    | NodeKind::Barrier
                    | NodeKind::Guard
            ) || matches!(node.kind, NodeKind::UnknownEffect)
                && node
                    .output
                    .map_or(true, |v| self.hir.values[v].storage == Type::Memory)
            {
                roots.extend(node.inputs.iter().filter_map(|input| match input {
                    Input::Value(id) => Some(*id),
                    _ => None,
                }));
                roots.extend(node.output);
            }
        }
        while let Some(id) = roots.pop() {
            if !self.live.insert(id) {
                continue;
            }
            if self.constants.contains_key(&id) {
                continue;
            }
            if let Some(node) = self.hir.values[id].definition.map(|id| &self.hir.nodes[id]) {
                roots.extend(node.inputs.iter().filter_map(|input| match input {
                    Input::Value(id) => Some(*id),
                    _ => None,
                }));
                if let NodeKind::Phi { initial, incoming } = &node.kind {
                    roots.extend(initial);
                    roots.extend(incoming.iter().map(|v| v.value));
                }
            }
        }
        // Count only uses that survive the observable slice. Dead flag math
        // must not prevent a result from being inlined into its sole real use.
        // Calls still root/count every machine-state snapshot operand, even
        // when their ABI is unknown or their target is in a later block.
        for block in &self.hir.blocks {
            for id in &block.operations {
                let node = &self.hir.nodes[*id];
                if matches!(node.kind, NodeKind::Scalar { .. } | NodeKind::UnknownEffect)
                    && node
                        .output
                        .is_some_and(|v| !self.live.contains(&v) || self.constants.contains_key(&v))
                {
                    continue;
                }
                for input in &node.inputs {
                    if let Input::Value(id) = input {
                        self.uses[*id] += 1;
                        self.use_blocks[*id].insert(block.address);
                    }
                }
            }
            for id in &block.phis {
                let node = &self.hir.nodes[*id];
                if node
                    .output
                    .is_some_and(|v| self.live.contains(&v) && !self.constants.contains_key(&v))
                {
                    if let NodeKind::Phi { initial, incoming } = &node.kind {
                        for value in initial.iter().chain(incoming.iter().map(|v| &v.value)) {
                            self.phi_inputs.insert(*value);
                            self.uses[*value] += 1;
                            self.use_blocks[*value].insert(block.address);
                        }
                    }
                }
            }
        }
    }
    fn expr(&self, input: Input) -> Expr {
        match input {
            Input::Constant(constant) => Expr {
                storage: constant.ty,
                source: None,
                kind: ExprKind::Constant { constant },
            },
            Input::Value(id) => self
                .constants
                .get(&id)
                .map(|constant| Expr {
                    storage: constant.ty,
                    source: self.hir.values[id]
                        .definition
                        .map(|d| self.hir.nodes[d].source),
                    kind: ExprKind::Constant {
                        constant: *constant,
                    },
                })
                .or_else(|| self.inline.get(&id).cloned())
                .unwrap_or_else(|| Expr::variable(id, self.hir.values[id].storage)),
        }
    }
    fn unknown(&self, storage: Type, reason: &str) -> Expr {
        Expr {
            storage,
            source: None,
            kind: ExprKind::Unknown {
                reason: reason.into(),
            },
        }
    }
    fn argument(&self, node: &semantic::Node, index: usize) -> Expr {
        node.inputs
            .get(index)
            .map(|v| self.expr(*v))
            .unwrap_or_else(|| self.unknown(Type::Bits(self.hir.address_width), "missing operand"))
    }
    fn node_expression(&self, node: &semantic::Node) -> Option<Expr> {
        let storage = self.hir.values.get(node.output?).map(|v| v.storage)?;
        if matches!(
            node.kind,
            NodeKind::Scalar {
                operator: ScalarOp::Extract { offset: 0 } | ScalarOp::Truncate
            }
        ) {
            if let Some(Input::Value(id)) = node.inputs.first() {
                let value = &self.hir.values[*id];
                if value.ssa.version == 0 {
                    if let Some(parameter)=self.hir.signature.as_ref().and_then(|s|s.parameters.iter().find(|p|
                        scalar_parameter(&p.ty)&&Some(p.width)==storage.width()&&matches!(&p.location,Location::Register {name} if Some(name)==value.register.as_ref()))) {
                        return Some(Expr {storage,source:Some(node.source),kind:ExprKind::Parameter {
                            index:parameter.index,register:value.register.clone()?}});
                    }
                }
            }
        }
        let kind = match node.kind {
            NodeKind::Scalar { operator } => ExprKind::Scalar {
                operator,
                arguments: node.inputs.iter().map(|v| self.expr(*v)).collect(),
            },
            NodeKind::ReadMemory => ExprKind::Load {
                address: Box::new(self.argument(node, 1)),
            },
            _ => return None,
        };
        Some(Expr {
            storage,
            source: Some(node.source),
            kind,
        })
    }
    fn edge(&mut self, from: Address, target: Option<Address>) -> Result<Edge, String> {
        let mut moves = Vec::new();
        if let Some(block) = target.and_then(|t| self.hir.blocks.iter().find(|b| b.address == t)) {
            for id in &block.phis {
                let node = &self.hir.nodes[*id];
                let output = node.output.ok_or("phi has no output")?;
                if !self.live.contains(&output)
                    || self.constants.contains_key(&output)
                    || self.hir.values[output].storage == Type::Memory
                {
                    continue;
                }
                if let NodeKind::Phi { incoming, .. } = &node.kind {
                    let value = incoming
                        .iter()
                        .find(|edge| edge.predecessor == from)
                        .map(|edge| self.expr(Input::Value(edge.value)))
                        .unwrap_or_else(|| {
                            self.unknown(self.hir.values[output].storage, "missing phi predecessor")
                        });
                    moves.push((output, value));
                }
            }
        }
        let copies = parallel_copies(&mut self.variables, moves)?;
        self.phi_copies += copies.len();
        Ok(Edge {
            target,
            copies,
            source: None,
        })
    }
    fn edge_initial(&mut self) -> Result<Vec<Statement>, String> {
        let block = self
            .hir
            .blocks
            .iter()
            .find(|b| b.address == self.hir.entry)
            .ok_or("missing source entry")?;
        let mut moves = Vec::new();
        for id in &block.phis {
            let node = &self.hir.nodes[*id];
            let output = node.output.ok_or("missing initial phi output")?;
            if !self.live.contains(&output)
                || self.constants.contains_key(&output)
                || self.hir.values[output].storage == Type::Memory
            {
                continue;
            }
            if let NodeKind::Phi { initial, .. } = node.kind {
                moves.push((
                    output,
                    initial
                        .map(|v| self.expr(Input::Value(v)))
                        .unwrap_or_else(|| {
                            self.unknown(
                                self.hir.values[output].storage,
                                "unestablished initial phi",
                            )
                        }),
                ));
            }
        }
        parallel_copies(&mut self.variables, moves)
    }
    fn call(&mut self, node: &semantic::Node) -> StatementKind {
        let target = self.argument(node, 0);
        let direct = match node.inputs.first() {
            Some(Input::Constant(c)) => Some(c.value),
            _ => None,
        };
        let signature = direct
            .map(|a| a.0)
            .or_else(|| self.call_bindings.get(&node.source).copied())
            .and_then(|a| self.hints.get(a));
        let mut arguments = Vec::new();
        let mut unknown_arguments = true;
        if let Some(signature) = signature {
            unknown_arguments = signature.variadic != Some(false);
            for parameter in &signature.parameters {
                let found = match &parameter.location {
                    Location::Register { name }
                        if scalar_parameter(&parameter.ty)
                            && (1..=64).contains(&parameter.width) =>
                    {
                        self.hir
                            .values
                            .iter()
                            .find(|v| v.register.as_ref() == Some(name))
                            .and_then(|v| node.inputs.get(1 + v.ssa.variable))
                    }
                    _ => None,
                };
                arguments.push(found.map(|v| self.expr(*v)).unwrap_or_else(|| {
                    self.unknown(
                        Type::Bits(parameter.width.clamp(1, 64)),
                        "unsupported call argument location",
                    )
                }));
                unknown_arguments |= found.is_none();
            }
        }
        // Call argument values cannot be inlined using a use count computed
        // solely from the opaque machine target.
        if unknown_arguments || signature.is_none() {
            self.unresolved += 1;
        }
        StatementKind::Call {
            target,
            callee: direct,
            name: signature.map(|s| identifier(&s.name)),
            arguments,
            unknown_arguments,
        }
    }
}
fn negated(condition: Expr) -> Expr {
    Expr {
        storage: Type::Bits(1),
        source: condition.source,
        kind: ExprKind::Scalar {
            operator: ScalarOp::Equal,
            arguments: vec![
                condition,
                Expr {
                    storage: Type::Bits(1),
                    source: None,
                    kind: ExprKind::Constant {
                        constant: Constant::bits(1, 0),
                    },
                },
            ],
        },
    }
}
fn edge_jump(edge: Edge, unresolved: &mut usize) -> Vec<Statement> {
    let mut result = edge.copies;
    result.push(Statement {
        source: edge.source,
        synthetic: edge.source.is_none(),
        kind: match edge.target {
            Some(target) => StatementKind::Goto { target },
            None => {
                *unresolved += 1;
                StatementKind::Exit {
                    destination: None,
                    reason: "unresolved edge".into(),
                }
            }
        },
    });
    result
}
fn scalar_parameter(ty: &TypeRef) -> bool {
    match ty {
        TypeRef::Int { .. }
        | TypeRef::Bool
        | TypeRef::Pointer { .. }
        | TypeRef::Unknown { .. }
        | TypeRef::Enum { .. } => true,
        TypeRef::Typedef { target, .. } | TypeRef::Qualified { target, .. } => {
            scalar_parameter(target)
        }
        _ => false,
    }
}
fn plain(block: Lowered, unresolved: &mut usize) -> Vec<Statement> {
    let mut body = block.operations;
    match block.transfer {
        End::Closed => {}
        End::Jump(edge) => body.extend(edge_jump(edge, unresolved)),
        End::Branch {
            condition,
            taken,
            otherwise,
            source,
        } => body.push(Statement {
            source: Some(source),
            synthetic: false,
            kind: StatementKind::If {
                condition,
                taken: edge_jump(taken, unresolved),
                otherwise: edge_jump(otherwise, unresolved),
            },
        }),
        End::Stop(statement) => body.push(statement),
    }
    body
}
fn predecessors(blocks: &BTreeMap<Address, Lowered>) -> BTreeMap<Address, BTreeSet<Address>> {
    let mut result: BTreeMap<_, BTreeSet<_>> = BTreeMap::new();
    for (address, block) in blocks {
        let edges = match &block.transfer {
            End::Jump(e) => vec![e],
            End::Branch {
                taken, otherwise, ..
            } => vec![taken, otherwise],
            _ => Vec::new(),
        };
        for target in edges.into_iter().filter_map(|e| e.target) {
            result.entry(target).or_default().insert(*address);
        }
    }
    result
}

/// Each reduction removes a uniquely entered block, or closes an exact
/// self-loop. No reachability, postdominator, or switch target is guessed.
fn reduce_regions(
    blocks: &mut BTreeMap<Address, Lowered>,
    entry: Address,
    unresolved: &mut usize,
    control: &dyn AnalysisControl,
) -> Result<(), String> {
    enum Reduction {
        Linear(Address, Address),
        Diamond(Address, Address, Address, Option<Address>),
        Loop(Address, bool),
    }
    for _ in 0..(crate::ir::MAX_IR_BLOCKS * 3) {
        if control.is_cancelled() {
            return Err("C-like region reduction cancelled".into());
        }
        let predecessors = predecessors(blocks);
        let unique = |target: Address, from: Address| {
            target != entry
                && target != from
                && predecessors
                    .get(&target)
                    .is_some_and(|p| p.len() == 1 && p.contains(&from))
        };
        let mut reduction = None;
        for (address, block) in blocks.iter() {
            match &block.transfer {
                End::Jump(edge) => {
                    if let Some(target) = edge
                        .target
                        .filter(|t| unique(*t, *address) && blocks.contains_key(t))
                    {
                        reduction = Some(Reduction::Linear(*address, target));
                        break;
                    }
                }
                End::Branch {
                    taken, otherwise, ..
                } => {
                    if (taken.target == Some(*address)) != (otherwise.target == Some(*address)) {
                        reduction = Some(Reduction::Loop(*address, taken.target == Some(*address)));
                        break;
                    }
                    if let (Some(a), Some(c)) = (taken.target, otherwise.target) {
                        if a != c && unique(a, *address) && unique(c, *address) {
                            if let (Some(left), Some(right)) = (blocks.get(&a), blocks.get(&c)) {
                                let join = match (&left.transfer, &right.transfer) {
                                    (End::Jump(x), End::Jump(y))
                                        if x.target == y.target
                                            && x.target != Some(*address)
                                            && x.target != Some(a)
                                            && x.target != Some(c) =>
                                    {
                                        Some(x.target)
                                    }
                                    (End::Stop(_) | End::Closed, End::Stop(_) | End::Closed) => {
                                        Some(None)
                                    }
                                    _ => None,
                                };
                                if let Some(join) = join {
                                    reduction = Some(Reduction::Diamond(*address, a, c, join));
                                    break;
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        match reduction {
            None => return Ok(()),
            Some(Reduction::Linear(from, target)) => {
                let tail = blocks.remove(&target).ok_or("missing linear region")?;
                let head = blocks.get_mut(&from).ok_or("missing linear head")?;
                let previous = std::mem::replace(&mut head.transfer, tail.transfer);
                if let End::Jump(edge) = previous {
                    // The physical jump is still represented in source mapping.
                    head.operations.extend(edge.copies);
                    if edge.source.is_some() {
                        head.operations.push(Statement {
                            source: edge.source,
                            synthetic: false,
                            kind: StatementKind::Provenance,
                        });
                    }
                }
                head.operations.extend(tail.operations);
            }
            Some(Reduction::Diamond(from, a, c, join)) => {
                let left = blocks.remove(&a).ok_or("missing diamond arm")?;
                let right = blocks.remove(&c).ok_or("missing diamond arm")?;
                let head = blocks.get_mut(&from).ok_or("missing diamond head")?;
                let replacement = if let Some(target) = join {
                    End::Jump(Edge {
                        target: Some(target),
                        copies: Vec::new(),
                        source: None,
                    })
                } else {
                    End::Closed
                };
                if let End::Branch {
                    condition,
                    taken,
                    otherwise,
                    source,
                } = std::mem::replace(&mut head.transfer, replacement)
                {
                    let mut left_body = taken.copies;
                    left_body.extend(plain(left, unresolved));
                    let mut right_body = otherwise.copies;
                    right_body.extend(plain(right, unresolved));
                    if join.is_some() {
                        for arm in [&mut left_body, &mut right_body] {
                            if let Some(jump) = arm.pop() {
                                if jump.source.is_some() {
                                    arm.push(Statement {
                                        kind: StatementKind::Provenance,
                                        ..jump
                                    });
                                }
                            }
                        }
                    }
                    head.operations.push(Statement {
                        source: Some(source),
                        synthetic: false,
                        kind: StatementKind::If {
                            condition,
                            taken: left_body,
                            otherwise: right_body,
                        },
                    });
                }
            }
            Some(Reduction::Loop(address, taken_repeats)) => {
                let block = blocks.remove(&address).ok_or("missing loop region")?;
                if let End::Branch {
                    condition,
                    taken,
                    otherwise,
                    source,
                } = block.transfer
                {
                    let (repeat, exit, condition) = if taken_repeats {
                        (taken, otherwise, condition)
                    } else {
                        (otherwise, taken, negated(condition))
                    };
                    let mut body = block.operations;
                    body.push(Statement {
                        source: Some(source),
                        synthetic: false,
                        kind: StatementKind::If {
                            condition: negated(condition),
                            taken: exit
                                .copies
                                .into_iter()
                                .chain([Statement::synthetic(StatementKind::Break)])
                                .collect(),
                            otherwise: Vec::new(),
                        },
                    });
                    body.extend(repeat.copies);
                    blocks.insert(
                        address,
                        Lowered {
                            operations: vec![Statement::synthetic(StatementKind::Loop { body })],
                            transfer: End::Jump(Edge {
                                target: exit.target,
                                copies: Vec::new(),
                                source: None,
                            }),
                        },
                    );
                }
            }
        }
    }
    Err("C-like region reduction budget exceeded".into())
}
