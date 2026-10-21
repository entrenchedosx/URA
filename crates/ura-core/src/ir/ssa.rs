use super::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dominators {
    pub entry: Address,
    pub immediate: BTreeMap<Address, Address>,
    pub children: BTreeMap<Address, Vec<Address>>,
    pub frontiers: BTreeMap<Address, Vec<Address>>,
    pub unreachable: Vec<Address>,
    pub preorder: BTreeMap<Address, usize>,
    pub postorder: BTreeMap<Address, usize>,
}
impl Dominators {
    pub fn dominates(&self, a: Address, b: Address) -> bool {
        match (
            self.preorder.get(&a),
            self.preorder.get(&b),
            self.postorder.get(&a),
            self.postorder.get(&b),
        ) {
            (Some(a0), Some(b0), Some(a1), Some(b1)) => a0 <= b0 && a1 >= b1,
            _ => false,
        }
    }
}

/// Cooper-style reverse-postorder iteration; no dense N×N dominator matrix.
pub fn dominators(f: &Function) -> Result<Dominators, String> {
    dominators_controlled(f, &())
}
fn dominators_controlled(
    f: &Function,
    control: &dyn crate::AnalysisControl,
) -> Result<Dominators, String> {
    if control.is_cancelled() {
        return Err("dominator analysis cancelled".into());
    }
    verify(f).map_err(|e| e.join("; "))?;
    let by_address: BTreeMap<_, _> = f.blocks.iter().map(|b| (b.address, b)).collect();
    let mut seen = BTreeSet::new();
    let mut post = Vec::new();
    let mut todo = vec![(f.entry, false)];
    while let Some((address, exit)) = todo.pop() {
        if exit {
            post.push(address);
            continue;
        }
        if !seen.insert(address) {
            continue;
        }
        todo.push((address, true));
        for s in by_address[&address].terminator.successors.iter().rev() {
            if !seen.contains(s) {
                todo.push((*s, false));
            }
        }
    }
    post.reverse();
    let order: BTreeMap<_, _> = post.iter().enumerate().map(|(i, b)| (*b, i)).collect();
    let predecessors = f.predecessors();
    let mut idom = BTreeMap::from([(f.entry, f.entry)]);
    let intersect = |mut a: Address, mut b: Address, parents: &BTreeMap<Address, Address>| {
        while a != b {
            while order[&a] > order[&b] {
                a = parents[&a];
            }
            while order[&b] > order[&a] {
                b = parents[&b];
            }
        }
        a
    };
    let mut changed = true;
    let mut rounds = 0;
    while changed {
        if control.is_cancelled() {
            return Err("dominator analysis cancelled".into());
        }
        changed = false;
        rounds += 1;
        if rounds > f.blocks.len() + 1 {
            return Err("dominator convergence budget exceeded".into());
        }
        for block in post.iter().skip(1) {
            let mut incoming = predecessors[block].iter().filter(|p| idom.contains_key(p));
            let Some(first) = incoming.next() else {
                continue;
            };
            let mut parent = *first;
            for p in incoming {
                parent = intersect(parent, *p, &idom);
            }
            if idom.get(block) != Some(&parent) {
                idom.insert(*block, parent);
                changed = true;
            }
        }
    }
    let mut children: BTreeMap<_, Vec<_>> = post.iter().map(|b| (*b, vec![])).collect();
    for (b, p) in &idom {
        if b != p {
            children.get_mut(p).unwrap().push(*b);
        }
    }
    let mut frontiers: BTreeMap<_, BTreeSet<_>> =
        post.iter().map(|b| (*b, BTreeSet::new())).collect();
    for b in &post {
        let incoming: Vec<_> = predecessors[b]
            .iter()
            .filter(|p| seen.contains(p))
            .collect();
        if incoming.len() >= 2 {
            for p in incoming {
                let mut runner = *p;
                while runner != idom[b] {
                    frontiers.get_mut(&runner).unwrap().insert(*b);
                    let next = idom[&runner];
                    if next == runner {
                        break;
                    }
                    runner = next;
                }
            }
        }
    }
    // Include an entry self-loop in its dominance frontier. This is required
    // for a phi merging initial state and loop-carried definitions.
    if predecessors[&f.entry].iter().any(|p| seen.contains(p)) {
        for p in &predecessors[&f.entry] {
            if seen.contains(p) {
                let mut r = *p;
                loop {
                    frontiers.get_mut(&r).unwrap().insert(f.entry);
                    if r == f.entry {
                        break;
                    }
                    r = idom[&r];
                }
            }
        }
    }
    let (mut preorder, mut postorder) = (BTreeMap::new(), BTreeMap::new());
    let mut clock = 0;
    let mut stack = vec![(f.entry, false)];
    while let Some((b, exit)) = stack.pop() {
        clock += 1;
        if exit {
            postorder.insert(b, clock);
        } else {
            preorder.insert(b, clock);
            stack.push((b, true));
            for child in children[&b].iter().rev() {
                stack.push((*child, false));
            }
        }
    }
    Ok(Dominators {
        entry: f.entry,
        immediate: idom,
        children,
        frontiers: frontiers
            .into_iter()
            .map(|(b, s)| (b, s.into_iter().collect()))
            .collect(),
        unreachable: f
            .blocks
            .iter()
            .filter(|b| !seen.contains(&b.address))
            .map(|b| b.address)
            .collect(),
        preorder,
        postorder,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Value {
    pub variable: VariableId,
    pub version: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
pub enum Use {
    Value(Value),
    Constant(Constant),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phi {
    pub output: Value,
    pub incoming: BTreeMap<Address, Value>,
    pub initial: Option<Value>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SsaStatement {
    pub source: Address,
    pub output: Option<Value>,
    pub op: Operation,
    pub args: Vec<Use>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SsaTerminator {
    pub flow: Terminator,
    pub value: Option<Use>,
    pub state: Vec<Use>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SsaBlock {
    pub address: Address,
    pub end: Address,
    pub predecessors: Vec<Address>,
    pub phis: Vec<Phi>,
    pub statements: Vec<SsaStatement>,
    pub terminator: SsaTerminator,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsaFunction {
    pub ir_version: u32,
    pub entry: Address,
    pub address_width: u16,
    pub variables: Vec<Variable>,
    pub blocks: Vec<SsaBlock>,
    pub dominators: Dominators,
    pub omitted_unreachable: Vec<Address>,
}

pub fn construct(f: &Function) -> Result<SsaFunction, String> {
    construct_with_control(f, &())
}
pub fn construct_with_control(
    f: &Function,
    control: &dyn crate::AnalysisControl,
) -> Result<SsaFunction, String> {
    let dom = dominators_controlled(f, control)?;
    let predecessors = f.predecessors();
    let reachable: BTreeSet<_> = dom.immediate.keys().copied().collect();
    let mut blocks: Vec<_> = f
        .blocks
        .iter()
        .filter(|b| reachable.contains(&b.address))
        .map(|b| SsaBlock {
            address: b.address,
            end: b.end,
            predecessors: predecessors[&b.address]
                .iter()
                .copied()
                .filter(|p| reachable.contains(p))
                .collect(),
            phis: vec![],
            statements: vec![],
            terminator: SsaTerminator {
                flow: b.terminator.clone(),
                value: None,
                state: vec![],
            },
        })
        .collect();
    let index: BTreeMap<_, _> = blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.address, i))
        .collect();
    let source: BTreeMap<_, _> = f.blocks.iter().map(|b| (b.address, b)).collect();
    let mut defs: Vec<BTreeSet<Address>> = vec![BTreeSet::new(); f.variables.len()];
    for b in f.blocks.iter().filter(|b| reachable.contains(&b.address)) {
        for s in &b.statements {
            if let Some(v) = s.output {
                defs[v].insert(b.address);
            }
        }
    }
    // Architectural inputs are definitions at an implicit predecessor of entry.
    // Temporaries have one local definition and never need phi placement.
    let mut phi_count = 0usize;
    for (v, var) in f.variables.iter().enumerate() {
        if control.is_cancelled() {
            return Err("SSA construction cancelled".into());
        }
        if var.kind == VariableKind::Temporary || defs[v].is_empty() {
            continue;
        }
        let mut pending: VecDeque<_> = defs[v].iter().copied().collect();
        let mut placed = BTreeSet::new();
        while let Some(b) = pending.pop_front() {
            for frontier in &dom.frontiers[&b] {
                if placed.insert(*frontier) {
                    phi_count += 1;
                    if phi_count > MAX_IR_OPERATIONS {
                        return Err("SSA phi budget exceeded".into());
                    }
                    blocks[index[frontier]].phis.push(Phi {
                        output: Value {
                            variable: v,
                            version: 0,
                        },
                        incoming: BTreeMap::new(),
                        initial: None,
                    });
                    if !defs[v].contains(frontier) {
                        pending.push_back(*frontier);
                    }
                }
            }
        }
    }
    let mut stacks: Vec<Vec<Value>> = f
        .variables
        .iter()
        .enumerate()
        .map(|(v, var)| {
            if var.kind == VariableKind::Temporary {
                vec![]
            } else {
                vec![Value {
                    variable: v,
                    version: 0,
                }]
            }
        })
        .collect();
    let mut counters = vec![0u32; f.variables.len()];
    fn next(v: usize, counters: &mut [u32], stacks: &mut [Vec<Value>]) -> Value {
        counters[v] += 1;
        let value = Value {
            variable: v,
            version: counters[v],
        };
        stacks[v].push(value);
        value
    }
    fn rename(arg: Operand, stacks: &[Vec<Value>]) -> Result<Use, String> {
        match arg {
            Operand::Constant(c) => Ok(Use::Constant(c)),
            Operand::Variable(v) => stacks
                .get(v)
                .and_then(|s| s.last())
                .copied()
                .map(Use::Value)
                .ok_or_else(|| format!("SSA input v{v} is undefined")),
        }
    }
    let mut todo = vec![(f.entry, None::<Vec<usize>>)];
    let mut phi_inputs = 0usize;
    while let Some((address, undo)) = todo.pop() {
        if control.is_cancelled() {
            return Err("SSA construction cancelled".into());
        }
        if let Some(vars) = undo {
            for v in vars.into_iter().rev() {
                stacks[v].pop();
            }
            continue;
        }
        let i = index[&address];
        let mut pushed = Vec::new();
        for phi in &mut blocks[i].phis {
            let v = phi.output.variable;
            if address == f.entry {
                phi.initial = Some(Value {
                    variable: v,
                    version: 0,
                });
            }
            phi.output = next(v, &mut counters, &mut stacks);
            pushed.push(v);
        }
        for s in &source[&address].statements {
            let args = s
                .args
                .iter()
                .map(|a| rename(*a, &stacks))
                .collect::<Result<Vec<_>, _>>()?;
            let output = s.output.map(|v| {
                pushed.push(v);
                next(v, &mut counters, &mut stacks)
            });
            blocks[i].statements.push(SsaStatement {
                source: s.source,
                output,
                op: s.op.clone(),
                args,
            });
        }
        let flow = &source[&address].terminator;
        blocks[i].terminator.value = flow.value.map(|v| rename(v, &stacks)).transpose()?;
        blocks[i].terminator.state = flow
            .state
            .iter()
            .map(|v| rename(*v, &stacks))
            .collect::<Result<Vec<_>, _>>()?;
        for s in &flow.successors {
            for phi in &mut blocks[index[s]].phis {
                phi_inputs += 1;
                if phi_inputs > MAX_IR_OPERATIONS * 4 {
                    return Err("SSA phi input budget exceeded".into());
                }
                let value = *stacks[phi.output.variable]
                    .last()
                    .ok_or("undefined phi input")?;
                phi.incoming.insert(address, value);
            }
        }
        todo.push((address, Some(pushed)));
        for child in dom.children[&address].iter().rev() {
            todo.push((*child, None));
        }
    }
    let result = SsaFunction {
        ir_version: IR_VERSION,
        entry: f.entry,
        address_width: f.address_width,
        variables: f.variables.clone(),
        blocks,
        omitted_unreachable: dom.unreachable.clone(),
        dominators: dom,
    };
    verify_ssa(&result)?;
    Ok(result)
}

pub fn verify_ssa(f: &SsaFunction) -> Result<(), String> {
    if f.ir_version != IR_VERSION
        || !matches!(f.address_width, 32 | 64)
        || f.blocks.len() > MAX_IR_BLOCKS
        || f.variables.len() > MAX_IR_OPERATIONS + 64
        || f.blocks
            .iter()
            .map(|b| b.phis.len() + b.statements.len())
            .sum::<usize>()
            > MAX_IR_OPERATIONS + MAX_IR_BLOCKS * 32
    {
        return Err("invalid SSA version or resource budget".into());
    }
    for variable in &f.variables {
        if !variable.valid() {
            return Err("invalid SSA variable type".into());
        }
    }
    let mut definitions = BTreeMap::new();
    let index: BTreeMap<_, _> = f.blocks.iter().map(|b| (b.address, b)).collect();
    if index.len() != f.blocks.len() || !index.contains_key(&f.entry) {
        return Err("SSA block identity failure".into());
    }
    // Recompute dominance from the CFG: serialized analysis metadata is not a
    // proof of correctness. Dummy constants isolate graph validation from SSA.
    let graph = Function {
        ir_version: f.ir_version,
        entry: f.entry,
        address_width: f.address_width,
        variables: vec![Variable {
            name: "graph_state".into(),
            ty: Type::Bits(1),
            kind: VariableKind::Register,
        }],
        diagnostics: vec![],
        source_instructions: 0,
        blocks: f
            .blocks
            .iter()
            .map(|b| {
                let mut flow = b.terminator.flow.clone();
                flow.value = if flow.kind == FlowKind::Branch {
                    Some(Operand::Constant(Constant::bits(1, 0)))
                } else if flow.kind == FlowKind::Jump {
                    flow.value.map(|_| {
                        Operand::Constant(Constant {
                            ty: Type::Address(f.address_width),
                            value: flow
                                .successors
                                .first()
                                .or(flow.exits.first())
                                .copied()
                                .unwrap_or(Address(0)),
                        })
                    })
                } else {
                    flow.value.map(|_| {
                        Operand::Constant(Constant {
                            ty: Type::Address(f.address_width),
                            value: Address(0),
                        })
                    })
                };
                flow.state = vec![Operand::Variable(0)];
                Block {
                    address: b.address,
                    end: b.end,
                    function: f.entry,
                    statements: vec![],
                    terminator: flow,
                }
            })
            .collect(),
    };
    let mut actual_dom = dominators(&graph)?;
    if !actual_dom.unreachable.is_empty()
        || f.omitted_unreachable.iter().any(|b| index.contains_key(b))
        || f.omitted_unreachable
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != f.omitted_unreachable.len()
    {
        return Err("invalid SSA reachability metadata".into());
    }
    actual_dom.unreachable = f.omitted_unreachable.clone();
    if actual_dom != f.dominators {
        return Err("SSA dominator metadata disagrees with CFG".into());
    }
    let predecessors = graph.predecessors();
    for b in &f.blocks {
        if b.predecessors != predecessors[&b.address] {
            return Err("SSA predecessors disagree with CFG".into());
        }
        let mut phi_variables = BTreeSet::new();
        for phi in &b.phis {
            if !phi_variables.insert(phi.output.variable) {
                return Err("duplicate phi variable".into());
            }
            if phi.incoming.keys().copied().collect::<BTreeSet<_>>()
                != b.predecessors.iter().copied().collect()
            {
                return Err("phi predecessor set mismatch".into());
            }
            if definitions
                .insert(phi.output, (b.address, 0usize))
                .is_some()
            {
                return Err("SSA value defined twice".into());
            }
        }
        for (i, s) in b.statements.iter().enumerate() {
            if let Some(v) = s.output {
                if v.version == 0 || f.variables.get(v.variable).is_none() {
                    return Err("invalid SSA output".into());
                }
                if definitions.insert(v, (b.address, i + 1)).is_some() {
                    return Err("SSA value defined twice".into());
                }
            }
        }
    }
    let check = |v: Value, block: Address, position: usize| -> Result<(), String> {
        let variable = f.variables.get(v.variable).ok_or("SSA variable missing")?;
        if v.version == 0 {
            if variable.kind == VariableKind::Temporary {
                return Err("undefined temporary input".into());
            }
            return Ok(());
        }
        let (def_block, def_position) = definitions.get(&v).ok_or("SSA definition missing")?;
        if *def_block == block {
            if *def_position >= position {
                return Err("SSA use precedes definition".into());
            }
        } else if !f.dominators.dominates(*def_block, block) {
            return Err("SSA definition does not dominate use".into());
        }
        Ok(())
    };
    let ty = |u: Use| -> Option<Type> {
        match u {
            Use::Constant(c) => {
                if c.valid() {
                    Some(c.ty)
                } else {
                    None
                }
            }
            Use::Value(v) => f.variables.get(v.variable).map(|v| v.ty),
        }
    };
    let expected_state: BTreeSet<_> = f
        .variables
        .iter()
        .enumerate()
        .filter(|(_, v)| v.kind != VariableKind::Temporary)
        .map(|(i, _)| i)
        .collect();
    for b in &f.blocks {
        for phi in &b.phis {
            if phi.output.version == 0
                || f.variables
                    .get(phi.output.variable)
                    .map_or(true, |v| v.kind == VariableKind::Temporary)
            {
                return Err("invalid phi definition".into());
            }
            if (b.address == f.entry) != phi.initial.is_some() {
                return Err("invalid entry phi input".into());
            }
            if phi.initial.is_some_and(|v| {
                v != Value {
                    variable: phi.output.variable,
                    version: 0,
                }
            }) {
                return Err("invalid initial architectural input".into());
            }
            for (p, v) in &phi.incoming {
                if !index.contains_key(p) || v.variable != phi.output.variable {
                    return Err("invalid phi input".into());
                }
                check(*v, *p, usize::MAX)?;
            }
        }
        let mut previous = b.address;
        for (i, s) in b.statements.iter().enumerate() {
            if s.source < previous || s.source > b.terminator.flow.source {
                return Err("invalid SSA source provenance".into());
            }
            previous = s.source;
            for u in &s.args {
                if let Use::Value(v) = u {
                    check(*v, b.address, i + 1)?;
                }
            }
            let types: Option<Vec<_>> = s.args.iter().map(|u| ty(*u)).collect();
            if types.map_or(true, |args| {
                !super::verify::signature(
                    &s.op,
                    s.output
                        .and_then(|v| f.variables.get(v.variable).map(|v| v.ty)),
                    &args,
                )
            }) {
                return Err("SSA operation type mismatch".into());
            }
        }
        for u in b.terminator.state.iter().chain(b.terminator.value.iter()) {
            if let Use::Value(v) = u {
                check(*v, b.address, usize::MAX)?;
            }
        }
        let unversioned = |u: Use| match u {
            Use::Constant(c) => Operand::Constant(c),
            Use::Value(v) => Operand::Variable(v.variable),
        };
        if b.terminator.value.map(unversioned) != b.terminator.flow.value
            || b.terminator
                .state
                .iter()
                .copied()
                .map(unversioned)
                .collect::<Vec<_>>()
                != b.terminator.flow.state
        {
            return Err("SSA terminator mapping mismatch".into());
        }
        if b.terminator.state.iter().any(|u| ty(*u).is_none())
            || b.terminator.value.is_some_and(|u| ty(u).is_none())
        {
            return Err("invalid SSA terminator operand".into());
        }
        if b.terminator.flow.kind == FlowKind::Branch
            && b.terminator.value.and_then(ty) != Some(Type::Bits(1))
        {
            return Err("SSA branch requires boolean".into());
        }
        if b.terminator.flow.kind == FlowKind::Jump {
            if let Some(Use::Constant(c)) = b.terminator.value {
                if !b
                    .terminator
                    .flow
                    .successors
                    .iter()
                    .chain(&b.terminator.flow.exits)
                    .any(|a| a.0 == c.value.0)
                {
                    return Err("SSA constant jump target disagrees with CFG".into());
                }
            }
        }
        if matches!(
            b.terminator.flow.kind,
            FlowKind::Return | FlowKind::Indirect | FlowKind::Jump
        ) && b.terminator.value.is_some()
            && b.terminator.value.and_then(ty) != Some(Type::Address(f.address_width))
        {
            return Err("SSA transfer requires address".into());
        }
        if (b.terminator.flow.successors.is_empty() || !b.terminator.flow.exits.is_empty())
            && b.terminator.state.is_empty()
        {
            return Err("SSA exit state missing".into());
        }
        if b.terminator.flow.successors.is_empty()
            || !b.terminator.flow.exits.is_empty()
            || matches!(
                b.terminator.flow.kind,
                FlowKind::Return | FlowKind::Indirect | FlowKind::Unresolved
            )
        {
            let actual: Option<BTreeSet<_>> = b
                .terminator
                .state
                .iter()
                .map(|v| {
                    if let Use::Value(v) = v {
                        Some(v.variable)
                    } else {
                        None
                    }
                })
                .collect();
            if actual.as_ref() != Some(&expected_state)
                || b.terminator.state.len() != expected_state.len()
            {
                return Err("SSA exit state does not cover architectural variables".into());
            }
        }
    }
    Ok(())
}
