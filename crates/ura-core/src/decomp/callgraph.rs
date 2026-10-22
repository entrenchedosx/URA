//! Bounded call-graph construction over the discovered function catalogue.
//!
//! Edges are the direct calls and tail calls already proven by analysis. The
//! graph never invents edges for unresolved indirect transfers; those are
//! counted and reported separately.
use crate::ProgramAnalysis;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_CALL_GRAPH_NODES: usize = 8_192;
pub const MAX_CALL_GRAPH_EDGES: usize = 20_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallGraphNode {
    pub address: u64,
    pub name: String,
    pub origin: String,
    pub external: bool,
    pub callers: usize,
    pub callees: usize,
    pub recursive: bool,
    pub component: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import: Option<ImportedTarget>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedTarget {
    pub binding: super::imports::ImportBinding,
    pub signature: Option<super::FunctionSignature>,
    pub uncertainty: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallGraphEdge {
    pub from: u64,
    pub to: u64,
    pub kind: String,
    pub instruction: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallGraph {
    pub nodes: Vec<CallGraphNode>,
    pub edges: Vec<CallGraphEdge>,
    pub cycles: Vec<Vec<u64>>,
    pub roots: Vec<u64>,
    pub leaves: Vec<u64>,
    pub unresolved_indirect: usize,
    pub truncated: bool,
    pub notes: Vec<String>,
}
impl CallGraph {
    pub fn node(&self, address: u64) -> Option<&CallGraphNode> {
        self.nodes.iter().find(|node| node.address == address)
    }
    pub fn callees(&self, address: u64) -> impl Iterator<Item = &CallGraphEdge> {
        self.edges.iter().filter(move |edge| edge.from == address)
    }
    pub fn callers(&self, address: u64) -> impl Iterator<Item = &CallGraphEdge> {
        self.edges.iter().filter(move |edge| edge.to == address)
    }
    pub fn path_exists(&self, from: u64, to: u64, max_depth: usize) -> bool {
        let mut seen = BTreeSet::new();
        let mut queue = std::collections::VecDeque::from([(from, 0usize)]);
        while let Some((current, depth)) = queue.pop_front() {
            if current == to {
                return true;
            }
            if depth >= max_depth || !seen.insert(current) {
                continue;
            }
            for edge in self.callees(current) {
                queue.push_back((edge.to, depth + 1));
            }
        }
        false
    }
}

pub fn build(analysis: &ProgramAnalysis) -> CallGraph {
    let mut functions = analysis.functions.iter().collect::<Vec<_>>();
    functions.sort_by_key(|function| function.address);
    let mut truncated = functions.len() > MAX_CALL_GRAPH_NODES;
    functions.truncate(MAX_CALL_GRAPH_NODES);
    let known: BTreeSet<u64> = functions.iter().map(|function| function.address).collect();
    let mut edges = Vec::new();
    let mut seen = BTreeSet::new();
    let mut unresolved_indirect = 0usize;
    // Preserve every actual call site. A function-pair edge alone loses repeated
    // calls and cannot support caller-side argument evidence or navigation.
    for xref in &analysis.xrefs {
        let Some(caller) = xref.function else {
            continue;
        };
        if xref.kind != crate::XrefKind::Call
            || !known.contains(&caller)
            || !known.contains(&xref.to)
        {
            continue;
        }
        if !seen.insert((caller, xref.to, xref.from, "call")) {
            continue;
        }
        if edges.len() == MAX_CALL_GRAPH_EDGES {
            truncated = true;
            break;
        }
        edges.push(CallGraphEdge {
            from: caller,
            to: xref.to,
            kind: "call".into(),
            instruction: Some(xref.from),
        });
    }
    for function in &functions {
        let facts = analysis.flow_facts(function);
        unresolved_indirect += facts.unresolved_indirect.len();
        unresolved_indirect += function
            .blocks
            .iter()
            .filter_map(|address| analysis.blocks.get(address))
            .flat_map(|block| &block.instructions)
            .filter_map(|address| analysis.instructions.get(address))
            .filter(|instruction| instruction.flow == crate::InstructionFlow::IndirectCall)
            .count();
        for (instruction, target) in &facts.tail_calls {
            if !known.contains(target) {
                continue;
            }
            if edges.len() == MAX_CALL_GRAPH_EDGES {
                truncated = true;
                break;
            }
            if seen.insert((function.address, *target, *instruction, "tail")) {
                edges.push(CallGraphEdge {
                    from: function.address,
                    to: *target,
                    kind: "tail".into(),
                    instruction: Some(*instruction),
                });
            }
        }
    }
    edges.sort_by_key(|edge| (edge.from, edge.to, edge.instruction, edge.kind.clone()));
    let mut adjacency: BTreeMap<u64, Vec<u64>> = functions
        .iter()
        .map(|function| (function.address, Vec::new()))
        .collect();
    for edge in &edges {
        adjacency
            .get_mut(&edge.from)
            .expect("known caller")
            .push(edge.to);
    }
    for targets in adjacency.values_mut() {
        targets.sort_unstable();
        targets.dedup();
    }
    let (component_of, cycles) = strongly_connected(&adjacency);
    let mut incoming: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for edge in &edges {
        incoming.entry(edge.to).or_default().insert(edge.from);
    }
    let mut nodes = Vec::with_capacity(functions.len());
    for function in &functions {
        let callers = incoming.get(&function.address).map_or(0, BTreeSet::len);
        let callees = adjacency[&function.address].len();
        let component = component_of.get(&function.address).copied();
        nodes.push(CallGraphNode {
            address: function.address,
            name: analysis
                .function_name(function.address)
                .unwrap_or_else(|| function.fallback_name()),
            origin: function.origin.name().to_string(),
            external: false,
            callers,
            callees,
            recursive: component.is_some(),
            component,
            import: None,
        });
    }
    let roots = nodes
        .iter()
        .filter(|node| node.callers == 0)
        .map(|node| node.address)
        .collect();
    let leaves = nodes
        .iter()
        .filter(|node| node.callees == 0)
        .map(|node| node.address)
        .collect();
    let mut notes = vec![
        "Only direct calls and direct tail calls become edges; unresolved indirect transfers are counted, not guessed."
            .into(),
    ];
    if truncated {
        notes.push(format!(
            "the call graph is limited to {MAX_CALL_GRAPH_NODES} functions and {MAX_CALL_GRAPH_EDGES} call sites"
        ));
    }
    if unresolved_indirect > 0 {
        notes.push(format!(
            "{unresolved_indirect} indirect transfer(s) could not be resolved to a callee"
        ));
    }
    CallGraph {
        nodes,
        edges,
        cycles,
        roots,
        leaves,
        unresolved_indirect,
        truncated,
        notes,
    }
}

/// Add only import relationships proved by an actual native-width, flat-memory
/// call/jump operand. Merely finding a symbol name never creates an edge.
pub fn build_with_imports(
    binary: &crate::LoadedBinary,
    analysis: &ProgramAnalysis,
    control: &dyn crate::AnalysisControl,
) -> Result<CallGraph, String> {
    let mut graph = build(analysis);
    let report = match super::imports::analyze_with_control(binary, control) {
        Ok(report) => report,
        Err(error) if control.is_cancelled() => return Err(error),
        Err(error) => {
            graph
                .notes
                .push(format!("external import recovery unavailable: {error}"));
            return Ok(graph);
        }
    };
    graph.truncated |= report.truncated;
    let imports: BTreeMap<_, _> = report
        .bindings
        .into_iter()
        .map(|binding| (binding.address.0, binding))
        .collect();
    if imports.is_empty() {
        return Ok(graph);
    }
    let internal: BTreeSet<_> = graph.nodes.iter().map(|node| node.address).collect();
    let mut external = BTreeSet::new();
    let mut resolved = BTreeSet::new();
    let mut examined = 0;
    let mut lifted_sites: BTreeMap<u64, BTreeMap<u64, u64>> = BTreeMap::new();
    let mut lifted_operations = 0usize;
    for function in analysis
        .functions
        .iter()
        .filter(|function| internal.contains(&function.address))
    {
        if control.is_cancelled() {
            return Err("external call graph cancelled".into());
        }
        for instruction in function
            .blocks
            .iter()
            .filter_map(|address| analysis.blocks.get(address))
            .flat_map(|block| &block.instructions)
            .filter_map(|address| analysis.instructions.get(address))
        {
            examined += 1;
            if examined > 200_000 {
                graph.truncated = true;
                break;
            }
            if !matches!(
                instruction.flow,
                crate::InstructionFlow::IndirectCall | crate::InstructionFlow::IndirectJump
            ) || resolved.contains(&instruction.address)
            {
                continue;
            }
            let slot = operand_slot(binary, instruction).or_else(|| {
                if instruction.flow != crate::InstructionFlow::IndirectCall {
                    return None;
                }
                if !lifted_sites.contains_key(&function.address) {
                    if lifted_sites.len() == 16 || lifted_operations >= crate::ir::MAX_IR_OPERATIONS
                    {
                        graph.truncated = true;
                        return None;
                    }
                    let mut sites = BTreeMap::new();
                    match crate::ir::inspect::analyze(binary, analysis, function.address, control) {
                        Ok(bundle) => {
                            let count = bundle
                                .ssa
                                .blocks
                                .iter()
                                .map(|block| block.statements.len())
                                .sum::<usize>();
                            if lifted_operations + count <= crate::ir::MAX_IR_OPERATIONS {
                                lifted_operations += count;
                                let constants = bundle.dataflow.constants.iter().copied().collect();
                                for block in &bundle.ssa.blocks {
                                    for statement in block.statements.iter().filter(|statement| {
                                        statement.op == crate::ir::Operation::Call
                                    }) {
                                        if let Some(slot) = super::imports::slot_for_call(
                                            block, statement, &constants,
                                        )
                                        .filter(|slot| imports.contains_key(slot))
                                        {
                                            sites.insert(statement.source.0, slot);
                                        }
                                    }
                                }
                            } else {
                                graph.truncated = true;
                            }
                        }
                        Err(_) => {
                            graph.truncated = true;
                        }
                    }
                    lifted_sites.insert(function.address, sites);
                }
                lifted_sites
                    .get(&function.address)
                    .and_then(|sites| sites.get(&instruction.address))
                    .copied()
            });
            if control.is_cancelled() {
                return Err("external call graph cancelled".into());
            }
            let Some(slot) = slot else {
                continue;
            };
            let Some(binding) = imports.get(&slot) else {
                continue;
            };
            if internal.contains(&slot) {
                graph.notes.push(format!(
                    "import slot {} collides with an internal function; no external edge was added",
                    binding.address
                ));
                continue;
            }
            if graph.edges.len() == MAX_CALL_GRAPH_EDGES
                || graph.nodes.len() == MAX_CALL_GRAPH_NODES
            {
                graph.truncated = true;
                continue;
            }
            if external.insert(slot) {
                graph.nodes.push(CallGraphNode { address:slot, name:binding.library.as_ref().map_or_else(||binding.name.clone(),|library|format!("{library}!{}",binding.name)),origin:binding.method.clone(),external:true,callers:0,callees:0,recursive:false,component:None,import:Some(ImportedTarget { binding:binding.clone(),signature:super::imports::prototype(binary,binding),uncertainty:"Import identity is resolved; runtime interposition, library behavior and unsupported ABI details remain unknown.".into() }) });
            }
            let kind = if instruction.flow == crate::InstructionFlow::IndirectCall {
                "importCall"
            } else if function.instruction_count == 1 {
                "importThunk"
            } else {
                "importTail"
            };
            graph.edges.push(CallGraphEdge {
                from: function.address,
                to: slot,
                kind: kind.into(),
                instruction: Some(instruction.address),
            });
            resolved.insert(instruction.address);
        }
        if examined > 200_000 {
            break;
        }
    }
    graph.unresolved_indirect = graph.unresolved_indirect.saturating_sub(resolved.len());
    graph.nodes.sort_by_key(|node| node.address);
    graph
        .edges
        .sort_by_key(|edge| (edge.from, edge.to, edge.instruction));
    let mut incoming: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    let mut outgoing: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for edge in &graph.edges {
        incoming.entry(edge.to).or_default().insert(edge.from);
        outgoing.entry(edge.from).or_default().insert(edge.to);
    }
    for node in &mut graph.nodes {
        node.callers = incoming.get(&node.address).map_or(0, BTreeSet::len);
        node.callees = outgoing.get(&node.address).map_or(0, BTreeSet::len);
    }
    graph.roots = graph
        .nodes
        .iter()
        .filter(|node| node.callers == 0)
        .map(|node| node.address)
        .collect();
    graph.leaves = graph
        .nodes
        .iter()
        .filter(|node| node.callees == 0)
        .map(|node| node.address)
        .collect();
    graph.notes[0]="Internal direct/tail calls and exact import-slot memory calls/jumps become edges. Callers of an import thunk retain the internal edge; the thunk has its own external edge. Unproved indirect transfers remain unresolved.".into();
    Ok(graph)
}

fn operand_slot(
    binary: &crate::LoadedBinary,
    instruction: &crate::DecodedInstruction,
) -> Option<u64> {
    use iced_x86::{Decoder, DecoderOptions, OpKind, Register};
    let bytes = binary.bytes_at_address(instruction.address, usize::from(instruction.length))?;
    let decoded = Decoder::with_ip(
        u32::from(binary.analysis().bitness),
        bytes,
        instruction.address,
        DecoderOptions::NONE,
    )
    .decode();
    if decoded.is_invalid()
        || decoded.op0_kind() != OpKind::Memory
        || decoded.memory_index() != Register::None
        || matches!(decoded.segment_prefix(), Register::FS | Register::GS)
    {
        return None;
    }
    if decoded.memory_size().size() * 8 != usize::from(binary.analysis().bitness) {
        return None;
    }
    if decoded.is_ip_rel_memory_operand() {
        Some(decoded.ip_rel_memory_address())
    } else if decoded.memory_base() == Register::None {
        Some(decoded.memory_displacement64())
    } else {
        None
    }
}

pub(crate) fn hydrate_thunks(
    binary: &crate::LoadedBinary,
    analysis: &ProgramAnalysis,
    hints: &mut super::SignatureHints,
    control: &dyn crate::AnalysisControl,
) -> Result<usize, String> {
    let mut count = 0;
    for function in analysis
        .functions
        .iter()
        .filter(|function| function.instruction_count == 1)
    {
        if control.is_cancelled() {
            return Err("import thunk recovery cancelled".into());
        }
        if hints.get(function.address).is_some() {
            continue;
        }
        let instruction = function
            .blocks
            .first()
            .and_then(|block| analysis.blocks.get(block))
            .and_then(|block| block.instructions.first())
            .and_then(|address| analysis.instructions.get(address));
        let Some(instruction) = instruction
            .filter(|instruction| instruction.flow == crate::InstructionFlow::IndirectJump)
        else {
            continue;
        };
        let Some(slot) = operand_slot(binary, instruction) else {
            continue;
        };
        let Some(mut signature) = hints.get(slot).cloned() else {
            continue;
        };
        if !signature
            .evidence
            .iter()
            .any(|evidence| evidence.kind == "curatedApiPrototype")
        {
            continue;
        }
        signature.function = function.address;
        signature.evidence.push(super::signature::Evidence {
            kind: "verifiedImportThunk".into(),
            address: Some(instruction.address),
            detail: format!(
                "native memory jump through bound import slot {}",
                crate::format_address(slot)
            ),
        });
        hints.insert(signature);
        count += 1;
    }
    Ok(count)
}

/// Iterative Kosaraju. Components are only reported when they contain a cycle.
fn strongly_connected(
    adjacency: &BTreeMap<u64, Vec<u64>>,
) -> (BTreeMap<u64, usize>, Vec<Vec<u64>>) {
    let mut visited = BTreeSet::new();
    let mut order = Vec::new();
    for start in adjacency.keys().copied() {
        if !visited.insert(start) {
            continue;
        }
        let mut stack = vec![(start, 0usize)];
        while let Some((node, index)) = stack.pop() {
            let targets = &adjacency[&node];
            if index < targets.len() {
                stack.push((node, index + 1));
                let next = targets[index];
                if visited.insert(next) {
                    stack.push((next, 0));
                }
            } else {
                order.push(node);
            }
        }
    }
    let mut reverse: BTreeMap<u64, Vec<u64>> = adjacency.keys().map(|key| (*key, vec![])).collect();
    for (from, targets) in adjacency {
        for to in targets {
            reverse.get_mut(to).expect("known target").push(*from);
        }
    }
    let mut assigned = BTreeSet::new();
    let mut component_of = BTreeMap::new();
    let mut cycles = Vec::new();
    let mut component = 0usize;
    for start in order.into_iter().rev() {
        if !assigned.insert(start) {
            continue;
        }
        let mut members = Vec::new();
        let mut stack = vec![start];
        while let Some(node) = stack.pop() {
            members.push(node);
            for next in &reverse[&node] {
                if assigned.insert(*next) {
                    stack.push(*next);
                }
            }
        }
        members.sort_unstable();
        let cyclic = members.len() > 1 || adjacency[&members[0]].contains(&members[0]);
        if cyclic {
            component_of.insert(members[0], component);
            for member in &members[1..] {
                component_of.insert(*member, component);
            }
            cycles.push(members);
            component += 1;
        }
    }
    cycles.sort_by_key(|cycle| cycle[0]);
    (component_of, cycles)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scc_reports_cycles_self_loops_and_excludes_acyclic_nodes() {
        let adjacency = BTreeMap::from([
            (1u64, vec![2u64]),
            (2, vec![3]),
            (3, vec![2]),
            (4, vec![4]),
            (5, vec![]),
            (6, vec![5]),
        ]);
        let (components, cycles) = strongly_connected(&adjacency);
        assert_eq!(cycles, vec![vec![2, 3], vec![4]]);
        assert_eq!(components.get(&2), components.get(&3));
        assert!(!components.contains_key(&1));
        assert!(!components.contains_key(&5));
        assert!(!components.contains_key(&6));
    }

    #[test]
    fn path_queries_respect_depth_and_missing_edges() {
        let graph = CallGraph {
            nodes: vec![],
            edges: vec![
                CallGraphEdge {
                    from: 16,
                    to: 32,
                    kind: "call".into(),
                    instruction: Some(20),
                },
                CallGraphEdge {
                    from: 32,
                    to: 48,
                    kind: "tail".into(),
                    instruction: Some(36),
                },
            ],
            cycles: vec![],
            roots: vec![16],
            leaves: vec![48],
            unresolved_indirect: 0,
            truncated: false,
            notes: vec![],
        };
        assert!(graph.path_exists(16, 48, 2));
        assert!(!graph.path_exists(16, 48, 1));
        assert!(!graph.path_exists(48, 16, 8));
        assert!(graph.callees(16).any(|edge| edge.to == 32));
        assert!(graph.callers(48).any(|edge| edge.from == 32));
    }
}
