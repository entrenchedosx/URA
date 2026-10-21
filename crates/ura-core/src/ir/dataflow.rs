//! Conservative SSA def-use, constant propagation and dead definitions.
//! Results are reports; the source CFG and lifted program are never rewritten.
use super::{ssa::*, *};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
pub enum Lattice {
    Bottom,
    Constant(Constant),
    Unknown,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dataflow {
    pub constants: Vec<(Value, Constant)>,
    pub definitions: Vec<Definition>,
    pub proven_branches: BTreeMap<Address, bool>,
    pub dead_definitions: Vec<Value>,
    pub unknown_values: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Definition {
    pub value: Value,
    pub block: Address,
    pub source: Address,
    pub uses: usize,
}

pub fn analyze(f: &SsaFunction) -> Result<Dataflow, String> {
    analyze_with_control(f, &())
}
pub fn analyze_with_control(
    f: &SsaFunction,
    control: &dyn crate::AnalysisControl,
) -> Result<Dataflow, String> {
    if control.is_cancelled() {
        return Err("dataflow analysis cancelled".into());
    }
    verify_ssa(f)?;
    struct Node {
        output: Value,
        args: Vec<Use>,
        op: Option<Operation>,
        block: Address,
        source: Address,
        observable: bool,
    }
    let mut nodes = Vec::new();
    let mut roots = Vec::new();
    let mut extra_uses = BTreeMap::<Value, usize>::new();
    for b in &f.blocks {
        for phi in &b.phis {
            let args = phi
                .incoming
                .values()
                .copied()
                .chain(phi.initial)
                .map(Use::Value)
                .collect();
            nodes.push(Node {
                output: phi.output,
                args,
                op: None,
                block: b.address,
                source: b.address,
                observable: false,
            });
        }
        for s in &b.statements {
            if s.op.observable() {
                roots.extend(s.args.iter().copied());
            }
            if s.output.is_none() {
                for arg in &s.args {
                    if let Use::Value(v) = arg {
                        *extra_uses.entry(*v).or_default() += 1;
                    }
                }
            }
            if let Some(output) = s.output {
                nodes.push(Node {
                    output,
                    args: s.args.clone(),
                    op: Some(s.op.clone()),
                    block: b.address,
                    source: s.source,
                    observable: s.op.observable(),
                });
            }
        }
        roots.extend(b.terminator.state.iter().copied());
        roots.extend(b.terminator.value);
        for arg in b.terminator.state.iter().chain(b.terminator.value.iter()) {
            if let Use::Value(v) = arg {
                *extra_uses.entry(*v).or_default() += 1;
            }
        }
    }
    let definition: BTreeMap<_, _> = nodes
        .iter()
        .enumerate()
        .map(|(i, n)| (n.output, i))
        .collect();
    let mut users: BTreeMap<Value, Vec<usize>> = BTreeMap::new();
    for (i, n) in nodes.iter().enumerate() {
        for a in &n.args {
            if let Use::Value(v) = a {
                users.entry(*v).or_default().push(i);
            }
        }
    }
    let mut states = vec![Lattice::Bottom; nodes.len()];
    let value = |u: Use, states: &[Lattice]| match u {
        Use::Constant(c) => Lattice::Constant(c),
        Use::Value(v) => {
            if v.version == 0 {
                Lattice::Unknown
            } else {
                definition
                    .get(&v)
                    .map(|i| states[*i])
                    .unwrap_or(Lattice::Unknown)
            }
        }
    };
    fn join(a: Lattice, b: Lattice) -> Lattice {
        match (a, b) {
            (Lattice::Bottom, x) | (x, Lattice::Bottom) => x,
            (Lattice::Constant(a), Lattice::Constant(b)) if a == b => Lattice::Constant(a),
            _ => Lattice::Unknown,
        }
    }
    let mut pending: VecDeque<_> = (0..nodes.len()).collect();
    let mut queued = vec![true; nodes.len()];
    while let Some(i) = pending.pop_front() {
        if control.is_cancelled() {
            return Err("dataflow analysis cancelled".into());
        }
        queued[i] = false;
        let n = &nodes[i];
        let result = if let Some(op) = &n.op {
            if matches!(
                op,
                Operation::Unknown { .. } | Operation::Load | Operation::Store
            ) {
                Lattice::Unknown
            } else if matches!(op, Operation::Xor | Operation::Sub)
                && n.args.len() == 2
                && n.args[0] == n.args[1]
            {
                Lattice::Constant(Constant::bits(
                    f.variables[n.output.variable].ty.width().unwrap(),
                    0,
                ))
            } else {
                let args: Vec<_> = n.args.iter().map(|a| value(*a, &states)).collect();
                if args.contains(&Lattice::Unknown) {
                    Lattice::Unknown
                } else if args.contains(&Lattice::Bottom) {
                    Lattice::Bottom
                } else {
                    let constants: Vec<_> = args
                        .into_iter()
                        .filter_map(|v| {
                            if let Lattice::Constant(c) = v {
                                Some(c)
                            } else {
                                None
                            }
                        })
                        .collect();
                    super::evaluate::pure(op, f.variables[n.output.variable].ty, &constants)
                        .map(Lattice::Constant)
                        .unwrap_or(Lattice::Unknown)
                }
            }
        } else {
            n.args
                .iter()
                .fold(Lattice::Bottom, |a, b| join(a, value(*b, &states)))
        };
        let result = join(states[i], result);
        if result != states[i] {
            states[i] = result;
            for user in users.get(&n.output).into_iter().flatten() {
                if !queued[*user] {
                    pending.push_back(*user);
                    queued[*user] = true;
                }
            }
        }
    }
    let mut live = BTreeSet::new();
    let mut stack: Vec<_> = roots
        .into_iter()
        .filter_map(|u| if let Use::Value(v) = u { Some(v) } else { None })
        .collect();
    stack.extend(nodes.iter().filter(|n| n.observable).map(|n| n.output));
    while let Some(v) = stack.pop() {
        if control.is_cancelled() {
            return Err("dataflow analysis cancelled".into());
        }
        if !live.insert(v) {
            continue;
        }
        if let Some(i) = definition.get(&v) {
            stack.extend(nodes[*i].args.iter().filter_map(|a| {
                if let Use::Value(v) = a {
                    Some(*v)
                } else {
                    None
                }
            }));
        }
    }
    let constants = nodes
        .iter()
        .zip(&states)
        .filter_map(|(n, v)| {
            if let Lattice::Constant(c) = v {
                Some((n.output, *c))
            } else {
                None
            }
        })
        .collect();
    let dead_definitions = nodes
        .iter()
        .filter(|n| !n.observable && !live.contains(&n.output))
        .map(|n| n.output)
        .collect();
    let definitions = nodes
        .iter()
        .map(|n| Definition {
            value: n.output,
            block: n.block,
            source: n.source,
            uses: users.get(&n.output).map_or(0, Vec::len)
                + extra_uses.get(&n.output).copied().unwrap_or(0),
        })
        .collect();
    let mut proven_branches = BTreeMap::new();
    for b in &f.blocks {
        if b.terminator.flow.kind == FlowKind::Branch {
            if let Some(Lattice::Constant(c)) = b.terminator.value.map(|u| value(u, &states)) {
                proven_branches.insert(b.address, c.value.0 != 0);
            }
        }
    }
    Ok(Dataflow {
        constants,
        definitions,
        proven_branches,
        dead_definitions,
        unknown_values: states
            .iter()
            .filter(|v| !matches!(v, Lattice::Constant(_)))
            .count(),
    })
}
