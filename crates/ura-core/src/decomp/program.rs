//! Bounded, monotone propagation of supplied parameter types through exact
//! native-width register arguments. This is a backward demand solver: it does
//! not infer a parameter merely because a machine register exists at a call.
//! Return consumers, stack arguments and width-changing transfers remain unknown.
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use super::abi::SignatureHints;
use super::signature::{CallingConvention, Evidence, FunctionSignature, Location, Parameter};
use super::types::{Confidence, TypeRef};
use crate::ir::inspect::{self, Bundle};
use crate::ir::ssa::{SsaFunction, Use, Value};
use crate::ir::{Address, Operation, VariableKind};
use crate::{AnalysisControl, LoadedBinary, ProgramAnalysis};

pub const MAX_FUNCTIONS: usize = 16;
pub const MAX_OPERATIONS: usize = 80_000;
pub const MAX_EDGES: usize = 1_024;
const MAX_NODES: usize = 512;
const MAX_TYPES: usize = 4;
const MAX_UPDATES: usize = 8_192;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParameterKey {
    pub function: Address,
    pub register: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArgumentEdge {
    pub caller: ParameterKey,
    pub callee: ParameterKey,
    pub instruction: Address,
    /// Actual SSA value passed at this site, before following exact copies.
    pub argument: Value,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeClaim {
    pub ty: TypeRef,
    pub origin: ParameterKey,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParameterFacts {
    pub claims: Vec<TypeClaim>,
    /// Absorbing top once distinct types exceed the retained-claim bound.
    pub overdefined: bool,
}
impl ParameterFacts {
    pub fn conflicting(&self) -> bool {
        self.overdefined || self.claims.len() > 1
    }
    fn merge(&mut self, incoming: &Self) -> bool {
        let before = (self.claims.len(), self.overdefined);
        if self.overdefined {
            return false;
        }
        for claim in &incoming.claims {
            if self.claims.iter().any(|known| known.ty == claim.ty) {
                continue;
            }
            if self.claims.len() == MAX_TYPES {
                self.overdefined = true;
                break;
            }
            self.claims.push(claim.clone());
        }
        self.overdefined |= incoming.overdefined;
        before != (self.claims.len(), self.overdefined)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParameterResult {
    pub parameter: ParameterKey,
    pub facts: ParameterFacts,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgramTypes {
    pub functions: Vec<Address>,
    pub edges: Vec<ArgumentEdge>,
    pub parameters: Vec<ParameterResult>,
    pub updates: usize,
    pub converged: bool,
    pub truncated: bool,
    pub notes: Vec<String>,
    #[serde(default)]
    pub flow: super::flow::FlowReport,
}
impl ProgramTypes {
    /// Bounded transport projection, not a change to the retained analysis.
    pub fn protocol_view(&self, function: u64) -> Self {
        let facts: Vec<_> = self
            .flow
            .facts
            .iter()
            .filter(|result| {
                !matches!(result.key, super::flow::Key::Value { .. })
                    || (result.key.function() == function && !result.facts.claims.is_empty())
            })
            .take(256)
            .cloned()
            .collect();
        let omitted = facts.len() < self.flow.facts.len()
            || self.edges.len() > 256
            || self.parameters.len() > 128
            || self.flow.calls.len() > 64;
        let mut notes = self.notes.clone();
        if omitted {
            notes.push(format!("Transport view omits details: {} total flow facts, {} total argument edges, {} total call sites. Fetch a semantic block for exact SSA types/provenance.",self.flow.facts.len(),self.edges.len(),self.flow.calls.len()));
        }
        Self {
            functions: self.functions.clone(),
            edges: self.edges.iter().take(256).cloned().collect(),
            parameters: self.parameters.iter().take(128).cloned().collect(),
            updates: self.updates,
            converged: self.converged,
            truncated: self.truncated,
            notes,
            flow: super::flow::FlowReport {
                facts,
                calls: self.flow.calls.iter().take(64).cloned().collect(),
                updates: self.flow.updates,
                converged: self.flow.converged,
                truncated: self.flow.truncated,
                notes: self.flow.notes.clone(),
                total_facts: self.flow.facts.len(),
                facts_omitted: omitted,
            },
        }
    }
}

fn check(control: &dyn AnalysisControl) -> Result<(), String> {
    if control.is_cancelled() {
        Err("interprocedural analysis cancelled".into())
    } else {
        Ok(())
    }
}

/// Deterministic sorted worklist. Facts only accumulate; recursive SCCs need
/// no special iteration order. Unknown cycles without a seed stay unknown.
fn fixed_point(
    edges: &[ArgumentEdge],
    mut facts: BTreeMap<ParameterKey, ParameterFacts>,
    control: &dyn AnalysisControl,
) -> Result<(BTreeMap<ParameterKey, ParameterFacts>, usize, bool), String> {
    let mut dependents: BTreeMap<ParameterKey, BTreeSet<ParameterKey>> = BTreeMap::new();
    for edge in edges {
        dependents
            .entry(edge.callee.clone())
            .or_default()
            .insert(edge.caller.clone());
    }
    let mut queue: BTreeSet<_> = facts.keys().cloned().collect();
    let mut updates = 0;
    while let Some(current) = queue.pop_first() {
        check(control)?;
        let incoming = facts[&current].clone();
        for dependent in dependents.get(&current).into_iter().flatten() {
            if updates == MAX_UPDATES {
                return Ok((facts, updates, false));
            }
            if facts.entry(dependent.clone()).or_default().merge(&incoming) {
                updates += 1;
                queue.insert(dependent.clone());
            }
        }
    }
    Ok((facts, updates, true))
}

fn entry_root(
    ssa: &SsaFunction,
    mut value: Value,
    definitions: &BTreeMap<Value, &crate::ir::ssa::SsaStatement>,
) -> Option<Value> {
    for _ in 0..16 {
        if value.version == 0 {
            return (ssa.variables.get(value.variable)?.kind == VariableKind::Register)
                .then_some(value);
        }
        let definition = definitions.get(&value)?;
        if definition.op != Operation::Copy {
            return None;
        }
        let Some(Use::Value(input)) = definition.args.first() else {
            return None;
        };
        if ssa.variables.get(value.variable)?.ty != ssa.variables.get(input.variable)?.ty {
            return None;
        }
        value = *input;
    }
    None
}

pub fn enrich(
    binary: &LoadedBinary,
    analysis: &ProgramAnalysis,
    entry: &Bundle,
    hints: &mut SignatureHints,
    control: &dyn AnalysisControl,
) -> Result<ProgramTypes, String> {
    check(control)?;
    let mut report = ProgramTypes::default();
    report.notes.push("Exact-copy parameter demands and combined SSA argument/return constraints use a bounded scope. Container ABI defaults remain assumptions; convergence is not whole-program coverage.".into());
    if entry.ssa.address_width != 64 || !matches!(binary.analysis().format.as_str(), "PE" | "ELF") {
        report.converged = true;
        report
            .notes
            .push("Cross-function propagation currently supports PE/ELF x86-64 only.".into());
        return Ok(report);
    }
    let default = if binary.analysis().format == "PE" {
        CallingConvention::Win64
    } else {
        CallingConvention::SysV64
    };
    let mut bodies = BTreeMap::from([(entry.ssa.entry.0, Cow::Borrowed(entry))]);
    let mut queue = VecDeque::from([entry.ssa.entry.0]);
    let mut operations: usize = entry.ssa.blocks.iter().map(|b| b.statements.len()).sum();
    let mut examined = BTreeSet::from([entry.ssa.entry.0]);
    while let Some(address) = queue.pop_front() {
        check(control)?;
        let targets: BTreeSet<_> = bodies[&address]
            .ssa
            .blocks
            .iter()
            .flat_map(|b| &b.statements)
            .filter(|s| s.op == Operation::Call)
            .filter_map(|s| match s.args.first() {
                Some(Use::Constant(c)) => Some(c.value.0),
                _ => None,
            })
            .collect();
        for target in targets {
            if !examined.insert(target) || !analysis.functions.iter().any(|f| f.address == target) {
                continue;
            }
            if bodies.len() == MAX_FUNCTIONS {
                report.truncated = true;
                continue;
            }
            match inspect::analyze(binary, analysis, target, control) {
                Ok(bundle) => {
                    let count: usize = bundle.ssa.blocks.iter().map(|b| b.statements.len()).sum();
                    if operations + count > MAX_OPERATIONS {
                        report.truncated = true;
                        continue;
                    }
                    operations += count;
                    bodies.insert(target, Cow::Owned(bundle));
                    queue.push_back(target);
                }
                Err(error) => {
                    check(control)?;
                    report.truncated = true;
                    if report.notes.len() < 10 {
                        report
                            .notes
                            .push(format!("{} was not included: {error}", Address(target)));
                    }
                }
            }
        }
    }
    report.functions = bodies.keys().copied().map(Address).collect();
    let mut nodes = BTreeSet::new();
    'functions: for (&function, bundle) in &bodies {
        let caller_convention = hints.get(function).map_or(default, |s| s.convention);
        let caller_registers = caller_convention.argument_registers(64);
        let definitions: BTreeMap<_, _> = bundle
            .ssa
            .blocks
            .iter()
            .flat_map(|b| &b.statements)
            .filter_map(|s| s.output.map(|v| (v, s)))
            .collect();
        let constants = bundle.dataflow.constants.iter().copied().collect();
        for block in &bundle.ssa.blocks {
            check(control)?;
            for call in block.statements.iter().filter(|s| s.op == Operation::Call) {
                let target = match call.args.first() {
                    Some(Use::Constant(c)) => Some(c.value.0),
                    _ => super::imports::slot_for_call(block, call, &constants),
                };
                let Some(target) = target else { continue };
                if !bodies.contains_key(&target) && hints.get(target).is_none() {
                    continue;
                }
                let callee_convention = hints.get(target).map_or(default, |s| s.convention);
                for &register in callee_convention.argument_registers(64) {
                    let Some(index) = bundle
                        .ssa
                        .variables
                        .iter()
                        .position(|v| v.kind == VariableKind::Register && v.name == register)
                    else {
                        continue;
                    };
                    let Some(Use::Value(argument)) = call.args.get(1 + index) else {
                        continue;
                    };
                    let Some(root) = entry_root(&bundle.ssa, *argument, &definitions) else {
                        continue;
                    };
                    let variable = &bundle.ssa.variables[root.variable];
                    if variable.ty.width() != Some(64)
                        || !caller_registers.contains(&variable.name.as_str())
                    {
                        continue;
                    }
                    let edge = ArgumentEdge {
                        caller: ParameterKey {
                            function: Address(function),
                            register: variable.name.clone(),
                        },
                        callee: ParameterKey {
                            function: Address(target),
                            register: register.into(),
                        },
                        instruction: call.source,
                        argument: *argument,
                    };
                    if report.edges.len() == MAX_EDGES || nodes.len() + 2 > MAX_NODES {
                        report.truncated = true;
                        break 'functions;
                    }
                    nodes.insert(edge.caller.clone());
                    nodes.insert(edge.callee.clone());
                    report.edges.push(edge);
                }
            }
        }
    }
    let database = super::types::TypeDatabase::new(64);
    let mut facts = BTreeMap::new();
    for node in nodes {
        let Some(signature) = hints.get(node.function.0) else {
            continue;
        };
        let mut value = ParameterFacts::default();
        for parameter in &signature.parameters {
            if parameter.location
                != (Location::Register {
                    name: node.register.clone(),
                })
                || parameter.confidence == Confidence::Unknown
                || matches!(parameter.ty, TypeRef::Unknown { .. })
                || parameter.ty.bits(&database) != Some(64)
            {
                continue;
            }
            if !super::flow::supported_type(&parameter.ty) {
                report.truncated = true;
                continue;
            }
            value.merge(&ParameterFacts {
                claims: vec![TypeClaim {
                    ty: parameter.ty.clone(),
                    origin: node.clone(),
                }],
                overdefined: false,
            });
        }
        if !value.claims.is_empty() {
            facts.insert(node, value);
        }
    }
    let (facts, updates, converged) = fixed_point(&report.edges, facts, control)?;
    report.updates = updates;
    report.converged = converged;
    report.truncated |= !converged;
    report.parameters = facts
        .into_iter()
        .map(|(parameter, facts)| ParameterResult { parameter, facts })
        .collect();
    report.flow = super::flow::solve(&bodies, hints, default, &report.edges, control)?;
    report.converged &= report.flow.converged;
    report.truncated |= report.flow.truncated;
    // No provisional facts escape if the update budget prevented convergence.
    if report.converged {
        let mut recovered = BTreeMap::new();
        for result in &report.parameters {
            let function = result.parameter.function.0;
            if hints.get(function).is_some() {
                continue;
            } // explicit assertions retain precedence
            let Some(bundle) = bodies.get(&function) else {
                continue;
            };
            if let std::collections::btree_map::Entry::Vacant(slot) = recovered.entry(function) {
                let frame =
                    super::stack::recover_with_control(binary, analysis, function, None, control)?;
                slot.insert(
                    super::abi::recover_with_control(
                        binary, analysis, bundle, &frame, hints, control,
                    )?
                    .signature,
                );
            }
            apply_fact(recovered.get_mut(&function).unwrap(), result, &report.edges);
        }
        for function in report
            .flow
            .facts
            .iter()
            .filter(|result| {
                !matches!(result.key, super::flow::Key::Value { .. })
                    && (result.facts.resolved().is_some() || result.facts.conflicting())
            })
            .map(|result| result.key.function())
            .collect::<BTreeSet<_>>()
        {
            if hints.get(function).is_some() || recovered.contains_key(&function) {
                continue;
            }
            let Some(bundle) = bodies.get(&function) else {
                continue;
            };
            let frame =
                super::stack::recover_with_control(binary, analysis, function, None, control)?;
            recovered.insert(
                function,
                super::abi::recover_with_control(binary, analysis, bundle, &frame, hints, control)?
                    .signature,
            );
        }
        for signature in recovered.values_mut() {
            super::flow::apply(signature, &report.flow);
        }
        for (_, signature) in recovered {
            hints.insert(signature);
        }
    }
    if report.truncated {
        report.notes.push("Program scope or work budget was reached; results do not describe the complete binary.".into());
    }
    Ok(report)
}

fn apply_fact(signature: &mut FunctionSignature, result: &ParameterResult, edges: &[ArgumentEdge]) {
    let Some(index) = signature
        .convention
        .argument_registers(64)
        .iter()
        .position(|r| *r == result.parameter.register)
    else {
        return;
    };
    if result.facts.claims.is_empty() && !result.facts.overdefined {
        return;
    }
    let conflict = result.facts.conflicting();
    let ty = if conflict {
        TypeRef::unknown(Some(64), "conflicting interprocedural parameter demands")
    } else {
        result.facts.claims[0].ty.clone()
    };
    let sites: Vec<_> = edges
        .iter()
        .filter(|edge| edge.caller == result.parameter)
        .map(|edge| edge.instruction.0)
        .collect();
    let evidence = Evidence {
        kind: "interproceduralParameterDemand".into(),
        address: sites.first().copied(),
        detail: format!(
            "{} exact register-copy call site(s); {} distinct supplied type(s)",
            sites.len(),
            result.facts.claims.len()
        ),
    };
    let parameter = Parameter {
        index,
        name: format!("a{index}"),
        location: Location::Register {
            name: result.parameter.register.clone(),
        },
        ty,
        width: 64,
        confidence: if conflict {
            Confidence::Unknown
        } else {
            Confidence::Medium
        },
        uses: sites.len(),
        evidence: vec![evidence],
    };
    if let Some(existing) = signature.parameters.iter_mut().find(|p| p.index == index) {
        // A supported demand must not erase conflicting/unsupported local
        // evidence (for example another callee expecting a narrower type).
        if existing.uses > 0 && existing.confidence == Confidence::Unknown {
            existing.evidence.extend(parameter.evidence);
        } else {
            *existing = parameter;
        }
    } else {
        signature.parameters.push(parameter);
    }
    for missing in 0..index {
        if !signature.parameters.iter().any(|p| p.index == missing) {
            signature.parameters.push(Parameter {
                index: missing,
                name: format!("a{missing}"),
                location: Location::Unknown {
                    reason: "unobserved ABI slot".into(),
                },
                ty: TypeRef::unknown(None, "parameter slot is never read"),
                width: 0,
                confidence: Confidence::Unknown,
                uses: 0,
                evidence: vec![],
            });
        }
    }
    signature.parameters.sort_by_key(|p| p.index);
    if conflict {
        signature.conflicts.push(format!(
            "{} has conflicting interprocedural parameter demands",
            result.parameter.register
        ));
    }
}

pub fn apply_to_signature(signature: &mut FunctionSignature, report: &ProgramTypes) {
    if !report.converged {
        return;
    }
    for result in &report.parameters {
        if result.parameter.function.0 == signature.function {
            apply_fact(signature, result, &report.edges);
        }
    }
    super::flow::apply(signature, &report.flow);
}

#[cfg(test)]
mod tests {
    use super::*;
    fn node(function: u64) -> ParameterKey {
        ParameterKey {
            function: Address(function),
            register: "rcx".into(),
        }
    }
    fn edge(caller: u64, callee: u64) -> ArgumentEdge {
        ArgumentEdge {
            caller: node(caller),
            callee: node(callee),
            instruction: Address(caller + 4),
            argument: Value {
                variable: 0,
                version: 0,
            },
        }
    }
    #[test]
    fn recursive_worklist_matches_transitive_reachability_and_is_order_independent() {
        let mut edges = vec![
            edge(1, 2),
            edge(2, 3),
            edge(3, 1),
            edge(3, 4),
            edge(8, 9),
            edge(9, 8),
        ];
        let seed = BTreeMap::from([(
            node(4),
            ParameterFacts {
                claims: vec![TypeClaim {
                    ty: TypeRef::pointer_to(TypeRef::uint(8), 64),
                    origin: node(4),
                }],
                overdefined: false,
            },
        )]);
        let (facts, _, converged) = fixed_point(&edges, seed.clone(), &()).unwrap();
        assert!(converged);
        // Independent closure: a node receives a demand exactly when it has
        // a directed call path to the seeded node. The disconnected SCC has none.
        assert_eq!(
            facts.keys().map(|k| k.function.0).collect::<Vec<_>>(),
            [1, 2, 3, 4]
        );
        edges.reverse();
        let (reversed, _, _) = fixed_point(&edges, seed, &()).unwrap();
        assert_eq!(
            serde_json::to_value(facts.values().collect::<Vec<_>>()).unwrap(),
            serde_json::to_value(reversed.values().collect::<Vec<_>>()).unwrap()
        );
    }
    #[test]
    fn type_claim_bound_is_absorbing_and_keeps_conflicts_explicit() {
        let mut facts = ParameterFacts::default();
        for bits in [8, 16, 32, 64, 1] {
            facts.merge(&ParameterFacts {
                claims: vec![TypeClaim {
                    ty: TypeRef::uint(bits),
                    origin: node(u64::from(bits)),
                }],
                overdefined: false,
            });
        }
        assert_eq!(facts.claims.len(), MAX_TYPES);
        assert!(facts.conflicting());
        assert!(facts.overdefined);
        assert!(!facts.merge(&ParameterFacts::default()));
    }
}
