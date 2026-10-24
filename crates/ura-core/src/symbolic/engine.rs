use super::{
    expr::{Arena, Id, Kind, Sort},
    solver::{Backend, Limits, Outcome, Query, Status},
};
use crate::{
    ir::{
        self,
        ssa::{self, SsaFunction, Use, Value},
        Address, FlowKind, Operation, Type, VariableKind,
    },
    AnalysisControl,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    time::Instant,
};

pub const ANALYSIS_VERSION: u32 = 1;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Options {
    pub state_memory_mb: usize,
    pub prove_predicates: bool,
    pub explore_paths: bool,
    pub recover_dispatchers: bool,
    pub recover_indirect_targets: bool,
    pub max_states: usize,
    pub max_paths: usize,
    pub max_depth: usize,
    pub max_operations: usize,
    pub max_queries: usize,
    pub total_ms: u64,
    pub max_nodes: usize,
    pub max_expression_depth: usize,
    pub solver: Limits,
    pub concrete_inputs: BTreeMap<String, Address>,
    pub memory_bytes: BTreeMap<Address, u8>,
    pub regions: Vec<Region>,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            state_memory_mb: 64,
            prove_predicates: true,
            explore_paths: true,
            recover_dispatchers: true,
            recover_indirect_targets: true,
            max_states: 128,
            max_paths: 64,
            max_depth: 64,
            max_operations: 20_000,
            max_queries: 128,
            total_ms: 15_000,
            max_nodes: 20_000,
            max_expression_depth: 128,
            solver: Limits::default(),
            concrete_inputs: BTreeMap::new(),
            memory_bytes: BTreeMap::new(),
            regions: Vec::new(),
        }
    }
}
impl Options {
    pub fn validate(&self) -> Result<(), String> {
        self.solver.validate()?;
        if !(8..=256).contains(&self.state_memory_mb)
            || !(1..=512).contains(&self.max_states)
            || !(1..=256).contains(&self.max_paths)
            || !(1..=256).contains(&self.max_depth)
            || !(1..=200_000).contains(&self.max_operations)
            || !(1..=256).contains(&self.max_queries)
            || !(1..=120_000).contains(&self.total_ms)
            || !(16..=super::expr::HARD_NODES).contains(&self.max_nodes)
            || !(4..=super::expr::HARD_DEPTH).contains(&self.max_expression_depth)
            || self.concrete_inputs.len() > 128
            || self.concrete_inputs.keys().any(|name| {
                name.is_empty()
                    || name.len() > 64
                    || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            })
            || self.memory_bytes.len() > 4096
            || self.regions.len() > 64
        {
            return Err("symbolic analysis limits exceeded".into());
        }
        for region in &self.regions {
            if region.size == 0 || region.start.0.checked_add(region.size - 1).is_none() {
                return Err("invalid memory region".into());
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Region {
    pub start: Address,
    pub size: u64,
    pub read: bool,
    pub write: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub node_count: usize,
    pub assertions: Vec<Id>,
    pub observables: BTreeMap<String, Id>,
    pub limits: Limits,
    pub query_sha256: String,
    pub outcome: Outcome,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PredicateStatus {
    AlwaysTrue,
    AlwaysFalse,
    BothFeasible,
    Unresolved,
    Unsupported,
    TimedOut,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Predicate {
    pub block: Address,
    pub source: Address,
    pub condition: Option<Id>,
    pub classification: PredicateStatus,
    pub scope: String,
    pub dependencies: Vec<String>,
    pub true_evidence: Option<usize>,
    pub false_evidence: Option<usize>,
    pub validation_evidence: Option<usize>,
    pub diagnostic: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Path {
    pub call_depth: usize,
    pub unavailable_registers: Vec<String>,
    pub trace: Vec<Address>,
    pub constraints: Vec<Id>,
    pub outcome: String,
    pub evidence: Option<usize>,
    pub registers: BTreeMap<String, Id>,
    pub operations: usize,
    pub branch_depth: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndirectTargets {
    pub value_set_seeds: Vec<Address>,
    pub transfer_kind: String,
    pub block: Address,
    pub source: Address,
    pub expression: Id,
    pub candidates: Vec<Address>,
    pub exhaustive: bool,
    pub evidence: Vec<usize>,
    pub scope: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemovedEdge {
    pub from: Address,
    pub removed: Address,
    pub retained: Address,
    pub predicate: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DispatcherTransition {
    pub from: Address,
    pub next: Vec<Address>,
    pub exhaustive_under_prefix: bool,
    pub through: Vec<Address>,
    pub constraints: Vec<Id>,
    pub evidence: Vec<usize>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dispatcher {
    pub header: Address,
    pub state: Value,
    pub state_name: String,
    pub compared_states: Vec<Address>,
    pub classification: String,
    pub scope: String,
    pub transitions: Vec<DispatcherTransition>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub ir_identity: String,
    pub variables: Vec<ir::Variable>,
    pub peak_state_bytes: usize,
    pub analysis_version: u32,
    pub ir_version: u32,
    pub function: Address,
    pub identity: String,
    pub solver: String,
    pub options: Options,
    pub assumptions: Vec<String>,
    pub expressions: Arena,
    pub predicates: Vec<Predicate>,
    pub queries: Vec<Evidence>,
    pub paths: Vec<Path>,
    pub indirect_targets: Vec<IndirectTargets>,
    pub removed_edges: Vec<RemovedEdge>,
    pub dispatchers: Vec<Dispatcher>,
    pub explored_states: usize,
    pub operations: usize,
    pub elapsed_us: u64,
    pub complete: bool,
    pub cancelled: bool,
    pub diagnostics: Vec<String>,
}
impl Report {
    pub fn replay_query(&self, index: usize) -> Result<Query, String> {
        let evidence = self.queries.get(index).ok_or("unknown proof query")?;
        if evidence.node_count > self.expressions.nodes.len() {
            return Err("invalid proof prefix".into());
        }
        let mut arena = self.expressions.clone();
        arena.nodes.truncate(evidence.node_count);
        arena.rebuild()?;
        let query = Query {
            arena,
            assertions: evidence.assertions.clone(),
            observables: evidence.observables.clone(),
            limits: evidence.limits.clone(),
        };
        if crate::sha256_hex(&serde_json::to_vec(&query).map_err(|e| e.to_string())?)
            != evidence.query_sha256
        {
            return Err("proof query identity mismatch".into());
        }
        Ok(query)
    }
}
struct Run<'a> {
    value_sets: BTreeMap<Value, super::value_set::Domain>,
    target_seeds: BTreeMap<Id, Vec<Address>>,
    queued_state_bytes: usize,
    peak_state_bytes: usize,
    function: &'a SsaFunction,
    options: &'a Options,
    backend: &'a dyn Backend,
    control: &'a dyn AnalysisControl,
    start: Instant,
    arena: Arena,
    queries: Vec<Evidence>,
    inputs: BTreeMap<String, Id>,
    operations: usize,
    dispatchers: Vec<Dispatcher>,
}
impl Run<'_> {
    fn stopped(&self) -> Option<String> {
        if self.control.is_cancelled() {
            Some("cancelled".into())
        } else if self.start.elapsed().as_millis() >= u128::from(self.options.total_ms) {
            Some("total analysis deadline".into())
        } else if self.operations >= self.options.max_operations {
            Some("IR operation budget".into())
        } else {
            None
        }
    }
    fn ask(
        &mut self,
        assertions: Vec<Id>,
        observables: BTreeMap<String, Id>,
    ) -> (Option<usize>, Outcome) {
        if let Some(reason) = self.stopped() {
            return (
                None,
                Outcome::stopped(
                    if self.control.is_cancelled() {
                        Status::Cancelled
                    } else {
                        Status::Limit
                    },
                    reason,
                ),
            );
        }
        if self.queries.len() >= self.options.max_queries {
            return (None, Outcome::stopped(Status::Limit, "solver query budget"));
        }
        let remaining = self
            .options
            .total_ms
            .saturating_sub(self.start.elapsed().as_millis() as u64)
            .max(1);
        let mut limits = self.options.solver.clone();
        limits.timeout_ms = limits.timeout_ms.min(remaining as u32);
        let query = Query {
            arena: self.arena.clone(),
            assertions: assertions.clone(),
            observables: observables.clone(),
            limits: limits.clone(),
        };
        let digest = match serde_json::to_vec(&query) {
            Ok(bytes) => crate::sha256_hex(&bytes),
            Err(e) => return (None, Outcome::stopped(Status::Error, e.to_string())),
        };
        let deadline = DeadlineControl {
            parent: self.control,
            until: self.start + std::time::Duration::from_millis(self.options.total_ms),
        };
        let mut outcome = self.backend.query(query, &deadline);
        if deadline.until <= Instant::now() && !self.control.is_cancelled() {
            outcome =
                Outcome::stopped(Status::Limit, "total analysis deadline during solver query");
        }
        let index = self.queries.len();
        self.queries.push(Evidence {
            node_count: self.arena.nodes.len(),
            assertions,
            observables,
            limits,
            query_sha256: digest,
            outcome: outcome.clone(),
        });
        (Some(index), outcome)
    }
    fn root(&mut self, v: Value, constrained: bool) -> Result<Id, String> {
        let var = &self.function.variables[v.variable];
        if constrained && v.version == 0 {
            if let Some(value) = self.options.concrete_inputs.get(&var.name) {
                let id = self.arena.constant(
                    var.ty.width().ok_or("concrete memory input unsupported")?,
                    value.0,
                )?;
                self.inputs.insert(var.name.clone(), id);
                return Ok(id);
            }
        }
        let name = format!("v{}_{}", v.variable, v.version);
        let poison =
            (var.kind == VariableKind::Temporary).then(|| "uninitialised temporary".into());
        let id = self.arena.symbol(
            &name,
            Sort::from_ir(var.ty, self.function.address_width),
            poison,
        )?;
        if v.version == 0 && var.ty.width().is_some() && var.kind != VariableKind::Temporary {
            self.inputs.insert(var.name.clone(), id);
        }
        Ok(id)
    }
    fn operation(&mut self, op: &Operation, ty: Type, args: Vec<Id>) -> Result<Id, String> {
        if let Some(reason) = self.stopped() {
            return Err(reason);
        }
        self.operations += 1;
        let sort = Sort::from_ir(ty, self.function.address_width);
        match op {
            Operation::Load => self.arena.add(
                sort,
                Kind::Load {
                    memory: args[0],
                    address: args[1],
                },
            ),
            Operation::Store => self.arena.add(
                sort,
                Kind::Store {
                    memory: args[0],
                    address: args[1],
                    value: args[2],
                },
            ),
            Operation::Copy if args.len() == 1 => Ok(args[0]),
            Operation::Unknown { reason } => self.arena.symbol(
                &format!("unknown_{}", self.arena.nodes.len()),
                sort,
                Some(reason.chars().take(512).collect()),
            ),
            _ => self.arena.pure(
                op.clone(),
                ty.width().ok_or("unsupported memory operation")?,
                args,
            ),
        }
    }
    fn scalar_use(
        &mut self,
        arg: Use,
        state: &mut BTreeMap<Value, Id>,
        constrained: bool,
    ) -> Result<Id, String> {
        match arg {
            Use::Constant(c) => self
                .arena
                .constant(c.ty.width().ok_or("memory constant")?, c.value.0),
            Use::Value(v) => {
                if let Some(id) = state.get(&v) {
                    if let Some(super::value_set::Domain::Finite { values }) =
                        self.value_sets.get(&v)
                    {
                        self.target_seeds
                            .insert(*id, values.iter().copied().collect());
                    }
                    return Ok(*id);
                }
                if v.version != 0 {
                    return Err("SSA value unavailable on this path".into());
                }
                let mut id = self.root(v, constrained)?;
                if constrained && self.function.variables[v.variable].ty == Type::Memory {
                    for (address, value) in &self.options.memory_bytes {
                        let a = self
                            .arena
                            .constant(self.function.address_width, address.0)?;
                        let b = self.arena.constant(8, u64::from(*value))?;
                        id = self.arena.add(
                            Sort::Memory(self.function.address_width),
                            Kind::Store {
                                memory: id,
                                address: a,
                                value: b,
                            },
                        )?;
                    }
                }
                state.insert(v, id);
                Ok(id)
            }
        }
    }
    fn local_use(
        &mut self,
        arg: Use,
        cache: &mut BTreeMap<Value, Id>,
        defs: &BTreeMap<Value, ssa::SsaStatement>,
        depth: usize,
    ) -> Result<Id, String> {
        if let Some(reason) = self.stopped() {
            return Err(reason);
        }
        if depth > self.options.max_expression_depth {
            return Err("predicate dependency depth limit".into());
        }
        match arg {
            Use::Constant(c) => self
                .arena
                .constant(c.ty.width().ok_or("memory constant")?, c.value.0),
            Use::Value(v) => {
                if let Some(id) = cache.get(&v) {
                    return Ok(*id);
                }
                let id = if let Some(statement) = defs.get(&v) {
                    let args = statement
                        .args
                        .iter()
                        .map(|a| self.local_use(*a, cache, defs, depth + 1))
                        .collect::<Result<Vec<_>, _>>()?;
                    self.operation(&statement.op, self.function.variables[v.variable].ty, args)?
                } else {
                    // Phi values are independent arbitrary inputs. This loses
                    // precision but overapproximates every loop/join value.
                    self.root(v, false)?
                };
                cache.insert(v, id);
                Ok(id)
            }
        }
    }
    fn predicates(&mut self) -> Vec<Predicate> {
        let defs: BTreeMap<_, _> = self
            .function
            .blocks
            .iter()
            .flat_map(|b| &b.statements)
            .filter_map(|s| s.output.map(|v| (v, s.clone())))
            .collect();
        let unsafe_effect = self
            .function
            .blocks
            .iter()
            .flat_map(|b| &b.statements)
            .any(|s| matches!(s.op, Operation::Call | Operation::Barrier { .. }));
        let mut cache = BTreeMap::new();
        let mut output = Vec::new();
        for block in &self.function.blocks {
            if block.terminator.flow.kind != FlowKind::Branch {
                continue;
            }
            if self.stopped().is_some() || self.queries.len() >= self.options.max_queries {
                break;
            }
            let mut predicate = Predicate { block: block.address, source: block.terminator.flow.source, condition: None,
                classification: PredicateStatus::Unresolved, scope: "universal local scalar/array formula; SSA joins are arbitrary; no user constraints".into(),
                dependencies: Vec::new(), true_evidence: None, false_evidence: None, validation_evidence: None, diagnostic: None };
            let build = if unsafe_effect {
                Err("function contains an unknown external effect boundary".into())
            } else {
                block
                    .terminator
                    .value
                    .ok_or("missing branch condition".into())
                    .and_then(|v| self.local_use(v, &mut cache, &defs, 0))
            };
            match build {
                Err(e) => {
                    predicate.classification = PredicateStatus::Unsupported;
                    predicate.diagnostic = Some(e);
                }
                Ok(condition) => {
                    predicate.condition = Some(condition);
                    predicate.dependencies = self.arena.dependencies(condition);
                    let outcomes = (|| -> Result<_, String> {
                        let yes = self.arena.condition(condition, true)?;
                        let no = self.arena.condition(condition, false)?;
                        let (yi, y) = self.ask(vec![yes], BTreeMap::new());
                        let (ni, n) = self.ask(vec![no], BTreeMap::new());
                        Ok((yi, y, ni, n, yes, no))
                    })();
                    match outcomes {
                        Err(e) => predicate.diagnostic = Some(e),
                        Ok((yi, y, ni, n, yes, no)) => {
                            predicate.true_evidence = yi;
                            predicate.false_evidence = ni;
                            predicate.classification = match (y.status, n.status) {
                                (Status::Sat, Status::Unsat) => PredicateStatus::AlwaysTrue,
                                (Status::Unsat, Status::Sat) => PredicateStatus::AlwaysFalse,
                                (Status::Sat, Status::Sat) => PredicateStatus::BothFeasible,
                                (Status::Unsupported, _) | (_, Status::Unsupported) => {
                                    PredicateStatus::Unsupported
                                }
                                (Status::Timeout, _) | (_, Status::Timeout) => {
                                    PredicateStatus::TimedOut
                                }
                                _ => PredicateStatus::Unresolved,
                            };
                            if matches!(
                                predicate.classification,
                                PredicateStatus::AlwaysTrue | PredicateStatus::AlwaysFalse
                            ) {
                                // A separate validation query is mandatory before
                                // this fact becomes an enabled CFG rewrite.
                                let opposite =
                                    if predicate.classification == PredicateStatus::AlwaysTrue {
                                        no
                                    } else {
                                        yes
                                    };
                                let (index, validation) = self.ask(vec![opposite], BTreeMap::new());
                                if validation.status == Status::Unsat {
                                    predicate.validation_evidence = index;
                                } else {
                                    predicate.diagnostic = Some("rewrite validation did not establish UNSAT; original edge retained".into());
                                }
                            }
                        }
                    }
                }
            }
            output.push(predicate);
        }
        output
    }
}
#[derive(Clone)]
struct State {
    block: Address,
    predecessor: Option<Address>,
    values: BTreeMap<Value, Id>,
    constraints: Vec<Id>,
    trace: Vec<Address>,
    depth: usize,
    operations: usize,
    dispatcher_visits: BTreeMap<Address, (Id, usize)>,
}
impl State {
    fn retained_bytes(&self) -> usize {
        // Conservative accounting for BTreeMap entries/node overhead and the
        // retained capacities of bounded path vectors, independent of solver RSS.
        1024 + self.values.len() * 96
            + self.constraints.capacity() * 8
            + self.trace.capacity() * 8
            + self.dispatcher_visits.len() * 96
    }
}
impl Run<'_> {
    fn finish(&mut self, state: &State, outcome: String, evidence: Option<usize>) -> Path {
        let mut registers = BTreeMap::new();
        let mut unavailable_registers = Vec::new();
        if let Some(block) = state
            .trace
            .last()
            .and_then(|address| self.function.blocks.iter().find(|b| b.address == *address))
        {
            for value in &block.terminator.state {
                if let Use::Value(v) = value {
                    let var = &self.function.variables[v.variable];
                    if let Some(id) = state.values.get(v) {
                        if matches!(var.kind, VariableKind::Register | VariableKind::Flag)
                            && self.arena.is_poisoned(*id)
                        {
                            unavailable_registers.push(var.name.clone());
                        }
                        if matches!(var.kind, VariableKind::Register | VariableKind::Flag)
                            && !self.arena.is_poisoned(*id)
                        {
                            registers.insert(var.name.clone(), *id);
                        }
                    }
                }
            }
        }
        Path {
            call_depth: 0,
            trace: state.trace.clone(),
            constraints: state.constraints.clone(),
            outcome,
            evidence,
            registers,
            unavailable_registers,
            operations: state.operations,
            branch_depth: state.depth,
        }
    }
    fn memory_valid(&mut self, op: &Operation, ty: Type, args: &[Id]) -> Result<Id, String> {
        let address = args[1];
        let w = self.function.address_width;
        let bytes = if *op == Operation::Load {
            ty.width().ok_or("load width")? / 8
        } else {
            self.arena.sort(args[2])?.width().ok_or("store width")? / 8
        };
        let max = self.arena.constant(w, ir::mask(w) - u64::from(bytes - 1))?;
        let overflow = self
            .arena
            .pure(Operation::UnsignedLess, 1, vec![max, address])?;
        let mut valid = self.arena.condition(overflow, false)?;
        if !self.options.regions.is_empty() {
            let mut region_valid = self.arena.constant(1, 0)?;
            for region in &self.options.regions {
                if !if *op == Operation::Load {
                    region.read
                } else {
                    region.write
                } {
                    continue;
                }
                if region.size < u64::from(bytes) || region.start.0 > ir::mask(w) {
                    continue;
                }
                let end = region
                    .start
                    .0
                    .saturating_add(region.size - u64::from(bytes))
                    .min(ir::mask(w));
                let lo = self.arena.constant(w, region.start.0)?;
                let hi = self.arena.constant(w, end)?;
                let below = self
                    .arena
                    .pure(Operation::UnsignedLess, 1, vec![address, lo])?;
                let above = self
                    .arena
                    .pure(Operation::UnsignedLess, 1, vec![hi, address])?;
                let outside = self.arena.pure(Operation::Or, 1, vec![below, above])?;
                let inside = self.arena.condition(outside, false)?;
                region_valid = self
                    .arena
                    .pure(Operation::Or, 1, vec![region_valid, inside])?;
            }
            valid = self
                .arena
                .pure(Operation::And, 1, vec![valid, region_valid])?;
        }
        Ok(valid)
    }
    fn guarded(
        &mut self,
        state: &mut State,
        valid: Id,
        paths: &mut Vec<Path>,
        label: &str,
    ) -> Result<bool, String> {
        let invalid = self.arena.condition(valid, false)?;
        let mut fault_constraints = state.constraints.clone();
        fault_constraints.push(invalid);
        let (fi, fault) = self.ask(fault_constraints.clone(), self.inputs.clone());
        match fault.status {
            Status::Sat => {
                let mut fault_state = state.clone();
                fault_state.constraints = fault_constraints;
                if paths.len() < self.options.max_paths {
                    paths.push(self.finish(&fault_state, label.into(), fi));
                }
            }
            Status::Unsat => {}
            _ => return Err(format!("unresolved fault feasibility: {:?}", fault.status)),
        }
        state.constraints.push(valid);
        let (_, normal) = self.ask(state.constraints.clone(), BTreeMap::new());
        match normal.status {
            Status::Sat => Ok(true),
            Status::Unsat => Ok(false),
            _ => Err(format!(
                "unresolved valid-state feasibility: {:?}",
                normal.status
            )),
        }
    }
    fn execute(&mut self) -> (Vec<Path>, Vec<IndirectTargets>, usize, bool) {
        self.inputs.clear();
        let mut initial = BTreeMap::new();
        for (variable, var) in self.function.variables.iter().enumerate() {
            if var.kind != VariableKind::Temporary
                && self
                    .scalar_use(
                        Use::Value(Value {
                            variable,
                            version: 0,
                        }),
                        &mut initial,
                        true,
                    )
                    .is_err()
            {
                return (Vec::new(), Vec::new(), 0, false);
            }
        }
        let mut queue = VecDeque::from([State {
            block: self.function.entry,
            predecessor: None,
            values: initial,
            constraints: Vec::new(),
            trace: Vec::new(),
            depth: 0,
            operations: 0,
            dispatcher_visits: BTreeMap::new(),
        }]);
        let blocks: BTreeMap<_, _> = self
            .function
            .blocks
            .iter()
            .map(|b| (b.address, b))
            .collect();
        let memory_limit = self.options.state_memory_mb * 1024 * 1024;
        self.queued_state_bytes = queue.iter().map(State::retained_bytes).sum();
        self.peak_state_bytes = self.peak_state_bytes.max(self.queued_state_bytes);
        let mut paths = Vec::new();
        let mut targets = Vec::new();
        let mut explored = 0;
        let mut complete = true;
        while let Some(mut state) = queue.pop_front() {
            self.queued_state_bytes = self
                .queued_state_bytes
                .saturating_sub(state.retained_bytes());
            if explored >= self.options.max_states
                || paths.len() >= self.options.max_paths
                || self.stopped().is_some()
            {
                complete = false;
                break;
            }
            explored += 1;
            if state.trace.len() >= self.options.max_depth || state.depth >= self.options.max_depth
            {
                paths.push(self.finish(&state, "depth limit".into(), None));
                complete = false;
                continue;
            }
            let Some(block) = blocks.get(&state.block) else {
                complete = false;
                let (i, q) = self.ask(state.constraints.clone(), self.inputs.clone());
                paths.push(self.finish(
                    &state,
                    format!("external CFG destination ({:?})", q.status),
                    i,
                ));
                continue;
            };
            state.trace.push(state.block);
            let result = (|| -> Result<bool, String> {
                let mut phis = Vec::new();
                for phi in &block.phis {
                    let incoming = match state.predecessor {
                        Some(p) => phi.incoming.get(&p).copied(),
                        None => phi.initial,
                    };
                    let id = self.scalar_use(
                        Use::Value(incoming.ok_or("missing phi input")?),
                        &mut state.values,
                        true,
                    )?;
                    phis.push((phi.output, id));
                }
                state.values.extend(phis);
                self.dispatcher_visit(&mut state);
                for statement in &block.statements {
                    let retained = self
                        .queued_state_bytes
                        .saturating_add(state.retained_bytes());
                    self.peak_state_bytes = self.peak_state_bytes.max(retained);
                    if retained > memory_limit {
                        return Err("retained state memory budget".into());
                    }
                    if let Some(reason) = self.stopped() {
                        return Err(reason);
                    }
                    if paths.len() >= self.options.max_paths {
                        return Err("path result budget".into());
                    }
                    state.operations += 1;
                    if matches!(statement.op, Operation::Call | Operation::Barrier { .. }) {
                        if statement.op == Operation::Call && self.options.recover_indirect_targets
                        {
                            if let Some(target @ Use::Value(_)) = statement.args.first() {
                                if let Ok(id) = self.scalar_use(*target, &mut state.values, true) {
                                    let mut recovered = self.enumerate(
                                        state.block,
                                        statement.source,
                                        id,
                                        &state.constraints,
                                    );
                                    recovered.transfer_kind = "indirectCall".into();
                                    targets.push(recovered);
                                }
                            }
                        }
                        return Err(
                            "unsupported external effect/call boundary (intraprocedural analysis)"
                                .into(),
                        );
                    }
                    let args = statement
                        .args
                        .iter()
                        .map(|a| self.scalar_use(*a, &mut state.values, true))
                        .collect::<Result<Vec<_>, _>>()?;
                    if let Operation::Guard { reason } = &statement.op {
                        self.operations += 1;
                        let valid = self.arena.condition(args[0], false)?;
                        if !self.guarded(
                            &mut state,
                            valid,
                            &mut paths,
                            &format!("machine fault: {reason}"),
                        )? {
                            return Ok(false);
                        }
                        continue;
                    }
                    if let Some(output) = statement.output {
                        let ty = self.function.variables[output.variable].ty;
                        if matches!(statement.op, Operation::Load | Operation::Store) {
                            let valid = self.memory_valid(&statement.op, ty, &args)?;
                            if !self.guarded(
                                &mut state,
                                valid,
                                &mut paths,
                                "memory access outside supplied regions/address width",
                            )? {
                                return Ok(false);
                            }
                        }
                        let value = self.operation(&statement.op, ty, args)?;
                        state.values.insert(output, value);
                    }
                }
                Ok(true)
            })();
            match result {
                Ok(false) => continue,
                Err(reason) => {
                    paths.push(self.finish(&state, format!("unresolved: {reason}"), None));
                    complete = false;
                    continue;
                }
                Ok(true) => {}
            }
            match block.terminator.flow.kind {
                FlowKind::Branch => {
                    let condition = block
                        .terminator
                        .value
                        .ok_or("missing branch condition")
                        .and_then(|v| {
                            self.scalar_use(v, &mut state.values, true)
                                .map_err(|_| "condition construction limit")
                        });
                    let Ok(condition) = condition else {
                        paths.push(self.finish(
                            &state,
                            "unresolved branch expression".into(),
                            None,
                        ));
                        complete = false;
                        continue;
                    };
                    for (taken, target) in [
                        (true, block.terminator.flow.taken),
                        (false, block.terminator.flow.fallthrough),
                    ] {
                        let branch = match self.arena.condition(condition, taken) {
                            Ok(id) => id,
                            Err(e) => {
                                paths.push(self.finish(&state, e, None));
                                complete = false;
                                break;
                            }
                        };
                        let mut constraints = state.constraints.clone();
                        constraints.push(branch);
                        let (i, q) = self.ask(constraints.clone(), self.inputs.clone());
                        match q.status {
                            Status::Sat => {
                                if let Some(target) = target {
                                    let mut next = state.clone();
                                    next.predecessor = Some(state.block);
                                    next.block = target;
                                    next.constraints = constraints;
                                    next.depth += 1;
                                    if queue.len() + explored < self.options.max_states
                                        && self.queued_state_bytes
                                            + next.retained_bytes()
                                            + state.retained_bytes()
                                            <= memory_limit
                                    {
                                        self.queued_state_bytes += next.retained_bytes();
                                        self.peak_state_bytes = self
                                            .peak_state_bytes
                                            .max(self.queued_state_bytes + state.retained_bytes());
                                        queue.push_back(next);
                                    } else {
                                        paths.push(self.finish(
                                            &next,
                                            "state queue or memory limit".into(),
                                            i,
                                        ));
                                        complete = false;
                                    }
                                }
                            }
                            Status::Unsat => {}
                            _ => {
                                let mut unresolved = state.clone();
                                unresolved.constraints = constraints;
                                if paths.len() < self.options.max_paths {
                                    paths.push(self.finish(
                                        &unresolved,
                                        format!("unresolved branch: {:?}", q.status),
                                        i,
                                    ));
                                }
                                complete = false;
                            }
                        }
                    }
                }
                FlowKind::Jump => {
                    let target = block.terminator.flow.successors.first().or(block
                        .terminator
                        .flow
                        .exits
                        .first());
                    if let Some(target) = target {
                        state.predecessor = Some(state.block);
                        state.block = *target;
                        if self.queued_state_bytes + state.retained_bytes() > memory_limit {
                            paths.push(self.finish(&state, "state memory budget".into(), None));
                            complete = false;
                        } else {
                            self.queued_state_bytes += state.retained_bytes();
                            self.peak_state_bytes =
                                self.peak_state_bytes.max(self.queued_state_bytes);
                            queue.push_back(state);
                        }
                    }
                }
                FlowKind::Indirect => {
                    complete = false;
                    if let Some(value) = block
                        .terminator
                        .value
                        .filter(|_| self.options.recover_indirect_targets)
                    {
                        if let Ok(id) = self.scalar_use(value, &mut state.values, true) {
                            targets.push(self.enumerate(
                                block.address,
                                block.terminator.flow.source,
                                id,
                                &state.constraints,
                            ));
                        }
                    }
                    let (i, q) = self.ask(state.constraints.clone(), self.inputs.clone());
                    paths.push(self.finish(
                        &state,
                        format!("indirect transfer boundary ({:?})", q.status),
                        i,
                    ));
                }
                FlowKind::Return => {
                    // Materialise the exact terminal SSA versions before exposing
                    // architectural outputs (older definitions may remain cached).
                    for value in &block.terminator.state {
                        let _ = self.scalar_use(*value, &mut state.values, true);
                    }
                    let (i, q) = self.ask(state.constraints.clone(), self.inputs.clone());
                    if q.status != Status::Unsat {
                        paths.push(self.finish(&state, format!("return ({:?})", q.status), i));
                    }
                    if q.status != Status::Sat && q.status != Status::Unsat {
                        complete = false;
                    }
                }
                FlowKind::Unresolved => {
                    paths.push(self.finish(&state, "unsupported unresolved transfer".into(), None));
                    complete = false;
                }
            }
        }
        if !queue.is_empty() {
            complete = false;
        }
        if paths.len() > self.options.max_paths {
            complete = false;
        }
        paths.truncate(self.options.max_paths);
        (paths, targets, explored, complete)
    }
    fn enumerate(
        &mut self,
        block: Address,
        source: Address,
        id: Id,
        constraints: &[Id],
    ) -> IndirectTargets {
        let seeds = self
            .arena
            .concrete(id)
            .map(|v| vec![Address(v)])
            .unwrap_or_else(|| self.target_seeds.get(&id).cloned().unwrap_or_default());
        let mut result = IndirectTargets { block, source, expression: id, candidates: Vec::new(), exhaustive: false, evidence: Vec::new(), transfer_kind: "indirectBranch".into(), value_set_seeds: seeds.clone(), scope: "bounded path prefix under configured entry/memory model; destinations are addresses, not validated executable edges; value-set seeds are suggestions, never asserted as exhaustive".into() };
        let mut assertions = constraints.to_vec();
        for seed in seeds.into_iter().take(16) {
            let equality = (|| -> Result<_, String> {
                let constant = self
                    .arena
                    .constant(self.arena.sort(id)?.width().ok_or("target width")?, seed.0)?;
                self.arena.pure(Operation::Equal, 1, vec![id, constant])
            })();
            let Ok(equality) = equality else {
                break;
            };
            let mut query = assertions.clone();
            query.push(equality);
            let (index, outcome) = self.ask(query, BTreeMap::from([("target".into(), id)]));
            if let Some(index) = index {
                result.evidence.push(index);
            }
            if outcome.status == Status::Sat {
                result.candidates.push(seed);
                match self.arena.condition(equality, false) {
                    Ok(exclude) => assertions.push(exclude),
                    Err(_) => break,
                }
            }
        }
        for _ in 0..=16 {
            let (index, outcome) =
                self.ask(assertions.clone(), BTreeMap::from([("target".into(), id)]));
            if let Some(index) = index {
                result.evidence.push(index);
            }
            if outcome.status == Status::Unsat {
                result.exhaustive = true;
                break;
            }
            if outcome.status != Status::Sat || result.candidates.len() == 16 {
                break;
            }
            let Some(target) = outcome.model.get("target").copied() else {
                break;
            };
            result.candidates.push(target);
            let excluded = (|| -> Result<_, String> {
                let c = self.arena.constant(
                    self.arena.sort(id)?.width().ok_or("target width")?,
                    target.0,
                )?;
                let eq = self.arena.pure(Operation::Equal, 1, vec![id, c])?;
                self.arena.condition(eq, false)
            })();
            match excluded {
                Ok(id) => assertions.push(id),
                Err(_) => break,
            }
        }
        result.candidates.sort();
        result
    }
}

pub(super) struct DeadlineControl<'a> {
    pub(super) parent: &'a dyn AnalysisControl,
    pub(super) until: Instant,
}
impl AnalysisControl for DeadlineControl<'_> {
    fn is_cancelled(&self) -> bool {
        self.parent.is_cancelled() || Instant::now() >= self.until
    }
    fn report(&self, progress: crate::AnalysisProgress) {
        self.parent.report(progress);
    }
}

fn dispatcher_candidates(
    function: &SsaFunction,
    control: &dyn AnalysisControl,
    start: Instant,
    options: &Options,
) -> Result<Vec<Dispatcher>, String> {
    let mut candidates = Vec::new();
    let defs: BTreeMap<_, _> = function
        .blocks
        .iter()
        .flat_map(|b| &b.statements)
        .filter_map(|s| s.output.map(|v| (v, s)))
        .collect();
    let mut comparisons: BTreeMap<Value, Vec<(Address, Address)>> = BTreeMap::new();
    let mut work = 0;
    for b in &function.blocks {
        if control.is_cancelled() || start.elapsed().as_millis() >= u128::from(options.total_ms) {
            return Err("dispatcher preprocessing cancelled/deadline".into());
        }
        if b.terminator.flow.kind != FlowKind::Branch {
            continue;
        }
        for statement in &b.statements {
            work += 1;
            if work > options.max_operations {
                return Err("dispatcher preprocessing operation budget".into());
            }
            if !matches!(statement.op, Operation::Sub | Operation::Equal) {
                continue;
            }
            if let [Use::Value(v), Use::Constant(c)] = statement.args.as_slice() {
                let mut v = *v;
                for _ in 0..8 {
                    let Some(def) = defs.get(&v) else {
                        break;
                    };
                    if matches!(
                        def.op,
                        Operation::Copy
                            | Operation::Truncate
                            | Operation::ZeroExtend
                            | Operation::ToAddress
                            | Operation::ToBits
                            | Operation::Extract { offset: 0 }
                    ) {
                        if let [Use::Value(input)] = def.args.as_slice() {
                            v = *input;
                            continue;
                        }
                    }
                    break;
                }
                comparisons.entry(v).or_default().push((b.address, c.value));
            }
        }
    }
    for block in &function.blocks {
        if !block
            .predecessors
            .iter()
            .any(|p| function.dominators.dominates(block.address, *p))
        {
            continue;
        }
        for phi in &block.phis {
            if control.is_cancelled() || start.elapsed().as_millis() >= u128::from(options.total_ms)
            {
                return Err("dispatcher preprocessing cancelled/deadline".into());
            }
            let var = &function.variables[phi.output.variable];
            if var.kind != VariableKind::Register {
                continue;
            }
            let mut states = std::collections::BTreeSet::new();
            let mut compared_blocks = std::collections::BTreeSet::new();
            if let Some(indexed) = comparisons.get(&phi.output) {
                for (address, constant) in indexed {
                    work += 1;
                    if work > options.max_operations {
                        return Err("dispatcher preprocessing operation budget".into());
                    }
                    if function.dominators.dominates(block.address, *address) {
                        states.insert(*constant);
                        compared_blocks.insert(*address);
                    }
                }
            }
            if states.len() >= 2 && compared_blocks.len() >= 2 {
                candidates.push(Dispatcher { header: block.address, state: phi.output, state_name: var.name.clone(),
                    compared_states: states.into_iter().take(16).collect(), classification: "dispatcher candidate; structure alone does not establish obfuscation".into(),
                    scope: "logical state transitions proved under captured bounded function-entry prefixes; no global completeness or dispatcher-elimination claim".into(), transitions: Vec::new() });
                if candidates.len() >= 4 {
                    return Ok(candidates);
                }
            }
        }
    }
    Ok(candidates)
}
impl Run<'_> {
    fn dispatcher_visit(&mut self, state: &mut State) {
        let Some(index) = self
            .dispatchers
            .iter()
            .position(|d| d.header == state.block)
        else {
            return;
        };
        let dispatcher = &self.dispatchers[index];
        let Some(current) = state.values.get(&dispatcher.state).copied() else {
            return;
        };
        let previous = state
            .dispatcher_visits
            .insert(state.block, (current, state.trace.len() - 1));
        let Some((old, position)) = previous else {
            return;
        };
        if self.dispatchers[index].transitions.len() >= 16 || self.stopped().is_some() {
            return;
        }
        let through = state.trace[position..].to_vec();
        if let (Some(from), Some(next)) = (self.arena.concrete(old), self.arena.concrete(current)) {
            if self.dispatchers[index]
                .transitions
                .iter()
                .any(|t| t.from.0 == from && t.next == vec![Address(next)] && t.through == through)
            {
                return;
            }
        }
        let froms = self.enumerate(state.block, state.block, old, &state.constraints);
        if !froms.exhaustive {
            return;
        }
        for from in froms.candidates {
            if self.dispatchers[index].transitions.len() >= 16 {
                break;
            }
            let constraints = (|| -> Result<_, String> {
                let c = self
                    .arena
                    .constant(self.arena.sort(old)?.width().ok_or("state width")?, from.0)?;
                let eq = self.arena.pure(Operation::Equal, 1, vec![old, c])?;
                let mut constraints = state.constraints.clone();
                constraints.push(eq);
                Ok(constraints)
            })();
            let Ok(constraints) = constraints else {
                break;
            };
            let next = self.enumerate(state.block, state.block, current, &constraints);
            if next.candidates.is_empty() {
                continue;
            }
            let mut evidence = froms.evidence.clone();
            evidence.extend(next.evidence);
            self.dispatchers[index]
                .transitions
                .push(DispatcherTransition {
                    from,
                    next: next.candidates,
                    exhaustive_under_prefix: next.exhaustive,
                    through: through.clone(),
                    constraints,
                    evidence,
                });
        }
        if !self.dispatchers[index].transitions.is_empty() {
            self.dispatchers[index].classification =
                "partially recovered dispatcher candidate with solver-backed prefix transitions"
                    .into();
        }
    }
}

pub fn analyze(
    raw: &ir::Function,
    options: &Options,
    backend: &dyn Backend,
    control: &dyn AnalysisControl,
) -> Result<Report, String> {
    options.validate()?;
    ir::verify(raw).map_err(|e| e.join("; "))?;
    if raw.variables.len() > 4096 || raw.blocks.len() > 512 {
        return Err("symbolic function capacity: at most 4096 variables and 512 blocks".into());
    }
    let architectural: BTreeMap<_, _> = raw
        .variables
        .iter()
        .filter(|v| matches!(v.kind, VariableKind::Register | VariableKind::Flag))
        .map(|v| (v.name.as_str(), v.ty))
        .collect();
    if architectural.len() > 128 {
        return Err("symbolic architectural input capacity: at most 128 registers/flags".into());
    }
    for (name, value) in &options.concrete_inputs {
        let width = architectural
            .get(name.as_str())
            .and_then(|t| t.width())
            .ok_or_else(|| format!("unknown architectural input {name}"))?;
        if value.0 & !ir::mask(width) != 0 {
            return Err(format!("input {name} exceeds its width"));
        }
    }
    if options
        .memory_bytes
        .keys()
        .any(|a| a.0 > ir::mask(raw.address_width))
    {
        return Err("initial memory address exceeds pointer width".into());
    }
    let start = Instant::now();
    let deadline = DeadlineControl {
        parent: control,
        until: start + std::time::Duration::from_millis(options.total_ms),
    };
    let function = ssa::construct_with_control(raw, &deadline).map_err(|error| {
        if Instant::now() >= deadline.until && !control.is_cancelled() {
            format!("symbolic preprocessing deadline: {error}")
        } else {
            error
        }
    })?;
    let value_sets = super::value_set::analyze(&function, &deadline);
    let mut run = Run {
        value_sets: value_sets
            .facts
            .into_iter()
            .map(|fact| (fact.value, fact.domain))
            .collect(),
        target_seeds: BTreeMap::new(),
        queued_state_bytes: 0,
        peak_state_bytes: 0,
        function: &function,
        options,
        backend,
        control,
        start,
        arena: Arena::new(options.max_nodes, options.max_expression_depth),
        queries: Vec::new(),
        inputs: BTreeMap::new(),
        operations: 0,
        dispatchers: if options.recover_dispatchers && options.explore_paths {
            dispatcher_candidates(&function, control, start, options)?
        } else {
            Vec::new()
        },
    };
    let predicates = if options.prove_predicates {
        run.predicates()
    } else {
        Vec::new()
    };
    let (paths, indirect_targets, explored_states, complete) = if options.explore_paths {
        run.execute()
    } else {
        (Vec::new(), Vec::new(), 0, false)
    };
    let mut removed_edges = Vec::new();
    for (index, predicate) in predicates.iter().enumerate() {
        if predicate.validation_evidence.is_none() {
            continue;
        }
        let block = function
            .blocks
            .iter()
            .find(|b| b.address == predicate.block)
            .ok_or("predicate block disappeared")?;
        let flow = &block.terminator.flow;
        let (retained, removed) = if predicate.classification == PredicateStatus::AlwaysTrue {
            (flow.taken, flow.fallthrough)
        } else if predicate.classification == PredicateStatus::AlwaysFalse {
            (flow.fallthrough, flow.taken)
        } else {
            continue;
        };
        if let (Some(retained), Some(removed)) = (retained, removed) {
            if retained != removed {
                removed_edges.push(RemovedEdge {
                    from: block.address,
                    retained,
                    removed,
                    predicate: index,
                });
            }
        }
    }
    let solver = format!("Z3 {}", z3::full_version());
    let identity = crate::sha256_hex(
        &serde_json::to_vec(&(ANALYSIS_VERSION, raw, options, &solver))
            .map_err(|e| e.to_string())?,
    );
    let mut diagnostics = Vec::new();
    if let Some(reason) = run.stopped() {
        diagnostics.push(reason);
    }
    if run.queries.len() >= options.max_queries {
        diagnostics.push("solver query budget reached".into());
    }
    if !complete {
        diagnostics.push(
            "bounded exploration is incomplete; no global theorem follows from path coverage"
                .into(),
        );
    }
    Ok(Report { analysis_version: ANALYSIS_VERSION, ir_version: ir::IR_VERSION, function: raw.entry, identity: identity.clone(), solver, options: options.clone(),
        assumptions: vec!["intraprocedural verified scalar IR; external calls/unknown effects stop paths".into(),
            "entry registers and unspecified bytes arbitrary; configured concrete inputs/bytes apply only to path exploration".into(),
            "byte-array memory, little endian; accessibility constrained only by supplied regions; no operating-system fault model".into(),
            "universal local predicate proofs ignore user assumptions and overapproximate SSA joins; path-only facts never prune global CFG".into()],
        expressions: run.arena, predicates, queries: run.queries, paths, indirect_targets, removed_edges, dispatchers: run.dispatchers,
        explored_states, operations: run.operations, elapsed_us: start.elapsed().as_micros() as u64, variables: raw.variables.clone(), peak_state_bytes: run.peak_state_bytes, ir_identity: identity.clone(),
        complete, cancelled: control.is_cancelled(), diagnostics })
}

/// Derive from a freshly recomputed report, never from an untrusted saved DTO.
/// This private entry point is called only by the shared analysis orchestrator.
pub(crate) fn refine(raw: &ir::Function, report: &Report) -> Result<ir::Function, String> {
    let mut result = raw.clone();
    for edge in &report.removed_edges {
        let block = result
            .blocks
            .iter_mut()
            .find(|b| b.address == edge.from)
            .ok_or("missing rewrite block")?;
        let t = &mut block.terminator;
        if t.kind != FlowKind::Branch {
            return Err("rewrite no longer matches original branch".into());
        }
        let internal = t.successors.contains(&edge.retained);
        t.kind = FlowKind::Jump;
        t.value = Some(ir::Operand::Constant(ir::Constant {
            ty: Type::Address(raw.address_width),
            value: edge.retained,
        }));
        t.successors = if internal {
            vec![edge.retained]
        } else {
            Vec::new()
        };
        t.exits = if internal {
            Vec::new()
        } else {
            vec![edge.retained]
        };
        t.taken = None;
        t.fallthrough = None;
    }
    // Exit state remains complete; SSA construction subsequently omits blocks
    // made unreachable. The original raw function is never modified.
    ir::verify(&result).map_err(|e| e.join("; "))?;
    Ok(result)
}
