//! Combined SSA/parameter/return type constraints. Facts are type evidence,
//! never concrete call effects or a rewriting of the machine IR.
use super::{
    abi::SignatureHints,
    signature::{CallingConvention, Evidence, FunctionSignature, Location, Parameter},
    types::{Confidence, TypeRef},
};
use crate::{
    ir::{
        inspect::Bundle,
        ssa::{Use, Value},
        Address, Operation, Type, VariableKind,
    },
    AnalysisControl,
};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
};

const MAX_VALUES: usize = 24_000;
const MAX_LINKS: usize = 80_000;
const MAX_UPDATES: usize = 160_000;
const MAX_CLAIMS: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Key {
    Value { function: Address, value: Value },
    Parameter { function: Address, register: String },
    Return { function: Address, register: String },
}
impl Key {
    pub fn function(&self) -> u64 {
        match self {
            Self::Value { function, .. }
            | Self::Parameter { function, .. }
            | Self::Return { function, .. } => function.0,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Claim {
    pub ty: TypeRef,
    pub origin: Address,
    pub instruction: Option<Address>,
    pub evidence: String,
    pub storage_only: bool,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Facts {
    pub claims: Vec<Claim>,
    pub unknown: bool,
    pub overdefined: bool,
}
fn compatible(a: &TypeRef, b: &TypeRef) -> bool {
    match (a, b) {
        (
            TypeRef::Pointer {
                to: a,
                address_bits: aw,
            },
            TypeRef::Pointer {
                to: b,
                address_bits: bw,
            },
        ) => {
            aw == bw
                && (matches!(a.as_ref(), TypeRef::Unknown { .. })
                    || matches!(b.as_ref(), TypeRef::Unknown { .. })
                    || compatible(a, b))
        }
        (
            TypeRef::Int {
                bits: a,
                signed: sa,
            },
            TypeRef::Int {
                bits: b,
                signed: sb,
            },
        ) => a == b && (sa.is_none() || sb.is_none() || sa == sb),
        _ => a == b,
    }
}
impl Facts {
    fn merge(&mut self, incoming: &Self) -> bool {
        let before = (self.claims.len(), self.unknown, self.overdefined);
        self.unknown |= incoming.unknown;
        self.overdefined |= incoming.overdefined;
        if !self.overdefined {
            for claim in &incoming.claims {
                if self
                    .claims
                    .iter()
                    .any(|old| (old.ty == claim.ty || matches!((&old.ty,&claim.ty),(TypeRef::Pointer {to:a,address_bits:aw},TypeRef::Pointer {to:b,address_bits:bw}) if aw==bw && matches!(a.as_ref(),TypeRef::Unknown {..}) && matches!(b.as_ref(),TypeRef::Unknown {..}))) && old.storage_only == claim.storage_only)
                {
                    continue;
                }
                if self.claims.len() == MAX_CLAIMS {
                    self.overdefined = true;
                    break;
                }
                self.claims.push(claim.clone());
            }
        }
        before != (self.claims.len(), self.unknown, self.overdefined)
    }
    pub fn conflicting(&self) -> bool {
        let database = super::types::TypeDatabase::new(64);
        self.overdefined
            || self.claims.iter().enumerate().any(|(i, a)| {
                self.claims.iter().skip(i + 1).any(|b| {
                    !((a.storage_only || b.storage_only)
                        && a.ty.bits(&database) == b.ty.bits(&database))
                        && !compatible(&a.ty, &b.ty)
                })
            })
    }
    pub fn resolved(&self) -> Option<TypeRef> {
        if self.unknown || self.conflicting() {
            return None;
        }
        self.claims
            .iter()
            .max_by_key(|claim| {
                if claim.storage_only {
                    0
                } else {
                    match &claim.ty {
                        TypeRef::Pointer { to, .. }
                            if !matches!(to.as_ref(), TypeRef::Unknown { .. }) =>
                        {
                            3
                        }
                        TypeRef::Int {
                            signed: Some(_), ..
                        } => 2,
                        _ => 1,
                    }
                }
            })
            .map(|claim| claim.ty.clone())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultFact {
    pub key: Key,
    pub facts: Facts,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallSite {
    pub caller: Address,
    pub callee: Address,
    pub instruction: Address,
    pub return_value: Option<Value>,
    pub arguments: Vec<(String, Use)>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowReport {
    pub facts: Vec<ResultFact>,
    pub calls: Vec<CallSite>,
    pub updates: usize,
    pub converged: bool,
    pub truncated: bool,
    pub notes: Vec<String>,
    pub total_facts: usize,
    pub facts_omitted: bool,
}
#[derive(Clone, Copy)]
enum Rule {
    Identity,
    IntegerCast(u16, Option<bool>),
    PointerBits(u16),
    PointerDemand(u16),
    Address(u16),
}
struct Link {
    from: Key,
    to: Key,
    rule: Rule,
}
struct Graph {
    seeds: BTreeMap<Key, Facts>,
    links: Vec<Link>,
    nodes: BTreeSet<Key>,
    required: Vec<(Key, Vec<Key>)>,
    partial: bool,
}
impl Graph {
    fn node(&mut self, key: Key) -> bool {
        if self.nodes.contains(&key) {
            return true;
        }
        if self.nodes.len() == MAX_VALUES {
            self.partial = true;
            return false;
        }
        self.nodes.insert(key);
        true
    }
    fn link(&mut self, from: Key, to: Key, rule: Rule) {
        if self.links.len() == MAX_LINKS || !self.node(from.clone()) || !self.node(to.clone()) {
            self.partial = true;
            return;
        }
        self.links.push(Link { from, to, rule });
    }
    fn seed(&mut self, key: Key, ty: TypeRef, instruction: Option<Address>, evidence: &str) {
        if !supported_type(&ty) {
            self.partial = true;
            return;
        }
        if !ty.valid()
            || matches!(ty, TypeRef::Unknown { .. } | TypeRef::Void)
            || !self.node(key.clone())
        {
            return;
        }
        let storage_only = matches!(
            evidence,
            "integer constant definition"
                | "constant actual argument"
                | "constant return"
                | "loaded scalar storage"
                | "boolean operation"
        );
        self.seeds.entry(key.clone()).or_default().merge(&Facts {
            claims: vec![Claim {
                ty,
                origin: Address(key.function()),
                instruction,
                evidence: evidence.into(),
                storage_only,
            }],
            ..Default::default()
        });
    }
    fn unknown(&mut self, key: Key) {
        if self.node(key.clone()) {
            self.seeds.entry(key).or_default().unknown = true;
        }
    }
}
fn key(function: u64, value: Value) -> Key {
    Key::Value {
        function: Address(function),
        value,
    }
}
fn param(function: u64, register: &str) -> Key {
    Key::Parameter {
        function: Address(function),
        register: register.into(),
    }
}
fn ret(function: u64, register: &str) -> Key {
    Key::Return {
        function: Address(function),
        register: register.into(),
    }
}
fn convention(
    hints: &SignatureHints,
    function: u64,
    default: CallingConvention,
) -> CallingConvention {
    hints
        .get(function)
        .map_or(default, |signature| signature.convention)
}
fn check(control: &dyn AnalysisControl) -> Result<(), String> {
    if control.is_cancelled() {
        Err("type-flow analysis cancelled".into())
    } else {
        Ok(())
    }
}

pub(crate) fn solve(
    bodies: &BTreeMap<u64, Cow<'_, Bundle>>,
    hints: &SignatureHints,
    default: CallingConvention,
    backward: &[super::program::ArgumentEdge],
    control: &dyn AnalysisControl,
) -> Result<FlowReport, String> {
    let mut graph = Graph {
        seeds: BTreeMap::new(),
        links: Vec::new(),
        nodes: BTreeSet::new(),
        required: Vec::new(),
        partial: false,
    };
    let mut report = FlowReport::default();
    let database = super::types::TypeDatabase::new(64);
    let mut observed = BTreeSet::new();
    for (&function, body) in bodies {
        let (registers, partial) = super::abi::observed_registers(&body.ssa, control)?;
        graph.partial |= partial;
        for register in registers {
            observed.insert(super::program::ParameterKey {
                function: Address(function),
                register,
            });
        }
    }
    for (&function, signature) in &hints.by_address {
        for parameter in &signature.parameters {
            if let Location::Register { name } = &parameter.location {
                observed.insert(super::program::ParameterKey {
                    function: Address(function),
                    register: name.clone(),
                });
            }
        }
    }
    let mut demanded: BTreeSet<_> = observed.clone();
    while let Some(current) = demanded.pop_first() {
        check(control)?;
        for edge in backward.iter().filter(|edge| edge.callee == current) {
            if observed.insert(edge.caller.clone()) {
                demanded.insert(edge.caller.clone());
            }
        }
    }
    for (&function, bundle) in bodies {
        check(control)?;
        let ssa = &bundle.ssa;
        let abi = convention(hints, function, default);
        let registers = abi.argument_registers(64);
        let constants: BTreeMap<_, _> = bundle.dataflow.constants.iter().copied().collect();
        let mut return_outputs = BTreeSet::new();
        // Call return locations are correlated with the exact call-generated
        // Unknown definition, never the next arbitrary write of RAX.
        for block in &ssa.blocks {
            for (index, call) in block
                .statements
                .iter()
                .enumerate()
                .filter(|(_, s)| s.op == Operation::Call)
            {
                let target = match call.args.first() {
                    Some(Use::Constant(c)) => Some(c.value.0),
                    _ => super::imports::slot_for_call(block, call, &constants),
                };
                let Some(target) = target else { continue };
                if !bodies.contains_key(&target) && hints.get(target).is_none() {
                    continue;
                }
                let callee_abi = convention(hints, target, default);
                let return_register = callee_abi.return_register(64).unwrap_or("rax");
                let return_value = block
                    .statements
                    .iter()
                    .skip(index + 1)
                    .take_while(|s| {
                        s.source == call.source && matches!(s.op, Operation::Unknown { .. })
                    })
                    .find_map(|s| {
                        s.output
                            .filter(|v| ssa.variables[v.variable].name == return_register)
                    });
                if let Some(value) = return_value {
                    return_outputs.insert(value);
                    graph.link(
                        ret(target, return_register),
                        key(function, value),
                        Rule::Identity,
                    );
                    graph.link(
                        key(function, value),
                        ret(target, return_register),
                        Rule::Identity,
                    );
                }
                let mut arguments = Vec::new();
                for &register in callee_abi.argument_registers(64) {
                    let Some(variable) = ssa
                        .variables
                        .iter()
                        .position(|v| v.kind == VariableKind::Register && v.name == register)
                    else {
                        continue;
                    };
                    let Some(argument) = call.args.get(1 + variable).copied() else {
                        continue;
                    };
                    // An unsupplied callee must actually read this entry
                    // register. Register presence alone is not a formal arg.
                    if !observed.contains(&super::program::ParameterKey {
                        function: Address(target),
                        register: register.into(),
                    }) {
                        continue;
                    }
                    let formal = param(target, register);
                    let formal_bits = hints
                        .get(target)
                        .and_then(|s| {
                            s.parameters.iter().find(|p| {
                                p.location
                                    == (Location::Register {
                                        name: register.into(),
                                    })
                            })
                        })
                        .and_then(|p| p.ty.bits(&database));
                    match argument {
                        Use::Value(value) => {
                            let rule = if formal_bits.is_some_and(|bits| bits < 64) {
                                Rule::IntegerCast(formal_bits.unwrap() as u16, None)
                            } else {
                                Rule::Identity
                            };
                            graph.link(key(function, value), formal.clone(), rule);
                            // A demand on only the low ABI bits does not type
                            // the entire native-width caller register.
                            if formal_bits.is_none_or(|bits| bits == 64) {
                                graph.link(formal.clone(), key(function, value), Rule::Identity);
                            }
                        }
                        Use::Constant(value) => graph.seed(
                            formal,
                            TypeRef::uint(value.ty.width().unwrap_or(64)),
                            Some(call.source),
                            "constant actual argument",
                        ),
                    }
                    arguments.push((register.into(), argument));
                }
                if report.calls.len() < super::program::MAX_EDGES {
                    report.calls.push(CallSite {
                        caller: Address(function),
                        callee: Address(target),
                        instruction: call.source,
                        return_value,
                        arguments,
                    });
                } else {
                    graph.partial = true;
                }
            }
        }
        if let Some(signature) = hints.get(function) {
            for parameter in &signature.parameters {
                if let Location::Register { name } = &parameter.location {
                    graph.seed(
                        param(function, name),
                        parameter.ty.clone(),
                        None,
                        "supplied parameter signature",
                    );
                }
            }
            if let Some(Location::Register { name }) = &signature.return_value.location {
                graph.seed(
                    ret(function, name),
                    signature.return_value.ty.clone(),
                    None,
                    "supplied return signature",
                );
            }
            if matches!(
                signature.return_value.ty,
                TypeRef::Void | TypeRef::Unknown { .. }
            ) {
                graph.unknown(ret(function, abi.return_register(64).unwrap_or("rax")));
            }
        }
        // Imported functions outside the lifted scope still provide bounded
        // assertions; only identities already bound by the import pass arrive.
        for call in report.calls.iter().filter(|call| call.caller.0 == function) {
            if let Some(signature) = hints.get(call.callee.0) {
                for parameter in &signature.parameters {
                    if let Location::Register { name } = &parameter.location {
                        graph.seed(
                            param(call.callee.0, name),
                            parameter.ty.clone(),
                            Some(call.instruction),
                            "supplied callee signature",
                        );
                    }
                }
                if let Some(Location::Register { name }) = &signature.return_value.location {
                    graph.seed(
                        ret(call.callee.0, name),
                        signature.return_value.ty.clone(),
                        Some(call.instruction),
                        "supplied callee return signature",
                    );
                }
                if matches!(
                    signature.return_value.ty,
                    TypeRef::Void | TypeRef::Unknown { .. }
                ) {
                    graph.unknown(ret(
                        call.callee.0,
                        convention(hints, call.callee.0, default)
                            .return_register(64)
                            .unwrap_or("rax"),
                    ));
                }
            }
        }
        let mut incoming_returns = Vec::new();
        for block in &ssa.blocks {
            check(control)?;
            for phi in &block.phis {
                let output = key(function, phi.output);
                let inputs: Vec<_> = phi
                    .incoming
                    .values()
                    .chain(phi.initial.iter())
                    .map(|v| key(function, *v))
                    .collect();
                for input in &inputs {
                    graph.link(input.clone(), output.clone(), Rule::Identity);
                }
                graph.required.push((output, inputs));
            }
            for statement in &block.statements {
                let Some(output) = statement.output else {
                    continue;
                };
                let destination = key(function, output);
                graph.node(destination.clone());
                let ty = ssa.variables[output.variable].ty;
                let width = ty.width().unwrap_or(64);
                match &statement.op {
                    Operation::Unknown { .. } if !return_outputs.contains(&output) => {
                        graph.unknown(destination.clone())
                    }
                    Operation::Copy
                    | Operation::ToBits
                    | Operation::ToAddress
                    | Operation::ZeroExtend
                    | Operation::SignExtend
                    | Operation::Truncate => {
                        let rule = match statement.op {
                            Operation::ZeroExtend => Rule::IntegerCast(width, Some(false)),
                            Operation::SignExtend => Rule::IntegerCast(width, Some(true)),
                            Operation::Truncate => Rule::IntegerCast(width, None),
                            Operation::ToAddress => Rule::Address(width),
                            _ => Rule::Identity,
                        };
                        if let Some(input) = statement.args.first() {
                            match input {
                                Use::Value(value) => {
                                    graph.link(key(function, *value), destination.clone(), rule);
                                    if matches!(
                                        statement.op,
                                        Operation::Copy | Operation::ToBits | Operation::ToAddress
                                    ) && ssa.variables[value.variable].ty.width() == Some(width)
                                    {
                                        graph.link(
                                            destination.clone(),
                                            key(function, *value),
                                            Rule::Identity,
                                        );
                                    }
                                }
                                Use::Constant(constant) => graph.seed(
                                    destination.clone(),
                                    if matches!(ty, Type::Address(_)) {
                                        TypeRef::pointer_to(
                                            TypeRef::unknown(None, "pointee not established"),
                                            width,
                                        )
                                    } else {
                                        TypeRef::uint(width)
                                    },
                                    Some(statement.source),
                                    if matches!(constant.ty, Type::Address(_)) {
                                        "constant address bits"
                                    } else {
                                        "integer constant definition"
                                    },
                                ),
                            }
                        }
                    }
                    Operation::Add | Operation::Sub
                        if matches!(statement.args.get(1), Some(Use::Constant(_))) =>
                    {
                        if let Some(Use::Value(value)) = statement.args.first() {
                            graph.link(
                                key(function, *value),
                                destination.clone(),
                                Rule::PointerBits(width),
                            );
                            graph.link(
                                destination.clone(),
                                key(function, *value),
                                Rule::PointerDemand(width),
                            );
                        }
                    }
                    Operation::Equal | Operation::UnsignedLess | Operation::Parity => graph.seed(
                        destination.clone(),
                        TypeRef::Bool,
                        Some(statement.source),
                        "boolean operation",
                    ),
                    Operation::Load => graph.seed(
                        destination.clone(),
                        TypeRef::int(width),
                        Some(statement.source),
                        "loaded scalar storage",
                    ),
                    _ => {}
                }
                if matches!(ty, Type::Address(_))
                    && !matches!(statement.op, Operation::Unknown { .. })
                {
                    graph.seed(
                        destination.clone(),
                        TypeRef::pointer_to(
                            TypeRef::unknown(None, "pointee not established"),
                            width,
                        ),
                        Some(statement.source),
                        "address interpretation",
                    );
                }
            }
            // A use as an address constrains its exact SSA value, including a
            // call result, without asserting that its concrete value is known.
            for statement in &block.statements {
                let input = match statement.op {
                    Operation::Load | Operation::Store => statement.args.get(1),
                    Operation::ToAddress => statement.args.first(),
                    _ => None,
                };
                if let Some(Use::Value(value)) = input {
                    graph.seed(
                        key(function, *value),
                        TypeRef::pointer_to(TypeRef::unknown(None, "pointee not established"), 64),
                        Some(statement.source),
                        "address-use constraint",
                    );
                }
            }
            if block.terminator.flow.kind == crate::ir::FlowKind::Return {
                let register = abi.return_register(64).unwrap_or("rax");
                if let Some(variable) = ssa
                    .variables
                    .iter()
                    .position(|v| v.kind == VariableKind::Register && v.name == register)
                {
                    let return_key = ret(function, register);
                    match block.terminator.state.get(variable) {
                        Some(Use::Value(value)) => {
                            let input = key(function, *value);
                            graph.link(input.clone(), return_key.clone(), Rule::Identity);
                            graph.link(return_key.clone(), input.clone(), Rule::Identity);
                            incoming_returns.push(input);
                        }
                        Some(Use::Constant(value)) => graph.seed(
                            return_key,
                            TypeRef::uint(value.ty.width().unwrap_or(64)),
                            Some(block.terminator.flow.source),
                            "constant return",
                        ),
                        None => graph.unknown(return_key),
                    }
                }
            }
        }
        if !incoming_returns.is_empty() {
            graph.required.push((
                ret(function, abi.return_register(64).unwrap_or("rax")),
                incoming_returns,
            ));
        }
        // Bind only used entry values to formal parameters. Other incoming
        // registers are unknown, especially an untouched return register.
        for (id, variable) in ssa.variables.iter().enumerate() {
            if variable.kind != VariableKind::Register {
                continue;
            }
            let value = key(
                function,
                Value {
                    variable: id,
                    version: 0,
                },
            );
            if registers.contains(&variable.name.as_str()) {
                graph.link(
                    param(function, &variable.name),
                    value.clone(),
                    Rule::Identity,
                );
                graph.link(value, param(function, &variable.name), Rule::Identity);
            } else {
                graph.unknown(value);
            }
        }
    }
    let (mut facts, updates, converged) = run(&graph, control)?;
    // Unknown phi/return alternatives are audited after evidence reaches its
    // fixed point; a later-discovered claim never has to retract uncertainty.
    let mut unknown_seeds = Vec::new();
    for (output, inputs) in &graph.required {
        if inputs.iter().any(|input| {
            facts
                .get(input)
                .is_none_or(|fact| fact.claims.is_empty() || fact.unknown)
        }) {
            unknown_seeds.push(output.clone());
        }
    }
    if !unknown_seeds.is_empty() {
        for key in unknown_seeds {
            graph.unknown(key);
        }
        let (audited, more, finished) = run(&graph, control)?;
        facts = audited;
        report.updates = updates + more;
        report.converged = converged && finished;
    } else {
        report.updates = updates;
        report.converged = converged;
    }
    report.truncated = graph.partial || !report.converged;
    report.facts = facts
        .into_iter()
        .map(|(key, facts)| ResultFact { key, facts })
        .collect();
    report.total_facts = report.facts.len();
    report.notes.push("Type evidence only; concrete call effects remain unknown. Scalar x86-64 registers, exact copies/casts, integer width conversions and phi/normal-return joins are bounded. Stack, vector/aggregate returns and memory value inference remain unsupported.".into());
    Ok(report)
}

pub(crate) fn supported_type(ty: &TypeRef) -> bool {
    let mut root = ty;
    for _ in 0..16 {
        match root {
            TypeRef::Qualified { target, .. } | TypeRef::Typedef { target, .. } => root = target,
            _ => break,
        }
    }
    if !matches!(
        root,
        TypeRef::Int { .. }
            | TypeRef::Bool
            | TypeRef::Pointer { .. }
            | TypeRef::Enum { .. }
            | TypeRef::Unknown { .. }
            | TypeRef::Void
    ) {
        return false;
    }
    let mut remaining = vec![ty];
    let mut count = 0;
    while let Some(ty) = remaining.pop() {
        count += 1;
        if count > 16 {
            return false;
        }
        match ty {
            TypeRef::Unknown { reason, .. } if reason.len() > 256 => return false,
            TypeRef::Pointer { to, .. } => remaining.push(to),
            TypeRef::Qualified { qualifier, target } => {
                if qualifier.len() > 128 {
                    return false;
                }
                remaining.push(target);
            }
            TypeRef::Typedef { name, target } => {
                if name.len() > 128 {
                    return false;
                }
                remaining.push(target);
            }
            TypeRef::Struct { name } | TypeRef::Union { name } | TypeRef::Named { name }
                if name.len() > 128 =>
            {
                return false
            }
            TypeRef::Function { .. } | TypeRef::Array { .. } => return false,
            TypeRef::Enum { name, underlying } => {
                if name.len() > 128 {
                    return false;
                }
                remaining.push(underlying);
            }
            _ => {}
        }
    }
    true
}

fn transformed(facts: &Facts, rule: Rule) -> Facts {
    let mut result = Facts {
        unknown: facts.unknown,
        overdefined: facts.overdefined,
        ..Default::default()
    };
    for claim in &facts.claims {
        let mut claim = claim.clone();
        match rule {
            Rule::Identity => {}
            Rule::IntegerCast(bits, sign) => match claim.ty {
                TypeRef::Int { signed, .. } => {
                    claim.ty = TypeRef::Int {
                        bits,
                        signed: sign.or(signed),
                    }
                }
                TypeRef::Bool => claim.ty = TypeRef::uint(bits),
                _ => {
                    result.unknown = true;
                    continue;
                }
            },
            Rule::PointerBits(bits) => match &claim.ty {
                TypeRef::Pointer { address_bits, .. } if *address_bits == bits => {}
                TypeRef::Int { .. } => claim.ty = TypeRef::int(bits),
                _ => continue,
            },
            Rule::PointerDemand(bits) => match &claim.ty {
                TypeRef::Pointer { address_bits, .. } if *address_bits == bits => {}
                _ => continue,
            },
            Rule::Address(bits) => match &claim.ty {
                TypeRef::Pointer { address_bits, .. } if *address_bits == bits => {}
                TypeRef::Int { bits: width, .. } if *width == bits => {
                    claim.ty =
                        TypeRef::pointer_to(TypeRef::unknown(None, "address interpretation"), bits)
                }
                _ => {
                    result.unknown = true;
                    continue;
                }
            },
        }
        result.claims.push(claim);
    }
    result
}
fn run(
    graph: &Graph,
    control: &dyn AnalysisControl,
) -> Result<(BTreeMap<Key, Facts>, usize, bool), String> {
    let mut outgoing: BTreeMap<&Key, Vec<&Link>> = BTreeMap::new();
    for link in &graph.links {
        outgoing.entry(&link.from).or_default().push(link);
    }
    let mut facts = graph.seeds.clone();
    let mut queue: BTreeSet<_> = facts.keys().cloned().collect();
    let mut updates = 0;
    while let Some(current) = queue.pop_first() {
        check(control)?;
        let incoming = facts[&current].clone();
        for link in outgoing.get(&current).into_iter().flatten() {
            if updates == MAX_UPDATES {
                return Ok((facts, updates, false));
            }
            if facts
                .entry(link.to.clone())
                .or_default()
                .merge(&transformed(&incoming, link.rule))
            {
                updates += 1;
                queue.insert(link.to.clone());
            }
        }
    }
    Ok((facts, updates, true))
}

pub(crate) fn apply(signature: &mut FunctionSignature, report: &FlowReport) {
    if !report.converged {
        return;
    }
    for result in report
        .facts
        .iter()
        .filter(|result| result.key.function() == signature.function)
    {
        let reason = if result.facts.conflicting() {
            "conflicting interprocedural type evidence"
        } else {
            "unestablished return/argument path"
        };
        let ty = result
            .facts
            .resolved()
            .unwrap_or_else(|| TypeRef::unknown(Some(64), reason));
        let evidence: Vec<_> = result
            .facts
            .claims
            .iter()
            .map(|claim| Evidence {
                kind: claim.evidence.clone(),
                address: claim.instruction.map(|address| address.0),
                detail: format!(
                    "type evidence from {}: {}",
                    claim.origin,
                    claim.ty.display()
                ),
            })
            .collect();
        match &result.key {
            Key::Return { .. } => {
                let both_integer = matches!((&signature.return_value.ty,&ty),(TypeRef::Int {bits:a,..},TypeRef::Int {bits:b,..}) if a==b);
                if result.facts.conflicting()
                    || (!both_integer
                        && (result.facts.resolved().is_some()
                            || matches!(signature.return_value.ty, TypeRef::Unknown { .. })))
                {
                    signature.return_value.ty = ty;
                }
                signature.return_value.location = Some(Location::Register {
                    name: signature
                        .convention
                        .return_register(64)
                        .unwrap_or("rax")
                        .into(),
                });
                signature.return_value.confidence =
                    if matches!(signature.return_value.ty, TypeRef::Unknown { .. }) {
                        Confidence::Unknown
                    } else {
                        Confidence::Low
                    };
                signature.return_value.evidence.extend(evidence);
            }
            Key::Parameter { register, .. } if !result.facts.claims.is_empty() => {
                let Some(index) = signature
                    .convention
                    .argument_registers(64)
                    .iter()
                    .position(|name| *name == register)
                else {
                    continue;
                };
                if let Some(existing) = signature.parameters.iter_mut().find(|p| p.index == index) {
                    if existing.confidence != Confidence::Unknown || existing.uses == 0 {
                        existing.ty = ty;
                        existing.confidence = if result.facts.resolved().is_some() {
                            Confidence::Low
                        } else {
                            Confidence::Unknown
                        };
                    }
                    existing.evidence.extend(evidence);
                } else {
                    signature.parameters.push(Parameter {
                        index,
                        name: format!("a{index}"),
                        location: Location::Register {
                            name: register.clone(),
                        },
                        width: 64,
                        ty,
                        confidence: if result.facts.resolved().is_some() {
                            Confidence::Low
                        } else {
                            Confidence::Unknown
                        },
                        uses: 1,
                        evidence,
                    });
                }
            }
            _ => {}
        }
        if result.facts.conflicting() {
            signature.conflicts.push(format!(
                "{:?}: conflicting interprocedural type evidence",
                result.key
            ));
        }
    }
    signature
        .parameters
        .sort_by_key(|parameter| parameter.index);
}

pub(crate) fn apply_values(
    function: u64,
    values: &mut [super::types::SsaInferredType],
    report: &FlowReport,
) {
    if !report.converged {
        return;
    }
    let index: BTreeMap<_, _> = report
        .facts
        .iter()
        .filter_map(|result| match result.key {
            Key::Value {
                function: owner,
                value,
            } if owner.0 == function => Some((value, &result.facts)),
            _ => None,
        })
        .collect();
    for value in values {
        let Some(facts) = index.get(&value.value) else {
            continue;
        };
        if facts.claims.is_empty() {
            continue;
        }
        value.ty = facts.resolved().unwrap_or_else(|| {
            TypeRef::unknown(
                value.storage.width(),
                "conflicting or unestablished interprocedural value",
            )
        });
        value.confidence = if facts.resolved().is_some() {
            Confidence::Low
        } else {
            Confidence::Unknown
        };
        for claim in &facts.claims {
            value.constraints.push(super::types::TypeConstraint {
                kind: claim.evidence.clone(),
                source: claim.instruction.map(|a| a.0),
                detail: format!("{}: {}", claim.origin, claim.ty.display()),
            });
        }
        if facts.conflicting() {
            value
                .conflicts
                .push("conflicting cross-function type evidence for this SSA definition".into());
        }
    }
}
