//! Calling-convention and parameter recovery from lifted IR.
//!
//! Recovery is evidence based: it reports what the function actually reads and
//! writes, labels ABI slots that were never observed, and never invents a
//! parameter list from a guess about the source language.
use super::signature::{
    CallingConvention, Evidence, FunctionSignature, Location, Parameter, ReturnValue,
};
use super::stack::StackFrame;
use super::types::{Confidence, InferredType, TypeConstraint, TypeRef};
use crate::ir::inspect::Bundle;
use crate::ir::ssa::{SsaFunction, Use, Value};
use crate::ir::{Operation, Type, VariableKind};
use crate::{LoadedBinary, ProgramAnalysis};
use iced_x86::{Decoder, DecoderOptions, Mnemonic};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_PARAMETERS: usize = 64;
const MAX_TAINT_VALUES: usize = 20_000;
const MAX_ROOTS_PER_VALUE: usize = 32;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureHints {
    pub by_address: BTreeMap<u64, FunctionSignature>,
}
impl SignatureHints {
    pub fn insert(&mut self, signature: FunctionSignature) {
        self.by_address.insert(signature.function, signature);
    }
    pub fn get(&self, address: u64) -> Option<&FunctionSignature> {
        self.by_address.get(&address)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureRecovery {
    pub signature: FunctionSignature,
    /// Type evidence for values that are not parameters, mostly values passed to
    /// known callees. Merged into the function type report by the orchestrator.
    pub value_constraints: BTreeMap<usize, Vec<TypeConstraint>>,
    pub notes: Vec<String>,
}

#[derive(Clone)]
struct Def {
    op: Option<Operation>,
    args: Vec<Use>,
}

struct RootEvidence {
    roots: BTreeSet<usize>,
    use_counts: BTreeMap<usize, (usize, u64)>,
    pointer_roots: BTreeSet<usize>,
    zero_compare_roots: BTreeSet<usize>,
    register_names: BTreeMap<usize, String>,
    truncated: bool,
}

pub fn recover(
    binary: &LoadedBinary,
    analysis: &ProgramAnalysis,
    bundle: &Bundle,
    frame: &StackFrame,
    hints: &SignatureHints,
) -> Result<SignatureRecovery, String> {
    recover_with_control(binary, analysis, bundle, frame, hints, &())
}

pub fn recover_with_control(
    binary: &LoadedBinary,
    analysis: &ProgramAnalysis,
    bundle: &Bundle,
    frame: &StackFrame,
    hints: &SignatureHints,
    control: &dyn crate::AnalysisControl,
) -> Result<SignatureRecovery, String> {
    check_cancelled(control)?;
    let ssa = &bundle.ssa;
    if !ssa.variables.iter().any(|variable| variable.is_register()) {
        return Err("ABI recovery requires architectural registers".into());
    }
    let bits = ssa.address_width;
    let evidence = collect_roots(ssa, control)?;
    let platform = platform_default(binary, bits);
    let cleanup = return_cleanup(binary, analysis, ssa);
    let (convention, convention_confidence, mut convention_evidence, mut conflicts) =
        choose_convention(bits, platform, &evidence, cleanup);
    let mut notes = vec![
        "Parameter locations follow the selected convention; values that were never read are reported as unobserved slots."
            .into(),
        "Register arguments are recognized from reads of the entry value in the lifted IR."
            .into(),
    ];
    if hints.by_address.is_empty() {
        notes.push(
            "No callee signatures were supplied; interprocedural argument hints were not applied."
                .into(),
        );
    }
    if evidence.truncated {
        notes.push("Register-root recovery reached a depth or value budget; parameter evidence is incomplete.".into());
    }
    let constants = bundle.dataflow.constants.iter().copied().collect();
    let hints_constraints = call_site_constraints(ssa, hints, &constants, control)?;
    let mut parameters: BTreeMap<usize, Parameter> = BTreeMap::new();
    let argument_registers = convention.argument_registers(bits);

    let mut max_index = None;
    for (index, register) in argument_registers.iter().enumerate() {
        check_cancelled(control)?;
        let Some(variable) = register_index(ssa, register) else {
            conflicts.push(format!(
                "convention register {register} is not present in this function"
            ));
            continue;
        };
        let observed = evidence.use_counts.get(&variable).copied().or_else(|| {
            hints_constraints
                .by_variable
                .get(&variable)
                .and_then(|hints| hints.first().map(|hint| (hints.len(), hint.source)))
        });
        let Some((uses, source)) = observed else {
            continue;
        };
        let ty = parameter_type(
            ssa,
            variable,
            &evidence,
            hints_constraints
                .by_variable
                .get(&variable)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
        );
        if let TypeRef::Unknown { reason, .. } = &ty {
            conflicts.push(format!("{register}: {reason}"));
        }
        let mut parameter_evidence = vec![Evidence {
            kind: "incomingRegister".into(),
            address: Some(source),
            detail: format!("entry value of {register} is read by the function"),
        }];
        for hint in hints_constraints
            .by_variable
            .get(&variable)
            .into_iter()
            .flatten()
        {
            parameter_evidence.push(Evidence {
                kind: hint.kind.clone(),
                address: Some(hint.source),
                detail: hint.detail.clone(),
            });
        }
        let confidence = if matches!(ty, TypeRef::Unknown { .. }) {
            Confidence::Unknown
        } else if evidence.pointer_roots.contains(&variable)
            || evidence.zero_compare_roots.contains(&variable)
            || uses >= 2
        {
            Confidence::Medium
        } else {
            Confidence::Low
        };
        parameters.insert(
            index,
            Parameter {
                index,
                name: format!("a{index}"),
                location: Location::Register {
                    name: (*register).to_string(),
                },
                ty,
                width: ssa.variables[variable].ty.width().unwrap_or(bits),
                confidence,
                uses,
                evidence: parameter_evidence,
            },
        );
        max_index = Some(index);
        convention_evidence.push(Evidence {
            kind: "incomingRegister".into(),
            address: Some(source),
            detail: format!("{register} is read before being defined"),
        });
    }

    let incoming = frame
        .slots
        .iter()
        .filter(|slot| slot.kind == "incomingArgument" && slot.reads > 0 && slot.writes == 0)
        .map(|slot| (slot.offset, Some(slot.width)))
        .collect::<BTreeMap<_, _>>();
    for (offset, width) in incoming {
        let Some(index) = stack_parameter_index(convention, bits, offset) else {
            continue;
        };
        if index >= MAX_PARAMETERS || parameters.contains_key(&index) {
            continue;
        }
        let width = width.unwrap_or(if bits == 64 { 64 } else { 32 });
        parameters.insert(
            index,
            Parameter {
                index,
                name: format!("a{index}"),
                location: Location::Stack { offset, width },
                ty: TypeRef::Int {
                    bits: width,
                    signed: None,
                },
                width,
                confidence: Confidence::Low,
                uses: 1,
                evidence: vec![Evidence {
                    kind: "incomingStackSlot".into(),
                    address: None,
                    detail: format!(
                        "stack access at entry-relative offset {offset:#x}; width only, value type is not inferred"
                    ),
                }],
            },
        );
        max_index = Some(max_index.map_or(index, |current| current.max(index)));
    }
    if let Some(max) = max_index {
        for index in 0..=max.min(MAX_PARAMETERS - 1) {
            parameters.entry(index).or_insert_with(|| Parameter {
                index,
                name: format!("a{index}"),
                location: Location::Unknown {
                    reason: "ABI argument slot".into(),
                },
                ty: TypeRef::unknown(None, "parameter slot is never read"),
                width: 0,
                confidence: Confidence::Unknown,
                uses: 0,
                evidence: vec![Evidence {
                    kind: "unobservedAbiSlot".into(),
                    address: None,
                    detail: "the convention reserves this slot but the function never reads it"
                        .into(),
                }],
            });
        }
    }
    let parameters: Vec<_> = parameters.into_values().collect();
    let return_value = recover_return(ssa, &bundle.raw, control)?;
    if convention == CallingConvention::Unknown {
        notes.push(
            "The calling convention could not be established from observed register use.".into(),
        );
    }
    if cleanup.is_some_and(|bytes| bytes > 0) && bits == 64 {
        conflicts.push("a callee stack cleanup immediate was observed in x64 code".into());
        notes.push("The x64 cleanup immediate is retained as evidence but is not part of the Win64 or SysV64 conventions.".into());
    }
    let name = analysis
        .function_name(bundle.raw.entry.0)
        .unwrap_or_else(|| {
            format!(
                "sub_{}",
                crate::format_address(bundle.raw.entry.0).trim_start_matches("0x")
            )
        });
    let signature = FunctionSignature {
        function: bundle.raw.entry.0,
        name,
        convention,
        convention_confidence,
        parameters,
        return_value,
        variadic: None,
        stack_parameter_bytes: if matches!(
            convention,
            CallingConvention::Stdcall | CallingConvention::Fastcall | CallingConvention::Thiscall
        ) {
            u32::from(cleanup.unwrap_or(0))
        } else {
            0
        },
        caller_observed_arguments: None,
        user_override: false,
        evidence: convention_evidence,
        conflicts,
    };
    Ok(SignatureRecovery {
        signature,
        value_constraints: hints_constraints.value_constraints,
        notes,
    })
}

trait VariableExt {
    fn is_register(&self) -> bool;
}
impl VariableExt for crate::ir::Variable {
    fn is_register(&self) -> bool {
        self.kind == VariableKind::Register && matches!(self.ty, Type::Bits(_) | Type::Address(_))
    }
}

fn platform_default(binary: &LoadedBinary, bits: u16) -> CallingConvention {
    if bits == 64 {
        match binary.analysis().format.as_str() {
            "PE" => CallingConvention::Win64,
            "ELF" | "Mach-O" => CallingConvention::SysV64,
            _ => CallingConvention::SysV64,
        }
    } else {
        CallingConvention::Cdecl
    }
}

fn choose_convention(
    bits: u16,
    platform: CallingConvention,
    evidence: &RootEvidence,
    cleanup: Option<u16>,
) -> (CallingConvention, Confidence, Vec<Evidence>, Vec<String>) {
    let mut evidence_list = vec![Evidence {
        kind: "platformDefault".into(),
        address: None,
        detail: format!("container format suggests {}", platform.name()),
    }];
    let mut conflicts = Vec::new();
    if bits == 64 {
        // RCX/R8/R9 are also System V arguments, and RDI/RSI can be
        // preserved nonvolatile values in Win64. Entry reads cannot prove an
        // alternate ABI, so retain the format default with explicit evidence.
        evidence_list.push(Evidence {
            kind: "registerAmbiguity".into(), address: None,
            detail: "x64 entry-register reads alone cannot distinguish an alternate ABI from saved or unused registers".into(),
        });
        return (platform, Confidence::Low, evidence_list, conflicts);
    }
    if let Some(bytes) = cleanup {
        if bytes > 0 {
            let fast = ["ecx", "edx"].iter().all(|name| {
                evidence
                    .use_counts
                    .keys()
                    .any(|id| evidence.register_names.get(id).map(String::as_str) == Some(*name))
            });
            let this = evidence
                .use_counts
                .keys()
                .any(|id| evidence.register_names.get(id).map(String::as_str) == Some("ecx"));
            let convention = if fast {
                CallingConvention::Fastcall
            } else if this {
                CallingConvention::Thiscall
            } else {
                CallingConvention::Stdcall
            };
            evidence_list.push(Evidence {
                kind: "calleeCleanup".into(),
                address: None,
                detail: format!("ret {bytes} indicates callee-cleaned stack arguments"),
            });
            return (convention, Confidence::Medium, evidence_list, conflicts);
        }
        evidence_list.push(Evidence {
            kind: "calleeCleanup".into(),
            address: None,
            detail: "ret without an immediate indicates caller-cleaned arguments".into(),
        });
        return (
            CallingConvention::Cdecl,
            Confidence::Medium,
            evidence_list,
            conflicts,
        );
    }
    conflicts
        .push("no return instruction was observed; stack cleanup cannot be established".into());
    (
        CallingConvention::Cdecl,
        Confidence::Low,
        evidence_list,
        conflicts,
    )
}

fn collect_roots(
    ssa: &SsaFunction,
    control: &dyn crate::AnalysisControl,
) -> Result<RootEvidence, String> {
    let mut defs: BTreeMap<Value, Def> = BTreeMap::new();
    for block in &ssa.blocks {
        check_cancelled(control)?;
        for phi in &block.phis {
            let mut args = phi
                .incoming
                .values()
                .copied()
                .map(Use::Value)
                .collect::<Vec<_>>();
            if let Some(initial) = phi.initial {
                args.push(Use::Value(initial));
            }
            defs.insert(phi.output, Def { op: None, args });
        }
        for statement in &block.statements {
            check_cancelled(control)?;
            if let Some(output) = statement.output {
                defs.insert(
                    output,
                    Def {
                        op: Some(statement.op.clone()),
                        args: statement.args.clone(),
                    },
                );
            }
        }
    }
    let mut evidence = RootEvidence {
        roots: BTreeSet::new(),
        use_counts: BTreeMap::new(),
        pointer_roots: BTreeSet::new(),
        zero_compare_roots: BTreeSet::new(),
        register_names: ssa
            .variables
            .iter()
            .enumerate()
            .filter(|(_, v)| v.is_register())
            .map(|(id, v)| (id, v.name.clone()))
            .collect(),
        truncated: false,
    };
    let mut resolver = RootResolver {
        defs,
        memo: BTreeMap::new(),
        budget: MAX_TAINT_VALUES,
        truncated: false,
    };
    for block in &ssa.blocks {
        check_cancelled(control)?;
        for statement in &block.statements {
            check_cancelled(control)?;
            if statement.output.is_some_and(|output| {
                ssa.variables[output.variable].kind == VariableKind::Temporary
            }) && !matches!(
                statement.op,
                Operation::Load | Operation::Store | Operation::Call
            ) {
                // Addressing/alias temporaries are implementation details. Count
                // their roots only when the completed value is consumed.
                continue;
            }
            let args: &[Use] = match &statement.op {
                Operation::Barrier { .. } => continue,
                Operation::Call => &statement.args[..statement.args.len().min(1)],
                _ => &statement.args,
            };
            if matches!(
                statement.op,
                Operation::Xor | Operation::Sub | Operation::Equal | Operation::UnsignedLess
            ) && args.len() == 2
                && args[0] == args[1]
            {
                continue;
            }
            let mut roots = BTreeSet::new();
            if let Some(output) = statement.output.filter(|_| {
                !matches!(
                    statement.op,
                    Operation::Load | Operation::Store | Operation::Call
                )
            }) {
                roots.extend(resolver.roots(output, 0));
            } else {
                for arg in args {
                    if let Use::Value(value) = arg {
                        roots.extend(resolver.roots(*value, 0));
                    }
                }
            }
            for root in &roots {
                evidence.roots.insert(*root);
            }
            let address_position = match &statement.op {
                Operation::Load | Operation::Store => Some(1),
                Operation::Call => Some(0),
                _ => None,
            };
            if let Some(position) = address_position {
                if let Some(Use::Value(value)) = args.get(position) {
                    evidence
                        .pointer_roots
                        .extend(resolver.address_roots(*value, 0));
                }
            }
            let compares_zero = matches!(&statement.op, Operation::Equal | Operation::UnsignedLess)
                && args
                    .iter()
                    .any(|arg| matches!(arg, Use::Constant(c) if c.value.0 == 0));
            if compares_zero {
                evidence.zero_compare_roots.extend(roots.iter().copied());
            }
            for root in roots {
                let entry = evidence
                    .use_counts
                    .entry(root)
                    .or_insert((0, statement.source.0));
                entry.0 += 1;
                entry.1 = entry.1.min(statement.source.0);
            }
        }
        if let Some(Use::Value(value)) = block.terminator.value {
            evidence.roots.extend(resolver.roots(value, 0));
        }
    }
    evidence.truncated = resolver.truncated;
    Ok(evidence)
}

struct RootResolver {
    defs: BTreeMap<Value, Def>,
    memo: BTreeMap<Value, BTreeSet<usize>>,
    budget: usize,
    truncated: bool,
}
impl RootResolver {
    fn address_roots(&mut self, value: Value, depth: usize) -> BTreeSet<usize> {
        if depth > 64 || self.budget == 0 {
            self.truncated = true;
            return BTreeSet::new();
        }
        self.budget -= 1;
        if value.version == 0 {
            return BTreeSet::from([value.variable]);
        }
        let Some(def) = self.defs.get(&value) else {
            return BTreeSet::new();
        };
        let next = match def.op {
            Some(Operation::Copy | Operation::ToAddress | Operation::ToBits) => {
                def.args.first().copied()
            }
            Some(Operation::Add | Operation::Sub)
                if matches!(def.args.get(1), Some(Use::Constant(_))) =>
            {
                def.args.first().copied()
            }
            Some(Operation::Add) if matches!(def.args.first(), Some(Use::Constant(_))) => {
                def.args.get(1).copied()
            }
            _ => None,
        };
        match next {
            Some(Use::Value(value)) => self.address_roots(value, depth + 1),
            _ => BTreeSet::new(),
        }
    }

    fn roots(&mut self, value: Value, depth: usize) -> BTreeSet<usize> {
        if value.version == 0 {
            return BTreeSet::from([value.variable]);
        }
        if let Some(cached) = self.memo.get(&value) {
            return cached.clone();
        }
        if depth > 64 || self.budget == 0 {
            self.truncated = true;
            return BTreeSet::new();
        }
        self.budget -= 1;
        let def = self.defs.get(&value);
        if def.is_some_and(|def| {
            matches!(
                def.op,
                Some(Operation::Xor | Operation::Sub | Operation::Equal | Operation::UnsignedLess)
            ) && def.args.len() == 2
                && def.args[0] == def.args[1]
        }) {
            self.memo.insert(value, BTreeSet::new());
            return BTreeSet::new();
        }
        let args = def.map(|def| def.args.clone()).unwrap_or_default();
        let mut roots = BTreeSet::new();
        for arg in args {
            if let Use::Value(next) = arg {
                roots.extend(self.roots(next, depth + 1));
                if roots.len() >= MAX_ROOTS_PER_VALUE {
                    self.truncated = true;
                    break;
                }
            }
        }
        self.memo.insert(value, roots.clone());
        roots
    }
}

fn register_index(ssa: &SsaFunction, name: &str) -> Option<usize> {
    ssa.variables
        .iter()
        .position(|variable| variable.kind == VariableKind::Register && variable.name == name)
}

fn parameter_type(
    ssa: &SsaFunction,
    variable: usize,
    evidence: &RootEvidence,
    hints: &[HintConstraint],
) -> TypeRef {
    let mut supplied = hints.iter().filter_map(|hint| hint.ty.as_ref());
    if let Some(first) = supplied.next() {
        if supplied.any(|other| other != first) {
            return TypeRef::unknown(
                ssa.variables[variable].ty.width(),
                "callee parameter type evidence conflicts",
            );
        }
        return first.clone();
    }
    let width = ssa.variables[variable]
        .ty
        .width()
        .unwrap_or(ssa.address_width);
    if evidence.pointer_roots.contains(&variable) {
        return TypeRef::pointer_to(
            TypeRef::unknown(None, "pointee type is not inferred"),
            ssa.address_width,
        );
    }
    TypeRef::Int {
        bits: width,
        signed: None,
    }
}

fn recover_return(
    ssa: &SsaFunction,
    _raw: &crate::ir::Function,
    control: &dyn crate::AnalysisControl,
) -> Result<ReturnValue, String> {
    let ret = register_index(ssa, "rax")
        .or_else(|| register_index(ssa, "eax"))
        .unwrap_or(0);
    let width = ssa
        .variables
        .get(ret)
        .and_then(|variable| variable.ty.width());
    let returns = ssa
        .blocks
        .iter()
        .filter(|block| block.terminator.flow.kind == crate::ir::FlowKind::Return)
        .collect::<Vec<_>>();
    let mut definitions = BTreeMap::new();
    for block in &ssa.blocks {
        check_cancelled(control)?;
        for statement in &block.statements {
            if let Some(output) = statement.output {
                definitions.insert(
                    output,
                    Def {
                        op: Some(statement.op.clone()),
                        args: statement.args.clone(),
                    },
                );
            }
        }
        for phi in &block.phis {
            let mut args = phi
                .incoming
                .values()
                .copied()
                .map(Use::Value)
                .collect::<Vec<_>>();
            args.extend(phi.initial.map(Use::Value));
            definitions.insert(phi.output, Def { op: None, args });
        }
    }
    // Unknown and entry-RAX provenance must survive copies and phi joins.
    // Cycles/depth bounds are conservative; they cannot manufacture a type.
    fn tracked(
        value: Value,
        ret: usize,
        defs: &BTreeMap<Value, Def>,
        active: &mut BTreeSet<Value>,
        budget: &mut usize,
    ) -> bool {
        if *budget == 0 || active.len() >= 64 {
            return false;
        }
        *budget -= 1;
        if value.version == 0 {
            return value.variable != ret;
        }
        if !active.insert(value) {
            return false;
        }
        let result = defs.get(&value).is_some_and(|def| {
            if matches!(
                def.op,
                Some(Operation::Unknown { .. } | Operation::Barrier { .. } | Operation::Call)
            ) {
                return false;
            }
            if matches!(
                def.op,
                Some(Operation::Xor | Operation::Sub | Operation::Equal | Operation::UnsignedLess)
            ) && def.args.len() == 2
                && def.args[0] == def.args[1]
            {
                return true;
            }
            def.args.iter().all(|arg| match arg {
                Use::Constant(_) => true,
                Use::Value(value) => tracked(*value, ret, defs, active, budget),
            })
        });
        active.remove(&value);
        result
    }
    let mut evidence = Vec::new();
    let mut all_tracked = !returns.is_empty();
    for block in &returns {
        check_cancelled(control)?;
        let value = block.terminator.state.get(ret);
        let mut budget = MAX_TAINT_VALUES;
        let is_tracked = match value {
            Some(Use::Value(value)) => {
                tracked(*value, ret, &definitions, &mut BTreeSet::new(), &mut budget)
            }
            Some(Use::Constant(_)) => true,
            None => false,
        };
        all_tracked &= is_tracked;
        evidence.push(Evidence {
            kind: if is_tracked { "returnRegister" } else { "unknownReturn" }.into(),
            address: Some(block.terminator.flow.source.0),
            detail: if is_tracked { "a return-register value is defined on this path" }
                else { "return register is unchanged, untracked, or depends on a call/unsupported effect; return type is unknown" }.into(),
        });
    }
    if returns.is_empty() {
        evidence.push(Evidence { kind: "noReturnObserved".into(), address: None,
            detail: "no return instruction was recovered; neither a void return type nor nonreturning behavior is established".into() });
    }
    Ok(ReturnValue {
        location: (!returns.is_empty()).then(|| Location::Register {
            name: if ssa.address_width == 64 {
                "rax"
            } else {
                "eax"
            }
            .into(),
        }),
        ty: if all_tracked {
            TypeRef::Int {
                bits: width.unwrap_or(ssa.address_width),
                signed: None,
            }
        } else {
            TypeRef::unknown(
                width,
                "return type is not established on every observed return path",
            )
        },
        confidence: if all_tracked {
            Confidence::Medium
        } else {
            Confidence::Low
        },
        evidence,
    })
}

#[derive(Clone, Debug)]
struct HintConstraint {
    kind: String,
    source: u64,
    detail: String,
    ty: Option<TypeRef>,
}
#[derive(Default)]
struct HintConstraints {
    by_variable: BTreeMap<usize, Vec<HintConstraint>>,
    value_constraints: BTreeMap<usize, Vec<TypeConstraint>>,
}

fn call_site_constraints(
    ssa: &SsaFunction,
    hints: &SignatureHints,
    constants: &BTreeMap<Value, crate::ir::Constant>,
    control: &dyn crate::AnalysisControl,
) -> Result<HintConstraints, String> {
    let mut result = HintConstraints::default();
    for block in &ssa.blocks {
        check_cancelled(control)?;
        for statement in &block.statements {
            check_cancelled(control)?;
            if statement.op != Operation::Call {
                continue;
            }
            let target = match statement.args.first() {
                Some(Use::Constant(target)) => Some(target.value.0),
                _ => super::imports::slot_for_call(block, statement, constants),
            };
            let Some(signature) = target.and_then(|target| hints.get(target)) else {
                continue;
            };
            for parameter in &signature.parameters {
                let Location::Register { name } = &parameter.location else {
                    continue;
                };
                let Some(variable) = register_index(ssa, name) else {
                    continue;
                };
                let Some(Use::Value(value)) = statement.args.get(1 + variable) else {
                    continue;
                };
                let ty = (parameter.confidence != Confidence::Unknown
                    && !matches!(&parameter.ty, TypeRef::Unknown { .. }))
                .then(|| parameter.ty.clone());
                let constraint = HintConstraint {
                    kind: "calleeParameter".into(),
                    source: statement.source.0,
                    detail: format!(
                        "passed to {} as parameter {} ({})",
                        signature.name,
                        parameter.index,
                        parameter.ty.display()
                    ),
                    ty,
                };
                if value.version == 0 {
                    result
                        .by_variable
                        .entry(value.variable)
                        .or_default()
                        .push(constraint.clone());
                } else {
                    result
                        .value_constraints
                        .entry(value.variable)
                        .or_default()
                        .push(TypeConstraint {
                            kind: "calleeParameter".into(),
                            source: Some(statement.source.0),
                            detail: constraint.detail.clone(),
                        });
                }
                if let Some(ty) = constraint.ty {
                    result
                        .value_constraints
                        .entry(value.variable)
                        .or_default()
                        .push(TypeConstraint {
                            kind: "calleeParameterType".into(),
                            source: Some(statement.source.0),
                            detail: format!("{}: {}", signature.name, ty.display()),
                        });
                }
            }
        }
    }
    Ok(result)
}

fn stack_parameter_index(convention: CallingConvention, bits: u16, offset: i64) -> Option<usize> {
    let word = i64::from(bits / 8);
    match convention {
        CallingConvention::Win64 if bits == 64 => {
            let start = word + 0x20;
            (offset >= start)
                .then(|| offset - start)
                .filter(|delta| delta % word == 0)
                .map(|delta| 4 + (delta / word) as usize)
        }
        CallingConvention::SysV64 if bits == 64 => (offset >= word)
            .then(|| offset - word)
            .filter(|delta| delta % word == 0)
            .map(|delta| 6 + (delta / word) as usize),
        CallingConvention::Fastcall if bits == 32 => (offset >= word)
            .then(|| offset - word)
            .filter(|delta| delta % word == 0)
            .map(|delta| 2 + (delta / word) as usize),
        CallingConvention::Thiscall if bits == 32 => (offset >= word)
            .then(|| offset - word)
            .filter(|delta| delta % word == 0)
            .map(|delta| 1 + (delta / word) as usize),
        CallingConvention::Cdecl | CallingConvention::Stdcall if bits == 32 => (offset >= word)
            .then(|| offset - word)
            .filter(|delta| delta % word == 0)
            .map(|delta| (delta / word) as usize),
        _ => None,
    }
}

fn return_cleanup(
    binary: &LoadedBinary,
    analysis: &ProgramAnalysis,
    ssa: &SsaFunction,
) -> Option<u16> {
    let mut cleanups = BTreeSet::new();
    for block in &ssa.blocks {
        if block.terminator.flow.kind != crate::ir::FlowKind::Return {
            continue;
        }
        let address = block.terminator.flow.source.0;
        let Some(length) = analysis
            .instructions
            .get(&address)
            .map(|i| i.length as usize)
        else {
            continue;
        };
        let Some(bytes) = binary.bytes_at_address(address, length) else {
            continue;
        };
        let instruction = Decoder::with_ip(
            ssa.address_width as u32,
            bytes,
            address,
            DecoderOptions::NONE,
        )
        .decode();
        if instruction.mnemonic() == Mnemonic::Ret {
            if instruction.op_count() == 1 {
                let value = instruction.immediate16();
                cleanups.insert(value);
            } else {
                cleanups.insert(0);
            }
        }
    }
    (cleanups.len() == 1).then(|| *cleanups.first().expect("one cleanup"))
}

/// Merge call-site constraints into the report produced by scalar type
/// inference. Existing entries gain evidence; no scalar type is replaced
/// silently unless the only inference was an unsized unknown.
pub fn merge_value_constraints(
    inference: &mut super::types::TypeInference,
    constraints: &BTreeMap<usize, Vec<TypeConstraint>>,
) {
    for (variable, extra) in constraints {
        if let Some(entry) = inference
            .variables
            .iter_mut()
            .find(|entry| entry.variable_id == *variable)
        {
            entry.constraints.extend(extra.iter().cloned());
        } else {
            inference.variables.push(InferredType {
                variable: format!("v{variable}"),
                variable_id: *variable,
                ty: TypeRef::unknown(None, "type evidence comes from a callee signature"),
                confidence: Confidence::Low,
                constraints: extra.clone(),
                conflicts: vec![],
            });
        }
    }
    inference.variables.sort_by(|a, b| {
        a.variable
            .cmp(&b.variable)
            .then(a.variable_id.cmp(&b.variable_id))
    });
}

fn check_cancelled(control: &dyn crate::AnalysisControl) -> Result<(), String> {
    if control.is_cancelled() {
        Err("ABI recovery cancelled".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_parameter_indices_follow_the_selected_convention() {
        assert_eq!(
            stack_parameter_index(CallingConvention::Win64, 64, 0x28),
            Some(4)
        );
        assert_eq!(
            stack_parameter_index(CallingConvention::Win64, 64, 0x30),
            Some(5)
        );
        assert_eq!(
            stack_parameter_index(CallingConvention::Win64, 64, 0x20),
            None
        );
        assert_eq!(
            stack_parameter_index(CallingConvention::Win64, 64, 0x2c),
            None
        );
        assert_eq!(
            stack_parameter_index(CallingConvention::SysV64, 64, 8),
            Some(6)
        );
        assert_eq!(
            stack_parameter_index(CallingConvention::SysV64, 64, 16),
            Some(7)
        );
        assert_eq!(
            stack_parameter_index(CallingConvention::SysV64, 64, 4),
            None
        );
        assert_eq!(
            stack_parameter_index(CallingConvention::Cdecl, 32, 4),
            Some(0)
        );
        assert_eq!(
            stack_parameter_index(CallingConvention::Cdecl, 32, 12),
            Some(2)
        );
        assert_eq!(
            stack_parameter_index(CallingConvention::Stdcall, 32, 8),
            Some(1)
        );
        assert_eq!(
            stack_parameter_index(CallingConvention::Fastcall, 32, 4),
            Some(2)
        );
        assert_eq!(
            stack_parameter_index(CallingConvention::Fastcall, 32, 8),
            Some(3)
        );
        assert_eq!(
            stack_parameter_index(CallingConvention::Thiscall, 32, 4),
            Some(1)
        );
        assert_eq!(stack_parameter_index(CallingConvention::Win64, 32, 8), None);
    }

    #[test]
    fn root_resolution_terminates_on_cycles_and_respects_budget() {
        let first = Value {
            variable: 0,
            version: 1,
        };
        let second = Value {
            variable: 1,
            version: 1,
        };
        let defs = BTreeMap::from([
            (
                first,
                Def {
                    op: None,
                    args: vec![Use::Value(second)],
                },
            ),
            (
                second,
                Def {
                    op: None,
                    args: vec![Use::Value(first)],
                },
            ),
        ]);
        let mut resolver = RootResolver {
            defs,
            memo: BTreeMap::new(),
            budget: 8,
            truncated: false,
        };
        assert!(resolver.roots(first, 0).is_empty());
        assert!(resolver.budget < 8);
    }
}
