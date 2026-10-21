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
}

pub fn recover(
    binary: &LoadedBinary,
    analysis: &ProgramAnalysis,
    bundle: &Bundle,
    frame: &StackFrame,
    hints: &SignatureHints,
) -> Result<SignatureRecovery, String> {
    let ssa = &bundle.ssa;
    if !ssa.variables.iter().any(|variable| variable.is_register()) {
        return Err("ABI recovery requires architectural registers".into());
    }
    let bits = ssa.address_width;
    let evidence = collect_roots(ssa);
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
    let hints_constraints = call_site_constraints(ssa, hints);
    let stack_offsets = incoming_stack_offsets(ssa);
    let mut parameters: BTreeMap<usize, Parameter> = BTreeMap::new();
    let argument_registers = convention.argument_registers(bits);

    let mut max_index = None;
    for (index, register) in argument_registers.iter().enumerate() {
        let Some(variable) = register_index(ssa, register) else {
            conflicts.push(format!(
                "convention register {register} is not present in this function"
            ));
            continue;
        };
        let Some((uses, source)) = evidence.use_counts.get(&variable).copied() else {
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
        let confidence = if evidence.pointer_roots.contains(&variable)
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

    let incoming = if frame.slots.is_empty() {
        stack_offsets
            .iter()
            .map(|offset| (*offset, None))
            .collect::<BTreeMap<_, _>>()
    } else {
        frame
            .slots
            .iter()
            .filter(|slot| slot.kind == "incomingArgument")
            .map(|slot| (slot.offset, Some(slot.width)))
            .chain(
                stack_offsets
                    .iter()
                    .filter(|offset| !frame.slots.iter().any(|slot| slot.offset == **offset))
                    .map(|offset| (*offset, None)),
            )
            .collect()
    };
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
    let return_value = recover_return(ssa, &bundle.raw);
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
        let sysv_exclusive = ["rdi", "rsi"];
        let win_exclusive = ["rcx", "r8", "r9"];
        let used = |name: &str| {
            evidence
                .use_counts
                .keys()
                .any(|id| evidence.register_names.get(id).map(String::as_str) == Some(name))
        };
        let win = win_exclusive.iter().filter(|name| used(name)).count();
        let sysv = sysv_exclusive.iter().filter(|name| used(name)).count();
        let shared = ["rdx"].iter().filter(|name| used(name)).count();
        if sysv > 0 && win == 0 {
            evidence_list.push(Evidence {
                kind: "registerPattern".into(),
                address: None,
                detail: "rdi/rsi are read as entry values and Windows argument registers are not"
                    .into(),
            });
            return (
                CallingConvention::SysV64,
                Confidence::High,
                evidence_list,
                conflicts,
            );
        }
        if win > 0 && sysv == 0 {
            evidence_list.push(Evidence {
                kind: "registerPattern".into(),
                address: None,
                detail: "Windows argument registers are read as entry values and rdi/rsi are not"
                    .into(),
            });
            return (
                CallingConvention::Win64,
                Confidence::High,
                evidence_list,
                conflicts,
            );
        }
        if win > 0 && sysv > 0 {
            conflicts.push(
                "both Windows and System V argument registers are read as entry values".into(),
            );
            evidence_list.push(Evidence {
                kind: "registerConflict".into(),
                address: None,
                detail: "mixed register use prevents a definitive x64 convention decision".into(),
            });
            return (platform, Confidence::Low, evidence_list, conflicts);
        }
        let confidence = if used("rdx") || shared > 0 {
            Confidence::Medium
        } else {
            Confidence::Low
        };
        return (platform, confidence, evidence_list, conflicts);
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

fn collect_roots(ssa: &SsaFunction) -> RootEvidence {
    let mut defs: BTreeMap<Value, Def> = BTreeMap::new();
    for block in &ssa.blocks {
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
    let register_names = ssa
        .variables
        .iter()
        .enumerate()
        .filter(|(_, variable)| variable.is_register())
        .map(|(id, variable)| (id, variable.name.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut evidence = RootEvidence {
        roots: BTreeSet::new(),
        use_counts: BTreeMap::new(),
        pointer_roots: BTreeSet::new(),
        zero_compare_roots: BTreeSet::new(),
        register_names,
    };
    let mut resolver = RootResolver {
        defs,
        memo: BTreeMap::new(),
        budget: MAX_TAINT_VALUES,
    };
    for block in &ssa.blocks {
        for statement in &block.statements {
            let args: &[Use] = match &statement.op {
                Operation::Barrier { .. } => continue,
                Operation::Call => &statement.args[..statement.args.len().min(1)],
                _ => &statement.args,
            };
            let mut roots = BTreeSet::new();
            for arg in args {
                if let Use::Value(value) = arg {
                    roots.extend(resolver.roots(*value, 0));
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
                    evidence.pointer_roots.extend(resolver.roots(*value, 0));
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
    evidence
}

struct RootResolver {
    defs: BTreeMap<Value, Def>,
    memo: BTreeMap<Value, BTreeSet<usize>>,
    budget: usize,
}
impl RootResolver {
    fn roots(&mut self, value: Value, depth: usize) -> BTreeSet<usize> {
        if depth > 64 || self.budget == 0 {
            return BTreeSet::new();
        }
        self.budget -= 1;
        if value.version == 0 {
            return BTreeSet::from([value.variable]);
        }
        if let Some(cached) = self.memo.get(&value) {
            return cached.clone();
        }
        let args = self
            .defs
            .get(&value)
            .map(|def| def.args.clone())
            .unwrap_or_default();
        let mut roots = BTreeSet::new();
        for arg in args {
            if let Use::Value(next) = arg {
                roots.extend(self.roots(next, depth + 1));
                if roots.len() >= MAX_ROOTS_PER_VALUE {
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
    if let Some(hint) = hints.iter().find(|hint| hint.ty.is_some()) {
        return hint.ty.clone().expect("checked");
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
    if evidence.zero_compare_roots.contains(&variable) && width == ssa.address_width {
        return TypeRef::pointer_to(
            TypeRef::unknown(None, "compared with zero; pointee type is not inferred"),
            ssa.address_width,
        );
    }
    TypeRef::Int {
        bits: width,
        signed: None,
    }
}

fn recover_return(ssa: &SsaFunction, _raw: &crate::ir::Function) -> ReturnValue {
    let ret = register_index(ssa, "rax")
        .or_else(|| register_index(ssa, "eax"))
        .unwrap_or(0);
    let returns = ssa
        .blocks
        .iter()
        .filter(|block| block.terminator.flow.kind == crate::ir::FlowKind::Return)
        .collect::<Vec<_>>();
    if returns.is_empty() {
        return ReturnValue {
            location: None,
            ty: TypeRef::Void,
            confidence: Confidence::Low,
            evidence: vec![Evidence {
                kind: "noReturnObserved".into(),
                address: None,
                detail: "no return instruction was recovered; the function may not return".into(),
            }],
        };
    }
    let mut observed = 0usize;
    let mut untracked = 0usize;
    let mut conflicts = Vec::new();
    let mut source = None;
    for block in &returns {
        let value = block
            .terminator
            .state
            .get(ret)
            .and_then(|use_| match use_ {
                Use::Value(value) => Some(*value),
                Use::Constant(_) => None,
            })
            .unwrap_or(Value {
                variable: ret,
                version: 0,
            });
        source = source.or(Some(block.terminator.flow.source.0));
        if value.version == 0 {
            conflicts.push(format!(
                "return at {} does not define the return register",
                block.terminator.flow.source
            ));
            continue;
        }
        let defined = ssa.blocks.iter().any(|candidate| {
            candidate
                .statements
                .iter()
                .any(|statement| statement.output == Some(value))
        }) || ssa
            .blocks
            .iter()
            .any(|candidate| candidate.phis.iter().any(|phi| phi.output == value));
        let unknown_effect = ssa.blocks.iter().any(|candidate| {
            candidate.statements.iter().any(|statement| {
                statement.output == Some(value)
                    && matches!(&statement.op, Operation::Unknown { .. })
            })
        });
        if !defined || unknown_effect {
            untracked += 1;
        } else {
            observed += 1;
        }
    }
    let width = ssa
        .variables
        .get(ret)
        .and_then(|variable| variable.ty.width());
    let ty = TypeRef::Int {
        bits: width.unwrap_or(ssa.address_width),
        signed: None,
    };
    let location = Some(Location::Register {
        name: if ssa.address_width == 64 {
            "rax".into()
        } else {
            "eax".into()
        },
    });
    let (ty, confidence, detail) = if observed > 0 {
        (
            ty,
            Confidence::Medium,
            "the return register is defined on at least one return path".to_string(),
        )
    } else if untracked > 0 {
        (
            TypeRef::unknown(
                width,
                "return value depends on a call or unsupported effect",
            ),
            Confidence::Low,
            "the return register is only written by an untracked effect".to_string(),
        )
    } else {
        (
            TypeRef::Void,
            Confidence::Medium,
            "the return register is never defined on any return path".to_string(),
        )
    };
    ReturnValue {
        location,
        ty,
        confidence,
        evidence: vec![Evidence {
            kind: "returnRegister".into(),
            address: source,
            detail,
        }],
    }
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

fn call_site_constraints(ssa: &SsaFunction, hints: &SignatureHints) -> HintConstraints {
    let mut result = HintConstraints::default();
    for block in &ssa.blocks {
        for statement in &block.statements {
            if statement.op != Operation::Call {
                continue;
            }
            let Some(Use::Constant(target)) = statement.args.first() else {
                continue;
            };
            let Some(signature) = hints.get(target.value.0) else {
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
    result
}

/// Entry-relative stack offsets read or written by the function.
fn incoming_stack_offsets(ssa: &SsaFunction) -> BTreeSet<i64> {
    let mut defs: BTreeMap<Value, Def> = BTreeMap::new();
    for block in &ssa.blocks {
        for statement in &block.statements {
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
    }
    let stack_pointer = if ssa.address_width == 64 {
        "rsp"
    } else {
        "esp"
    };
    let Some(sp) = register_index(ssa, stack_pointer) else {
        return BTreeSet::new();
    };
    fn constant(use_: Use) -> Option<i64> {
        match use_ {
            Use::Constant(c) if c.ty.width().is_some_and(|width| width <= 64) => {
                Some(c.value.0 as i64)
            }
            _ => None,
        }
    }
    fn offset(value: Value, sp: usize, defs: &BTreeMap<Value, Def>, depth: usize) -> Option<i64> {
        if depth > 64 {
            return None;
        }
        if value.version == 0 {
            return (value.variable == sp).then_some(0);
        }
        let def = defs.get(&value)?;
        match def.op.as_ref()? {
            Operation::Copy
            | Operation::ToAddress
            | Operation::ToBits
            | Operation::ZeroExtend
            | Operation::SignExtend
            | Operation::Truncate => match def.args.first() {
                Some(Use::Value(value)) => offset(*value, sp, defs, depth + 1),
                _ => None,
            },
            Operation::Extract { offset: 0 } => match def.args.first() {
                Some(Use::Value(value)) => offset(*value, sp, defs, depth + 1),
                _ => None,
            },
            Operation::Add => match (def.args.first(), def.args.get(1)) {
                (Some(Use::Value(a)), Some(Use::Value(b))) => offset(*a, sp, defs, depth + 1)
                    .and_then(|a| offset(*b, sp, defs, depth + 1).map(|b| a.wrapping_add(b))),
                (Some(Use::Value(a)), Some(b)) => offset(*a, sp, defs, depth + 1)
                    .map(|a| a.wrapping_add(constant(*b).unwrap_or(0))),
                (Some(a), Some(Use::Value(b))) => offset(*b, sp, defs, depth + 1)
                    .map(|b| b.wrapping_add(constant(*a).unwrap_or(0))),
                _ => None,
            },
            Operation::Sub => match (def.args.first(), def.args.get(1)) {
                (Some(Use::Value(a)), Some(b)) => offset(*a, sp, defs, depth + 1)
                    .map(|a| a.wrapping_sub(constant(*b).unwrap_or(0))),
                (Some(a), Some(Use::Value(b))) => {
                    constant(*a).and_then(|a| offset(*b, sp, defs, depth + 1).map(|b| a - b))
                }
                _ => None,
            },
            _ => None,
        }
    }
    let mut offsets = BTreeSet::new();
    for block in &ssa.blocks {
        for statement in &block.statements {
            if !matches!(statement.op, Operation::Load | Operation::Store) {
                continue;
            }
            let Some(Use::Value(value)) = statement.args.get(1) else {
                continue;
            };
            if let Some(offset) = offset(*value, sp, &defs, 0) {
                if (1..=0x10_000).contains(&offset) {
                    offsets.insert(offset);
                }
            }
        }
    }
    offsets
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
    let mut cleanup = None;
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
                cleanup = Some(cleanup.map_or(value, |current: u16| current.max(value)));
            } else {
                cleanup = Some(cleanup.unwrap_or(0));
            }
        }
    }
    cleanup
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
        };
        assert!(resolver.roots(first, 0).is_empty());
        assert!(resolver.budget < 8);
    }
}
