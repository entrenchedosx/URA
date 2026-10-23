//! Decompiler foundations: ABI recovery, stack frames, conservative types,
//! a bounded call graph and a recovered high-level IR rendering.
//!
//! Everything in this module is derived from the verified lifted IR. Views are
//! explicitly labelled as recovered analysis and never claim to reproduce
//! original source code.
pub mod abi;
pub mod api;
pub mod callgraph;
pub mod execute;
pub mod flow;
pub mod hir;
pub mod imports;
pub mod postdom;
pub mod program;
pub mod semantic;
pub mod signature;
pub mod source;
pub mod stack;
pub mod types;

pub use abi::{SignatureHints, SignatureRecovery};
pub use callgraph::{CallGraph, CallGraphEdge, CallGraphNode};
pub use hir::{
    HighLevelFunction, HighLevelLine, HirArgument, HirBinaryOp, HirCastKind, HirExpr, HirFunction,
    HirIncoming, HirInvocation, HirReturnShape, HirStatement, HirValueDisplay, IfExitTarget,
    UnsupportedCase,
};
pub use postdom::{PostDominators, SINK};
pub use signature::{
    CallingConvention, FunctionSignature, Location, Parameter, ReturnValue, SignatureOverride,
    SignatureParameterInput,
};
pub use stack::{StackAccess, StackFrame, StackSlot};
pub use types::{
    Confidence, InferredType, StructField, Structure, TypeConstraint, TypeDatabase, TypeInference,
    TypeRef,
};

use crate::ir::inspect;
use crate::{AnalysisControl, LoadedBinary, ProgramAnalysis};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecompContext {
    pub function_name: Option<String>,
    pub hints: SignatureHints,
    pub type_database: TypeDatabase,
    pub override_signature: Option<SignatureOverride>,
    /// Stack slot overrides keyed by the exact entry-relative offset rendered in
    /// decimal, matching the stack-frame view.
    pub stack_overrides: BTreeMap<String, (Option<String>, Option<TypeRef>)>,
}
impl DecompContext {
    pub fn new(address_bits: u16) -> Self {
        Self {
            type_database: TypeDatabase::new(address_bits),
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionDecompilation {
    pub function: u64,
    pub name: String,
    pub signature: FunctionSignature,
    pub frame: StackFrame,
    pub types: TypeInference,
    pub high_level: HighLevelFunction,
    /// Typed high-level IR tree; the source of `high_level` lines. Never
    /// serialised through string rendering. Old project files omit it.
    #[serde(default)]
    pub ast: Option<hir::HirFunction>,
    pub program: program::ProgramTypes,
    pub semantic: semantic::SemanticFunction,
    pub pseudocode: source::Output,
    pub diagnostics: Vec<String>,
}

pub fn analyze_function(
    binary: &LoadedBinary,
    analysis: &ProgramAnalysis,
    address: u64,
    context: &DecompContext,
    control: &dyn AnalysisControl,
) -> Result<FunctionDecompilation, String> {
    if context.type_database.address_bits != binary.analysis().bitness as u16 {
        return Err("type database target width differs from the binary".into());
    }
    let type_errors = context.type_database.validation_errors();
    if !type_errors.is_empty() {
        return Err(format!("invalid type database: {}", type_errors.join("; ")));
    }
    let bundle = inspect::analyze(binary, analysis, address, control)?;
    if control.is_cancelled() {
        return Err("decompiler analysis cancelled".into());
    }
    let mut hints = context.hints.clone();
    let import_notes = match imports::hydrate_with_control(binary, &mut hints, control) {
        Ok((notes, _)) => notes,
        Err(error) if control.is_cancelled() => return Err(error),
        Err(error) => vec![format!("import recovery unavailable: {error}")],
    };
    callgraph::hydrate_thunks(binary, analysis, &mut hints, control)?;
    // The current function's explicit signature must also be a solver seed.
    if let Some(override_signature) = &context.override_signature {
        let errors = override_signature.validate_for_processor(
            crate::processor::Processor::for_analysis(binary.analysis())?,
        );
        if !errors.is_empty() {
            return Err(format!(
                "signature override rejected: {}",
                errors.join("; ")
            ));
        }
        let name = analysis
            .functions
            .iter()
            .find(|f| f.address == address)
            .and_then(|f| f.symbol.as_deref())
            .unwrap_or("function");
        hints.insert(signature::describe_override(
            address,
            name,
            override_signature,
        ));
    }
    let program = program::enrich(binary, analysis, &bundle, &mut hints, control)?;
    let mut frame = stack::recover_with_control(binary, analysis, address, None, control)?;
    let recovery = abi::recover_with_control(binary, analysis, &bundle, &frame, &hints, control)?;
    let mut signature = recovery.signature;
    if context.override_signature.is_none() && context.hints.get(address).is_none() {
        program::apply_to_signature(&mut signature, &program);
    }
    if let Some(override_signature) = &context.override_signature {
        let errors = override_signature.validate_for_processor(
            crate::processor::Processor::for_analysis(binary.analysis())?,
        );
        if !errors.is_empty() {
            return Err(format!(
                "signature override rejected: {}",
                errors.join("; ")
            ));
        }
        signature = signature::apply_override(&signature, override_signature);
        for parameter in &mut signature.parameters {
            parameter.width = parameter
                .ty
                .bits(&context.type_database)
                .unwrap_or(0)
                .min(u64::from(u16::MAX)) as u16;
        }
    }
    if control.is_cancelled() {
        return Err("decompiler analysis cancelled".into());
    }
    frame = stack::recover_with_control(binary, analysis, address, Some(&signature), control)?;
    stack::apply_overrides(&mut frame, &context.stack_overrides);
    let mut inferred = types::infer_types_with_control(&bundle, control)?;
    abi::merge_value_constraints(&mut inferred, &recovery.value_constraints);
    flow::apply_values(address, &mut inferred.values, &program.flow);
    inferred.conflicts += inferred
        .values
        .iter()
        .map(|value| value.conflicts.len())
        .sum::<usize>();
    if program.truncated || !program.converged {
        inferred.truncated = true;
        inferred.notes.push("Interprocedural facts cover a bounded partial scope; missing information remains unknown.".into());
    }
    let mut semantic = semantic::lower(&bundle.ssa, &inferred.values, control)?;
    semantic.types_partial |= inferred.truncated;
    semantic.attach_signature(&signature);
    if let Some(name) = &context.function_name {
        signature.name = name.clone();
    }
    let constants = bundle.dataflow.constants.iter().copied().collect();
    let mut call_bindings = BTreeMap::new();
    for node in &semantic.nodes {
        if !matches!(node.kind, semantic::NodeKind::Invoke) {
            continue;
        }
        let source = &semantic.sources[node.source];
        if let Some((block, statement)) = bundle
            .ssa
            .blocks
            .iter()
            .find(|b| b.address == source.block)
            .and_then(|b| {
                source
                    .ordinal
                    .and_then(|ordinal| b.statements.get(ordinal))
                    .map(|s| (b, s))
            })
        {
            if let Some(slot) = imports::slot_for_call(block, statement, &constants)
                .filter(|slot| hints.get(*slot).is_some())
            {
                call_bindings.insert(node.source, slot);
            }
        }
    }
    let pseudocode = source::build_with_facts(
        &semantic,
        &signature.name,
        &hints,
        Some(&frame),
        &call_bindings,
        &bundle.dataflow.constants,
        control,
    )?;
    let mut diagnostics = recovery.notes;
    diagnostics.extend(import_notes);
    diagnostics.push(format!("SSA argument/return constraints: {} facts, {} call sites, {} updates; converged={}, partial={}",program.flow.total_facts,program.flow.calls.len(),program.flow.updates,program.flow.converged,program.flow.truncated));
    diagnostics.push(format!("interprocedural parameter demands: {} function(s), {} register-copy edge(s), {} update(s), converged={}, partial={}", program.functions.len(), program.edges.len(), program.updates, program.converged, program.truncated));
    let (high_level, ast) = hir::build_with_ast(
        &bundle.ssa,
        &bundle.dataflow,
        &signature,
        &hints,
        Some(&frame),
    );
    if control.is_cancelled() {
        return Err("decompiler analysis cancelled".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    for diagnostic in &bundle.raw.diagnostics {
        if diagnostics.len() >= 64 {
            diagnostics.push("lift diagnostics were truncated at 64 entries".into());
            break;
        }
        if seen.insert(diagnostic.message.clone()) {
            diagnostics.push(format!(
                "lift at {}: {}",
                crate::format_address(diagnostic.source.0),
                diagnostic.message
            ));
        }
    }
    if frame.truncated || high_level.truncated {
        diagnostics
            .push("stack or high-level output hit a configured bound and is incomplete".into());
    }
    let name = signature.name.clone();
    Ok(FunctionDecompilation {
        function: address,
        name,
        signature,
        frame,
        types: inferred,
        high_level,
        ast: Some(ast),
        program,
        semantic,
        pseudocode,
        diagnostics,
    })
}

pub fn build_call_graph(analysis: &ProgramAnalysis) -> CallGraph {
    callgraph::build(analysis)
}

pub fn imported_signature(
    name: &str,
    convention: CallingConvention,
    address_bits: u16,
) -> Option<Result<FunctionSignature, String>> {
    api::lookup(name).map(|prototype| api::instantiate(prototype, convention, address_bits))
}

mod stack_risc;
