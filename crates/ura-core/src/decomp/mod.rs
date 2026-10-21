//! Decompiler foundations: ABI recovery, stack frames, conservative types,
//! a bounded call graph and a recovered high-level IR rendering.
//!
//! Everything in this module is derived from the verified lifted IR. Views are
//! explicitly labelled as recovered analysis and never claim to reproduce
//! original source code.
pub mod abi;
pub mod api;
pub mod callgraph;
pub mod hir;
pub mod postdom;
pub mod signature;
pub mod stack;
pub mod types;

pub use abi::{SignatureHints, SignatureRecovery};
pub use callgraph::{CallGraph, CallGraphEdge, CallGraphNode};
pub use hir::{
    HirArgument, HirBinaryOp, HirCastKind, HirExpr, HirFunction, HirIncoming, HirInvocation,
    HirReturnShape, HirStatement, HirValueDisplay, HighLevelFunction, HighLevelLine, IfExitTarget,
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
    let mut frame = stack::recover_with_control(binary, analysis, address, None, control)?;
    let recovery =
        abi::recover_with_control(binary, analysis, &bundle, &frame, &context.hints, control)?;
    let mut signature = recovery.signature;
    if let Some(override_signature) = &context.override_signature {
        let errors = override_signature.validate_for_width(binary.analysis().bitness as u16);
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
    let mut inferred = types::infer_types(&bundle);
    abi::merge_value_constraints(&mut inferred, &recovery.value_constraints);
    let (high_level, ast) = hir::build_with_ast(
        &bundle.ssa,
        &bundle.dataflow,
        &signature,
        &context.hints,
        Some(&frame),
    );
    if control.is_cancelled() {
        return Err("decompiler analysis cancelled".into());
    }
    let mut diagnostics = recovery.notes;
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
