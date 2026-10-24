//! Bounded symbolic analysis of verified scalar IR. Unknown effects never prove
//! an edge infeasible. Original IR remains the authoritative machine evidence.
pub mod alias;
mod engine;
pub mod expr;
pub mod solver;
pub mod value_set;
pub use engine::{
    analyze, Evidence, IndirectTargets, Options, Path, Predicate, PredicateStatus, Region,
    RemovedEdge, Report, ANALYSIS_VERSION,
};

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Deobfuscation {
    pub processor: crate::processor::Processor,
    pub effective_sha256: String,
    pub logical_indirect_edges: Vec<LogicalIndirectEdge>,
    pub report: Report,
    pub original: crate::decomp::FunctionDecompilation,
    pub simplified: crate::decomp::FunctionDecompilation,
    pub derived_ir: crate::ir::Function,
    pub value_sets: value_set::Analysis,
}
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogicalIndirectEdge {
    pub source: crate::ir::Address,
    pub target: crate::ir::Address,
    pub transfer_kind: String,
    pub known_function: Option<crate::ir::Address>,
    pub target_evidence: usize,
    pub exhaustive_under_prefix: bool,
    pub scope: String,
}

/// Shared Desktop/CLI/MCP pipeline. Rebuilds SSA and the existing decompiler
/// from a proof-gated IR overlay; it never changes binary bytes or original CFG.
pub fn deobfuscate(
    binary: &crate::LoadedBinary,
    analysis: &crate::ProgramAnalysis,
    address: u64,
    context: &crate::decomp::DecompContext,
    options: &Options,
    backend: &dyn solver::Backend,
    control: &dyn crate::AnalysisControl,
) -> Result<Deobfuscation, String> {
    options.validate()?;
    let deadline = engine::DeadlineControl {
        parent: control,
        until: std::time::Instant::now() + std::time::Duration::from_millis(options.total_ms),
    };
    let result = deobfuscate_inner(
        binary, analysis, address, context, options, backend, &deadline,
    );
    if std::time::Instant::now() >= deadline.until && !control.is_cancelled() {
        return Err("symbolic pipeline total deadline reached; no result accepted".into());
    }
    result
}
fn deobfuscate_inner(
    binary: &crate::LoadedBinary,
    analysis: &crate::ProgramAnalysis,
    address: u64,
    context: &crate::decomp::DecompContext,
    options: &Options,
    backend: &dyn solver::Backend,
    control: &dyn crate::AnalysisControl,
) -> Result<Deobfuscation, String> {
    let original_bundle = crate::ir::inspect::analyze(binary, analysis, address, control)?;
    options.validate()?;
    if original_bundle.raw.variables.len() > 4096 || original_bundle.raw.blocks.len() > 512 {
        return Err("symbolic function capacity: at most 4096 variables and 512 blocks".into());
    }
    let value_sets = value_set::analyze(&original_bundle.ssa, control);
    let mut report = analyze(&original_bundle.raw, options, backend, control)?;
    let processor = crate::processor::Processor::for_analysis(binary.analysis())?;
    let effective_sha256 = crate::sha256_hex(binary.bytes());
    report.identity = crate::sha256_hex(
        &serde_json::to_vec(&(
            &report.ir_identity,
            &effective_sha256,
            processor,
            context,
            env!("CARGO_PKG_VERSION"),
        ))
        .map_err(|e| e.to_string())?,
    );
    if control.is_cancelled() {
        return Err("symbolic analysis cancelled".into());
    }
    let derived_ir = engine::refine(&original_bundle.raw, &report)?;
    let mut logical_indirect_edges = Vec::new();
    for (index, targets) in report.indirect_targets.iter().enumerate() {
        for target in &targets.candidates {
            let executable = binary
                .analysis()
                .sections
                .iter()
                .any(|section| section.executable && section.contains_address(target.0));
            if !executable || !analysis.instructions.contains_key(&target.0) {
                continue;
            }
            logical_indirect_edges.push(LogicalIndirectEdge { source: targets.source, target: *target,
                transfer_kind: targets.transfer_kind.clone(), known_function: analysis.function_by_start(target.0).map(|f| crate::ir::Address(f.address)),
                target_evidence: index, exhaustive_under_prefix: targets.exhaustive,
                scope: "analysis-only CFG/call-graph overlay: solver target for this captured prefix and a mapped executable instruction boundary; original indirect transfer preserved".into() });
        }
    }
    let original = crate::decomp::analyze_with_bundle(
        binary,
        analysis,
        address,
        context,
        control,
        original_bundle,
    )?;
    let ssa = crate::ir::ssa::construct_with_control(&derived_ir, control)?;
    let dataflow = crate::ir::dataflow::analyze_with_control(&ssa, control)?;
    let bundle = crate::ir::inspect::Bundle {
        raw: derived_ir.clone(),
        ssa,
        dataflow,
    };
    let simplified =
        crate::decomp::analyze_with_bundle(binary, analysis, address, context, control, bundle)?;
    Ok(Deobfuscation {
        processor,
        effective_sha256,
        logical_indirect_edges,
        report,
        original,
        simplified,
        derived_ir,
        value_sets,
    })
}

impl Deobfuscation {
    /// Bounded historical data only. This snapshot never enables a rewrite;
    /// rebuilding proofs from current effective bytes is always mandatory.
    pub fn historical_metadata(&self, context_stamp: Option<&str>) -> serde_json::Value {
        let report = &self.report;
        serde_json::json!({"version":1,"identity":report.identity,"function":report.function,
            "processor":self.processor,"effectiveSha256":self.effective_sha256,
            "solver":report.solver,"options":report.options,"assumptions":report.assumptions,"authoritative":false,
            "contextStamp":context_stamp,"predicates":report.predicates.iter().take(16).collect::<Vec<_>>(),
            "removedEdges":report.removed_edges.iter().take(16).collect::<Vec<_>>(),
            "proofMetadata":report.queries.iter().take(32).map(|q| serde_json::json!({"querySha256":q.query_sha256,"status":q.outcome.status,"limits":q.limits})).collect::<Vec<_>>() })
    }
}
