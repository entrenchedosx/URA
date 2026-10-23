use crate::address::format_address;
use crate::binary::{CpuArchitecture, LoadedBinary};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter, OpKind, Register,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Instant;

pub const DEFAULT_MAX_INSTRUCTIONS: usize = 200_000;
pub const DEFAULT_MAX_FUNCTIONS: usize = 8_192;
pub const DEFAULT_MAX_BLOCKS: usize = 150_000;
pub const MAX_ANALYSIS_DIAGNOSTICS: usize = 250;

#[derive(Debug, Clone)]
pub struct AnalysisOptions {
    pub max_instructions: usize,
    pub max_functions: usize,
    pub max_blocks: usize,
    pub follow_calls: bool,
    pub seed_symbols: bool,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            max_instructions: DEFAULT_MAX_INSTRUCTIONS,
            max_functions: DEFAULT_MAX_FUNCTIONS,
            max_blocks: DEFAULT_MAX_BLOCKS,
            follow_calls: true,
            seed_symbols: true,
        }
    }
}

impl AnalysisOptions {
    pub fn normalized(&self) -> Self {
        Self {
            max_instructions: self.max_instructions.clamp(64, 2_000_000),
            max_functions: self.max_functions.clamp(1, 50_000),
            max_blocks: self.max_blocks.clamp(1, 500_000),
            follow_calls: self.follow_calls,
            seed_symbols: self.seed_symbols,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FunctionOrigin {
    EntryPoint,
    Export,
    Symbol,
    CallTarget,
    UserDefined,
}

impl FunctionOrigin {
    pub fn name(self) -> &'static str {
        match self {
            FunctionOrigin::EntryPoint => "entryPoint",
            FunctionOrigin::Export => "export",
            FunctionOrigin::Symbol => "symbol",
            FunctionOrigin::CallTarget => "callTarget",
            FunctionOrigin::UserDefined => "user",
        }
    }

    fn priority(self) -> u8 {
        match self {
            FunctionOrigin::EntryPoint => 4,
            FunctionOrigin::Export => 3,
            FunctionOrigin::Symbol => 2,
            FunctionOrigin::CallTarget => 1,
            FunctionOrigin::UserDefined => 5,
        }
    }

    pub fn is_verified(self) -> bool {
        !matches!(self, FunctionOrigin::CallTarget)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum InstructionFlow {
    Next,
    Call,
    IndirectCall,
    Jump,
    ConditionalJump,
    IndirectJump,
    Return,
    Interrupt,
    Exception,
}

impl InstructionFlow {
    pub fn name(self) -> &'static str {
        match self {
            InstructionFlow::Next => "next",
            InstructionFlow::Call => "call",
            InstructionFlow::IndirectCall => "indirectCall",
            InstructionFlow::Jump => "jump",
            InstructionFlow::ConditionalJump => "conditionalJump",
            InstructionFlow::IndirectJump => "indirectJump",
            InstructionFlow::Return => "return",
            InstructionFlow::Interrupt => "interrupt",
            InstructionFlow::Exception => "exception",
        }
    }

    fn ends_block(self) -> bool {
        !matches!(
            self,
            InstructionFlow::Next | InstructionFlow::Call | InstructionFlow::IndirectCall
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EdgeKind {
    FallThrough,
    Jump,
    Taken,
}

impl EdgeKind {
    pub fn name(self) -> &'static str {
        match self {
            EdgeKind::FallThrough => "fallthrough",
            EdgeKind::Jump => "jump",
            EdgeKind::Taken => "taken",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum XrefKind {
    Call,
    Jump,
    ConditionalJump,
    Data,
}

impl XrefKind {
    pub fn name(self) -> &'static str {
        match self {
            XrefKind::Call => "call",
            XrefKind::Jump => "jump",
            XrefKind::ConditionalJump => "conditionalJump",
            XrefKind::Data => "data",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataReferenceKind {
    RipRelative,
    PcRelative,
    Absolute,
}

impl DataReferenceKind {
    pub fn name(self) -> &'static str {
        match self {
            DataReferenceKind::RipRelative => "ripRelative",
            DataReferenceKind::PcRelative => "pcRelative",
            DataReferenceKind::Absolute => "absolute",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DataReference {
    pub target: u64,
    pub kind: DataReferenceKind,
}

#[derive(Debug, Clone)]
pub struct DecodedInstruction {
    pub address: u64,
    pub length: u8,
    pub flow: InstructionFlow,
    pub target: Option<u64>,
    pub data_references: Vec<DataReference>,
    pub invalid: bool,
    pub mnemonic: String,
    pub operands: String,
}

impl DecodedInstruction {
    pub fn end(&self) -> u64 {
        self.address.saturating_add(self.length as u64)
    }

    pub fn is_terminal(&self) -> bool {
        self.invalid || self.flow.ends_block()
    }

    pub fn text(&self) -> String {
        if self.operands.is_empty() {
            self.mnemonic.clone()
        } else {
            format!("{} {}", self.mnemonic, self.operands)
        }
    }
}

#[derive(Debug, Clone)]
pub struct AnalysisSeed {
    pub address: u64,
    pub name: Option<String>,
    pub origin: FunctionOrigin,
}

#[derive(Debug, Clone, Copy)]
pub struct Edge {
    pub target: u64,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub address: u64,
    pub end: u64,
    pub function: u64,
    pub instructions: Vec<u64>,
    pub successors: Vec<Edge>,
}

#[derive(Debug, Clone)]
pub struct Function {
    pub address: u64,
    pub end: u64,
    pub origin: FunctionOrigin,
    pub symbol: Option<String>,
    pub blocks: Vec<u64>,
    pub instruction_count: usize,
    pub reference_count: usize,
    pub callers: Vec<u64>,
    pub callees: Vec<u64>,
}

impl Function {
    pub fn verified(&self) -> bool {
        self.origin.is_verified()
    }

    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.address)
    }

    pub fn fallback_name(&self) -> String {
        format!(
            "sub_{}",
            format_address(self.address).trim_start_matches("0x")
        )
    }
}

#[derive(Debug, Clone)]
pub struct Xref {
    pub from: u64,
    pub to: u64,
    pub kind: XrefKind,
    pub data_kind: Option<DataReferenceKind>,
    pub function: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisDiagnostic {
    pub address: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisReport {
    pub instruction_count: usize,
    pub function_count: usize,
    pub block_count: usize,
    pub xref_count: usize,
    pub data_xref_count: usize,
    pub cancelled: bool,
    pub truncated: bool,
    pub diagnostics_dropped: usize,
    pub elapsed_ms: u64,
    pub diagnostics: Vec<AnalysisDiagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AnalysisStage {
    Preparing,
    Discovering,
    Finalizing,
    Complete,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisProgress {
    pub stage: AnalysisStage,
    pub instructions: usize,
    pub functions: usize,
    pub blocks: usize,
    pub current_address: Option<String>,
}

pub trait AnalysisControl: Send + Sync {
    fn is_cancelled(&self) -> bool;
    fn report(&self, progress: AnalysisProgress);
}

impl AnalysisControl for () {
    fn is_cancelled(&self) -> bool {
        false
    }

    fn report(&self, _progress: AnalysisProgress) {}
}

pub struct ProgramAnalysis {
    pub functions: Vec<Function>,
    pub blocks: BTreeMap<u64, BasicBlock>,
    pub instructions: BTreeMap<u64, DecodedInstruction>,
    pub xrefs: Vec<Xref>,
    pub report: AnalysisReport,
    /// Guarded byte-pattern evidence, not a proof of exhaustive indirect flow.
    pub jump_tables: BTreeMap<u64, JumpTable>,
    function_by_address: BTreeMap<u64, usize>,
    xrefs_to: BTreeMap<u64, Vec<usize>>,
    xrefs_from: BTreeMap<u64, Vec<usize>>,
}
#[derive(Debug, Clone)]
pub struct JumpTable {
    pub source: u64,
    pub guard: u64,
    pub table: u64,
    pub entry_width: u8,
    pub relative: bool,
    pub targets: Vec<u64>,
}
#[derive(Debug, Clone)]
pub struct FunctionFlowFacts {
    /// Candidates require a direct jump to a separately discovered entry.
    /// A function boundary can still be heuristic, so this is not an ABI proof.
    pub tail_calls: Vec<(u64, u64)>,
    pub thunk_candidate: bool,
    pub thunk_target: Option<u64>,
    pub unresolved_indirect: Vec<u64>,
}

impl ProgramAnalysis {
    pub fn flow_facts(&self, function: &Function) -> FunctionFlowFacts {
        let mut tail_calls = Vec::new();
        let mut unresolved_indirect = Vec::new();
        for block in &function.blocks {
            let Some(last) = self
                .blocks
                .get(block)
                .and_then(|b| b.instructions.last())
                .and_then(|a| self.instructions.get(a))
            else {
                continue;
            };
            if last.flow == InstructionFlow::IndirectJump {
                unresolved_indirect.push(last.address);
            }
            if last.flow == InstructionFlow::Jump {
                if let Some(target) = last.target {
                    if target != function.address && self.function_by_start(target).is_some() {
                        tail_calls.push((last.address, target));
                    }
                }
            }
        }
        let thunk_candidate = function.instruction_count == 1
            && (!tail_calls.is_empty() || !unresolved_indirect.is_empty());
        let thunk_target = if thunk_candidate {
            tail_calls.first().map(|t| t.1)
        } else {
            None
        };
        FunctionFlowFacts {
            tail_calls,
            thunk_candidate,
            thunk_target,
            unresolved_indirect,
        }
    }
    pub fn function_by_start(&self, address: u64) -> Option<&Function> {
        self.function_by_address
            .get(&address)
            .map(|index| &self.functions[*index])
    }

    pub fn function_containing(&self, address: u64) -> Option<&Function> {
        // Function extents can include holes. Require a retained source block,
        // including interleaved/discontiguous bodies and partial analysis.
        let block = self.blocks.range(..=address).next_back()?.1;
        if address < block.end {
            self.function_by_start(block.function)
        } else {
            None
        }
    }

    pub fn block_containing(&self, address: u64) -> Option<&BasicBlock> {
        let (_, block) = self.blocks.range(..=address).next_back()?;
        if address < block.end {
            Some(block)
        } else {
            None
        }
    }

    pub fn function_name(&self, address: u64) -> Option<String> {
        self.function_by_start(address).map(|function| {
            function
                .symbol
                .clone()
                .unwrap_or_else(|| function.fallback_name())
        })
    }

    pub fn xrefs_to(&self, address: u64) -> impl Iterator<Item = &Xref> {
        self.xrefs_to
            .get(&address)
            .into_iter()
            .flatten()
            .map(|index| &self.xrefs[*index])
    }

    pub fn xrefs_from(&self, address: u64) -> impl Iterator<Item = &Xref> {
        self.xrefs_from
            .get(&address)
            .into_iter()
            .flatten()
            .map(|index| &self.xrefs[*index])
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CodeRegion<'a> {
    pub start: u64,
    pub bytes: &'a [u8],
}

pub struct CodeImage<'a> {
    regions: Vec<CodeRegion<'a>>,
}

impl<'a> CodeImage<'a> {
    pub fn new(mut regions: Vec<CodeRegion<'a>>) -> Self {
        regions.sort_by_key(|region| region.start);
        Self { regions }
    }

    pub fn from_binary(binary: &'a LoadedBinary) -> Self {
        let bytes = binary.bytes();
        let analysis = binary.analysis();
        let mut regions = Vec::new();
        for section in analysis.executable_sections() {
            let Some(file_offset) = section.file_offset else {
                continue;
            };
            if section.file_size == 0 {
                continue;
            }
            let start = file_offset as usize;
            let end = start.saturating_add(section.file_size as usize);
            if start >= bytes.len() {
                continue;
            }
            let end = end.min(bytes.len());
            if end <= start {
                continue;
            }
            regions.push(CodeRegion {
                start: section.address,
                bytes: &bytes[start..end],
            });
        }
        Self::new(regions)
    }

    pub fn readonly_data(binary: &'a LoadedBinary) -> Self {
        let regions = binary
            .analysis()
            .sections
            .iter()
            .filter(|s| s.readable && !s.writable)
            .filter_map(|s| {
                let offset = usize::try_from(s.file_offset?).ok()?;
                let length = usize::try_from(s.file_size.min(s.size)).ok()?;
                let end = offset.checked_add(length)?;
                Some(CodeRegion {
                    start: s.address,
                    bytes: binary.bytes().get(offset..end)?,
                })
            })
            .collect();
        Self::new(regions)
    }

    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    pub fn region_for(&self, address: u64) -> Option<&CodeRegion<'a>> {
        let index = self
            .regions
            .partition_point(|region| region.start <= address);
        let region = self.regions.get(index.checked_sub(1)?)?;
        let length = region.bytes.len() as u64;
        if address < region.start.saturating_add(length) {
            Some(region)
        } else {
            None
        }
    }

    pub fn contains(&self, address: u64) -> bool {
        self.region_for(address).is_some()
    }

    pub fn bytes_at(&self, address: u64) -> Option<&'a [u8]> {
        let region = self.region_for(address)?;
        let offset = (address - region.start) as usize;
        Some(&region.bytes[offset..])
    }

    pub fn read(&self, address: u64, length: usize) -> Option<&'a [u8]> {
        let bytes = self.bytes_at(address)?;
        if bytes.len() < length {
            return None;
        }
        Some(&bytes[..length])
    }
}

pub fn analyze_binary(
    binary: &LoadedBinary,
    options: &AnalysisOptions,
    control: &dyn AnalysisControl,
) -> ProgramAnalysis {
    analyze_binary_with_seeds(binary, options, &[], control)
}

pub fn analyze_binary_with_seeds(
    binary: &LoadedBinary,
    options: &AnalysisOptions,
    extra_seeds: &[AnalysisSeed],
    control: &dyn AnalysisControl,
) -> ProgramAnalysis {
    let image = CodeImage::from_binary(binary);
    let analysis = binary.analysis();
    let mut seeds = seeds_for_binary(binary);
    if !options.seed_symbols {
        seeds.retain(|s| s.origin != FunctionOrigin::Symbol);
    }
    seeds.extend_from_slice(extra_seeds);
    let mapped = mapped_ranges(binary);
    let options = options.normalized();
    let memory = CodeImage::readonly_data(binary);
    let processor = crate::processor::Processor::for_analysis(analysis).ok();
    if processor == Some(crate::processor::Processor::Thumb) {
        for seed in &mut seeds {
            seed.address &= !1;
        }
    }
    analyze_images(
        (&image, &memory),
        (analysis.bitness, processor),
        analysis.entry_point.map(|a| {
            if processor == Some(crate::processor::Processor::Thumb) {
                a & !1
            } else {
                a
            }
        }),
        &seeds,
        &options,
        &mapped,
        control,
    )
}

fn mapped_ranges(binary: &LoadedBinary) -> Vec<(u64, u64)> {
    binary
        .analysis()
        .sections
        .iter()
        .filter(|section| section.size > 0)
        .map(|section| {
            (
                section.address,
                section.address.saturating_add(section.size),
            )
        })
        .collect()
}

pub fn seeds_for_binary(binary: &LoadedBinary) -> Vec<AnalysisSeed> {
    let analysis = binary.analysis();
    let mut seeds: BTreeMap<u64, AnalysisSeed> = BTreeMap::new();

    let mut insert = |address: u64, name: Option<String>, origin: FunctionOrigin| {
        if !analysis.code_section_containing_address(address).is_some() {
            return;
        }
        let name = name
            .map(|value| sanitize_name(&value))
            .filter(|value| !value.is_empty());
        match seeds.get_mut(&address) {
            Some(existing) => {
                if origin.priority() > existing.origin.priority() {
                    let previous_name = existing.name.clone();
                    existing.origin = origin;
                    if name.is_some() {
                        existing.name = name;
                    } else {
                        existing.name = previous_name;
                    }
                } else if existing.name.is_none() && name.is_some() {
                    existing.name = name;
                }
            }
            None => {
                seeds.insert(
                    address,
                    AnalysisSeed {
                        address,
                        name,
                        origin,
                    },
                );
            }
        }
    };

    if let Some(entry) = analysis.entry_point {
        insert(entry, None, FunctionOrigin::EntryPoint);
    }
    for export in &analysis.exports {
        insert(
            export.address,
            Some(export.name.clone()),
            FunctionOrigin::Export,
        );
    }
    for symbol in &analysis.symbols {
        if !symbol.defined {
            continue;
        }
        if symbol.kind != "function" {
            continue;
        }
        let Some(address) = symbol.address else {
            continue;
        };
        insert(address, Some(symbol.name.clone()), FunctionOrigin::Symbol);
    }

    let entry = analysis.entry_point;
    let mut values: Vec<AnalysisSeed> = seeds.into_values().collect();
    values.sort_by_key(|seed| {
        let entry_rank = if Some(seed.address) == entry {
            0u8
        } else {
            1u8
        };
        (entry_rank, seed.address)
    });
    values
}

pub fn analyze_image(
    image: &CodeImage<'_>,
    bitness: u8,
    entry: Option<u64>,
    seeds: &[AnalysisSeed],
    options: &AnalysisOptions,
    control: &dyn AnalysisControl,
) -> ProgramAnalysis {
    analyze_image_mapped(image, bitness, entry, seeds, options, &[], control)
}

pub fn analyze_image_mapped(
    image: &CodeImage<'_>,
    bitness: u8,
    entry: Option<u64>,
    seeds: &[AnalysisSeed],
    options: &AnalysisOptions,
    mapped: &[(u64, u64)],
    control: &dyn AnalysisControl,
) -> ProgramAnalysis {
    analyze_images(
        (image, image),
        (
            bitness,
            match bitness {
                32 => Some(crate::processor::Processor::X86),
                64 => Some(crate::processor::Processor::X86_64),
                _ => None,
            },
        ),
        entry,
        seeds,
        options,
        mapped,
        control,
    )
}

pub fn analyze_processor_image(
    image: &CodeImage<'_>,
    processor: crate::processor::Processor,
    entry: Option<u64>,
    seeds: &[AnalysisSeed],
    options: &AnalysisOptions,
    control: &dyn AnalysisControl,
) -> ProgramAnalysis {
    analyze_images(
        (image, image),
        (processor.bits(), Some(processor)),
        entry,
        seeds,
        options,
        &[],
        control,
    )
}

fn analyze_images(
    images: (&CodeImage<'_>, &CodeImage<'_>),
    mode: (u8, Option<crate::processor::Processor>),
    entry: Option<u64>,
    seeds: &[AnalysisSeed],
    options: &AnalysisOptions,
    mapped: &[(u64, u64)],
    control: &dyn AnalysisControl,
) -> ProgramAnalysis {
    let (image, memory) = images;
    let (bitness, processor) = mode;
    let normalized_options = options.normalized();
    let options = &normalized_options;
    let started = Instant::now();
    let mut diagnostics = Diagnostics::default();
    let mut discovered = Discovery::default();

    if processor.is_none() {
        diagnostics.push(
            None,
            format!(
                "function analysis requires a supported little-endian processor/mode (bitness {})",
                bitness
            ),
        );
        return finalize(
            discovered,
            diagnostics,
            control,
            started,
            options,
            bitness,
            mapped,
        );
    }
    let processor = processor.unwrap();
    if image.is_empty() {
        diagnostics.push(
            None,
            "the binary has no executable file-backed sections".to_string(),
        );
        return finalize(
            discovered,
            diagnostics,
            control,
            started,
            options,
            bitness,
            mapped,
        );
    }

    control.report(AnalysisProgress {
        stage: AnalysisStage::Preparing,
        instructions: 0,
        functions: 0,
        blocks: 0,
        current_address: entry.map(format_address),
    });

    let mut formatter = IntelFormatter::new();
    let mut seed_map: BTreeMap<u64, AnalysisSeed> = BTreeMap::new();
    for seed in seeds {
        if !image.contains(seed.address) {
            diagnostics.push(
                Some(seed.address),
                "analysis seed is not inside a file-backed executable section".to_string(),
            );
            continue;
        }
        match seed_map.get_mut(&seed.address) {
            Some(existing) => {
                if seed.origin.priority() > existing.origin.priority() {
                    *existing = seed.clone();
                } else if existing.name.is_none() && seed.name.is_some() {
                    existing.name = seed.name.clone();
                }
            }
            None => {
                seed_map.insert(seed.address, seed.clone());
            }
        }
    }
    if let Some(entry) = entry {
        if !image.contains(entry) {
            diagnostics.push(
                Some(entry),
                "entry point is not inside a file-backed executable section".to_string(),
            );
        }
    }

    let entry_address = entry.filter(|address| image.contains(*address));
    let mut function_queue: VecDeque<AnalysisSeed> = VecDeque::new();
    if let Some(entry) = entry_address {
        if let Some(seed) = seed_map.get(&entry) {
            function_queue.push_back(seed.clone());
        } else {
            function_queue.push_back(AnalysisSeed {
                address: entry,
                name: None,
                origin: FunctionOrigin::EntryPoint,
            });
        }
    }
    for seed in seed_map.values() {
        if Some(seed.address) != entry_address {
            function_queue.push_back(seed.clone());
        }
    }

    let mut function_starts: BTreeSet<u64> =
        function_queue.iter().map(|seed| seed.address).collect();
    if let Some(entry) = entry_address {
        function_starts.insert(entry);
    }

    let mut cancelled = false;
    let mut truncated = false;
    let mut processed_since_report = 0usize;

    'functions: while let Some(seed) = function_queue.pop_front() {
        if control.is_cancelled() {
            cancelled = true;
            break;
        }
        if discovered.functions.len() >= options.max_functions {
            truncated = true;
            break;
        }
        if discovered.functions.contains_key(&seed.address) {
            continue;
        }
        if let Some((previous_address, previous)) =
            discovered.instructions.range(..=seed.address).next_back()
        {
            let previous_end = previous_address.saturating_add(previous.length as u64);
            if seed.address > *previous_address && seed.address < previous_end {
                diagnostics.push(
                    Some(seed.address),
                    format!(
                        "function seed falls inside the instruction at {}",
                        format_address(*previous_address)
                    ),
                );
                continue;
            }
        }
        if let Some(owner) = discovered.owner.get(&seed.address) {
            if *owner != seed.address {
                diagnostics.push(
                    Some(seed.address),
                    "function seed overlaps code owned by another function".to_string(),
                );
                continue;
            }
        }

        let mut queue: VecDeque<u64> = VecDeque::new();
        queue.push_back(seed.address);
        let mut visited: BTreeSet<u64> = BTreeSet::new();
        let mut leaders: BTreeSet<u64> = BTreeSet::new();
        leaders.insert(seed.address);
        let mut function_instructions: Vec<u64> = Vec::new();
        let mut function = FunctionBuilder {
            seed: seed.clone(),
            leaders: BTreeSet::new(),
        };

        while let Some(address) = queue.pop_front() {
            if control.is_cancelled() {
                cancelled = true;
                break;
            }
            if discovered.instructions.len() >= options.max_instructions {
                truncated = true;
                break;
            }
            if !image.contains(address) {
                continue;
            }
            if discovered.instructions.contains_key(&address) {
                continue;
            }
            if !visited.insert(address) {
                continue;
            }
            {
                if let Some(owner) = discovered.owner.get(&address) {
                    if *owner != seed.address {
                        continue;
                    }
                }
                if let Some((previous_address, previous)) =
                    discovered.instructions.range(..address).next_back()
                {
                    let previous_end = previous_address.saturating_add(previous.length as u64);
                    if address < previous_end {
                        diagnostics.push(
                            Some(address),
                            format!(
                                "overlapping code at {} (instruction at {} spans {} bytes)",
                                format_address(address),
                                format_address(*previous_address),
                                previous.length
                            ),
                        );
                        continue;
                    }
                }
            }
            let Some(instruction) = decode_instruction(image, address, processor, &mut formatter)
            else {
                diagnostics.push(
                    Some(address),
                    "unable to decode instruction (truncated code section)".to_string(),
                );
                continue;
            };
            // Traversal may reach this instruction after another branch has
            // already decoded a later start. Check both ends, including seeds.
            if discovered
                .instructions
                .range(address..instruction.end())
                .next()
                .is_some()
            {
                diagnostics.push(
                    Some(address),
                    "instruction overlaps an already decoded instruction".into(),
                );
                continue;
            }
            discovered.instructions.insert(address, instruction.clone());
            discovered.owner.insert(address, seed.address);
            function_instructions.push(address);
            processed_since_report += 1;

            if instruction.invalid {
                diagnostics.push(
                    Some(address),
                    "invalid instruction encountered; stopping this path".to_string(),
                );
            }

            match instruction.flow {
                InstructionFlow::Next | InstructionFlow::IndirectCall => {
                    let next = instruction.end();
                    if can_enter(image, next, seed.address, &function_starts) {
                        queue.push_back(next);
                    }
                }
                InstructionFlow::Call => {
                    let next = instruction.end();
                    if can_enter(image, next, seed.address, &function_starts) {
                        queue.push_back(next);
                    }
                    if options.follow_calls {
                        if let Some(target) = instruction.target {
                            if target != seed.address
                                && image.contains(target)
                                && !function_starts.contains(&target)
                            {
                                function_starts.insert(target);
                                function_queue.push_back(AnalysisSeed {
                                    address: target,
                                    name: None,
                                    origin: FunctionOrigin::CallTarget,
                                });
                            }
                        }
                    }
                }
                InstructionFlow::Jump => {
                    if let Some(target) = instruction.target {
                        if can_enter(image, target, seed.address, &function_starts) {
                            leaders.insert(target);
                            queue.push_back(target);
                        }
                    }
                }
                InstructionFlow::ConditionalJump => {
                    if let Some(target) = instruction.target {
                        if can_enter(image, target, seed.address, &function_starts) {
                            leaders.insert(target);
                            queue.push_back(target);
                        }
                    }
                    let next = instruction.end();
                    if can_enter(image, next, seed.address, &function_starts) {
                        leaders.insert(next);
                        queue.push_back(next);
                    }
                }
                InstructionFlow::IndirectJump => {
                    if !processor.x86() {
                        diagnostics.push(
                            Some(address),
                            "indirect transfer remains unresolved for this processor".into(),
                        );
                        continue;
                    }
                    let mut preceding = Vec::new();
                    let mut cursor = address;
                    for _ in 0..7 {
                        let Some((a, previous)) =
                            discovered.instructions.range(..cursor).next_back()
                        else {
                            break;
                        };
                        if previous.end() != cursor
                            || discovered.owner.get(a) != Some(&seed.address)
                        {
                            break;
                        }
                        let Some(bytes) = image.read(*a, previous.length as usize) else {
                            break;
                        };
                        preceding.push(
                            Decoder::with_ip(bitness as u32, bytes, *a, DecoderOptions::NONE)
                                .decode(),
                        );
                        cursor = *a;
                    }
                    preceding.reverse();
                    let decoded = Decoder::with_ip(
                        bitness as u32,
                        image.bytes_at(address).unwrap(),
                        address,
                        DecoderOptions::NONE,
                    )
                    .decode();
                    match crate::jumptable::recover(image, memory, bitness, &decoded, &preceding) {
                        Ok(table) => {
                            let valid = table.targets.iter().all(|t| {
                                let boundary = discovered
                                    .instructions
                                    .range(..=*t)
                                    .next_back()
                                    .map_or(true, |(a, i)| *a == *t || i.end() <= *t);
                                let length = Decoder::with_ip(
                                    bitness as u32,
                                    image.bytes_at(*t).unwrap(),
                                    *t,
                                    DecoderOptions::NONE,
                                )
                                .decode()
                                .len();
                                let Some(end) = t.checked_add(length as u64) else {
                                    return false;
                                };
                                let forward = discovered
                                    .instructions
                                    .range(*t..end)
                                    .all(|(a, _)| *a == *t);
                                boundary
                                    && forward
                                    && can_enter(image, *t, seed.address, &function_starts)
                                    && discovered.owner.get(t).map_or(true, |f| *f == seed.address)
                            });
                            if valid {
                                for target in &table.targets {
                                    leaders.insert(*target);
                                    queue.push_back(*target);
                                }
                                discovered.jump_tables.insert(address, table);
                            } else {
                                diagnostics.push(Some(address),"jump table rejected: target conflicts with an instruction or function boundary".into());
                            }
                        }
                        Err(reason) => diagnostics.push(Some(address), reason),
                    }
                }
                InstructionFlow::Return
                | InstructionFlow::Interrupt
                | InstructionFlow::Exception => {}
            }

            if processed_since_report >= 256 {
                processed_since_report = 0;
                control.report(AnalysisProgress {
                    stage: AnalysisStage::Discovering,
                    instructions: discovered.instructions.len(),
                    functions: discovered.functions.len() + 1,
                    blocks: 0,
                    current_address: Some(format_address(address)),
                });
            }
        }

        function.leaders = leaders;
        if !function_instructions.is_empty() {
            discovered.functions.insert(seed.address, function);
        } else {
            diagnostics.push(
                Some(seed.address),
                "function seed produced no decodable instructions".to_string(),
            );
        }
        if cancelled {
            break 'functions;
        }
    }

    if cancelled {
        diagnostics.push(None, "analysis cancelled by request".to_string());
    }
    if truncated {
        diagnostics.push(
            None,
            format!(
                "analysis stopped at a configured limit ({} instructions, {} functions, {} blocks)",
                options.max_instructions, options.max_functions, options.max_blocks
            ),
        );
    }

    control.report(AnalysisProgress {
        stage: AnalysisStage::Finalizing,
        instructions: discovered.instructions.len(),
        functions: discovered.functions.len(),
        blocks: 0,
        current_address: None,
    });

    let mut result = finalize(
        discovered,
        diagnostics,
        control,
        started,
        options,
        bitness,
        mapped,
    );
    result.report.cancelled |= cancelled;
    result.report.truncated |= truncated;
    result
}

fn finalize(
    mut discovered: Discovery,
    mut diagnostics: Diagnostics,
    control: &dyn AnalysisControl,
    started: Instant,
    options: &AnalysisOptions,
    _bitness: u8,
    mapped: &[(u64, u64)],
) -> ProgramAnalysis {
    let mut blocks: BTreeMap<u64, BasicBlock> = BTreeMap::new();
    let mut functions: Vec<Function> = Vec::new();
    let mut block_cap_hit = false;

    let mut function_addresses: Vec<u64> = discovered.functions.keys().copied().collect();
    function_addresses.sort_unstable();

    for address in function_addresses {
        if control.is_cancelled() {
            break;
        }
        let builder = discovered
            .functions
            .remove(&address)
            .expect("known function");
        let mut leaders: Vec<u64> = builder
            .leaders
            .iter()
            .copied()
            .filter(|leader| {
                discovered.owner.get(leader) == Some(&address)
                    && discovered.instructions.contains_key(leader)
            })
            .collect();
        if discovered.owner.get(&address) == Some(&address) {
            leaders.push(address);
        }
        leaders.sort_unstable();
        leaders.dedup();

        let leader_set: BTreeSet<u64> = leaders.iter().copied().collect();
        let mut block_starts: Vec<u64> = Vec::new();
        let mut function_instruction_count = 0usize;
        let mut function_end = address;

        for leader in leaders {
            if blocks.contains_key(&leader) {
                block_starts.push(leader);
                continue;
            }
            let mut addresses: Vec<u64> = Vec::new();
            let mut cursor = leader;
            while let Some(instruction) = discovered.instructions.get(&cursor) {
                if discovered.owner.get(&cursor) != Some(&address) {
                    break;
                }
                addresses.push(cursor);
                if instruction.is_terminal() {
                    break;
                }
                let next = instruction.end();
                if leader_set.contains(&next) || !discovered.instructions.contains_key(&next) {
                    break;
                }
                cursor = next;
            }
            if addresses.is_empty() {
                continue;
            }
            if blocks.len() >= options.max_blocks {
                block_cap_hit = true;
                break;
            }
            let last = discovered
                .instructions
                .get(addresses.last().expect("non empty"))
                .expect("instruction exists")
                .clone();
            let mut successors: Vec<Edge> = Vec::new();
            function_end = function_end.max(last.end());
            let mut push_edge = |target: u64, kind: EdgeKind| {
                if leader_set.contains(&target)
                    && !successors.iter().any(|edge| edge.target == target)
                {
                    successors.push(Edge { target, kind });
                }
            };
            match last.flow {
                InstructionFlow::ConditionalJump => {
                    if let Some(target) = last.target {
                        push_edge(target, EdgeKind::Taken);
                    }
                    push_edge(last.end(), EdgeKind::FallThrough);
                }
                InstructionFlow::Jump => {
                    if let Some(target) = last.target {
                        push_edge(target, EdgeKind::Jump);
                    }
                }
                InstructionFlow::Next | InstructionFlow::Call | InstructionFlow::IndirectCall => {
                    push_edge(last.end(), EdgeKind::FallThrough);
                }
                InstructionFlow::IndirectJump => {
                    if let Some(table) = discovered.jump_tables.get(&last.address) {
                        for target in &table.targets {
                            push_edge(*target, EdgeKind::Jump);
                        }
                    }
                }
                _ => {}
            }
            function_instruction_count += addresses.len();
            block_starts.push(leader);
            blocks.insert(
                leader,
                BasicBlock {
                    address: leader,
                    end: last.end(),
                    function: address,
                    instructions: addresses,
                    successors,
                },
            );
        }

        if !block_starts.is_empty() {
            functions.push(Function {
                address,
                end: function_end,
                origin: builder.seed.origin,
                symbol: builder.seed.name,
                blocks: block_starts,
                instruction_count: function_instruction_count,
                reference_count: 0,
                callers: Vec::new(),
                callees: Vec::new(),
            });
        }
        if block_cap_hit {
            diagnostics.push(
                None,
                "basic block limit reached; the CFG is incomplete".to_string(),
            );
            break;
        }
    }

    // Budget stops must never leave dangling edges or orphaned retained blocks.
    let retained: BTreeSet<_> = blocks.keys().copied().collect();
    for block in blocks.values_mut() {
        block.successors.retain(|e| retained.contains(&e.target));
    }

    let mut xref_set: BTreeSet<(u64, u64, u8, u8)> = BTreeSet::new();
    for (address, instruction) in &discovered.instructions {
        let flow_kind = match instruction.flow {
            InstructionFlow::Call => Some(XrefKind::Call),
            InstructionFlow::Jump => Some(XrefKind::Jump),
            InstructionFlow::ConditionalJump => Some(XrefKind::ConditionalJump),
            _ => None,
        };
        if let (Some(kind), Some(target)) = (flow_kind, instruction.target) {
            let kind_code = match kind {
                XrefKind::Call => 0,
                XrefKind::Jump => 1,
                XrefKind::ConditionalJump => 2,
                XrefKind::Data => 3,
            };
            xref_set.insert((*address, target, kind_code, 0));
        }
        for reference in &instruction.data_references {
            if !mapped_contains(mapped, reference.target) {
                continue;
            }
            let detail_code = match reference.kind {
                DataReferenceKind::RipRelative => 0,
                DataReferenceKind::PcRelative => 2,
                DataReferenceKind::Absolute => 1,
            };
            xref_set.insert((*address, reference.target, 3, detail_code));
        }
    }

    let mut data_xref_count = 0usize;
    let mut xrefs: Vec<Xref> = Vec::with_capacity(xref_set.len());
    for (from, to, kind_code, detail_code) in xref_set {
        let (kind, data_kind) = match kind_code {
            0 => (XrefKind::Call, None),
            1 => (XrefKind::Jump, None),
            2 => (XrefKind::ConditionalJump, None),
            _ => {
                data_xref_count += 1;
                let data_kind = if detail_code == 0 {
                    DataReferenceKind::RipRelative
                } else if detail_code == 2 {
                    DataReferenceKind::PcRelative
                } else {
                    DataReferenceKind::Absolute
                };
                (XrefKind::Data, Some(data_kind))
            }
        };
        xrefs.push(Xref {
            from,
            to,
            kind,
            data_kind,
            function: discovered.owner.get(&from).copied(),
        });
    }

    let function_by_address: BTreeMap<u64, usize> = functions
        .iter()
        .enumerate()
        .map(|(index, function)| (function.address, index))
        .collect();

    let find_function = |address: u64, _functions: &[Function]| -> Option<usize> {
        let block = blocks.range(..=address).next_back()?.1;
        if address < block.end {
            function_by_address.get(&block.function).copied()
        } else {
            None
        }
    };

    for xref in &xrefs {
        if let Some(function_index) = find_function(xref.to, &functions) {
            functions[function_index].reference_count += 1;
        }
        if xref.kind == XrefKind::Call {
            let caller = xref
                .function
                .and_then(|address| function_by_address.get(&address).copied());
            let callee = function_by_address
                .get(&xref.to)
                .copied()
                .or_else(|| find_function(xref.to, &functions));
            if let (Some(caller), Some(callee)) = (caller, callee) {
                if caller != callee {
                    let caller_address = functions[caller].address;
                    let callee_address = functions[callee].address;
                    if !functions[caller].callees.contains(&callee_address) {
                        functions[caller].callees.push(callee_address);
                    }
                    if !functions[callee].callers.contains(&caller_address) {
                        functions[callee].callers.push(caller_address);
                    }
                }
            }
        }
    }
    for function in &mut functions {
        function.callers.sort_unstable();
        function.callees.sort_unstable();
    }
    for block in blocks.values_mut() {
        block
            .successors
            .sort_by_key(|edge| (edge.target, edge.kind.name()));
    }

    let mut xrefs_to: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    let mut xrefs_from: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (index, xref) in xrefs.iter().enumerate() {
        xrefs_to.entry(xref.to).or_default().push(index);
        xrefs_from.entry(xref.from).or_default().push(index);
    }

    let report = AnalysisReport {
        instruction_count: discovered.instructions.len(),
        function_count: functions.len(),
        block_count: blocks.len(),
        xref_count: xrefs.len(),
        data_xref_count,
        cancelled: control.is_cancelled(),
        truncated: block_cap_hit,
        diagnostics_dropped: diagnostics.dropped,
        elapsed_ms: started.elapsed().as_millis() as u64,
        diagnostics: diagnostics.entries,
    };

    control.report(AnalysisProgress {
        stage: AnalysisStage::Complete,
        instructions: report.instruction_count,
        functions: report.function_count,
        blocks: report.block_count,
        current_address: None,
    });

    ProgramAnalysis {
        functions,
        blocks,
        instructions: discovered.instructions,
        xrefs,
        report,
        jump_tables: discovered.jump_tables,
        function_by_address,
        xrefs_to,
        xrefs_from,
    }
}

fn can_enter(
    image: &CodeImage<'_>,
    address: u64,
    current_function: u64,
    function_starts: &BTreeSet<u64>,
) -> bool {
    image.contains(address) && (address == current_function || !function_starts.contains(&address))
}

fn mapped_contains(mapped: &[(u64, u64)], address: u64) -> bool {
    mapped
        .iter()
        .any(|(start, end)| address >= *start && address < *end)
}

fn decode_instruction(
    image: &CodeImage<'_>,
    address: u64,
    processor: crate::processor::Processor,
    formatter: &mut IntelFormatter,
) -> Option<DecodedInstruction> {
    let bytes = image.bytes_at(address)?;
    let bitness = processor.bits();
    if !processor.x86() {
        let d = crate::processor::decode(processor, bytes, address).ok()?;
        let mut data_references = vec![];
        if processor == crate::processor::Processor::Aarch64
            && (matches!(d.mnemonic.as_str(), "adr" | "adrp")
                || d.args
                    .iter()
                    .any(|a| matches!(a.value, crate::processor::Arg::Imm(_)))
                    && d.flow == InstructionFlow::Next)
        {
            if let Some(target) = d.args.iter().rev().find_map(|a| {
                if let crate::processor::Arg::Imm(n) = a.value {
                    Some(n as u64)
                } else {
                    None
                }
            }) {
                if matches!(d.mnemonic.as_str(), "adr" | "adrp" | "ldr" | "ldrsw") {
                    data_references.push(DataReference {
                        target,
                        kind: DataReferenceKind::PcRelative,
                    });
                }
            }
        }
        return Some(DecodedInstruction {
            address,
            length: d.length as u8,
            flow: d.flow,
            target: d.target,
            data_references,
            invalid: false,
            mnemonic: d.mnemonic,
            operands: d.text,
        });
    }
    let mut decoder = Decoder::with_ip(bitness as u32, bytes, address, DecoderOptions::NONE);
    if !decoder.can_decode() {
        return None;
    }
    let instruction: Instruction = decoder.decode();
    if instruction.len() == 0 {
        return None;
    }
    let flow = flow_of(instruction.flow_control());
    let target = direct_target(&instruction);
    let data_references = data_references(&instruction);
    let invalid = instruction.is_invalid();

    let mut mnemonic = String::new();
    formatter.format_mnemonic(&instruction, &mut mnemonic);
    let mut operands = String::new();
    if !invalid {
        for operand in 0..instruction.op_count() {
            if operand > 0 {
                formatter.format_operand_separator(&instruction, &mut operands);
            }
            let _ = formatter.format_operand(&instruction, &mut operands, operand);
        }
    }

    Some(DecodedInstruction {
        address,
        length: instruction.len() as u8,
        flow,
        target,
        data_references,
        invalid,
        mnemonic: mnemonic.trim().to_string(),
        operands: operands.trim().to_string(),
    })
}

fn data_references(instruction: &Instruction) -> Vec<DataReference> {
    if instruction.is_invalid() {
        return Vec::new();
    }
    let mut references = Vec::new();
    for operand in 0..instruction.op_count() {
        if instruction.op_kind(operand) != OpKind::Memory {
            continue;
        }
        if instruction.is_ip_rel_memory_operand() {
            references.push(DataReference {
                target: instruction.ip_rel_memory_address(),
                kind: DataReferenceKind::RipRelative,
            });
        } else if instruction.memory_base() == Register::None
            && instruction.memory_index() == Register::None
        {
            let target = instruction.memory_displacement64();
            if target != 0 {
                references.push(DataReference {
                    target,
                    kind: DataReferenceKind::Absolute,
                });
            }
        }
        break;
    }
    references
}

fn flow_of(flow: FlowControl) -> InstructionFlow {
    match flow {
        FlowControl::Next => InstructionFlow::Next,
        FlowControl::Call => InstructionFlow::Call,
        FlowControl::IndirectCall => InstructionFlow::IndirectCall,
        FlowControl::UnconditionalBranch => InstructionFlow::Jump,
        FlowControl::ConditionalBranch => InstructionFlow::ConditionalJump,
        FlowControl::IndirectBranch => InstructionFlow::IndirectJump,
        FlowControl::Return => InstructionFlow::Return,
        FlowControl::Interrupt => InstructionFlow::Interrupt,
        FlowControl::XbeginXabortXend | FlowControl::Exception => InstructionFlow::Exception,
    }
}

fn direct_target(instruction: &Instruction) -> Option<u64> {
    match instruction.flow_control() {
        FlowControl::Call | FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
            match instruction.op0_kind() {
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    Some(instruction.near_branch_target())
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn sanitize_name(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .collect::<String>()
        .trim()
        .trim_matches('\u{0}')
        .chars()
        .take(256)
        .collect()
}

#[derive(Default)]
struct Diagnostics {
    entries: Vec<AnalysisDiagnostic>,
    dropped: usize,
}

impl Diagnostics {
    fn push(&mut self, address: Option<u64>, message: String) {
        if self.entries.len() >= MAX_ANALYSIS_DIAGNOSTICS {
            self.dropped += 1;
            return;
        }
        self.entries.push(AnalysisDiagnostic {
            address: address.map(format_address),
            message,
        });
    }
}

#[derive(Default)]
struct Discovery {
    instructions: BTreeMap<u64, DecodedInstruction>,
    owner: BTreeMap<u64, u64>,
    functions: BTreeMap<u64, FunctionBuilder>,
    jump_tables: BTreeMap<u64, JumpTable>,
}

struct FunctionBuilder {
    seed: AnalysisSeed,
    leaders: BTreeSet<u64>,
}

pub fn architecture_supports_analysis(architecture: CpuArchitecture) -> bool {
    matches!(
        architecture,
        CpuArchitecture::X86
            | CpuArchitecture::X86_64
            | CpuArchitecture::Aarch64
            | CpuArchitecture::Arm
            | CpuArchitecture::Riscv32
            | CpuArchitecture::Riscv64
    )
}
