use crate::address::format_address;
use crate::binary::{CpuArchitecture, LoadedBinary};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter, OpKind,
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
}

impl FunctionOrigin {
    pub fn name(self) -> &'static str {
        match self {
            FunctionOrigin::EntryPoint => "entryPoint",
            FunctionOrigin::Export => "export",
            FunctionOrigin::Symbol => "symbol",
            FunctionOrigin::CallTarget => "callTarget",
        }
    }

    fn priority(self) -> u8 {
        match self {
            FunctionOrigin::EntryPoint => 4,
            FunctionOrigin::Export => 3,
            FunctionOrigin::Symbol => 2,
            FunctionOrigin::CallTarget => 1,
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
}

impl XrefKind {
    pub fn name(self) -> &'static str {
        match self {
            XrefKind::Call => "call",
            XrefKind::Jump => "jump",
            XrefKind::ConditionalJump => "conditionalJump",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DecodedInstruction {
    pub address: u64,
    pub length: u8,
    pub flow: InstructionFlow,
    pub target: Option<u64>,
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
    function_by_address: BTreeMap<u64, usize>,
    xrefs_to: BTreeMap<u64, Vec<usize>>,
    xrefs_from: BTreeMap<u64, Vec<usize>>,
}

impl ProgramAnalysis {
    pub fn function_by_start(&self, address: u64) -> Option<&Function> {
        self.function_by_address
            .get(&address)
            .map(|index| &self.functions[*index])
    }

    pub fn function_containing(&self, address: u64) -> Option<&Function> {
        let index = self
            .functions
            .partition_point(|function| function.address <= address);
        let candidate = index.checked_sub(1)?;
        let function = &self.functions[candidate];
        if address < function.end {
            Some(function)
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
    let image = CodeImage::from_binary(binary);
    let analysis = binary.analysis();
    let seeds = seeds_for_binary(binary);
    let options = options.normalized();
    analyze_image(
        &image,
        analysis.bitness,
        analysis.entry_point,
        &seeds,
        &options,
        control,
    )
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
    let normalized_options = options.normalized();
    let options = &normalized_options;
    let started = Instant::now();
    let mut diagnostics = Diagnostics::default();
    let mut discovered = Discovery::default();

    if bitness != 32 && bitness != 64 {
        diagnostics.push(
            None,
            format!(
                "function analysis supports x86/x86-64 only (bitness {})",
                bitness
            ),
        );
        return finalize(discovered, diagnostics, control, started, options, bitness);
    }
    if image.is_empty() {
        diagnostics.push(
            None,
            "the binary has no executable file-backed sections".to_string(),
        );
        return finalize(discovered, diagnostics, control, started, options, bitness);
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
            if address != seed.address {
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
            let Some(instruction) = decode_instruction(image, address, bitness, &mut formatter)
            else {
                diagnostics.push(
                    Some(address),
                    "unable to decode instruction (truncated code section)".to_string(),
                );
                continue;
            };
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
                InstructionFlow::IndirectJump
                | InstructionFlow::Return
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

    let mut result = finalize(discovered, diagnostics, control, started, options, bitness);
    result.report.cancelled = cancelled;
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
                function_end = function_end.max(instruction.end());
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

        if block_cap_hit {
            diagnostics.push(
                None,
                "basic block limit reached; the CFG is incomplete".to_string(),
            );
            break;
        }

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

    let mut xref_set: BTreeSet<(u64, u64, u8)> = BTreeSet::new();
    for (address, instruction) in &discovered.instructions {
        let kind = match instruction.flow {
            InstructionFlow::Call => Some(XrefKind::Call),
            InstructionFlow::Jump => Some(XrefKind::Jump),
            InstructionFlow::ConditionalJump => Some(XrefKind::ConditionalJump),
            _ => None,
        };
        let (Some(kind), Some(target)) = (kind, instruction.target) else {
            continue;
        };
        let kind_code = match kind {
            XrefKind::Call => 0,
            XrefKind::Jump => 1,
            XrefKind::ConditionalJump => 2,
        };
        xref_set.insert((*address, target, kind_code));
    }

    let mut xrefs: Vec<Xref> = Vec::with_capacity(xref_set.len());
    for (from, to, kind_code) in xref_set {
        let kind = match kind_code {
            0 => XrefKind::Call,
            1 => XrefKind::Jump,
            _ => XrefKind::ConditionalJump,
        };
        xrefs.push(Xref {
            from,
            to,
            kind,
            function: discovered.owner.get(&from).copied(),
        });
    }

    let function_by_address: BTreeMap<u64, usize> = functions
        .iter()
        .enumerate()
        .map(|(index, function)| (function.address, index))
        .collect();

    let find_function = |address: u64, functions: &[Function]| -> Option<usize> {
        let index = functions.partition_point(|function| function.address <= address);
        let candidate = index.checked_sub(1)?;
        if address < functions[candidate].end {
            Some(candidate)
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
        cancelled: false,
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

fn decode_instruction(
    image: &CodeImage<'_>,
    address: u64,
    bitness: u8,
    formatter: &mut IntelFormatter,
) -> Option<DecodedInstruction> {
    let bytes = image.bytes_at(address)?;
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
        invalid,
        mnemonic: mnemonic.trim().to_string(),
        operands: operands.trim().to_string(),
    })
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
}

struct FunctionBuilder {
    seed: AnalysisSeed,
    leaders: BTreeSet<u64>,
}

pub fn architecture_supports_analysis(architecture: CpuArchitecture) -> bool {
    matches!(architecture, CpuArchitecture::X86 | CpuArchitecture::X86_64)
}
