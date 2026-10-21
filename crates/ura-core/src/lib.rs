pub mod address;
pub mod analysis;
pub mod binary;
pub mod decomp;
pub mod disasm;
pub mod error;
pub mod hex;
pub mod ir;
mod jumptable;
pub mod strings;

pub use address::{format_address, format_offset, parse_address};
pub use analysis::{
    analyze_binary as analyze_functions, analyze_binary_with_seeds, analyze_image,
    analyze_image_mapped, architecture_supports_analysis, seeds_for_binary, AnalysisControl,
    AnalysisDiagnostic, AnalysisOptions, AnalysisProgress, AnalysisReport, AnalysisSeed,
    AnalysisStage, BasicBlock, CodeImage, CodeRegion, DataReference, DataReferenceKind,
    DecodedInstruction, Edge, EdgeKind, Function, FunctionOrigin, InstructionFlow, ProgramAnalysis,
    Xref, XrefKind,
};
pub use binary::{
    analyze_path, Analysis, BinaryOpenResult, BinaryView, CpuArchitecture, Endianness, ExportInfo,
    ImportInfo, LoadedBinary, Section, SectionView, Symbol, SymbolView,
};
pub use disasm::{
    decoder_for, disassemble, DisassemblyPage, InstructionDecoder, InstructionView, X86Decoder,
};
pub use error::{Result, UraError};
pub use hex::{read_hex_page, HexPage, MAX_HEX_READ};
pub use strings::{extract_strings, ExtractedString, StringScanOptions, StringScanResult};

use sha2::{Digest, Sha256};
use std::path::Path;

pub const MAX_FILE_SIZE: u64 = 512 * 1024 * 1024;
pub const MAX_SYMBOLS: usize = 50_000;
pub const MAX_IMPORTS: usize = 20_000;
pub const MAX_EXPORTS: usize = 20_000;
pub const MAX_STRINGS: usize = 200_000;
pub const MAX_INSTRUCTIONS: usize = 2_000;

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let data = std::fs::read(path)?;
    Ok(sha256_hex(&data))
}
