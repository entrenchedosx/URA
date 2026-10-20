use std::str::FromStr;

use serde::Serialize;
use ura_core::{
    AnalysisOptions, AnalysisReport, BinaryView, DisassemblyPage, ExtractedString, SectionView,
};
use ura_project::{Annotation, ExportSummary, ProjectInfo};

use crate::error::ServiceError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionSort {
    Address,
    Name,
    Instructions,
    References,
}

impl FunctionSort {
    pub fn name(self) -> &'static str {
        match self {
            FunctionSort::Address => "address",
            FunctionSort::Name => "name",
            FunctionSort::Instructions => "instructions",
            FunctionSort::References => "references",
        }
    }
}

impl FromStr for FunctionSort {
    type Err = ServiceError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "address" | "" => Ok(FunctionSort::Address),
            "name" => Ok(FunctionSort::Name),
            "instructions" | "instruction" => Ok(FunctionSort::Instructions),
            "references" | "reference" | "refs" => Ok(FunctionSort::References),
            other => Err(ServiceError::InvalidArgument(format!(
                "unknown function sort '{other}'; expected address, name, instructions or references"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefDirection {
    To,
    From,
}

impl XrefDirection {
    pub fn name(self) -> &'static str {
        match self {
            XrefDirection::To => "to",
            XrefDirection::From => "from",
        }
    }
}

impl FromStr for XrefDirection {
    type Err = ServiceError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "to" | "" => Ok(XrefDirection::To),
            "from" => Ok(XrefDirection::From),
            other => Err(ServiceError::InvalidArgument(format!(
                "unknown xref direction '{other}'; expected to or from"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenBinaryResponse {
    pub schema_version: u32,
    pub handle: String,
    pub attached_project: Option<String>,
    pub info: BinaryView,
    pub sections: Vec<SectionView>,
    pub imports: Vec<ura_core::binary::ImportView>,
    pub exports: Vec<ura_core::binary::ExportView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BinaryInfoResponse {
    pub schema_version: u32,
    pub handle: String,
    pub attached_project: Option<String>,
    pub analyzed: bool,
    pub function_count: Option<usize>,
    pub info: BinaryView,
    pub sections: Vec<SectionView>,
    pub imports: Vec<ura_core::binary::ImportView>,
    pub exports: Vec<ura_core::binary::ExportView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseBinaryResponse {
    pub schema_version: u32,
    pub handle: String,
    pub closed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisOptionsView {
    pub max_instructions: usize,
    pub max_functions: usize,
    pub max_blocks: usize,
    pub follow_calls: bool,
}

impl From<&AnalysisOptions> for AnalysisOptionsView {
    fn from(options: &AnalysisOptions) -> Self {
        Self {
            max_instructions: options.max_instructions,
            max_functions: options.max_functions,
            max_blocks: options.max_blocks,
            follow_calls: options.follow_calls,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyzeResponse {
    pub schema_version: u32,
    pub handle: String,
    pub options: AnalysisOptionsView,
    pub report: AnalysisReport,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionSummary {
    pub address: String,
    pub end: String,
    pub name: String,
    pub symbol: Option<String>,
    pub origin: String,
    pub verified: bool,
    pub size: u64,
    pub instruction_count: usize,
    pub block_count: usize,
    pub reference_count: usize,
    pub caller_count: usize,
    pub callee_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionRef {
    pub address: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionListResponse {
    pub schema_version: u32,
    pub handle: String,
    pub query: Option<String>,
    pub sort: String,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub returned: usize,
    pub functions: Vec<FunctionSummary>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdgeView {
    pub target: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockSummary {
    pub address: String,
    pub end: String,
    pub instruction_count: usize,
    pub successors: Vec<EdgeView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionDetailResponse {
    pub schema_version: u32,
    pub handle: String,
    pub function: FunctionSummary,
    pub callers: Vec<FunctionRef>,
    pub callees: Vec<FunctionRef>,
    pub blocks: Vec<BlockSummary>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CfgBlock {
    pub address: String,
    pub end: String,
    pub instructions: Vec<String>,
    pub successors: Vec<EdgeView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CfgResponse {
    pub schema_version: u32,
    pub handle: String,
    pub function: FunctionSummary,
    pub max_blocks: usize,
    pub truncated: bool,
    pub blocks: Vec<CfgBlock>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XrefView {
    pub from: String,
    pub to: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XrefsResponse {
    pub schema_version: u32,
    pub handle: String,
    pub address: String,
    pub direction: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub total: usize,
    pub returned: usize,
    pub truncated: bool,
    pub xrefs: Vec<XrefView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DisassemblyResponse {
    pub schema_version: u32,
    pub handle: String,
    #[serde(flatten)]
    pub page: DisassemblyPage,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StringsResponse {
    pub schema_version: u32,
    pub handle: String,
    pub min_length: usize,
    pub ascii: bool,
    pub utf16le: bool,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub returned: usize,
    pub has_more: bool,
    pub scan_truncated: bool,
    pub ascii_count: usize,
    pub utf16_count: usize,
    pub scanned_bytes: u64,
    pub strings: Vec<ExtractedString>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BytesResponse {
    pub schema_version: u32,
    pub handle: String,
    pub offset: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    pub requested_length: usize,
    pub returned_length: usize,
    pub eof: bool,
    pub file_size: u64,
    pub hex: String,
    pub ascii: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveProjectResponse {
    pub schema_version: u32,
    pub handle: String,
    pub created: bool,
    pub project: ProjectInfo,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenameFunctionResponse {
    pub schema_version: u32,
    pub handle: String,
    pub project: String,
    pub function: FunctionSummary,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommentResponse {
    pub schema_version: u32,
    pub handle: String,
    pub project: String,
    pub annotation: Annotation,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportResponse {
    pub schema_version: u32,
    pub project: String,
    pub export: ExportSummary,
}
