mod decomp;
pub mod dto;
pub mod error;
mod ir;
pub mod paths;
mod service;
pub use ir::{DiagnosticsPage, DominatorPage, IrPage};

pub use dto::{
    AnalysisOptionsView, AnalyzeResponse, BinaryInfoResponse, BlockSummary, BytesResponse,
    CallGraphEdgeView, CallGraphNodeView, CallGraphResponse, CfgBlock, CfgResponse,
    CloseBinaryResponse, CommentResponse, DisassemblyResponse, EdgeView, ExportResponse,
    FunctionDetailResponse, FunctionListResponse, FunctionRef, FunctionSort, FunctionSummary,
    HighLevelResponse, OpenBinaryResponse, RenameFunctionResponse, SaveProjectResponse,
    SignatureResponse, StackFrameResponse, StackVariableResponse, StringsResponse, TypesResponse,
    XrefDirection, XrefView, XrefsResponse,
};
pub use error::{ErrorBody, ErrorView, ServiceError};
pub use paths::PathPolicy;
pub use service::Service;

pub const RESPONSE_SCHEMA_VERSION: u32 = 1;
