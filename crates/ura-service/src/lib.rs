pub mod dto;
pub mod error;
mod ir;
pub mod paths;
mod service;
pub use ir::{DiagnosticsPage, DominatorPage, IrPage};

pub use dto::{
    AnalysisOptionsView, AnalyzeResponse, BinaryInfoResponse, BlockSummary, BytesResponse,
    CfgBlock, CfgResponse, CloseBinaryResponse, CommentResponse, DisassemblyResponse, EdgeView,
    ExportResponse, FunctionDetailResponse, FunctionListResponse, FunctionRef, FunctionSort,
    FunctionSummary, OpenBinaryResponse, RenameFunctionResponse, SaveProjectResponse,
    StringsResponse, XrefDirection, XrefView, XrefsResponse,
};
pub use error::{ErrorBody, ErrorView, ServiceError};
pub use paths::PathPolicy;
pub use service::Service;

pub const RESPONSE_SCHEMA_VERSION: u32 = 1;
