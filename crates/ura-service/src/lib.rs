pub mod debugger;
mod decomp;
pub mod dynamic;
pub use debugger::{DebugPermissions, DebugService};
pub mod dto;
pub mod error;
mod ir;
mod patch;
pub mod paths;
mod service;
pub mod symbolic;
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
pub use patch::{patch_address, EffectiveBytes, PatchList};
pub use paths::PathPolicy;
pub use service::Service;

pub const RESPONSE_SCHEMA_VERSION: u32 = 1;
