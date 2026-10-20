use serde::Serialize;
use thiserror::Error;
use ura_core::UraError;
use ura_project::ProjectError;

use crate::RESPONSE_SCHEMA_VERSION;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("{0}")]
    InvalidArgument(String),
    #[error("unknown binary handle: {0}")]
    UnknownHandle(String),
    #[error("function analysis has not run for this handle; call ura_analyze first")]
    AnalysisRequired,
    #[error("no function contains address {0}")]
    FunctionNotFound(String),
    #[error("path is outside the allowed analysis roots: {0}")]
    PathDenied(String),
    #[error("the project does not record the opened binary's SHA-256")]
    ProjectBinaryMismatch,
    #[error("file-writing operations are disabled for this process")]
    WriteDisabled,
    #[error("{0}")]
    LimitExceeded(String),
    #[error(transparent)]
    Engine(#[from] UraError),
    #[error(transparent)]
    Project(#[from] ProjectError),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl ServiceError {
    pub fn code(&self) -> &'static str {
        match self {
            ServiceError::InvalidArgument(_) => "invalid_argument",
            ServiceError::UnknownHandle(_) => "unknown_handle",
            ServiceError::AnalysisRequired => "analysis_required",
            ServiceError::FunctionNotFound(_) => "function_not_found",
            ServiceError::PathDenied(_) => "path_denied",
            ServiceError::ProjectBinaryMismatch => "project_binary_mismatch",
            ServiceError::WriteDisabled => "write_disabled",
            ServiceError::LimitExceeded(_) => "limit_exceeded",
            ServiceError::Engine(error) => match error {
                UraError::Io(_) => "io_error",
                UraError::UnsupportedFormat(_) => "unsupported_format",
                UraError::Parse(_) => "parse_error",
                UraError::FileTooLarge { .. } => "file_too_large",
                UraError::InvalidAddress(_) => "invalid_address",
                UraError::NoCodeAt(_) => "no_code_at",
                UraError::UnmappedAddress(_) => "unmapped_address",
                UraError::UnsupportedArchitecture(_) => "unsupported_architecture",
                UraError::InvalidRange => "invalid_range",
                UraError::Disassembly(_) => "disassembly_error",
                UraError::NoBinaryLoaded => "no_binary",
                UraError::Project(_) => "project_error",
            },
            ServiceError::Project(error) => match error {
                ProjectError::NotFound(_) => "project_not_found",
                ProjectError::AlreadyExists(_) => "project_exists",
                ProjectError::UnsupportedSchema { .. } => "unsupported_project_schema",
                ProjectError::InvalidProject(_) => "invalid_project",
                ProjectError::InvalidAddress(_) => "invalid_address",
                ProjectError::InvalidName(_) => "invalid_name",
                ProjectError::InvalidViewState(_) => "invalid_view_state",
                ProjectError::InvalidExport(_) => "invalid_export",
                ProjectError::Io(_) => "io_error",
                ProjectError::Database(_) => "project_database_error",
            },
            ServiceError::Io(_) => "io_error",
            ServiceError::Serialization(_) => "serialization_error",
            ServiceError::Internal(_) => "internal_error",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorView {
    pub schema_version: u32,
    pub error: ErrorBody,
}

impl ErrorView {
    pub fn new(error: &ServiceError) -> Self {
        Self {
            schema_version: RESPONSE_SCHEMA_VERSION,
            error: ErrorBody {
                code: error.code().to_string(),
                message: error.to_string(),
            },
        }
    }
}

pub type ServiceResult<T> = Result<T, ServiceError>;
