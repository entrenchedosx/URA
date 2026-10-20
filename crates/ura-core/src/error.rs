use thiserror::Error;

#[derive(Debug, Error)]
pub enum UraError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("unsupported file format: {0}")]
    UnsupportedFormat(String),
    #[error("failed to parse binary: {0}")]
    Parse(String),
    #[error("file is {size} bytes which exceeds the {limit} byte analysis limit")]
    FileTooLarge { size: u64, limit: u64 },
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("no executable section contains address {0}")]
    NoCodeAt(String),
    #[error("address {0} is not backed by file data")]
    UnmappedAddress(String),
    #[error("architecture {0} is not supported by the disassembler")]
    UnsupportedArchitecture(String),
    #[error("invalid byte range requested")]
    InvalidRange,
    #[error("disassembly failed: {0}")]
    Disassembly(String),
    #[error("analysis is unavailable until a binary is loaded")]
    NoBinaryLoaded,
    #[error("project error: {0}")]
    Project(String),
}

impl From<std::io::Error> for UraError {
    fn from(value: std::io::Error) -> Self {
        UraError::Io(value.to_string())
    }
}

impl From<object::Error> for UraError {
    fn from(value: object::Error) -> Self {
        UraError::Parse(value.to_string())
    }
}

pub type Result<T> = std::result::Result<T, UraError>;
