use crate::address::format_address;
use crate::binary::Analysis;
use crate::error::{Result, UraError};
use serde::Serialize;

pub const MAX_HEX_READ: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HexPage {
    pub offset: String,
    pub requested_length: usize,
    pub data: Vec<u8>,
    pub eof: bool,
    pub address: Option<String>,
    pub section: Option<String>,
    pub file_size: u64,
}

pub fn read_hex_page(
    data: &[u8],
    analysis: &Analysis,
    offset: u64,
    length: usize,
) -> Result<HexPage> {
    if length == 0 || length > MAX_HEX_READ {
        return Err(UraError::InvalidRange);
    }
    if offset >= data.len() as u64 {
        return Err(UraError::InvalidRange);
    }
    let start = offset as usize;
    let end = start.saturating_add(length).min(data.len());
    let section = analysis
        .section_containing_file_offset(offset)
        .map(|section| section.name.clone());
    Ok(HexPage {
        offset: format_address(offset),
        requested_length: length,
        data: data[start..end].to_vec(),
        eof: end >= data.len(),
        address: analysis.file_offset_to_address(offset).map(format_address),
        section,
        file_size: data.len() as u64,
    })
}
