use crate::error::{Result, UraError};

pub fn format_address(value: u64) -> String {
    format!("0x{:X}", value)
}

pub fn format_offset(value: u64) -> String {
    format!("0x{:X}", value)
}

pub fn parse_address(input: &str) -> Result<u64> {
    let trimmed = input
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    let cleaned: String = trimmed.chars().filter(|c| *c != '_').collect();
    if cleaned.is_empty() {
        return Err(UraError::InvalidAddress(input.to_string()));
    }
    u64::from_str_radix(&cleaned, 16).map_err(|_| UraError::InvalidAddress(input.to_string()))
}

pub fn checked_range(offset: u64, length: u64, total: u64) -> Result<(usize, usize)> {
    if length == 0 {
        return Err(UraError::InvalidRange);
    }
    let end = offset.checked_add(length).ok_or(UraError::InvalidRange)?;
    if end > total {
        return Err(UraError::InvalidRange);
    }
    Ok((offset as usize, length as usize))
}
