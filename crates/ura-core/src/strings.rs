use crate::address::format_address;
use crate::binary::Analysis;
use crate::MAX_STRINGS;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractedString {
    pub offset: String,
    pub address: Option<String>,
    pub section: Option<String>,
    pub encoding: String,
    pub value: String,
    pub length: usize,
}

#[derive(Debug, Clone)]
pub struct StringScanOptions {
    pub min_length: usize,
    pub ascii: bool,
    pub utf16le: bool,
    pub max_results: usize,
}

impl Default for StringScanOptions {
    fn default() -> Self {
        StringScanOptions {
            min_length: 4,
            ascii: true,
            utf16le: true,
            max_results: MAX_STRINGS,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StringScanResult {
    pub strings: Vec<ExtractedString>,
    pub truncated: bool,
    pub ascii_count: usize,
    pub utf16_count: usize,
    pub scanned_bytes: u64,
}

pub fn extract_strings(
    data: &[u8],
    analysis: &Analysis,
    options: &StringScanOptions,
) -> StringScanResult {
    let min_length = options.min_length.clamp(2, 512);
    let max_results = options.max_results.clamp(1, MAX_STRINGS);
    let mut strings = Vec::new();
    let mut truncated = false;
    let mut ascii_count = 0usize;
    let mut utf16_count = 0usize;

    if options.ascii {
        let mut index = 0usize;
        while index < data.len() {
            if is_printable_ascii(data[index]) {
                let start = index;
                while index < data.len() && is_printable_ascii(data[index]) {
                    index += 1;
                }
                let length = index - start;
                if length >= min_length {
                    ascii_count += 1;
                    if strings.len() < max_results {
                        strings.push(make_string(
                            analysis,
                            start as u64,
                            "ASCII",
                            String::from_utf8_lossy(&data[start..index]).to_string(),
                            length,
                        ));
                    } else {
                        truncated = true;
                        break;
                    }
                }
            } else {
                index += 1;
            }
        }
    }

    if options.utf16le && !truncated {
        let mut index = 0usize;
        while index + 1 < data.len() {
            let mut cursor = index;
            let mut chars: Vec<char> = Vec::new();
            let mut ascii_chars = 0usize;
            while cursor + 1 < data.len() {
                let unit = u16::from_le_bytes([data[cursor], data[cursor + 1]]);
                match char::from_u32(unit as u32) {
                    Some(ch) if !ch.is_control() => {
                        if ch.is_ascii() && !ch.is_ascii_control() {
                            ascii_chars += 1;
                        }
                        chars.push(ch);
                        cursor += 2;
                    }
                    _ => break,
                }
            }
            if chars.len() >= min_length && ascii_chars >= 1 && ascii_chars * 3 >= chars.len() {
                utf16_count += 1;
                if strings.len() < max_results {
                    let value: String = chars.iter().collect();
                    let byte_length = chars.len() * 2;
                    strings.push(make_string(
                        analysis,
                        index as u64,
                        "UTF-16LE",
                        value,
                        byte_length,
                    ));
                } else {
                    truncated = true;
                    break;
                }
                index = cursor.max(index + 2);
            } else {
                index += 1;
            }
        }
    }

    strings.sort_by(|left, right| left.offset.cmp(&right.offset));

    StringScanResult {
        strings,
        truncated,
        ascii_count,
        utf16_count,
        scanned_bytes: data.len() as u64,
    }
}

fn make_string(
    analysis: &Analysis,
    offset: u64,
    encoding: &str,
    value: String,
    length: usize,
) -> ExtractedString {
    let section = analysis
        .section_containing_file_offset(offset)
        .map(|section| section.name.clone());
    ExtractedString {
        offset: format_address(offset),
        address: analysis.file_offset_to_address(offset).map(format_address),
        section,
        encoding: encoding.to_string(),
        value,
        length,
    }
}

fn is_printable_ascii(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7e)
}
