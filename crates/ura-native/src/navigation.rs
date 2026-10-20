use serde::{Deserialize, Serialize};
use ura_core::{Analysis, parse_address};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    pub address: Option<u64>,
    pub file_offset: Option<u64>,
}

impl Location {
    pub fn address(analysis: &Analysis, address: u64) -> Self {
        Self {
            address: Some(address),
            file_offset: analysis.address_to_file_offset(address),
        }
    }
    pub fn offset(analysis: &Analysis, offset: u64) -> Self {
        Self {
            address: analysis.file_offset_to_address(offset),
            file_offset: Some(offset),
        }
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct History {
    pub entries: Vec<Location>,
    pub index: usize,
}

impl History {
    pub fn visit(&mut self, location: Location) {
        if self.entries.get(self.index) == Some(&location) {
            return;
        }
        self.entries.truncate(self.index.saturating_add(1));
        self.entries.push(location);
        if self.entries.len() > 100 {
            self.entries.remove(0);
        }
        self.index = self.entries.len() - 1;
    }
    pub fn step(&mut self, delta: isize) -> Option<Location> {
        let index = self.index.checked_add_signed(delta)?;
        let location = *self.entries.get(index)?;
        self.index = index;
        Some(location)
    }
    pub fn normalize(&mut self) {
        self.entries
            .retain(|v| v.address.is_some() || v.file_offset.is_some());
        if self.entries.len() > 100 {
            self.entries.drain(..self.entries.len() - 100);
        }
        self.index = self.index.min(self.entries.len().saturating_sub(1));
    }
}

pub fn resolve(
    input: &str,
    analysis: &Analysis,
    current: Location,
    file_size: u64,
) -> Result<Location, String> {
    let input = input.trim();
    let lower = input.to_lowercase();
    for prefix in ["@", "file:", "offset "] {
        if let Some(value) = lower.strip_prefix(prefix) {
            let offset = parse_address(value.trim()).map_err(|e| e.to_string())?;
            return if offset < file_size {
                Ok(Location::offset(analysis, offset))
            } else {
                Err("File offset is outside the binary".into())
            };
        }
    }
    if input.starts_with(['+', '-']) {
        let delta = parse_address(input[1..].trim()).map_err(|e| e.to_string())?;
        let base = current.address.ok_or("Select a mapped address first")?;
        let address = if input.starts_with('+') {
            base.checked_add(delta)
        } else {
            base.checked_sub(delta)
        }
        .ok_or("Address overflow")?;
        return Ok(Location::address(analysis, address));
    }
    for section in &analysis.sections {
        if input == section.name {
            return Ok(Location::address(analysis, section.address));
        }
        if let Some(suffix) = input.strip_prefix(&section.name) {
            let suffix = suffix.trim();
            if suffix.starts_with(['+', '-']) {
                let delta = parse_address(suffix[1..].trim()).map_err(|e| e.to_string())?;
                let address = if suffix.starts_with('+') {
                    if delta >= section.size {
                        return Err("Offset is outside the section".into());
                    }
                    section.address.checked_add(delta)
                } else {
                    section.address.checked_sub(delta)
                };
                return address
                    .map(|v| Location::address(analysis, v))
                    .ok_or("Address overflow".into());
            }
        }
    }
    if let Some(symbol) = analysis
        .symbols
        .iter()
        .find(|s| s.name == input && s.address.is_some())
    {
        return Ok(Location::address(analysis, symbol.address.unwrap()));
    }
    if let Some(export) = analysis.exports.iter().find(|s| s.name == input) {
        return Ok(Location::address(analysis, export.address));
    }
    // A pasted dump starts with an address and then at least two byte tokens.
    let words: Vec<_> = input.split_whitespace().collect();
    let value = if words.len() >= 3
        && words[1..]
            .iter()
            .all(|w| (1..=4).contains(&w.len()) && w.chars().all(|c| c.is_ascii_hexdigit()))
    {
        words[0].trim_end_matches(':')
    } else {
        input
    };
    parse_address(value)
        .map(|v| Location::address(analysis, v))
        .map_err(|_| "No matching address, offset, section or symbol".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> ura_core::LoadedBinary {
        ura_core::analyze_path(std::path::Path::new("../../tests/fixtures/ura64.exe")).unwrap()
    }
    #[test]
    fn navigation_forms_and_bounds() {
        let b = fixture();
        let a = b.analysis();
        let cur = Location::address(a, 0x140001000);
        for (input, address, offset) in [
            ("@0x200", Some(0x140001000), Some(0x200)),
            (".text+0x10", Some(0x140001010), Some(0x210)),
            ("+10", Some(0x140001010), Some(0x210)),
            ("140001000: 48 83 ec 28", Some(0x140001000), Some(0x200)),
        ] {
            assert_eq!(
                resolve(input, a, cur, b.bytes().len() as u64).unwrap(),
                Location {
                    address,
                    file_offset: offset
                }
            );
        }
        assert!(resolve("@ffffffff", a, cur, b.bytes().len() as u64).is_err());
        assert!(resolve(".text+ffffffff", a, cur, b.bytes().len() as u64).is_err());
    }
    #[test]
    fn history_deduplicates_truncates_forward_and_bounds() {
        let mut h = History::default();
        let loc = |n| Location {
            address: Some(n),
            file_offset: None,
        };
        h.visit(loc(1));
        h.visit(loc(1));
        h.visit(loc(2));
        assert_eq!(h.entries.len(), 2);
        assert_eq!(h.step(-1), Some(loc(1)));
        h.visit(loc(3));
        assert_eq!(h.step(1), None);
        for n in 4..130 {
            h.visit(loc(n));
        }
        assert_eq!(h.entries.len(), 100);
        assert_eq!(h.index, 99);
    }
}
