use super::{PatchError, PatchResult};
use object::{Object, ObjectSection, ObjectSegment};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Mapping {
    pub address: u64,
    pub memory_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
}

pub(super) fn mappings(bytes: &[u8]) -> PatchResult<(String, u32, Vec<Mapping>)> {
    let file = object::File::parse(bytes).map_err(|e| PatchError(e.to_string()))?;
    let bits = if file.is_64() { 64 } else { 32 };
    let mut maps = Vec::new();
    let format = match file.format() {
        object::BinaryFormat::Pe => {
            let word = |offset: usize| -> PatchResult<u32> {
                let slice = bytes
                    .get(
                        offset
                            ..offset
                                .checked_add(4)
                                .ok_or_else(|| PatchError("header overflow".into()))?,
                    )
                    .ok_or_else(|| PatchError("truncated PE header".into()))?;
                Ok(u32::from_le_bytes(slice.try_into().unwrap()))
            };
            let pe = word(0x3c)? as usize;
            let header_size = u64::from(word(
                pe.checked_add(24 + 60)
                    .ok_or_else(|| PatchError("PE header overflow".into()))?,
            )?);
            let half = |offset: usize| -> PatchResult<u16> {
                Ok(u16::from_le_bytes(
                    bytes
                        .get(offset..offset + 2)
                        .ok_or_else(|| PatchError("truncated PE file header".into()))?
                        .try_into()
                        .unwrap(),
                ))
            };
            let actual_end =
                pe as u64 + 24 + u64::from(half(pe + 20)?) + u64::from(half(pe + 6)?) * 40;
            if pe < 64 || header_size < actual_end || header_size > bytes.len() as u64 {
                return Err(PatchError(
                    "PE SizeOfHeaders does not cover parsed file/optional/section tables".into(),
                ));
            }
            maps.push(Mapping {
                address: file.relative_address_base(),
                memory_size: header_size,
                file_offset: 0,
                file_size: header_size,
            });
            for section in file.sections() {
                if let Some((offset, size)) = section.file_range() {
                    maps.push(Mapping {
                        address: section.address(),
                        memory_size: section.size(),
                        file_offset: offset,
                        file_size: size.min(section.size()),
                    });
                } else {
                    maps.push(Mapping {
                        address: section.address(),
                        memory_size: section.size(),
                        file_offset: 0,
                        file_size: 0,
                    });
                }
            }
            "PE"
        }
        object::BinaryFormat::Elf => {
            if !matches!(
                file.kind(),
                object::ObjectKind::Executable | object::ObjectKind::Dynamic
            ) {
                return Err(PatchError(
                    "patching requires a linked ELF executable/shared image".into(),
                ));
            }
            // object exposes PT_LOAD segments here, not section-header addresses.
            for segment in file.segments() {
                let (offset, size) = segment.file_range();
                maps.push(Mapping {
                    address: segment.address(),
                    memory_size: segment.size(),
                    file_offset: offset,
                    file_size: size,
                });
            }
            "ELF"
        }
        _ => {
            return Err(PatchError(
                "file patching supports linked PE/ELF and explicit raw images only".into(),
            ))
        }
    };
    for map in &maps {
        if map.file_size > map.memory_size
            || map
                .file_offset
                .checked_add(map.file_size)
                .map_or(true, |end| end > bytes.len() as u64)
            || map.address.checked_add(map.memory_size).is_none()
        {
            return Err(PatchError(
                "invalid or truncated file-backed mapping".into(),
            ));
        }
    }
    Ok((format.into(), bits, maps))
}

pub(super) fn translate(maps: &[Mapping], address: u64, length: usize) -> PatchResult<u64> {
    let end = address
        .checked_add(length as u64)
        .ok_or_else(|| PatchError("address range overflow".into()))?;
    let overlapping: Vec<_> = maps
        .iter()
        .filter(|m| address < m.address + m.memory_size && m.address < end)
        .collect();
    if overlapping.len() != 1 {
        return Err(PatchError(
            "virtual range is unmapped, ambiguous or crosses a mapping boundary".into(),
        ));
    }
    let m = overlapping[0];
    let delta = address
        .checked_sub(m.address)
        .ok_or_else(|| PatchError("virtual range begins outside mapping".into()))?;
    if delta
        .checked_add(length as u64)
        .map_or(true, |end| end > m.file_size)
    {
        return Err(PatchError(
            "virtual range includes memory without file backing".into(),
        ));
    }
    Ok(m.file_offset + delta)
}

pub(super) fn protected(bytes: &[u8], format: &str) -> PatchResult<Vec<(u64, u64)>> {
    if format == "PE" {
        return Ok(vec![(0, mappings(bytes)?.2[0].file_size)]);
    }
    let wide = bytes[4] == 2;
    let little = bytes[5] == 1;
    let read = |offset: usize, size: usize| -> PatchResult<u64> {
        let b = bytes
            .get(offset..offset + size)
            .ok_or_else(|| PatchError("truncated ELF layout header".into()))?;
        Ok(if little {
            b.iter().rev().fold(0, |v, &b| (v << 8) | u64::from(b))
        } else {
            b.iter().fold(0, |v, &b| (v << 8) | u64::from(b))
        })
    };
    let (phoff, shoff, fields, minimum) = if wide {
        (read(32, 8)?, read(40, 8)?, 52, 64)
    } else {
        (read(28, 4)?, read(32, 4)?, 40, 52)
    };
    let ehsize = read(fields, 2)?;
    let phsize = read(fields + 2, 2)?;
    let phnum = read(fields + 4, 2)?;
    let shsize = read(fields + 6, 2)?;
    let shnum = read(fields + 8, 2)?;
    if ehsize < minimum
        || ehsize > bytes.len() as u64
        || phnum == 0xffff
        || (shoff != 0 && shnum == 0)
    {
        return Err(PatchError(
            "unsupported or invalid ELF layout/extended numbering".into(),
        ));
    }
    let mut ranges = vec![(0, ehsize)];
    for (start, size, count) in [(phoff, phsize, phnum), (shoff, shsize, shnum)] {
        if count == 0 {
            continue;
        }
        let end = size
            .checked_mul(count)
            .and_then(|n| start.checked_add(n))
            .ok_or_else(|| PatchError("ELF table range overflow".into()))?;
        if size == 0 || end > bytes.len() as u64 {
            return Err(PatchError("truncated ELF layout table".into()));
        }
        ranges.push((start, end));
    }
    Ok(ranges)
}
