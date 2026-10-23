use super::*;
use std::sync::Arc;
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}
impl Permissions {
    pub const RX: Self = Self {
        read: true,
        write: false,
        execute: true,
    };
    pub const RW: Self = Self {
        read: true,
        write: true,
        execute: false,
    };
}
#[derive(Clone, Debug, Serialize)]
pub struct Region {
    pub base: Address,
    pub size: usize,
    pub permissions: Permissions,
    pub source: String,
    #[serde(skip)]
    pub(crate) bytes: Arc<Vec<u8>>,
}
impl Region {
    pub fn bytes_for_image(&self) -> Vec<u8> {
        self.bytes.as_ref().clone()
    }
}
#[derive(Clone, Debug)]
pub struct Memory {
    pub bits: u8,
    pub regions: Vec<Region>,
    pub allocated: usize,
    pub limit: usize,
}
impl Memory {
    pub fn new(bits: u8, limit: usize) -> Result<Self> {
        if !matches!(bits, 32 | 64) || limit == 0 || limit > 16 * 1024 * 1024 {
            return Err(Fault::new(
                "configuration",
                0,
                "mode32/64 and memory1..16MiB required",
            ));
        }
        Ok(Self {
            bits,
            regions: vec![],
            allocated: 0,
            limit,
        })
    }
    pub fn map(
        &mut self,
        base: u64,
        size: usize,
        data: &[u8],
        permissions: Permissions,
        source: &str,
    ) -> Result<()> {
        let end = base
            .checked_add(size as u64)
            .filter(|&e| self.bits != 32 || e <= 1u64 << 32)
            .ok_or_else(|| Fault::new("address", base, "region exceeds address width"))?;
        if size == 0
            || data.len() > size
            || source.len() > 512
            || self.regions.len() >= 256
            || self
                .allocated
                .checked_add(size)
                .map_or(true, |n| n > self.limit)
        {
            return Err(Fault::new(
                "memoryBudget",
                base,
                "empty/oversized region, source or allocation limit",
            ));
        }
        if self
            .regions
            .iter()
            .any(|r| base < r.base.0 + r.size as u64 && r.base.0 < end)
        {
            return Err(Fault::new("overlap", base, "mapped ranges overlap"));
        }
        let mut bytes = data.to_vec();
        bytes.resize(size, 0);
        self.regions.push(Region {
            base: Address(base),
            size,
            permissions,
            source: source.into(),
            bytes: Arc::new(bytes),
        });
        self.regions.sort_by_key(|r| r.base);
        self.allocated += size;
        Ok(())
    }
    fn locate(&self, address: u64, access: &str) -> Result<(usize, usize)> {
        if self.bits == 32 && address > u32::MAX as u64 {
            return Err(Fault::new("address", address, "x86 address exceeds32bits"));
        }
        let i = self
            .regions
            .partition_point(|r| r.base.0 <= address)
            .checked_sub(1)
            .ok_or_else(|| Fault::new("unmapped", address, access))?;
        let r = &self.regions[i];
        let offset = address - r.base.0;
        if offset >= r.size as u64 {
            return Err(Fault::new("unmapped", address, access));
        }
        let permitted = match access {
            "execute" => r.permissions.execute,
            "write" => r.permissions.write,
            _ => r.permissions.read,
        };
        if !permitted {
            return Err(Fault::new("permission", address, access));
        }
        Ok((i, offset as usize))
    }
    pub fn read(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        if length > 65536 || address.checked_add(length as u64).is_none() {
            return Err(Fault::new("limit", address, "read limit64KiB or overflow"));
        }
        (0..length)
            .map(|n| {
                let (i, o) = self.locate(address + n as u64, "read")?;
                Ok(self.regions[i].bytes[o])
            })
            .collect()
    }
    pub fn fetch(&self, address: u64) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        for n in 0..15 {
            let Some(a) = address.checked_add(n) else {
                break;
            };
            match self.locate(a, "execute") {
                Ok((i, o)) => bytes.push(self.regions[i].bytes[o]),
                Err(e) if bytes.is_empty() => return Err(e),
                Err(_) => break,
            }
        }
        Ok(bytes)
    }
    pub(crate) fn validate_write(&self, address: u64, bytes: &[u8]) -> Result<()> {
        if bytes.len() > 65536 || address.checked_add(bytes.len() as u64).is_none() {
            return Err(Fault::new("limit", address, "write limit64KiB or overflow"));
        }
        for n in 0..bytes.len() {
            self.locate(address + n as u64, "write")?;
        }
        Ok(())
    }
    pub fn write(&mut self, address: u64, bytes: &[u8]) -> Result<()> {
        self.validate_write(address, bytes)?;
        for (n, &b) in bytes.iter().enumerate() {
            let (i, o) = self.locate(address + n as u64, "write")?;
            Arc::make_mut(&mut self.regions[i].bytes)[o] = b;
        }
        Ok(())
    }
    pub(crate) fn executable(&self, address: u64) -> bool {
        self.locate(address, "execute").is_ok()
    }
}
