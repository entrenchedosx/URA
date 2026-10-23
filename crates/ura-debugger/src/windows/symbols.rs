//! Explicit, local, identity-matched PDBs. No symbol-server or source retrieval.
use super::*;
use std::path::PathBuf;
pub(super) struct SymbolFile {
    path: PathBuf,
    guid: [u8; 16],
    age: u32,
    hash: String,
    _file: std::fs::File,
}
fn guid_bytes(g: &windows_sys::core::GUID) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..4].copy_from_slice(&g.data1.to_le_bytes());
    bytes[4..6].copy_from_slice(&g.data2.to_le_bytes());
    bytes[6..8].copy_from_slice(&g.data3.to_le_bytes());
    bytes[8..].copy_from_slice(&g.data4);
    bytes
}
fn local_session<T>(process: HANDLE, body: impl FnOnce() -> Result<T>) -> Result<T> {
    let _lock = os::DBGHELP.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        let old = SymGetOptions();
        SymSetOptions(
            SYMOPT_EXACT_SYMBOLS
                | SYMOPT_FAIL_CRITICAL_ERRORS
                | SYMOPT_NO_PROMPTS
                | SYMOPT_IGNORE_NT_SYMPATH
                | SYMOPT_IGNORE_IMAGEDIR
                | SYMOPT_NO_IMAGE_SEARCH
                | SYMOPT_DISABLE_SYMSRV_AUTODETECT
                | SYMOPT_SECURE
                | SYMOPT_LOAD_LINES,
        );
        let empty = [0u16];
        if SymInitializeW(process, empty.as_ptr(), 0) == 0 {
            SymSetOptions(old);
            return Err(error("SymInitializeW"));
        }
        let result = body();
        let cleanup = check(SymCleanup(process), "SymCleanup");
        SymSetOptions(old);
        match (result, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(e), _) | (_, Err(e)) => Err(e),
        }
    }
}
fn load(process: HANDLE, base: u64, size: u64, file: &SymbolFile) -> Result<()> {
    unsafe {
        let path = wide(&file.path)?;
        if SymLoadModuleExW(
            process,
            std::ptr::null_mut(),
            path.as_ptr(),
            std::ptr::null(),
            base,
            size as u32,
            std::ptr::null(),
            0,
        ) == 0
        {
            return Err(error("SymLoadModuleExW explicit PDB"));
        }
        let mut info = IMAGEHLP_MODULEW64 {
            SizeOfStruct: std::mem::size_of::<IMAGEHLP_MODULEW64>() as u32,
            ..Default::default()
        };
        check(
            SymGetModuleInfoW64(process, base, &mut info),
            "SymGetModuleInfoW64",
        )?;
        if info.PdbUnmatched != 0
            || guid_bytes(&info.PdbSig70) != file.guid
            || info.PdbAge != file.age
        {
            return Err(DebugError::new(
                "identity",
                "loaded PDB identity does not match authorized PE GUID/age",
            ));
        }
        Ok(())
    }
}
fn lookup(process: HANDLE, address: u64) -> Result<Value> {
    unsafe {
        let mut buffer = SYMBOL_INFO_PACKAGEW::default();
        buffer.si.SizeOfStruct = std::mem::size_of::<SYMBOL_INFOW>() as u32;
        buffer.si.MaxNameLen = 2000;
        let mut displacement = 0;
        if SymFromAddrW(process, address, &mut displacement, &mut buffer.si) == 0 {
            return Ok(
                json!({"address":hex(address),"found":false,"reason":error("SymFromAddrW").message}),
            );
        }
        let length = (buffer.si.NameLen as usize).min(2000);
        let name =
            String::from_utf16_lossy(std::slice::from_raw_parts(buffer.si.Name.as_ptr(), length));
        let mut line = IMAGEHLP_LINEW64 {
            SizeOfStruct: std::mem::size_of::<IMAGEHLP_LINEW64>() as u32,
            ..Default::default()
        };
        let mut line_displacement = 0;
        let line_number =
            if SymGetLineFromAddrW64(process, address, &mut line_displacement, &mut line) != 0 {
                Some(line.LineNumber)
            } else {
                None
            };
        Ok(
            json!({"address":hex(address),"found":true,"name":name,"symbolAddress":hex(buffer.si.Address),"displacement":displacement,"moduleBase":hex(buffer.si.ModBase),"line":line_number,"source":"explicit-local-matched-pdb"}),
        )
    }
}
impl WindowsBackend {
    pub(super) fn symbol_action(&mut self, action: SymbolAction) -> Result<Value> {
        self.paused()?;
        let process = self.process()?;
        match action {
            SymbolAction::Load { base, pdb } => {
                use std::{io::Read, os::windows::fs::OpenOptionsExt};
                let module = self
                    .view
                    .modules
                    .iter()
                    .find(|m| {
                        m.sha256.is_some() && ura_core::parse_address(&m.base).ok() == Some(base)
                    })
                    .ok_or_else(|| {
                        DebugError::new(
                            "symbols",
                            "PDB loading currently supports only the identity-verified main image",
                        )
                    })?;
                let expected = self
                    .image
                    .as_ref()
                    .and_then(|i| i.pdb_identity)
                    .ok_or_else(|| {
                        DebugError::new("symbols", "main image has no supported RSDS PDB GUID/age")
                    })?;
                let path = pdb
                    .canonicalize()
                    .map_err(|e| DebugError::new("path", e.to_string()))?;
                if path.to_string_lossy().starts_with(r"\\?\UNC\") {
                    return Err(DebugError::new(
                        "permission",
                        "network symbol paths are disabled",
                    ));
                }
                let mut file = std::fs::OpenOptions::new()
                    .read(true)
                    .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
                    .open(&path)
                    .map_err(|e| DebugError::new("path", e.to_string()))?;
                if file
                    .metadata()
                    .map_err(|e| DebugError::new("path", e.to_string()))?
                    .len()
                    > 128 * 1024 * 1024
                {
                    return Err(DebugError::new("limit", "local PDB exceeds128MiB"));
                }
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)
                    .map_err(|e| DebugError::new("path", e.to_string()))?;
                if !bytes.starts_with(b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0") {
                    return Err(DebugError::new(
                        "symbols",
                        "explicit symbol file must be an MSF7 PDB",
                    ));
                }
                let record = local_session(process, || {
                    let mut index = SYMSRV_INDEX_INFOW {
                        sizeofstruct: std::mem::size_of::<SYMSRV_INDEX_INFOW>() as u32,
                        ..Default::default()
                    };
                    unsafe {
                        check(
                            SymSrvGetFileIndexInfoW(wide(&path)?.as_ptr(), &mut index, 0),
                            "SymSrvGetFileIndexInfoW local PDB",
                        )?;
                    }
                    if guid_bytes(&index.guid) != expected.0 || index.age != expected.1 {
                        return Err(DebugError::new(
                            "identity",
                            "PDB GUID/age mismatch; filename agreement is insufficient",
                        ));
                    }
                    let record = SymbolFile {
                        path,
                        guid: expected.0,
                        age: expected.1,
                        hash: ura_core::sha256_hex(&bytes),
                        _file: file,
                    };
                    load(process, base, module.size, &record)?;
                    Ok(record)
                })?;
                let result = json!({"base":hex(base),"pdb":record.path,"sha256":record.hash,"guidBytes":record.guid,"age":record.age,"identityMatched":true,"network":false,"scope":"main image symbols and lines; no C++ type recovery"});
                self.symbols.insert(base, record);
                Ok(result)
            }
            SymbolAction::Lookup { address } => {
                let module = self
                    .view
                    .modules
                    .iter()
                    .find(|m| {
                        ura_core::parse_address(&m.base)
                            .is_ok_and(|b| address >= b && address - b < m.size)
                    })
                    .ok_or_else(|| DebugError::new("symbols", "address has no observed module"))?;
                let base = ura_core::parse_address(&module.base).unwrap();
                if let Some(file) = self.symbols.get(&base) {
                    return local_session(process, || {
                        load(process, base, module.size, file)?;
                        lookup(process, address)
                    });
                }
                if let Some(name) = self
                    .image
                    .as_ref()
                    .filter(|_| module.sha256.is_some())
                    .and_then(|i| i.exports.get(&(address - base)))
                {
                    return Ok(
                        json!({"found":true,"address":hex(address),"name":name,"source":"exact-main-image-export","displacement":0}),
                    );
                }
                Ok(
                    json!({"found":false,"address":hex(address),"reason":"no explicitly loaded matching local PDB or exact export"}),
                )
            }
        }
    }
    pub(super) fn symbolize_stack(&self, result: &mut Value) {
        if self.symbols.is_empty() {
            return;
        }
        let Ok(process) = self.process() else {
            return;
        };
        let response = local_session(process, || {
            for (&base, file) in &self.symbols {
                if let Some(module) = self
                    .view
                    .modules
                    .iter()
                    .find(|m| ura_core::parse_address(&m.base).ok() == Some(base))
                {
                    load(process, base, module.size, file)?;
                }
            }
            for frame in result["frames"].as_array_mut().unwrap() {
                let address =
                    ura_core::parse_address(frame["instructionPointer"].as_str().unwrap()).unwrap();
                if let Ok(symbol) = lookup(process, address) {
                    if symbol["found"] == true {
                        frame["symbol"] = symbol["name"].clone();
                        frame["symbolEvidence"] = symbol;
                    }
                }
            }
            Ok(())
        });
        if let Err(error) = response {
            result["symbolWarning"] = json!(error.message);
        }
    }
}
