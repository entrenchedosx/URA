use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use ura_core::analysis::ProgramAnalysis;
use ura_core::{parse_address, LoadedBinary, UraError};

#[derive(Clone, Default)]
pub struct AppState {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    binary: Mutex<Option<Arc<LoadedBinary>>>,
    binary_hash: Mutex<Option<String>>,
    startup_path: Mutex<Option<String>>,
    analysis: Mutex<Option<Arc<ProgramAnalysis>>>,
    analysis_running: AtomicBool,
    analysis_cancel: Mutex<Option<Arc<AtomicBool>>>,
    names: Mutex<NameContext>,
}

#[derive(Default)]
struct NameContext {
    binary_hash: Option<String>,
    names: BTreeMap<u64, String>,
}

impl AppState {
    pub fn set_binary(&self, binary: LoadedBinary) {
        let hash = binary.view().sha256;
        self.cancel_analysis();
        self.clear_analysis();
        if let Ok(mut names) = self.inner.names.lock() {
            if names.binary_hash.as_deref() != Some(hash.as_str()) {
                *names = NameContext::default();
            }
        }
        if let Ok(mut guard) = self.inner.binary_hash.lock() {
            *guard = Some(hash);
        }
        if let Ok(mut guard) = self.inner.binary.lock() {
            *guard = Some(Arc::new(binary));
        }
    }

    pub fn binary_hash(&self) -> Option<String> {
        self.inner
            .binary_hash
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    pub fn binary(&self) -> Result<Arc<LoadedBinary>, UraError> {
        self.inner
            .binary
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
            .ok_or(UraError::NoBinaryLoaded)
    }

    pub fn clear_binary(&self) {
        self.cancel_analysis();
        self.clear_analysis();
        if let Ok(mut guard) = self.inner.binary_hash.lock() {
            *guard = None;
        }
        if let Ok(mut guard) = self.inner.binary.lock() {
            *guard = None;
        }
    }

    pub fn set_startup_path(&self, path: String) {
        if let Ok(mut guard) = self.inner.startup_path.lock() {
            *guard = Some(path);
        }
    }

    pub fn take_startup_path(&self) -> Option<String> {
        self.inner
            .startup_path
            .lock()
            .ok()
            .and_then(|mut guard| guard.take())
    }

    pub fn analysis(&self) -> Option<Arc<ProgramAnalysis>> {
        self.inner
            .analysis
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    pub fn set_analysis(&self, analysis: ProgramAnalysis) {
        if let Ok(mut guard) = self.inner.analysis.lock() {
            *guard = Some(Arc::new(analysis));
        }
    }

    pub fn clear_analysis(&self) {
        if let Ok(mut guard) = self.inner.analysis.lock() {
            *guard = None;
        }
    }

    pub fn analysis_running(&self) -> bool {
        self.inner.analysis_running.load(Ordering::SeqCst)
    }

    pub fn try_start_analysis(&self) -> Option<Arc<AtomicBool>> {
        if self.inner.analysis_running.swap(true, Ordering::SeqCst) {
            return None;
        }
        let token = Arc::new(AtomicBool::new(false));
        if let Ok(mut guard) = self.inner.analysis_cancel.lock() {
            *guard = Some(token.clone());
        }
        Some(token)
    }

    pub fn finish_analysis(&self) {
        if let Ok(mut guard) = self.inner.analysis_cancel.lock() {
            *guard = None;
        }
        self.inner.analysis_running.store(false, Ordering::SeqCst);
    }

    pub fn cancel_analysis(&self) -> bool {
        let token = self
            .inner
            .analysis_cancel
            .lock()
            .ok()
            .and_then(|guard| guard.clone());
        match token {
            Some(token) => {
                token.store(true, Ordering::SeqCst);
                true
            }
            None => false,
        }
    }

    pub fn set_name_context<I>(&self, binary_hash: String, names: I)
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let mut map = BTreeMap::new();
        for (address, name) in names {
            if let Ok(value) = parse_address(&address) {
                map.insert(value, name);
            }
        }
        if let Ok(mut guard) = self.inner.names.lock() {
            *guard = NameContext {
                binary_hash: Some(binary_hash),
                names: map,
            };
        }
    }

    pub fn function_names(&self) -> BTreeMap<u64, String> {
        self.inner
            .names
            .lock()
            .map(|guard| guard.names.clone())
            .unwrap_or_default()
    }

    pub fn set_function_name(&self, address: u64, name: Option<String>) {
        if let Ok(mut guard) = self.inner.names.lock() {
            match name {
                Some(name) if !name.trim().is_empty() => {
                    guard.names.insert(address, name);
                }
                _ => {
                    guard.names.remove(&address);
                }
            }
        }
    }
}
