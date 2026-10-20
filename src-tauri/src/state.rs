use std::sync::{Arc, Mutex};
use ura_core::{LoadedBinary, UraError};

#[derive(Clone, Default)]
pub struct AppState {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    binary: Mutex<Option<Arc<LoadedBinary>>>,
    startup_path: Mutex<Option<String>>,
}

impl AppState {
    pub fn set_binary(&self, binary: LoadedBinary) {
        if let Ok(mut guard) = self.inner.binary.lock() {
            *guard = Some(Arc::new(binary));
        }
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
}
