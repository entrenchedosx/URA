//! Event-thread-owned user-mode debugger. No target is executed by construction.
mod model;
pub use model::*;
mod advanced;
pub use advanced::*;
mod condition;
pub use condition::Condition;
#[cfg(all(windows, target_arch = "x86_64"))]
mod windows;
use serde_json::Value;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, Mutex,
};
use std::time::Duration;
pub fn capabilities() -> Value {
    serde_json::json!({"backend":"windows-user-mode","available":cfg!(all(windows,target_arch="x86_64")),"architectures":["windows-x64"],"hardwareSlotsPerThread":4,"watchSizes":[1,2,4,8],"watchAccess":["write","readWrite"],"conditions":"unsigned register predicates; per-session hit counts","traceModes":["events","instructions"],"maxSnapshotBytes":1048576,"wow64":false,"remote":false,"kernel":false})
}

/// All OS operations, including launch/attach and continuation, stay on this owner.
pub trait Backend {
    fn stable(&self) -> bool;
    fn command(
        &mut self,
        session: Option<&str>,
        command: Command,
        cancelled: &AtomicBool,
    ) -> Result<Value>;
    fn poll(&mut self);
    fn shutdown(&mut self);
}
struct Request {
    session: Option<String>,
    command: Command,
    reply: mpsc::SyncSender<Result<Value>>,
    cancelled: Arc<AtomicBool>,
}
pub struct Controller {
    sender: Option<mpsc::SyncSender<Request>>,
    snapshot: Arc<Mutex<Snapshot>>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Default for Controller {
    fn default() -> Self {
        Self::new()
    }
}
impl Controller {
    pub fn new() -> Self {
        let snapshot = Arc::new(Mutex::new(Snapshot {
            schema_version: 1,
            ..Default::default()
        }));
        let (sender, receiver) = mpsc::sync_channel::<Request>(32);
        let shared = snapshot.clone();
        let worker = std::thread::Builder::new()
            .name("ura-debug-events".into())
            .spawn(move || {
                #[cfg(all(windows, target_arch = "x86_64"))]
                let mut backend = windows::WindowsBackend::new(shared);
                #[cfg(not(all(windows, target_arch = "x86_64")))]
                let mut backend = Unsupported(shared);
                loop {
                    let incoming = if backend.stable() {
                        receiver
                            .recv()
                            .map_err(|_| mpsc::RecvTimeoutError::Disconnected)
                    } else {
                        // WaitForDebugEventEx supplies the bounded running wait.
                        // Do not add another command-channel delay to every event.
                        receiver.try_recv().map_err(|error| match error {
                            mpsc::TryRecvError::Empty => mpsc::RecvTimeoutError::Timeout,
                            mpsc::TryRecvError::Disconnected => {
                                mpsc::RecvTimeoutError::Disconnected
                            }
                        })
                    };
                    match incoming {
                        Ok(request) => {
                            if request.cancelled.load(Ordering::Acquire) {
                                continue;
                            }
                            let result = backend.command(
                                request.session.as_deref(),
                                request.command,
                                &request.cancelled,
                            );
                            if request.cancelled.load(Ordering::Acquire) {
                                backend.shutdown();
                            }
                            let _ = request.reply.send(result);
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                    backend.poll();
                }
                backend.shutdown();
            })
            .expect("debug worker creation failed");
        Self {
            sender: Some(sender),
            snapshot,
            worker: Some(worker),
        }
    }
    pub fn snapshot(&self) -> Snapshot {
        self.snapshot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    pub fn command(&self, session: Option<&str>, command: Command) -> Result<Value> {
        let (reply, receive) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        self.sender
            .as_ref()
            .ok_or_else(|| DebugError::new("closed", "debugger is closed"))?
            .try_send(Request {
                session: session.map(str::to_owned),
                command,
                reply,
                cancelled: cancelled.clone(),
            })
            .map_err(|_| DebugError::new("busy", "debug command queue is full or closed"))?;
        receive.recv_timeout(Duration::from_secs(5)).unwrap_or_else(|_|{
            cancelled.store(true,Ordering::Release);
            Err(DebugError::new("timeout","debug request timed out; owner will cancel/clean up before accepting a new session"))
        })
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
#[cfg(not(all(windows, target_arch = "x86_64")))]
struct Unsupported(Arc<Mutex<Snapshot>>);
#[cfg(not(all(windows, target_arch = "x86_64")))]
impl Backend for Unsupported {
    fn stable(&self) -> bool {
        true
    }
    fn command(&mut self, _: Option<&str>, _: Command, _: &AtomicBool) -> Result<Value> {
        Err(DebugError::new(
            "unsupported",
            "native Windows x64 host/target required",
        ))
    }
    fn poll(&mut self) {
        let _ = &self.0;
    }
    fn shutdown(&mut self) {}
}
