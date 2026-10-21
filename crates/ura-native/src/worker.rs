use crate::graph::GraphLayout;
use eframe::egui;
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use ura_core::{
    AnalysisControl, AnalysisProgress, BinaryView, DisassemblyPage, LoadedBinary, ProgramAnalysis,
    StringScanResult,
    decomp::{CallGraph, FunctionDecompilation},
};
use ura_project::ProjectSnapshot;

pub struct Opened {
    pub binary: Option<Arc<LoadedBinary>>,
    pub info: Option<BinaryView>,
    pub project: Option<(PathBuf, ProjectSnapshot)>,
}
pub enum Event {
    Opened(Box<Opened>),
    Analysis(Arc<ProgramAnalysis>),
    Strings(StringScanResult),
    Page(u64, DisassemblyPage),
    Graph(u64, GraphLayout),
    Ir(
        (u64, u64, bool),
        Arc<ura_core::ir::inspect::Bundle>,
        Vec<IrRow>,
    ),
    Decomp {
        key: DecompKey,
        data: Arc<FunctionDecompilation>,
    },
    CallGraph {
        key: u64,
        graph: Arc<CallGraph>,
    },
    Project(PathBuf, Box<ProjectSnapshot>, bool),
    Message(String),
    Done,
}
pub struct IrRow {
    pub source: u64,
    pub text: String,
    pub unsupported: bool,
    pub block: bool,
}
type Task = Box<dyn FnOnce() -> Result<Event, String> + Send>;
#[derive(Clone, Copy)]
pub enum TaskKind {
    Other,
    Open,
    Analysis,
    Strings,
    Page(u64),
    Graph(u64),
    Ir((u64, u64, bool)),
    Decomp(DecompKey),
    CallGraph(u64),
}
pub type DecompKey = (u64, u64, u64);
pub struct Reply {
    pub generation: u64,
    pub kind: TaskKind,
    pub result: Result<Event, String>,
}
pub struct Worker {
    sender: Option<mpsc::Sender<(u64, TaskKind, Task)>>,
    pub receiver: mpsc::Receiver<Reply>,
    handle: Option<thread::JoinHandle<()>>,
}
impl Worker {
    pub fn new(ctx: egui::Context) -> Self {
        let (sender, input) = mpsc::channel::<(u64, TaskKind, Task)>();
        let (output, receiver) = mpsc::channel();
        let handle = thread::Builder::new()
            .name("ura-background".into())
            .spawn(move || {
                while let Ok((generation, kind, task)) = input.recv() {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(task))
                        .unwrap_or_else(|_| {
                            Err("Background task panicked. See %TEMP%/ura-native-panic.log".into())
                        });
                    if output
                        .send(Reply {
                            generation,
                            kind,
                            result,
                        })
                        .is_err()
                    {
                        break;
                    }
                    ctx.request_repaint();
                }
            })
            .expect("start background worker");
        Self {
            sender: Some(sender),
            receiver,
            handle: Some(handle),
        }
    }
    pub fn submit(
        &self,
        generation: u64,
        task: impl FnOnce() -> Result<Event, String> + Send + 'static,
    ) {
        self.submit_typed(generation, TaskKind::Other, task);
    }
    pub fn submit_typed(
        &self,
        generation: u64,
        kind: TaskKind,
        task: impl FnOnce() -> Result<Event, String> + Send + 'static,
    ) {
        if let Some(sender) = &self.sender {
            let _ = sender.send((generation, kind, Box::new(task)));
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
pub struct Control {
    pub cancel: Arc<AtomicBool>,
    pub progress: Arc<Mutex<Option<AnalysisProgress>>>,
    pub ctx: egui::Context,
    pub last: Mutex<Instant>,
}
impl AnalysisControl for Control {
    fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
    fn report(&self, progress: AnalysisProgress) {
        let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
        if last.elapsed() < Duration::from_millis(100) {
            return;
        }
        *last = Instant::now();
        *self.progress.lock().unwrap_or_else(|p| p.into_inner()) = Some(progress);
        self.ctx.request_repaint();
    }
}
pub fn open(path: PathBuf) -> Result<Event, String> {
    if path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("ura"))
    {
        let snapshot = ura_project::open_project(&path).map_err(|e| e.to_string())?;
        let (binary, info) = if snapshot.binary_status != "missing" {
            let binary =
                ura_core::analyze_path(std::path::Path::new(&snapshot.project.binary_path))
                    .map_err(|e| e.to_string())?;
            let info = binary.view();
            (Some(Arc::new(binary)), Some(info))
        } else {
            (None, None)
        };
        Ok(Event::Opened(Box::new(Opened {
            binary,
            info,
            project: Some((path, snapshot)),
        })))
    } else {
        let binary = ura_core::analyze_path(&path).map_err(|e| e.to_string())?;
        let info = binary.view();
        Ok(Event::Opened(Box::new(Opened {
            binary: Some(Arc::new(binary)),
            info: Some(info),
            project: None,
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_preserves_order_and_reports_panics() {
        let w = Worker::new(egui::Context::default());
        w.submit(7, || Ok(Event::Message("first".into())));
        w.submit(8, || panic!("test worker recovery"));
        w.submit(9, || Ok(Event::Done));
        let a = w.receiver.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(a.generation, 7);
        assert!(a.result.is_ok());
        assert!(
            w.receiver
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .result
                .is_err()
        );
        assert_eq!(
            w.receiver
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .generation,
            9
        );
    }
}
