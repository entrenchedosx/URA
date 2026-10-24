//! Bounded ordered notifications; subscribers execute outside service locks.
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisEvent {
    pub sequence: u64,
    pub kind: String,
    pub handle: String,
    pub generation: u64,
    pub timestamp_ms: u128,
    pub origin: Option<String>,
    pub data: Value,
}
#[derive(Default)]
struct Queue {
    sequence: u64,
    rows: VecDeque<AnalysisEvent>,
}
#[derive(Clone, Default)]
pub struct EventBus(Arc<(Mutex<Queue>, Condvar)>);
impl EventBus {
    pub fn emit(
        &self,
        kind: &str,
        handle: &str,
        generation: u64,
        origin: Option<&str>,
        data: Value,
    ) {
        let (lock, signal) = &*self.0;
        let mut queue = lock.lock().unwrap_or_else(|e| e.into_inner());
        queue.sequence = queue.sequence.saturating_add(1);
        let sequence = queue.sequence;
        if queue.rows.len() == 256 {
            queue.rows.pop_front();
        }
        let data = if serde_json::to_vec(&data).map_or(true, |b| b.len() > 8192) {
            serde_json::json!({"payloadOmitted":true,"reason":"event payload exceeds8KiB; query current state"})
        } else {
            data
        };
        queue.rows.push_back(AnalysisEvent {
            sequence,
            kind: kind.into(),
            handle: handle.into(),
            generation,
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            origin: origin.map(str::to_owned),
            data,
        });
        signal.notify_all();
    }
    pub fn page(&self, after: u64) -> (u64, bool, Vec<AnalysisEvent>) {
        let queue = self.0 .0.lock().unwrap_or_else(|e| e.into_inner());
        let rows: Vec<_> = queue
            .rows
            .iter()
            .filter(|e| e.sequence > after)
            .take(32)
            .cloned()
            .collect();
        (
            rows.last().map_or(queue.sequence, |r| r.sequence),
            queue
                .rows
                .front()
                .is_some_and(|r| after.saturating_add(1) < r.sequence),
            rows,
        )
    }
    pub fn wait(&self, after: u64, timeout: Duration) {
        let (lock, signal) = &*self.0;
        let queue = lock.lock().unwrap_or_else(|e| e.into_inner());
        if queue.sequence <= after {
            drop(
                signal
                    .wait_timeout(queue, timeout)
                    .unwrap_or_else(|e| e.into_inner()),
            );
        }
    }
}
