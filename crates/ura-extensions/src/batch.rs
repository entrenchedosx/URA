//! Sequential bounded batches reuse the same host and worker protocol.
use crate::{bridge::required, invalid, runtime::read_bounded, worker::ExtensionHost, Result};
use serde_json::{json, Value};
use std::{
    io::Write,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::Duration,
};
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct AnalysisOptions {
    max_instructions: usize,
    max_functions: usize,
    max_blocks: usize,
    follow_calls: bool,
    seed_symbols: bool,
}
impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            max_instructions: 16384,
            max_functions: 2048,
            max_blocks: 16384,
            follow_calls: true,
            seed_symbols: true,
        }
    }
}
pub(crate) struct Batch {
    status: Arc<Mutex<Value>>,
    cancel: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}
impl Drop for Batch {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
impl ExtensionHost {
    pub(crate) fn batch(&self, action: &str, p: &Value) -> Result<Value> {
        self.enabled()?;
        if action != "start" {
            let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
            let id = required(p, "id")?;
            let b = state.batches.get(id).ok_or("Unknown batch")?;
            return match action {
                "status" => Ok(b.status.lock().unwrap_or_else(|e| e.into_inner()).clone()),
                "cancel" => {
                    b.cancel.store(true, Ordering::Release);
                    Ok(json!({"cancelling":true}))
                }
                "close" => {
                    let b = state.batches.remove(id).unwrap();
                    drop(state);
                    drop(b);
                    Ok(json!({"closed":true}))
                }
                _ => invalid("Unknown batch action"),
            };
        }
        if p["parallelism"].as_u64().unwrap_or(1) != 1 {
            return invalid("Only bounded parallelism1 is supported");
        }
        let service = self.inner.service.lock().unwrap_or_else(|e| e.into_inner());
        let policy = service.extension_policy();
        if !service.extension_writes_enabled()
            || !self.inner.config.capabilities.contains("files.export")
        {
            return invalid("Batch export requires files.export and --enable-writes");
        }
        drop(service);
        let script = policy
            .allow_read(Path::new(required(p, "script")?))
            .map_err(|e| e.to_string())?;
        let script_sha = ura_core::sha256_hex(&read_bounded(&script, 65536)?);
        if self.inner.config.trusted_scripts.get(&script) != Some(&script_sha) {
            return invalid("Batch script path/content is not explicitly trusted");
        }
        let destination = policy
            .allow_write(Path::new(required(p, "destination")?))
            .map_err(|e| e.to_string())?;
        if !destination.is_dir() {
            return invalid("Destination must be an existing directory");
        }
        let mut inputs = Vec::new();
        if let Some(paths) = p["paths"].as_array() {
            if paths.len() > 64 {
                return invalid("At most64 batch inputs");
            }
            for path in paths {
                inputs.push(
                    policy
                        .allow_read(Path::new(
                            path.as_str().ok_or("Input path string required")?,
                        ))
                        .map_err(|e| e.to_string())?,
                );
            }
        } else {
            let dir = policy
                .allow_read(Path::new(required(p, "directory")?))
                .map_err(|e| e.to_string())?;
            for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
                let e = entry.map_err(|e| e.to_string())?;
                if e.file_type().map_err(|e| e.to_string())?.is_file() {
                    if inputs.len() >= 64 {
                        return invalid("Directory exceeds64 files");
                    }
                    inputs.push(policy.allow_read(&e.path()).map_err(|e| e.to_string())?);
                }
            }
            inputs.sort();
        }
        if inputs.is_empty() {
            return invalid("No batch inputs");
        }
        let limits: crate::Limits =
            serde_json::from_value(p.get("limits").cloned().unwrap_or(json!({})))
                .map_err(|e| e.to_string())?;
        limits.validate()?;
        let options: AnalysisOptions =
            serde_json::from_value(p.get("analysis").cloned().unwrap_or(json!({})))
                .map_err(|e| e.to_string())?;
        if !(64..=65536).contains(&options.max_instructions)
            || !(1..=8192).contains(&options.max_functions)
            || !(1..=65536).contains(&options.max_blocks)
        {
            return invalid("Batch analysis options exceed bounded limits");
        }
        let contract=ura_core::sha256_hex(&serde_json::to_vec(&json!({"scriptSha256":script_sha,"runtime":crate::runtime::PYTHON_VERSION,"api":crate::API_VERSION,"limits":limits,"analysis":options,"capabilities":self.inner.config.capabilities})).map_err(|e|e.to_string())?);

        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.batches.len() >= 2 {
            return invalid("At most two retained batches; close a completed batch");
        }
        let id = format!("batch-{}", self.inner.next.fetch_add(1, Ordering::Relaxed));
        let cancel = Arc::new(AtomicBool::new(false));
        let status = Arc::new(Mutex::new(
            json!({"id":id,"state":"running","total":inputs.len(),"inputs":inputs,"destination":destination,"limits":limits,"analysis":options,"contract":contract,"completed":0,"failed":0,"skipped":0,"rows":[],"parallelism":1}),
        ));
        let (status_copy, cancel_copy, config, resume) = (
            status.clone(),
            cancel.clone(),
            self.inner.config.clone(),
            p["resume"].as_bool().unwrap_or(false),
        );
        let thread=std::thread::Builder::new().name("ura-batch".into()).spawn(move||{
            for (index,path) in inputs.iter().enumerate(){if cancel_copy.load(Ordering::Acquire){break;}
                let result=(||->Result<Value>{let sha=ura_core::sha256_hex(&read_bounded(path,32*1024*1024)?);let mut output=destination.join(format!("{index:03}-{}.json",&sha[..16]));
                    if output.exists(){
                        if !resume{return invalid("Output exists; explicit resume required");}
                        for attempt in 0..=64 {if attempt>0{output=destination.join(format!("{index:03}-{}.attempt-{attempt:03}.json",&sha[..16]));}
                            if !output.exists(){break;}
                            let old:Value=serde_json::from_slice(&read_bounded(&output,1024*1024)?).map_err(|e|e.to_string())?;
                            if old["inputSha256"]!=sha || old["scriptSha256"]!=script_sha || old["version"]!=env!("CARGO_PKG_VERSION") || old["contract"]!=contract{return invalid("Resume identity mismatch; choose a new output directory");}
                            if old["result"]["state"]=="complete"{return Ok(json!({"path":path,"state":"skipped","output":output}));}
                            if attempt==64{return invalid("Resume attempt limit64; choose a new output directory");}
                        }
                    }
                    let mut service=ura_service::Service::new(policy.clone(),false);let h=service.open_binary(path,None).map_err(|e|e.to_string())?.handle;if service.info(&h).map_err(|e|e.to_string())?.info.sha256!=sha{return invalid("Input changed during batch load");}let core_options=ura_core::AnalysisOptions{max_instructions:options.max_instructions,max_functions:options.max_functions,max_blocks:options.max_blocks,follow_calls:options.follow_calls,seed_symbols:options.seed_symbols};service.analyze(&h,&core_options).map_err(|e|e.to_string())?;if cancel_copy.load(Ordering::Acquire){return invalid("Batch cancelled during input analysis");}
                    let host=ExtensionHost::new(Arc::new(Mutex::new(service)),config.clone())?;let s=host.rpc(json!({"operation":"scripts","action":"open","handle":h,"limits":limits,"capabilities":config.capabilities}))?;
                    let job=host.rpc(json!({"operation":"scripts","action":"run","session":s["session"],"path":script,"limits":limits}))?;
                    let result=loop{let r=host.job(job["job"].as_str().ok_or("Missing job")?)?;if r["state"]!="running"{break r;}
                    if cancel_copy.load(Ordering::Acquire){let _=host.rpc(json!({"operation":"scripts","action":"cancel","job":job["job"]}));}std::thread::sleep(Duration::from_millis(10));};
                    let record=json!({"version":env!("CARGO_PKG_VERSION"),"input":path,"inputSha256":sha,"scriptSha256":script_sha,"contract":contract,"result":result});let bytes=serde_json::to_vec_pretty(&record).map_err(|e|e.to_string())?;if bytes.len()>1024*1024{return invalid("Batch record exceeds1MiB");}
                    let mut file=tempfile::NamedTempFile::new_in(&destination).map_err(|e|e.to_string())?;file.write_all(&bytes).map_err(|e|e.to_string())?;file.persist_noclobber(&output).map_err(|e|e.to_string())?;
                    Ok(json!({"path":path,"state":if record["result"]["state"]=="complete"{"complete"}else{"failed"},"output":output,"scriptState":record["result"]["state"]}))})();
                let row=match result{Ok(v)=>v,Err(e)=>json!({"path":path,"state":"failed","error":e})};let mut status=status_copy.lock().unwrap_or_else(|e|e.into_inner());let counter=match row["state"].as_str(){Some("complete")=>"completed",Some("skipped")=>"skipped",_=>"failed"};let n=status[counter].as_u64().unwrap_or(0);status[counter]=json!(n+1);status["rows"].as_array_mut().unwrap().push(row);
            }
            let mut status=status_copy.lock().unwrap_or_else(|e|e.into_inner());status["state"]=json!(if cancel_copy.load(Ordering::Acquire){"cancelled"}else{"complete"});
            let summary=(||->Result<_>{let mut file=tempfile::Builder::new().prefix("ura-batch-summary-").suffix(".json").tempfile_in(&destination).map_err(|e|e.to_string())?;file.write_all(&serde_json::to_vec_pretty(&*status).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;let(_,path)=file.keep().map_err(|e|e.to_string())?;Ok(path)})();match summary{Ok(path)=>status["summary"]=json!(path),Err(e)=>status["summaryError"]=json!(e)}

        }).map_err(|e|e.to_string())?;
        state.batches.insert(
            id.clone(),
            Batch {
                status,
                cancel,
                thread: Some(thread),
            },
        );
        Ok(json!({"id":id,"state":"running"}))
    }
}
