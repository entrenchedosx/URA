use crate::Result;
#[cfg(windows)]
mod windows {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::JobObjects::*,
    };
    pub struct Job(HANDLE);
    impl Drop for Job {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    pub fn attach(child: &std::process::Child, memory_mb: u32) -> Result<Job> {
        unsafe {
            let handle = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if handle.is_null() {
                return Err(std::io::Error::last_os_error().to_string());
            }
            let job = Job(handle);
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY
                | JOB_OBJECT_LIMIT_JOB_MEMORY
                | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            info.ProcessMemoryLimit = memory_mb as usize * 1024 * 1024;
            info.JobMemoryLimit = info.ProcessMemoryLimit;
            if SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as _,
                std::mem::size_of_val(&info) as u32,
            ) == 0
                || AssignProcessToJobObject(handle, child.as_raw_handle() as _) == 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
            Ok(job)
        }
    }
}
#[cfg(windows)]
pub use windows::*;
#[cfg(not(windows))]
pub struct Job;
#[cfg(not(windows))]
pub fn attach(_: &std::process::Child, _: u32) -> Result<Job> {
    Err("Managed Python workers are qualified on Windows x64 only".into())
}
