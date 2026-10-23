//! Owned, windowless debugger fixture. No network or external file writes.
use std::time::Duration;
#[link(name="kernel32")]
extern "system" {
    fn SetErrorMode(mode:u32)->u32;
    fn DebugBreak();
    fn Sleep(milliseconds:u32);
    fn LoadLibraryExW(path:*const u16,file:*mut core::ffi::c_void,flags:u32)->*mut core::ffi::c_void;
    fn FreeLibrary(module:*mut core::ffi::c_void)->i32;
}
#[no_mangle]
#[inline(never)]
pub extern "C" fn ura_marker(value:u64)->u64 {
    std::hint::black_box(value.wrapping_mul(3).wrapping_add(7))
}
#[no_mangle]
pub static ura_existing_int3:[u8;1]=[0xcc];
#[no_mangle]
pub static ura_watch:std::sync::atomic::AtomicU64=std::sync::atomic::AtomicU64::new(0);
#[no_mangle]
#[inline(never)]
pub extern "C" fn ura_store(value:u64){ura_watch.store(value,std::sync::atomic::Ordering::Relaxed);}
#[no_mangle]
#[inline(never)]
pub extern "C" fn ura_nested(value:u64)->u64 {ura_marker(value)+1}
static STEP_GATE:std::sync::atomic::AtomicBool=std::sync::atomic::AtomicBool::new(false);
#[no_mangle]
#[inline(never)]
pub extern "C" fn ura_step_wait(){
    STEP_GATE.store(true,std::sync::atomic::Ordering::Release);
    unsafe {Sleep(1000);}
}
#[inline(never)]
fn recursive(depth:u64)->u64 {if depth==0 {ura_nested(2)}else{recursive(std::hint::black_box(depth-1))+1}}
fn main() {
    unsafe {SetErrorMode(0x0001|0x0002|0x8000);}
    let arguments=std::env::args().collect::<Vec<_>>();
    if arguments.iter().any(|v|v=="--thread-exit") {
        std::thread::spawn(||{std::hint::black_box(ura_marker(1));}).join().unwrap();
        std::hint::black_box(ura_marker(3));std::process::exit(42);
    }
    if arguments.iter().any(|v|v=="--step-race") {
        let worker=std::thread::spawn(||{
            while !STEP_GATE.load(std::sync::atomic::Ordering::Acquire) {std::thread::sleep(Duration::from_millis(1));}
            std::hint::black_box(ura_marker(7));
        });
        ura_step_wait();
        worker.join().unwrap();
        std::process::exit(42);
    }
    if arguments.iter().any(|v|v=="--attach") {std::thread::sleep(Duration::from_secs(3));}
    if arguments.iter().any(|v|v=="--blocking") {unsafe{Sleep(2000);}}
    if arguments.iter().any(|v|v=="--crash") {std::process::abort();}
    if arguments.iter().any(|v|v=="--application-break") {unsafe{DebugBreak();}}
    let done=std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker_done=done.clone();
    let worker=std::thread::spawn(move||{ura_watch.store(0xCAFE,std::sync::atomic::Ordering::Release); while !worker_done.load(std::sync::atomic::Ordering::Acquire) {std::thread::sleep(Duration::from_millis(10));}});
    while ura_watch.load(std::sync::atomic::Ordering::Acquire)!=0xCAFE {std::thread::yield_now();}
    unsafe {
        let path="version.dll\0".encode_utf16().collect::<Vec<_>>();
        let module=LoadLibraryExW(path.as_ptr(),std::ptr::null_mut(),0x800);
        if !module.is_null(){FreeLibrary(module);}
    }
    assert_eq!(ura_nested(1),11);
    assert_eq!(recursive(2),16);
    assert_eq!(ura_marker(3),16);
    ura_store(0xBEEF);
    done.store(true,std::sync::atomic::Ordering::Release);
    worker.join().unwrap();
    std::process::exit(42);
}
