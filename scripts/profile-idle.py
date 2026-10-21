"""Target-process thread CPU/start-module sample. No UI polling or elevation.

Usage: python scripts/profile-idle.py EXE SAMPLE OUTPUT [seconds] [--leave-open]
Only the spawned, read-only verification process is terminated on completion.
"""
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import psutil

kernel = c.WinDLL("kernel32", use_last_error=True)
ntdll = c.WinDLL("ntdll")
kernel.OpenThread.argtypes = [w.DWORD, w.BOOL, w.DWORD]
kernel.OpenThread.restype = w.HANDLE
kernel.GetThreadDescription.argtypes = [w.HANDLE, c.POINTER(w.LPWSTR)]
kernel.GetThreadDescription.restype = c.c_long
kernel.CloseHandle.argtypes = [w.HANDLE]
kernel.LocalFree.argtypes = [c.c_void_p]
ntdll.NtQueryInformationThread.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.ULONG, c.c_void_p]

def thread_identity(thread_id, modules):
    handle = kernel.OpenThread(0x0040 | 0x0800, False, thread_id)
    if not handle:
        return {"name": "unavailable", "module": "unavailable"}
    try:
        description = w.LPWSTR()
        name = "unnamed"
        if kernel.GetThreadDescription(handle, c.byref(description)) == 0:
            name = description.value or name
            kernel.LocalFree(c.cast(description, c.c_void_p))
        address = c.c_void_p()
        status = ntdll.NtQueryInformationThread(handle, 9, c.byref(address), c.sizeof(address), None)
        module = next((name for lo, hi, name in modules if address.value and lo <= address.value < hi), "unresolved") if status == 0 else "unavailable"
        return {"name": name, "module": module}
    finally:
        kernel.CloseHandle(handle)

exe, sample, destination = map(Path, sys.argv[1:4])
seconds = float(sys.argv[4]) if len(sys.argv) > 4 else 20.0
leave_open = '--leave-open' in sys.argv[5:]
env = os.environ.copy()
folder = destination.resolve().parent
folder.mkdir(parents=True, exist_ok=True)
env["URA_BENCHMARK_OUTPUT"] = str(folder)
started = time.perf_counter()
child = subprocess.Popen([str(exe.resolve()), str(sample.resolve())], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    process = psutil.Process(child.pid)
    time.sleep(8)
    # psutil reports image ranges through memory maps only on some platforms.
    # Toolhelp enumerates loaded image modules without walking target memory.
    class Module(c.Structure):
        _fields_ = [("dwSize", w.DWORD), ("th32ModuleID", w.DWORD), ("th32ProcessID", w.DWORD), ("GlblcntUsage", w.DWORD), ("ProccntUsage", w.DWORD), ("modBaseAddr", c.c_void_p), ("modBaseSize", w.DWORD), ("hModule", w.HMODULE), ("szModule", w.WCHAR * 256), ("szExePath", w.WCHAR * 260)]
    kernel.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = w.HANDLE
    kernel.Module32FirstW.argtypes = [w.HANDLE, c.POINTER(Module)]
    kernel.Module32NextW.argtypes = [w.HANDLE, c.POINTER(Module)]
    snapshot = kernel.CreateToolhelp32Snapshot(0x18, child.pid)
    modules = []
    item = Module()
    item.dwSize = c.sizeof(item)
    if kernel.Module32FirstW(snapshot, c.byref(item)):
        while True:
            modules.append((item.modBaseAddr, item.modBaseAddr + item.modBaseSize, item.szModule))
            if not kernel.Module32NextW(snapshot, c.byref(item)):
                break
    kernel.CloseHandle(snapshot)
    before = {t.id: t.user_time + t.system_time for t in process.threads()}
    cpu_before = sum(process.cpu_times()[:2])
    sample_start = time.perf_counter()
    time.sleep(seconds)
    duration = time.perf_counter() - sample_start
    rows = []
    for thread in process.threads():
        delta = thread.user_time + thread.system_time - before.get(thread.id, 0.0)
        rows.append({"id": thread.id, "cpuSeconds": delta, **thread_identity(thread.id, modules)})
    result = {"sample": sample.name, "seconds": duration, "cpuOneCorePercent": (sum(process.cpu_times()[:2])-cpu_before) / duration * 100, "workingSetMiB": process.memory_info().rss / (1024 * 1024), "threads": sorted(rows, key=lambda r: r["cpuSeconds"], reverse=True), "method": "Eight second settle, target-only process/thread CPU deltas; start-module attribution, not stack sampling."}
    destination.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
finally:
    if leave_open:
        print('Verification child left open for native input/shutdown checks, PID:', child.pid)
    else:
        child.terminate()
        child.wait(timeout=10)
