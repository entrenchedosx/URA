param([string]$Llvm = 'C:\Program Files\LLVM\bin')
$ErrorActionPreference = 'Stop'
$uraRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $uraRoot
try {
    foreach ($level in 0, 1, 2) {
        & "$Llvm\clang.exe" --target=x86_64-pc-windows-msvc "-O$level" -c tests/samples/switch.c -o "target/switch-O$level.obj"
        if ($LASTEXITCODE -ne 0) { throw 'Clang failed' }
        & "$Llvm\lld-link.exe" /entry:switch_sample /subsystem:console /nodefaultlib /timestamp:0 "/implib:target/switch-O$level.lib" "/out:tests/fixtures/switch-O$level.exe" "target/switch-O$level.obj"
        if ($LASTEXITCODE -ne 0) { throw 'Link failed' }
    }
    & "$Llvm\clang.exe" --target=x86_64-unknown-linux-gnu -fuse-ld=lld -nostdlib -no-pie '-Wl,-e,switch_sample' -O2 tests/samples/switch.c -o tests/fixtures/switch-O2.elf
    if ($LASTEXITCODE -ne 0) { throw 'ELF fixture build failed' }
} finally { Pop-Location }
