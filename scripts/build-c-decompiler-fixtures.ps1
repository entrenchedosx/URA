param([string]$Llvm = 'C:\Program Files\LLVM\bin')
$ErrorActionPreference = 'Stop'
$uraRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $uraRoot
try {
    New-Item -ItemType Directory -Path target -Force | Out-Null
    foreach ($level in 0, 1, 2, 3) {
        & "$Llvm\clang++.exe" --target=x86_64-pc-windows-msvc "-O$level" -fno-builtin -fno-stack-protector -fno-exceptions -fno-rtti -c tests/samples/decompiler.cpp -o "target/decompiler-O$level.obj"
        if ($LASTEXITCODE -ne 0) { throw 'PE C++ fixture compilation failed' }
        & "$Llvm\lld-link.exe" /entry:cpp_scalar /subsystem:console /nodefaultlib /timestamp:0 "/implib:target/decompiler-O$level.lib" "/out:tests/fixtures/decompiler-O$level.exe" "target/decompiler-O$level.obj"
        if ($LASTEXITCODE -ne 0) { throw 'PE C++ fixture linking failed' }
        & "$Llvm\clang++.exe" --target=x86_64-unknown-linux-gnu -fuse-ld=lld -nostdlib -no-pie '-Wl,-e,cpp_scalar' "-O$level" -fno-builtin -fno-stack-protector -fno-exceptions -fno-rtti tests/samples/decompiler.cpp -o "tests/fixtures/decompiler-O$level.elf"
        if ($LASTEXITCODE -ne 0) { throw 'ELF C++ fixture compilation failed' }
    }
} finally { Pop-Location }
