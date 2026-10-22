param([string]$Llvm = 'C:\Program Files\LLVM\bin')
$ErrorActionPreference = 'Stop'
$uraRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $uraRoot
try {
    New-Item -ItemType Directory -Path target -Force | Out-Null
    foreach ($level in 0, 1, 2, 3) {
        & "$Llvm\clang.exe" --target=x86_64-pc-windows-msvc "-O$level" -fno-builtin -fno-stack-protector -c tests/samples/semantic.c -o "target/semantic-O$level.obj"
        if ($LASTEXITCODE -ne 0) { throw 'PE fixture compilation failed' }
        & "$Llvm\lld-link.exe" /entry:semantic_sum /subsystem:console /nodefaultlib /timestamp:0 "/implib:target/semantic-O$level.lib" "/out:tests/fixtures/semantic-O$level.exe" "target/semantic-O$level.obj"
        if ($LASTEXITCODE -ne 0) { throw 'PE fixture linking failed' }
        & "$Llvm\clang.exe" --target=x86_64-unknown-linux-gnu -fuse-ld=lld -nostdlib -no-pie '-Wl,-e,semantic_sum' "-O$level" -fno-builtin -fno-stack-protector tests/samples/semantic.c -o "tests/fixtures/semantic-O$level.elf"
        if ($LASTEXITCODE -ne 0) { throw 'ELF fixture compilation failed' }
    }
} finally { Pop-Location }
