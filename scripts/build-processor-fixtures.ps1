param([string]$Llvm = 'C:\Program Files\LLVM\bin')
$ErrorActionPreference = 'Stop'
$uraRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $uraRoot
try {
    New-Item -ItemType Directory -Path target/processor-fixtures -Force | Out-Null
    foreach ($level in 0, 1, 2, 3) {
        foreach ($spec in @(
            @{Name='aarch64'; Target='aarch64-unknown-linux-gnu'; Extra=@()},
            @{Name='arm'; Target='armv7-none-eabi'; Extra=@('-marm','-mfloat-abi=soft')},
            @{Name='thumb'; Target='armv7-none-eabi'; Extra=@('-mthumb','-mfloat-abi=soft')},
            @{Name='riscv64'; Target='riscv64-unknown-elf'; Extra=@('-march=rv64i','-mabi=lp64')},
            @{Name='riscv32'; Target='riscv32-unknown-elf'; Extra=@('-march=rv32i','-mabi=ilp32')}
        )) {
            # ARM/RV32 use compiler helper routines for 64-bit division, so exclude
            # that function from those ELF images rather than linking a runtime.
            $extra = $spec.Extra
            & "$Llvm\clang.exe" "--target=$($spec.Target)" @extra -fuse-ld=lld -nostdlib "-O$level" -fno-builtin -fno-stack-protector -ffunction-sections '-Wl,--gc-sections' '-Wl,--undefined=ura_scalar' '-Wl,--undefined=ura_select' '-Wl,--undefined=ura_width' '-Wl,--undefined=ura_loop' '-Wl,--undefined=ura_pointer' '-Wl,--undefined=ura_stack' '-Wl,--undefined=ura_nested' '-Wl,--undefined=ura_literal' '-Wl,--undefined=ura_stack_args' '-Wl,-e,ura_scalar' tests/samples/processors.c -o "target/processor-fixtures/$($spec.Name)-O$level.elf"
            if ($LASTEXITCODE -ne 0) { throw "ELF processor fixture failed: $($spec.Name) O$level" }
        }
        & "$Llvm\clang.exe" --target=aarch64-pc-windows-msvc "-O$level" -fno-builtin -fno-stack-protector -c tests/samples/processors.c -o "target/processor-fixtures/aarch64-O$level.obj"
        if ($LASTEXITCODE -ne 0) { throw 'ARM64 PE compilation failed' }
        & "$Llvm\lld-link.exe" /machine:arm64 /entry:ura_scalar /subsystem:console /nodefaultlib /timestamp:0 "/implib:target/processor-fixtures/aarch64-O$level.lib" "/out:target/processor-fixtures/aarch64-O$level.exe" "target/processor-fixtures/aarch64-O$level.obj"
        if ($LASTEXITCODE -ne 0) { throw 'ARM64 PE linking failed' }
    }
    & "$Llvm\clang.exe" --target=aarch64-unknown-linux-gnu -fuse-ld=lld -nostdlib '-Wl,-e,ura_udiv' tests/samples/aarch64-edges.s -o target/processor-fixtures/aarch64-edges.elf
    if ($LASTEXITCODE -ne 0) { throw 'AArch64 edge fixture compilation failed' }
    $uraFixtures=Join-Path $uraRoot 'tests/fixtures/processors'
    New-Item -ItemType Directory -Path $uraFixtures -Force | Out-Null
    Get-ChildItem -LiteralPath (Join-Path $uraRoot 'target/processor-fixtures') -File | Where-Object { $_.Extension -in '.elf','.exe' } | Copy-Item -Destination $uraFixtures
    $uraHashes=Get-ChildItem -LiteralPath $uraFixtures -File | Where-Object { $_.Extension -in '.elf','.exe' } | Sort-Object Name | ForEach-Object { @{name=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()} }
    @{compiler=(& "$Llvm\clang.exe" --version | Select-Object -First 1);source='tests/samples/processors.c';sourceSha256=(Get-FileHash -LiteralPath tests/samples/processors.c -Algorithm SHA256).Hash.ToLowerInvariant();edgesSourceSha256=(Get-FileHash -LiteralPath tests/samples/aarch64-edges.s -Algorithm SHA256).Hash.ToLowerInvariant();generator='scripts/build-processor-fixtures.ps1';foreignImagesNeverHostExecuted=$true;files=@($uraHashes)} | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 (Join-Path $uraFixtures 'manifest.json')
} finally { Pop-Location }
