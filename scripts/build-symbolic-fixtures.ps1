param([string]$Llvm = 'C:\Program Files\LLVM\bin')
$ErrorActionPreference='Stop'
$uraRoot=Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $uraRoot
try {
    $fixtureDirectory=Join-Path $uraRoot 'tests/fixtures/symbolic'
    $objectDirectory=Join-Path $uraRoot 'target/symbolic-fixtures'
    New-Item -ItemType Directory -Path $fixtureDirectory,$objectDirectory -Force | Out-Null
    & "$Llvm/clang.exe" --target=x86_64-pc-windows-msvc -c tests/samples/symbolic-flat.S -o "$objectDirectory/flat.obj"
    if($LASTEXITCODE -ne 0){throw 'Windows dispatcher assembly failed'}
    foreach($level in 0,1,2,3) {
        & "$Llvm/clang.exe" --target=x86_64-pc-windows-msvc "-O$level" -fno-builtin -fno-stack-protector -c tests/samples/symbolic.c -o "$objectDirectory/O$level.obj"
        if($LASTEXITCODE -ne 0){throw 'Windows symbolic fixture compilation failed'}
        & "$Llvm/lld-link.exe" /entry:ura_opaque_even /subsystem:console /nodefaultlib /timestamp:0 /export:ura_flattened "/implib:$objectDirectory/O$level.lib" "/out:$fixtureDirectory/x64-O$level.exe" "$objectDirectory/O$level.obj" "$objectDirectory/flat.obj"
        if($LASTEXITCODE -ne 0){throw 'Windows symbolic fixture linking failed'}
        & "$Llvm/clang.exe" --target=x86_64-unknown-linux-gnu -fuse-ld=lld -nostdlib "-O$level" -fno-builtin -fno-stack-protector '-Wl,--build-id=none' '-Wl,-e,ura_opaque_even' tests/samples/symbolic.c tests/samples/symbolic-flat.S -o "$fixtureDirectory/x64-O$level.elf"
        if($LASTEXITCODE -ne 0){throw 'ELF symbolic fixture compilation failed'}
    }
    $hashes=Get-ChildItem -LiteralPath $fixtureDirectory -File | Where-Object Extension -In '.elf','.exe' | Sort-Object Name | ForEach-Object { @{name=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()} }
    @{compiler=(& "$Llvm/clang.exe" --version | Select-Object -First 1);source='tests/samples/symbolic.c';sourceSha256=(Get-FileHash -LiteralPath tests/samples/symbolic.c -Algorithm SHA256).Hash.ToLowerInvariant();dispatcherSourceSha256=(Get-FileHash -LiteralPath tests/samples/symbolic-flat.S -Algorithm SHA256).Hash.ToLowerInvariant();generator='scripts/build-symbolic-fixtures.ps1';foreignImagesNeverHostExecuted=$true;files=@($hashes)} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$fixtureDirectory/manifest.json" -Encoding utf8
} finally {Pop-Location}
