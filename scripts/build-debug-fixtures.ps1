$ErrorActionPreference='Stop'
$root=(Resolve-Path "$PSScriptRoot/..").Path
$folder=Join-Path $root 'target/debug-fixtures'
New-Item -ItemType Directory -Path $folder -Force | Out-Null
rustc --edition=2021 -C opt-level=1 -C debuginfo=0 -C link-arg=/EXPORT:ura_marker -C link-arg=/EXPORT:ura_nested -C link-arg=/EXPORT:ura_existing_int3,DATA "$root/tests/fixtures/debuggee.rs" -o "$folder/ura-debuggee.exe"
if ($LASTEXITCODE -ne 0) {throw 'Controlled debugger fixture compilation failed'}
Get-FileHash -LiteralPath "$folder/ura-debuggee.exe"
