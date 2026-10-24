param(
    [string]$OutputDirectory,
    [string]$ExpectedCommit,
    [string]$ApprovedTag,
    [switch]$AllowDirty
)
$ErrorActionPreference = 'Stop'
# Keep verification caches bounded on Windows; these do not change Release code.
if(-not $env:CARGO_PROFILE_DEV_DEBUG){$env:CARGO_PROFILE_DEV_DEBUG='0'}
if(-not $env:CARGO_PROFILE_TEST_DEBUG){$env:CARGO_PROFILE_TEST_DEBUG='0'}
if(-not $env:CARGO_INCREMENTAL){$env:CARGO_INCREMENTAL='0'}

$root = (Resolve-Path "$PSScriptRoot/..").Path
Set-Location -LiteralPath $root
function Invoke-Checked([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}
$version = (Select-String -Path "$root/Cargo.toml" -Pattern '^version = "([^"]+)"').Matches[0].Groups[1].Value
$commit = (git rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') { throw 'Cannot identify exact source commit' }
if ($ExpectedCommit -and $ExpectedCommit -ne $commit) { throw 'Source commit mismatch' }
$dirty = [bool](git status --porcelain)
if ($dirty -and -not $AllowDirty) { throw 'Commit source before producing a qualified package' }
function Confirm-Source {
    $currentCommit = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $currentCommit -cne $commit) { throw 'Source HEAD changed during qualification' }
    if (-not $AllowDirty -and [bool](git status --porcelain)) { throw 'Source changed during qualification; commit and restart from clean source' }
}

if ($ApprovedTag) {
    if ($ApprovedTag -cne "v$version") { throw 'Tag must exactly match workspace version' }
    $qualification = Get-Content -LiteralPath "$root/release-qualification.json" -Raw | ConvertFrom-Json
    if ($qualification.version -cne $version -or $qualification.publishable -ne $true) { throw 'This source is not approved for publication; see release-qualification.json' }
    $evidence = [IO.Path]::GetFullPath((Join-Path $root $qualification.requiredEvidence))
    if (-not $evidence.StartsWith($root + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $evidence -PathType Leaf)) { throw 'Required release evidence is absent or outside the source tree' }

    if ((git rev-parse "$ApprovedTag^{commit}").Trim() -ne $commit) { throw 'Tag does not identify this source commit' }
    if ($dirty) { throw 'Release tag source is dirty' }
}
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $root ("target/release-audit-" + [guid]::NewGuid().ToString('N')) }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if ((Test-Path -LiteralPath $OutputDirectory) -and @(Get-ChildItem -LiteralPath $OutputDirectory -Force).Count -ne 0) { throw 'Use a new empty output directory for every build' }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
# Install the complete verification-only dependency set before expensive builds.
# Keep it outside the product package and the user's global Python environment.
$verificationPython = Join-Path $root 'target/release-verification-python'
Invoke-Checked -Program python -Arguments @('-c','import sys; assert sys.version_info >= (3, 11), "Release verification requires Python 3.11+"')
Invoke-Checked -Program python -Arguments @('-m','pip','install','--disable-pip-version-check','--upgrade','--target',$verificationPython,'-r',"$root/scripts/requirements-release.txt")
Invoke-Checked -Program python -Arguments @('-I','-S','-c','import sys; sys.path.insert(0,sys.argv[1]); import psutil, unicorn; assert psutil.__version__ == "7.2.2"; assert unicorn.__version__ == "2.1.4"',$verificationPython)
$env:PYTHONPATH = if ($env:PYTHONPATH) { $verificationPython + [IO.Path]::PathSeparator + $env:PYTHONPATH } else { $verificationPython }
if ($ApprovedTag -or -not $AllowDirty) { Invoke-Checked -Program python -Arguments @("$root/scripts/verify-symbolic-checkout.py") }
Invoke-Checked -Program python -Arguments @("$root/scripts/prepare-python-runtime.py")
Invoke-Checked -Program python -Arguments @("$root/scripts/prepare-python-runtime.py",'--output',"$root/target/release/runtime/python")
Invoke-Checked -Program cargo -Arguments @('fmt','--all','--','--check')
Invoke-Checked -Program cargo -Arguments @('clippy','--workspace','--all-targets','--locked','--','-D','warnings')
Invoke-Checked -Program cargo -Arguments @('test','--workspace','--locked')
Invoke-Checked -Program cargo -Arguments @('build','--workspace','--release','--locked')
Invoke-Checked -Program cargo -Arguments @('build','-p','ura-core','--example','processor-verify','--release','--locked')
Invoke-Checked -Program cargo -Arguments @('build','-p','ura-core','--example','symbolic-verify','--release','--locked')
Invoke-Checked -Program python -Arguments @("$root/scripts/verify-symbolic-oracle.py",'--release','--output',"$OutputDirectory/symbolic-oracle")
Invoke-Checked -Program python -Arguments @("$root/scripts/verify-processor-oracle.py",'--release')
Confirm-Source
$buildStart = (Get-Date).ToUniversalTime()
$nonce = $commit + [guid]::NewGuid().ToString('N')
foreach ($component in @('ura-native','ura-cli','ura-mcp')) {
    # A unique compiler metadata input rebuilds each executable root even if its
    # source has not changed. Dependencies may be reused; old EXEs are never inputs.
    Invoke-Checked -Program cargo -Arguments @('rustc','-p',$component,'--bin',$component,'--release','--locked','--','-C',"metadata=$nonce-$component")
}
$hashes = @{}
foreach ($name in @('ura-native.exe','ura-cli.exe','ura-mcp.exe')) {
    $file = Get-Item -LiteralPath "$root/target/release/$name"
    if ($file.LastWriteTimeUtc -lt $buildStart) { throw "Executable was not freshly built: $name" }
    if ($file.VersionInfo.FileVersion -cne $version -or $file.VersionInfo.ProductName -cne 'URA') { throw "Incorrect version/product resource: $name" }
    $hashes[$name] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
}
Confirm-Source
$receipt = Join-Path $OutputDirectory 'BUILD-INFO.json'
@{schemaVersion=1;version=$version;sourceCommit=$commit;dirtySource=$dirty;profile='release';target='x86_64-pc-windows-msvc';buildStartedUtc=$buildStart.ToString('o');executableSha256=$hashes;rustc=(rustc --version);qualification=(Get-Content -LiteralPath "$root/release-qualification.json" -Raw | ConvertFrom-Json)} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $receipt -Encoding utf8
Invoke-Checked -Program python -Arguments @("$root/scripts/verify-dynamic-release.py",'--output',"$OutputDirectory/dynamic")
Invoke-Checked -Program python -Arguments @("$root/scripts/verify-symbolic-release.py",'--output',"$OutputDirectory/symbolic")
Invoke-Checked -Program python -Arguments @("$root/scripts/verify-patching-release.py",'--output',"$OutputDirectory/patching")
Invoke-Checked -Program python -Arguments @("$root/scripts/verify-debugger-release.py",'--output',"$OutputDirectory/debugger")
Invoke-Checked -Program python -Arguments @("$root/scripts/verify-advanced-debugger-release.py",'--output',"$OutputDirectory/advanced")
Invoke-Checked -Program python -Arguments @("$root/scripts/verify-scripting-release.py",'--output',"$OutputDirectory/scripting")
Confirm-Source
& "$root/scripts/package-windows.ps1" -Version $version -OutputDirectory $OutputDirectory -BuildReceipt $receipt
$archive = Join-Path $OutputDirectory "URA-$version-windows-x64.zip"
Invoke-Checked -Program python -Arguments @("$root/scripts/verify-audit-package.py",$archive,'--version',$version)
$manifest = @()
foreach ($name in @('ura-native.exe','ura-cli.exe','ura-mcp.exe')) { $manifest += "$($hashes[$name])  $name" }
$manifest += "$((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant())  $([IO.Path]::GetFileName($archive))"
$manifest | Set-Content -LiteralPath "$OutputDirectory/SHA256SUMS.txt" -Encoding utf8
foreach ($name in @('ura-native.exe','ura-cli.exe','ura-mcp.exe')) { Copy-Item -LiteralPath "$root/target/release/$name" -Destination $OutputDirectory }
Confirm-Source
Write-Output "Verified local artifacts: $OutputDirectory"
