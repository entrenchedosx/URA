param([Parameter(Mandatory)][string]$Tag,[Parameter(Mandatory)][string]$ExpectedCommit,[string]$Repository='entrenchedosx/URA',[Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
$root=(Resolve-Path "$PSScriptRoot/..").Path
$version=$Tag.Substring(1)
if ($Tag -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$') { throw 'Invalid release tag' }
$remoteCommit=gh api "repos/$Repository/commits/$Tag" --jq '.sha'
if ($LASTEXITCODE -ne 0 -or $remoteCommit.Trim() -cne $ExpectedCommit) { throw 'Remote tag/source mismatch' }
$releaseJson=gh release view $Tag --repo $Repository --json tagName,assets,isDraft,isPrerelease,url
if ($LASTEXITCODE -ne 0) { throw 'Cannot read GitHub release' }
$release=$releaseJson | ConvertFrom-Json
$names=@('ura-native.exe','ura-cli.exe','ura-mcp.exe',"URA-$version-windows-x64.zip",'SHA256SUMS.txt')
if ($release.tagName -cne $Tag -or $release.assets.Count -ne $names.Count) { throw 'Release asset set mismatch' }
foreach ($name in $names) {
    if (@($release.assets | Where-Object {$_.name -ceq $name -and $_.size -gt 0}).Count -ne 1) { throw "Missing/nonunique/empty release asset: $name" }
}
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Download verification requires a new empty directory' }
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
foreach ($name in $names) {
    gh release download $Tag --repo $Repository --pattern $name --dir $OutputDirectory
    if ($LASTEXITCODE -ne 0) { throw "GitHub download failed: $name" }
}
$manifest=Get-Content -LiteralPath "$OutputDirectory/SHA256SUMS.txt"
if ($manifest.Count -ne 4) { throw 'Expected exactly four checksum entries' }
$seen=@{}
foreach ($line in $manifest) {
    if ($line -notmatch '^([0-9a-f]{64})  ([^/\\]+)$') { throw 'Malformed checksum entry' }
    $hash=$Matches[1];$name=$Matches[2]
    if ($name -cnotin $names -or $name -ceq 'SHA256SUMS.txt' -or $seen.ContainsKey($name)) { throw 'Unexpected or duplicate checksum entry' }
    if ((Get-FileHash -LiteralPath (Join-Path $OutputDirectory $name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hash) { throw "Downloaded hash mismatch: $name" }
    $seen[$name]=$hash
}
$archive=Join-Path $OutputDirectory "URA-$version-windows-x64.zip"
"$($seen[[IO.Path]::GetFileName($archive)])  $([IO.Path]::GetFileName($archive))" | Set-Content -LiteralPath "$archive.sha256"
# Audit extracts to a new directory, verifies every member and license, compares
# all three EXEs to this commit's freshly built images, and runs CLI/MCP checks.
python "$root/scripts/verify-audit-package.py" $archive --version $version
if ($LASTEXITCODE -ne 0) { throw 'Downloaded package audit failed' }
$packageCheck=Get-Content -LiteralPath "$OutputDirectory/package-verification.json" -Raw | ConvertFrom-Json
$receipt=Get-Content -LiteralPath (Join-Path $packageCheck.extraction 'BUILD-INFO.json') -Raw | ConvertFrom-Json
if ($receipt.sourceCommit -cne $ExpectedCommit -or $receipt.version -cne $version -or $receipt.dirtySource) { throw 'Downloaded provenance/version mismatch' }
foreach ($name in @('ura-native.exe','ura-cli.exe','ura-mcp.exe')) {
    if ($receipt.executableSha256.$name -cne $seen[$name]) { throw 'Individual and packaged EXE mismatch' }
    $info=(Get-Item -LiteralPath (Join-Path $OutputDirectory $name)).VersionInfo
    if ($info.FileVersion -cne $version -or $info.ProductName -cne 'URA') { throw 'Downloaded Windows resource mismatch' }
}
python "$root/scripts/verify-dynamic-release.py" --bin-dir $OutputDirectory --output "$OutputDirectory/dynamic"
if ($LASTEXITCODE -ne 0) { throw 'Downloaded CLI/MCP dynamic smoke failed' }
@{tag=$Tag;sourceCommit=$ExpectedCommit;release=$release.url;draft=$release.isDraft;verifiedUtc=(Get-Date).ToUniversalTime().ToString('o');sha256=$seen;nativeStartup='Manual gate unverified; no desktop launch'} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath "$OutputDirectory/github-verification.json" -Encoding utf8
