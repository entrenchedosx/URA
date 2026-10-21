param([ValidatePattern('^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$')][string]$Version = '0.7.0-dev')
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot/..").Path
$nativeVersion = (Get-Item -LiteralPath "$root/target/release/ura-native.exe").VersionInfo.FileVersion
if ($nativeVersion -ne $Version) { throw "Requested package version $Version differs from native build $nativeVersion" }
$package = Join-Path $root "target/URA-$Version-windows-x64"
if ((Test-Path -LiteralPath $package) -and @(Get-ChildItem -LiteralPath $package -Force).Count -gt 0) { throw "Package directory already exists and is nonempty: $package" }
cargo metadata --format-version 1 --filter-platform x86_64-pc-windows-msvc | Set-Content -Encoding utf8 "$root/target/release-metadata.json"
if ($LASTEXITCODE -ne 0) { throw 'Cargo metadata failed' }
python "$root/scripts/collect_licenses.py"
if ($LASTEXITCODE -ne 0) { throw 'License collection failed' }
if (-not [string]::IsNullOrWhiteSpace([IO.File]::ReadAllText("$root/target/release-licenses/MISSING-TEXTS.txt"))) { throw 'Missing dependency license texts; inspect target/release-licenses/MISSING-TEXTS.txt' }
New-Item -ItemType Directory -Path $package -Force | Out-Null
foreach ($name in @('ura-native.exe', 'ura-cli.exe', 'ura-mcp.exe')) {
    Copy-Item -LiteralPath "$root/target/release/$name" -Destination $package -Force
}
foreach ($name in @('LICENSE', 'README.md', 'THIRD_PARTY.md', 'icon.webp', 'Cargo.lock')) {
    Copy-Item -LiteralPath "$root/$name" -Destination $package -Force
}
Copy-Item -LiteralPath "$root/target/release-licenses" -Destination "$package/licenses" -Recurse -Force
Copy-Item -LiteralPath "$root/docs" -Destination "$package/docs" -Recurse -Force
Get-ChildItem -LiteralPath $package -File | Get-FileHash | ForEach-Object { "$($_.Hash)  $([IO.Path]::GetFileName($_.Path))" } | Set-Content "$package/SHA256SUMS.txt"
$archive = "$package.zip"
Compress-Archive -Path "$package/*" -DestinationPath $archive -Force
Get-FileHash -LiteralPath $archive
