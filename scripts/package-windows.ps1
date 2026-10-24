param(
    [ValidatePattern('^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$')][string]$Version,
    [string]$OutputDirectory,
    [string]$BuildReceipt
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot/..").Path
if (-not $Version) { $Version = (Select-String -Path "$root/Cargo.toml" -Pattern '^version = "([^"]+)"').Matches[0].Groups[1].Value }
foreach ($name in @('ura-native.exe', 'ura-cli.exe', 'ura-mcp.exe')) {
    $info = (Get-Item -LiteralPath "$root/target/release/$name").VersionInfo
    if ($info.FileVersion -ne $Version) { throw "Requested package version $Version differs from $name build $($info.FileVersion)" }
    if ($info.ProductName -ne 'URA') { throw "$name does not carry the URA product resource" }
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = Join-Path $root 'target' }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$package = Join-Path $OutputDirectory "URA-$Version-windows-x64"
if (Test-Path -LiteralPath "$package.zip") { throw "Archive already exists; choose a new output directory/version" }
if ((Test-Path -LiteralPath $package) -and @(Get-ChildItem -LiteralPath $package -Force).Count -gt 0) { throw "Package directory already exists and is nonempty: $package" }
cargo metadata --locked --format-version 1 --filter-platform x86_64-pc-windows-msvc | Set-Content -Encoding utf8 "$root/target/release-metadata.json"
if ($LASTEXITCODE -ne 0) { throw 'Cargo metadata failed' }
$licenseOutput = Join-Path $OutputDirectory ("license-collection-" + [guid]::NewGuid().ToString('N'))
python "$root/scripts/collect_licenses.py" --output $licenseOutput
if ($LASTEXITCODE -ne 0) { throw 'License collection failed' }
$missingLicenseText = [IO.File]::ReadAllText((Join-Path $licenseOutput 'MISSING-TEXTS.txt'))
if (-not [string]::IsNullOrWhiteSpace($missingLicenseText)) { throw "Missing dependency license texts; inspect $licenseOutput/MISSING-TEXTS.txt" }
New-Item -ItemType Directory -Path $package -Force | Out-Null
foreach ($name in @('ura-native.exe', 'ura-cli.exe', 'ura-mcp.exe')) {
    Copy-Item -LiteralPath "$root/target/release/$name" -Destination $package -Force
}
foreach ($name in @('LICENSE', 'README.md', 'THIRD_PARTY.md', 'icon.webp', 'Cargo.lock', 'release-qualification.json')) {
    Copy-Item -LiteralPath "$root/$name" -Destination $package -Force
}
Copy-Item -LiteralPath "$root/target/release/runtime" -Destination "$package/runtime" -Recurse -Force
Copy-Item -LiteralPath "$root/sdk" -Destination "$package/sdk" -Recurse -Force
Copy-Item -LiteralPath $licenseOutput -Destination "$package/licenses" -Recurse -Force
if ($BuildReceipt) { Copy-Item -LiteralPath $BuildReceipt -Destination "$package/BUILD-INFO.json" }
Copy-Item -LiteralPath "$root/docs" -Destination "$package/docs" -Recurse -Force
Get-ChildItem -LiteralPath $package -Recurse -File | Get-FileHash | ForEach-Object { "$($_.Hash.ToLowerInvariant())  $($_.Path.Substring($package.Length + 1).Replace('\', '/'))" } | Set-Content "$package/SHA256SUMS.txt"
$stamp = Get-Date
Get-ChildItem -LiteralPath $package -Recurse -Force | ForEach-Object { $_.LastWriteTime = $stamp }
$archive = "$package.zip"
Compress-Archive -Path "$package/*" -DestinationPath $archive -ErrorAction Stop
if (-not (Test-Path -LiteralPath $archive)) { throw "Archive was not created: $archive" }
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $([IO.Path]::GetFileName($archive))" | Set-Content "$archive.sha256"
$hash
