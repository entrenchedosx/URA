param(
    [int]$Runs = 3,
    [string]$Output = "$PSScriptRoot/../target/desktop-benchmarks.json"
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot/..").Path
$cases = @(
    @{ Name = 'small'; Path = "$root/tests/fixtures/ura64.exe" },
    @{ Name = 'medium'; Path = "$env:WINDIR/System32/ntdll.dll" },
    @{ Name = 'large'; Path = "$env:LOCALAPPDATA/Programs/Microsoft VS Code/Code.exe" }
)
$apps = @(
    @{ Name = 'v0.4-tauri'; Path = "$root/target/release/ura-app.exe" },
    @{ Name = 'v0.5-native'; Path = "$root/target/release/ura-native.exe" }
)
$snapshotDir = Join-Path $root 'target/benchmark-bin'
New-Item -ItemType Directory -Path $snapshotDir -Force | Out-Null
foreach ($app in $apps) {
    $snapshot = Join-Path $snapshotDir ($app.Name + '.exe')
    Copy-Item -LiteralPath $app.Path -Destination $snapshot -Force
    $app.Path = $snapshot
    $app.Hash = (Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash
}
$env:URA_BENCHMARK_OUTPUT = $snapshotDir
$env:WEBVIEW2_USER_DATA_FOLDER = Join-Path $snapshotDir 'webview-profile'
function Get-ProcessFamily([int]$RootId) {
    $processRows = @(Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId)
    $family = [System.Collections.Generic.HashSet[int]]::new()
    [void]$family.Add($RootId)
    do {
        $changed = $false
        foreach ($row in $processRows) {
            if ($family.Contains([int]$row.ParentProcessId) -and $family.Add([int]$row.ProcessId)) { $changed = $true }
        }
    } while ($changed)
    return @($family | ForEach-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue })
}
$results = @()
foreach ($case in $cases) {
    if (-not (Test-Path -LiteralPath $case.Path)) { throw "Missing benchmark input: $($case.Path)" }
    foreach ($app in $apps) {
        for ($run = 0; $run -lt $Runs; $run++) {
            $timer = [System.Diagnostics.Stopwatch]::StartNew()
            $process = Start-Process -FilePath $app.Path -ArgumentList ('"' + $case.Path + '"') -PassThru
            $peak = 0L
            try {
                do { $process.Refresh(); if ($process.HasExited) { throw 'Application exited during startup' }; Start-Sleep -Milliseconds 10 } while ($process.MainWindowHandle -eq 0 -and $timer.Elapsed.TotalSeconds -lt 30)
                $windowMs = $timer.Elapsed.TotalMilliseconds
                # Fixed settling interval includes automatic analysis and strings.
                # This is a process-level benchmark, not proof of analysis completion.
                $settleUntil = [DateTime]::UtcNow.AddSeconds(8)
                do {
                    $family = @(Get-ProcessFamily $process.Id)
                    $working = ($family | Measure-Object WorkingSet64 -Sum).Sum
                    if ($working -gt $peak) { $peak = [long]$working }
                    Start-Sleep -Milliseconds 250
                } while ([DateTime]::UtcNow -lt $settleUntil)
                $before = @(Get-ProcessFamily $process.Id)
                $cpuBefore = ($before | ForEach-Object { $_.TotalProcessorTime.TotalSeconds } | Measure-Object -Sum).Sum
                $cpuTimer = [System.Diagnostics.Stopwatch]::StartNew()
                Start-Sleep -Seconds 2
                $after = @(Get-ProcessFamily $process.Id)
                $cpuAfter = ($after | ForEach-Object { $_.TotalProcessorTime.TotalSeconds } | Measure-Object -Sum).Sum
                $results += [pscustomobject]@{
                    App = $app.Name; Case = $case.Name; Run = $run + 1; Bytes = (Get-Item -LiteralPath $case.Path).Length
                    WindowHandleMs = [math]::Round($windowMs, 2)
                    WorkingSetMiB = [math]::Round((($after | Measure-Object WorkingSet64 -Sum).Sum / 1MB), 2)
                    SampledPeakMiB = [math]::Round(($peak / 1MB), 2)
                    IdleCpuOneCorePercent = [math]::Round([math]::Max(0.0, ($cpuAfter - $cpuBefore) / $cpuTimer.Elapsed.TotalSeconds * 100), 3)
                    ProcessCount = $after.Count
                    ProcessNames = @($after | ForEach-Object { $_.ProcessName })
                    ExecutableSHA256 = $app.Hash
                }
            } finally {
                # Terminate only the read-only benchmark instance and its children.
                $family = @(Get-ProcessFamily $process.Id)
                foreach ($child in $family) { Stop-Process -Id $child.Id -ErrorAction SilentlyContinue }
            }
        }
    }
}
@{ Method = 'Release builds, 1480x920 initial client size, fresh dedicated persistence/profile. Sum of process-family working sets (shared pages can be counted multiple times). WindowHandleMs ends when HWND exists, before content is necessarily painted. Eight-second settle, two-second CPU sample. First run is not a controlled cold-cache launch. Peak is sampled, not an OS high-water mark.'; OS = [Environment]::OSVersion.VersionString; LogicalProcessors = [Environment]::ProcessorCount; Results = $results } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Output
Remove-Item Env:/URA_BENCHMARK_OUTPUT
Remove-Item Env:/WEBVIEW2_USER_DATA_FOLDER
$results | Format-Table -AutoSize
