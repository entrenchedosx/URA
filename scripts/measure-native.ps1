param(
    [string]$Sample = "$env:WINDIR/System32/ntdll.dll",
    [int]$SettleSeconds = 8,
    [int]$SampleSeconds = 20,
    [string]$Output = "$PSScriptRoot/../target/native-idle.json"
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot/..").Path
$samplePath = (Resolve-Path -LiteralPath $Sample).Path
$outputDirectory = Join-Path $root 'target/idle-verification'
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
# A copy avoids Windows locking the build artifact while measuring.
$executable = Join-Path $outputDirectory 'ura-native-measure.exe'
Copy-Item -LiteralPath "$root/target/release/ura-native.exe" -Destination $executable -Force
$env:URA_BENCHMARK_OUTPUT = $outputDirectory
$timer = [Diagnostics.Stopwatch]::StartNew()
$process = Start-Process -FilePath $executable -ArgumentList ('"' + $samplePath + '"') -PassThru
try {
    do {
        Start-Sleep -Milliseconds 20
        $process.Refresh()
        if ($process.HasExited) { throw 'Native app exited before opening a window' }
    } while ($process.MainWindowHandle -eq 0 -and $timer.Elapsed.TotalSeconds -lt 30)
    if ($process.MainWindowHandle -eq 0) { throw 'No native window after 30 seconds' }
    $windowMs = $timer.Elapsed.TotalMilliseconds
    Start-Sleep -Seconds $SettleSeconds
    $process.Refresh()
    $cpuBefore = $process.TotalProcessorTime.TotalSeconds
    $threadsBefore = @{}
    foreach ($thread in $process.Threads) { $threadsBefore[$thread.Id] = $thread.TotalProcessorTime.TotalSeconds }
    $sampleTimer = [Diagnostics.Stopwatch]::StartNew()
    Start-Sleep -Seconds $SampleSeconds
    $process.Refresh()
    $cpuAfter = $process.TotalProcessorTime.TotalSeconds
    $threadDeltas = @($process.Threads | ForEach-Object {
        [pscustomobject]@{ Id = $_.Id; CpuSeconds = $_.TotalProcessorTime.TotalSeconds - [double]$threadsBefore[$_.Id]; State = [string]$_.ThreadState }
    } | Sort-Object CpuSeconds -Descending | Select-Object -First 5)
    [pscustomobject]@{
        InputName = [IO.Path]::GetFileName($samplePath)
        InputBytes = (Get-Item -LiteralPath $samplePath).Length
        InputSHA256 = (Get-FileHash -LiteralPath $samplePath).Hash
        ExecutableSHA256 = (Get-FileHash -LiteralPath $executable).Hash
        WindowHandleMs = [math]::Round($windowMs, 3)
        SampleSeconds = [math]::Round($sampleTimer.Elapsed.TotalSeconds, 3)
        CpuOneCorePercent = [math]::Round(($cpuAfter - $cpuBefore) / $sampleTimer.Elapsed.TotalSeconds * 100, 3)
        CpuBeforeSeconds = $cpuBefore
        CpuAfterSeconds = $cpuAfter
        Threads = $threadDeltas
        WorkingSetMiB = [math]::Round($process.WorkingSet64 / 1MB, 2)
        Method = 'Release build; visible window; fixed settle; no input or accessibility polling during CPU sample. HWND timing is not content-ready timing. A fixed settle does not prove analysis completion.'
    } | ConvertTo-Json | Set-Content -LiteralPath $Output
} finally {
    $process.Refresh()
    if (-not $process.HasExited) { [void]$process.CloseMainWindow(); [void]$process.WaitForExit(5000) }
    if (-not $process.HasExited) { Stop-Process -Id $process.Id }
    Remove-Item Env:/URA_BENCHMARK_OUTPUT
}
