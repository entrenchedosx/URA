param([Parameter(Mandatory)][ValidatePattern('^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$')][string]$Tag,[Parameter(Mandatory)][string]$ExpectedCommit,[Parameter(Mandatory)][string]$ArtifactDirectory,[string]$Repository='entrenchedosx/URA')
$ErrorActionPreference='Stop'
$root=(Resolve-Path "$PSScriptRoot/..").Path
$qualification=Get-Content -LiteralPath "$root/release-qualification.json" -Raw | ConvertFrom-Json
if ($Tag -cne "v$($qualification.version)" -or $qualification.publishable -ne $true) { throw 'Publication is not approved for this version' }
$evidence=[IO.Path]::GetFullPath((Join-Path $root $qualification.requiredEvidence))
if (-not $evidence.StartsWith($root + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $evidence -PathType Leaf)) { throw 'Required release evidence is absent or outside the source tree' }
if ((git rev-parse HEAD).Trim() -cne $ExpectedCommit -or [bool](git status --porcelain)) { throw 'Publisher requires the exact clean source commit' }
$ArtifactDirectory=(Resolve-Path -LiteralPath $ArtifactDirectory).Path
$receipt=Get-Content -LiteralPath "$ArtifactDirectory/BUILD-INFO.json" -Raw | ConvertFrom-Json
if ($receipt.sourceCommit -cne $ExpectedCommit -or $receipt.dirtySource -or $receipt.version -cne $qualification.version) { throw 'Build receipt does not match release source' }
$remoteCommit=gh api "repos/$Repository/commits/$Tag" --jq '.sha'
if ($LASTEXITCODE -ne 0 -or $remoteCommit.Trim() -cne $ExpectedCommit) { throw 'Release tag mismatch' }
gh release view $Tag --repo $Repository *> $null
if ($LASTEXITCODE -eq 0) { throw 'Release already exists; historical releases are immutable. Use a new version/tag.' }
$notes=Join-Path $ArtifactDirectory 'RELEASE-NOTES.md'
$body=Get-Content -LiteralPath "$root/docs/RELEASE-NOTES-$($qualification.version).md" -Raw
"Source commit: $ExpectedCommit`n`n$body" | Set-Content -LiteralPath $notes -Encoding utf8
$version=$qualification.version
$assets=@("$ArtifactDirectory/ura-native.exe","$ArtifactDirectory/ura-cli.exe","$ArtifactDirectory/ura-mcp.exe","$ArtifactDirectory/URA-$version-windows-x64.zip","$ArtifactDirectory/SHA256SUMS.txt")
foreach($asset in $assets){if(-not(Test-Path -LiteralPath $asset)){throw "Missing release artifact: $asset"}}
$arguments=@('release','create',$Tag,'--repo',$Repository,'--verify-tag','--draft','--title',"URA $Tag",'--notes-file',$notes)+$assets
if($version.Contains('-')){$arguments+='--prerelease'}
& gh @arguments
if($LASTEXITCODE -ne 0){throw 'Draft creation/upload failed; publication incomplete'}
try {
    & "$PSScriptRoot/verify-github-release.ps1" -Tag $Tag -ExpectedCommit $ExpectedCommit -Repository $Repository -OutputDirectory "$ArtifactDirectory/download-draft"
    gh release edit $Tag --repo $Repository --draft=false
    if($LASTEXITCODE -ne 0){throw 'Could not publish verified draft'}
    & "$PSScriptRoot/verify-github-release.ps1" -Tag $Tag -ExpectedCommit $ExpectedCommit -Repository $Repository -OutputDirectory "$ArtifactDirectory/download-public"
} catch {
    # Only this newly created release is affected; no asset replacement or tag moves.
    $originalFailure=$_.Exception.Message
    gh release edit $Tag --repo $Repository --draft=true
    $rollbackCode=$LASTEXITCODE
    $draftState=gh release view $Tag --repo $Repository --json isDraft --jq '.isDraft'
    $queryCode=$LASTEXITCODE
    if($rollbackCode -eq 0 -and $queryCode -eq 0 -and ([string]$draftState).Trim() -ceq 'true') {
        throw "Release verification failed/incomplete; confirmed draft. $originalFailure"
    }
    throw "Release verification failed; DRAFT ROLLBACK UNCONFIRMED. The new release MAY STILL BE PUBLIC. Inspect https://github.com/$Repository/releases/tag/$Tag immediately. Original failure: $originalFailure"
}
