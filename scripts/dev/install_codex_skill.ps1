[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$CodexHome = '',
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$skillName = 'repo-privacy-guardian'
$sourceSkill = Join-Path $repoRoot "codex/skills/$skillName"
$requiredFiles = @(
    'SKILL.md',
    'agents/openai.yaml',
    'scripts/resolve_repo_privacy_guardian.ps1',
    'references/advanced-operations.md'
)
foreach ($relative in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $sourceSkill $relative) -PathType Leaf)) {
        throw "The checkout is missing a required skill file: $relative"
    }
}
foreach ($relative in @('Repo_Privacy_Guardian.py', 'repo_privacy_guardian/core.py', 'pyproject.toml')) {
    if (-not (Test-Path -LiteralPath (Join-Path $repoRoot $relative) -PathType Leaf)) {
        throw 'Run this installer from its maintained RepoPrivacyGuardian checkout.'
    }
}
$project = Get-Content -LiteralPath (Join-Path $repoRoot 'pyproject.toml') -Raw -Encoding UTF8
if ($project -notmatch '(?ms)^\[project\]\s*\r?\n(?:(?!^\[).)*?^name\s*=\s*["'']repo-privacy-guardian["'']\s*$') {
    throw 'The installer source is not a RepoPrivacyGuardian project.'
}

if (-not $CodexHome) {
    $CodexHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else {
        Join-Path ([Environment]::GetFolderPath('UserProfile')) '.codex'
    }
}
$provider = $null
$drive = $null
$CodexHome = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CodexHome, [ref]$provider, [ref]$drive)
if ($provider.Name -ne 'FileSystem') {
    throw 'The Codex home must use the filesystem provider.'
}
$skillsRoot = [IO.Path]::GetFullPath((Join-Path $CodexHome 'skills'))
$targetSkill = [IO.Path]::GetFullPath((Join-Path $skillsRoot $skillName))
$comparison = if ([Environment]::OSVersion.Platform -eq 'Win32NT') {
    [StringComparison]::OrdinalIgnoreCase
} else { [StringComparison]::Ordinal }
$separator = [IO.Path]::DirectorySeparatorChar

function Test-WithinPath {
    param([string]$Child, [string]$Parent)
    return $Child.Equals($Parent, $comparison) -or $Child.StartsWith($Parent.TrimEnd($separator) + $separator, $comparison)
}

function Assert-NoReparsePath {
    param([string]$Candidate)
    $current = $Candidate
    while ($current) {
        $item = Get-Item -LiteralPath $current -Force -ErrorAction SilentlyContinue
        if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Skill installation refuses symlink or reparse-point paths.'
        }
        $parent = Split-Path -Parent $current
        if (-not $parent -or $parent -eq $current) { break }
        $current = $parent
    }
}

function Assert-NoReparseTree {
    param([string]$Candidate)
    Assert-NoReparsePath $Candidate
    if (Test-Path -LiteralPath $Candidate -PathType Container) {
        foreach ($item in (Get-ChildItem -LiteralPath $Candidate -Force -Recurse)) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Skill installation refuses a tree containing symlinks or reparse points.'
            }
        }
    }
}

function Assert-WorkDirectory {
    param([string]$Candidate)
    $absolute = [IO.Path]::GetFullPath($Candidate)
    $leaf = Split-Path -Leaf $absolute
    if (-not (Split-Path -Parent $absolute).Equals($skillsRoot, $comparison) -or
        -not ($leaf.StartsWith(".$skillName.stage-", $comparison) -or $leaf.StartsWith(".$skillName.backup-", $comparison))) {
        throw 'Skill staging and backup directories must remain in the configured skills directory.'
    }
    Assert-NoReparseTree $absolute
}

function Assert-PreparedSkill {
    param([string]$Candidate)
    Assert-NoReparseTree $Candidate
    foreach ($relative in $requiredFiles) {
        $destination = Join-Path $Candidate $relative
        if (-not (Test-Path -LiteralPath $destination -PathType Leaf) -or
            (Get-SkillFileHash $destination) -ne (Get-SkillFileHash (Join-Path $sourceSkill $relative))) {
            throw 'The prepared skill does not match its maintained source.'
        }
    }
    $installedMetadata = Get-Content -LiteralPath (Join-Path $Candidate '.local/install.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($installedMetadata.schemaVersion -ne 1 -or $installedMetadata.repoRoot -ne $repoRoot -or
        $installedMetadata.skillSource -ne $sourceSkill -or $installedMetadata.installer -ne $PSCommandPath -or
        -not $installedMetadata.installedAt) {
        throw 'The prepared skill has invalid local linkage metadata.'
    }
}

function Get-SkillFileHash {
    param([string]$Candidate)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Candidate)
    try { return [BitConverter]::ToString($algorithm.ComputeHash($stream)) }
    finally { $stream.Dispose(); $algorithm.Dispose() }
}

# Check the resolved absolute destination before any recursive replacement.
if ($targetSkill.Equals($skillsRoot, $comparison) -or -not (Test-WithinPath $targetSkill $skillsRoot)) {
    throw 'The skill destination must remain inside the configured skills directory.'
}
if ((Test-WithinPath $targetSkill $sourceSkill) -or (Test-WithinPath $sourceSkill $targetSkill)) {
    throw 'The installed skill and repository source must not overlap.'
}
Assert-NoReparseTree $sourceSkill
Assert-NoReparseTree $targetSkill
if ((Test-Path -LiteralPath $targetSkill) -and -not $Force) {
    throw 'The skill is already installed. Use -Force to replace that skill after reviewing the source.'
}

if ($PSCmdlet.ShouldProcess($targetSkill, 'Install the repo-linked Repo Privacy Guardian Codex skill')) {
    New-Item -ItemType Directory -Path $skillsRoot -Force | Out-Null
    $transactionId = [Guid]::NewGuid().ToString('N')
    $stageSkill = Join-Path $skillsRoot ".$skillName.stage-$transactionId"
    $backupSkill = Join-Path $skillsRoot ".$skillName.backup-$transactionId"
    $backupCreated = $false
    $replacementInstalled = $false
    try {
        Assert-WorkDirectory $stageSkill
        Assert-WorkDirectory $backupSkill
        New-Item -ItemType Directory -Path $stageSkill | Out-Null
        # Copy only maintained public files; local metadata never comes from the repository.
        foreach ($relative in $requiredFiles) {
            $destination = Join-Path $stageSkill $relative
            New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
            Copy-Item -LiteralPath (Join-Path $sourceSkill $relative) -Destination $destination
        }
        $localRoot = Join-Path $stageSkill '.local'
        New-Item -ItemType Directory -Path $localRoot | Out-Null
        $metadata = [ordered]@{
            schemaVersion = 1
            repoRoot = $repoRoot
            skillSource = $sourceSkill
            installedAt = (Get-Date).ToUniversalTime().ToString('o')
            installer = $PSCommandPath
        }
        $metadataJson = $metadata | ConvertTo-Json -Depth 4
        [IO.File]::WriteAllText((Join-Path $localRoot 'install.json'), $metadataJson, [Text.UTF8Encoding]::new($false))
        Assert-PreparedSkill $stageSkill
        Assert-NoReparseTree $targetSkill
        if (Test-Path -LiteralPath $targetSkill) {
            if (-not $Force) {
                throw 'The skill destination appeared during preparation. Review it before retrying with -Force.'
            }
            # A rename cannot silently nest the old skill in an existing backup container.
            Rename-Item -LiteralPath $targetSkill -NewName (Split-Path -Leaf $backupSkill)
            $backupCreated = $true
        }
        # Directory.Move refuses an existing destination instead of nesting the source inside it.
        [IO.Directory]::Move($stageSkill, $targetSkill)
        $replacementInstalled = $true
    }
    catch {
        if ($backupCreated -and -not $replacementInstalled) {
            Assert-WorkDirectory $backupSkill
            if (Test-Path -LiteralPath $targetSkill) {
                # Preserve an unexpected concurrently-created destination instead of deleting it.
                throw 'Skill replacement failed; the previous skill remains in its sibling backup for recovery.'
            }
            [IO.Directory]::Move($backupSkill, $targetSkill)
            $backupCreated = $false
        }
        throw
    }
    finally {
        if (Test-Path -LiteralPath $stageSkill) {
            Assert-WorkDirectory $stageSkill
            Remove-Item -LiteralPath $stageSkill -Recurse -Force
        }
    }
    if ($backupCreated) {
        # Replacement has committed. Cleanup failure must retain the usable replacement and backup.
        try {
            Assert-WorkDirectory $backupSkill
            Remove-Item -LiteralPath $backupSkill -Recurse -Force
        }
        catch { Write-Warning 'The skill was installed, but its sibling backup could not be removed.' }
    }
    Write-Output 'Installed repo-privacy-guardian with a local checkout link.'
}
