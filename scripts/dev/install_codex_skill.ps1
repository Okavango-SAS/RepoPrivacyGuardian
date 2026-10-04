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
$project = Get-Content -LiteralPath (Join-Path $repoRoot 'pyproject.toml') -Raw
if ($project -notmatch '(?ms)^\[project\]\s*\r?\n(?:(?!^\[).)*?^name\s*=\s*["'']repo-privacy-guardian["'']\s*$') {
    throw 'The installer source is not a RepoPrivacyGuardian project.'
}

if (-not $CodexHome) {
    $CodexHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else {
        Join-Path ([Environment]::GetFolderPath('UserProfile')) '.codex'
    }
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
    if (Test-Path -LiteralPath $targetSkill) {
        Remove-Item -LiteralPath $targetSkill -Recurse -Force
    }
    New-Item -ItemType Directory -Path $targetSkill | Out-Null
    # Copy the maintained public files only; local metadata never comes from the repository.
    foreach ($relative in $requiredFiles) {
        $destination = Join-Path $targetSkill $relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $sourceSkill $relative) -Destination $destination
    }
    $localRoot = Join-Path $targetSkill '.local'
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
    Write-Output 'Installed repo-privacy-guardian with a local checkout link.'
}
