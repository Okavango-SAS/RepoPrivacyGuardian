[CmdletBinding()]
param(
    [string]$StartPath = (Get-Location).Path,
    [switch]$Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-GuardianCheckout {
    param([string]$Candidate)

    if (-not $Candidate) { return $false }
    foreach ($relative in @('Repo_Privacy_Guardian.py', 'repo_privacy_guardian/core.py', 'pyproject.toml')) {
        if (-not (Test-Path -LiteralPath (Join-Path $Candidate $relative) -PathType Leaf)) {
            return $false
        }
    }
    $project = Get-Content -LiteralPath (Join-Path $Candidate 'pyproject.toml') -Raw
    return $project -match '(?ms)^\[project\]\s*\r?\n(?:(?!^\[).)*?^name\s*=\s*["'']repo-privacy-guardian["'']\s*$'
}

function Find-WorkspaceCheckout {
    param([string]$Candidate)

    $current = [IO.Path]::GetFullPath($Candidate)
    if (Test-Path -LiteralPath $current -PathType Leaf) { $current = Split-Path -Parent $current }
    while ($current) {
        if (Test-GuardianCheckout $current) { return $current }
        $parent = Split-Path -Parent $current
        if (-not $parent -or $parent -eq $current) { break }
        $current = $parent
    }
    return $null
}

function Get-CheckoutCommand {
    param([string]$Checkout)

    foreach ($relative in @('.venv/Scripts/python.exe', '.venv/bin/python')) {
        $localPython = Join-Path $Checkout $relative
        if (Test-Path -LiteralPath $localPython -PathType Leaf) {
            return @($localPython, '-m', 'Repo_Privacy_Guardian')
        }
    }
    foreach ($name in @('python', 'py', 'python3')) {
        $pythonCommand = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($pythonCommand) {
            if ($name -eq 'py') { return @($pythonCommand.Source, '-3', '-m', 'Repo_Privacy_Guardian') }
            return @($pythonCommand.Source, '-m', 'Repo_Privacy_Guardian')
        }
    }
    throw 'A RepoPrivacyGuardian checkout was found, but Python is unavailable. Prepare Python 3.10 or newer.'
}

$checkout = Find-WorkspaceCheckout $StartPath
$source = 'workspace'
if (-not $checkout) {
    $skillRoot = Split-Path -Parent $PSScriptRoot
    $metadataPath = Join-Path $skillRoot '.local/install.json'
    if (Test-Path -LiteralPath $metadataPath -PathType Leaf) {
        try {
            $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
            if ($metadata.schemaVersion -eq 1 -and (Test-GuardianCheckout ([string]$metadata.repoRoot))) {
                $checkout = [IO.Path]::GetFullPath([string]$metadata.repoRoot)
                $source = 'installed-metadata'
            }
        }
        catch {
            # A stale or malformed local link must not prevent the explicit env/PATH fallbacks.
            $checkout = $null
        }
    }
    if (-not $checkout -and $env:REPO_PRIVACY_GUARDIAN_REPO -and (Test-GuardianCheckout $env:REPO_PRIVACY_GUARDIAN_REPO)) {
        $checkout = [IO.Path]::GetFullPath($env:REPO_PRIVACY_GUARDIAN_REPO)
        $source = 'env'
    }
}

if ($checkout) {
    $resolution = [pscustomobject]@{
        kind = 'repo'
        source = $source
        repoRoot = $checkout
        cwd = $checkout
        command = @(Get-CheckoutCommand $checkout)
    }
}
else {
    $consoleCommand = Get-Command 'repo-privacy-guardian' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $consoleCommand) {
        throw 'RepoPrivacyGuardian was not found. Install its linked skill from a checkout, set REPO_PRIVACY_GUARDIAN_REPO, or prepare the CLI on PATH.'
    }
    $resolution = [pscustomobject]@{
        kind = 'path'
        source = 'path'
        repoRoot = $null
        cwd = (Get-Location).Path
        command = @($consoleCommand.Source)
    }
}

if ($Json) { $resolution | ConvertTo-Json -Depth 4 }
else { $resolution }
