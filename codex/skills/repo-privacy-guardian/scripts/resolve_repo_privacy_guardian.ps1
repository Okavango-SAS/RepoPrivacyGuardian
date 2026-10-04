[CmdletBinding()]
param(
    [string]$StartPath = (Get-Location).Path,
    [switch]$Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-FileSystemPath {
    param([string]$Candidate)

    $provider = $null
    $drive = $null
    $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Candidate, [ref]$provider, [ref]$drive)
    if ($provider.Name -ne 'FileSystem') {
        throw 'Backend paths must use the filesystem provider.'
    }
    return $resolved
}

function Test-GuardianCheckout {
    param([string]$Candidate)

    if (-not $Candidate) { return $false }
    foreach ($relative in @('Repo_Privacy_Guardian.py', 'repo_privacy_guardian/core.py', 'pyproject.toml')) {
        if (-not (Test-Path -LiteralPath (Join-Path $Candidate $relative) -PathType Leaf)) {
            return $false
        }
    }
    $project = Get-Content -LiteralPath (Join-Path $Candidate 'pyproject.toml') -Raw -Encoding UTF8
    return $project -match '(?ms)^\[project\]\s*\r?\n(?:(?!^\[).)*?^name\s*=\s*["'']repo-privacy-guardian["'']\s*$'
}

function Find-WorkspaceCheckout {
    param([string]$Candidate)

    $current = Resolve-FileSystemPath $Candidate
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
        if ((Test-Path -LiteralPath $localPython -PathType Leaf) -and (Test-SupportedPython $localPython @())) {
            return @($localPython, '-m', 'Repo_Privacy_Guardian')
        }
    }
    foreach ($name in @('python', 'py', 'python3')) {
        foreach ($pythonCommand in @(Get-Command $name -CommandType Application -All -ErrorAction SilentlyContinue)) {
            $prefix = if ($name -eq 'py') { @('-3') } else { @() }
            if (Test-SupportedPython $pythonCommand.Source $prefix) {
                return @($pythonCommand.Source) + $prefix + @('-m', 'Repo_Privacy_Guardian')
            }
        }
    }
    throw 'A RepoPrivacyGuardian checkout was found, but Python is unavailable. Prepare Python 3.10 or newer.'
}

function Test-SupportedPython {
    param([string]$Executable, [string[]]$PrefixArguments)

    $process = [Diagnostics.Process]::new()
    try {
        $info = [Diagnostics.ProcessStartInfo]::new()
        $arguments = ($PrefixArguments + @('-c', '"import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"')) -join ' '
        $info.FileName = $Executable
        $info.Arguments = $arguments
        if ([Environment]::OSVersion.Platform -eq 'Win32NT' -and [IO.Path]::GetExtension($Executable) -in @('.cmd', '.bat')) {
            # Expansion happens once inside quotes, including paths containing spaces or percent signs.
            $info.FileName = $env:ComSpec
            $info.EnvironmentVariables['RPG_PYTHON_PROBE_EXECUTABLE'] = $Executable
            $info.Arguments = '/d /s /c ""%RPG_PYTHON_PROBE_EXECUTABLE%" ' + $arguments + '"'
        }
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $process.StartInfo = $info
        if (-not $process.Start()) { return $false }
        # Consume both pipes without exposing candidate diagnostics or retaining their contents.
        $stdout = $process.StandardOutput.BaseStream.CopyToAsync([IO.Stream]::Null)
        $stderr = $process.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null)
        if (-not $process.WaitForExit(3000)) {
            if ($process.GetType().GetMethod('Kill', [type[]]@([bool]))) {
                $process.Kill($true)
            }
            elseif ([Environment]::OSVersion.Platform -eq 'Win32NT') {
                # .NET Framework has no tree-aware Kill overload (Windows PowerShell 5.1).
                $cleanup = [Diagnostics.Process]::new()
                try {
                    $cleanup.StartInfo.FileName = Join-Path $env:SystemRoot 'System32/taskkill.exe'
                    $cleanup.StartInfo.Arguments = '/PID ' + $process.Id + ' /T /F'
                    $cleanup.StartInfo.UseShellExecute = $false
                    $cleanup.StartInfo.CreateNoWindow = $true
                    $cleanup.StartInfo.RedirectStandardOutput = $true
                    $cleanup.StartInfo.RedirectStandardError = $true
                    if ($cleanup.Start()) {
                        $cleanupOut = $cleanup.StandardOutput.BaseStream.CopyToAsync([IO.Stream]::Null)
                        $cleanupError = $cleanup.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null)
                        if (-not $cleanup.WaitForExit(1000)) { $cleanup.Kill() }
                    }
                }
                finally { $cleanup.Dispose() }
            }
            else { $process.Kill() }
            $null = $process.WaitForExit(1000)
            return $false
        }
        return $process.ExitCode -eq 0
    }
    catch { return $false }
    finally { $process.Dispose() }
}

$checkout = Find-WorkspaceCheckout $StartPath
$source = 'workspace'
if (-not $checkout) {
    $skillRoot = Split-Path -Parent $PSScriptRoot
    $metadataPath = Join-Path $skillRoot '.local/install.json'
    if (Test-Path -LiteralPath $metadataPath -PathType Leaf) {
        try {
            $metadata = Get-Content -LiteralPath $metadataPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $metadataRoot = Resolve-FileSystemPath ([string]$metadata.repoRoot)
            if ($metadata.schemaVersion -eq 1 -and (Test-GuardianCheckout $metadataRoot)) {
                $checkout = $metadataRoot
                $source = 'installed-metadata'
            }
        }
        catch {
            # A stale or malformed local link must not prevent the explicit env/PATH fallbacks.
            $checkout = $null
        }
    }
    if (-not $checkout -and $env:REPO_PRIVACY_GUARDIAN_REPO) {
        $environmentRoot = Resolve-FileSystemPath $env:REPO_PRIVACY_GUARDIAN_REPO
        if (Test-GuardianCheckout $environmentRoot) {
            $checkout = $environmentRoot
            $source = 'env'
        }
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
