# =============================================================================
# Max1m - Launch 2 isolated client windows on one PC (--instance 1 & 2)
# =============================================================================
$ErrorActionPreference = "Continue"

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot   = Split-Path -Parent $ScriptDir
$DesktopDir = Join-Path $RepoRoot "max1m_desktop"
$SpecFile   = Join-Path $ScriptDir "max1m_desktop.spec"

function Resolve-ShortBuildRoot {
    param([string]$BaseDir)
    $driveRoot = [System.IO.Path]::GetPathRoot($BaseDir)
    $candidates = @()
    if ($driveRoot) {
        $candidates += (Join-Path $driveRoot ".m1b")
    }
    if ($env:USERPROFILE) {
        $candidates += (Join-Path $env:USERPROFILE ".m1b")
    }
    if ($env:SystemDrive) {
        $candidates += ($env:SystemDrive + "\.m1b")
    }
    foreach ($dir in $candidates) {
        try {
            if (-not (Test-Path $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }
            $probe = Join-Path $dir "_w.tmp"
            [System.IO.File]::WriteAllText($probe, "ok")
            Remove-Item $probe -Force -ErrorAction SilentlyContinue
            return $dir
        } catch {}
    }
    return (Join-Path $BaseDir ".m1b")
}

function Test-ExeMatchesCurrentSpec {
    param([string]$ExePath, [string]$ExpectedStamp)
    if (-not (Test-Path $ExePath)) { return $false }
    if (-not $ExpectedStamp) { return $true }
    $stampPath = Join-Path (Split-Path -Parent $ExePath) "_build_stamp.txt"
    if (-not (Test-Path $stampPath)) { return $false }
    try {
        $actual = ([System.IO.File]::ReadAllText($stampPath)).Trim().ToLower()
        return ($actual -eq $ExpectedStamp)
    } catch {
        return $false
    }
}

$ExpectedStamp = ""
if (Test-Path $SpecFile) {
    try {
        $ExpectedStamp = (Get-FileHash -Path $SpecFile -Algorithm SHA256).Hash.Substring(0, 16).ToLower()
    } catch {}
}

$ShortRoot     = Resolve-ShortBuildRoot -BaseDir $RepoRoot
$RepoBuiltExe  = Join-Path $ScriptDir "dist\Max1m\Max1m.exe"
$ShortBuiltExe = Join-Path $ShortRoot "dist\Max1m\Max1m.exe"

$TargetExe = $null
if (Test-ExeMatchesCurrentSpec -ExePath $ShortBuiltExe -ExpectedStamp $ExpectedStamp) {
    $TargetExe = $ShortBuiltExe
} elseif (Test-ExeMatchesCurrentSpec -ExePath $RepoBuiltExe -ExpectedStamp $ExpectedStamp) {
    $TargetExe = $RepoBuiltExe
}

if ($TargetExe) {
    Write-Host "[EXE] Using current $TargetExe" -ForegroundColor Cyan
    Write-Host "[1/2] Launching Window #1 (~/.max1m) ..." -ForegroundColor Cyan
    Start-Process -FilePath $TargetExe -ArgumentList @("--instance", "1") -WorkingDirectory (Split-Path -Parent $TargetExe)
    Start-Sleep -Seconds 2
    Write-Host "[2/2] Launching Window #2 (~/.max1m_inst_2) ..." -ForegroundColor Cyan
    Start-Process -FilePath $TargetExe -ArgumentList @("--instance", "2") -WorkingDirectory (Split-Path -Parent $TargetExe)
    Write-Host "[OK] Both Max1m.exe windows started!" -ForegroundColor Green
    exit 0
}

if ((Test-Path $ShortBuiltExe) -or (Test-Path $RepoBuiltExe)) {
    Write-Host "[INFO] Cached Max1m.exe was built from an older version." -ForegroundColor Yellow
    Write-Host "       Launching updated Python client directly (run build_windows_exe.bat anytime to refresh Max1m.exe)." -ForegroundColor Yellow
}

$candidates = @(
    (Join-Path $ShortRoot "dv\Scripts\pythonw.exe"),
    (Join-Path $ShortRoot "dv\Scripts\python.exe"),
    (Join-Path $DesktopDir ".venv\Scripts\pythonw.exe"),
    (Join-Path $DesktopDir "venv\Scripts\pythonw.exe"),
    (Join-Path $DesktopDir ".venv\Scripts\python.exe"),
    (Join-Path $DesktopDir "venv\Scripts\python.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\Python\Python315\python.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\Python\Python314\python.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\Python\Python313\python.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\Python\Python311\python.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\Python\Python310\python.exe"),
    "python"
)

$PyExe = $null
foreach ($p in $candidates) {
    if ($p -eq "python") {
        if (Get-Command python -ErrorAction SilentlyContinue) { $PyExe = "python"; break }
    } elseif (Test-Path $p) {
        $PyExe = $p
        break
    }
}

if (-not $PyExe) {
    Write-Host "[ERROR] Max1m.exe is not built yet and Python was not found. Run build_windows_exe.bat first." -ForegroundColor Red
    exit 1
}

$RunScript = Join-Path $DesktopDir "run_desktop.py"
Write-Host "[Python] Launching Window #1 (~/.max1m) via $PyExe ..." -ForegroundColor Cyan
Start-Process -FilePath $PyExe -ArgumentList @($RunScript, "--instance", "1") -WorkingDirectory $DesktopDir
Start-Sleep -Seconds 2
Write-Host "[Python] Launching Window #2 (~/.max1m_inst_2) via $PyExe ..." -ForegroundColor Cyan
Start-Process -FilePath $PyExe -ArgumentList @($RunScript, "--instance", "2") -WorkingDirectory $DesktopDir
Write-Host "[OK] Both client windows started!" -ForegroundColor Green
