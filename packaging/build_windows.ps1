# =============================================================================
# Max1m - Build standalone Windows client Max1m.exe (Python 3.10 - 3.15 x64)
# Automatically picks the NEWEST installed Python (3.15 -> 3.14 -> 3.13 -> 3.12)
# and upgrades <Drive>:\.m1b\dv when a newer Python version is installed.
# Output:
#   packaging\dist\Max1m\Max1m.exe  (and <Drive>:\.m1b\dist\Max1m\Max1m.exe)
#   packaging\dist\Max1m\launch_two_instances.bat
#   packaging\dist\Max1m-Windows-x64.zip
# =============================================================================
$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

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

function Get-PythonVersionTag {
    param([string]$ExePath)
    if (-not $ExePath -or -not (Test-Path $ExePath)) { return "" }
    if ($ExePath -match "WindowsApps") { return "" }
    try {
        $out = & $ExePath -c "import sys, struct; assert struct.calcsize('P') == 8 and (3, 10) <= sys.version_info[:2] < (3, 16); print(f'{sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]}')" 2>$null
        if ($LASTEXITCODE -eq 0 -and $out) {
            return ($out | Select-Object -Last 1).ToString().Trim()
        }
    } catch {}
    return ""
}

function Resolve-CompatiblePython {
    # Prefer the NEWEST installed 64-bit Python first (3.15 -> 3.14 -> 3.13 -> 3.12 -> 3.11 -> 3.10)
    if (Get-Command py -ErrorAction SilentlyContinue) {
        foreach ($ver in @("-3.15", "-3.14", "-3.13", "-3.12", "-3.11", "-3.10")) {
            try {
                $out = & py $ver -c "import sys; print(sys.executable)" 2>$null
                if ($LASTEXITCODE -eq 0 -and $out) {
                    $trimmed = ($out | Select-Object -Last 1).ToString().Trim()
                    if ((Get-PythonVersionTag -ExePath $trimmed) -ne "") { return $trimmed }
                }
            } catch {}
        }
    }

    $candidates = @(
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python315\python.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python314\python.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python313\python.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python311\python.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python310\python.exe"),
        (Join-Path $env:ProgramFiles "Python315\python.exe"),
        (Join-Path $env:ProgramFiles "Python314\python.exe"),
        (Join-Path $env:ProgramFiles "Python313\python.exe"),
        (Join-Path $env:ProgramFiles "Python312\python.exe"),
        (Join-Path $env:ProgramFiles "Python311\python.exe"),
        (Join-Path $env:ProgramFiles "Python310\python.exe"),
        "C:\Python315\python.exe",
        "C:\Python314\python.exe",
        "C:\Python313\python.exe",
        "C:\Python312\python.exe",
        "C:\Python311\python.exe",
        "C:\Python310\python.exe"
    )
    foreach ($p in $candidates) {
        if ((Get-PythonVersionTag -ExePath $p) -ne "") { return $p }
    }

    if (Get-Command python -ErrorAction SilentlyContinue) {
        try {
            $out = & python -c "import sys; print(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $out) {
                $trimmed = ($out | Select-Object -Last 1).ToString().Trim()
                if ((Get-PythonVersionTag -ExePath $trimmed) -ne "") { return $trimmed }
            }
        } catch {}
    }
    return $null
}

$BasePython = Resolve-CompatiblePython
if (-not $BasePython) {
    Write-Host "[ERROR] 64-bit Python 3.10 - 3.15 was not found on this machine." -ForegroundColor Red
    Write-Host "        Install the latest 64-bit Python from https://www.python.org/downloads/ and re-run." -ForegroundColor Yellow
    exit 1
}

$TargetVer = Get-PythonVersionTag -ExePath $BasePython
$ShortRoot = Resolve-ShortBuildRoot -BaseDir $RepoRoot
$VenvDir   = Join-Path $ShortRoot "dv"
$PyExe     = Join-Path $VenvDir "Scripts\python.exe"

Write-Host "[1/4] Selected Python  : $BasePython (v$TargetVer)" -ForegroundColor Cyan
Write-Host "      Short build root : $ShortRoot (bypasses Windows 260-char MAX_PATH)" -ForegroundColor Cyan

$ExistingVenvVer = Get-PythonVersionTag -ExePath $PyExe
if ((Test-Path $VenvDir) -and ($ExistingVenvVer -ne $TargetVer)) {
    Write-Host "[2/4] Upgrading build virtualenv from Python '$ExistingVenvVer' to Python '$TargetVer' ..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $VenvDir -ErrorAction SilentlyContinue
}

if (-not (Test-Path $PyExe)) {
    Write-Host "[2/4] Creating clean short-path build virtualenv: $VenvDir ..." -ForegroundColor Cyan
    & $BasePython -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to create virtualenv at $VenvDir" -ForegroundColor Red
        exit 1
    }
}

$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
$env:MAX1M_SHORT_BUILD_ROOT = $ShortRoot

Write-Host "[3/4] Installing desktop wheels and PyInstaller (pyinstaller==6.22.3) ..." -ForegroundColor Cyan
& $PyExe -m pip install --upgrade pip wheel
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $PyExe -m pip install --only-binary=:all: -r (Join-Path $RepoRoot "max1m_desktop\requirements.txt") pyinstaller==6.22.3
if ($LASTEXITCODE -ne 0) {
    Write-Host "[WARN] Retrying pip install without strict binary-only flag ..." -ForegroundColor Yellow
    & $PyExe -m pip install -r (Join-Path $RepoRoot "max1m_desktop\requirements.txt") pyinstaller==6.22.3
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] pip install failed." -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

Write-Host "[4/4] Building portable Max1m.exe bundle ..." -ForegroundColor Cyan
& $PyExe (Join-Path $ScriptDir "build_portable.py")
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] PyInstaller build failed." -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Green
Write-Host "  BUILD SUCCEEDED (Python $TargetVer)!" -ForegroundColor Green
Write-Host "  Executable : packaging\dist\Max1m\Max1m.exe"
Write-Host "  Fallback   : $ShortRoot\dist\Max1m\Max1m.exe"
Write-Host "  2 Windows  : run_two_windows.bat"
Write-Host "  ZIP Bundle : packaging\dist\Max1m-Windows-x64.zip"
Write-Host "=================================================================" -ForegroundColor Green
