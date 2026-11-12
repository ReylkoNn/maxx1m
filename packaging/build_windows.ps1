# =============================================================================
# Max1m - Build standalone Windows client Max1m.exe (PowerShell 5.1 / 7+)
# Supports Python 3.10, 3.11, 3.12, 3.13 (x64 prebuilt wheels, no MSVC needed).
# Output:
#   packaging\dist\Max1m\Max1m.exe
#   packaging\dist\Max1m\launch_two_instances.bat
#   packaging\dist\Max1m-Windows-x64.zip
# =============================================================================
$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

function Resolve-CompatiblePython {
    $candidates = @(
        (Join-Path $RepoRoot "max1m_desktop\.venv\Scripts\python.exe"),
        (Join-Path $RepoRoot "max1m_desktop\venv\Scripts\python.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python311\python.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python310\python.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python313\python.exe"),
        "C:\Python312\python.exe",
        "C:\Python311\python.exe",
        "C:\Python310\python.exe",
        "C:\Python313\python.exe"
    )
    foreach ($p in $candidates) {
        if ($p -and (Test-Path $p)) { return $p }
    }
    if (Get-Command py -ErrorAction SilentlyContinue) {
        foreach ($ver in @("-3.12", "-3.11", "-3.10", "-3.13")) {
            $out = & py $ver -c "import sys; print(sys.executable)"
            if ($LASTEXITCODE -eq 0 -and $out) {
                $trimmed = ($out | Select-Object -Last 1).ToString().Trim()
                if (Test-Path $trimmed) { return $trimmed }
            }
        }
    }
    if (Get-Command python -ErrorAction SilentlyContinue) {
        $out = & python -c "import sys; print(sys.executable)"
        if ($LASTEXITCODE -eq 0 -and $out) {
            $trimmed = ($out | Select-Object -Last 1).ToString().Trim()
            if (Test-Path $trimmed) { return $trimmed }
        }
    }
    return $null
}

$BasePython = Resolve-CompatiblePython
if (-not $BasePython) {
    Write-Host "[ERROR] Python 3.10-3.13 (x64) was not found on this machine." -ForegroundColor Red
    exit 1
}
Write-Host "[1/4] Using Python interpreter: $BasePython" -ForegroundColor Cyan

$VenvDir = Join-Path $ScriptDir ".build_venv"
$PyExe   = Join-Path $VenvDir "Scripts\python.exe"
$PipExe  = Join-Path $VenvDir "Scripts\pip.exe"

if (-not (Test-Path $PyExe)) {
    Write-Host "[2/4] Creating isolated build virtualenv: $VenvDir ..." -ForegroundColor Cyan
    & $BasePython -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to create virtualenv." -ForegroundColor Red
        exit 1
    }
}

$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

Write-Host "[3/4] Installing desktop dependencies and PyInstaller (pyinstaller==6.11.1) ..." -ForegroundColor Cyan
& $PyExe -m pip install --upgrade pip wheel
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $PyExe -m pip install -r (Join-Path $RepoRoot "max1m_desktop\requirements.txt") pyinstaller==6.11.1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] pip install failed." -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "[4/4] Building portable Max1m.exe bundle ..." -ForegroundColor Cyan
& $PyExe (Join-Path $ScriptDir "build_portable.py")
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] PyInstaller build failed." -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Green
Write-Host "  BUILD SUCCEEDED!" -ForegroundColor Green
Write-Host "  Executable : packaging\dist\Max1m\Max1m.exe"
Write-Host "  2 Windows  : packaging\dist\Max1m\launch_two_instances.bat"
Write-Host "  ZIP Bundle : packaging\dist\Max1m-Windows-x64.zip"
Write-Host "=================================================================" -ForegroundColor Green
