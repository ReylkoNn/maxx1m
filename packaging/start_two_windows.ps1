# =============================================================================
# Max1m - Launch 2 isolated client windows on one PC (--instance 1 & 2)
# =============================================================================
$ErrorActionPreference = "Continue"

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot   = Split-Path -Parent $ScriptDir
$DesktopDir = Join-Path $RepoRoot "max1m_desktop"
$BuiltExe   = Join-Path $ScriptDir "dist\Max1m\Max1m.exe"

if (Test-Path $BuiltExe) {
    Write-Host "[EXE] Launching Window #1 (~/.max1m) ..." -ForegroundColor Cyan
    Start-Process -FilePath $BuiltExe -ArgumentList @("--instance", "1") -WorkingDirectory (Split-Path -Parent $BuiltExe)
    Start-Sleep -Seconds 2
    Write-Host "[EXE] Launching Window #2 (~/.max1m_inst_2) ..." -ForegroundColor Cyan
    Start-Process -FilePath $BuiltExe -ArgumentList @("--instance", "2") -WorkingDirectory (Split-Path -Parent $BuiltExe)
    Write-Host "[OK] Both Max1m.exe windows started!" -ForegroundColor Green
    exit 0
}

$candidates = @(
    (Join-Path $ScriptDir ".build_venv\Scripts\pythonw.exe"),
    (Join-Path $DesktopDir ".venv\Scripts\pythonw.exe"),
    (Join-Path $DesktopDir "venv\Scripts\pythonw.exe"),
    (Join-Path $ScriptDir ".build_venv\Scripts\python.exe"),
    (Join-Path $DesktopDir ".venv\Scripts\python.exe"),
    (Join-Path $DesktopDir "venv\Scripts\python.exe"),
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
Write-Host "[Python] Launching Window #1 (~/.max1m) ..." -ForegroundColor Cyan
Start-Process -FilePath $PyExe -ArgumentList @($RunScript, "--instance", "1") -WorkingDirectory $DesktopDir
Start-Sleep -Seconds 2
Write-Host "[Python] Launching Window #2 (~/.max1m_inst_2) ..." -ForegroundColor Cyan
Start-Process -FilePath $PyExe -ArgumentList @($RunScript, "--instance", "2") -WorkingDirectory $DesktopDir
Write-Host "[OK] Both client windows started!" -ForegroundColor Green
