# =============================================================================
# Max1m - Local test backend starter for tunnel / 2-window testing (port 8000)
# =============================================================================
$ErrorActionPreference = "Continue"

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot   = Split-Path -Parent $ScriptDir
$BackendDir = Join-Path $RepoRoot "max1m_backend"
Set-Location $BackendDir

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

function Resolve-BackendPython {
    $candidates = @(
        (Join-Path $BackendDir ".venv\Scripts\python.exe"),
        (Join-Path $BackendDir "venv\Scripts\python.exe"),
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

$ShortRoot    = Resolve-ShortBuildRoot -BaseDir $RepoRoot
$ShortVenvDir = Join-Path $ShortRoot "bv"
$ShortVenvPy  = Join-Path $ShortVenvDir "Scripts\python.exe"
$LocalVenvPy  = Join-Path $BackendDir ".venv\Scripts\python.exe"
$LegacyVenvPy = Join-Path $BackendDir "venv\Scripts\python.exe"

if (Test-Path $ShortVenvPy) {
    $PyExe = $ShortVenvPy
} elseif (Test-Path $LocalVenvPy) {
    $PyExe = $LocalVenvPy
} elseif (Test-Path $LegacyVenvPy) {
    $PyExe = $LegacyVenvPy
} else {
    $BasePy = Resolve-BackendPython
    if (-not $BasePy) {
        Write-Host "[ERROR] Python 3.10-3.13 was not found." -ForegroundColor Red
        exit 1
    }
    Write-Host "[1/3] Creating short-path backend virtualenv: $ShortVenvDir ..." -ForegroundColor Cyan
    & $BasePy -m venv $ShortVenvDir
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $PyExe = $ShortVenvPy
    & $PyExe -m pip install --upgrade pip wheel
    & $PyExe -m pip install -r (Join-Path $BackendDir "requirements.txt")
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
$env:RATE_LIMIT_LOGIN = "60/minute"
$env:RATE_LIMIT_REGISTER = "30/hour"
$env:CALL_STUN_URLS = "stun:stun.cloudflare.com:3478"

& $PyExe -c "import pathlib, secrets; p = pathlib.Path('.env'); (p.exists() and len(p.read_text(encoding='utf-8')) >= 40) or p.write_text('SECRET_KEY=' + secrets.token_hex(32) + '\n', encoding='utf-8')"

Write-Host ""
$TunnelUrl = Read-Host "Optional: paste HTTPS tunnel URL to generate 1-click max1m-join:// links (or press Enter to skip)"
$TunnelUrl = $TunnelUrl.Trim()

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  Generating 2 fresh invite codes for Window #1 and Window #2:" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
$Out1 = (& $PyExe create_invite.py | Out-String)
$Out2 = (& $PyExe create_invite.py | Out-String)
Write-Host $Out1
Write-Host $Out2

if ($TunnelUrl -match "^https://") {
    $GenScript = Join-Path $RepoRoot "deploy\generate_join_link.py"
    $Inv1 = if ($Out1 -match "(MAX1M-[A-Z0-9-]+)") { $Matches[1] } else { "" }
    $Inv2 = if ($Out2 -match "(MAX1M-[A-Z0-9-]+)") { $Matches[1] } else { "" }
    Write-Host "=================================================================" -ForegroundColor Yellow
    Write-Host "  1-CLICK max1m-join:// STRINGS (paste into Max1m -> Apply):" -ForegroundColor Yellow
    Write-Host "=================================================================" -ForegroundColor Yellow
    Write-Host "[Window #1]:" -ForegroundColor Cyan
    & $PyExe $GenScript --server $TunnelUrl --invite $Inv1
    Write-Host "[Window #2]:" -ForegroundColor Cyan
    & $PyExe $GenScript --server $TunnelUrl --invite $Inv2
}

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Green
Write-Host "  Starting Max1m server on http://127.0.0.1:8000" -ForegroundColor Green
Write-Host "  Point your HTTPS tunnel to port 8000 (e.g. cloudflared / tuna)"
Write-Host "=================================================================" -ForegroundColor Green
& $PyExe run_server.py
