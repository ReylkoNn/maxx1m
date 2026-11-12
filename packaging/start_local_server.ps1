# =============================================================================
# Max1m - Local test backend starter for tunnel / 2-window testing (port 8000)
# =============================================================================
$ErrorActionPreference = "Continue"

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot   = Split-Path -Parent $ScriptDir
$BackendDir = Join-Path $RepoRoot "max1m_backend"
Set-Location $BackendDir

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

$VenvPy = Join-Path $BackendDir ".venv\Scripts\python.exe"
$LegacyVenvPy = Join-Path $BackendDir "venv\Scripts\python.exe"

if (Test-Path $VenvPy) {
    $PyExe = $VenvPy
} elseif (Test-Path $LegacyVenvPy) {
    $PyExe = $LegacyVenvPy
} else {
    $BasePy = Resolve-BackendPython
    if (-not $BasePy) {
        Write-Host "[ERROR] Python 3.10-3.13 was not found." -ForegroundColor Red
        exit 1
    }
    Write-Host "[1/3] Creating backend virtualenv max1m_backend\.venv ..." -ForegroundColor Cyan
    & $BasePy -m venv (Join-Path $BackendDir ".venv")
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $PyExe = $VenvPy
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
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  Generating 2 fresh invite codes for Window #1 and Window #2:" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
& $PyExe create_invite.py
& $PyExe create_invite.py

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Green
Write-Host "  Starting Max1m server on http://127.0.0.1:8000" -ForegroundColor Green
Write-Host "  Point your HTTPS tunnel to port 8000 (e.g. cloudflared / tuna)"
Write-Host "=================================================================" -ForegroundColor Green
& $PyExe run_server.py
