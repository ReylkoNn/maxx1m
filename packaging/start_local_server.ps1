# =============================================================================
# Max1m - Local test backend starter for tunnel / 2-window testing (port 8000)
# Automatically picks the NEWEST installed Python (3.15 -> 3.14 -> 3.13 -> 3.12)
# and upgrades <Drive>:\.m1b\bv when a newer Python version is installed.
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

function Resolve-BackendPython {
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

$BasePy = Resolve-BackendPython
if (-not $BasePy) {
    Write-Host "[ERROR] 64-bit Python 3.10 - 3.15 was not found." -ForegroundColor Red
    exit 1
}

$TargetVer    = Get-PythonVersionTag -ExePath $BasePy
$ShortRoot    = Resolve-ShortBuildRoot -BaseDir $RepoRoot
$ShortVenvDir = Join-Path $ShortRoot "bv"
$ShortVenvPy  = Join-Path $ShortVenvDir "Scripts\python.exe"

$ExistingVenvVer = Get-PythonVersionTag -ExePath $ShortVenvPy
if ((Test-Path $ShortVenvDir) -and ($ExistingVenvVer -ne $TargetVer)) {
    Write-Host "[INFO] Upgrading backend virtualenv from Python '$ExistingVenvVer' to Python '$TargetVer' ..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $ShortVenvDir -ErrorAction SilentlyContinue
}

if (-not (Test-Path $ShortVenvPy)) {
    Write-Host "[1/3] Creating short-path backend virtualenv ($TargetVer): $ShortVenvDir ..." -ForegroundColor Cyan
    & $BasePy -m venv $ShortVenvDir
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & $ShortVenvPy -m pip install --upgrade pip wheel
    & $ShortVenvPy -m pip install -r (Join-Path $BackendDir "requirements.txt")
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$PyExe = $ShortVenvPy

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
Write-Host "  Starting Max1m server on http://127.0.0.1:8000 (Python $TargetVer)" -ForegroundColor Green
Write-Host "  Point your HTTPS tunnel to port 8000 (e.g. cloudflared / tuna)"
Write-Host "=================================================================" -ForegroundColor Green
& $PyExe run_server.py
