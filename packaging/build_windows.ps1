# =============================================================================
# Max1m — Сборка готового Windows-клиента Max1m.exe в 1 команду (PowerShell)
# Поддерживает Python 3.10, 3.11, 3.12, 3.13 (x64, без Visual Studio C++).
# Запуск:
#   двойным кликом по build_windows_exe.bat  ИЛИ
#   powershell -ExecutionPolicy Bypass -File .\packaging\build_windows.ps1
# Результат:
#   .\packaging\dist\Max1m\Max1m.exe
#   .\packaging\dist\Max1m\launch_two_instances.bat
#   .\packaging\dist\Max1m-Windows-x64.zip
# =============================================================================
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

function Resolve-CompatiblePython {
    # Prefer Python 3.12 / 3.11 / 3.10 / 3.13 x64 which have 100% prebuilt PyPI wheels (including PyAudio).
    if (Get-Command py -ErrorAction SilentlyContinue) {
        foreach ($ver in @("-3.12", "-3.11", "-3.10", "-3.13")) {
            try {
                $out = & py $ver -c "import sys; print(sys.executable)" 2>$null
                if ($LASTEXITCODE -eq 0 -and $out) {
                    return $out.Trim()
                }
            } catch {}
        }
    }
    $desktopVenvPy = Join-Path $RepoRoot "max1m_desktop\.venv\Scripts\python.exe"
    if (Test-Path $desktopVenvPy) { return $desktopVenvPy }
    return "python"
}

$BasePython = Resolve-CompatiblePython
Write-Host "[0/4] Используется интерпретатор Python: $BasePython"

$VenvDir = Join-Path $ScriptDir ".build_venv"
if (-not (Test-Path (Join-Path $VenvDir "Scripts\python.exe"))) {
    Write-Host "[1/4] Создаём изолированное окружение сборки..."
    & $BasePython -m venv $VenvDir
}

$PipExe = Join-Path $VenvDir "Scripts\pip.exe"
$PyExe  = Join-Path $VenvDir "Scripts\python.exe"

Write-Host "[2/4] Устанавливаем зависимости клиента и PyInstaller..."
& $PipExe install --upgrade pip wheel
& $PipExe install -r (Join-Path $RepoRoot "max1m_desktop\requirements.txt") pyinstaller==6.11.1

Write-Host "[3/4] Собираем автономный клиент Max1m.exe (PyInstaller)..."
& $PyExe (Join-Path $ScriptDir "build_portable.py")

Write-Host ""
Write-Host "================================================================="
Write-Host "[4/4] СБОРКА УСПЕШНО ЗАВЕРШЕНА!"
Write-Host "  Готовый клиент : packaging\dist\Max1m\Max1m.exe"
Write-Host "  Тест 2 окон    : packaging\dist\Max1m\launch_two_instances.bat"
Write-Host "  Портативный ZIP: packaging\dist\Max1m-Windows-x64.zip"
Write-Host "================================================================="
