# ═══════════════════════════════════════════════════════════════════════════
# AUTARCH — PyInstaller .exe Builder
#
# Creates a standalone Windows executable bundle using PyInstaller.
# Output: dist\bin\AUTARCH\AUTARCH.exe  (one-directory bundle)
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\build-exe.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\build-exe.ps1 -OneFile
#
# Prerequisites:
#   pip install pyinstaller
# ═══════════════════════════════════════════════════════════════════════════

param(
    [switch]$OneFile = $false,    # --onefile build (larger, slower to start)
    [string]$Python  = "python"   # Python interpreter to use
)

$ErrorActionPreference = "Stop"
$AppDir = Split-Path -Parent $PSScriptRoot

Write-Host ""
Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  AUTARCH .exe Builder (PyInstaller)"           -ForegroundColor Cyan
Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# ── Verify PyInstaller ────────────────────────────────────────────────────────
try {
    $ver = & $Python -c "import PyInstaller; print(PyInstaller.__version__)" 2>&1
    Write-Host "PyInstaller $ver" -ForegroundColor Green
} catch {
    Write-Host "ERROR: PyInstaller not found." -ForegroundColor Red
    Write-Host "Install it:  pip install pyinstaller" -ForegroundColor Yellow
    exit 1
}

# ── Prepare output directory ──────────────────────────────────────────────────
$BinDir = Join-Path $AppDir "dist\bin"
if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
}

# ── Run PyInstaller ───────────────────────────────────────────────────────────
$SpecFile  = Join-Path $AppDir "autarch.spec"
$DistDir   = $BinDir
$WorkDir   = Join-Path $AppDir "dist\.pyinstaller-work"

Write-Host "Building AUTARCH.exe..." -ForegroundColor Yellow
Write-Host "  Spec:   $SpecFile" -ForegroundColor DarkGray
Write-Host "  Output: $DistDir" -ForegroundColor DarkGray
Write-Host ""

$Args = @(
    $SpecFile,
    "--distpath", $DistDir,
    "--workpath", $WorkDir,
    "--noconfirm",
    "--clean"
)

if ($OneFile) {
    # Override spec and do a one-file build directly
    Write-Host "Mode: --onefile (single .exe, slower startup)" -ForegroundColor Magenta
    $Args = @(
        (Join-Path $AppDir "autarch.py"),
        "--onefile",
        "--name", "AUTARCH",
        "--distpath", $DistDir,
        "--workpath", $WorkDir,
        "--noconfirm",
        "--clean",
        "--add-data", "web/templates;web/templates",
        "--add-data", "web/static;web/static",
        "--add-data", "data;data",
        "--add-data", "modules;modules",
        "--add-data", "autarch_settings.conf;.",
        "--add-data", "user_manual.md;.",
        "--add-data", "windows_manual.md;.",
        "--add-data", "custom_sites.inf;.",
        "--add-data", "custom_adultsites.json;.",
        "--add-data", "android;android",
        "--add-data", "tools;tools",
        "--hidden-import", "flask",
        "--hidden-import", "werkzeug",
        "--hidden-import", "jinja2",
        "--hidden-import", "bcrypt",
        "--hidden-import", "requests",
        "--hidden-import", "msgpack",
        "--console"
    )
}

Set-Location $AppDir
& $Python -m PyInstaller @Args

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "ERROR: PyInstaller build failed (exit code $LASTEXITCODE)" -ForegroundColor Red
    exit $LASTEXITCODE
}

# ── Report ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  Build complete!" -ForegroundColor Green
Write-Host "════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""

if ($OneFile) {
    $exePath = Join-Path $DistDir "AUTARCH.exe"
    if (Test-Path $exePath) {
        $sizeMB = [math]::Round((Get-Item $exePath).Length / 1MB, 1)
        Write-Host "  Output: $exePath ($sizeMB MB)" -ForegroundColor White
    }
} else {
    $exePath = Join-Path $DistDir "AUTARCH\AUTARCH.exe"
    if (Test-Path $exePath) {
        $sizeKB = [math]::Round((Get-Item $exePath).Length / 1KB, 0)
        Write-Host "  Exe:    $exePath ($sizeKB KB)" -ForegroundColor White
        $dirSize = [math]::Round((Get-ChildItem (Join-Path $DistDir "AUTARCH") -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB, 1)
        Write-Host "  Bundle: dist\bin\AUTARCH\  ($dirSize MB total)" -ForegroundColor White
    }
}
Write-Host ""
Write-Host "  Run it:  .\dist\bin\AUTARCH\AUTARCH.exe --web" -ForegroundColor Cyan
Write-Host ""
