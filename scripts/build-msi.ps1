# ═══════════════════════════════════════════════════════════════════════════
# AUTARCH - Windows MSI Installer Builder
#
# Creates a Windows .msi installer using Python's built-in msilib.
# Packages the PyInstaller bundle (dist\bin\AUTARCH\) into an MSI.
# Output: dist\bin\AUTARCH-1.3-win64.msi
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\build-msi.ps1
#
# Prerequisites:
#   - Python 3.10+ (msilib is a Windows standard library module)
#   - dist\bin\AUTARCH\ must exist (run build-exe.ps1 first)
# ===============================================================================

param(
    [string]$Python  = "python"
)

$ErrorActionPreference = "Stop"
$AppDir = Split-Path -Parent $PSScriptRoot

Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "  AUTARCH .msi Builder (msilib)"               -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

$BundleDir = Join-Path $AppDir "dist\bin\AUTARCH"
if (-not (Test-Path (Join-Path $BundleDir "AUTARCH.exe"))) {
    Write-Host "ERROR: dist\bin\AUTARCH\AUTARCH.exe not found." -ForegroundColor Red
    Write-Host "       Run build-exe.ps1 first to create the bundle." -ForegroundColor Yellow
    exit 1
}

Set-Location $AppDir
Write-Host "Building MSI from dist\bin\AUTARCH\ bundle..." -ForegroundColor Yellow
Write-Host ""

& $Python (Join-Path $AppDir "scripts\make_msi.py")

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "ERROR: MSI build failed (exit code $LASTEXITCODE)" -ForegroundColor Red
    exit $LASTEXITCODE
}

$msiFiles = Get-ChildItem (Join-Path $AppDir "dist\bin") -Filter "*.msi" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "===============================================" -ForegroundColor Green
Write-Host "  MSI build complete!" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Green
Write-Host ""
foreach ($msi in $msiFiles) {
    $sizeMB = [math]::Round($msi.Length / 1MB, 1)
    Write-Host "  Output: $($msi.FullName) ($sizeMB MB)" -ForegroundColor White
}
Write-Host ""
Write-Host "  Install: Double-click the .msi file" -ForegroundColor Cyan
Write-Host "  Or:      msiexec /i AUTARCH-1.3-win64.msi" -ForegroundColor Cyan
Write-Host ""
