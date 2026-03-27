# ═══════════════════════════════════════════════════════════════════════════
# AUTARCH — Full Windows Installer Builder
#
# Auto-installs required tools, then builds:
#   dist\bin\AUTARCH\AUTARCH.exe  — standalone executable bundle
#   dist\bin\AUTARCH-1.3-win64.msi — Windows installer
#
# Usage (run as Administrator or allow UAC prompt):
#   powershell -ExecutionPolicy Bypass -File scripts\build-all.ps1
#
# What this script installs (if not already present):
#   - pyinstaller          (via pip)
#   - WiX Toolset 4        (via dotnet tool install --global wix)
#   - .NET SDK             (via winget, if dotnet is missing)
# ═══════════════════════════════════════════════════════════════════════════

param(
    [string]$Python   = "python",
    [string]$Version  = "1.3",
    [switch]$SkipExe  = $false,    # Skip .exe build (use existing dist\bin\AUTARCH\)
    [switch]$SkipMsi  = $false     # Skip .msi build
)

$ErrorActionPreference = "Stop"
$AppDir  = Split-Path -Parent $PSScriptRoot
$BinDir  = Join-Path $AppDir "dist\bin"
$DistDir = Join-Path $AppDir "dist"

Write-Host ""
Write-Host "████████████████████████████████████████████████████" -ForegroundColor Cyan
Write-Host "  AUTARCH $Version — Windows Build System"           -ForegroundColor Cyan
Write-Host "████████████████████████████████████████████████████" -ForegroundColor Cyan
Write-Host ""

# ── Helper functions ──────────────────────────────────────────────────────────
function Write-Step([string]$msg) {
    Write-Host ""
    Write-Host "  ► $msg" -ForegroundColor Yellow
}

function Write-OK([string]$msg) {
    Write-Host "    ✔ $msg" -ForegroundColor Green
}

function Write-Warn([string]$msg) {
    Write-Host "    ⚠ $msg" -ForegroundColor Magenta
}

function Test-Command([string]$cmd) {
    return $null -ne (Get-Command $cmd -ErrorAction SilentlyContinue)
}

# ── 1. Verify Python ──────────────────────────────────────────────────────────
Write-Step "Checking Python..."
try {
    $pyVer = & $Python --version 2>&1
    Write-OK "$pyVer"
} catch {
    Write-Host "ERROR: Python not found. Install Python 3.10+ from python.org" -ForegroundColor Red
    exit 1
}

# ── 2. Install / verify PyInstaller ──────────────────────────────────────────
Write-Step "Checking PyInstaller..."
$piVer = & $Python -c "import PyInstaller; print(PyInstaller.__version__)" 2>&1
if ($piVer -match "^\d") {
    Write-OK "PyInstaller $piVer"
} else {
    Write-Warn "PyInstaller not found — installing..."
    & $Python -m pip install pyinstaller --quiet
    $piVer = & $Python -c "import PyInstaller; print(PyInstaller.__version__)" 2>&1
    Write-OK "PyInstaller $piVer installed"
}

# ── 3. Install / verify .NET SDK (required for WiX 4) ────────────────────────
if (-not $SkipMsi) {
    Write-Step "Checking .NET SDK (required for WiX)..."
    if (Test-Command "dotnet") {
        $dotnetVer = (dotnet --version 2>&1)
        Write-OK ".NET SDK $dotnetVer"
    } else {
        Write-Warn ".NET SDK not found — installing via winget..."
        if (Test-Command "winget") {
            winget install Microsoft.DotNet.SDK.8 --silent --accept-package-agreements --accept-source-agreements
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
            if (Test-Command "dotnet") {
                Write-OK ".NET SDK installed"
            } else {
                Write-Host "ERROR: Failed to install .NET SDK. Install manually from https://dot.net" -ForegroundColor Red
                Write-Host "       Then re-run this script." -ForegroundColor Yellow
                exit 1
            }
        } else {
            Write-Host "ERROR: winget not found. Install .NET SDK 8+ manually from https://dot.net" -ForegroundColor Red
            Write-Host "       Then re-run this script." -ForegroundColor Yellow
            exit 1
        }
    }
}

# ── 4. Install / verify WiX Toolset 4 ────────────────────────────────────────
if (-not $SkipMsi) {
    Write-Step "Checking WiX Toolset 4..."
    $wixOk = $false
    if (Test-Command "wix") {
        $wixVer = (wix --version 2>&1)
        Write-OK "wix $wixVer"
        $wixOk = $true
    } else {
        # Try via dotnet tool
        $dtWix = (dotnet tool list --global 2>&1) | Select-String "wix"
        if ($dtWix) {
            Write-OK "WiX found (dotnet tool)"
            $wixOk = $true
        } else {
            Write-Warn "WiX not found — installing via dotnet tool..."
            dotnet tool install --global wix --prerelease 2>&1 | Out-Null
            # Refresh PATH
            $env:Path += ";$env:USERPROFILE\.dotnet\tools"
            if (Test-Command "wix") {
                $wixVer = (wix --version 2>&1)
                Write-OK "WiX $wixVer installed"
                $wixOk = $true
            } else {
                Write-Warn "WiX could not be installed automatically."
                Write-Warn "Install manually: dotnet tool install --global wix"
                Write-Warn "Skipping MSI build."
                $SkipMsi = $true
            }
        }
    }
}

# ── 5. Create output directory ────────────────────────────────────────────────
Write-Step "Preparing output directory..."
if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
}
Write-OK "dist\bin\"

# ── 6. Build .exe with PyInstaller ───────────────────────────────────────────
if (-not $SkipExe) {
    Write-Step "Building AUTARCH.exe (PyInstaller one-directory bundle)..."
    Write-Host "    This may take 3–10 minutes..." -ForegroundColor DarkGray

    $SpecFile = Join-Path $AppDir "autarch.spec"
    $WorkDir  = Join-Path $DistDir ".pyinstaller-work"

    Set-Location $AppDir
    & $Python -m PyInstaller $SpecFile `
        --distpath $BinDir `
        --workpath $WorkDir `
        --noconfirm `
        --clean

    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: PyInstaller build failed." -ForegroundColor Red
        exit $LASTEXITCODE
    }

    $exePath = Join-Path $BinDir "AUTARCH\AUTARCH.exe"
    if (Test-Path $exePath) {
        $sizeMB = [math]::Round((Get-ChildItem (Join-Path $BinDir "AUTARCH") -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB, 1)
        Write-OK "dist\bin\AUTARCH\AUTARCH.exe  ($sizeMB MB bundle)"
    } else {
        Write-Host "ERROR: AUTARCH.exe not found after build." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Warn "Skipping .exe build (-SkipExe)"
    $exePath = Join-Path $BinDir "AUTARCH\AUTARCH.exe"
    if (-not (Test-Path $exePath)) {
        Write-Host "ERROR: dist\bin\AUTARCH\AUTARCH.exe not found. Remove -SkipExe to build it." -ForegroundColor Red
        exit 1
    }
}

# ── 7. Generate WiX source (.wxs) from PyInstaller output ────────────────────
if (-not $SkipMsi) {
    Write-Step "Generating WiX source from AUTARCH bundle..."

    $WxsFile     = Join-Path $DistDir ".wix\AUTARCH.wxs"
    $WxsDir      = Split-Path $WxsFile
    $BundleDir   = Join-Path $BinDir "AUTARCH"
    $MsiOut      = Join-Path $BinDir "AUTARCH-${Version}-win64.msi"

    if (-not (Test-Path $WxsDir)) {
        New-Item -ItemType Directory -Path $WxsDir -Force | Out-Null
    }

    # Use WiX 4 harvest tool to generate component list from the bundle directory
    $HeatOut = Join-Path $WxsDir "components.wxs"

    # Build WiX 4 MSI directly using wix build command
    Write-Host "    Running wix build (WiX 4)..." -ForegroundColor DarkGray

    # Create a minimal WiX 4 package definition
    $WixSrcDir = Join-Path $DistDir ".wix"
    $PackageWxs = Join-Path $WixSrcDir "Package.wxs"

    # Generate file list for WiX
    $files = Get-ChildItem $BundleDir -Recurse -File
    $compLines = @()
    $fileLines  = @()
    $i = 0
    foreach ($f in $files) {
        $rel   = $f.FullName.Substring($BundleDir.Length + 1)
        $relDir = [System.IO.Path]::GetDirectoryName($rel)
        $id    = "f$i"
        $compId = "c$i"
        $fileLines  += "    <File Id='$id' Source='$($f.FullName.Replace('\','\\'))' />"
        $compLines  += "    <Component Id='$compId' Guid='*'><File Id='${id}f' Source='$($f.FullName.Replace('\','\\'))' /></Component>"
        $i++
    }

    # Write Package.wxs (WiX 4 syntax)
    @"
<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package Name="AUTARCH" Version="$Version.0.0" Manufacturer="darkHal Security Group"
           UpgradeCode="A1B2C3D4-E5F6-7890-ABCD-EF1234567890"
           Language="1033" Codepage="1252">

    <MajorUpgrade DowngradeErrorMessage="A newer version of AUTARCH is already installed." />
    <MediaTemplate EmbedCab="yes" />

    <Feature Id="Main" Title="AUTARCH" Level="1">
      <ComponentGroupRef Id="AppFiles" />
    </Feature>

    <StandardDirectory Id="ProgramFilesFolder">
      <Directory Id="INSTALLFOLDER" Name="AUTARCH">
        <ComponentGroup Id="AppFiles">
"@ | Out-File -FilePath $PackageWxs -Encoding utf8

    # Add all files as components
    $i = 0
    foreach ($f in $files) {
        $rel    = $f.FullName.Substring($BundleDir.Length + 1)
        $relDir = [System.IO.Path]::GetDirectoryName($rel)
        $fid    = "File_$i"
        $cid    = "Comp_$i"
        $did    = if ($relDir) { "Dir_$($relDir.Replace('\','_').Replace(' ','_'))" } else { "INSTALLFOLDER" }
        $srcPath = $f.FullName
        "          <Component Id='$cid' Guid='*'><File Id='$fid' Source='$srcPath' /></Component>" |
            Out-File -FilePath $PackageWxs -Encoding utf8 -Append
        $i++
    }

    @"
        </ComponentGroup>
      </Directory>
    </StandardDirectory>
  </Package>
</Wix>
"@ | Out-File -FilePath $PackageWxs -Encoding utf8 -Append

    Write-Host "    Compiling MSI with WiX 4..." -ForegroundColor DarkGray
    $env:Path += ";$env:USERPROFILE\.dotnet\tools"
    wix build $PackageWxs -out $MsiOut

    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: WiX MSI build failed." -ForegroundColor Red
        Write-Warn "The .exe bundle is still available at dist\bin\AUTARCH\AUTARCH.exe"
        exit $LASTEXITCODE
    }

    if (Test-Path $MsiOut) {
        $sizeMB = [math]::Round((Get-Item $MsiOut).Length / 1MB, 1)
        Write-OK "dist\bin\AUTARCH-${Version}-win64.msi  ($sizeMB MB)"
    }
}

# ── 8. Summary ────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "████████████████████████████████████████████████████" -ForegroundColor Green
Write-Host "  BUILD COMPLETE" -ForegroundColor Green
Write-Host "████████████████████████████████████████████████████" -ForegroundColor Green
Write-Host ""
Write-Host "  Standalone bundle: dist\bin\AUTARCH\AUTARCH.exe" -ForegroundColor White
if (-not $SkipMsi) {
    Write-Host "  MSI installer:     dist\bin\AUTARCH-${Version}-win64.msi" -ForegroundColor White
}
Write-Host ""
Write-Host "  Run standalone:    .\dist\bin\AUTARCH\AUTARCH.exe --web" -ForegroundColor Cyan
Write-Host "  Install MSI:       msiexec /i dist\bin\AUTARCH-${Version}-win64.msi" -ForegroundColor Cyan
Write-Host ""
