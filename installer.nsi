; ============================================================================
; AUTARCH NSIS Installer Script
; ============================================================================
;
; Prerequisites:
;   1. Build PyInstaller first:  pyinstaller autarch_public.spec
;   2. Install NSIS:             https://nsis.sourceforge.io/Download
;   3. Compile this script:      makensis installer.nsi
;      Or right-click installer.nsi -> "Compile NSIS Script"
;
; Output: AUTARCH_Setup.exe
; ============================================================================

!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "LogicLib.nsh"

; ── App metadata ─────────────────────────────────────────────────────────────
!define APPNAME      "AUTARCH"
!define APPVERSION   "1.3"
!define PUBLISHER    "darkHal Security Group"
!define DESCRIPTION  "Autonomous Tactical Agent for Reconnaissance, Counterintelligence, and Hacking"

; Source directory — PyInstaller onedir output
!define SRCDIR       "dist\autarch"

; ── Installer settings ───────────────────────────────────────────────────────
Name "${APPNAME} ${APPVERSION}"
OutFile "AUTARCH_Setup.exe"
InstallDir "$LOCALAPPDATA\${APPNAME}"
InstallDirRegKey HKCU "Software\${APPNAME}" "InstallDir"
RequestExecutionLevel user
SetCompressor /SOLID lzma
SetCompressorDictSize 64
Unicode True

; ── Variables ────────────────────────────────────────────────────────────────
Var StartMenuGroup

; ── MUI configuration ────────────────────────────────────────────────────────
!define MUI_ABORTWARNING
!define MUI_ICON   "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

; Welcome page
!define MUI_WELCOMEPAGE_TITLE "Welcome to ${APPNAME} Setup"
!define MUI_WELCOMEPAGE_TEXT "This wizard will install ${APPNAME} ${APPVERSION} on your computer.$\r$\n$\r$\n${DESCRIPTION}$\r$\n$\r$\nClick Next to continue."

; Finish page — option to launch
!define MUI_FINISHPAGE_RUN "$INSTDIR\autarch_web.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Launch ${APPNAME} Web Dashboard"
!define MUI_FINISHPAGE_SHOWREADME ""
!define MUI_FINISHPAGE_SHOWREADME_NOTCHECKED
!define MUI_FINISHPAGE_SHOWREADME_TEXT "Create Desktop Shortcut"
!define MUI_FINISHPAGE_SHOWREADME_FUNCTION CreateDesktopShortcut

; ── Pages ────────────────────────────────────────────────────────────────────
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Language
!insertmacro MUI_LANGUAGE "English"

; ── Install section ──────────────────────────────────────────────────────────
Section "Install" SecInstall
    SetOutPath "$INSTDIR"

    ; Copy everything from the PyInstaller dist/autarch/ directory
    File /r "${SRCDIR}\*.*"

    ; Write uninstaller
    WriteUninstaller "$INSTDIR\Uninstall.exe"

    ; Registry — install location + Add/Remove Programs entry
    WriteRegStr HKCU "Software\${APPNAME}" "InstallDir" "$INSTDIR"

    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" \
        "DisplayName" "${APPNAME}"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" \
        "DisplayVersion" "${APPVERSION}"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" \
        "Publisher" "${PUBLISHER}"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" \
        "UninstallString" '"$INSTDIR\Uninstall.exe"'
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" \
        "InstallLocation" "$INSTDIR"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" \
        "DisplayIcon" "$INSTDIR\autarch.exe"
    WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" \
        "NoModify" 1
    WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" \
        "NoRepair" 1

    ; Estimate installed size for Add/Remove Programs
    ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
    IntFmt $0 "0x%08X" $0
    WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" \
        "EstimatedSize" "$0"

    ; ── Start Menu shortcuts ─────────────────────────────────────────────────
    CreateDirectory "$SMPROGRAMS\${APPNAME}"

    CreateShortcut "$SMPROGRAMS\${APPNAME}\${APPNAME} Web Dashboard.lnk" \
        "$INSTDIR\autarch_web.exe" "" "$INSTDIR\autarch_web.exe" 0
    CreateShortcut "$SMPROGRAMS\${APPNAME}\${APPNAME} CLI.lnk" \
        "$INSTDIR\autarch.exe" "" "$INSTDIR\autarch.exe" 0
    CreateShortcut "$SMPROGRAMS\${APPNAME}\Uninstall ${APPNAME}.lnk" \
        "$INSTDIR\Uninstall.exe" "" "$INSTDIR\Uninstall.exe" 0

SectionEnd

; ── Desktop shortcut function (called from finish page checkbox) ─────────────
Function CreateDesktopShortcut
    CreateShortcut "$DESKTOP\${APPNAME} Web.lnk" \
        "$INSTDIR\autarch_web.exe" "" "$INSTDIR\autarch_web.exe" 0
FunctionEnd

; ── Uninstall section ────────────────────────────────────────────────────────
Section "Uninstall"

    ; Kill running instances
    nsExec::ExecToLog 'taskkill /F /IM autarch.exe'
    nsExec::ExecToLog 'taskkill /F /IM autarch_web.exe'

    ; Remove Start Menu
    RMDir /r "$SMPROGRAMS\${APPNAME}"

    ; Remove Desktop shortcut
    Delete "$DESKTOP\${APPNAME} Web.lnk"

    ; Remove install directory (everything)
    RMDir /r "$INSTDIR"

    ; Remove registry entries
    DeleteRegKey HKCU "Software\${APPNAME}"
    DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"

SectionEnd
