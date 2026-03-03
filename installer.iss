; ============================================================================
; AUTARCH Inno Setup Installer Script — v2.2
; ============================================================================
;
; Prerequisites:
;   1. Build PyInstaller first:  python -m PyInstaller autarch_public.spec -y
;   2. Install Inno Setup 6:    https://jrsoftware.org/isdl.php
;   3. Compile this script:     Open in Inno Setup Compiler -> Build -> Compile
;      Or from CLI:             iscc installer.iss
;
; Output: Output\AUTARCH_Setup.exe
; ============================================================================

[Setup]
AppName=AUTARCH
AppVersion=2.2
AppVerName=AUTARCH 2.2
AppPublisher=darkHal Security Group
AppPublisherURL=https://github.com/darkhal
AppSupportURL=https://github.com/darkhal
DefaultDirName={localappdata}\AUTARCH
DefaultGroupName=AUTARCH
OutputBaseFilename=AUTARCH_Setup
Compression=lzma2
SolidCompression=no
LZMANumBlockThreads=4
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayName=AUTARCH
DisableProgramGroupPage=yes
WizardStyle=modern
SetupLogging=yes

SetupIconFile=autarch.ico
UninstallDisplayIcon={app}\autarch_web.exe

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a Desktop shortcut"; GroupDescription: "Additional shortcuts:"
Name: "startupicon"; Description: "Launch Web Dashboard on Windows startup"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
; Everything from PyInstaller output (compressed with lzma2)
; NOTE: GGUF model excluded — download separately from release page
Source: "dist\autarch\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "_internal\models\Hal_v2.gguf"

; DNS server binary — standalone copy alongside the bundled one in _internal
Source: "services\dns-server\autarch-dns.exe"; DestDir: "{app}\services\dns-server"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
; Start Menu
Name: "{group}\AUTARCH Web Dashboard"; Filename: "{app}\autarch_web.exe"; IconFilename: "{app}\_internal\autarch.ico"; Comment: "Launch AUTARCH Web Dashboard with system tray"
Name: "{group}\AUTARCH CLI"; Filename: "{app}\autarch.exe"; IconFilename: "{app}\_internal\autarch.ico"; Comment: "AUTARCH command-line interface"
Name: "{group}\Uninstall AUTARCH"; Filename: "{uninstallexe}"

; Desktop (optional)
Name: "{commondesktop}\AUTARCH Web"; Filename: "{app}\autarch_web.exe"; IconFilename: "{app}\_internal\autarch.ico"; Tasks: desktopicon; Comment: "Launch AUTARCH Web Dashboard"

; Windows Startup (optional)
Name: "{userstartup}\AUTARCH Web"; Filename: "{app}\autarch_web.exe"; Tasks: startupicon

[Run]
; Option to launch after install
Filename: "{app}\autarch_web.exe"; Description: "Launch AUTARCH Web Dashboard"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Kill running instances before uninstall
Filename: "taskkill"; Parameters: "/F /IM autarch.exe"; Flags: runhidden
Filename: "taskkill"; Parameters: "/F /IM autarch_web.exe"; Flags: runhidden
Filename: "taskkill"; Parameters: "/F /IM autarch-dns.exe"; Flags: runhidden

[UninstallDelete]
; Clean up runtime-generated files
Type: filesandordirs; Name: "{app}\data"
Type: filesandordirs; Name: "{app}\results"
Type: filesandordirs; Name: "{app}\dossiers"
Type: filesandordirs; Name: "{app}\backups"
Type: filesandordirs; Name: "{app}\services"
Type: files; Name: "{app}\autarch_settings.conf"

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
end;
