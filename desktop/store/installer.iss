; Network Doctor - Windows installer (Inno Setup)
;
; The app has always shipped as a single portable NetworkDoctor.exe: double-click, no install step,
; no Start Menu entry, no entry in "Add or remove programs". This wraps that same exe in a normal
; Windows installer experience instead - Program Files-style install (per-user, no admin needed to
; install), Start Menu + optional Desktop shortcut, and a proper uninstaller - while leaving the exe's
; own self-updater (nd_update.py) untouched: it keeps updating the installed copy in place exactly as
; it always has, since the install folder stays user-writable.
;
; Built in CI by ISCC.exe (Inno Setup, preinstalled on GitHub's windows-latest runner) right after
; PyInstaller produces dist\NetworkDoctor.exe - see .github/workflows/desktop-release.yml.
; MyAppVersion is passed in with /DMyAppVersion=X.Y.Z; AppSourceDir with /DAppSourceDir=<path to the
; folder holding the built NetworkDoctor.exe>.

#ifndef MyAppVersion
  #define MyAppVersion "0.0.0"
#endif
#ifndef AppSourceDir
  #define AppSourceDir "..\dist"
#endif

[Setup]
AppId={{B6B6C6B1-6E1D-4B8E-9B0D-5C8E7D6F2A91}
AppName=Network Doctor
AppVersion={#MyAppVersion}
AppPublisher=Network Doctor
DefaultDirName={autopf}\Network Doctor
DefaultGroupName=Network Doctor
; Per-user by default (no admin prompt to install) - "All users" is still offered if run elevated.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=NetworkDoctor-Setup
SetupIconFile={#AppSourceDir}\..\store\NetworkDoctor.ico
UninstallDisplayIcon={app}\NetworkDoctor.exe
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
; Updates itself from here on (nd_update.py) - this installer is only the first copy.
AppUpdatesURL=https://github.com/yadavrkpacheriya/network-doctor/releases/latest

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Files]
Source: "{#AppSourceDir}\NetworkDoctor.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Network Doctor"; Filename: "{app}\NetworkDoctor.exe"
Name: "{group}\Uninstall Network Doctor"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Network Doctor"; Filename: "{app}\NetworkDoctor.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\NetworkDoctor.exe"; Description: "Launch Network Doctor now"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; The self-updater can drop a sibling NetworkDoctor.new.exe / a leftover update .cmd next to the exe -
; clean those up too so an uninstall does not leave stray files behind.
Type: files; Name: "{app}\NetworkDoctor.new.exe"
