; FileLocker installer (Inno Setup 6). Built by GitHub Actions; see .github/workflows/build.yml.
; Installs for the current user only, so it never needs an administrator password.

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#define AppName "FileLocker"
#define AppExe "FileLocker.exe"
#define Cmd "{app}\" + AppExe

[Setup]
AppId={{6F3C2A1E-8B4D-4E7A-9C21-5D0F7B3E9A42}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=FileLocker (open source)
AppPublisherURL=https://github.com/olamideba/filelocker
AppSupportURL=https://github.com/olamideba/filelocker/issues
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
DisableDirPage=yes
PrivilegesRequired=lowest
OutputDir=Output
OutputBaseFilename=FileLocker-Setup
SetupIconFile=..\assets\app.ico
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ChangesAssociations=yes
MinVersion=10.0
LicenseFile=..\LICENSE

[Files]
Source: "..\out\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs
Source: "..\assets\locked.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\assets\app.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\assets\unlocked.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autoprograms}\FileLocker - Lock everything I unlocked"; Filename: "{app}\{#AppExe}"; Parameters: "lockall"; IconFilename: "{app}\locked.ico"

[Registry]
; .locked files: padlock icon; double-click unlocks and opens.
Root: HKA; Subkey: "Software\Classes\.locked"; ValueType: string; ValueData: "FileLocker.LockedFile"; Flags: uninsdeletevalue uninsdeletekeyifempty
Root: HKA; Subkey: "Software\Classes\FileLocker.LockedFile"; ValueType: string; ValueData: "Locked file (FileLocker)"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\FileLocker.LockedFile\DefaultIcon"; ValueType: string; ValueData: "{app}\locked.ico,0"
Root: HKA; Subkey: "Software\Classes\FileLocker.LockedFile\shell"; ValueType: string; ValueData: "open"
Root: HKA; Subkey: "Software\Classes\FileLocker.LockedFile\shell\open"; ValueType: string; ValueData: "Unlock and open"
Root: HKA; Subkey: "Software\Classes\FileLocker.LockedFile\shell\open"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExe}"
Root: HKA; Subkey: "Software\Classes\FileLocker.LockedFile\shell\open\command"; ValueType: string; ValueData: """{#Cmd}"" open ""%1"""
Root: HKA; Subkey: "Software\Classes\FileLocker.LockedFile\shell\unlock"; ValueType: string; ValueData: "Unlock with FileLocker"
Root: HKA; Subkey: "Software\Classes\FileLocker.LockedFile\shell\unlock"; ValueType: string; ValueName: "MultiSelectModel"; ValueData: "Player"
Root: HKA; Subkey: "Software\Classes\FileLocker.LockedFile\shell\unlock\command"; ValueType: string; ValueData: """{#Cmd}"" unlock ""%1"""

; Right-click any file: Lock.
Root: HKA; Subkey: "Software\Classes\*\shell\FileLocker.Lock"; ValueType: string; ValueData: "Lock with FileLocker"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\*\shell\FileLocker.Lock"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExe}"
Root: HKA; Subkey: "Software\Classes\*\shell\FileLocker.Lock"; ValueType: string; ValueName: "MultiSelectModel"; ValueData: "Player"
Root: HKA; Subkey: "Software\Classes\*\shell\FileLocker.Lock\command"; ValueType: string; ValueData: """{#Cmd}"" lock ""%1"""

; Right-click any folder: Lock / Unlock.
Root: HKA; Subkey: "Software\Classes\Directory\shell\FileLocker.Lock"; ValueType: string; ValueData: "Lock folder with FileLocker"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\Directory\shell\FileLocker.Lock"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExe}"
Root: HKA; Subkey: "Software\Classes\Directory\shell\FileLocker.Lock"; ValueType: string; ValueName: "MultiSelectModel"; ValueData: "Player"
Root: HKA; Subkey: "Software\Classes\Directory\shell\FileLocker.Lock\command"; ValueType: string; ValueData: """{#Cmd}"" lock ""%1"""
Root: HKA; Subkey: "Software\Classes\Directory\shell\FileLocker.Unlock"; ValueType: string; ValueData: "Unlock folder with FileLocker"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\Directory\shell\FileLocker.Unlock"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\locked.ico"
Root: HKA; Subkey: "Software\Classes\Directory\shell\FileLocker.Unlock"; ValueType: string; ValueName: "MultiSelectModel"; ValueData: "Player"
Root: HKA; Subkey: "Software\Classes\Directory\shell\FileLocker.Unlock\command"; ValueType: string; ValueData: """{#Cmd}"" unlock ""%1"""

; Right-click empty space in a folder or on the desktop: Lock everything I unlocked.
Root: HKA; Subkey: "Software\Classes\Directory\Background\shell\FileLocker.LockAll"; ValueType: string; ValueData: "Lock everything I unlocked (FileLocker)"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\Directory\Background\shell\FileLocker.LockAll"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\locked.ico"
Root: HKA; Subkey: "Software\Classes\Directory\Background\shell\FileLocker.LockAll\command"; ValueType: string; ValueData: """{#Cmd}"" lockall"

[Run]
Filename: "{app}\{#AppExe}"; Parameters: "setup"; Description: "Open FileLocker"; Flags: postinstall nowait skipifsilent

[Code]
function InitializeSetup(): Boolean;
var
  Release: Cardinal;
begin
  Result := True;
  if not RegQueryDWordValue(HKLM, 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full', 'Release', Release) or (Release < 461808) then
  begin
    MsgBox('FileLocker needs .NET Framework 4.7.2 or newer. Run Windows Update (or install .NET Framework 4.8 from microsoft.com), then run this installer again.', mbError, MB_OK);
    Result := False;
  end;
end;

function InitializeUninstall(): Boolean;
begin
  Result := MsgBox('Before uninstalling, UNLOCK anything you still want to open.' #13#10#13#10 +
    'Locked files stay locked after uninstalling. Your key is kept, so reinstalling FileLocker on this PC unlocks them again.' #13#10#13#10 +
    'Continue uninstalling?', mbConfirmation, MB_YESNO) = IDYES;
end;
