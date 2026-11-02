#define AppVersion "0.1.0"

[Setup]
AppId={{E8FBA0E7-CE38-47C4-9D91-3D810A99FC4A}
AppName=Helios
AppVersion={#AppVersion}
AppPublisher=Helios
DefaultDirName={autopf}\Helios
DefaultGroupName=Helios
OutputBaseFilename=Helios-Setup-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
Uninstallable=yes

[Files]
Source: "..\target\release\helios-client.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\release\helios-daemon.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\release\helios-helper.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\release\heliosctl.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Helios"; Filename: "{app}\helios-client.exe"
Name: "{autodesktop}\Helios"; Filename: "{app}\helios-client.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Run]
Filename: "{app}\helios-client.exe"; Description: "Launch Helios"; Flags: postinstall nowait skipifsilent
