[Setup]
AppId=FedoraCoin
AppName=FedoraCoin
AppVersion=0.60
DefaultDirName={pf}\FedoraCoin
DefaultGroupName=FedoraCoin
UninstallDisplayIcon={app}\fedoracoin-qt.exe
Compression=lzma2
SolidCompression=yes
OutputDir=..\release
SourceDir=..\release
OutputBaseFilename=fedoracoin-0.60-win32

[Files]
Source: "fedoracoin-qt.exe"; DestDir: "{app}"
Source: "fedoracoind.exe"; DestDir: "{app}"
Source: "libeay32.dll"; DestDir: "{app}"
Source: "libgcc_s_dw2-1.dll"; DestDir: "{app}"
Source: "libstdc++-6.dll"; DestDir: "{app}"
Source: "libwinpthread-1.dll"; DestDir: "{app}"
Source: "QtCore4.dll"; DestDir: "{app}"
Source: "QtGui4.dll"; DestDir: "{app}"
Source: "QtNetwork4.dll"; DestDir: "{app}"
Source: "CHANGELOG.txt"; DestDir: "{app}"

[Icons]
Name: "{group}\FedoraCoin"; Filename: "{app}\fedoracoin-qt.exe"
Name: "{group}\FedoraCoin Daemon"; Filename: "{app}\fedoracoind.exe"

[Run]
Filename: "{app}\fedoracoin-qt.exe"; Description: Start FedoraCoin Client; Flags: postinstall nowait skipifsilent
