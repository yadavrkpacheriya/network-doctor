@echo off
REM Network Doctor - install the PC agent (run as administrator, once per PC).
REM Sets up the background watch at logon and puts a single "Fix my PC" button on the Desktop.
setlocal
set DST=%ProgramData%\NetworkDoctor
if not exist "%DST%" mkdir "%DST%"
copy /Y "%~dp0networkdoctor-agent.ps1" "%DST%\networkdoctor-agent.ps1" >nul
set PS=powershell -NoProfile -ExecutionPolicy Bypass

schtasks /Create /TN "NetworkDoctor Agent" /TR ^
 "powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \"%DST%\networkdoctor-agent.ps1\" -Mode background" ^
 /SC ONLOGON /RL HIGHEST /F >nul

%PS% -Command ^
 "$s=(New-Object -ComObject WScript.Shell).CreateShortcut([Environment]::GetFolderPath('CommonDesktopDirectory')+'\Fix my PC.lnk');" ^
 "$s.TargetPath='powershell.exe';" ^
 "$s.Arguments='-NoProfile -ExecutionPolicy Bypass -File \"%DST%\networkdoctor-agent.ps1\" -Mode fix';" ^
 "$s.IconLocation='shell32.dll,222';$s.Description='Clean and speed up this PC';$s.Save()"

echo Agent installed. A "Fix my PC" button is on the Desktop; the background watch starts at the next logon.
echo Starting the background watch now...
start "" /min powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "%DST%\networkdoctor-agent.ps1" -Mode background
pause
