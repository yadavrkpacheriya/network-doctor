@echo off
REM Network Doctor - install the PC agent (run as administrator, ONCE per PC).
REM After this, any user can double-click "Fix my PC" and it runs with full rights - no password, no prompt.
setlocal
set DST=%ProgramData%\NetworkDoctor
if not exist "%DST%" mkdir "%DST%"
copy /Y "%~dp0networkdoctor-agent.ps1" "%DST%\networkdoctor-agent.ps1" >nul
copy /Y "%~dp0fix-launch.cmd"          "%DST%\fix-launch.cmd"          >nul
set PSF=-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "%DST%\networkdoctor-agent.ps1"

REM Background watch (USB + which app uses the network), as SYSTEM so it has full rights for every user.
schtasks /Create /TN "NetworkDoctor Agent" /TR "powershell %PSF% -Mode background" /SC ONLOGON /RU SYSTEM /RL HIGHEST /F >nul

REM The "Fix my PC" job: runs as SYSTEM (elevated, no password). Triggered on demand by the Desktop button.
schtasks /Create /TN "NetworkDoctor Fix" /TR "powershell %PSF% -Mode fix" /SC ONCE /ST 00:00 /RU SYSTEM /RL HIGHEST /F >nul

REM Let ordinary users start the Fix job (read + execute), while only admins/SYSTEM can change it.
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
 "$s=New-Object -ComObject Schedule.Service;$s.Connect();$t=$s.GetFolder('\').GetTask('NetworkDoctor Fix');" ^
 "$t.SetSecurityDescriptor('D:(A;;GA;;;BA)(A;;GA;;;SY)(A;;GRGX;;;AU)',0)" >nul 2>&1

REM One Desktop button for everyone.
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
 "$s=(New-Object -ComObject WScript.Shell).CreateShortcut([Environment]::GetFolderPath('CommonDesktopDirectory')+'\Fix my PC.lnk');" ^
 "$s.TargetPath='%DST%\fix-launch.cmd';$s.IconLocation='shell32.dll,222';$s.WindowStyle=7;" ^
 "$s.Description='Clean and speed up this PC';$s.Save()" >nul 2>&1

echo Done. "Fix my PC" is on the Desktop - any user can run it with full rights, no password.
echo Starting the background watch now...
start "" /min powershell %PSF% -Mode background
pause
