@echo off
REM Network Doctor - install LeakWatch on this PC (run as administrator).
REM Registers a hidden scheduled task that starts the agent at every logon and keeps it running.
setlocal
set DST=%ProgramData%\NetworkDoctor
if not exist "%DST%" mkdir "%DST%"
copy /Y "%~dp0leakwatch-agent.ps1" "%DST%\leakwatch-agent.ps1" >nul

schtasks /Create /TN "NetworkDoctor LeakWatch" /TR ^
 "powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \"%DST%\leakwatch-agent.ps1\"" ^
 /SC ONLOGON /RL HIGHEST /F >nul
if %errorlevel%==0 (echo LeakWatch installed. It starts at the next logon.) else (echo Install failed - run this file as administrator.)

echo Starting it now...
start "" /min powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "%DST%\leakwatch-agent.ps1"
echo Done.
pause
