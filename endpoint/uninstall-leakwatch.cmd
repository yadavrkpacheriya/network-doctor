@echo off
schtasks /End /TN "NetworkDoctor LeakWatch" >nul 2>&1
schtasks /Delete /TN "NetworkDoctor LeakWatch" /F >nul 2>&1
taskkill /F /FI "WINDOWTITLE eq leakwatch-agent*" >nul 2>&1
echo LeakWatch removed. The logs already collected are kept.
pause
