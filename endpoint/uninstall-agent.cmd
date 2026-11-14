@echo off
schtasks /End /TN "NetworkDoctor Agent" >nul 2>&1
schtasks /Delete /TN "NetworkDoctor Agent" /F >nul 2>&1
del "%PUBLIC%\Desktop\Fix my PC.lnk" >nul 2>&1
echo Network Doctor agent removed. Collected logs are kept.
pause
