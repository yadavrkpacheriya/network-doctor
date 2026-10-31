@echo off
title Build NetworkDoctor.exe
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo Python is not installed on this PC.
  echo Install it from https://www.python.org/downloads/  ^(tick "Add python.exe to PATH"^)
  echo and run this file again. Python is only needed to BUILD the exe, not to use it.
  pause
  exit /b
)
echo Installing the build tool...
python -m pip install --upgrade pyinstaller
echo.
set /p deep="Include deep packet tests (Scapy)? Npcap must also be installed on PCs that use them. [y/N]: "
set EXTRA=
if /i "%deep%"=="y" (
  python -m pip install scapy
  set EXTRA=--collect-all scapy
)
echo.
if not exist nd_core.py (echo nd_core.py is missing - put all 3 .py files in this folder & pause & exit /b)
if not exist nd_monitor.py (echo nd_monitor.py is missing - put all 3 .py files in this folder & pause & exit /b)
echo Building NetworkDoctor.exe ...
python -m PyInstaller --noconfirm --onefile --windowed --uac-admin --name NetworkDoctor --hidden-import nd_core --hidden-import nd_monitor --hidden-import nd_update --hidden-import nd_tools --hidden-import nd_tabs --hidden-import nd_net --hidden-import nd_toolstab --hidden-import nd_snmp --hidden-import nd_plugins --hidden-import nd_linux --hidden-import nd_dnsfilter --hidden-import nd_routeros --hidden-import nd_usage --hidden-import nd_home %EXTRA% NetworkDoctor.py
if exist dist\NetworkDoctor.exe (
  copy /y dist\NetworkDoctor.exe . >nul
  rmdir /s /q build >nul 2>nul
  del NetworkDoctor.spec >nul 2>nul
  echo.
  echo  DONE:  %~dp0NetworkDoctor.exe
  echo  Copy this single file to any office PC and double-click it.
) else (
  echo Build failed - see the messages above.
)
pause
