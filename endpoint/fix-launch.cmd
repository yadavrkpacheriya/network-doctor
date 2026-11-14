@echo off
title Fix my PC
echo.
echo    Cleaning and optimising your PC...
echo    You can keep working - a message pops up when it is done.
echo.
schtasks /Run /TN "NetworkDoctor Fix" >nul 2>&1
if errorlevel 1 (echo    Could not start. Please tell IT.) else (echo    Started.)
timeout /t 6 >nul
