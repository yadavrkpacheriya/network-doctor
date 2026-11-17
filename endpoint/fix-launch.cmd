@echo off
setlocal EnableExtensions
title Fix my PC
set "ST=%ProgramData%\NetworkDoctor\fix-status.txt"
del "%ST%" >nul 2>&1
echo(
echo    Cleaning and optimising your PC... you can keep working.
echo    (A Windows repair, if needed, can take 15-30 minutes - that is normal.)
echo(
schtasks /Run /TN "NetworkDoctor Fix" >nul 2>&1
if errorlevel 1 (
    echo    Could not start. Please tell IT.
    echo(
    pause
    exit /b 1
)

set "LAST="
set /a tries=0
:loop
set "LINE="
if exist "%ST%" set /p LINE=<"%ST%"
if not "%LINE%"=="%LAST%" (
    for /f "tokens=1,2,3 delims=|" %%a in ("%LINE%") do (
        if /I "%%a"=="DONE"   ( echo    Done^!  Freed about %%b MB.  & goto done )
        if /I "%%a"=="FAILED" ( echo    Could not finish: %%b  -  please tell IT.  & goto done )
        if /I "%%a"=="RUNNING" ( echo       - %%b )
    )
    set "LAST=%LINE%"
)
set /a tries+=1
rem ~40 minutes max of waiting (480 x 5s), then let the user go - the task keeps running in the background
if %tries% GEQ 480 (
    echo(
    echo    Still working in the background ^(Windows repair takes a while^). It is safe to close this window.
    goto done
)
timeout /t 5 >nul 2>&1
goto loop

:done
echo(
pause
exit /b 0
