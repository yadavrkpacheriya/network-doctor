@echo off
REM Puts a "Clean my PC" shortcut on every user's Desktop, pointing at the one-click cleaner.
setlocal
set DST=%ProgramData%\NetworkDoctor
if not exist "%DST%" mkdir "%DST%"
copy /Y "%~dp0pc-speedup.ps1" "%DST%\pc-speedup.ps1" >nul
set PS=powershell -NoProfile -ExecutionPolicy Bypass
%PS% -Command ^
 "$s=(New-Object -ComObject WScript.Shell).CreateShortcut([Environment]::GetFolderPath('CommonDesktopDirectory')+'\Clean my PC.lnk');" ^
 "$s.TargetPath='powershell.exe';" ^
 "$s.Arguments='-NoProfile -ExecutionPolicy Bypass -File \"%DST%\pc-speedup.ps1\"';" ^
 "$s.IconLocation='shell32.dll,32';$s.Description='Clean junk and speed up this PC';$s.Save()"
echo A "Clean my PC" shortcut has been placed on the Desktop.
pause
