# Builds NetworkDoctor-Store.msix for the Microsoft Store (run from desktop/ on Windows after the store exe is built).
#   dist-store\NetworkDoctor.exe  : the exe built WITHOUT --uac-admin (Store apps start as a normal user)
param([string]$Version)
$ErrorActionPreference = 'Stop'
$v = ($Version.Split('.') + @('0', '0', '0'))[0..2] -join '.'
$layout = 'msix-layout'
Remove-Item -Recurse -Force $layout -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force "$layout\Assets" | Out-Null
Copy-Item dist-store\NetworkDoctor.exe $layout\
python store\make_assets.py "$layout\Assets"
Remove-Item "$layout\Assets\NetworkDoctor.ico", "$layout\Assets\AppIcon.png" -ErrorAction SilentlyContinue
(Get-Content store\AppxManifest.xml -Raw).Replace('__VERSION__', "$v.0") | Set-Content -Encoding UTF8 "$layout\AppxManifest.xml"
$makeappx = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter makeappx.exe |
    Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $makeappx) { Write-Error "makeappx.exe not found (Windows SDK)" }
& $makeappx.FullName pack /o /d $layout /p dist\NetworkDoctor-Store.msix
if ($LASTEXITCODE -ne 0) { Write-Error "makeappx failed" }
Write-Host "Built dist\NetworkDoctor-Store.msix version $v.0"
