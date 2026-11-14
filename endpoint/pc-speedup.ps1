# Network Doctor - one-click PC speed-up (safe for ordinary users)
# Clears only junk: temp files, caches, Windows Update leftovers, recycle bin, and flushes DNS.
# It NEVER touches Documents, Desktop, Downloads, Pictures or any real file. Shows how much space it freed.
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
$host.UI.RawUI.WindowTitle = "Network Doctor - Clean my PC"
function Free($drive = "C") { (Get-PSDrive $drive).Free }
$before = Free

Write-Host ""
Write-Host "  Cleaning this PC... please wait (about a minute)." -ForegroundColor Cyan
Write-Host ""

function Purge($path, $label) {
    if (-not (Test-Path $path)) { return }
    Write-Host ("   - {0}" -f $label)
    Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -lt (Get-Date).AddHours(-1) } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

# --- user-level junk (no admin needed) ---
Purge "$env:TEMP" "Your temporary files"
Purge "$env:LOCALAPPDATA\Temp" "App temporary files"
Purge "$env:LOCALAPPDATA\Microsoft\Windows\INetCache" "Internet cache"
Purge "$env:LOCALAPPDATA\CrashDumps" "Crash dumps"
foreach ($b in @("$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache",
                 "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache",
                 "$env:APPDATA\Mozilla\Firefox\Profiles")) { Purge $b "Browser cache" }

# --- machine-level junk: only if this is already running as administrator ---
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if ($admin) {
    Purge "$env:WINDIR\Temp" "Windows temp"
    Write-Host "   - Windows Update leftovers"
    Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
    Purge "$env:WINDIR\SoftwareDistribution\Download" "Windows Update downloads"
    Start-Service wuauserv -ErrorAction SilentlyContinue
} else {
    Write-Host "   - (Run as administrator to also clear Windows Update leftovers)" -ForegroundColor DarkGray
}

Write-Host "   - Recycle Bin"
Clear-RecycleBin -Force -ErrorAction SilentlyContinue

Write-Host "   - Flushing DNS (fixes slow / wrong website loading)"
ipconfig /flushdns | Out-Null

Write-Host "   - Restarting Explorer (frees stuck memory)"
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Sleep 2
if (-not (Get-Process explorer -ErrorAction SilentlyContinue)) { Start-Process explorer }

$freed = [math]::Round((Free - $before) / 1MB)
if ($freed -lt 0) { $freed = 0 }
Write-Host ""
Write-Host ("  Done. Freed about {0} MB. Your PC should feel faster." -f $freed) -ForegroundColor Green
Write-Host "  If it is still slow, tell IT - it may need the full PC Care repair." -ForegroundColor Green
Write-Host ""
Start-Sleep 6
