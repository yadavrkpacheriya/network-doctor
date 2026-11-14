# Network Doctor - LeakWatch endpoint agent
# Runs quietly on each office PC and reports the things the office network cannot see:
#   - a USB pen drive / phone / external disk plugged in or removed
#   - a file copied, created or renamed ON such a removable drive (a file leaving by USB)
# It writes one CSV line per event to a shared folder on the IT PC (and a local copy as a fallback).
# It reads nothing else, opens no file's contents, and sends nothing to the internet.
#
# Set these two lines, then install with install-leakwatch.cmd:
$Central = "\\RAKESH-IT\LeakLog"          # shared folder on the IT PC (read by Network Doctor). "" = local only.
$MinCopyKB = 1                            # ignore copies smaller than this (KB)

$ErrorActionPreference = "SilentlyContinue"
$pc   = $env:COMPUTERNAME
$user = $env:USERNAME
$local = Join-Path $env:ProgramData "NetworkDoctor\leakwatch"
New-Item -ItemType Directory -Force -Path $local | Out-Null

function Write-Event($event, $detail, $drive, $sizeKB) {
    $row = [pscustomobject]@{
        time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); pc = $pc; user = $user
        event = $event; detail = $detail; drive = $drive; size_kb = [int]$sizeKB
    }
    $line = ($row.time, $row.pc, $row.user, $row.event,
             ('"' + ($detail -replace '"','""') + '"'), $drive, $row.size_kb) -join ","
    $name = "leak-$pc-$(Get-Date -f yyyyMM).csv"
    foreach ($dir in @($local, $Central)) {
        if (-not $dir) { continue }
        $path = Join-Path $dir $name
        if (-not (Test-Path $path)) {
            "time,pc,user,event,detail,drive,size_kb" | Out-File -FilePath $path -Encoding utf8 -Append
        }
        $line | Out-File -FilePath $path -Encoding utf8 -Append
    }
}

function Removable-Drives {
    Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2" | ForEach-Object { $_.DeviceID }
}

Write-Event "AGENT_START" "LeakWatch started" "" 0

# ---- watch every removable drive for files written to it ----
$watchers = @{}
function Add-Watcher($drive) {
    if ($watchers.ContainsKey($drive)) { return }
    $w = New-Object IO.FileSystemWatcher ($drive + "\"), "*.*"
    $w.IncludeSubdirectories = $true
    $w.EnableRaisingEvents = $true
    $action = {
        $p = $Event.SourceEventArgs.FullPath
        Start-Sleep -Milliseconds 400
        $kb = 0; try { $kb = [math]::Round((Get-Item -LiteralPath $p).Length / 1KB) } catch {}
        if ($kb -ge $using:MinCopyKB) {
            Write-Event "COPY_TO_USB" $p ($p.Substring(0,2)) $kb
        }
    }
    Register-ObjectEvent $w Created -Action $action | Out-Null
    Register-ObjectEvent $w Renamed -Action $action | Out-Null
    $watchers[$drive] = $w
}

foreach ($d in Removable-Drives) { Add-Watcher $d; Write-Event "USB_PRESENT" "Drive $d already connected" $d 0 }

# ---- poll for drives appearing / disappearing (works without admin, unlike WMI volume events) ----
$known = @(Removable-Drives)
while ($true) {
    Start-Sleep -Seconds 3
    $now = @(Removable-Drives)
    foreach ($d in $now)  { if ($known -notcontains $d) { Write-Event "USB_IN"  "Removable drive connected" $d 0; Add-Watcher $d } }
    foreach ($d in $known){ if ($now   -notcontains $d) { Write-Event "USB_OUT" "Removable drive removed"   $d 0 } }
    $known = $now
}
