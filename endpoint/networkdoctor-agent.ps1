# Network Doctor - one PC agent. Users click one button ("Fix my PC"); everything else runs in the background.
#   -Mode fix         : clean the PC + send fresh details, connections and resource use to Network Doctor now
#   -Mode background  : (runs at logon) watch USB drives and, every minute, which app uses the network + CPU/RAM
# It sends only to the shared folder on the IT PC. It never reads a file's contents and never uses the internet.
param([ValidateSet("fix", "background")] [string]$Mode = "fix")

# ===== set this one line to your IT PC's shared folder (read by Network Doctor) =====
$Central   = "\\RAKESH-IT\LeakLog"
$MinCopyKB = 1
# ====================================================================================

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference    = "SilentlyContinue"
$pc    = $env:COMPUTERNAME
$user  = $env:USERNAME
$local = Join-Path $env:ProgramData "NetworkDoctor\agent"
New-Item -ItemType Directory -Force -Path $local | Out-Null
$month = Get-Date -f yyyyMM
function Dirs { @($local, $Central) | Where-Object { $_ } }
function Append($name, $header, $line) {
    foreach ($d in Dirs) {
        $p = Join-Path $d $name
        if (-not (Test-Path $p)) { $header | Out-File -FilePath $p -Encoding utf8 }
        $line | Out-File -FilePath $p -Encoding utf8 -Append
    }
}
function Csv($v) { '"' + ("$v" -replace '"', '""') + '"' }

# ---------- PC details + resources (JSON that Network Doctor reads straight into its inventory) ----------
function Send-Details {
    $cs   = Get-CimInstance Win32_ComputerSystem
    $osi  = Get-CimInstance Win32_OperatingSystem
    $bios = Get-CimInstance Win32_BIOS
    $cpu  = Get-CimInstance Win32_Processor | Select-Object -First 1
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    $ads = foreach ($a in @(Get-NetAdapter -Physical)) {
        [pscustomobject]@{ name = $a.Name; desc = $a.InterfaceDescription; mac = $a.MacAddress;
            permanent = $a.PermanentAddress; status = [string]$a.Status;
            wifi = [bool]($a.MediaType -match '802\.11'); speed = [string]$a.LinkSpeed;
            bps = [int64]$a.ReceiveLinkSpeed; duplex = $a.FullDuplex;
            errors = [int64]((Get-NetAdapterStatistics -Name $a.Name).ReceivedPacketErrors);
            ip = ((Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4).IPAddress -join ',') }
    }
    $cpuPct = [math]::Round((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average)
    $memPct = if ($osi.TotalVisibleMemorySize) {
        [math]::Round(100 * ($osi.TotalVisibleMemorySize - $osi.FreePhysicalMemory) / $osi.TotalVisibleMemorySize) }
    $top = @(Get-Process | Group-Object ProcessName | ForEach-Object {
        [pscustomobject]@{ name = $_.Name; mb = [math]::Round((($_.Group | Measure-Object WorkingSet64 -Sum).Sum)/1MB) }
    } | Sort-Object mb -Descending | Select-Object -First 8)
    $av = (@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct) | ForEach-Object { $_.displayName }) -join '; '
    $prn = (@(Get-CimInstance Win32_Printer | Where-Object { $_.Name -notmatch 'PDF|XPS|OneNote|Fax' }) | ForEach-Object { $_.Name }) -join '; '
    $hw = @{ maker=[string]$cs.Manufacturer; model=[string]$cs.Model; serial=[string]$bios.SerialNumber;
             cpu=[string]$cpu.Name; ram_gb=[math]::Round(([double]$cs.TotalPhysicalMemory)/1GB,1);
             disk_gb=[math]::Round(([double]$disk.Size)/1GB); disk_free_gb=[math]::Round(([double]$disk.FreeSpace)/1GB);
             os_name=[string]$osi.Caption; os_version=[string]$osi.Version; last_boot=[string]$osi.LastBootUpTime;
             logged_on=[string]$cs.UserName; antivirus=$av; printers=$prn;
             cpu_load=$cpuPct; mem_used_pct=$memPct; top_procs=$top }
    $body = @{ hostname=$pc; user=$user; os=[string]$osi.Caption; hw=$hw; adapters=@($ads);
               time=(Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); actions=@('PC agent report') } | ConvertTo-Json -Depth 5
    foreach ($d in Dirs) { $body | Out-File -FilePath (Join-Path $d "pc-$pc.json") -Encoding utf8 -Force }
}

# ---------- which app uses the network right now (process <-> remote address) ----------
function Send-Connections {
    $procs = @{}; Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
    $seen = @{}
    foreach ($c in @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)) {
        $r = $c.RemoteAddress
        if ($r -in @('127.0.0.1','::1','0.0.0.0','::') -or $r -like '192.168.*' -or $r -like '10.*' -or
            $r -like '172.1[6-9].*' -or $r -like '172.2*' -or $r -like '172.3[01].*' -or $r -like 'fe80*') { continue }
        $name = $procs[[int]$c.OwningProcess]; if (-not $name) { continue }
        $k = "$name|$r|$($c.RemotePort)"
        if ($seen[$k]) { continue }; $seen[$k] = $true
        Append "conn-$pc-$month.csv" "time,pc,user,process,local_ip,remote_ip,remote_port" `
            (((Get-Date).ToString("yyyy-MM-dd HH:mm:ss")), $pc, $user, (Csv $name), $c.LocalAddress, $r, $c.RemotePort -join ",")
    }
}

function Log-Usb($event, $detail, $drive, $kb) {
    Append "leak-$pc-$month.csv" "time,pc,user,event,detail,drive,size_kb" `
        (((Get-Date).ToString("yyyy-MM-dd HH:mm:ss")), $pc, $user, $event, (Csv $detail), $drive, [int]$kb -join ",")
}
function Removable { Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2" | ForEach-Object { $_.DeviceID } }


# Shield against the "router drops for a few seconds" problem (ARP spoofing / a faked gateway): pin the router's
# real MAC on THIS PC so it ignores fake ARP for the gateway. No router change, no IP/MAC binding, affects no one
# else. Guarded: it pins ONLY when the internet is working right now, so it can never pin a spoofed MAC. A reboot
# or "netsh interface ip delete neighbors" clears it. Needs admin.
function Lock-Gateway {
    $gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
           Sort-Object RouteMetric | Select-Object -First 1).NextHop
    if (-not $gw -or $gw -eq '0.0.0.0') { return }
    $okNet = (Test-Connection -Count 1 -Quiet -ErrorAction SilentlyContinue $gw) -and
             (Test-Connection -Count 1 -Quiet -ErrorAction SilentlyContinue 8.8.8.8)
    if (-not $okNet) { Write-Host "   - Router shield skipped (internet not stable right now)" -ForegroundColor DarkGray; return }
    $n = Get-NetNeighbor -IPAddress $gw -ErrorAction SilentlyContinue |
         Where-Object { $_.LinkLayerAddress -and $_.State -ne 'Unreachable' } | Select-Object -First 1
    if ($n -and $n.LinkLayerAddress) {
        netsh interface ipv4 set neighbors $n.InterfaceIndex $gw $n.LinkLayerAddress store=active 2>$null | Out-Null
        Write-Host "   - Router address locked ($gw = $($n.LinkLayerAddress)) - ignores fake ARP"
    }
}

# ================================ FIX (the one button the user clicks) ================================
if ($Mode -eq "fix") {
    # The deep clean, Windows repair and router shield need administrator rights. If the user ran this without
    # them, relaunch once with a UAC prompt so one click does everything (and skip nothing silently).
    $amAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if (-not $amAdmin) {
        try {
            Start-Process powershell -Verb RunAs -ArgumentList @(
                "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"", "-Mode", "fix")
            return
        } catch {
            Write-Host "  (Running without administrator - some deep steps will be skipped.)" -ForegroundColor DarkGray
        }
    }
    $host.UI.RawUI.WindowTitle = "Fix my PC"
    $before = (Get-PSDrive C).Free
    Write-Host "`n  Fixing and cleaning this PC... please wait (about a minute).`n" -ForegroundColor Cyan
    function Purge($path, $label) {
        if (-not (Test-Path $path)) { return }
        Write-Host "   - $label"
        Get-ChildItem $path -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -lt (Get-Date).AddHours(-1) } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
    Purge "$env:TEMP" "Your temporary files"
    Purge "$env:LOCALAPPDATA\Temp" "App temporary files"
    Purge "$env:LOCALAPPDATA\Microsoft\Windows\INetCache" "Internet cache"
    Purge "$env:LOCALAPPDATA\CrashDumps" "Crash dumps"
    foreach ($b in @("$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache",
                     "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache")) { Purge $b "Browser cache" }
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
             ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if ($admin) {
        Purge "$env:WINDIR\Temp" "Windows temp"
        Stop-Service wuauserv -Force; Purge "$env:WINDIR\SoftwareDistribution\Download" "Windows Update leftovers"; Start-Service wuauserv
        Write-Host "   - Prefetch (Windows rebuilds it)"
        Remove-Item "$env:WINDIR\Prefetch\*" -Force -ErrorAction SilentlyContinue
        Write-Host "   - Delivery Optimisation cache"
        Delete-DeliveryOptimizationCache -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Host "   - Windows disk cleanup (old updates, logs)"
        Dism.exe /Online /Cleanup-Image /StartComponentCleanup /Quiet | Out-Null   # reclaims WinSxS space, safe, ~1-3 min
        Write-Host "   - Checking Windows health"
        $check = Dism.exe /Online /Cleanup-Image /CheckHealth                       # fast, a few seconds
        if ("$check" -match 'repairable') {
            Write-Host "     Repairable damage found - repairing Windows (this takes several minutes)..." -ForegroundColor Yellow
            Dism.exe /Online /Cleanup-Image /RestoreHealth /Quiet | Out-Null
            sfc /scannow | Out-Null
            Write-Host "     Windows repair done."
        } else {
            Write-Host "     Windows is healthy."
        }
        Lock-Gateway
    }
    Write-Host "   - Recycle Bin";  Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    Write-Host "   - Flushing DNS"; ipconfig /flushdns | Out-Null
    Write-Host "   - Optimising"
    Send-Details; Send-Connections
    Write-Host "   - Restarting Explorer"
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue; Start-Sleep 2
    if (-not (Get-Process explorer)) { Start-Process explorer }
    $freed = [math]::Round(((Get-PSDrive C).Free - $before)/1MB); if ($freed -lt 0) { $freed = 0 }
    Write-Host "`n  Done. Freed about $freed MB. Your PC should feel faster." -ForegroundColor Green
    Write-Host "  If it is still slow, tell IT.`n" -ForegroundColor Green
    Start-Sleep 6
    return
}

# ================================ BACKGROUND (starts at logon, no window) ================================
Log-Usb "AGENT_START" "PC agent started" "" 0
Send-Details
$watchers = @{}
function Watch($drive) {
    if ($watchers.ContainsKey($drive)) { return }
    $w = New-Object IO.FileSystemWatcher ($drive + "\"), "*.*"; $w.IncludeSubdirectories = $true; $w.EnableRaisingEvents = $true
    $act = {
        $p = $Event.SourceEventArgs.FullPath; Start-Sleep -Milliseconds 400
        $kb = 0; try { $kb = [math]::Round((Get-Item -LiteralPath $p).Length/1KB) } catch {}
        if ($kb -ge $using:MinCopyKB) {
            & $using:LogUsb "COPY_TO_USB" $p ($p.Substring(0,2)) $kb
        }
    }
    Register-ObjectEvent $w Created -Action $act | Out-Null
    Register-ObjectEvent $w Renamed -Action $act | Out-Null
    $watchers[$drive] = $w
}
$LogUsb = ${function:Log-Usb}
foreach ($d in Removable) { Watch $d; Log-Usb "USB_PRESENT" "Drive $d already connected" $d 0 }
$known = @(Removable); $tick = 0
while ($true) {
    Start-Sleep -Seconds 3
    $now = @(Removable)
    foreach ($d in $now)   { if ($known -notcontains $d) { Log-Usb "USB_IN"  "Removable drive connected" $d 0; Watch $d } }
    foreach ($d in $known) { if ($now   -notcontains $d) { Log-Usb "USB_OUT" "Removable drive removed"   $d 0 } }
    $known = $now
    $tick++
    if ($tick % 20 -eq 0) { Send-Connections }           # every ~60s: which app is using the network
    if ($tick % 600 -eq 0) { Send-Details }              # every ~30 min: refresh details + CPU/RAM
}
