# Network Doctor - one PC agent. Users click one button ("Fix my PC"); everything else runs in the background.
#   -Mode fix         : clean the PC + send fresh details, connections and resource use to Network Doctor now
#   -Mode background  : (runs at logon) watch USB drives and, every minute, which app uses the network + CPU/RAM
# It sends only to the shared folder on the IT PC. It never reads a file's contents and never uses the internet.
param([ValidateSet("fix", "background")] [string]$Mode = "fix")

$AgentVersion = "1.1.0"    # the publisher bumps this; every PC silently self-updates to the newest in the share

# ===== IT PC's shared folder (read by Network Doctor). Set once at install in central.txt; the line below is
#       only the fallback when that file is missing, so a self-update never resets your real share. =====
$cfgFile   = Join-Path $env:ProgramData "NetworkDoctor\central.txt"
$Central   = "\\RAKESH-IT\LeakLog"
try { if (Test-Path $cfgFile) { $c = (Get-Content -LiteralPath $cfgFile -TotalCount 1).Trim(); if ($c) { $Central = $c } } } catch {}
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

# Is someone guessing this PC's password? Reads the Security log for failed logons (Event ID 4625) in the last
# few minutes and reports them grouped by account + where they came from (source IP / computer). Network Doctor
# raises a brute-force alert when the tries pile up. Reading the Security log needs admin - the agent runs as
# SYSTEM, so it can. $mins is the look-back; the background loop calls it on the same cadence so nothing is missed.
function Send-Auth($mins = 6) {
    $since = (Get-Date).AddMinutes(-$mins)
    $ev = @(Get-WinEvent -FilterHashtable @{LogName = 'Security'; Id = 4625; StartTime = $since} `
            -MaxEvents 1000 -ErrorAction SilentlyContinue)
    if (-not $ev) { return }
    $agg = @{}
    foreach ($e in $ev) {
        $d = @{}
        try { foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $d[$n.Name] = [string]$n.'#text' } } catch { continue }
        $acct = $d['TargetUserName']; if (-not $acct) { $acct = '?' }
        $ip = $d['IpAddress']; $host2 = $d['WorkstationName']
        $from = if ($ip -and $ip -notin @('-', '::1', '127.0.0.1')) { $ip } elseif ($host2) { $host2 } else { 'this PC / console' }
        $lt = $d['LogonType']   # 10 = RDP (remote desktop), 3 = network share, 2 = at the keyboard
        $kind = switch ($lt) { '10' { 'RDP' } '3' { 'network' } '2' { 'console' } default { "type $lt" } }
        $key = "$acct|$from|$kind"
        if (-not $agg[$key]) { $agg[$key] = 0 }
        $agg[$key]++
    }
    foreach ($k in $agg.Keys) {
        $p = $k -split '\|'
        Append "auth-$pc-$month.csv" "time,pc,account,source,logon,fails" `
            (((Get-Date).ToString("yyyy-MM-dd HH:mm:ss")), $pc, (Csv $p[0]), (Csv $p[1]), $p[2], $agg[$k] -join ",")
    }
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
    if (-not (Test-Connection -Count 1 -Quiet -ErrorAction SilentlyContinue $gw)) { return }
    # internet check: ICMP to 8.8.8.8 is blocked on many office networks, so fall back to a quick TCP test.
    $okNet = (Test-Connection -Count 1 -Quiet -ErrorAction SilentlyContinue 8.8.8.8)
    if (-not $okNet) {
        foreach ($hp in @(@('8.8.8.8', 53), @('1.1.1.1', 443), @('8.8.4.4', 443))) {
            try { $c = New-Object Net.Sockets.TcpClient; $a = $c.BeginConnect($hp[0], $hp[1], $null, $null)
                  if ($a.AsyncWaitHandle.WaitOne(1200) -and $c.Connected) { $okNet = $true; $c.Close(); break }
                  $c.Close() } catch {}
        }
    }
    if (-not $okNet) { Write-Host "   - Router shield skipped (internet not reachable right now)" -ForegroundColor DarkGray; return }
    $n = Get-NetNeighbor -IPAddress $gw -ErrorAction SilentlyContinue |
         Where-Object { $_.LinkLayerAddress -and $_.State -ne 'Unreachable' } | Select-Object -First 1
    if ($n -and $n.LinkLayerAddress) {
        netsh interface ipv4 set neighbors $n.InterfaceIndex $gw $n.LinkLayerAddress store=active 2>$null | Out-Null
        Write-Host "   - Router address locked ($gw = $($n.LinkLayerAddress)) - ignores fake ARP"
    }
}

# ================================ FIX (the one button the user clicks) ================================
if ($Mode -eq "fix") {
    $me = [Security.Principal.WindowsIdentity]::GetCurrent()
    $amAdmin = ([Security.Principal.WindowsPrincipal]$me).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    $asSystem = $me.IsSystem        # launched by the scheduled task: full rights, no password, runs hidden
    # If a person ran this directly without rights (not through the "Fix my PC" task), lift it once.
    if (-not $amAdmin -and -not $asSystem) {
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
    # --- status file: the one reliable signal. Written as SYSTEM, read by fix-launch.cmd in the user's
    #     session - so "Fix my PC" shows live progress and the result WITHOUT depending on msg.exe (which is
    #     missing on Windows Home) or on a visible window (the task runs hidden). "done" vs "stuck" is never
    #     a guess again: the file says exactly which step is running, or DONE / FAILED.
    $StatusDir = Join-Path $env:ProgramData "NetworkDoctor"
    try { if (-not (Test-Path $StatusDir)) { New-Item -ItemType Directory -Path $StatusDir -Force | Out-Null } } catch {}
    $StatusFile = Join-Path $StatusDir "fix-status.txt"
    function Set-Status($line) { try { Set-Content -LiteralPath $StatusFile -Value $line -Encoding ASCII -ErrorAction SilentlyContinue } catch {} }
    Set-Status "RUNNING|starting"
    Write-Host "`n  Fixing and cleaning this PC... please wait.`n" -ForegroundColor Cyan
    function Purge($path, $label) {
        if (-not (Test-Path $path)) { return }
        Write-Host "   - $label"; Set-Status "RUNNING|$label"
        Get-ChildItem $path -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -lt (Get-Date).AddHours(-1) } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
    try {
        # Clean every user's junk (works whether started as SYSTEM by the task, or by an admin). Never real files.
        Purge "C:\Users\*\AppData\Local\Temp" "Temporary files"
        Purge "C:\Users\*\AppData\Local\Microsoft\Windows\INetCache" "Internet cache"
        Purge "C:\Users\*\AppData\Local\CrashDumps" "Crash dumps"
        Purge "C:\Users\*\AppData\Local\Google\Chrome\User Data\*\Cache" "Chrome cache"
        Purge "C:\Users\*\AppData\Local\Microsoft\Edge\User Data\*\Cache" "Edge cache"
        Purge "$env:WINDIR\Temp" "Windows temp"
        Set-Status "RUNNING|Windows Update leftovers"
        Stop-Service wuauserv -Force; Purge "$env:WINDIR\SoftwareDistribution\Download" "Windows Update leftovers"; Start-Service wuauserv
        Write-Host "   - Prefetch (Windows rebuilds it)"; Set-Status "RUNNING|Prefetch"
        Remove-Item "$env:WINDIR\Prefetch\*" -Force -ErrorAction SilentlyContinue
        Delete-DeliveryOptimizationCache -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Host "   - Windows disk cleanup (old updates, logs)"; Set-Status "RUNNING|Windows disk cleanup"
        Dism.exe /Online /Cleanup-Image /StartComponentCleanup /Quiet | Out-Null   # reclaims WinSxS space, safe
        Write-Host "   - Checking Windows health"; Set-Status "RUNNING|Checking Windows health"
        if ("$(Dism.exe /Online /Cleanup-Image /CheckHealth)" -match 'repairable') {
            Write-Host "     Repairable damage found - repairing Windows (several minutes)..." -ForegroundColor Yellow
            Set-Status "RUNNING|Repairing Windows (this can take 15-30 min)"
            Dism.exe /Online /Cleanup-Image /RestoreHealth /Quiet | Out-Null
            sfc /scannow | Out-Null
            Write-Host "     Windows repair done."
        } else { Write-Host "     Windows is healthy." }
        Lock-Gateway                                                               # router-drop shield (needs rights)
        Write-Host "   - Recycle Bin"; Set-Status "RUNNING|Emptying Recycle Bin"; Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        Write-Host "   - Flushing DNS"; Set-Status "RUNNING|Flushing DNS"; ipconfig /flushdns | Out-Null
        Write-Host "   - Updating details"; Set-Status "RUNNING|Updating details"; Send-Details; Send-Connections
        if (-not $asSystem) {                                                      # restarting Explorer only makes
            Write-Host "   - Restarting Explorer"                                  # sense in the user's own session
            Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue; Start-Sleep 2
            if (-not (Get-Process explorer -ErrorAction SilentlyContinue)) { Start-Process explorer }
        }
        $freed = [math]::Round(((Get-PSDrive C).Free - $before)/1MB); if ($freed -lt 0) { $freed = 0 }
        $msg = "PC cleaned and optimised. Freed about $freed MB. If it is still slow, tell IT."
        Write-Host "`n  $msg`n" -ForegroundColor Green
        Set-Status "DONE|$freed|$(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        if ($asSystem) { try { & msg.exe * /TIME:30 $msg } catch {} }             # bonus popup where msg.exe exists
    } catch {
        Set-Status "FAILED|$($_.Exception.Message)"
        Write-Host "  Problem while fixing: $($_.Exception.Message)" -ForegroundColor Red
    }
    Start-Sleep 4
    return
}

# ================================ SELF-UPDATE (silent, from the IT share - no internet, no per-PC reinstall) ===
$DST = Split-Path $local    # %ProgramData%\NetworkDoctor  (where the installed agent + launcher live)
function Update-Self {
    # Pull a newer agent that Network Doctor published to <share>\agent-dist\. Returns $true if it updated the
    # local files (the caller then relaunches so the new code runs). Never throws - an update must never break
    # the agent that is already working.
    try {
        $dist = Join-Path $Central "agent-dist"
        $verFile = Join-Path $dist "version.txt"
        if (-not (Test-Path $verFile)) { return $false }
        $remote = (Get-Content -LiteralPath $verFile -TotalCount 1).Trim()
        if (-not $remote) { return $false }
        if ([version]$remote -le [version]$AgentVersion) { return $false }
        $src = Join-Path $dist "networkdoctor-agent.ps1"
        if (-not (Test-Path $src)) { return $false }
        Copy-Item -LiteralPath $src -Destination (Join-Path $DST "networkdoctor-agent.ps1") -Force
        $fl = Join-Path $dist "fix-launch.cmd"
        if (Test-Path $fl) { Copy-Item -LiteralPath $fl -Destination (Join-Path $DST "fix-launch.cmd") -Force }
        return $true
    } catch { return $false }
}

# ================================ BACKGROUND (starts at logon, no window) ================================
# One background instance only. A self-update relaunches a fresh copy; this mutex stops duplicates stacking up.
$mtx = New-Object System.Threading.Mutex($false, "Global\NetworkDoctorAgentBG")
if (-not $mtx.WaitOne(0)) { exit }
if (Update-Self) {
    $mtx.ReleaseMutex()
    Start-Process powershell -ArgumentList '-NoProfile','-WindowStyle','Hidden','-ExecutionPolicy','Bypass','-File',(Join-Path $DST 'networkdoctor-agent.ps1'),'-Mode','background'
    exit
}
Log-Usb "AGENT_START" "PC agent v$AgentVersion started" "" 0
Send-Details
Lock-Gateway        # shield the router's address at every logon (background runs as SYSTEM, so it has the rights)
Send-Auth 60        # catch password-guessing that happened in the last hour before the agent started
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
    if ($tick % 100 -eq 0) { Send-Auth 6 }               # every ~5 min: failed-login (brute-force) check
    if ($tick % 600 -eq 0) {                               # every ~30 min: refresh details, re-pin router, self-update
        Send-Details; Lock-Gateway
        if (Update-Self) {
            $mtx.ReleaseMutex()
            Start-Process powershell -ArgumentList '-NoProfile','-WindowStyle','Hidden','-ExecutionPolicy','Bypass','-File',(Join-Path $DST 'networkdoctor-agent.ps1'),'-Mode','background'
            exit
        }
    }
}
