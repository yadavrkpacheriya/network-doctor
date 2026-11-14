# -*- coding: utf-8 -*-
"""
Network Doctor - PC Care engine (the PowerShell script nd_pccare.py runs on Windows).
Kept as text inside a module so the exe build and the source updater ship it like any other module.
The rules of the page are in nd_pccare.py; this file is only the script.
"""

ENGINE = r'''# Network Doctor - PC Care engine (Windows PowerShell 5.1). Started by nd_pccare.py; needs Administrator.
# One action per run:  -Choice A|1|2|3|4|5|6|7|8|8.1|9.2|10 . Never asks questions; prints tagged lines (@@colour@@text).
param([string]$Choice = '', [int]$OptStartup = 1, [int]$OptWinget = 0)
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$Ui = @{ Headless = $true; OptStartup = [bool]$OptStartup; OptWinget = [bool]$OptWinget }
try { [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false } catch {}
function Write-Host {
    param($Object, $ForegroundColor, $BackgroundColor, [switch]$NoNewline)
    foreach ($ln in ("$Object" -split "`r?`n")) { [Console]::Out.WriteLine("@@$ForegroundColor@@$ln") }
    [Console]::Out.Flush()
}
function Read-Host { param($Prompt, [switch]$AsSecureString) return '' }
function Out-Host { $t = ($input | Out-String).TrimEnd(); if ($t) { foreach ($ln in ($t -split "`r?`n")) { Write-Host $ln } } }
function Ask-Ui($kind, $prompt, $default) { return '' }

# ===================== SETTINGS (edit here) =====================
$removeUsers      = @()     # account names for 'remove user accounts' (not offered in Network Doctor yet)
$BackupRoot       = ''      # '' = auto (prefers an NTFS drive other than C: with the most free space). Or e.g. 'D:\PCCare_Backup'
$BackupCaches     = $false  # $false = leave browser/temp caches out of user backups
$DoUpdates        = $true   # menu 5: install Windows + driver updates
$DeepRepair       = $false  # menu 2: $true = always run DISM RestoreHealth + sfc + chkdsk (adds 30-60 min)
$PrinterCompatFix = $false  # menu 7: $true = registry fixes for printer errors 0x0000011b / 0x00000709 (relaxes print security; trusted LAN only)
$ResetNetwork     = $false  # menu 6: $true = always reset Winsock (otherwise only when a fault is detected)
$FullNetReset     = $false  # menu 6: $true = also reset TCP/IP (WIPES STATIC IP ADDRESSES - note them first)
$DupMinMB         = 1       # menu 9: ignore files smaller than this when looking for duplicates
# ================================================================

$desk      = [Environment]::GetFolderPath('Desktop')
$rep       = "$desk\PCCare_Reports"
New-Item $rep -ItemType Directory -Force | Out-Null
if (-not $Ui) { Start-Transcript -Path "$rep\fastclean_log.txt" -Force | Out-Null }
$me        = $env:USERNAME
$sysLetter = $env:SystemDrive.Substring(0,1)
$total     = [Diagnostics.Stopwatch]::StartNew()
$free0     = [math]::Round((Get-PSDrive $sysLetter).Free / 1GB, 1)
$global:FC = @{ findings = (New-Object 'Collections.Generic.List[object]'); auto = $false; changed = $false; disableList = @() }
$global:Manifest   = New-Object 'Collections.Generic.List[object]'
$global:BackupBase = $null
$global:BackupDir  = $null
$sysNames  = '^(Windows|Microsoft|Common Files|Internet Explorer|ModifiableWindowsApps|Reference Assemblies|MSBuild|Uninstall Information|WindowsPowerShell|WindowsApps|Intel|NVIDIA|AMD|dotnet)'
$skipDirRx = '^(\$Recycle\.Bin|System Volume Information|Windows|Program Files|Program Files \(x86\)|ProgramData|AppData|PCCare_Backup|PCCare_Duplicates|node_modules|\.git|Windows\.old)$'
$catDefs = [ordered]@{
    Documents  = 'doc docx docm pdf txt rtf odt xls xlsx xlsm csv ppt pptx odp ods md'
    Pictures   = 'jpg jpeg png gif bmp tif tiff heic webp svg raw cr2 nef psd'
    Videos     = 'mp4 mkv avi mov wmv flv webm m4v mpg mpeg 3gp'
    Music      = 'mp3 wav flac aac m4a wma ogg'
    Archives   = 'zip rar 7z tar gz bz2 cab'
    Installers = 'exe msi msix iso img apk'
    Databases  = 'mdf ldf bak sql db sqlite accdb mdb pst ost'
}
$extCat = @{}
foreach ($k in $catDefs.Keys) { foreach ($e in $catDefs[$k].Split(' ')) { $extCat['.' + $e] = $k } }
$bugInfo = @{
    'a'    = 'IRQL_NOT_LESS_OR_EQUAL - faulty driver or RAM'
    '1a'   = 'MEMORY_MANAGEMENT - RAM fault (run the memory test)'
    '1e'   = 'KMODE_EXCEPTION_NOT_HANDLED - faulty driver'
    '3b'   = 'SYSTEM_SERVICE_EXCEPTION - driver or damaged system files'
    '50'   = 'PAGE_FAULT_IN_NONPAGED_AREA - RAM or driver'
    '7a'   = 'KERNEL_DATA_INPAGE_ERROR - disk or cable fault'
    '7b'   = 'INACCESSIBLE_BOOT_DEVICE - storage driver or disk'
    '7e'   = 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED - faulty driver'
    '9f'   = 'DRIVER_POWER_STATE_FAILURE - driver fails on sleep/wake'
    'd1'   = 'DRIVER_IRQL_NOT_LESS_OR_EQUAL - faulty driver (often network)'
    'ef'   = 'CRITICAL_PROCESS_DIED - damaged system files or disk'
    'f4'   = 'CRITICAL_OBJECT_TERMINATION - disk fault'
    '116'  = 'VIDEO_TDR_FAILURE - graphics driver or GPU'
    '124'  = 'WHEA_UNCORRECTABLE_ERROR - hardware (CPU/RAM/heat/power)'
    '133'  = 'DPC_WATCHDOG_VIOLATION - storage driver or SSD firmware'
    '139'  = 'KERNEL_SECURITY_CHECK_FAILURE - driver or RAM'
    '154'  = 'UNEXPECTED_STORE_EXCEPTION - disk fault'
    'c000021a' = 'Critical system process failed - damaged system files'
}

# ---------- text of the restore tools that get written into the backup folder ----------
$restoreText = @'
# PCCare - restore deleted users from this backup folder. Start it with UNDO_RESTORE_USERS.bat (Administrator).
$ErrorActionPreference = 'Continue'
function Repair-Hive($file, $sid) {
    # the user's registry file still names the OLD account id; give the new one access
    if (-not (Test-Path -LiteralPath $file)) { return }
    $name = 'FC_' + [guid]::NewGuid().ToString('N')
    reg load "HKU\$name" "$file" 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Host "  Could not open $file - Windows may start a fresh profile; the files are still restored." -ForegroundColor Yellow; return }
    try {
        $rights = [Security.AccessControl.RegistryRights]'ReadPermissions, ChangePermissions'
        $key  = [Microsoft.Win32.Registry]::Users.OpenSubKey($name, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, $rights)
        $acl  = $key.GetAccessControl()
        $id   = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.RegistryAccessRule($id, 'FullControl', 'ContainerInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
        $key.SetAccessControl($acl)
        $key.Close()
    } catch { Write-Host "  Could not fix permissions inside $file ($_)" -ForegroundColor Yellow }
    finally { [gc]::Collect(); [gc]::WaitForPendingFinalizers(); reg unload "HKU\$name" 2>$null | Out-Null }
}
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$mf = Join-Path $root 'manifest.json'
if (-not (Test-Path $mf)) { Write-Host 'manifest.json not found next to this script.' -ForegroundColor Red; Read-Host 'Press Enter'; exit }
$m = Get-Content $mf -Raw | ConvertFrom-Json
$list = @($m | ForEach-Object { $_ } | Where-Object { $_.backedUp })
if ($list.Count -eq 0) { Write-Host 'No backed-up users in this folder.'; Read-Host 'Press Enter'; exit }
Write-Host ''
Write-Host "Users available to restore from $root" -ForegroundColor Cyan
$i = 0
foreach ($it in $list) {
    $i++
    $note = ''
    if (-not $it.hadAccount) { $note = '  (profile folder only - no account existed)' }
    Write-Host ('  [{0}] {1}   ({2} files, {3} GB){4}' -f $i, $it.name, $it.files, [math]::Round($it.bytes / 1GB, 2), $note)
}
$sel = Read-Host 'Type number(s) separated by commas, or ALL'
$pick = @()
if ($sel -match '^\s*all\s*$') { $pick = $list }
else {
    foreach ($n in ($sel -split '[,\s]+' | Where-Object { $_ -match '^\d+$' })) {
        $k = [int]$n
        if ($k -ge 1 -and $k -le $list.Count) { $pick += $list[$k - 1] }
    }
}
foreach ($it in $pick) {
    $u    = $it.name
    $dest = $it.profilePath
    $src  = Join-Path (Join-Path $root $u) 'profile'
    Write-Host ''
    Write-Host "=== Restoring $u ===" -ForegroundColor Cyan
    if ($it.hadProfile -and -not (Test-Path $src)) { Write-Host "  Backup folder missing: $src" -ForegroundColor Red; continue }
    if ($it.hadProfile -and (Test-Path $dest)) { Write-Host "  $dest already exists - rename or remove it first. Skipped." -ForegroundColor Yellow; continue }
    $sid = $null
    if ($it.hadAccount) {
        $acct = Get-LocalUser -Name $u -ErrorAction SilentlyContinue
        if (-not $acct) {
            $pw = Read-Host "  New password for $u (press Enter for a random one)" -AsSecureString
            if ($pw.Length -eq 0) {
                $chars = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'.ToCharArray()
                $rand  = (-join (1..14 | ForEach-Object { $chars | Get-Random })) + 'Aa1!'
                $pw    = ConvertTo-SecureString $rand -AsPlainText -Force
                Write-Host "  Temporary password for ${u}: $rand   (change it after the first login)" -ForegroundColor Yellow
            }
            $p = @{ Name = $u; Password = $pw; AccountNeverExpires = $true }
            if ($it.fullName)    { $p.FullName    = $it.fullName }
            if ($it.description) { $p.Description = $it.description }
            try { $acct = New-LocalUser @p -ErrorAction Stop } catch { Write-Host "  Could not create the account: $_" -ForegroundColor Red; continue }
            if (-not $it.enabled) { Disable-LocalUser -Name $u }
            $grp = @($it.groups | Where-Object { $_ })
            if ($grp.Count -eq 0) { $grp = @((Get-LocalGroup -SID 'S-1-5-32-545').Name) }
            foreach ($g in $grp) { Add-LocalGroupMember -Group $g -Member $u -ErrorAction SilentlyContinue }
            Write-Host ('  Account re-created. Groups: ' + ($grp -join ', '))
        } else { Write-Host '  Account already exists - keeping it.' }
        $sid = $acct.SID.Value
    }
    if ($it.hadProfile) {
        Write-Host "  Copying profile files back to $dest (may take a while)..."
        robocopy $src $dest /E /B /COPY:DAT /DCOPY:DAT /XJ /R:1 /W:1 /MT:16 /NFL /NDL /NP /NJH /NJS | Out-Null
        if ($LASTEXITCODE -ge 8) { Write-Host "  Copy had errors (robocopy code $LASTEXITCODE)." -ForegroundColor Red; continue }
        if ($sid) {
            icacls $dest /reset /T /C /Q | Out-Null
            icacls $dest /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*${sid}:(OI)(CI)F" | Out-Null
            icacls $dest /setowner "*${sid}" /T /C /Q | Out-Null
            $k = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
            New-Item -Path $k -Force | Out-Null
            Set-ItemProperty -Path $k -Name ProfileImagePath -Value $dest -Type ExpandString
            Set-ItemProperty -Path $k -Name Flags -Value 0 -Type DWord
            Set-ItemProperty -Path $k -Name State -Value 0 -Type DWord
            $so = New-Object Security.Principal.SecurityIdentifier($sid)
            $bytes = New-Object byte[] $so.BinaryLength
            $so.GetBinaryForm($bytes, 0)
            Set-ItemProperty -Path $k -Name Sid -Value $bytes -Type Binary
            Repair-Hive (Join-Path $dest 'NTUSER.DAT') $sid
            Repair-Hive (Join-Path $dest 'AppData\Local\Microsoft\Windows\UsrClass.dat') $sid
            Write-Host '  Profile registered with Windows.'
        }
    }
    Write-Host "  DONE: $u restored. Passwords cannot be recovered - the account has a new password." -ForegroundColor Green
}
Write-Host ''
Read-Host 'Press Enter to close'
'@

$batRestore = @'
@echo off
title PCCare - restore deleted users
net session >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Restore-Users.ps1"
'@

$batSettings = @'
@echo off
title PCCare - undo settings changes
net session >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Undo-Settings.ps1"
pause
'@

$awakeText = @'
param([double]$Hours = 2)
Add-Type -Namespace FC -Name Pw -MemberDefinition '[DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint f);'
[void][FC.Pw]::SetThreadExecutionState([uint32]2147483651)
Start-Sleep -Seconds ([int]($Hours * 3600))
'@

$lockCode = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class FcLock {
    [StructLayout(LayoutKind.Sequential)]
    struct RM_UNIQUE_PROCESS { public int dwProcessId; public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct RM_PROCESS_INFO {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string strServiceShortName;
        public int ApplicationType; public uint AppStatus; public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
    }
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)] static extern int RmStartSession(out uint h, int flags, string key);
    [DllImport("rstrtmgr.dll")] static extern int RmEndSession(uint h);
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)] static extern int RmRegisterResources(uint h, uint nFiles, string[] files, uint nApps, [In] RM_UNIQUE_PROCESS[] apps, uint nSvc, string[] svc);
    [DllImport("rstrtmgr.dll")] static extern int RmGetList(uint h, out uint needed, ref uint count, [In, Out] RM_PROCESS_INFO[] apps, ref uint reasons);
    public static List<string> Who(string path) {
        List<string> res = new List<string>(); uint h;
        if (RmStartSession(out h, 0, Guid.NewGuid().ToString()) != 0) return res;
        try {
            if (RmRegisterResources(h, 1, new string[] { path }, 0, null, 0, null) != 0) return res;
            uint needed = 0, count = 0, reasons = 0;
            int r = RmGetList(h, out needed, ref count, null, ref reasons);
            if (r == 234 && needed > 0) {
                RM_PROCESS_INFO[] info = new RM_PROCESS_INFO[needed]; count = needed;
                if (RmGetList(h, out needed, ref count, info, ref reasons) == 0)
                    for (int i = 0; i < count; i++) res.Add(info[i].Process.dwProcessId + " " + info[i].strAppName);
            }
        } finally { RmEndSession(h); }
        return res;
    }
}
'@

# =====================================================================
#  HELPERS
# =====================================================================
function Section($t) {
    End-Section
    $FC.sw = [Diagnostics.Stopwatch]::StartNew()
    Write-Host "`n=== $t ===" -ForegroundColor Cyan
}
function End-Section {
    if ($FC.sw) { Write-Host ("   done in {0:mm\:ss}" -f $FC.sw.Elapsed) -ForegroundColor DarkGray; $FC.sw = $null }
}
function Ask-YN($q, $default = $false) {
    if ($FC.auto) { return $default }
    if ($Ui) { return ((Ask-Ui 'yesno' $q '') -eq 'Yes') }
    $a = Read-Host "$q (Y/N)"
    return ($a -match '^[Yy]')
}
function Read-Folder($prompt, $default) {
    if ($Ui) {
        $picked = Ask-Ui 'folder' $prompt $default
        if (-not $picked) { return $null }
        return $picked
    }
    $p = Read-Host "$prompt [Enter = $default]"
    if (-not $p) { $p = $default }
    $p = $p.Trim().Trim('"')
    if (-not (Test-Path -LiteralPath $p -PathType Container)) { Write-Host '   Folder not found.' -ForegroundColor Yellow; return $null }
    return $p
}
function Add-Finding($sev, $issue, $fix) {
    $FC.findings.Add([pscustomobject]@{ Sev = $sev; Issue = $issue; Fix = $fix })
}
function Show-Findings {
    $order = @{ High = 0; Medium = 1; Low = 2 }
    if ($FC.findings.Count -eq 0) { Write-Host '   No problems recorded.' -ForegroundColor Green; return }
    foreach ($f in ($FC.findings | Sort-Object { $order[$_.Sev] })) {
        $col = 'Gray'
        if ($f.Sev -eq 'High') { $col = 'Red' } elseif ($f.Sev -eq 'Medium') { $col = 'Yellow' }
        Write-Host ("   [{0}] {1}" -f $f.Sev, $f.Issue) -ForegroundColor $col
        Write-Host ("          -> {0}" -f $f.Fix) -ForegroundColor DarkGray
    }
}
function Save-Findings {
    ($FC.findings | ForEach-Object { "[{0}] {1}`r`n      -> {2}" -f $_.Sev, $_.Issue, $_.Fix }) | Out-File "$rep\PCCare_findings.txt"
}
# Safe-path guard shared by Purge and Remove-Tree
function Get-SafePath($p) {
    if (-not $p -or -not (Test-Path -LiteralPath $p)) { return $null }
    $full = [IO.Path]::GetFullPath($p).TrimEnd('\')
    if ($full.Length -lt 10) { return $null }
    $block = @($env:SystemDrive, "$env:SystemDrive\Users", $env:windir, "$env:windir\System32", $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') }
    if ($block -contains $full) { return $null }
    return $full
}
# Empties a folder but keeps the folder itself. rd never follows junctions/symlinks.
function Purge($p) {
    $full = Get-SafePath $p
    if (-not $full) { return }
    foreach ($e in @(Get-ChildItem -LiteralPath $full -Force)) {
        if ($e.PSIsContainer) { cmd /c "rd /s /q `"$($e.FullName)`"" 2>$null | Out-Null }
        else { Remove-Item -LiteralPath $e.FullName -Force }
    }
}
function Take-Ownership($p) {
    takeown /F $p /R /A /D Y 2>$null | Out-Null
    icacls $p /grant '*S-1-5-32-544:F' /T /L /C /Q 2>$null | Out-Null
}
# Deletes a whole folder tree. Plain delete first; takes ownership only if that was not enough.
function Remove-Tree($p) {
    $full = Get-SafePath $p
    if (-not $full) { return }
    cmd /c "rd /s /q `"$full`"" 2>$null | Out-Null
    if (Test-Path -LiteralPath $full) {
        Take-Ownership $full
        cmd /c "rd /s /q `"$full`"" 2>$null | Out-Null
    }
}
function Test-PendingReboot {
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending')
}
function Run-WithTimeout($exe, $argList, $minutes) {
    $p = Start-Process $exe -ArgumentList $argList -PassThru -NoNewWindow
    $null = $p.Handle
    if (-not $p.WaitForExit($minutes * 60000)) {
        Write-Host "   $exe ran longer than $minutes min - stopped, moving on." -ForegroundColor Yellow
        Stop-Process -Id $p.Id -Force
        return -1
    }
    return $p.ExitCode
}
# Estimates files + bytes in a folder (very deep paths may be missed); skips junctions and anything in $skip
function Get-DirStat($root, $skip = @(), $maxSec = 0) {
    $files = 0L; $bytes = 0L; $partial = $false
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $skipSet = @($skip | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\').ToLower() })
    $stack = New-Object 'Collections.Generic.Stack[string]'
    $stack.Push($root)
    while ($stack.Count -gt 0) {
        if ($maxSec -gt 0 -and $clock.Elapsed.TotalSeconds -gt $maxSec) { $partial = $true; break }
        $d = $stack.Pop()
        try {
            foreach ($e in ([IO.DirectoryInfo]$d).EnumerateFileSystemInfos()) {
                if ($e.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
                if ($e -is [IO.DirectoryInfo]) {
                    if ($skipSet -contains $e.FullName.ToLower()) { continue }
                    $stack.Push($e.FullName)
                } else { $files++; $bytes += $e.Length }
            }
        } catch {}
    }
    [pscustomobject]@{ Files = $files; Bytes = $bytes; Partial = $partial }
}
# Lists user-data files under the given roots (system/program folders are skipped)
function Get-FileList($roots, $minBytes) {
    $list  = New-Object 'Collections.Generic.List[IO.FileInfo]'
    $stack = New-Object 'Collections.Generic.Stack[string]'
    foreach ($r in $roots) { if (Test-Path -LiteralPath $r) { $stack.Push($r) } }
    while ($stack.Count -gt 0) {
        $d = $stack.Pop()
        try {
            foreach ($e in ([IO.DirectoryInfo]$d).EnumerateFileSystemInfos()) {
                if ($e.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
                if ($e -is [IO.DirectoryInfo]) { if ($e.Name -notmatch $skipDirRx) { $stack.Push($e.FullName) } }
                elseif ($e.Length -ge $minBytes) { $list.Add($e) }
            }
        } catch {}
    }
    return ,$list
}
function Get-FileKey($path, $len, $full) {
    try {
        $sha = New-Object Security.Cryptography.SHA256CryptoServiceProvider
        $fs  = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
        try {
            if ($full -or $len -le 1MB) { $h = $sha.ComputeHash($fs) }
            else {
                $buf = New-Object byte[] 524288
                $n1 = $fs.Read($buf, 0, 262144)
                [void]$fs.Seek(-262144, 'End')
                $n2 = $fs.Read($buf, 262144, 262144)
                $h = $sha.ComputeHash($buf, 0, ($n1 + $n2))
            }
        } finally { $fs.Close(); $sha.Dispose() }
        return [BitConverter]::ToString($h)
    } catch { return $null }
}
function Get-FreeName($path) {
    if (-not (Test-Path -LiteralPath $path)) { return $path }
    $dir = Split-Path $path -Parent
    $b = [IO.Path]::GetFileNameWithoutExtension($path)
    $x = [IO.Path]::GetExtension($path)
    for ($i = 1; $i -lt 1000; $i++) {
        $c = Join-Path $dir ($b + ' (' + $i + ')' + $x)
        if (-not (Test-Path -LiteralPath $c)) { return $c }
    }
    return $null
}
function Register-MoveLog($log) {
    New-Item "$env:ProgramData\PCCare" -ItemType Directory -Force | Out-Null
    Add-Content -Path "$env:ProgramData\PCCare\move_logs.txt" -Value $log
}
function Move-Logged($from, $to, $log) {
    New-Item (Split-Path $to -Parent) -ItemType Directory -Force | Out-Null
    Move-Item -LiteralPath $from -Destination $to
    if ((Test-Path -LiteralPath $to) -and -not (Test-Path -LiteralPath $from)) {
        [pscustomobject]@{ From = $from; To = $to } | Export-Csv -LiteralPath $log -Append -NoTypeInformation -Encoding UTF8
        return $true
    }
    return $false
}
function Get-BackupExcludes($path) {
    if ($BackupCaches) { return @() }
    $l = "$path\AppData\Local"
    $x = @("$l\Temp", "$l\CrashDumps", "$l\D3DSCache", "$l\Microsoft\Windows\INetCache")
    foreach ($b in "$l\Google\Chrome\User Data\Default", "$l\Microsoft\Edge\User Data\Default", "$l\BraveSoftware\Brave-Browser\User Data\Default") {
        foreach ($d in 'Cache', 'Code Cache', 'GPUCache') { $x += "$b\$d" }
    }
    return $x
}
function Select-BackupBase($need) {
    if ($BackupRoot) { return $BackupRoot }
    $vols = @(Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter -and $_.FileSystem -eq 'NTFS' })
    $other = $vols | Where-Object { "$($_.DriveLetter)" -ne $sysLetter -and $_.SizeRemaining -gt ($need + 2GB) } | Sort-Object SizeRemaining -Descending | Select-Object -First 1
    if ($other) { return ("$($other.DriveLetter)" + ':\PCCare_Backup') }
    return "$env:SystemDrive\PCCare_Backup"
}
function Ensure-BackupDir {
    if ($global:BackupDir) { return }
    if (-not $global:BackupBase) { $global:BackupBase = Select-BackupBase 0 }
    $global:BackupDir = Join-Path $global:BackupBase ('Backup_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
    New-Item $global:BackupDir -ItemType Directory -Force | Out-Null
    if (-not (Test-Path $global:BackupDir)) {
        Write-Host "   Cannot create $global:BackupDir - using $env:SystemDrive\PCCare_Backup instead." -ForegroundColor Yellow
        $global:BackupBase = "$env:SystemDrive\PCCare_Backup"
        $global:BackupDir  = Join-Path $global:BackupBase ('Backup_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
        New-Item $global:BackupDir -ItemType Directory -Force | Out-Null
    }
    # only Administrators and SYSTEM may open the backup (it can hold other users' private files)
    icacls $global:BackupDir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' 2>$null | Out-Null
    Set-Content -Path "$global:BackupDir\Restore-Users.ps1"      -Value $restoreText -Encoding ASCII
    Set-Content -Path "$global:BackupDir\UNDO_RESTORE_USERS.bat" -Value $batRestore  -Encoding ASCII
    Set-Content -Path "$global:BackupDir\UNDO_SETTINGS.bat"      -Value $batSettings -Encoding ASCII
    Set-Content -Path "$global:BackupDir\Undo-Settings.ps1"      -Value '# PCCare settings undo. Run with UNDO_SETTINGS.bat (Administrator).' -Encoding ASCII
    $readme = @(
        'PCCare backup',
        '',
        'UNDO_RESTORE_USERS.bat  -> brings deleted users back (account, groups, profile files).',
        '                          Passwords cannot be recovered; a new/temporary password is set.',
        '                          Browser-saved passwords and Windows-encrypted data of that user are lost.',
        'UNDO_SETTINGS.bat       -> reverts settings, services, firewall rules, startup items, old drivers.',
        '<username>\profile      -> full copy of that user''s profile folder.',
        'manifest.json           -> list of what was backed up.'
    )
    Set-Content -Path "$global:BackupDir\README.txt" -Value $readme -Encoding ASCII
}
function Add-Undo($line) {
    Ensure-BackupDir
    Add-Content -Path "$global:BackupDir\Undo-Settings.ps1" -Value $line -Encoding ASCII
}
function Set-RegTracked($path, $name, $value, $type = 'DWord') {
    $old = (Get-ItemProperty -Path $path -Name $name).$name
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    if ($null -eq $old) { Add-Undo "Remove-ItemProperty -Path '$path' -Name '$name' -ErrorAction SilentlyContinue" }
    elseif ($type -eq 'String') { Add-Undo "Set-ItemProperty -Path '$path' -Name '$name' -Value '$old' -Type String" }
    else { Add-Undo "Set-ItemProperty -Path '$path' -Name '$name' -Value $old -Type $type" }
    Set-ItemProperty -Path $path -Name $name -Value $value -Type $type
}
function Set-SvcTracked($name, $type) {
    $sv = Get-Service -Name $name
    if (-not $sv) { return }
    if ("$($sv.StartType)" -ne $type) {
        Add-Undo ("Set-Service -Name {0} -StartupType {1}" -f $name, $sv.StartType)
        Set-Service -Name $name -StartupType $type
    }
    if ("$($sv.Status)" -ne 'Running') { Start-Service -Name $name }
}
function Get-ActiveScheme {
    [regex]::Match((powercfg /getactivescheme | Out-String), '[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}').Value
}
function Get-StartupItems {
    $defs = @(
        @{ Hive = 'HKLM'; Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run';             Appr = 'Run'   },
        @{ Hive = 'HKLM'; Key = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Appr = 'Run32' },
        @{ Hive = 'HKCU'; Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run';             Appr = 'Run'   }
    )
    foreach ($d in $defs) {
        $rp = $d.Hive + ':\' + $d.Key
        $ap = $d.Hive + ':\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\' + $d.Appr
        $props = Get-ItemProperty -Path $rp
        if (-not $props) { continue }
        foreach ($pr in $props.PSObject.Properties) {
            if ($pr.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$' -or $pr.Name -eq '(default)') { continue }
            $st  = (Get-ItemProperty -Path $ap -Name $pr.Name).($pr.Name)
            $off = ($st -is [byte[]]) -and (($st[0] -band 1) -eq 1)
            [pscustomobject]@{ Name = $pr.Name; Command = "$($pr.Value)"; Where = ($d.Hive + '\' + $d.Key); ApprPath = $ap; Disabled = $off }
        }
    }
}
function Get-StartupTag($n, $cmd) {
    if ("$n $cmd" -match 'Defender|Security|Antivirus|Sophos|McAfee|Norton|Kaspersky|Realtek|Audio|Synaptics|Touchpad|Bluetooth|Intel|NVIDIA|AMD|Wacom|Fingerprint') { return 'keep (driver/security)' }
    if ("$n $cmd" -match 'Update|Updater|Teams|OneDrive|Spotify|Skype|Discord|Steam|Adobe|Java|iTunes|Zoom|Dropbox|Epic|Origin|Cortana|Edge|Chrome|Brave|Opera|Torrent|Helper') { return 'usually safe to disable' }
    return ''
}
function Disable-StartupItem($it) {
    if (-not (Test-Path $it.ApprPath)) { New-Item -Path $it.ApprPath -Force | Out-Null }
    $bytes = [byte[]](3,0,0,0,0,0,0,0,0,0,0,0)
    $ft = [BitConverter]::GetBytes([DateTime]::UtcNow.ToFileTimeUtc())
    [Array]::Copy($ft, 0, $bytes, 4, 8)
    Set-ItemProperty -Path $it.ApprPath -Name $it.Name -Value $bytes -Type Binary
    $nm = $it.Name.Replace("'", "''")
    Add-Undo "Remove-ItemProperty -Path '$($it.ApprPath)' -Name '$nm' -ErrorAction SilentlyContinue"
}

# ---------- facts gathered once and shared by every menu item ----------
function Ensure-Facts {
    if ($FC.facts) { return }
    $FC.os       = Get-CimInstance Win32_OperatingSystem
    $cs          = Get-CimInstance Win32_ComputerSystem
    $FC.ramGB    = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
    $FC.isLaptop = [bool](Get-CimInstance Win32_Battery)
    $dn          = (Get-Partition -DriveLetter $sysLetter | Get-Disk).Number
    $FC.pd       = Get-PhysicalDisk | Where-Object { "$($_.DeviceId)" -eq "$dn" } | Select-Object -First 1
    $FC.isHDD    = ("$($FC.pd.MediaType)" -eq 'HDD')
    $FC.isSSD    = ("$($FC.pd.MediaType)" -eq 'SSD') -or ("$($FC.pd.BusType)" -eq 'NVMe')
    $FC.allSvc   = @(Get-CimInstance Win32_Service)
    $FC.allTasks = @(Get-ScheduledTask)
    $FC.badSvc   = @($FC.allSvc | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' -and $_.ExitCode -notin 0, 1077 } | Select-Object -ExpandProperty Name)
    $FC.svc3     = @($FC.allSvc | Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName -notmatch '\\Windows\\|\\Microsoft\\|svchost' })
    $FC.pfu      = @(Get-CimInstance Win32_PageFileUsage)
    $FC.countersBroken = $false
    $FC.facts    = $true
}
function Ensure-Events {
    if ($FC.events) { return }
    Write-Host '   Reading event log (last 7 days)...'
    $since = (Get-Date).AddDays(-7)
    $FC.sysEv = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2, 3; StartTime = $since } -MaxEvents 4000)
    $FC.appEv = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Level = 1, 2; StartTime = $since } -MaxEvents 3000)
    $FC.diskErr = @($FC.sysEv | Where-Object { $_.ProviderName -match '^(disk|Ntfs|Microsoft-Windows-Ntfs|stornvme|storahci|iaStor|nvstor)' -and $_.Id -in 7, 11, 15, 51, 55, 129, 153 }).Count
    $FC.kp      = @($FC.sysEv | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-Kernel-Power' -and $_.Id -eq 41 }).Count
    $FC.bugEv   = @($FC.sysEv | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-WER-SystemErrorReporting' -and $_.Id -eq 1001 })
    $FC.bsod    = $FC.bugEv.Count
    $wheaEv     = @($FC.sysEv | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-WHEA-Logger' })
    $FC.whea    = $wheaEv.Count
    $FC.wheaBad = @($wheaEv | Where-Object { $_.Level -le 2 }).Count
    $FC.lowm    = @($FC.sysEv | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-Resource-Exhaustion-Detector' }).Count
    $FC.wuFail  = @($FC.sysEv | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-WindowsUpdateClient' -and $_.Id -eq 20 }).Count
    $FC.events  = $true
}
function Ensure-RestorePoint {
    $FC.changed = $true
    if ($FC.rpDone) { return }
    $FC.rpDone = $true
    Write-Host '   Creating a restore point first...'
    $rpKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    $rpOld = (Get-ItemProperty $rpKey -Name SystemRestorePointCreationFrequency).SystemRestorePointCreationFrequency
    Set-ItemProperty -Path $rpKey -Name SystemRestorePointCreationFrequency -Value 0 -Type DWord
    Enable-ComputerRestore -Drive "$env:SystemDrive\"
    Checkpoint-Computer -Description 'Before PCCare v4' -RestorePointType MODIFY_SETTINGS
    if ($null -eq $rpOld) { Remove-ItemProperty -Path $rpKey -Name SystemRestorePointCreationFrequency } else { Set-ItemProperty -Path $rpKey -Name SystemRestorePointCreationFrequency -Value $rpOld -Type DWord }
    $rp = Get-ComputerRestorePoint | Select-Object -Last 1
    if ($rp.Description -like 'Before PCCare*') { Write-Host '   Restore point created.' }
    else { Write-Host '   Could not create a restore point (System Protection is off?). Settings changes are still logged for undo.' -ForegroundColor Yellow }
}
function Ask-Startup {
    $FC.askedStartup = $true
    $FC.disableList = @()
    $on = @(Get-StartupItems | Where-Object { -not $_.Disabled })
    if ($on.Count -eq 0) { return }
    if ($Ui) {
        # window mode: no question. Only well-known non-essential items are switched off, and only if the option is ticked.
        if ($Ui.OptStartup) {
            $FC.disableList = @($on | Where-Object { "$($_.Name) $($_.Command)" -match 'Update|Updater|Spotify|Skype|Discord|Steam|Adobe|Java|iTunes|Epic|Origin|Cortana|Torrent|Helper' -and (Get-StartupTag $_.Name $_.Command) -ne 'keep (driver/security)' })
        }
        Write-Host "   Startup apps: $($on.Count) enabled, $($FC.disableList.Count) will be switched off (reversible with UNDO_SETTINGS.bat)."
        return
    }
    Write-Host ''
    Write-Host 'Startup apps (they start with Windows and slow the boot):' -ForegroundColor Cyan
    for ($i = 0; $i -lt $on.Count; $i++) {
        $cmdShort = $on[$i].Command
        if ($cmdShort.Length -gt 70) { $cmdShort = $cmdShort.Substring(0, 70) + '...' }
        Write-Host ("  [{0,2}] {1,-28} {2}  {3}" -f ($i + 1), $on[$i].Name, $cmdShort, (Get-StartupTag $on[$i].Name $on[$i].Command))
    }
    $ans = Read-Host 'Numbers to DISABLE, e.g. 2,5,7  (Enter = none; reversible with UNDO_SETTINGS.bat)'
    foreach ($n in ($ans -split '[,\s]+' | Where-Object { $_ -match '^\d+$' })) {
        $k = [int]$n
        if ($k -ge 1 -and $k -le $on.Count) { $FC.disableList += $on[$k - 1] }
    }
}
function Ask-Winget {
    $FC.askedWinget = $true
    $FC.doWinget = $false
    $FC.wg = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $FC.wg) { return }
    if ($Ui) { $FC.doWinget = [bool]$Ui.OptWinget; return }
    Write-Host ''
    Write-Host 'Checking which installed apps have updates (winget)...' -ForegroundColor Cyan
    & $FC.wg.Source upgrade --include-unknown --accept-source-agreements | Out-Host
    $ans = Read-Host 'Update ALL the apps listed above? Y/N  - say N if any app must stay on its current version (ERP/SAP clients, Java, SQL tools)'
    $FC.doWinget = ($ans -match '^[Yy]')
}
function Fix-Devices {
    $bad = @(Get-PnpDevice -PresentOnly | Where-Object { $_.Status -eq 'Error' })
    foreach ($d in $bad) {
        Write-Host "   Device problem: $($d.FriendlyName) - restarting it"
        pnputil /restart-device "$($d.InstanceId)" 2>$null | Out-Null
    }
    pnputil /scan-devices 2>$null | Out-Null
    if ($bad.Count -gt 0) {
        Start-Sleep -Seconds 5
        $still = @(Get-PnpDevice -PresentOnly | Where-Object { $_.Status -eq 'Error' })
        Write-Host "   Devices fixed: $($bad.Count - $still.Count) of $($bad.Count)"
        foreach ($d in $still) { Write-Host "   Still broken: $($d.FriendlyName) - install its driver from the PC maker's website." -ForegroundColor Yellow }
    } else { Write-Host '   No device problems.' }
}
function Schedule-MemTest {
    bcdedit /bootsequence '{memdiag}' | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Add-Undo "bcdedit /deletevalue '{bootmgr}' bootsequence"
        Write-Host '   Windows Memory Diagnostic will run at the next restart (about 15-30 min). Result appears after you sign in.' -ForegroundColor Green
    } else { Write-Host '   Could not schedule it. Run  mdsched.exe  manually.' -ForegroundColor Yellow }
}

# =====================================================================
#  1. SCAN
# =====================================================================
function Invoke-Scan {
    Section '1. SCAN AND REPORT (read-only - nothing is changed)'
    $FC.findings.Clear()
    Ensure-Facts
    $os = $FC.os; $ramGB = $FC.ramGB; $pd = $FC.pd
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $upDays = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
    Write-Host ("   {0} build {1} | {2} | RAM {3} GB | up {4} days" -f $os.Caption, $os.BuildNumber, ($cpu.Name -replace '\s+', ' '), $ramGB, $upDays)
    if ($ramGB -lt 8) { Add-Finding 'High' "Only $ramGB GB RAM" 'Windows needs 8 GB or more for smooth use. More RAM is the biggest fix for hanging.' }
    if ($upDays -gt 14) { Add-Finding 'Low' "PC not restarted for $upDays days" 'Restart weekly (Fast Startup makes Shut down NOT a real restart; menu 3 turns it off).' }
    if ($os.Caption -match 'Windows 10') { Add-Finding 'Low' 'Windows 10 is past end of support (14 Oct 2025)' 'It no longer gets free security updates. Plan a move to Windows 11.' }

    # --- disk
    $rel = $pd | Get-StorageReliabilityCounter
    Write-Host ("   System disk: {0} | {1} | {2} | health {3} | temp {4} C | wear {5} % | power-on {6} h" -f $pd.FriendlyName, $pd.MediaType, $pd.BusType, $pd.HealthStatus, $rel.Temperature, $rel.Wear, $rel.PowerOnHours)
    if ($pd -and "$($pd.HealthStatus)" -ne 'Healthy') { Add-Finding 'High' "System disk health is '$($pd.HealthStatus)'" 'BACK UP YOUR DATA NOW and replace the disk.' }
    if ($rel.Wear -ge 80) { Add-Finding 'High' "SSD wear is $($rel.Wear) %" 'SSD is near end of life - back up and replace.' }
    if ($rel.Temperature -ge 70) { Add-Finding 'Medium' "Disk temperature $($rel.Temperature) C" 'Improve airflow / clean dust; hot disks throttle and hang.' }
    if (($rel.ReadErrorsUncorrected -gt 0) -or ($rel.WriteErrorsUncorrected -gt 0)) { Add-Finding 'High' 'Disk reports uncorrected read/write errors' 'BACK UP YOUR DATA NOW - the disk is failing.' }
    if ($FC.isHDD) { Add-Finding 'Medium' 'Windows is installed on a hard disk (HDD)' 'An SSD is the biggest speed upgrade possible for this PC.' }
    foreach ($v in (Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter })) {
        $pct = 0
        if ($v.Size) { $pct = [math]::Round($v.SizeRemaining / $v.Size * 100) }
        Write-Host ("   Drive {0}: {1} GB free of {2} GB ({3} % free)" -f $v.DriveLetter, [math]::Round($v.SizeRemaining / 1GB, 1), [math]::Round($v.Size / 1GB, 1), $pct)
        if ("$($v.DriveLetter)" -eq $sysLetter -and $pct -lt 15) { Add-Finding 'High' "Only $pct % free on $($v.DriveLetter): " 'Windows slows down and updates fail when the system drive is nearly full. Run menu 4.' }
    }
    $tz = Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature | Select-Object -First 1
    if ($tz) {
        $tc = [math]::Round($tz.CurrentTemperature / 10 - 273.15)
        Write-Host "   Board thermal zone: $tc C"
        if ($tc -ge 85) { Add-Finding 'High' "System temperature $tc C" 'Overheating causes hangs and shutdowns. Clean the fans/vents and renew thermal paste.' }
    }

    # --- live load (5 s sample) + top processes (3 s)
    $cpuLoad = $null; $diskBusy = $null; $diskLat = $null; $availMB = $null
    try {
        $cn = '\Processor(_Total)\% Processor Time', '\PhysicalDisk(_Total)\% Disk Time', '\PhysicalDisk(_Total)\Avg. Disk sec/Transfer', '\Memory\Available MBytes'
        $smp = Get-Counter -Counter $cn -SampleInterval 1 -MaxSamples 5 -ErrorAction Stop | ForEach-Object { $_.CounterSamples }
        $cpuLoad  = ($smp | Where-Object { $_.Path -like '*processor(_total)*% processor time' } | Measure-Object CookedValue -Average).Average
        $diskBusy = ($smp | Where-Object { $_.Path -like '*physicaldisk(_total)*% disk time' } | Measure-Object CookedValue -Average).Average
        $diskLat  = ($smp | Where-Object { $_.Path -like '*physicaldisk(_total)*avg. disk sec/transfer' } | Measure-Object CookedValue -Average).Average
        $availMB  = ($smp | Where-Object { $_.Path -like '*memory*available mbytes' } | Measure-Object CookedValue -Average).Average
        Write-Host ("   Live (5 s avg): CPU {0:N0} % | disk busy {1:N0} % | disk latency {2:N0} ms | free RAM {3:N0} MB" -f $cpuLoad, $diskBusy, ($diskLat * 1000), $availMB)
        if ($cpuLoad -gt 85) { Add-Finding 'Medium' ("CPU is busy ({0:N0} %)" -f $cpuLoad) 'See top processes; stop or uninstall the heavy one.' }
        if ($diskBusy -gt 85 -or $diskLat -gt 0.05) { Add-Finding 'High' ("Disk is saturated (busy {0:N0} %, latency {1:N0} ms)" -f $diskBusy, ($diskLat * 1000)) 'Classic cause of hangs, especially on an HDD. See top processes; consider an SSD.' }
        if ($availMB -lt 800 -or ($availMB / 1024) -lt ($ramGB * 0.1)) { Add-Finding 'High' ("Low free RAM ({0:N0} MB)" -f $availMB) 'Memory is exhausted -> swapping -> hangs. Disable startup apps (menu 3); add RAM.' }
    } catch {
        $FC.countersBroken = $true
        Add-Finding 'Low' 'Windows performance counters are unreadable' 'Live load was not measured. Menu 3 rebuilds them on English Windows.'
    }
    $p1 = @{}
    Get-Process | ForEach-Object { $p1[$_.Id] = $_.CPU }
    Start-Sleep -Seconds 3
    $cores = [Environment]::ProcessorCount
    $topCpu = Get-Process | ForEach-Object {
        if ($_.Id -ne 0 -and $null -ne $_.CPU -and $null -ne $p1[$_.Id]) {
            [pscustomobject]@{ Name = $_.ProcessName; CPUpct = [math]::Round((($_.CPU - $p1[$_.Id]) / 3 / $cores * 100), 1) }
        }
    } | Sort-Object CPUpct -Descending | Select-Object -First 6
    $topRam = Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 6
    Write-Host ('   Top CPU:  ' + (($topCpu | ForEach-Object { "$($_.Name) $($_.CPUpct)%" }) -join ', '))
    Write-Host ('   Top RAM:  ' + (($topRam | ForEach-Object { "$($_.ProcessName) $([math]::Round($_.WorkingSet64 / 1MB))MB" }) -join ', '))
    $hints = @{ MsMpEng = 'Windows Defender scanning (check for a 2nd antivirus)'; TiWorker = 'Windows Update servicing'; TrustedInstaller = 'Windows Update servicing'; SearchIndexer = 'Windows Search indexing'; OneDrive = 'OneDrive syncing' }
    foreach ($t in ($topCpu | Where-Object { $_.CPUpct -gt 25 })) {
        $h = $hints[$t.Name]
        if (-not $h) { $h = 'check if you need it' }
        Add-Finding 'Medium' "$($t.Name) is using $($t.CPUpct) % CPU" $h
    }

    # --- memory / pagefile / power
    if ($FC.pfu.Count -eq 0) { Add-Finding 'High' 'No page file' 'Hangs and app crashes when RAM fills. Menu 3 turns on automatic management.' }
    else {
        foreach ($pf in $FC.pfu) { if ($pf.AllocatedBaseSize -gt 0 -and ($pf.PeakUsage / $pf.AllocatedBaseSize) -gt 0.85) { Add-Finding 'Medium' "Page file peaked at $($pf.PeakUsage) of $($pf.AllocatedBaseSize) MB" 'Page file is too small; menu 3 fixes this.' } }
    }
    $schemeTxt = (powercfg /getactivescheme | Out-String).Trim()
    Write-Host "   $schemeTxt"
    if ($schemeTxt -match 'Power saver') { Add-Finding 'Medium' 'Power plan is Power saver' 'CPU is throttled. Menu 3 switches desktops to High performance; on laptops choose Balanced.' }
    if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power').HiberbootEnabled -eq 1) { Add-Finding 'Low' 'Fast Startup is on' 'It can cause odd hangs and stale drivers; menu 3 turns it off.' }

    # --- event log
    Ensure-Events
    $sysEv = $FC.sysEv; $appEv = $FC.appEv
    $gpu   = @($sysEv | Where-Object { $_.ProviderName -eq 'Display' -and $_.Id -eq 4101 }).Count
    $scm   = @($sysEv | Where-Object { $_.ProviderName -eq 'Service Control Manager' -and $_.Id -in 7000, 7001, 7009, 7011, 7022, 7023, 7024, 7031, 7034 })
    $hangs = @($appEv | Where-Object { $_.ProviderName -eq 'Application Hang' })
    $crash = @($appEv | Where-Object { $_.ProviderName -eq 'Application Error' })
    Write-Host ("   Events: disk errors {0} | unexpected shutdowns {1} | blue screens {2} | hardware (WHEA) {3} | GPU resets {4} | low-memory {5} | service faults {6} | app hangs {7} | app crashes {8}" -f $FC.diskErr, $FC.kp, $FC.bsod, $FC.whea, $gpu, $FC.lowm, $scm.Count, $hangs.Count, $crash.Count)
    if ($FC.diskErr -gt 0) { Add-Finding 'High' "$($FC.diskErr) disk/file-system errors in the last 7 days" 'Failing disk, bad cable or controller. BACK UP NOW. Menu 2 runs a disk scan.' }
    if ($FC.kp -gt 0) { Add-Finding 'High' "$($FC.kp) unexpected shutdowns" 'Power cut, weak power supply, overheating or a hard freeze.' }
    foreach ($g in ($FC.bugEv | ForEach-Object { $m = [regex]::Match($_.Message, '0x([0-9a-fA-F]{8,16})'); if ($m.Success) { $m.Groups[1].Value.TrimStart('0').ToLower() } } | Group-Object)) {
        $why = $bugInfo[$g.Name]
        if (-not $why) { $why = 'driver or hardware fault' }
        Add-Finding 'High' ("Blue screen 0x{0} x{1}: {2}" -f $g.Name.ToUpper(), $g.Count, $why) 'Run menu 2 (crash repair). If it repeats, send PCCare_findings.txt for analysis.'
    }
    if ($FC.wheaBad -gt 0) { Add-Finding 'High' "$($FC.wheaBad) uncorrected hardware errors (WHEA)" 'CPU/RAM/PCIe hardware fault or overheating - check temperatures and run the memory test (menu 8).' }
    elseif ($FC.whea -gt 0) { Add-Finding 'Medium' "$($FC.whea) corrected hardware errors (WHEA)" 'Hardware is retrying operations (often a PCIe/NVMe link or heat). Update BIOS and chipset drivers.' }
    if ($gpu -gt 3) { Add-Finding 'Medium' "Display driver reset $gpu times" 'Update/reinstall the graphics driver from the GPU maker.' }
    if ($FC.lowm -gt 0) { Add-Finding 'High' "Windows ran out of memory $($FC.lowm) times" 'Close/disable heavy apps; add RAM.' }
    if ($FC.wuFail -ge 3) { Add-Finding 'Medium' "Windows Update failed $($FC.wuFail) times" 'Menu 5 resets the update components.' }
    if ($scm.Count -gt 0) {
        $names = $scm | ForEach-Object { $m = [regex]::Match($_.Message, '(?i)\bthe (.+?) service\b'); if ($m.Success) { $m.Groups[1].Value } } | Group-Object | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name) x$($_.Count)" }
        Add-Finding 'Medium' ("Services failing/timing out: " + ($names -join ', ')) 'Slow or stuck services cause boot/login hangs. Update or uninstall the related software.'
    }
    if ($hangs.Count -gt 5) {
        $names = $hangs | ForEach-Object { $m = [regex]::Match($_.Message, 'The program (.+?) version'); if ($m.Success) { $m.Groups[1].Value } } | Group-Object | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name) x$($_.Count)" }
        Add-Finding 'Medium' ("Apps that hang most: " + ($names -join ', ')) 'Update (menu 5) or reinstall these apps.'
    }
    if ($crash.Count -gt 5) {
        $names = $crash | ForEach-Object { $m = [regex]::Match($_.Message, 'Faulting application name: ([^,]+),'); if ($m.Success) { $m.Groups[1].Value } } | Group-Object | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name) x$($_.Count)" }
        Add-Finding 'Low' ("Apps that crash most: " + ($names -join ', ')) 'Update (menu 5) or reinstall these apps.'
    }

    # --- devices, startup load, odd processes
    $badDev = @(Get-PnpDevice -PresentOnly | Where-Object { $_.Status -eq 'Error' } | Select-Object -ExpandProperty FriendlyName)
    if ($badDev.Count -gt 0) { Add-Finding 'Medium' ("Devices with driver problems: " + (($badDev | Select-Object -First 6) -join ', ')) 'Menu 5 updates drivers and restarts these devices.' }
    if ($FC.badSvc.Count -gt 0) { Add-Finding 'Low' ("Auto-start services that failed: " + (($FC.badSvc | Select-Object -First 8) -join ', ')) 'Menu 3 restarts them. Reinstall the related software if they keep failing.' }
    $startOn = @(Get-StartupItems | Where-Object { -not $_.Disabled })
    Write-Host ("   Startup apps (registry): {0} enabled | 3rd-party auto-start services: {1}" -f $startOn.Count, $FC.svc3.Count)
    if (($startOn.Count + $FC.svc3.Count) -gt 25) { Add-Finding 'Medium' ("{0} startup apps + {1} 3rd-party services load at boot" -f $startOn.Count, $FC.svc3.Count) 'Biggest cause of slow boot. Menu 3 lets you disable startup apps.' }
    $odd = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -match '\\AppData\\Local\\Temp\\|\\Windows\\Temp\\|\\Users\\Public\\' } | Select-Object -ExpandProperty Name -Unique)
    if ($odd.Count -gt 0) { Add-Finding 'Medium' ("Programs running from Temp/Public folders: " + ($odd -join ', ')) 'Often installers - but malware also hides here. Run a full antivirus scan.' }

    # --- startup report
    $su  = Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | Format-List | Out-String
    $st3 = $FC.svc3 | Select-Object Name, StartName, PathName | Format-List | Out-String
    $lt  = $FC.allTasks | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' -and ($_.Triggers | Where-Object { $_.CimClass.CimClassName -match 'Logon|Boot' }) } | Select-Object TaskName, TaskPath | Format-Table -AutoSize | Out-String
    ("STARTUP ITEMS`r`n" + $su + "`r`n3RD-PARTY AUTO-START SERVICES`r`n" + $st3 + "`r`nNON-MICROSOFT TASKS THAT RUN AT LOGON/BOOT`r`n" + $lt) | Out-File "$rep\startup_items_review.txt"

    Write-Host ''
    Write-Host '   ---- WHAT THE SCAN FOUND ----' -ForegroundColor White
    Show-Findings
    Save-Findings
    Write-Host "   Saved: $rep\PCCare_findings.txt"
}

# =====================================================================
#  2. BLUE SCREEN AND CRASH REPAIR
# =====================================================================
function Invoke-CrashRepair {
    Section '2. BLUE SCREEN AND CRASH REPAIR'
    Ensure-Facts; Ensure-Events; Ensure-RestorePoint
    $dumps = @(Get-ChildItem "$env:windir\Minidump" -Filter *.dmp -File)
    Write-Host "   Blue screens in 7 days: $($FC.bsod) | unexpected shutdowns: $($FC.kp) | hardware errors: $($FC.whea) | dump files: $($dumps.Count)"
    $drvEv = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-UserPnp'; Id = 20001; StartTime = (Get-Date).AddDays(-30) } -MaxEvents 12)
    if ($drvEv.Count -gt 0) {
        Write-Host '   Drivers installed in the last 30 days (a crash that started after one of these points to it):'
        foreach ($e in $drvEv) { Write-Host ("     {0:dd-MMM HH:mm}  {1}" -f $e.TimeCreated, (($e.Message -split "`n")[0]).Trim()) }
    }
    # crash dumps must be enabled so the next crash can be analysed
    $cc = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
    if ((Get-ItemProperty $cc).CrashDumpEnabled -eq 0) { Set-RegTracked $cc 'CrashDumpEnabled' 3 'DWord'; Write-Host '   Crash dumps were off - small dumps enabled.' }
    # system files
    $chk = DISM /Online /Cleanup-Image /CheckHealth | Out-String
    if ($DeepRepair -or $chk -match 'repairable' -or $FC.bsod -gt 0) {
        Write-Host '   Repairing Windows system files (DISM + SFC, up to 60 min)...' -ForegroundColor Yellow
        $rc = Run-WithTimeout 'dism.exe' '/Online /Cleanup-Image /RestoreHealth' 30
        $rc = Run-WithTimeout 'sfc.exe'  '/scannow' 30
    } else { Write-Host '   Windows component store is healthy - slow repair skipped.' }
    $wmi = (winmgmt /verifyrepository) | Out-String
    if ($wmi -match 'inconsistent') { Write-Host '   WMI repository is damaged - salvaging.' -ForegroundColor Yellow; winmgmt /salvagerepository | Out-Null }
    else { Write-Host '   WMI repository is consistent.' }
    # disk
    if ($FC.diskErr -gt 0 -or $DeepRepair) {
        Write-Host '   Running an online disk scan.' -ForegroundColor Yellow
        $rc = Run-WithTimeout 'chkdsk.exe' "$env:SystemDrive /scan" 30
        if ($rc -in 2, 3) { Write-Host '   Errors need an offline fix - full check scheduled for the next restart.' -ForegroundColor Yellow; cmd /c "echo Y| chkdsk $env:SystemDrive /F" | Out-Null }
    }
    $dirty = (fsutil dirty query "$env:SystemDrive") -join ' '
    if ($dirty -notmatch 'NOT Dirty' -and $dirty -match 'Dirty') {
        Write-Host '   Disk is flagged dirty - a disk check will run at the next restart.' -ForegroundColor Yellow
        cmd /c "echo Y| chkdsk $env:SystemDrive /F" | Out-Null
    }
    Fix-Devices
    # RAM test when the evidence points at memory or hardware
    $ramSuspect = ($FC.wheaBad -gt 0) -or ($FC.bsod -ge 2)
    if ($ramSuspect -and ($FC.auto -or $Ui)) { Schedule-MemTest }
    elseif (-not $FC.auto -and -not $Ui) { if (Ask-YN '   Schedule a RAM hardware test at the next restart?') { Schedule-MemTest } }
    if ($FC.bsod -eq 0 -and $FC.kp -gt 0) { Write-Host '   Shutdowns without a blue screen point to power (supply, UPS, loose cable) or overheating.' -ForegroundColor Yellow }
}

# =====================================================================
#  3. SLOW PC AND HANG FIX
# =====================================================================
function Invoke-SpeedFix {
    Section '3. SLOW PC AND HANG FIX (every change is logged for undo)'
    Ensure-Facts
    if (-not $FC.askedStartup) { Ask-Startup }
    Ensure-RestorePoint
    foreach ($si in $FC.disableList) { Disable-StartupItem $si; Write-Host "   Startup app disabled: $($si.Name)" }
    $FC.disableList = @()
    $FC.askedStartup = $false
    # Fast Startup / hibernate
    if ($FC.isLaptop) {
        Set-RegTracked 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' 0 'DWord'
        Write-Host '   Fast Startup off (hibernate kept - it protects work when the battery runs out).'
    } else {
        if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power').HibernateEnabled -eq 1) { Add-Undo 'powercfg -h on' }
        powercfg -h off
        $old = Get-ActiveScheme
        if ($old) { Add-Undo "powercfg /setactive $old" }
        powercfg /setactive SCHEME_MIN | Out-Null
        if ($LASTEXITCODE -ne 0) {
            $out = powercfg -duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2>&1 | Out-String
            if ($out -match '([0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})') { powercfg /setactive $Matches[1] }
        }
        Write-Host '   Hibernate/Fast Startup off, High performance power plan on.'
    }
    # page file
    $cs2   = Get-CimInstance Win32_ComputerSystem
    $pfSet = @(Get-CimInstance Win32_PageFileSetting)
    $tiny  = $false
    foreach ($ps in $pfSet) { if ($ps.MaximumSize -gt 0 -and $ps.MaximumSize -lt 4096) { $tiny = $true } }
    if (-not $cs2.AutomaticManagedPagefile -and ($FC.pfu.Count -eq 0 -or $tiny)) {
        $desc = ($pfSet | ForEach-Object { "$($_.Name) initial=$($_.InitialSize)MB max=$($_.MaximumSize)MB" }) -join '; '
        Add-Undo "# Page file was manually set before PCCare: $desc  (re-set it in System Properties > Advanced > Performance > Virtual memory)"
        try { Get-CimInstance Win32_ComputerSystem | Set-CimInstance -Property @{ AutomaticManagedPagefile = $true } -ErrorAction Stop }
        catch { $w = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges; $w.AutomaticManagedPagefile = $true; [void]$w.Put() }
        if ((Get-CimInstance Win32_ComputerSystem).AutomaticManagedPagefile) { Write-Host '   Page file set to automatic (takes effect after restart).' }
        else { Write-Host '   Could not switch the page file to automatic - do it in System Properties.' -ForegroundColor Yellow }
    }
    # SysMain (Superfetch) hammers hard disks
    if ($FC.isHDD) {
        $sm = Get-Service SysMain
        if ($sm -and "$($sm.StartType)" -ne 'Disabled') {
            Add-Undo ("Set-Service SysMain -StartupType {0}; Start-Service SysMain" -f $sm.StartType)
            Stop-Service SysMain -Force
            Set-Service SysMain -StartupType Disabled
            Write-Host '   SysMain turned off (HDD).'
        }
    }
    # lighter visuals only where the hardware is weak
    if ($FC.ramGB -lt 8 -or $FC.isHDD) {
        Set-RegTracked 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' 'EnableTransparency' 0 'DWord'
        Set-RegTracked 'HKCU:\Control Panel\Desktop\WindowMetrics' 'MinAnimate' '0' 'String'
        Write-Host '   Transparency and window animations off (low RAM or HDD). Applies at next sign-in.'
    }
    # failed auto-start services
    foreach ($n in $FC.badSvc) {
        Start-Service -Name $n
        Write-Host ("   Service {0}: {1}" -f $n, (Get-Service -Name $n).Status)
    }
    if ($FC.countersBroken -and (Get-UICulture).Name -like 'en*') {
        lodctr /R 2>$null | Out-Null
        winmgmt /resyncperf 2>$null | Out-Null
        Write-Host '   Performance counters rebuilt.'
    }
    # keep it clean automatically
    $ss = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'
    Set-RegTracked $ss '01'   1 'DWord'
    Set-RegTracked $ss '04'   1 'DWord'
    Set-RegTracked $ss '2048' 7 'DWord'
    $wk = @'
Get-ChildItem 'C:\Windows\Temp','C:\Users\*\AppData\Local\Temp' -Recurse -Force -File -ErrorAction SilentlyContinue |
  Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } | Remove-Item -Force -ErrorAction SilentlyContinue
'@
    Set-Content -Path "$env:ProgramData\weekly_cleanup.ps1" -Value $wk -Force
    $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$env:ProgramData\weekly_cleanup.ps1`""
    $trg = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 1pm
    $prn = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    $tset = New-ScheduledTaskSettingsSet -StartWhenAvailable
    if (-not (Get-ScheduledTask -TaskName 'WeeklyTempCleanup')) { Add-Undo "Unregister-ScheduledTask -TaskName 'WeeklyTempCleanup' -Confirm:`$false -ErrorAction SilentlyContinue" }
    Register-ScheduledTask -TaskName 'WeeklyTempCleanup' -Action $act -Trigger $trg -Principal $prn -Settings $tset -Force | Out-Null
    if ($FC.isSSD) { Optimize-Volume -DriveLetter $sysLetter -ReTrim; Write-Host '   SSD trimmed.' }
    elseif ($FC.isHDD) { schtasks /run /tn "\Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null; Write-Host '   HDD defrag started in the background.' }
}

# =====================================================================
#  4. C: DRIVE CLEANUP
# =====================================================================
function Invoke-Cleanup {
    Section '4. C: DRIVE CLEANUP'
    Ensure-RestorePoint
    $before = (Get-PSDrive $sysLetter).Free
    $pending = Test-PendingReboot
    Delete-DeliveryOptimizationCache -Force
    if (-not $pending) {
        Stop-Service wuauserv, bits -Force
        Purge "$env:windir\SoftwareDistribution\Download"
        Start-Service bits, wuauserv
    } else { Write-Host '   Restart pending - leaving the update download folder alone.' }
    Purge "$env:windir\Temp"
    Purge "$env:windir\System32\DriverStore\Temp"
    Purge "$env:windir\Minidump"
    Purge "$env:windir\LiveKernelReports"
    Purge "$env:ProgramData\Microsoft\Windows\WER"
    Remove-Item "$env:windir\MEMORY.DMP" -Force
    Get-ChildItem "$env:windir\Logs\CBS" -Filter *.log -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-14) } | Remove-Item -Force
    Get-ChildItem "$env:SystemDrive\Users" -Directory -Force | ForEach-Object {
        $l = "$($_.FullName)\AppData\Local"
        $r = "$($_.FullName)\AppData\Roaming"
        Purge "$l\Temp"
        Purge "$l\CrashDumps"
        Purge "$l\D3DSCache"
        Purge "$l\Microsoft\Windows\INetCache"
        Purge "$l\Microsoft\Windows\WER"
        foreach ($b in "$l\Google\Chrome\User Data", "$l\Microsoft\Edge\User Data", "$l\BraveSoftware\Brave-Browser\User Data") {
            foreach ($d in 'Cache', 'Code Cache', 'GPUCache', 'Service Worker\CacheStorage') {
                Get-ChildItem "$b\*\$d" -Directory | ForEach-Object { Purge $_.FullName }
            }
        }
        Get-ChildItem "$l\Mozilla\Firefox\Profiles\*\cache2" -Directory | ForEach-Object { Purge $_.FullName }
        foreach ($d in 'Cache', 'Code Cache', 'GPUCache') { Purge "$r\Microsoft\Teams\$d" }
        Purge "$l\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\Default\Cache"
    }
    foreach ($old in "$env:SystemDrive\Windows.old", "$env:SystemDrive\`$Windows.~BT", "$env:SystemDrive\`$Windows.~WS", "$env:SystemDrive\`$GetCurrent", "$env:SystemDrive\`$SysReset") {
        if (Test-Path $old) { Write-Host "   Removing $old (can take a few minutes)"; Remove-Tree $old }
    }
    Clear-RecycleBin -DriveLetter $sysLetter -Force
    # empty leftover folders in Program Files (system/vendor folders are never touched)
    foreach ($root in $env:ProgramFiles, ${env:ProgramFiles(x86)}) {
        Get-ChildItem $root -Directory | Where-Object {
            if ($_.Name -match $sysNames) { return $false }
            $ev = $null
            $inside = @(Get-ChildItem -LiteralPath $_.FullName -Recurse -Force -File -ErrorAction SilentlyContinue -ErrorVariable ev | Select-Object -First 1)
            ($inside.Count -eq 0) -and (-not $ev)
        } | ForEach-Object { cmd /c "rd /s /q `"$($_.FullName)`"" 2>$null | Out-Null }
    }
    # restore-point storage: cap it when the drive is nearly full (oldest points go first, newest stays)
    $vol = Get-Volume -DriveLetter $sysLetter
    if ($vol.Size -and ($vol.SizeRemaining / $vol.Size) -lt 0.15) {
        vssadmin Resize ShadowStorage /For=$env:SystemDrive /On=$env:SystemDrive /MaxSize=5% | Out-Null
        Add-Undo '# Restore-point storage was capped at 5 % of C: (change in System Properties > System Protection > Configure)'
        Write-Host '   Restore-point storage capped at 5 % (drive nearly full).'
    }
    # Windows component store
    if (Test-PendingReboot) {
        $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command "& dism.exe /Online /Cleanup-Image /StartComponentCleanup; Unregister-ScheduledTask -TaskName PCCarePost -Confirm:$false"'
        $t = New-ScheduledTaskTrigger -AtStartup
        $t.Delay = 'PT5M'
        $p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
        $ts = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 3)
        Register-ScheduledTask -TaskName 'PCCarePost' -Action $a -Trigger $t -Principal $p -Settings $ts -Force | Out-Null
        Write-Host '   Restart pending: component cleanup will run quietly 5 minutes after the restart.'
    } else {
        Write-Host '   Cleaning the Windows component store (max 20 min)...'
        $rc = Run-WithTimeout 'dism.exe' '/Online /Cleanup-Image /StartComponentCleanup' 20
    }
    $freed = [math]::Round(((Get-PSDrive $sysLetter).Free - $before) / 1GB, 2)
    Write-Host "   Freed about $freed GB on ${sysLetter}:" -ForegroundColor Green

    # ---- storage report: what is using the space
    Write-Host '   Building the storage report (max ~5 min)...'
    $lines = @("STORAGE REPORT  $(Get-Date -Format 'dd-MMM-yyyy HH:mm')", '', "TOP-LEVEL FOLDERS ON ${sysLetter}:")
    $lines += Get-ChildItem "$env:SystemDrive\" -Directory -Force | ForEach-Object {
        $st = Get-DirStat $_.FullName @() 40
        $mark = ''
        if ($st.Partial) { $mark = '  (partial - stopped at 40 s)' }
        '{0,9:N2} GB  {1}{2}' -f ($st.Bytes / 1GB), $_.FullName, $mark
    } | Sort-Object -Descending
    $lines += @('', 'USER PROFILE SIZES')
    $lines += Get-ChildItem "$env:SystemDrive\Users" -Directory -Force | ForEach-Object { $st = Get-DirStat $_.FullName @() 40; '{0,9:N2} GB  {1}' -f ($st.Bytes / 1GB), $_.FullName } | Sort-Object -Descending
    $lines += @('', 'BIGGEST FILES (> 500 MB) IN USER FOLDERS')
    $bigF = Get-FileList @("$env:SystemDrive\Users") 500MB
    $lines += $bigF | Sort-Object Length -Descending | Select-Object -First 30 | ForEach-Object { '{0,9:N2} GB  {1}' -f ($_.Length / 1GB), $_.FullName }
    $apps = foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*') {
        Get-ItemProperty $k | ForEach-Object { "$($_.DisplayName)|$($_.InstallLocation)|$($_.Publisher)" }
    }
    $appText = $apps -join "`n"
    $lines += @('', 'PROGRAM FOLDERS WITH NO MATCHING INSTALLED APP (possible leftovers - check before deleting)')
    $lines += foreach ($root in $env:ProgramFiles, ${env:ProgramFiles(x86)}) {
        Get-ChildItem $root -Directory | Where-Object { $_.Name -notmatch $sysNames -and $appText -notlike "*$($_.Name)*" } | Select-Object -ExpandProperty FullName
    }
    $lines | Out-File "$rep\storage_report.txt"
    Write-Host "   Saved: $rep\storage_report.txt"
}

# =====================================================================
#  5. APPS AND DRIVERS
# =====================================================================
function Invoke-AppsDrivers {
    Section '5. APPS AND DRIVERS (updates, broken apps, devices, old drivers)'
    Ensure-Facts; Ensure-Events
    if (-not $FC.askedWinget) { Ask-Winget }
    Ensure-RestorePoint
    # --- Windows Update keeps failing: reset its working folders first
    if ($FC.wuFail -ge 3 -and -not (Test-PendingReboot)) {
        Write-Host "   Windows Update failed $($FC.wuFail) times this week - resetting its components."
        Stop-Service wuauserv, bits, cryptsvc -Force
        foreach ($f in "$env:windir\SoftwareDistribution", "$env:windir\System32\catroot2") {
            Remove-Tree "$f.fcold"
            Rename-Item -LiteralPath $f -NewName ((Split-Path $f -Leaf) + '.fcold')
        }
        Start-Service cryptsvc, bits, wuauserv
        foreach ($f in "$env:windir\SoftwareDistribution", "$env:windir\System32\catroot2") { Remove-Tree "$f.fcold" }
    }
    # --- Windows + driver updates
    if ($DoUpdates) {
        $online = $false
        try { $online = (New-Object Net.Sockets.TcpClient).ConnectAsync('www.msftconnecttest.com', 80).Wait(4000) } catch {}
        if (-not $online) { Write-Host '   No internet - skipping Windows updates.' -ForegroundColor Yellow }
        else {
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                if (-not (Get-Module -ListAvailable PSWindowsUpdate)) {
                    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
                    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
                    Install-Module PSWindowsUpdate -Force -Scope AllUsers
                }
                $job = Start-Job {
                    Import-Module PSWindowsUpdate
                    Add-WUServiceManager -MicrosoftUpdate -Confirm:$false | Out-Null
                    Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install -IgnoreReboot | Out-String
                }
                Write-Host '   Installing Windows and driver updates (max 60 min, please wait)...'
                if (Wait-Job $job -Timeout 3600) { Receive-Job $job | Out-Host }
                else { Write-Host '   Updates took too long - stopped. Run again later.' -ForegroundColor Yellow; Stop-Job $job }
                Remove-Job $job -Force
            } catch { Write-Host '   Update step failed (policy or network). Continuing.' -ForegroundColor Yellow }
        }
    }
    Fix-Devices
    # --- old driver versions (exported to the backup first; newest and in-use are kept)
    $drv = Get-WindowsDriver -Online -All | Where-Object { $_.Driver -like 'oem*.inf' }
    $grp = $drv | Group-Object { (Split-Path $_.OriginalFileName -Leaf).ToLower() + '|' + $_.ClassName + '|' + $_.ProviderName }
    $removed = 0
    foreach ($g in $grp) {
        if ($g.Count -gt 1) {
            $olds = $g.Group | Sort-Object @{ e = { $_.Date } }, @{ e = { try { [version]$_.Version } catch { [version]'0.0' } } } -Descending | Select-Object -Skip 1
            foreach ($d in $olds) {
                Ensure-BackupDir
                $dst = "$global:BackupDir\OldDrivers\" + ($d.Driver -replace '\.inf$', '')
                New-Item $dst -ItemType Directory -Force | Out-Null
                pnputil /export-driver $d.Driver $dst | Out-Null
                if ($LASTEXITCODE -ne 0) { Remove-Item $dst -Recurse -Force; continue }
                pnputil /delete-driver $d.Driver | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    $removed++
                    Add-Undo ('pnputil /add-driver "{0}\*.inf" /install' -f $dst)
                    Write-Host "   Removed old driver: $($d.Driver) ($($d.ProviderName) $($d.Version))"
                } else { Remove-Item $dst -Recurse -Force }
            }
        }
    }
    Write-Host "   Old driver versions removed: $removed"
    # --- apps
    $brokenApps = @(Get-AppxPackage | Where-Object { "$($_.Status)" -ne 'Ok' -and $_.InstallLocation })
    foreach ($a in $brokenApps) {
        $mf = Join-Path $a.InstallLocation 'AppxManifest.xml'
        if (Test-Path -LiteralPath $mf) {
            Add-AppxPackage -DisableDevelopmentMode -Register $mf
            Write-Host "   Re-registered Store app: $($a.Name) (was $($a.Status))"
        }
    }
    if ($brokenApps.Count -eq 0) { Write-Host '   No broken Store apps.' }
    if ($FC.doWinget) {
        Write-Host '   Updating apps with winget (max 40 min)...'
        $rc = Run-WithTimeout $FC.wg.Source 'upgrade --all --silent --include-unknown --accept-source-agreements --accept-package-agreements' 40
    } elseif (-not $FC.wg) { Write-Host '   winget not found - app updates skipped (install "App Installer" from the Microsoft Store).' }
    else { Write-Host '   App updates skipped (you answered N).' }
    $FC.askedWinget = $false
}

# =====================================================================
#  6. NETWORK REPAIR
# =====================================================================
function Test-Host($h) {
    $r = @(Test-Connection -ComputerName $h -Count 4 -ErrorAction SilentlyContinue)
    $avg = $null
    if ($r.Count -gt 0) { $avg = [math]::Round(($r | Measure-Object ResponseTime -Average).Average) }
    [pscustomobject]@{ Loss = (4 - $r.Count) * 25; Ms = $avg }
}
function Invoke-NetRepair {
    Section '6. NETWORK REPAIR'
    Ensure-RestorePoint
    foreach ($na in (Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' })) {
        Write-Host ("   Adapter {0}: {1}, link {2}" -f $na.Name, $na.InterfaceDescription, $na.LinkSpeed)
        if ($na.LinkSpeed -match '^(10|100) Mbps') { Add-Finding 'Medium' "Adapter '$($na.Name)' is linked at only $($na.LinkSpeed)" 'A bad cable, old switch port or 4-wire cable limits speed. Try another cable/port.' }
    }
    $gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop
    $tg = $null
    if ($gw) { $tg = Test-Host $gw; Write-Host ("   Gateway {0}: loss {1} %, {2} ms" -f $gw, $tg.Loss, $tg.Ms) } else { Write-Host '   No default gateway found.' -ForegroundColor Yellow }
    $ti = Test-Host '8.8.8.8'
    Write-Host ("   Internet (8.8.8.8): loss {0} %, {1} ms" -f $ti.Loss, $ti.Ms)
    $dnsOk = $false
    try { [void][Net.Dns]::GetHostAddresses('www.microsoft.com'); $dnsOk = $true } catch {}
    Write-Host "   DNS name lookup working: $dnsOk"
    ipconfig /flushdns | Out-Null
    ipconfig /registerdns | Out-Null
    $fault = $false
    if (-not $gw -or $tg.Loss -eq 100) {
        $fault = $true
        Write-Host '   Gateway unreachable - restarting network adapters and renewing the address.' -ForegroundColor Yellow
        Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' } | Restart-NetAdapter
        Start-Sleep -Seconds 8
        ipconfig /renew | Out-Null
        $gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop
        if ($gw) { $tg = Test-Host $gw; Write-Host ("   After restart - gateway {0}: loss {1} %" -f $gw, $tg.Loss) }
        if (-not $gw -or $tg.Loss -eq 100) { Add-Finding 'High' 'Still no connection to the router/gateway' 'Check the cable, switch port, Wi-Fi password or router. This is outside the PC.' }
    } elseif ($tg.Loss -ge 25) {
        Add-Finding 'Medium' "Packet loss to the gateway ($($tg.Loss) %)" 'Bad cable, weak Wi-Fi signal or a failing switch port.'
    }
    if (($gw -and $tg.Loss -lt 100) -and ($ti.Loss -eq 100)) { Add-Finding 'Medium' 'LAN works but the internet is unreachable' 'Problem is at the router/ISP, or a firewall blocks ping.' }
    if (($ti.Loss -lt 100) -and -not $dnsOk) { $fault = $true; Add-Finding 'Medium' 'Internet works but DNS lookups fail' 'Set the adapter DNS to your router or 8.8.8.8 / 1.1.1.1.' }
    if ($ResetNetwork -or $fault) {
        netsh winsock reset | Out-Null
        Write-Host '   Winsock reset (takes effect after the restart).'
    }
    if ($FullNetReset) {
        netsh int ip reset | Out-Null
        Write-Host '   TCP/IP reset done - STATIC IP ADDRESSES WERE CLEARED. Re-enter them after the restart.' -ForegroundColor Yellow
    }
    # proxy and hosts file (often left behind by old software or malware)
    $ie = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    if ($ie.ProxyEnable -eq 1) { Add-Finding 'Low' "A proxy is set for this user: $($ie.ProxyServer)" 'If your office does not use a proxy, turn it off in Settings > Network > Proxy.' }
    $hostsExtra = @(Get-Content "$env:windir\System32\drivers\etc\hosts" | Where-Object { $_.Trim() -and $_ -notmatch '^\s*#' -and $_ -notmatch 'localhost' })
    if ($hostsExtra.Count -gt 0) { Add-Finding 'Low' "The hosts file has $($hostsExtra.Count) custom entries" 'Check them (menu 11 > hosts editor). Unknown entries can redirect or block websites.' }
}

# =====================================================================
#  7. PRINTER AND SHARING REPAIR
# =====================================================================
function Invoke-PrintRepair {
    Section '7. PRINTER AND SHARING REPAIR'
    if (-not (Get-Service Spooler)) { Write-Host '   Print Spooler service not found.'; return }
    Ensure-RestorePoint
    $shared = @(Get-Printer | Where-Object { $_.Shared })
    $remote = @(Get-Printer | Where-Object { "$($_.Type)" -eq 'Connection' })
    Write-Host "   Printers: $($shared.Count) shared from this PC, $($remote.Count) connected from other PCs."
    $spool = "$env:windir\System32\spool\PRINTERS"
    $stuck = @(Get-ChildItem -LiteralPath $spool -File -Force | Where-Object { $_.LastWriteTime -lt (Get-Date).AddHours(-1) })
    if ($stuck.Count -gt 0) {
        Stop-Service Spooler -Force
        $stuck | Remove-Item -Force
        Write-Host "   Removed $($stuck.Count) stuck print-job files."
    }
    Set-SvcTracked 'Spooler' 'Automatic'
    if ($shared.Count -gt 0 -or $remote.Count -gt 0) {
        Set-SvcTracked 'fdPHost'  'Manual'
        Set-SvcTracked 'FDResPub' 'Automatic'
        Set-SvcTracked 'SSDPSRV'  'Manual'
        foreach ($np in @(Get-NetConnectionProfile | Where-Object { "$($_.NetworkCategory)" -eq 'Public' })) {
            Add-Finding 'Medium' "Network '$($np.Name)' is set to Public" 'Sharing is blocked on Public networks. If this is your office LAN: Settings > Network > Properties > Private.'
        }
    }
    if ($shared.Count -gt 0) {
        Set-SvcTracked 'LanmanServer' 'Automatic'
        # firewall: File and Printer Sharing (-28502) and Network Discovery (-32752), Private/Domain rules only
        foreach ($g in '@FirewallAPI.dll,-28502', '@FirewallAPI.dll,-32752') {
            $rules = @(Get-NetFirewallRule -Group $g | Where-Object { "$($_.Enabled)" -eq 'False' -and "$($_.Profile)" -match 'Private' -and "$($_.Profile)" -notmatch 'Public' })
            foreach ($r in $rules) {
                Enable-NetFirewallRule -Name $r.Name
                Add-Undo "Disable-NetFirewallRule -Name '$($r.Name)'"
            }
            if ($rules.Count -gt 0) { Write-Host "   Firewall: enabled $($rules.Count) sharing rules (Private network)." }
        }
    }
    if ($PrinterCompatFix) {
        Set-RegTracked 'HKLM:\SYSTEM\CurrentControlSet\Control\Print' 'RpcAuthnLevelPrivacyEnabled' 0 'DWord'
        $rpc = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC'
        Set-RegTracked $rpc 'RpcUseNamedPipeProtocol' 1 'DWord'
        Set-RegTracked $rpc 'RpcProtocols' 7 'DWord'
        Restart-Service Spooler -Force
        Write-Host '   Printer-sharing registry fixes applied (undo with UNDO_SETTINGS.bat).'
    } else { Write-Host '   Registry fixes for errors 0x0000011b / 0x00000709 are OFF (set $PrinterCompatFix = $true to apply).' }
}

# =====================================================================
#  8. RAM CHECK AND REPAIR
# =====================================================================
function Invoke-RamCheck {
    Section '8. RAM CHECK AND REPAIR'
    Ensure-Facts; Ensure-Events
    $mods  = @(Get-CimInstance Win32_PhysicalMemory)
    $slots = (Get-CimInstance Win32_PhysicalMemoryArray | Measure-Object MemoryDevices -Sum).Sum
    Write-Host "   Installed: $($FC.ramGB) GB in $($mods.Count) of $slots slots"
    foreach ($m in $mods) { Write-Host ("     {0}: {1} GB, {2} MHz, {3} {4}" -f $m.DeviceLocator, [math]::Round($m.Capacity / 1GB), $m.Speed, $m.Manufacturer, $m.PartNumber) }
    if ($mods.Count -lt $slots -and $FC.ramGB -lt 8) { Add-Finding 'Medium' "$($slots - $mods.Count) free RAM slot(s) and only $($FC.ramGB) GB installed" 'Adding a matching module is a cheap, effective upgrade.' }
    $os = Get-CimInstance Win32_OperatingSystem
    $usedPct   = [math]::Round((1 - $os.FreePhysicalMemory / $os.TotalVisibleMemorySize) * 100)
    $commitPct = [math]::Round((1 - $os.FreeVirtualMemory / $os.TotalVirtualMemorySize) * 100)
    Write-Host "   In use now: $usedPct % of RAM | commit charge: $commitPct % of the limit"
    if ($commitPct -ge 90) { Add-Finding 'High' "Commit charge is $commitPct % of the limit" 'Apps will crash with out-of-memory errors. Close heavy apps; menu 3 fixes the page file; add RAM.' }
    Write-Host '   Biggest memory users:'
    $procs = Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10
    foreach ($pr in $procs) { Write-Host ("     {0,-28} {1,7:N0} MB   handles {2}" -f $pr.ProcessName, ($pr.WorkingSet64 / 1MB), $pr.HandleCount) }
    foreach ($pr in (Get-Process | Where-Object { $_.HandleCount -gt 50000 })) { Add-Finding 'Medium' "$($pr.ProcessName) holds $($pr.HandleCount) handles (a leak)" 'Restart or update that app; leaks make the PC slower the longer it runs.' }
    $last = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-MemoryDiagnostics-Results' } -MaxEvents 1
    if ($last) {
        Write-Host ("   Last RAM test ({0:dd-MMM-yyyy}): {1}" -f $last.TimeCreated, (($last.Message -split "`n")[0]).Trim())
        if ($last.Message -match 'hardware problems were detected|detected hardware') { Add-Finding 'High' 'The last RAM test found hardware errors' 'Reseat or replace the RAM module.' }
    } else { Write-Host '   No RAM hardware test has been run on this PC yet.' }
    Write-Host '   Note: "RAM booster" tools only push memory to disk, which makes a PC slower. The real fixes are above.' -ForegroundColor DarkGray
    $suspect = ($FC.wheaBad -gt 0) -or ($FC.bsod -ge 2)
    if ($FC.auto -or $Ui) {
        if ($suspect) { Ensure-RestorePoint; Schedule-MemTest }
        else { Write-Host '   No sign of faulty RAM in the logs. To test anyway use "Schedule a RAM hardware test".' }
    }
    elseif (Ask-YN '   Schedule a RAM hardware test at the next restart?') { Ensure-RestorePoint; Schedule-MemTest }
}

# =====================================================================
#  9. FILE TOOLS
# =====================================================================
function Invoke-Duplicates {
    Write-Host '   Where to look?  1 = my Desktop/Documents/Downloads/Pictures/Videos/Music (fast)   2 = all drives   or type a folder path'
    $w = (Read-Host '   Choice').Trim().Trim('"')
    if ($w -eq '1' -or -not $w) { $roots = 'Desktop', 'Documents', 'Downloads', 'Pictures', 'Videos', 'Music' | ForEach-Object { Join-Path $env:USERPROFILE $_ } }
    elseif ($w -eq '2') { $roots = @(Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter } | ForEach-Object { "$($_.DriveLetter):\" }) }
    elseif (Test-Path -LiteralPath $w -PathType Container) { $roots = @($w) }
    else { Write-Host '   Folder not found.' -ForegroundColor Yellow; return }
    Write-Host "   Listing files of $DupMinMB MB and larger (system and program folders are skipped)..."
    $files = Get-FileList $roots ($DupMinMB * 1MB)
    Write-Host "   $($files.Count) files. Comparing..."
    $bySize = @{}
    foreach ($f in $files) {
        $k = $f.Length
        if (-not $bySize.ContainsKey($k)) { $bySize[$k] = New-Object 'Collections.Generic.List[IO.FileInfo]' }
        $bySize[$k].Add($f)
    }
    $groups = New-Object 'Collections.Generic.List[object]'
    foreach ($set in $bySize.Values) {
        if ($set.Count -lt 2) { continue }
        $part = @{}
        foreach ($f in $set) {
            $k = Get-FileKey $f.FullName $f.Length $false
            if (-not $k) { continue }
            if (-not $part.ContainsKey($k)) { $part[$k] = New-Object 'Collections.Generic.List[IO.FileInfo]' }
            $part[$k].Add($f)
        }
        foreach ($ps in $part.Values) {
            if ($ps.Count -lt 2) { continue }
            if ($ps[0].Length -le 1MB) { $groups.Add($ps); continue }
            $fullH = @{}
            foreach ($f in $ps) {
                $k = Get-FileKey $f.FullName $f.Length $true
                if (-not $k) { continue }
                if (-not $fullH.ContainsKey($k)) { $fullH[$k] = New-Object 'Collections.Generic.List[IO.FileInfo]' }
                $fullH[$k].Add($f)
            }
            foreach ($qs in $fullH.Values) { if ($qs.Count -ge 2) { $groups.Add($qs) } }
        }
    }
    if ($groups.Count -eq 0) { Write-Host '   No duplicate files found.' -ForegroundColor Green; return }
    $sorted = @($groups | Sort-Object { $_[0].Length * ($_.Count - 1) } -Descending)
    $rows = New-Object 'Collections.Generic.List[object]'
    $dupes = New-Object 'Collections.Generic.List[IO.FileInfo]'
    $wasted = 0L; $gi = 0
    foreach ($g in $sorted) {
        $gi++
        $ord = @($g | Sort-Object LastWriteTime -Descending)
        for ($i = 0; $i -lt $ord.Count; $i++) {
            $act = 'duplicate'
            if ($i -eq 0) { $act = 'KEEP (newest)' } else { $wasted += $ord[$i].Length; $dupes.Add($ord[$i]) }
            $rows.Add([pscustomobject]@{ Group = $gi; Action = $act; SizeMB = [math]::Round($ord[$i].Length / 1MB, 2); Modified = $ord[$i].LastWriteTime.ToString('yyyy-MM-dd HH:mm'); Path = $ord[$i].FullName })
        }
    }
    $csv = "$rep\duplicates_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
    $rows | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
    Write-Host ("   {0} duplicate groups, {1} extra copies, {2:N2} GB could be freed." -f $groups.Count, $dupes.Count, ($wasted / 1GB)) -ForegroundColor Green
    Write-Host '   Biggest groups (newest copy first):'
    foreach ($r in ($rows | Where-Object { $_.Group -le 8 })) { Write-Host ("     [{0}] {1,-14} {2,9:N1} MB  {3}  {4}" -f $r.Group, $r.Action, $r.SizeMB, $r.Modified, $r.Path) }
    Write-Host "   Full list: $csv"
    $ans = Read-Host '   Type MOVE to move the extra copies into <drive>:\PCCare_Duplicates (reversible, nothing is deleted). Enter = leave everything'
    if ($ans -ne 'MOVE') { return }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $moved = 0; $logs = @{}
    foreach ($f in $dupes) {
        if ($f.FullName -notmatch '^[A-Za-z]:\\') { continue }
        $base = $f.FullName.Substring(0, 3) + "PCCare_Duplicates\$stamp"
        $log  = "$base\moves.csv"
        if (-not $logs.ContainsKey($log)) { New-Item $base -ItemType Directory -Force | Out-Null; $logs[$log] = $true; Register-MoveLog $log }
        if (Move-Logged $f.FullName (Join-Path $base $f.FullName.Substring(3)) $log) { $moved++ }
    }
    Write-Host "   Moved $moved files. Check your programs still work, then delete the PCCare_Duplicates folder yourself. Undo: File tools > 4." -ForegroundColor Green
}
function Invoke-CategoryReport {
    $out = @("FILES BY CATEGORY  $(Get-Date -Format 'dd-MMM-yyyy HH:mm')   (Windows, Program Files and AppData are not counted)")
    $allBig = New-Object 'Collections.Generic.List[IO.FileInfo]'
    foreach ($v in (Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter })) {
        $root = "$($v.DriveLetter):\"
        Write-Host "   Reading drive $root (max 10 min)..."
        $agg = @{}
        $clock = [Diagnostics.Stopwatch]::StartNew(); $partial = $false
        $stack = New-Object 'Collections.Generic.Stack[string]'
        $stack.Push($root)
        while ($stack.Count -gt 0) {
            if ($clock.Elapsed.TotalMinutes -gt 10) { $partial = $true; break }
            $d = $stack.Pop()
            try {
                foreach ($e in ([IO.DirectoryInfo]$d).EnumerateFileSystemInfos()) {
                    if ($e.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
                    if ($e -is [IO.DirectoryInfo]) { if ($e.Name -notmatch $skipDirRx) { $stack.Push($e.FullName) }; continue }
                    $c = $extCat[$e.Extension.ToLower()]
                    if (-not $c) { $c = 'Other' }
                    if (-not $agg.ContainsKey($c)) { $agg[$c] = @(0L, 0L) }
                    $agg[$c][0] += 1; $agg[$c][1] += $e.Length
                    if ($e.Length -ge 50MB) { $allBig.Add($e) }
                }
            } catch {}
        }
        $out += ''
        $hdr = "DRIVE $root"
        if ($partial) { $hdr += '   (partial - stopped at 10 minutes)' }
        $out += $hdr
        $out += $agg.Keys | Sort-Object { $agg[$_][1] } -Descending | ForEach-Object { '  {0,-11} {1,9:N0} files  {2,9:N2} GB' -f $_, $agg[$_][0], ($agg[$_][1] / 1GB) }
        $out | Select-Object -Last ($agg.Count + 1) | ForEach-Object { Write-Host "   $_" }
    }
    $out | Out-File "$rep\files_by_category.txt"
    $allBig | Sort-Object Length -Descending | ForEach-Object {
        $c = $extCat[$_.Extension.ToLower()]
        if (-not $c) { $c = 'Other' }
        [pscustomobject]@{ SizeMB = [math]::Round($_.Length / 1MB); Category = $c; Modified = $_.LastWriteTime.ToString('yyyy-MM-dd'); Path = $_.FullName }
    } | Export-Csv -LiteralPath "$rep\large_files_sorted.csv" -NoTypeInformation -Encoding UTF8
    Write-Host "   Saved: $rep\files_by_category.txt and large_files_sorted.csv (every file over 50 MB, biggest first)"
}
function Invoke-Organizer {
    $folder = Read-Folder '   Folder to organize (only its loose files are sorted; sub-folders are not touched)' (Join-Path $env:USERPROFILE 'Downloads')
    if (-not $folder) { return }
    $block = @($env:SystemDrive + '\', $env:windir, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, "$env:SystemDrive\Users", $env:USERPROFILE) | ForEach-Object { "$_".TrimEnd('\').ToLower() }
    if ($block -contains $folder.TrimEnd('\').ToLower() -or $folder -match '\\(Windows|Program Files|ProgramData|AppData)(\\|$)') { Write-Host '   That is a system or program folder - not organizing it.' -ForegroundColor Red; return }
    $items = @(Get-ChildItem -LiteralPath $folder -File | Where-Object { $_.Extension -notin '.lnk', '.url', '.ini' -and $_.Name -notlike '_PCCare_*' })
    if ($items.Count -eq 0) { Write-Host '   No loose files there.'; return }
    $prev = $items | Group-Object { $c = $extCat[$_.Extension.ToLower()]; if ($c) { $c } else { 'Other' } }
    foreach ($g in $prev) { Write-Host ("     {0,-11} {1} files" -f $g.Name, $g.Count) }
    if (-not (Ask-YN "   Move these $($items.Count) files into category sub-folders of $folder ?")) { return }
    $log = Join-Path $folder ("_PCCare_organize_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    Register-MoveLog $log
    $n = 0
    foreach ($f in $items) {
        $c = $extCat[$f.Extension.ToLower()]
        if (-not $c) { $c = 'Other' }
        $to = Get-FreeName (Join-Path (Join-Path $folder $c) $f.Name)
        if ($to -and (Move-Logged $f.FullName $to $log)) { $n++ }
    }
    Write-Host "   Sorted $n files. Undo: File tools > 4." -ForegroundColor Green
}
function Invoke-UndoMoves {
    $idx = "$env:ProgramData\PCCare\move_logs.txt"
    $logs = @(Get-Content $idx | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique)
    if ($logs.Count -eq 0) { Write-Host '   Nothing to undo.'; return }
    for ($i = 0; $i -lt $logs.Count; $i++) { Write-Host ("     [{0}] {1}" -f ($i + 1), $logs[$i]) }
    $k = Read-Host '   Number to undo (Enter = cancel)'
    if ($k -notmatch '^\d+$' -or [int]$k -lt 1 -or [int]$k -gt $logs.Count) { return }
    $log = $logs[[int]$k - 1]
    $rowsU = @(Import-Csv -LiteralPath $log)
    [array]::Reverse($rowsU)
    $n = 0
    foreach ($r in $rowsU) {
        if ((Test-Path -LiteralPath $r.To) -and -not (Test-Path -LiteralPath $r.From)) {
            New-Item (Split-Path $r.From -Parent) -ItemType Directory -Force | Out-Null
            Move-Item -LiteralPath $r.To -Destination $r.From
            if (Test-Path -LiteralPath $r.From) { $n++ }
        }
    }
    Write-Host "   Put back $n of $($rowsU.Count) files." -ForegroundColor Green
    if ($n -eq $rowsU.Count) { Remove-Item -LiteralPath $log -Force }
}
function Invoke-FileTools {
    $go = $true
    while ($go) {
        Write-Host ''
        Write-Host '--- 9. FILE TOOLS ---' -ForegroundColor Cyan
        Write-Host '  1  Find duplicate files (newest copy marked KEEP; optional reversible move)'
        Write-Host '  2  Files by category on every drive + list of all large files, sorted'
        Write-Host '  3  Organize one folder into category sub-folders (Documents, Pictures, Videos...)'
        Write-Host '  4  Undo a duplicate move, organize or bulk rename'
        Write-Host '  Enter = back'
        switch ((Read-Host 'Choose').Trim()) {
            '1' { Invoke-Duplicates }
            '2' { Invoke-CategoryReport }
            '3' { Invoke-Organizer }
            '4' { Invoke-UndoMoves }
            default { $go = $false }
        }
    }
}

# =====================================================================
#  10. SECURITY CHECK
# =====================================================================
function Invoke-Security {
    Section '10. SECURITY CHECK'
    $avs = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct)
    $third = $false
    foreach ($a in $avs) {
        $hex = '{0:x6}' -f [int]$a.productState
        $on  = $hex.Substring(2, 2) -in '10', '11'
        $upd = $hex.Substring(4, 2) -eq '00'
        Write-Host ("   {0}: real-time {1}, definitions {2}" -f $a.displayName, $(if ($on) { 'ON' } else { 'off' }), $(if ($upd) { 'up to date' } else { 'OUT OF DATE' }))
        if ($on -and $a.displayName -notmatch 'Defender') { $third = $true }
        if ($on -and -not $upd) { Add-Finding 'Medium' "$($a.displayName) definitions are out of date" 'Open it and update.' }
    }
    if ($avs.Count -eq 0) { Write-Host '   No antivirus registered with Windows Security Center (normal on Windows Server).' }
    $mp = Get-MpComputerStatus
    if ($mp) { Write-Host "   Microsoft Defender mode: $($mp.AMRunningMode) | real-time: $($mp.RealTimeProtectionEnabled)" }
    if ($third) {
        if ($mp -and $mp.RealTimeProtectionEnabled) { Add-Finding 'Medium' 'Defender real-time protection is ON together with another antivirus' 'Two real-time scanners slow the PC. Normally Defender switches itself off; reinstall/repair the other antivirus so it registers properly.' }
        else { Write-Host '   Good: your antivirus is active and Defender has stepped aside automatically. Defender cannot and need not be uninstalled.' -ForegroundColor Green }
        Write-Host '   Run a full scan from your antivirus console (this script cannot start a third-party scan).'
    } elseif ($mp -and $mp.AMServiceEnabled -and $mp.RealTimeProtectionEnabled) {
        Update-MpSignature
        $job = Start-Job { Start-MpScan -ScanType QuickScan }
        Write-Host '   Defender quick scan running (max 20 min)...'
        if (-not (Wait-Job $job -Timeout 1200)) {
            Write-Host '   Scan took too long - cancelled.' -ForegroundColor Yellow
            & "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -Cancel | Out-Null
            Stop-Job $job
        }
        Remove-Job $job -Force
        $threats = @(Get-MpThreat | Where-Object { $_.IsActive })
        if ($threats.Count -gt 0) { Add-Finding 'High' ("Defender reports active threats: " + (($threats | Select-Object -First 5 | ForEach-Object { $_.ThreatName }) -join ', ')) 'Open Windows Security > Protection history, remove them, then run a Full scan.' }
        else { Write-Host '   No active threats found.' -ForegroundColor Green }
    } else { Add-Finding 'High' 'No antivirus has real-time protection ON' 'Turn on your antivirus or Windows Security real-time protection.' }
    foreach ($fp in (Get-NetFirewallProfile | Where-Object { -not $_.Enabled })) {
        if (-not $third) { Add-Finding 'Medium' "Windows Firewall is off for the $($fp.Name) profile" 'Turn it on unless another firewall product manages it.' }
    }
    if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA -eq 0) { Add-Finding 'Medium' 'User Account Control (UAC) is turned off' 'Turn it on in Control Panel > User Accounts.' }
}

# =====================================================================
#  11. TOOLBOX (PowerToys-style tools that work without a GUI)
# =====================================================================
function Tool-BulkRename {
    $folder = Read-Folder '   Folder with the files to rename' (Join-Path $env:USERPROFILE 'Downloads')
    if (-not $folder) { return }
    $find = Read-Host '   Text to find in the file names'
    if (-not $find) { return }
    $repl = Read-Host '   Replace with (Enter = remove it)'
    $useRx = Ask-YN '   Is the "find" text a regular expression?'
    $gp = @{ LiteralPath = $folder; File = $true }
    if (Ask-YN '   Include sub-folders?') { $gp.Recurse = $true }
    $bad = [IO.Path]::GetInvalidFileNameChars()
    $planR = @()
    foreach ($f in (Get-ChildItem @gp)) {
        try { if ($useRx) { $nn = [regex]::Replace($f.Name, $find, $repl) } else { $nn = $f.Name.Replace($find, $repl) } } catch { Write-Host "   Bad pattern: $_" -ForegroundColor Red; return }
        if ($nn -and $nn -ne $f.Name -and $nn.IndexOfAny($bad) -lt 0) { $planR += [pscustomobject]@{ From = $f.FullName; To = (Join-Path $f.DirectoryName $nn) } }
    }
    if ($planR.Count -eq 0) { Write-Host '   No file names match (plain text search is case-sensitive).'; return }
    foreach ($r in ($planR | Select-Object -First 12)) { Write-Host ("     {0}  ->  {1}" -f (Split-Path $r.From -Leaf), (Split-Path $r.To -Leaf)) }
    if (-not (Ask-YN "   Rename $($planR.Count) files?")) { return }
    $log = Join-Path $folder ("_PCCare_rename_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    Register-MoveLog $log
    $n = 0
    foreach ($r in $planR) { if (-not (Test-Path -LiteralPath $r.To)) { if (Move-Logged $r.From $r.To $log) { $n++ } } }
    Write-Host "   Renamed $n files. Undo: menu 9 > 4." -ForegroundColor Green
}
function Tool-ImageResize {
    $folder = Read-Folder '   Folder with pictures (jpg, png, bmp)' (Join-Path $env:USERPROFILE 'Pictures')
    if (-not $folder) { return }
    $mx = Read-Host '   Longest side in pixels [Enter = 1920]'
    if ($mx -notmatch '^\d+$') { $mx = 1920 }
    $mx = [int]$mx
    Add-Type -AssemblyName System.Drawing
    $outDir = Join-Path $folder "Resized_$mx"
    New-Item $outDir -ItemType Directory -Force | Out-Null
    $enc = [Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' }
    $n = 0
    foreach ($f in (Get-ChildItem -LiteralPath $folder -File | Where-Object { $_.Extension -match '^\.(jpe?g|png|bmp)$' })) {
        try {
            $img = [Drawing.Image]::FromFile($f.FullName)
            $ratio = [math]::Min($mx / $img.Width, $mx / $img.Height)
            if ($ratio -ge 1) { $img.Dispose(); continue }
            $w = [int]($img.Width * $ratio); $h = [int]($img.Height * $ratio)
            $bmp = New-Object Drawing.Bitmap($w, $h)
            $gr = [Drawing.Graphics]::FromImage($bmp)
            $gr.InterpolationMode = 'HighQualityBicubic'
            $gr.DrawImage($img, 0, 0, $w, $h)
            $outF = Join-Path $outDir $f.Name
            if ($f.Extension -match 'jpe?g') {
                $ep = New-Object Drawing.Imaging.EncoderParameters(1)
                $ep.Param[0] = New-Object Drawing.Imaging.EncoderParameter([Drawing.Imaging.Encoder]::Quality, [long]85)
                $bmp.Save($outF, $enc, $ep)
            } else { $bmp.Save($outF, $img.RawFormat) }
            $gr.Dispose(); $bmp.Dispose(); $img.Dispose()
            $n++
        } catch { Write-Host "   Skipped $($f.Name): $_" -ForegroundColor Yellow }
    }
    Write-Host "   $n resized copies written to $outDir (originals untouched)." -ForegroundColor Green
}
function Tool-Awake {
    $awake = "$env:ProgramData\PCCare\fc_awake.ps1"
    $run = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like '*fc_awake.ps1*' })
    if ($run.Count -gt 0) {
        if (Ask-YN '   Keep-awake is running. Stop it?') { $run | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }; Write-Host '   Stopped.' }
        return
    }
    $hrs = Read-Host '   Keep the PC and screen awake for how many hours? [Enter = 2]'
    if ($hrs -notmatch '^\d+(\.\d+)?$') { $hrs = '2' }
    New-Item "$env:ProgramData\PCCare" -ItemType Directory -Force | Out-Null
    Set-Content -Path $awake -Value $awakeText -Encoding ASCII
    Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$awake`" -Hours $hrs"
    Write-Host "   PC will not sleep for $hrs hours (or until restart). Run this tool again to stop it." -ForegroundColor Green
}
function Tool-Locksmith {
    $f = (Read-Host '   Full path of the file that cannot be deleted/renamed').Trim().Trim('"')
    if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { Write-Host '   File not found (this works on files, not folders).' -ForegroundColor Yellow; return }
    if (-not ('FcLock' -as [type])) { try { Add-Type -TypeDefinition $lockCode -ErrorAction Stop } catch { Write-Host "   This tool could not load on this PC: $_" -ForegroundColor Red; return } }
    $who = @([FcLock]::Who($f))
    if ($who.Count -eq 0) { Write-Host '   No program is holding that file open.' -ForegroundColor Green; return }
    Write-Host '   Held open by (process id, name):'
    $who | ForEach-Object { Write-Host "     $_" }
    if (Ask-YN '   Close those programs now? (unsaved work in them is lost)') { foreach ($w in $who) { Stop-Process -Id ([int]($w -split ' ')[0]) -Force } }
}
function Tool-Hash {
    $f = (Read-Host '   Full path of the file').Trim().Trim('"')
    if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { Write-Host '   File not found.' -ForegroundColor Yellow; return }
    foreach ($alg in 'SHA256', 'SHA1', 'MD5') { Write-Host ("   {0,-7} {1}" -f $alg, (Get-FileHash -LiteralPath $f -Algorithm $alg).Hash) }
}
function Invoke-Toolbox {
    $go = $true
    while ($go) {
        Write-Host ''
        Write-Host '--- 11. TOOLBOX ---' -ForegroundColor Cyan
        Write-Host '  1  Bulk rename files (find/replace, regex)          [PowerRename]'
        Write-Host '  2  Resize pictures in a folder                      [Image Resizer]'
        Write-Host '  3  Keep the PC awake for N hours / stop             [Awake]'
        Write-Host '  4  Find and close what is locking a file            [File Locksmith]'
        Write-Host '  5  Edit the hosts file                              [Hosts File Editor]'
        Write-Host '  6  Edit environment variables                       [Environment Variables]'
        Write-Host '  7  File checksum (SHA256 / SHA1 / MD5)              [File hash]'
        Write-Host '  Enter = back'
        Write-Host '  (FancyZones, Color Picker, Keyboard Manager, PowerToys Run, Text Extractor, Screen Ruler' -ForegroundColor DarkGray
        Write-Host '   are on-screen graphical tools - a script cannot provide them.)' -ForegroundColor DarkGray
        switch ((Read-Host 'Choose').Trim()) {
            '1' { Tool-BulkRename }
            '2' { Tool-ImageResize }
            '3' { Tool-Awake }
            '4' { Tool-Locksmith }
            '5' { Start-Process notepad.exe "$env:windir\System32\drivers\etc\hosts" }
            '6' { Start-Process rundll32.exe 'sysdm.cpl,EditEnvironmentVariables' }
            '7' { Tool-Hash }
            default { $go = $false }
        }
    }
}

# =====================================================================
#  12. REMOVE USER ACCOUNTS (backup first, with undo)
# =====================================================================
function Invoke-RemoveUsers {
    Section '12. REMOVE USER ACCOUNTS (each is backed up and verified first)'
    Ensure-Facts
    $plan = @()
    $quser    = (quser 2>&1 | Out-String)
    $profiles = Get-CimInstance Win32_UserProfile
    $protectedNames = @($me, 'Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount')
    foreach ($u in $removeUsers) {
        $path    = Join-Path "$env:SystemDrive\Users" $u
        $acct    = Get-LocalUser -Name $u
        $hasProf = Test-Path $path
        if (-not $acct -and -not $hasProf) { continue }
        $rx  = '(^|\\)' + [regex]::Escape($u) + '$'
        $svc = @($FC.allSvc   | Where-Object { $_.StartName -match $rx })
        $tsk = @($FC.allTasks | Where-Object { $_.Principal.UserId -match $rx })
        $blocked = $null
        if ($protectedNames -contains $u) { $blocked = 'protected account' }
        elseif ($svc.Count -gt 0 -or $tsk.Count -gt 0) { $blocked = 'still used by: ' + ((@($svc.Name) + @($tsk.TaskName) | Where-Object { $_ }) -join ', ') }
        elseif ($quser -match ('(?m)^\s*>?\s*' + [regex]::Escape($u) + '\s')) { $blocked = 'currently logged in' }
        elseif ($profiles | Where-Object { $_.LocalPath -ieq $path -and $_.Loaded }) { $blocked = 'profile is loaded - restart the PC and run again' }
        $st = [pscustomobject]@{ Files = 0L; Bytes = 0L }
        if (-not $blocked -and $hasProf) { Write-Host "   Measuring $u ..."; $st = Get-DirStat $path (Get-BackupExcludes $path) }
        $plan += [pscustomobject]@{ Name = $u; Path = $path; HasAccount = [bool]$acct; HasProfile = $hasProf; Files = $st.Files; Bytes = $st.Bytes; Blocked = $blocked }
    }
    if ($plan.Count -eq 0) { Write-Host '   None of the accounts listed in $removeUsers exist on this PC.'; return }
    if (-not $global:BackupDir) {
        $need = ($plan | Where-Object { -not $_.Blocked } | Measure-Object Bytes -Sum).Sum
        $global:BackupBase = Select-BackupBase ([long]$need)
    }
    foreach ($p in $plan) {
        if ($p.Blocked) { Write-Host ("   - {0,-22} SKIPPED: {1}" -f $p.Name, $p.Blocked) -ForegroundColor Red }
        else { Write-Host ("   - {0,-22} {1,7:N2} GB" -f $p.Name, ($p.Bytes / 1GB)) -ForegroundColor Yellow }
    }
    Write-Host "   Backup + undo folder: $global:BackupBase\Backup_<date-time>   (UNDO_RESTORE_USERS.bat inside)"
    if ((Read-Host '   Type YES to back up and then delete these accounts') -ne 'YES') { Write-Host '   Cancelled.'; return }
    Ensure-RestorePoint
    foreach ($it in $plan) {
        $u = $it.Name; $path = $it.Path
        if ($it.Blocked) { Write-Host "SKIPPED $u - $($it.Blocked)" -ForegroundColor Red; continue }
        Ensure-BackupDir
        $ud = Join-Path $global:BackupDir $u
        New-Item $ud -ItemType Directory -Force | Out-Null
        $acct = Get-LocalUser -Name $u
        $prof = Get-CimInstance Win32_UserProfile | Where-Object { $_.LocalPath -ieq $path } | Select-Object -First 1
        $sid  = $null
        if ($acct) { $sid = $acct.SID.Value } elseif ($prof) { $sid = $prof.SID }
        $groups = @()
        if ($acct) {
            try {
                $usr = [ADSI]"WinNT://./$u,user"
                foreach ($g in $usr.psbase.Invoke('Groups')) { $groups += $g.GetType().InvokeMember('Name', 'GetProperty', $null, $g, $null) }
            } catch {}
        }
        $meta = [ordered]@{
            name = $u; hadAccount = [bool]$acct; fullName = "$($acct.FullName)"; description = "$($acct.Description)"
            enabled = [bool]$acct.Enabled; oldSid = "$sid"; principalSource = "$($acct.PrincipalSource)"; groups = $groups
            profilePath = $path; hadProfile = [bool]$it.HasProfile; files = $it.Files; bytes = $it.Bytes
            backedUp = $false; date = (Get-Date).ToString('s'); computer = $env:COMPUTERNAME
        }
        if ($sid) { reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" "$ud\profilelist.reg" /y | Out-Null }
        if ($it.HasProfile) {
            $drv = $global:BackupDir.Substring(0, 1)
            $freeB = (Get-Volume -DriveLetter $drv).SizeRemaining
            if ($freeB -and $freeB -lt ($it.Bytes + 1GB)) {
                Write-Host "SKIPPED $u - not enough free space on ${drv}: for the backup (set `$BackupRoot to a bigger drive)" -ForegroundColor Red
                continue
            }
            Write-Host ("   Backing up {0} ({1:N2} GB) ..." -f $u, ($it.Bytes / 1GB))
            $xd = @(Get-BackupExcludes $path | Where-Object { $_ })
            $base = @($path, "$ud\profile", '/E', '/B', '/COPY:DAT', '/DCOPY:DAT', '/XJ', '/FFT', '/R:1', '/W:1', '/NP', '/NFL', '/NDL')
            $xdArgs = @()
            if ($xd.Count -gt 0) { $xdArgs = @('/XD') + $xd }
            & robocopy @base '/MT:16' "/LOG:$ud\backup_robocopy.log" @xdArgs | Out-Null
            $rc = $LASTEXITCODE
            # verify: a second, list-only pass must find nothing left to copy
            & robocopy @base '/L' '/NJH' '/NJS' @xdArgs | Out-Null
            $rc2 = $LASTEXITCODE
            if (-not (($rc -lt 8) -and (($rc2 -band 29) -eq 0))) {
                Write-Host "BACKUP FAILED for $u (copy code $rc, verify code $rc2) - NOT deleting this user. See $ud\backup_robocopy.log" -ForegroundColor Red
                continue
            }
            $bk = Get-DirStat "$ud\profile"
            $meta.files = $bk.Files; $meta.bytes = $bk.Bytes
            Write-Host "   Backup verified: $($bk.Files) files." -ForegroundColor Green
        }
        $meta.backedUp = $true
        $global:Manifest.Add([pscustomobject]$meta)
        ConvertTo-Json -InputObject @($global:Manifest.ToArray()) -Depth 4 | Set-Content -Path "$global:BackupDir\manifest.json" -Encoding UTF8
        if ($acct) { Remove-LocalUser -Name $u; Write-Host "Removed account: $u" }
        Get-CimInstance Win32_UserProfile | Where-Object { $_.LocalPath -ieq $path } | Remove-CimInstance
        if (Test-Path $path) { Remove-Tree $path }
        if (Test-Path $path) { Write-Host "Could not fully delete $path (restart, then run again)" -ForegroundColor Yellow }
        else { Write-Host "Deleted profile: $path" }
    }
    if ($global:BackupDir) { Write-Host "   UNDO: double-click  $global:BackupDir\UNDO_RESTORE_USERS.bat" -ForegroundColor Green }
}

# =====================================================================
#  RUN ALL, MENU, SUMMARY
# =====================================================================
function Invoke-All {
    Write-Host ''
    Write-Host 'RUN ALL = scan, updates, cleanup, crash repair, speed fix, network, printer, RAM and security checks.' -ForegroundColor White
    Write-Host 'It does NOT delete user accounts (menu 12) and does NOT move or delete your files (menu 9).'
    Write-Host 'Close other apps first. Expected time: 30-120 minutes. Do not turn the PC off.'
    if (-not $Ui -and (Read-Host 'Type YES to continue') -ne 'YES') { Write-Host 'Cancelled.'; return }
    Invoke-Scan
    End-Section
    Ask-Startup
    Ask-Winget
    $FC.auto = $true
    Ensure-RestorePoint
    Invoke-AppsDrivers
    Invoke-Cleanup
    Invoke-CrashRepair
    Invoke-SpeedFix
    Invoke-NetRepair
    Invoke-PrintRepair
    Invoke-RamCheck
    Invoke-Security
    End-Section
    $FC.auto = $false
    Show-Summary
}
function Show-Summary {
    $free = [math]::Round((Get-PSDrive $sysLetter).Free / 1GB, 1)
    Write-Host "`n=== SUMMARY ===" -ForegroundColor Green
    Write-Host ("Time: {0:hh\:mm\:ss}   |   Free space on {1}: {2} GB (was {3} GB at start)" -f $total.Elapsed, $sysLetter, $free, $free0)
    Write-Host 'Findings and what to do about them:' -ForegroundColor White
    Show-Findings
    Save-Findings
    if ($global:BackupDir) {
        Write-Host "UNDO folder: $global:BackupDir" -ForegroundColor Green
        Write-Host '   UNDO_SETTINGS.bat = revert settings/drivers | UNDO_RESTORE_USERS.bat = bring deleted users back'
    }
    Write-Host "Reports: $rep"
}
function Show-Menu {
    Write-Host ''
    Write-Host '==================== PC CARE v4 ====================' -ForegroundColor Green
    Write-Host "  Signed in as $me   |   reports: Desktop\PCCare_Reports"
    Write-Host '   A   RUN ALL repairs in the best order (1-8 and 10)' -ForegroundColor White
    Write-Host '   1   Scan and report (read-only)'
    Write-Host '   2   Blue screen and crash repair'
    Write-Host '   3   Slow PC and hang fix'
    Write-Host '   4   C: drive cleanup + storage report'
    Write-Host '   5   Apps and drivers (updates, broken apps, old drivers)'
    Write-Host '   6   Network repair'
    Write-Host '   7   Printer and sharing repair'
    Write-Host '   8   RAM check and repair'
    Write-Host '   9   File tools (duplicates, categories, organizer)'
    Write-Host '  10   Security check (antivirus, Defender, firewall)'
    Write-Host '  11   Toolbox (rename, resize, awake, file locks, hosts...)'
    Write-Host '  12   Remove user accounts (with backup and undo)'
    Write-Host '   U   Open the undo/backup folder      S  Show summary      Q  Quit'
}
function Invoke-Choice($c) {
    switch ($c) {
        'A'    { Invoke-All }
        '1'    { Invoke-Scan }
        '2'    { Invoke-CrashRepair }
        '3'    { Invoke-SpeedFix }
        '4'    { Invoke-Cleanup }
        '5'    { Invoke-AppsDrivers }
        '6'    { Invoke-NetRepair }
        '7'    { Invoke-PrintRepair }
        '8'    { Invoke-RamCheck }
        '8.1'  { Ensure-RestorePoint; Schedule-MemTest }
        '9'    { Invoke-FileTools }
        '9.1'  { Invoke-Duplicates }
        '9.2'  { Invoke-CategoryReport }
        '9.3'  { Invoke-Organizer }
        '9.4'  { Invoke-UndoMoves }
        '10'   { Invoke-Security }
        '11'   { Invoke-Toolbox }
        '11.1' { Tool-BulkRename }
        '11.2' { Tool-ImageResize }
        '11.3' { Tool-Awake }
        '11.4' { Tool-Locksmith }
        '11.5' { Start-Process notepad.exe "$env:windir\System32\drivers\etc\hosts" }
        '11.6' { Start-Process rundll32.exe 'sysdm.cpl,EditEnvironmentVariables' }
        '11.7' { Tool-Hash }
        '12'   { Invoke-RemoveUsers }
        'U'    { if ($global:BackupDir) { Start-Process explorer.exe $global:BackupDir } elseif ($global:BackupBase -and (Test-Path $global:BackupBase)) { Start-Process explorer.exe $global:BackupBase } else { Write-Host '   No backup folder yet in this session. Earlier ones are in <drive>:\PCCare_Backup.' } }
        'S'    { Show-Summary }
        default { Write-Host "   Unknown choice: $c" -ForegroundColor Yellow }
    }
}
if (-not $Choice) { Write-Host 'Start this from Network Doctor: This PC & Wi-Fi > PC Care.'; exit 2 }
Invoke-Choice $Choice
End-Section
exit 0
'''
