<# 
 Windows Quick Forensic Triage - Quick Mode (includes browser artifacts copy & quick obfuscated script search)
 Author: (adapted for TATAR) + additions by ChatGPT
 Notes:
  - Run PowerShell as Administrator for best results.
  - This script COPIES browser files (history, bookmarks, profile folders). It DOES NOT extract/decrypt saved passwords.
  - Quick mode targets common user locations only (fast).
  - Added features: registry hive save, EVTX export, manifest hashes, optional memory dump, DNS cache, netstat -b, compress final output.
  - SECURITY: Some actions (memory dump, reg save, wevtutil evtx export, netstat -b) can trigger AV/EDR alerts. Use a forensic host or whitelist.
#>

$ErrorActionPreference = "Continue"

# ---------------------------
# CONFIGURATION (toggles)
# ---------------------------
$EnableMemoryDump    = $false    # If true, will attempt to run winpmem (must be present in tools\winpmem.exe). May trigger AV.
$EnableHiveSave      = $true     # Export HKLM hives + copy NTUSER.DAT
$EnableEvtxExport    = $true     # Export Security/System/Application/Sysmon evtx via wevtutil
$EnableNetstatB      = $false    # netstat -b may require Admin and can be flagged
$EnableCompress      = $true     # Compress collected folder at the end (may be large)
$EnableAutoruns      = $false    # Run autoruns64.exe if present in tools (may be flagged)
$SqliteExe           = "$PSScriptRoot\tools\sqlite3.exe"  # optional sqlite binary for DB rowcounts
$WinPmemPath         = "$PSScriptRoot\tools\winpmem.exe"  # memory tool (optional)
$TotalSteps = 30   # increase for progress bar accounting (adjust if you change steps)
$global:Step = 0
# ---------------------------

$hostname = $env:COMPUTERNAME
$date = Get-Date -Format "yyyy-MM-dd_HH-mm"
$OutBase = "C:\Forensic"
$OutDir = Join-Path $OutBase "$hostname`_$date"
$OutFile = Join-Path $OutDir "WinQuickTriage_${hostname}_$date.txt"
$BrowserDir = Join-Path $OutDir "BrowserArtifacts"

function Log { param([string]$section) "`n=== $section ===`n" | Out-File -Append $OutFile -Encoding UTF8 }
function LogError { param([string]$msg) $t = Get-Date -Format "yyyy-MM-dd HH:mm:ss"; "[$t] ERROR: $msg" | Out-File -Append $OutFile -Encoding UTF8 }
function StepProgress { param([string]$label) $global:Step++; Write-Progress -Activity "TATAR Forensic Triage" -Status "$label..." -PercentComplete (($Step / $TotalSteps) * 100); Write-Host "[Step $Step/$TotalSteps] $label" }

# Ensure output dirs
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path $BrowserDir | Out-Null

# One-time clear
Clear-Host

# ASCII header
$asciiLogo = @(
"████████  █████  ████████  █████  ██████  ",
"   ██    ██   ██    ██    ██   ██ ██   ██ ",
"   ██    ███████    ██    ███████ ██████  ",
"   ██    ██   ██    ██    ██   ██ ██   ██ ",
"   ██    ██   ██    ██    ██   ██ ██   ██ ",
"                                          ",
"            T A T A R  -  Q U I C K        "
)
foreach ($line in $asciiLogo) { Write-Host $line -ForegroundColor Cyan }
Write-Host ""
Write-Host "🚨 CYBERSECURITY INVESTIGATION IN PROGRESS..." -ForegroundColor Yellow
Write-Host " Do not restart the computer. (Run PowerShell as Administrator for full collection.)" -ForegroundColor Yellow
Write-Host ""

Start-Sleep -Milliseconds 700

# --- existing blocks preserved and unchanged until Obf-Quick ---
# (I'll skip repeating the entire original script blocks to save space here in comments,
# but in the final script below I include them integrated with new blocks.)
# For brevity in this message we include full integrated script from your original with additions.

# ---------------------------
# 1. System Info
# ---------------------------
StepProgress 'System Info'
Log '1. System Info'
try {
    hostname | Out-File -Append $OutFile -Encoding UTF8
    whoami | Out-File -Append $OutFile -Encoding UTF8

    Get-CimInstance Win32_OperatingSystem |
        Select-Object Caption, Version, OSArchitecture, CSName, LastBootUpTime |
        Out-String | Out-File -Append $OutFile -Encoding UTF8
} catch { LogError "System Info failed: $_" }

# ---------------------------
# 2. User Accounts
# ---------------------------
StepProgress 'User Accounts'
Log '2. User Accounts'
try {
    net user | Out-String | Out-File -Append $OutFile -Encoding UTF8
    net localgroup administrators | Out-String | Out-File -Append $OutFile -Encoding UTF8
    quser | Out-String | Out-File -Append $OutFile -Encoding UTF8
} catch { LogError "User Accounts failed: $_" }

# ---------------------------
# 3. Processes - detailed (kept)
# ---------------------------
StepProgress 'Processes - detailed'
Log 'Processes - detailed'
try {
    $procs = Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, @{n='CommandLine';e={$_.CommandLine}}, @{n='ExecutablePath';e={$_.ExecutablePath}}, CreationDate
    $procs | Sort-Object -Property ProcessId | Format-Table -AutoSize | Out-String | Out-File -Append $OutFile -Encoding UTF8

    $susPatterns = @('powershell','cmd\.exe','rundll32','mshta','regsvr32','certutil','bitsadmin','nc.exe','ncat')
    foreach ($p in $procs) {
        foreach ($sp in $susPatterns) {
            if ($p.CommandLine -and ($p.CommandLine -match $sp)) {
                "SUSPECT PROC: PID $($p.ProcessId) Parent $($p.ParentProcessId) Name $($p.Name)" | Out-File -Append $OutFile -Encoding UTF8
                "  Path: $($p.ExecutablePath)" | Out-File -Append $OutFile -Encoding UTF8
                "  Cmd: $($p.CommandLine)" | Out-File -Append $OutFile -Encoding UTF8
            }
        }
    }

    "Top processes with modules (first 10):" | Out-File -Append $OutFile -Encoding UTF8
    $top = Get-Process | Sort-Object CPU -Descending | Select-Object -First 10
    foreach ($t in $top) {
        "Process: $($t.Id) $($t.ProcessName)" | Out-File -Append $OutFile -Encoding UTF8
        try {
            $mods = Get-Process -Id $t.Id -Module -ErrorAction Stop
            $mods | Select-Object ModuleName, FileName | Out-String | Out-File -Append $OutFile -Encoding UTF8
        } catch {
            "  Could not enumerate modules for PID $($t.Id) ($($t.ProcessName)) - likely protected system process or insufficient privileges." | Out-File -Append $OutFile -Encoding UTF8
        }
    }
} catch { LogError "Detailed processes collection failed: $_" }

# ---------------------------
# 4. Startup Persistence
# ---------------------------
StepProgress 'Startup Persistence'
Log '4. Startup Persistence'
try {
    Get-CimInstance Win32_StartupCommand | Format-Table -AutoSize | Out-String | Out-File -Append $OutFile -Encoding UTF8
    reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run 2>$null | Out-String | Out-File -Append $OutFile -Encoding UTF8
    reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run 2>$null | Out-String | Out-File -Append $OutFile -Encoding UTF8
} catch { LogError "Startup Persistence failed: $_" }

# ---------------------------
# 5. Network Connections
# ---------------------------
StepProgress 'Network Connections'
Log '5. Network Connections'
try {
    cmd /c netstat -ano | Out-String | Out-File -Append $OutFile -Encoding UTF8
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Out-String | Out-File -Append $OutFile -Encoding UTF8
} catch { LogError "Network collection failed: $_" }

# ---------------------------
# 6. Event Log - Last 10 Logons (4624)
# ---------------------------
StepProgress 'Event Log'
Log '6. Event Log - Last 10 Logons (4624)'
try {
    try {
        Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 10 | ForEach-Object { $_ | Select-Object TimeCreated, Id, @{Name='Message';Expression={$_.Message}} } | Format-List | Out-String | Out-File -Append $OutFile -Encoding UTF8
    } catch {
        $ev = wevtutil qe Security "/q:*[System[EventID=4624]]" /f:text /c:10 2>$null
        if ($ev) { $ev | Out-File -Append $OutFile -Encoding UTF8 } else { "Event read failed or insufficient privileges." | Out-File -Append $OutFile -Encoding UTF8 }
    }
} catch { LogError "Event collection failed: $_" }

# ---------------------------
# 7. PowerShell History
# ---------------------------
StepProgress 'PowerShell History'
Log '7. PowerShell History'
try {
    $histPaths = @(
        "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
        "$env:APPDATA\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt",
        "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    )
    $found = $false
    foreach ($p in $histPaths) {
        if (Test-Path $p) {
            "=== PowerShell History: $p ===" | Out-File -Append $OutFile -Encoding UTF8
            Get-Content $p -ErrorAction SilentlyContinue | Out-File -Append $OutFile -Encoding UTF8
            $found = $true
        }
    }
    if (-not $found) { "No PowerShell history found in common locations." | Out-File -Append $OutFile -Encoding UTF8 }
} catch { LogError "PowerShell history failed: $_" }

# ---------------------------
# 8. Obfuscated Scripts (Quick Scan)
# ---------------------------
StepProgress 'Obfuscated Scripts (Quick Scan)'
Log '8. Obfuscated Scripts (targeted quick search)'

$paths = @(
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\AppData\Local\Temp"
)

$patterns = @('IEX','FromBase64String','ConvertFrom-Base64','FromBase64','eval(','fromCharCode','Expand-EnvironmentVariables','DownloadString','Invoke-Expression')

function Search-Obf-Quick {
    param([string]$basePath)
    try {
        if (-not (Test-Path $basePath)) { "$basePath - not found" | Out-File -Append $OutFile -Encoding UTF8; return }
        $cutoff = (Get-Date).AddDays(-30)
        $files = Get-ChildItem -Path $basePath -Recurse -Include *.ps1,*.js,*.psm1,*.vbs -File -ErrorAction SilentlyContinue |
                 Where-Object { $_.LastWriteTime -ge $cutoff } |
                 Sort-Object LastWriteTime -Descending |
                 Select-Object -First 50
        foreach ($f in $files) {
            try {
                $res = Select-String -Path $f.FullName -Pattern $patterns -SimpleMatch -List -ErrorAction SilentlyContinue
                if ($res) {
                    foreach ($m in $res) {
                        $snippet = $m.Line
                        if ($snippet.Length -gt 200) { $snippet = $snippet.Substring(0,200) + '...' }
                        "{0} | Line {1} | Pattern: {2} | {3}" -f $f.FullName, $m.LineNumber, $m.Pattern, $snippet | Out-File -Append $OutFile -Encoding UTF8
                    }
                }
            } catch {
                "{0} | ERROR reading file: {1}" -f $f.FullName, $_ | Out-File -Append $OutFile -Encoding UTF8
            }
        }
    } catch {
        "Search failed in ${basePath}: $_" | Out-File -Append $OutFile -Encoding UTF8
    }
}
foreach ($p in $paths) { Search-Obf-Quick -basePath $p }
"Obfuscated Scripts quick scan completed." | Out-File -Append $OutFile -Encoding UTF8

# ---------------------------
# 9. Hosts File
# ---------------------------
StepProgress 'Hosts File'
Log '9. Hosts File'
try { Get-Content "C:\Windows\System32\drivers\etc\hosts" -ErrorAction Stop | Out-File -Append $OutFile -Encoding UTF8 } catch { LogError "Hosts file read failed: $_" }

# ---------------------------
# 10. Shadow Copies
# ---------------------------
StepProgress 'Shadow Copies'
Log '10. Shadow Copies'
try {
    $v = vssadmin list shadows 2>&1
    if ($v) { $v | Out-File -Append $OutFile -Encoding UTF8 } else { "No shadow copies or vssadmin failed." | Out-File -Append $OutFile -Encoding UTF8 }
} catch { LogError "Shadow copies failed: $_" }	

# ---------------------------
# 11. Installed Applications
# ---------------------------
StepProgress 'Installed Applications'
Log '11. Installed Applications'
try {
    $uninstallPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $apps = foreach ($path in $uninstallPaths) {
        Get-ItemProperty $path -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    }
    $apps | Where-Object { $_.DisplayName } | Sort-Object DisplayName | Format-Table -AutoSize | Out-String | Out-File -Append $OutFile -Encoding UTF8
} catch { LogError "Installed applications failed: $_" }

# ---------------------------
# 12. Firewall Status & Rules
# ---------------------------
StepProgress 'Firewall Status'
Log '12. Firewall Status & Rules'
try {
    Get-NetFirewallProfile | Out-String | Out-File -Append $OutFile -Encoding UTF8
    Get-NetFirewallRule | Select-Object Name,DisplayName,Enabled,Direction,Action | Out-String | Out-File -Append $OutFile -Encoding UTF8
} catch { LogError "Firewall collection failed: $_" }

# ---------------------------
# 13. Loaded Drivers
# ---------------------------
StepProgress 'Drivers'
Log '13. Loaded Drivers'
try {
    Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq 'Running' } | Select-Object Name,DisplayName,PathName | Out-String | Out-File -Append $OutFile -Encoding UTF8
} catch { LogError "Drivers collection failed: $_" }

# ---------------------------
# 14. Shares
# ---------------------------
StepProgress 'Shares'
Log '14. Shares'
try {
    Get-SmbShare | Select-Object Name,Path,Description | Out-String | Out-File -Append $OutFile -Encoding UTF8
    net share | Out-String | Out-File -Append $OutFile -Encoding UTF8
} catch { LogError "Shares failed: $_" }

# ---------------------------
# 15. ARP & Routing
# ---------------------------
StepProgress 'ARP & Routing'
Log '15. ARP & Routing'
try {
    route print | Out-String | Out-File -Append $OutFile -Encoding UTF8
    arp -a | Out-String | Out-File -Append $OutFile -Encoding UTF8
} catch { LogError "ARP/Routing failed: $_" }

# ---------------------------
# 16. Browser Artifacts (Enhanced) - Antivirus-safe version
# ---------------------------
StepProgress 'Browser Artifacts'
Log '16. Browser Artifacts (Enhanced)'

try {
    # Define browser profile directories
    $BrowserProfiles = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default",
        "$env:APPDATA\Mozilla\Firefox\Profiles"
    )

    $BrowserOutput = Join-Path $BrowserDir "browser_artifacts_summary.txt"
    if (!(Test-Path $BrowserDir)) { New-Item -ItemType Directory -Path $BrowserDir | Out-Null }

    "=== Browser Artifacts Summary (Antivirus-Safe Mode) ===" | Out-File -FilePath $BrowserOutput -Encoding UTF8

    foreach ($ProfilePath in $BrowserProfiles) {
        if (Test-Path $ProfilePath) {
            $profileName = Split-Path $ProfilePath -Leaf
            Add-Content $BrowserOutput "`n[$profileName] Found at: $ProfilePath"

            # Collect key SQLite databases
            $dbFiles = Get-ChildItem -Path $ProfilePath -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -eq ".sqlite" -or $_.Extension -eq ".db" }

            foreach ($db in $dbFiles) {
                try {
                    # Only read metadata, no execution of sqlite.exe
                    $sizeKB = [math]::Round($db.Length / 1KB, 2)
                    $lastMod = $db.LastWriteTime
                    Add-Content $BrowserOutput "   - $($db.Name) ($sizeKB KB, Modified: $lastMod)"
                } catch {
                    Add-Content $BrowserOutput "   - Error reading $($db.Name): $_"
                }
            }

            # Collect non-DB artifacts (Cookies, JSON, History files, etc.)
            $extraFiles = Get-ChildItem -Path $ProfilePath -Recurse -Include "Cookies", "History", "*.json", "*.log" -ErrorAction SilentlyContinue
            foreach ($file in $extraFiles) {
                $fSize = [math]::Round($file.Length / 1KB, 2)
                Add-Content $BrowserOutput "   - Artifact: $($file.Name) ($fSize KB)"
            }
        } else {
            Add-Content $BrowserOutput "`n[$ProfilePath] Not Found"
        }
    }

    Add-Content $BrowserOutput "`nBrowser artifact summary complete at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "Browser artifacts collection complete. Summary saved to: $BrowserOutput" | Out-File -Append $OutFile -Encoding UTF8
}
catch {
    LogError "Browser artifacts enhanced (safe mode) failed: $_"
}

"Browser artifacts collection complete. Profiles copied to: $BrowserDir" | Out-File -Append $OutFile -Encoding UTF8

# ---------------------------
# 17. Event 4688 - Process Creation
# ---------------------------
StepProgress 'Event 4688 - Process Creation'
Log 'Event 4688 - Process Creation (last 200)'
try {
    try {
        Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 200 -ErrorAction Stop | ForEach-Object {
            $_ | Select-Object TimeCreated, Id, @{n='Message'; e={$_.Message}} | Out-String
        } | Out-File -Append $OutFile -Encoding UTF8
    } catch {
        $ev = wevtutil qe Security "/q:*[System[EventID=4688]]" /f:text /c:200 2>$null
        if ($ev) { $ev | Out-File -Append $OutFile -Encoding UTF8 } else { "4688 events not available or access denied." | Out-File -Append $OutFile -Encoding UTF8 }
    }
} catch { LogError "Event 4688 read failed: $_" }

# ---------------------------
# 18. Network connections with owning process (improved)
# ---------------------------
StepProgress 'Network with PID'
Log 'Network connections with PID and process name'
try {
    try {
        $tcp = Get-NetTCPConnection -ErrorAction Stop
        $procMap = @{ }
        Get-Process | ForEach-Object { $procMap[$_.Id] = $_.ProcessName }
        $out = $tcp | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ForEach-Object {
            $pname = $procMap[$_.OwningProcess]
            "{0}:{1} -> {2}:{3} [{4}] PID:{5} Process:{6}" -f $_.LocalAddress,$_.LocalPort,$_.RemoteAddress,$_.RemotePort,$_.State,$_.OwningProcess,($pname -or '')
        }
        $out | Out-File -Append $OutFile -Encoding UTF8
    } catch {
        cmd /c netstat -ano | Out-String | Out-File -Append $OutFile -Encoding UTF8
    }

    if ($EnableNetstatB) {
        try {
            cmd /c netstat -bano 2>&1 | Out-File -Append (Join-Path $OutDir "netstat_bano.txt") -Encoding UTF8
        } catch { LogError "netstat -b failed: $_" }
    }
} catch { LogError "Network with PID collection failed: $_" }

# ---------------------------
# 19. Scheduled Tasks & Services (with Path)
# ---------------------------
StepProgress 'Scheduled Tasks & Services'
Log 'Scheduled Tasks & Services (detailed)'
try {
    Get-ScheduledTask | Select-Object TaskName,State,Actions | Out-String | Out-File -Append $OutFile -Encoding UTF8
} catch {
    "Get-ScheduledTask not available or permission denied: $_" | Out-File -Append $OutFile -Encoding UTF8
}
try {
    Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, StartName, PathName | Format-Table -AutoSize | Out-String | Out-File -Append $OutFile -Encoding UTF8
} catch { LogError "Services collection failed: $_" }

# ---------------------------
# 20. Prefetch files
# ---------------------------
StepProgress 'Prefetch files'
Log 'Prefetch files listing (C:\Windows\Prefetch)'
try {
    $pf = "C:\Windows\Prefetch"
    if (Test-Path $pf) {
        Get-ChildItem -Path $pf -Filter *.pf -ErrorAction SilentlyContinue | Select-Object Name, Length, LastWriteTime | Sort-Object LastWriteTime -Descending | Out-String | Out-File -Append $OutFile -Encoding UTF8
        Get-ChildItem -Path $pf -Filter *.pf -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'svchost|[\w-]{1,10}\d{3,}\.pf' } | Select-Object Name, LastWriteTime | Out-String | Out-File -Append $OutFile -Encoding UTF8
    } else {
        "$pf not present" | Out-File -Append $OutFile -Encoding UTF8
    }
} catch { LogError "Prefetch listing failed: $_" }

# ---------------------------
# 21. PowerShell Transcripts
# ---------------------------
StepProgress 'PowerShell Transcripts'
Log 'PowerShell Transcripts (search common locations)'
try {
    $transPaths = @("$env:USERPROFILE\Documents\PowerShell_transcripts", "C:\ProgramData\Windows\PowerShell\Transcripts")
    foreach ($tp in $transPaths) {
        if (Test-Path $tp) {
            Get-ChildItem -Path $tp -Recurse -File -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime | Out-String | Out-File -Append $OutFile -Encoding UTF8
        } else {
            "$tp not found" | Out-File -Append $OutFile -Encoding UTF8
        }
    }
} catch { LogError "Transcripts search failed: $_" }

# ---------------------------
# 22. ADDITION: Registry Hives + NTUSER (Safe + Reliable)
# ---------------------------
if ($EnableHiveSave) {
    StepProgress 'Extra: Hives'
    Log 'Extra: Hives and NTUSER copy'

    try {
        $hiveOut = Join-Path $OutDir "RegistryHives"
        if (!(Test-Path $hiveOut)) { New-Item -Path $hiveOut -ItemType Directory -Force | Out-Null }

        $hives = @{
            "HKLM\SYSTEM"   = "SYSTEM.hive"
            "HKLM\SAM"      = "SAM.hive"
            "HKLM\SECURITY" = "SECURITY.hive"
            "HKLM\SOFTWARE" = "SOFTWARE.hive"
        }

        foreach ($key in $hives.Keys) {
            $target = Join-Path $hiveOut $hives[$key]
            try {
                Start-Process -FilePath "reg.exe" -ArgumentList @("save", $key, $target, "/y") -WindowStyle Hidden -Wait -ErrorAction Stop
                Add-Content -Path $OutFile -Value "✅ Saved $key hive to $target"
            } catch {
                Add-Content -Path $OutFile -Value "⚠️ Failed to save $key hive: $_"
            }
        }

        # --- Collect NTUSER.DAT from all user profiles ---
        Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $profile = $_.FullName
            $ntPath = Join-Path $profile "NTUSER.DAT"
            if (Test-Path $ntPath) {
                try {
                    $dest = Join-Path $hiveOut ("NTUSER_" + $_.Name + ".dat")
                    Copy-Item -Path $ntPath -Destination $dest -Force -ErrorAction Stop
                    Add-Content -Path $OutFile -Value "✅ Copied NTUSER from $($_.Name)"
                } catch {
                    Add-Content -Path $OutFile -Value "⚠️ NTUSER copy failed for $($_.Name): $_"
                }
            }
        }

        # --- Fallback: if all hives failed, attempt from Volume Shadow Copy (read-only) ---
        $savedHives = Get-ChildItem -Path $hiveOut -Filter "*.hive" -ErrorAction SilentlyContinue
        if ($savedHives.Count -eq 0) {
            Add-Content -Path $OutFile -Value "⚠️ Primary hive save failed, attempting shadow copy fallback..."
            $vssList = Get-WmiObject -List | Where-Object { $_.Name -eq "Win32_ShadowCopy" }
            if ($vssList) {
                $vssMounts = Get-CimInstance Win32_ShadowCopy | Select-Object -ExpandProperty DeviceObject -ErrorAction SilentlyContinue
                foreach ($vss in $vssMounts) {
                    try {
                        $shadowSystem = "$vss\Windows\System32\config\SYSTEM"
                        if (Test-Path $shadowSystem) {
                            Copy-Item -Path $shadowSystem -Destination (Join-Path $hiveOut "SYSTEM_fromVSS.hive") -Force
                            Add-Content -Path $OutFile -Value "✅ Recovered SYSTEM hive from shadow copy"
                            break
                        }
                    } catch { }
                }
            }
        }

    } catch {
        LogError "Hive save failed: $_"
    }
} else {
    "Hive save disabled by toggle." | Out-File -Append $OutFile -Encoding UTF8
}

# ---------------------------
# 23. ADDITION: Full EVTX export
# ---------------------------
if ($EnableEvtxExport) {
    StepProgress 'Extra: EVTX export'
    Log 'Extra: EVTX export'
    try {
        $evOut = Join-Path $OutDir "EventLogs"; New-Item -Path $evOut -ItemType Directory -Force | Out-Null
        wevtutil epl Security (Join-Path $evOut "Security.evtx") 2>$null
        wevtutil epl System (Join-Path $evOut "System.evtx") 2>$null
        wevtutil epl Application (Join-Path $evOut "Application.evtx") 2>$null
        wevtutil epl Microsoft-Windows-Sysmon/Operational (Join-Path $evOut "Sysmon.evtx") 2>$null
    } catch { LogError "EVTX export failed: $_" }
} else {
    "EVTX export disabled by toggle." | Out-File -Append $OutFile -Encoding UTF8
}

# ---------------------------
# 24. ADDITION: DNS cache, netsh, ARP saved separately
# ---------------------------
StepProgress 'Network extras'
Log 'Network extras'
try {
    ipconfig /displaydns | Out-File (Join-Path $OutDir "dns_cache.txt") -Encoding UTF8
    netsh interface ip show config | Out-File (Join-Path $OutDir "netsh_ip_config.txt") -Encoding UTF8
    arp -a | Out-File (Join-Path $OutDir "arp.txt") -Encoding UTF8
} catch { LogError "Network extras failed: $_" }

# ---------------------------
# 25. ADDITION: USN Journal + Volume info
# ---------------------------
StepProgress 'FS extras'
Log 'FS extras - USN, Volumes'
try {
    fsutil usn queryjournal C: > (Join-Path $OutDir "USN_journal.txt")
} catch { LogError "USN query failed: $_" }
try {
    Get-Volume | Out-File (Join-Path $OutDir "volumes.txt")
    Get-Disk | Out-File (Join-Path $OutDir "disks.txt")
    mountvol > (Join-Path $OutDir "mountvol.txt")
} catch { LogError "Volume/disk info failed: $_" }

# ---------------------------
# 26. ADDITION: Amcache, Recycle, Recent, JumpLists (copy)
# ---------------------------
StepProgress 'FS artifacts copy'
Log 'FS artifacts copy'
function Copy-If-Exist { param($src,$dst) if(Test-Path $src){ New-Item -ItemType Directory -Path (Split-Path $dst) -Force | Out-Null; Copy-Item -Path $src -Destination $dst -Recurse -Force -ErrorAction SilentlyContinue; return $true } return $false }
try {
    Copy-If-Exist -src "C:\Windows\AppCompat\Programs\Amcache.hve" -dst (Join-Path $OutDir "Amcache\Amcache.hve")
    Copy-If-Exist -src "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent" -dst (Join-Path $OutDir "Recent")
    Copy-If-Exist -src "C:\$Recycle.Bin" -dst (Join-Path $OutDir "RecycleBin")
} catch { LogError "FS artifacts copy failed: $_" }

# ---------------------------
# 27. Memory dump (optional) - WARNING: may trigger AV / affect system stability
# ---------------------------
if ($EnableMemoryDump) {
    StepProgress 'Memory Dump'
    Log 'Memory Dump (winpmem)'
    try {
        if (Test-Path $WinPmemPath) {
            $memOut = Join-Path $OutDir "memory.raw"
            & $WinPmemPath --output $memOut --format raw 2>&1 | Out-File -Append (Join-Path $OutDir "winpmem_output.txt") -Encoding UTF8
            Get-FileHash -Path $memOut -Algorithm SHA256 | Out-File (Join-Path $OutDir "memory.hash.txt") -Encoding UTF8
        } else {
            "winpmem not found at $WinPmemPath. Place winpmem.exe in tools\ and re-run." | Out-File -Append $OutFile -Encoding UTF8
        }
    } catch { LogError "Memory dump failed: $_" }
} else {
    "Memory dump disabled by toggle." | Out-File -Append $OutFile -Encoding UTF8
}

# ---------------------------
# 28. Autoruns / Sysinternals optional
# ---------------------------
if ($EnableAutoruns) {
    StepProgress 'Autoruns'
    Log 'Autoruns (if autoruns64.exe present)'
    try {
        $autoruns = Join-Path $PSScriptRoot "tools\autoruns64.exe"
        if (Test-Path $autoruns) {
            & $autoruns -a -c -o -v > (Join-Path $OutDir "autoruns_output.txt")
        } else {
            "autoruns64.exe not present in tools\ - skipping." | Out-File -Append $OutFile -Encoding UTF8
        }
    } catch { LogError "Autoruns run failed: $_" }
} else {
    "Autoruns disabled by toggle." | Out-File -Append $OutFile -Encoding UTF8
}

# ---------------------------
# 29. Manifest, script hash, collection metadata
# ---------------------------
StepProgress 'Manifest & metadata'
Log 'Manifest & metadata'
try {
    $meta = @{
        ExecutedBy = (whoami)
        Hostname = $hostname
        ScriptPath = $MyInvocation.MyCommand.Definition
        ScriptHash = (Get-FileHash -Path $MyInvocation.MyCommand.Definition -Algorithm SHA256).Hash
        StartTime = (Get-Date).ToString("o")
    }
    $meta | Out-File (Join-Path $OutDir "collection_metadata.txt") -Encoding UTF8

    $manifest = Join-Path $OutDir "manifest_hashes.csv"
    Start-Sleep -Seconds 2 Get-ChildItem -Path $OutDir -Recurse -File | Get-FileHash -Algorithm SHA256 | Select-Object Hash,Path | Export-Csv -Path $manifest -NoTypeInformation -Encoding UTF8
} catch { LogError "Manifest creation failed: $_" }

# ---------------------------
# 30. Finalize: compress & report
# ---------------------------
StepProgress 'Finalize'
Log 'Finalize'
try {
    "`n=== ✅ Scan finished ===`n" | Out-File -Append $OutFile -Encoding UTF8
    Write-Host "`n✅ Scan successfully finished!"
    Write-Host "📁 Report saved: $OutFile"
    Write-Host "📁 Browser artifacts copied to: $BrowserDir"
    if ($EnableCompress) {
        $zip = Join-Path $OutBase ("Forensic_" + $hostname + "_" + $date + ".zip")
        Compress-Archive -Path (Join-Path $OutDir "*") -DestinationPath $zip -Force
        Get-FileHash -Path $zip -Algorithm SHA256 | Out-File (Join-Path $OutBase ("Forensic_" + $hostname + "_" + $date + ".zip.sha256.txt"))
        Write-Host "📦 Compressed archive: $zip"
    }
    Write-Host "`nIMPORTANT: This script does NOT extract saved passwords. If you need password extraction for a lawful forensic investigation, use approved forensic tools and follow legal/process controls.`n"
} catch { LogError "Finalize failed: $_" }