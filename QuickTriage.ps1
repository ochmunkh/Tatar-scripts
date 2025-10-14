<#
Windows Quick Forensic Triage - Quick Mode (includes browser artifacts copy & quick obfuscated script search)
Author: (adapted for TATAR)
Notes:
 - Run PowerShell as Administrator for best results.
 - This script COPIES browser files (history, bookmarks, profile folders). It DOES NOT extract/decrypt saved passwords.
 - Quick mode targets common user locations only (fast).
#>

$ErrorActionPreference = "Continue"

$hostname = $env:COMPUTERNAME
$date = Get-Date -Format "yyyy-MM-dd_HH-mm"
$OutBase = "C:\Forensic"
$OutDir = Join-Path $OutBase "$hostname`_$date"
$OutFile = Join-Path $OutDir "WinQuickTriage_${hostname}_$date.txt"
$BrowserDir = Join-Path $OutDir "BrowserArtifacts"

# Quick mode default
$ObfMode = 'quick'   # allowed values: quick, medium, full (but script defaults to quick)

# Total steps (adjust if you change number of steps)
$TotalSteps = 16
$global:Step = 0

# Ensure output dirs
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path $BrowserDir | Out-Null

function Log {
    param([string]$section)
    "`n=== $section ===`n" | Out-File -Append $OutFile -Encoding UTF8
}

function LogError {
    param([string]$msg)
    $t = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$t] ERROR: $msg" | Out-File -Append $OutFile -Encoding UTF8
}

function StepProgress {
    param([string]$label)
    $global:Step++
    Write-Progress -Activity "TATAR Forensic Triage" -Status "$label..." -PercentComplete (($Step / $TotalSteps) * 100)
    Write-Host "[Step $Step/$TotalSteps] $label"
}

# One-time clear
Clear-Host

# ASCII logo at top (kept visible)
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
}
catch { LogError "System Info failed: $_" }

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
# 3. Suspicious Processes
# ---------------------------
StepProgress 'Suspicious Processes'
Log '3. Suspicious Processes'
try {
    Get-Process | Sort-Object CPU -Descending | Select-Object Id,ProcessName,CPU,StartTime | Format-Table -AutoSize | Out-String | Out-File -Append $OutFile -Encoding UTF8
} catch { LogError "Process list failed: $_" }

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
    # Try Get-WinEvent (may need admin)
    try {
        Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 10 | ForEach-Object { $_ | Select-Object TimeCreated, Id, @{Name='Message';Expression={$_.Message}} } | Format-List | Out-String | Out-File -Append $OutFile -Encoding UTF8
    } catch {
        # fallback to wevtutil
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
# 8. Obfuscated Scripts (quick) - targeted paths (replace this block)
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
        if (-not (Test-Path $basePath)) {
            "$basePath - not found" | Out-File -Append $OutFile -Encoding UTF8
            return
        }

        # Gather recent script-like files only, limit to top 100 per path (fast)
        $cutoff = (Get-Date).AddDays(-30)
        $files = Get-ChildItem -Path $basePath -Recurse -Include *.ps1,*.js,*.psm1,*.vbs -File -ErrorAction SilentlyContinue |
                 Where-Object { $_.LastWriteTime -ge $cutoff } |
                 Sort-Object LastWriteTime -Descending |
                 Select-Object -First 50

        foreach ($f in $files) {
            try {
                # -List returns first match per file (faster); -SimpleMatch is quicker than regex
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
# Browser Artifacts (quick) - copy profiles & capture autofill/password-manager settings (NO password extraction)
# ---------------------------
StepProgress 'Browser Artifacts'
Log '16. Browser Artifacts - copy profiles & capture autofill/password-manager settings (NO password extraction)'

function SafeCopy {
    param($src, $dst)
    try {
        if (Test-Path $src) {
            $d = Split-Path $dst -Parent
            New-Item -ItemType Directory -Force -Path $d | Out-Null
            Copy-Item -Path $src -Destination $dst -Force -ErrorAction Stop
            return $true
        }
    } catch {
        "$src -> copy failed: $_" | Out-File -Append $OutFile -Encoding UTF8
    }
    return $false
}

# Collect common chromium-based browsers + Firefox (quick paths)
$browserProfiles = @()

$chromeDefault = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
if (Test-Path $chromeDefault) { $browserProfiles += @{Name='Chrome'; Path=$chromeDefault; Type='chromium'} }

$edgeDefault = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
if (Test-Path $edgeDefault) { $browserProfiles += @{Name='Edge'; Path=$edgeDefault; Type='chromium'} }

$braveDefault = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default"
if (Test-Path $braveDefault) { $browserProfiles += @{Name='Brave'; Path=$braveDefault; Type='chromium'} }

$operaDefault = "$env:APPDATA\Opera Software\Opera Stable"
if (Test-Path $operaDefault) { $browserProfiles += @{Name='Opera'; Path=$operaDefault; Type='chromium'} }

# Firefox profiles: parse profiles.ini
$ffIni = "$env:APPDATA\Mozilla\Firefox\profiles.ini"
if (Test-Path $ffIni) {
    try {
        $ini = Get-Content $ffIni -ErrorAction SilentlyContinue
        $paths = ($ini | Where-Object { $_ -match '^Path=' }) -replace '^Path=',''
        foreach ($rel in $paths) {
            $full = Join-Path "$env:APPDATA\Mozilla\Firefox" $rel
            if (Test-Path $full) { $browserProfiles += @{Name='Firefox'; Path=$full; Type='firefox'} }
        }
    } catch { "Firefox profiles parse failed: $_" | Out-File -Append $OutFile -Encoding UTF8 }
}

if ($browserProfiles.Count -eq 0) {
    "No browser profiles found in common locations." | Out-File -Append $OutFile -Encoding UTF8
}

foreach ($bp in $browserProfiles) {
    $name = $bp.Name
    $path = $bp.Path
    $type = $bp.Type
    $dest = Join-Path $BrowserDir $name
    New-Item -ItemType Directory -Force -Path $dest | Out-Null

    "---- Browser: $name ; Path: $path ; Type: $type ----" | Out-File -Append $OutFile -Encoding UTF8

    if ($type -eq 'chromium') {
        # Important files: Preferences (JSON), Local State (JSON), History (sqlite), Login Data (sqlite, copied only), Bookmarks
        $prefs = Join-Path $path "Preferences"
        $localState = Join-Path (Split-Path $path -Parent) "Local State"
        $history = Join-Path $path "History"
        $loginData = Join-Path $path "Login Data"
        $bookmarks = Join-Path $path "Bookmarks"

        # copy them (if accessible)
        SafeCopy $prefs (Join-Path $dest "Preferences")
        SafeCopy $localState (Join-Path $dest "Local State")
        SafeCopy $history (Join-Path $dest "History")
        SafeCopy $loginData (Join-Path $dest "Login Data")
        SafeCopy $bookmarks (Join-Path $dest "Bookmarks")

        # Parse Preferences JSON for autofill/password manager related keys (if copy succeeded)
        $copiedPrefs = Join-Path $dest "Preferences"
        if (Test-Path $copiedPrefs) {
            try {
                $json = Get-Content $copiedPrefs -Raw | ConvertFrom-Json -ErrorAction Stop

                # Common keys of interest
                $creds_enabled = $null
                $autofill_enabled = $null
                $profile_name = $null

                # credentials_enable_service may be in 'credentials_enable_service' in Local State or Preferences.profile
                if ($json.profile -ne $null) { $profile_name = $json.profile.name }
                if ($json.autofill -ne $null -and $json.autofill.profile_enabled -ne $null) {
                    $autofill_enabled = $json.autofill.profile_enabled
                }
                # try to find saved password related keys
                if ($json.credentials_enable_service -ne $null) { $creds_enabled = $json.credentials_enable_service }
                if ($json.password_manager_enabled -ne $null) { $creds_enabled = $json.password_manager_enabled }

                "Chromium Preferences summary for ${name}:" | Out-File -Append $OutFile -Encoding UTF8
                " ProfileName: $profile_name" | Out-File -Append $OutFile -Encoding UTF8
                " Autofill enabled (autofill.profile_enabled): $autofill_enabled" | Out-File -Append $OutFile -Encoding UTF8
                " Password manager enabled (credentials/password_manager flags): $creds_enabled" | Out-File -Append $OutFile -Encoding UTF8

            } catch {
                "Preferences parse failed for ${name}: $_" | Out-File -Append $OutFile -Encoding UTF8
            }
        } else {
            "Preferences not found/copied for $name" | Out-File -Append $OutFile -Encoding UTF8
        }

        # Check History file presence (for URL history)
        if (Test-Path (Join-Path $dest "History")) {
            "History file copied for $name" | Out-File -Append $OutFile -Encoding UTF8
        } else {
            "History not found for $name" | Out-File -Append $OutFile -Encoding UTF8
        }

        # Note: Login Data copied but NOT parsed/decrypted
        if (Test-Path (Join-Path $dest "Login Data")) {
            "Login Data (copied) present for $name - passwords NOT extracted by this script." | Out-File -Append $OutFile -Encoding UTF8
        }
    } elseif ($type -eq 'firefox') {
        # Files: prefs.js (settings), logins.json (contains encrypted logins), places.sqlite (history/bookmarks)
        $prefsjs = Join-Path $path "prefs.js"
        $logins = Join-Path $path "logins.json"
        $places = Join-Path $path "places.sqlite"

        SafeCopy $prefsjs (Join-Path $dest "prefs.js")
        SafeCopy $logins (Join-Path $dest "logins.json")
        SafeCopy $places (Join-Path $dest "places.sqlite")

        # Parse prefs.js lines for relevant prefs
        if (Test-Path (Join-Path $dest "prefs.js")) {
            try {
                $pcontent = Get-Content (Join-Path $dest "prefs.js") -ErrorAction Stop
                $interesting = $pcontent | Where-Object { $_ -match 'signon\.rememberSignons|signon\.autocompleteForms|browser\.formfill\.enable|places\.history' }
                if ($interesting) {
                    "Firefox prefs of interest for ${name}:" | Out-File -Append $OutFile -Encoding UTF8
                    $interesting | Out-File -Append $OutFile -Encoding UTF8
                } else {
                    "No key prefs found in prefs.js for $name" | Out-File -Append $OutFile -Encoding UTF8
                }
            } catch {
                "Failed to read prefs.js for ${name}: $_" | Out-File -Append $OutFile -Encoding UTF8
            }
        } else {
            "prefs.js not found/copied for Firefox profile $name" | Out-File -Append $OutFile -Encoding UTF8
        }

        if (Test-Path (Join-Path $dest "logins.json")) {
            "logins.json copied for Firefox (contains encrypted login entries) - NOT decrypted by this script." | Out-File -Append $OutFile -Encoding UTF8
        }
    }

    # Small separator
    "`n" | Out-File -Append $OutFile -Encoding UTF8
}

"Browser artifacts collection complete. Profiles copied to: $BrowserDir" | Out-File -Append $OutFile -Encoding UTF8

# End of browser artifacts block

# ---------------------------
# Finish
# ---------------------------
"`n=== ✅ Scan finished ===`n" | Out-File -Append $OutFile -Encoding UTF8

Write-Host "`n✅ Scan successfully finished!"
Write-Host "📁 Report saved: $OutFile"
Write-Host "📁 Browser artifacts copied to: $BrowserDir"
Write-Host "`nIMPORTANT: This script does NOT extract saved passwords. If you need password extraction for a lawful forensic investigation, use approved forensic tools and follow legal/process controls.`n"
