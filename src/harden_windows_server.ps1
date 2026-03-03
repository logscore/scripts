#Requires -RunAsAdministrator
#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================================
# Windows Server 2022+ Hardening Script
# Run as Administrator in an elevated PowerShell session
# ============================================================

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $currentPrincipal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run as Administrator."
    exit 1
}

# --- Detect OS ---
$os = Get-CimInstance Win32_OperatingSystem
if ($os.Caption -notmatch "Windows Server" -or
    [int]$os.BuildNumber -lt 20348) {
    Write-Error "This script targets Windows Server 2022+ (build 20348+). Detected: $($os.Caption) build $($os.BuildNumber)"
    exit 1
}

Write-Host "Detected: $($os.Caption) (build $($os.BuildNumber))"
Write-Host "Starting hardening..."
Write-Host ""

# ============================================================
# 1. FILESYSTEM AND TEMP DIRECTORY HARDENING
# ============================================================
# WHAT IT DOES:
#   - Restricts ACLs on the system Temp directory so only
#     Administrators and SYSTEM have full control.
#   - Disables legacy 8.3 short filename generation which
#     attackers use to bypass path-based security controls.
#   - Enables DEP (Data Execution Prevention) for all
#     processes, not just Windows services.
#
# IMPACT:
#   Some very old 16-bit or legacy applications may break
#   without 8.3 names. DEP can crash poorly written native
#   binaries that execute code from non-executable memory.
#   Both are acceptable tradeoffs on a modern server.
# ============================================================

Write-Host "[1/10] Hardening filesystem and temp directories..."

# Restrict TEMP directory ACLs
$tempPath = [System.IO.Path]::GetTempPath().TrimEnd('\')
if (Test-Path $tempPath) {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)  # disable inheritance
    $rules = @(
        @{ Identity = "BUILTIN\Administrators"; Rights = "FullControl";
           Inherit = "ContainerInherit,ObjectInherit"; Prop = "None"; Type = "Allow" },
        @{ Identity = "NT AUTHORITY\SYSTEM"; Rights = "FullControl";
           Inherit = "ContainerInherit,ObjectInherit"; Prop = "None"; Type = "Allow" },
        @{ Identity = "CREATOR OWNER"; Rights = "GenericAll";
           Inherit = "ContainerInherit,ObjectInherit"; Prop = "InheritOnly"; Type = "Allow" },
        @{ Identity = "BUILTIN\Users"; Rights = "CreateFiles,AppendData,ReadAndExecute,Synchronize";
           Inherit = "None"; Prop = "None"; Type = "Allow" }
    )
    foreach ($r in $rules) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $r.Identity,
            [System.Security.AccessControl.FileSystemRights]$r.Rights,
            [System.Security.AccessControl.InheritanceFlags]$r.Inherit,
            [System.Security.AccessControl.PropagationFlags]$r.Prop,
            [System.Security.AccessControl.AccessControlType]$r.Type
        )
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $tempPath -AclObject $acl
}

# Disable 8.3 short name generation
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"
Set-ItemProperty -Path $regPath -Name "NtfsDisable8dot3NameCreation" -Value 1 -Type DWord

# Enable DEP for all processes (OptOut = on for everything except explicitly excluded)
$dep = (Get-CimInstance Win32_OperatingSystem).DataExecutionPrevention_SupportPolicy
if ($dep -ne 3) {
    # bcdedit requires direct invocation
    & bcdedit.exe /set "{current}" nx OptOut 2>$null | Out-Null
}

# ============================================================
# 2. NETWORK STACK HARDENING (Registry)
# ============================================================
# WHAT IT DOES:
#   - Disables IP source routing (prevents spoofing tricks)
#   - Enables SYN flood protection
#   - Disables ICMP redirects
#   - Disables NetBIOS over TCP/IP on all adapters
#   - Disables LLMNR (Link-Local Multicast Name Resolution)
#     which is a common credential theft vector
#   - Disables WPAD (Web Proxy Auto-Discovery) to prevent
#     MITM proxy injection
#   - Enables Windows Firewall on all profiles
#
# IMPACT:
#   NetBIOS and LLMNR are disabled. Legacy name resolution
#   that depends on these (very old apps, some printers) will
#   break. Use DNS instead. WPAD disabled means no auto proxy
#   detection — configure proxies explicitly if needed.
# ============================================================

Write-Host "[2/10] Hardening network stack..."

# TCP/IP stack hardening via registry
$tcpParams = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$regSettings = @{
    "DisableIPSourceRouting"    = @{ Value = 2;  Type = "DWord" }  # drop source-routed packets
    "EnableICMPRedirect"        = @{ Value = 0;  Type = "DWord" }
    "SynAttackProtect"          = @{ Value = 1;  Type = "DWord" }
    "TcpMaxHalfOpen"            = @{ Value = 100; Type = "DWord" }
    "TcpMaxHalfOpenRetried"     = @{ Value = 80;  Type = "DWord" }
    "EnableDeadGWDetect"        = @{ Value = 0;  Type = "DWord" }
    "KeepAliveTime"             = @{ Value = 300000; Type = "DWord" }  # 5 min
    "PerformRouterDiscovery"    = @{ Value = 0;  Type = "DWord" }
    "EnablePMTUDiscovery"       = @{ Value = 0;  Type = "DWord" }
    "NoNameReleaseOnDemand"     = @{ Value = 1;  Type = "DWord" }
}

foreach ($name in $regSettings.Keys) {
    $s = $regSettings[$name]
    Set-ItemProperty -Path $tcpParams -Name $name -Value $s.Value -Type $s.Type -ErrorAction SilentlyContinue
}

# Also harden IPv6
$tcpv6Params = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
if (Test-Path $tcpv6Params) {
    Set-ItemProperty -Path $tcpv6Params -Name "DisableIPSourceRouting" -Value 2 -Type DWord -ErrorAction SilentlyContinue
}

# Disable NetBIOS over TCP/IP on all adapters
$adapters = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -ErrorAction SilentlyContinue
foreach ($adapter in $adapters) {
    Set-ItemProperty -Path $adapter.PSPath -Name "NetbiosOptions" -Value 2 -Type DWord -ErrorAction SilentlyContinue
}

# Disable LLMNR
$llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $llmnrPath)) { New-Item -Path $llmnrPath -Force | Out-Null }
Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWord

# Disable WPAD
$wpadPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc"
if (Test-Path $wpadPath) {
    Set-ItemProperty -Path $wpadPath -Name "Start" -Value 4 -Type DWord -ErrorAction SilentlyContinue
}

# Enable Windows Firewall on all profiles and set default deny inbound
Set-NetFirewallProfile -Profile Domain,Public,Private `
    -Enabled True `
    -DefaultInboundAction Block `
    -DefaultOutboundAction Allow `
    -LogAllowed False `
    -LogBlocked True `
    -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" `
    -LogMaxSizeKilobytes 16384

# ============================================================
# 3. DISABLE CRASH DUMPS AND ERROR REPORTING
# ============================================================
# WHAT IT DOES:
#   Disables Windows Error Reporting and memory dump
#   generation on crashes. Like core dumps on Linux, crash
#   dumps can contain secrets, credentials, and encryption
#   keys from process memory.
#
# IMPACT:
#   Debugging BSODs and application crashes becomes harder.
#   If you need to debug a specific crash, temporarily
#   re-enable via: wmic recoveros set DebugInfoType = 3
# ============================================================

Write-Host "[3/10] Disabling crash dumps and error reporting..."

# Disable full/kernel/small memory dumps
$crashPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
Set-ItemProperty -Path $crashPath -Name "CrashDumpEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path $crashPath -Name "LogEvent" -Value 1 -Type DWord

# Disable Windows Error Reporting
$werPath = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"
if (-not (Test-Path $werPath)) { New-Item -Path $werPath -Force | Out-Null }
Set-ItemProperty -Path $werPath -Name "Disabled" -Value 1 -Type DWord

# Disable WER service
Set-Service -Name "WerSvc" -StartupType Disabled -ErrorAction SilentlyContinue
Stop-Service -Name "WerSvc" -Force -ErrorAction SilentlyContinue

# ============================================================
# 4. AUDIT AND RESTRICT SERVICE ACCOUNT PRIVILEGES
# ============================================================
# WHAT IT DOES:
#   - Removes the "Debug programs" privilege from all users
#     (SeDebugPrivilege is the Windows equivalent of setuid
#     root — it lets you attach to any process)
#   - Restricts dangerous privileges to Administrators only
#   - Disables the built-in Guest account
#   - Disables the built-in Administrator account (after
#     verifying another admin exists in step 5)
#
# IMPACT:
#   Debuggers (WinDbg, Visual Studio debugger) won't work
#   for non-admin users. Remote debugging by non-admins
#   will fail. This is the correct posture for a server.
# ============================================================

Write-Host "[4/10] Restricting dangerous privileges..."

# Export current security policy, modify, and re-import
$secEditExport = "$env:TEMP\secpol_export.inf"
$secEditImport = "$env:TEMP\secpol_import.inf"
$secEditDb     = "$env:TEMP\secpol.sdb"

& secedit.exe /export /cfg $secEditExport /quiet 2>$null

$secContent = Get-Content $secEditExport -Raw

# SeDebugPrivilege — restrict to Administrators only
$secContent = $secContent -replace '(?m)^SeDebugPrivilege\s*=.*$', 'SeDebugPrivilege = *S-1-5-32-544'

# SeRemoteShutdownPrivilege — Administrators only
$secContent = $secContent -replace '(?m)^SeRemoteShutdownPrivilege\s*=.*$', 'SeRemoteShutdownPrivilege = *S-1-5-32-544'

# SeTakeOwnershipPrivilege — Administrators only
$secContent = $secContent -replace '(?m)^SeTakeOwnershipPrivilege\s*=.*$', 'SeTakeOwnershipPrivilege = *S-1-5-32-544'

Set-Content -Path $secEditImport -Value $secContent -Encoding ASCII
& secedit.exe /configure /db $secEditDb /cfg $secEditImport /quiet 2>$null

# Clean up temp files
Remove-Item -Path $secEditExport, $secEditImport, $secEditDb -Force -ErrorAction SilentlyContinue

# Disable Guest account
net user Guest /active:no 2>$null | Out-Null

# ============================================================
# 5. CREATE NON-ADMIN USER WITH SSH KEY
# ============================================================
# WHAT IT DOES:
#   Creates a new local administrator account and sets up
#   SSH public key authentication. This mirrors the LXC
#   script's approach: you'll log in as this user and
#   elevate with "Run as Administrator" or UAC instead of
#   logging in as the built-in Administrator.
#
# IMPACT:
#   The built-in Administrator account will be disabled
#   after this step. Use the new account for all access.
#   If you get locked out, boot into Safe Mode to re-enable
#   the built-in Administrator.
# ============================================================

Write-Host "[5/10] Creating administrative user..."

$NewUser = Read-Host "Enter username for new admin user"

if ([string]::IsNullOrWhiteSpace($NewUser)) {
    Write-Error "No username provided. Exiting."
    exit 1
}

$existingUser = Get-LocalUser -Name $NewUser -ErrorAction SilentlyContinue
if ($existingUser) {
    Write-Host "User '$NewUser' already exists. Skipping creation."
} else {
    $password = Read-Host "Enter password for '$NewUser'" -AsSecureString
    $confirmPassword = Read-Host "Confirm password" -AsSecureString

    # Convert to plain text for comparison
    $bstr1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    $bstr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmPassword)
    $plain1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr1)
    $plain2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr2)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr1)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2)

    if ($plain1 -ne $plain2) {
        # Zero out plaintext
        $plain1 = $null; $plain2 = $null
        Write-Error "Passwords do not match. Exiting."
        exit 1
    }
    $plain1 = $null; $plain2 = $null

    New-LocalUser -Name $NewUser -Password $password `
        -FullName "$NewUser" `
        -Description "Hardening script admin account" `
        -PasswordNeverExpires $false `
        -UserMayNotChangePassword $false | Out-Null

    Add-LocalGroupMember -Group "Administrators" -Member $NewUser
    Write-Host "User '$NewUser' created and added to Administrators."
}

# Set up SSH public key
Write-Host ""
Write-Host "Paste the SSH public key for '$NewUser'."
Write-Host "(Single line, starts with ssh-rsa, ssh-ed25519, etc.)"
$sshPubKey = Read-Host ">"

if ([string]::IsNullOrWhiteSpace($sshPubKey)) {
    Write-Host "WARNING: No SSH key provided. You can add one later to:"
    Write-Host "  C:\Users\$NewUser\.ssh\authorized_keys"
    Write-Host "  (or C:\ProgramData\ssh\administrators_authorized_keys for admin users)"
} else {
    # For members of Administrators group, keys go in the special file
    $sshDir = "C:\ProgramData\ssh"
    if (-not (Test-Path $sshDir)) { New-Item -Path $sshDir -ItemType Directory -Force | Out-Null }

    $adminKeysFile = Join-Path $sshDir "administrators_authorized_keys"

    # Append key (don't overwrite — other admins may have keys)
    Add-Content -Path $adminKeysFile -Value $sshPubKey

    # Fix permissions: only Administrators and SYSTEM
    $keyAcl = New-Object System.Security.AccessControl.FileSecurity
    $keyAcl.SetAccessRuleProtection($true, $false)
    $keyAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators", "FullControl", "Allow")))
    $keyAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT AUTHORITY\SYSTEM", "FullControl", "Allow")))
    Set-Acl -Path $adminKeysFile -AclObject $keyAcl

    # Also set up per-user authorized_keys for non-admin fallback
    $userSshDir = "C:\Users\$NewUser\.ssh"
    if (-not (Test-Path $userSshDir)) { New-Item -Path $userSshDir -ItemType Directory -Force | Out-Null }
    Add-Content -Path (Join-Path $userSshDir "authorized_keys") -Value $sshPubKey

    Write-Host "SSH key installed for '$NewUser'."
}

# Disable built-in Administrator account now that we have another admin
$builtinAdmin = Get-LocalUser | Where-Object { $_.SID -like "S-1-5-*-500" }
if ($builtinAdmin -and $builtinAdmin.Enabled) {
    Disable-LocalUser -Name $builtinAdmin.Name
    Write-Host "Built-in Administrator account '$($builtinAdmin.Name)' disabled."
}

# ============================================================
# 6. HARDEN SSH (OpenSSH Server)
# ============================================================
# WHAT IT DOES:
#   Installs OpenSSH Server if not present, then locks down
#   the sshd_config:
#   - Disables password authentication (key-only)
#   - Disables root/Administrator login
#   - Restricts to the user created in step 5
#   - Reduces auth timeout and max attempts
#
# IMPACT:
#   Only key-based SSH login works. If you lose your key,
#   you'll need console/RDP access to recover. Password-
#   based SSH will be rejected.
# ============================================================

Write-Host "[6/10] Hardening OpenSSH Server..."

# Install OpenSSH Server if not present
$sshdCapability = Get-WindowsCapability -Online | Where-Object { $_.Name -like "OpenSSH.Server*" }
if ($sshdCapability.State -ne "Installed") {
    Write-Host "Installing OpenSSH Server..."
    Add-WindowsCapability -Online -Name $sshdCapability.Name | Out-Null
}

# Ensure sshd service is set to auto-start
Set-Service -Name sshd -StartupType Automatic -ErrorAction SilentlyContinue

$sshdConfig = "C:\ProgramData\ssh\sshd_config"
if (Test-Path $sshdConfig) {
    Copy-Item $sshdConfig "${sshdConfig}.bak" -Force

    $hardenedConfig = @"
# Hardened sshd_config - Generated by harden_windows_server.ps1

Port 22
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

# Authentication
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 20
AuthenticationMethods publickey

# Disable root/Administrator login
# On Windows, this maps to the built-in Administrator account
DenyUsers Administrator

# Restrict to hardened user
AllowUsers $NewUser

# Session
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Override default of using administrators_authorized_keys for admin users
# (We already set this up in step 5, keep it enabled)
Match Group administrators
    AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
"@

    Set-Content -Path $sshdConfig -Value $hardenedConfig -Encoding ASCII
    Restart-Service sshd -ErrorAction SilentlyContinue
    Write-Host "OpenSSH Server hardened and restarted."
} else {
    Write-Host "WARNING: sshd_config not found. OpenSSH may not be installed correctly."
}

# Allow SSH through firewall
$sshRule = Get-NetFirewallRule -DisplayName "OpenSSH Server (sshd)" -ErrorAction SilentlyContinue
if (-not $sshRule) {
    New-NetFirewallRule -DisplayName "OpenSSH Server (sshd)" `
        -Direction Inbound -Protocol TCP -LocalPort 22 `
        -Action Allow -Profile Any | Out-Null
}

# ============================================================
# 7. AUTOMATIC SECURITY UPDATES
# ============================================================
# WHAT IT DOES:
#   Configures Windows Update to automatically download and
#   install security updates. Sets active hours to avoid
#   unexpected reboots during business hours.
#
# IMPACT:
#   The server will auto-install security patches. In rare
#   cases a bad update can break something. You can review
#   update history in Settings > Windows Update > Update
#   history, or via: Get-HotFix | Sort InstalledOn
# ============================================================

Write-Host "[7/10] Configuring automatic security updates..."

$wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$auPath = "$wuPath\AU"

if (-not (Test-Path $wuPath)) { New-Item -Path $wuPath -Force | Out-Null }
if (-not (Test-Path $auPath)) { New-Item -Path $auPath -Force | Out-Null }

# AUOptions: 4 = Auto download and schedule install
Set-ItemProperty -Path $auPath -Name "AUOptions" -Value 4 -Type DWord
# Enable auto updates
Set-ItemProperty -Path $auPath -Name "NoAutoUpdate" -Value 0 -Type DWord
# Schedule install day: 0 = every day
Set-ItemProperty -Path $auPath -Name "ScheduledInstallDay" -Value 0 -Type DWord
# Schedule install time: 3 = 3:00 AM
Set-ItemProperty -Path $auPath -Name "ScheduledInstallTime" -Value 3 -Type DWord
# Include recommended updates
Set-ItemProperty -Path $auPath -Name "IncludeRecommendedUpdates" -Value 1 -Type DWord

Write-Host "Windows Update configured for automatic security patching at 3:00 AM daily."

# ============================================================
# 8. REMOVE UNNECESSARY SERVICES AND FEATURES
# ============================================================
# WHAT IT DOES:
#   Disables Windows services and optional features that
#   increase attack surface on a server. Includes:
#   - Print Spooler (common exploit vector, PrintNightmare)
#   - Remote Registry
#   - Xbox services
#   - Fax, Bluetooth, etc.
#   - SMBv1 (WannaCry, EternalBlue)
#   - PowerShell v2 (bypasses AMSI, script block logging)
#
# IMPACT:
#   No printing from this server. No SMBv1 clients can
#   connect. PowerShell v2 engine unavailable (good — it
#   bypasses modern security controls). If you need any of
#   these, re-enable them individually.
# ============================================================

Write-Host "[8/10] Removing unnecessary services and features..."

$servicesToDisable = @(
    "Spooler"           # Print Spooler — PrintNightmare vector
    "RemoteRegistry"    # Remote Registry access
    "lfsvc"             # Geolocation
    "MapsBroker"        # Downloaded Maps Manager
    "XblAuthManager"    # Xbox Live Auth
    "XblGameSave"       # Xbox Live Game Save
    "XboxNetApiSvc"     # Xbox Live Networking
    "XboxGipSvc"        # Xbox Gamepad Input Protocol
    "Fax"               # Fax service
    "TapiSrv"           # Telephony
    "bthserv"           # Bluetooth Support
    "irmon"             # Infrared Monitor
    "WMPNetworkSvc"     # Windows Media Player Sharing
    "wisvc"             # Windows Insider Service
    "RetailDemo"        # Retail Demo
    "lltdsvc"           # Link-Layer Topology Discovery
    "SSDPSRV"           # SSDP Discovery
    "upnphost"          # UPnP Device Host
    "WpcMonSvc"         # Parental Controls
    "icssvc"            # Windows Mobile Hotspot
    "PhoneSvc"          # Phone Service
    "Browser"           # Computer Browser (SMBv1 dependent)
)

foreach ($svc in $servicesToDisable) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    }
}

# Disable SMBv1
$smb1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
if ($smb1 -and $smb1.State -eq "Enabled") {
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Write-Host "SMBv1 disabled (requires reboot to take full effect)."
}

# Disable PowerShell v2 engine (bypasses AMSI and script block logging)
$psv2 = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction SilentlyContinue
if ($psv2 -and $psv2.State -eq "Enabled") {
    Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Write-Host "PowerShell v2 engine disabled."
}

# Harden SMBv2/v3 settings
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
Set-SmbServerConfiguration -EncryptData $true -Force -ErrorAction SilentlyContinue
Set-SmbServerConfiguration -RejectUnencryptedAccess $true -Force -ErrorAction SilentlyContinue

Write-Host "Unnecessary services and features disabled."

# ============================================================
# 9. USER, LOGIN, AND AUDIT POLICY HARDENING
# ============================================================
# WHAT IT DOES:
#   - Sets strong password policy (min length, complexity,
#     history, max age)
#   - Configures account lockout after failed attempts
#   - Enables comprehensive audit logging (logon events,
#     privilege use, object access, policy changes)
#   - Enables PowerShell script block logging and module
#     logging for forensic analysis
#   - Restricts anonymous access and null sessions
#
# IMPACT:
#   Users must use complex passwords (12+ chars). Accounts
#   lock for 30 minutes after 5 failed attempts. Audit logs
#   will consume more disk space. PowerShell commands are
#   logged to the event log — do not type secrets in PS.
# ============================================================

Write-Host "[9/10] Hardening user, login, and audit policies..."

# Password policy via net accounts
& net accounts /minpwlen:12 /maxpwage:90 /minpwage:1 /uniquepw:12 2>$null | Out-Null

# Account lockout policy
& net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 2>$null | Out-Null

# Enable advanced audit policies
$auditCategories = @(
    @{ Subcategory = "Logon";                   Success = "enable"; Failure = "enable" }
    @{ Subcategory = "Logoff";                  Success = "enable"; Failure = "disable" }
    @{ Subcategory = "Account Lockout";         Success = "enable"; Failure = "enable" }
    @{ Subcategory = "Special Logon";           Success = "enable"; Failure = "disable" }
    @{ Subcategory = "Credential Validation";   Success = "enable"; Failure = "enable" }
    @{ Subcategory = "Sensitive Privilege Use";  Success = "enable"; Failure = "enable" }
    @{ Subcategory = "Security Group Management"; Success = "enable"; Failure = "enable" }
    @{ Subcategory = "User Account Management"; Success = "enable"; Failure = "enable" }
    @{ Subcategory = "Process Creation";        Success = "enable"; Failure = "disable" }
    @{ Subcategory = "Audit Policy Change";     Success = "enable"; Failure = "enable" }
    @{ Subcategory = "Authentication Policy Change"; Success = "enable"; Failure = "enable" }
)

foreach ($audit in $auditCategories) {
    & auditpol.exe /set /subcategory:"$($audit.Subcategory)" `
        /success:$($audit.Success) /failure:$($audit.Failure) 2>$null | Out-Null
}

# Enable command line in process creation events (Event ID 4688)
$processCreationPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $processCreationPath)) { New-Item -Path $processCreationPath -Force | Out-Null }
Set-ItemProperty -Path $processCreationPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

# PowerShell script block logging
$psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $psLogPath)) { New-Item -Path $psLogPath -Force | Out-Null }
Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

# PowerShell module logging
$psModLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (-not (Test-Path $psModLogPath)) { New-Item -Path $psModLogPath -Force | Out-Null }
Set-ItemProperty -Path $psModLogPath -Name "EnableModuleLogging" -Value 1 -Type DWord
$psModNamesPath = "$psModLogPath\ModuleNames"
if (-not (Test-Path $psModNamesPath)) { New-Item -Path $psModNamesPath -Force | Out-Null }
Set-ItemProperty -Path $psModNamesPath -Name "*" -Value "*" -Type String

# PowerShell transcription (log all PS sessions to disk)
$psTransPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
if (-not (Test-Path $psTransPath)) { New-Item -Path $psTransPath -Force | Out-Null }
Set-ItemProperty -Path $psTransPath -Name "EnableTranscripting" -Value 1 -Type DWord
Set-ItemProperty -Path $psTransPath -Name "OutputDirectory" -Value "C:\PSTranscripts" -Type String
Set-ItemProperty -Path $psTransPath -Name "EnableInvocationHeader" -Value 1 -Type DWord
if (-not (Test-Path "C:\PSTranscripts")) { New-Item -Path "C:\PSTranscripts" -ItemType Directory -Force | Out-Null }

# Restrict anonymous access
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymous" -Value 1 -Type DWord
Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymousSAM" -Value 1 -Type DWord
Set-ItemProperty -Path $lsaPath -Name "EveryoneIncludesAnonymous" -Value 0 -Type DWord
# Disable null sessions
Set-ItemProperty -Path $lsaPath -Name "RestrictNullSessAccess" -Value 1 -Type DWord
# Enable auditing of backup and restore privilege use
Set-ItemProperty -Path $lsaPath -Name "FullPrivilegeAuditing" -Value ([byte[]](1)) -Type Binary

# Increase Security event log size (default is too small for auditing)
$secLogPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"
Set-ItemProperty -Path $secLogPath -Name "MaxSize" -Value 1073741824 -Type DWord  # 1 GB

Write-Host "Password policy, account lockout, audit logging configured."

# ============================================================
# 10. RESTRICT REMOTE ACCESS AND ENUMERATION
# ============================================================
# WHAT IT DOES:
#   - Disables remote Desktop unless explicitly needed
#   - Enables NLA (Network Level Authentication) for RDP
#   - Restricts anonymous enumeration of SAM accounts and
#     shares (prevents attackers from listing users/shares)
#   - Disables WinRM if not needed (common lateral movement
#     vector)
#   - Enables LSA protection (RunAsPPL) to prevent credential
#     dumping tools like Mimikatz
#   - Enables Credential Guard where supported
#
# IMPACT:
#   RDP is disabled by default. If you need RDP, re-enable
#   with NLA required. WinRM is disabled — if you use
#   Ansible/DSC/remote PS, you'll need to re-enable it
#   with HTTPS transport and certificate auth. LSA protection
#   may break some very old authentication providers.
# ============================================================

Write-Host "[10/10] Restricting remote access and enumeration..."

# Disable RDP (uncomment the second line to keep RDP enabled with NLA)
$rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
Set-ItemProperty -Path $rdpPath -Name "fDenyTSConnections" -Value 1 -Type DWord
# If you want RDP enabled with NLA, comment the line above and uncomment these:
# Set-ItemProperty -Path $rdpPath -Name "fDenyTSConnections" -Value 0 -Type DWord
# Set-ItemProperty -Path "$rdpPath\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -Type DWord
# Set-ItemProperty -Path "$rdpPath\WinStations\RDP-Tcp" -Name "SecurityLayer" -Value 2 -Type DWord

# Disable WinRM service
Set-Service -Name WinRM -StartupType Disabled -ErrorAction SilentlyContinue
Stop-Service -Name WinRM -Force -ErrorAction SilentlyContinue

# Restrict remote SAM calls to Administrators only (SDDL: only BA = Builtin Administrators)
$lsaPath10 = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $lsaPath10 -Name "RestrictRemoteSAM" `
    -Value "O:BAG:BAD:(A;;RC;;;BA)" -Type String -ErrorAction SilentlyContinue

# Enable LSA Protection (RunAsPPL) — blocks Mimikatz-style credential dumping
Set-ItemProperty -Path $lsaPath10 -Name "RunAsPPL" -Value 1 -Type DWord

# Enable Credential Guard (if hardware supports it)
$credGuardPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
if (-not (Test-Path $credGuardPath)) { New-Item -Path $credGuardPath -Force | Out-Null }
Set-ItemProperty -Path $credGuardPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
Set-ItemProperty -Path $credGuardPath -Name "RequirePlatformSecurityFeatures" -Value 1 -Type DWord
Set-ItemProperty -Path $lsaPath10 -Name "LsaCfgFlags" -Value 1 -Type DWord

Write-Host "Remote access restricted. LSA protection enabled."

# ============================================================
# DONE
# ============================================================

Write-Host ""
Write-Host "========================================="
Write-Host " Hardening complete."
Write-Host "========================================="
Write-Host ""
Write-Host "IMPORTANT reminders:"
Write-Host "  - Admin user: $NewUser (built-in Administrator disabled)"
Write-Host "  - SSH is key-only. Password is for local/RDP only."
Write-Host "  - Test SSH access BEFORE closing your current session."
Write-Host "  - RDP is DISABLED. Re-enable in section 10 if needed."
Write-Host "  - WinRM is DISABLED. Re-enable with HTTPS if you need"
Write-Host "    remote PowerShell/Ansible/DSC management."
Write-Host "  - SMBv1 is disabled. Old XP/2003 clients cannot connect."
Write-Host "  - Print Spooler is disabled (PrintNightmare mitigation)."
Write-Host "  - PowerShell sessions are transcribed to C:\PSTranscripts"
Write-Host "  - Review Windows Update settings if using WSUS/SCCM."
Write-Host "  - Reboot the server to ensure all changes take effect"
Write-Host "    (some features like Credential Guard require reboot)."
Write-Host ""
