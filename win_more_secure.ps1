# =============================================================================
#  Windows Security Enhancer  v5.0
#  Hardens Windows 10 / 11 / Server systems against modern attack techniques.
#
#  Run via runner.bat (requires Administrator privileges).
#
#  Highlights of v5.0:
#    * Full transcript logging  ->  %ProgramData%\WSE\logs\
#    * Automatic registry backup before each change (Option 93 = rollback)
#    * OS / edition / capability detection (gracefully skips unsupported ops)
#    * 20+ new hardening features (SChannel, DoH, HVCI, SMB/LDAP signing, ...)
#    * Critical bug fixes from v4.x (USB root-hub, $profile shadow, AllSigned-lockout)
# =============================================================================

# -----------------------------------------------------------------------------
#  Global execution context
# -----------------------------------------------------------------------------
Set-StrictMode -Version 1.0   # catches uninitialized vars without breaking on $null property access
$ErrorActionPreference = 'Continue'   # don't crash the whole script on one bad call
$PSDefaultParameterValues['*:ErrorAction'] = 'SilentlyContinue'

$Script:WSEVersion       = '5.0'
$Script:WSERoot          = Join-Path $env:ProgramData 'WSE'
$Script:WSELogDir        = Join-Path $Script:WSERoot 'logs'
$Script:WSEBackupRoot    = Join-Path $Script:WSERoot 'backups'
$Script:WSESessionStart  = Get-Date
$Script:WSESessionStamp  = $Script:WSESessionStart.ToString('yyyyMMdd_HHmmss')
$Script:WSESessionBackup = Join-Path $Script:WSEBackupRoot $Script:WSESessionStamp
$Script:WSETranscript    = Join-Path $Script:WSELogDir   "wse_$($Script:WSESessionStamp).log"
$Script:WSEBackupFile    = Join-Path $Script:WSESessionBackup 'registry_backup.json'
$Script:WSEBackupEntries = New-Object System.Collections.Generic.List[object]
$Script:WSECapabilities  = $null
$Script:WSETranscriptStarted = $false

# -----------------------------------------------------------------------------
#  Privilege check / self-elevation
# -----------------------------------------------------------------------------
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "  [!] Administrator privileges required. Re-launching as Administrator..." -ForegroundColor Yellow
    $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
    try {
        Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" `
            -Verb RunAs -ErrorAction Stop
    } catch {
        Write-Host "  [-] Could not elevate privileges: $_" -ForegroundColor Red
        Write-Host "  [!] Right-click runner.bat and select 'Run as administrator'." -ForegroundColor Yellow
        Read-Host "  Press ENTER to exit"
        exit 1
    }
    exit
}

# =============================================================================
#  COLOURED OUTPUT HELPERS
# =============================================================================
function Write-Info    { param([string]$m) Write-Host "  [*] $m" -ForegroundColor Cyan    }
function Write-Ok      { param([string]$m) Write-Host "  [+] $m" -ForegroundColor Green   }
function Write-Warn    { param([string]$m) Write-Host "  [!] $m" -ForegroundColor Yellow  }
function Write-Fail    { param([string]$m) Write-Host "  [-] $m" -ForegroundColor Red     }
function Write-Section {
    param([string]$Title)
    $line = '─' * 60
    Write-Host ""
    Write-Host "  $line" -ForegroundColor DarkCyan
    Write-Host "   $Title" -ForegroundColor White
    Write-Host "  $line" -ForegroundColor DarkCyan
}

# =============================================================================
#  INFRASTRUCTURE  —  logging, backups, OS detection
# =============================================================================

function Initialize-WSE {
    foreach ($d in @($Script:WSERoot, $Script:WSELogDir, $Script:WSEBackupRoot, $Script:WSESessionBackup)) {
        if (-not (Test-Path $d)) {
            try { New-Item -Path $d -ItemType Directory -Force | Out-Null } catch {
                Write-Fail "Could not create WSE directory '$d': $_"
            }
        }
    }

    # ACL the WSE root so only Administrators + SYSTEM can read/write (logs may contain configs)
    try {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        $admins = New-Object System.Security.AccessControl.FileSystemAccessRule(
            'BUILTIN\Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $system = New-Object System.Security.AccessControl.FileSystemAccessRule(
            'NT AUTHORITY\SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($admins)
        $acl.AddAccessRule($system)
        Set-Acl -Path $Script:WSERoot -AclObject $acl -ErrorAction SilentlyContinue
    } catch {}

    try {
        Start-Transcript -Path $Script:WSETranscript -Append -ErrorAction Stop | Out-Null
        $Script:WSETranscriptStarted = $true
    } catch {
        Write-Warn "Could not start transcript logging: $_"
    }
}

function Stop-WSE {
    if ($Script:WSETranscriptStarted) {
        try { Stop-Transcript | Out-Null } catch {}
    }
    if ($Script:WSEBackupEntries.Count -gt 0) {
        try {
            $Script:WSEBackupEntries |
                ConvertTo-Json -Depth 5 |
                Set-Content -Path $Script:WSEBackupFile -Encoding UTF8 -Force
        } catch {
            Write-Warn "Could not write registry backup file: $_"
        }
    }
}

function Get-WSECapabilities {
    if ($Script:WSECapabilities) { return $Script:WSECapabilities }

    $os = $null
    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch {}

    $caps = [pscustomobject]@{
        OSName            = if ($os) { $os.Caption } else { 'Unknown' }
        OSVersion         = if ($os) { $os.Version } else { 'Unknown' }
        OSBuild           = if ($os) { $os.BuildNumber } else { 'Unknown' }
        Edition           = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'EditionID' -ErrorAction SilentlyContinue).EditionID
        IsServer          = if ($os) { $os.ProductType -ne 1 } else { $false }
        PSVersion         = $PSVersionTable.PSVersion.ToString()
        BitLockerAvailable= [bool](Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)
        DefenderAvailable = [bool](Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)
        SmbCmdletsAvailable= [bool](Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue)
        ProcessMitigationAvailable = [bool](Get-Command Set-ProcessMitigation -ErrorAction SilentlyContinue)
        TpmPresent        = $false
        TpmReady          = $false
        DnsClientCmdlets  = [bool](Get-Command Set-DnsClientServerAddress -ErrorAction SilentlyContinue)
        DohSupported      = [bool](Get-Command Set-DnsClientDohServerAddress -ErrorAction SilentlyContinue)
    }
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        $caps.TpmPresent = [bool]$tpm.TpmPresent
        $caps.TpmReady   = [bool]$tpm.TpmReady
    } catch {}

    $Script:WSECapabilities = $caps
    return $caps
}

function Show-CapabilityReport {
    $c = Get-WSECapabilities
    Write-Section "Operating-System & Capability Report"
    Write-Host ("  OS                 : {0}"  -f $c.OSName)            -ForegroundColor Cyan
    Write-Host ("  Version / Build    : {0} / {1}"  -f $c.OSVersion, $c.OSBuild) -ForegroundColor Cyan
    Write-Host ("  Edition            : {0}"  -f $c.Edition)           -ForegroundColor Cyan
    Write-Host ("  Server SKU         : {0}"  -f $c.IsServer)          -ForegroundColor Cyan
    Write-Host ("  PowerShell         : {0}"  -f $c.PSVersion)         -ForegroundColor Cyan
    Write-Host ("  Defender cmdlets   : {0}"  -f $c.DefenderAvailable) -ForegroundColor Cyan
    Write-Host ("  BitLocker cmdlets  : {0}"  -f $c.BitLockerAvailable)-ForegroundColor Cyan
    Write-Host ("  SMB Server cmdlets : {0}"  -f $c.SmbCmdletsAvailable) -ForegroundColor Cyan
    Write-Host ("  Process mitigation : {0}"  -f $c.ProcessMitigationAvailable) -ForegroundColor Cyan
    Write-Host ("  DoH supported      : {0}"  -f $c.DohSupported)      -ForegroundColor Cyan
    Write-Host ("  TPM present        : {0}"  -f $c.TpmPresent)        -ForegroundColor Cyan
    Write-Host ("  TPM ready          : {0}"  -f $c.TpmReady)          -ForegroundColor Cyan
    Write-Host ""
    Write-Host ("  Log file           : {0}"  -f $Script:WSETranscript) -ForegroundColor DarkGray
    Write-Host ("  Backup dir         : {0}"  -f $Script:WSESessionBackup) -ForegroundColor DarkGray
    Write-Host ""
}

function Backup-RegistryValue {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Name,
        [string] $Type = 'DWord'
    )
    $existing = $null
    $existedBefore = $true
    try {
        $existing = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
    } catch {
        $existedBefore = $false
    }
    $entry = [pscustomobject]@{
        Path          = $Path
        Name          = $Name
        Type          = $Type
        ExistedBefore = $existedBefore
        OldValue      = $existing
        Timestamp     = (Get-Date).ToString('o')
    }
    $Script:WSEBackupEntries.Add($entry) | Out-Null
}

function Set-WSERegistry {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] $Value,
        [ValidateSet('DWord','QWord','String','ExpandString','MultiString','Binary')]
        [string] $Type = 'DWord'
    )
    if (-not (Test-Path $Path)) {
        try { New-Item -Path $Path -Force | Out-Null } catch {
            Write-Fail "Could not create registry path '$Path': $_"
            return $false
        }
    }
    Backup-RegistryValue -Path $Path -Name $Name -Type $Type
    try {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
        return $true
    } catch {
        Write-Fail "Failed to set '$Path\$Name' = $Value : $_"
        return $false
    }
}

function New-WSERestorePoint {
    Write-Info "Creating a System Restore Point before applying changes..."
    try {
        # SR is throttled by Windows — bypass the 1440-minute limit for this op
        $sr = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
        if (Test-Path $sr) {
            Set-ItemProperty -Path $sr -Name "SystemRestorePointCreationFrequency" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        }
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
        Checkpoint-Computer -Description "Windows Security Enhancer v$($Script:WSEVersion) - $($Script:WSESessionStamp)" `
            -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Ok "System Restore Point created."
    } catch {
        Write-Warn "Could not create a System Restore Point: $_"
        Write-Warn "System Protection may be disabled or unsupported on this edition."
    }
}

function Invoke-WSERollback {
    Write-Section "Rollback — Restore registry values from a previous WSE backup"
    if (-not (Test-Path $Script:WSEBackupRoot)) {
        Write-Warn "No backup directory found at $Script:WSEBackupRoot"
        return
    }
    $backups = @(Get-ChildItem -Path $Script:WSEBackupRoot -Directory -ErrorAction SilentlyContinue |
                 Where-Object { Test-Path (Join-Path $_.FullName 'registry_backup.json') } |
                 Sort-Object Name -Descending)
    if ($backups.Count -eq 0) {
        Write-Warn "No backups available."
        return
    }
    Write-Host "  Available backups (newest first):" -ForegroundColor Cyan
    for ($i = 0; $i -lt $backups.Count; $i++) {
        Write-Host ("    [{0}]  {1}" -f $i, $backups[$i].Name) -ForegroundColor White
    }
    $sel = Read-Host "  Enter backup index to restore (blank to cancel)"
    if ([string]::IsNullOrWhiteSpace($sel)) { Write-Warn "Rollback cancelled."; return }
    $idx = 0
    if (-not [int]::TryParse($sel, [ref]$idx)) { Write-Fail "Not a number."; return }
    if ($idx -lt 0 -or $idx -ge $backups.Count) { Write-Fail "Index out of range."; return }
    $file = Join-Path $backups[$idx].FullName 'registry_backup.json'
    try {
        $entries = Get-Content $file -Raw | ConvertFrom-Json
    } catch {
        Write-Fail "Failed to read backup file: $_"
        return
    }

    $confirm = Read-Host "  Restore $($entries.Count) registry values from '$($backups[$idx].Name)'? Type YES to confirm"
    if ($confirm -ne 'YES') { Write-Warn "Rollback aborted."; return }

    $restored = 0; $deleted = 0; $errors = 0
    foreach ($e in $entries) {
        try {
            if (-not (Test-Path $e.Path)) { New-Item -Path $e.Path -Force | Out-Null }
            if ($e.ExistedBefore) {
                Set-ItemProperty -Path $e.Path -Name $e.Name -Value $e.OldValue -Type $e.Type -Force -ErrorAction Stop
                $restored++
            } else {
                Remove-ItemProperty -Path $e.Path -Name $e.Name -Force -ErrorAction SilentlyContinue
                $deleted++
            }
        } catch {
            $errors++
        }
    }
    Write-Ok "Rollback complete: $restored values restored, $deleted removed, $errors errors."
    Write-Warn "Some changes (services, firewall rules, GPO-style policies) are NOT rolled back automatically."
    Write-Warn "Use option 50 to inspect the current state, then re-enable specific features if needed."
}

# =============================================================================
#  UAC FUNCTIONS
# =============================================================================

function Enforce-UACPasswordPrompt {
    Write-Info "Enforcing UAC to require credentials for admin tasks..."
    $p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-WSERegistry -Path $p -Name "ConsentPromptBehaviorAdmin" -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $p -Name "PromptOnSecureDesktop"      -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $p -Name "EnableLUA"                  -Value 1 -Type DWord | Out-Null
    Write-Ok "UAC configured to require credentials for admin tasks."
}

function Set-UACAlwaysNotify {
    Write-Info "Setting UAC to 'Always Notify'..."
    $p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-WSERegistry -Path $p -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord | Out-Null
    Set-WSERegistry -Path $p -Name "PromptOnSecureDesktop"      -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $p -Name "EnableLUA"                  -Value 1 -Type DWord | Out-Null
    Write-Ok "UAC set to 'Always Notify'."
}

function Restore-UACToNormal {
    Write-Info "Restoring UAC to Windows default settings..."
    $p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-WSERegistry -Path $p -Name "ConsentPromptBehaviorAdmin" -Value 5 -Type DWord | Out-Null
    Set-WSERegistry -Path $p -Name "PromptOnSecureDesktop"      -Value 0 -Type DWord | Out-Null
    Write-Ok "UAC restored to default (notify on app changes)."
}

# =============================================================================
#  ACCOUNT & PASSWORD POLICY
# =============================================================================

function Set-AccountLockoutPolicy {
    Write-Info "Setting account lockout policy (5 attempts / 30-min lockout)..."
    & net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 2>&1 | Out-Null
    Write-Ok "Account lockout policy applied."
}

function Disable-AccountLockoutPolicy {
    Write-Warn "Removing account lockout protection is a security regression."
    & net accounts /lockoutthreshold:0 2>&1 | Out-Null
    Write-Ok "Account lockout policy reverted to default."
}

function Set-StrongPasswordPolicy {
    Write-Info "Enforcing strong password policy (14+ chars, complexity, 90-day expiry)..."
    & net accounts /minpwlen:14 /maxpwage:90 /minpwage:1 /uniquepw:10 2>&1 | Out-Null

    $tmpCfg = Join-Path $env:TEMP "secpol_tmp_$([Guid]::NewGuid().ToString('N')).cfg"
    $tmpSdb = Join-Path $env:TEMP "secpol_tmp_$([Guid]::NewGuid().ToString('N')).sdb"
    & secedit /export /cfg $tmpCfg /quiet 2>&1 | Out-Null
    if (Test-Path $tmpCfg) {
        (Get-Content $tmpCfg) `
            -replace 'PasswordComplexity\s*=\s*\d', 'PasswordComplexity = 1' `
            -replace 'ClearTextPassword\s*=\s*\d', 'ClearTextPassword = 0' `
            -replace 'LSAAnonymousNameLookup\s*=\s*\d', 'LSAAnonymousNameLookup = 0' |
            Set-Content $tmpCfg
        & secedit /configure /db $tmpSdb /cfg $tmpCfg /quiet 2>&1 | Out-Null
        Remove-Item $tmpCfg, $tmpSdb -Force -ErrorAction SilentlyContinue
    }
    Write-Ok "Strong password policy applied (14-char minimum, complexity on, 90-day expiry)."
}

# =============================================================================
#  CAMERA MANAGEMENT
# =============================================================================

function Disable-Cameras {
    Write-Info "Detecting and disabling connected camera devices..."
    $cameras = @(Get-PnpDevice -ErrorAction SilentlyContinue |
                 Where-Object { $_.Class -in @('Camera','Image') -or
                                $_.FriendlyName -match 'camera|webcam' })
    if ($cameras.Count -eq 0) { Write-Warn "No camera devices found."; return }
    foreach ($cam in $cameras) {
        try {
            Disable-PnpDevice -InstanceId $cam.InstanceId -Confirm:$false -ErrorAction Stop
            Write-Ok "Disabled: $($cam.FriendlyName)"
        } catch {
            Write-Fail "Could not disable '$($cam.FriendlyName)': $_"
        }
    }
    # Policy-level lockdown — prevents apps from accessing the camera even if drivers are re-enabled
    $cap = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"
    if (Test-Path $cap) { Set-WSERegistry -Path $cap -Name "Value" -Value "Deny" -Type String | Out-Null }
}

function Enable-Cameras {
    Write-Info "Enabling connected camera devices..."
    $cameras = @(Get-PnpDevice -ErrorAction SilentlyContinue |
                 Where-Object { $_.Class -in @('Camera','Image') -or
                                $_.FriendlyName -match 'camera|webcam' })
    if ($cameras.Count -eq 0) { Write-Warn "No camera devices found."; return }
    foreach ($cam in $cameras) {
        try {
            Enable-PnpDevice -InstanceId $cam.InstanceId -Confirm:$false -ErrorAction Stop
            Write-Ok "Enabled: $($cam.FriendlyName)"
        } catch {
            Write-Fail "Could not enable '$($cam.FriendlyName)': $_"
        }
    }
}

# =============================================================================
#  USB STORAGE   (fixed — no longer disables USB root hubs / HID devices)
# =============================================================================

function Disable-USBPorts {
    Write-Info "Disabling USB mass-storage class drivers..."
    # USBSTOR driver — blocks USB sticks / external HDDs
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor" -Name "Start" -Value 4 -Type DWord | Out-Null
    # USB CD/DVD class
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\cdrom"   -Name "Start" -Value 4 -Type DWord | Out-Null
    # Removable storage policy (deny all read/write to removable drives)
    $rsp = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"
    Set-WSERegistry -Path $rsp -Name "Deny_All" -Value 1 -Type DWord | Out-Null
    Write-Ok "USB mass storage disabled.  Keyboards, mice and other HID devices are not affected."
}

function Enable-USBPorts {
    Write-Info "Re-enabling USB mass-storage class drivers..."
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor" -Name "Start" -Value 3 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\cdrom"   -Name "Start" -Value 1 -Type DWord | Out-Null
    $rsp = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"
    if (Test-Path $rsp) { Set-WSERegistry -Path $rsp -Name "Deny_All" -Value 0 -Type DWord | Out-Null }
    Write-Ok "USB mass storage re-enabled."
}

# =============================================================================
#  WINDOWS FIREWALL
# =============================================================================

function Enable-WindowsFirewall {
    Write-Info "Enabling Windows Firewall for all profiles..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
    Set-NetFirewallProfile -Profile Domain,Public,Private -AllowInboundRules True
    Set-NetFirewallProfile -Profile Public                -NotifyOnListen True
    Write-Ok "Windows Firewall enabled; default inbound action set to Block."

    Write-Info "Blocking commonly exploited inbound ports..."
    $ports = @(
        @{Port=23;   Name='Telnet'},
        @{Port=135;  Name='RPC-DCOM'},
        @{Port=137;  Name='NetBIOS-NS'; Proto='UDP'},
        @{Port=138;  Name='NetBIOS-DGM';Proto='UDP'},
        @{Port=139;  Name='NetBIOS-SSN'},
        @{Port=445;  Name='SMB'},
        @{Port=1433; Name='MSSQL'},
        @{Port=1434; Name='MSSQL-Browser'; Proto='UDP'},
        @{Port=3389; Name='RDP'},
        @{Port=5985; Name='WinRM-HTTP'},
        @{Port=5986; Name='WinRM-HTTPS'}
    )
    foreach ($p in $ports) {
        $proto = if ($p.ContainsKey('Proto')) { $p.Proto } else { 'TCP' }
        $rule  = "WSE-Block-$($p.Name)-Inbound-$proto"
        if (-not (Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $rule -Direction Inbound -Protocol $proto `
                -LocalPort $p.Port -Action Block -Profile Public -ErrorAction SilentlyContinue | Out-Null
            Write-Ok "Blocked inbound $proto $($p.Port) ($($p.Name)) on Public profile."
        } else {
            Write-Warn "Rule '$rule' already exists — skipped."
        }
    }
    Write-Ok "Firewall hardening complete (Public profile gets the strictest rules)."
}

function Disable-WindowsFirewall {
    Write-Warn "WARNING: Disabling the Windows Firewall removes a critical defence layer."
    $c = Read-Host "  Type DISABLE to confirm (any other input cancels)"
    if ($c -ne 'DISABLE') { Write-Warn "Cancelled."; return }
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    Write-Ok "Windows Firewall disabled for all profiles."
}

# =============================================================================
#  SMBv1
# =============================================================================

function Disable-SMBv1 {
    Write-Info "Disabling SMBv1 (prevents WannaCry / EternalBlue attacks)..."
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
        Write-Ok "SMBv1 server protocol disabled via Set-SmbServerConfiguration."
    } catch {
        Write-Warn "Set-SmbServerConfiguration unavailable — using registry fallback."
        Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
            -Name "SMB1" -Value 0 -Type DWord | Out-Null
        Write-Ok "SMBv1 disabled via registry."
    }
    # SMBv1 client (mrxsmb10)
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Value 4 -Type DWord | Out-Null

    $feat = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
    if ($feat -and $feat.State -eq 'Enabled') {
        Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Write-Ok "SMBv1 Windows optional feature disabled."
    }
    Write-Warn "A restart may be required for all SMBv1 changes to take full effect."
}

function Enable-SMBv1 {
    Write-Warn "WARNING: SMBv1 is a legacy, insecure protocol. Enabling it is not recommended."
    $c = Read-Host "  Type ENABLE-SMB1 to confirm (any other input cancels)"
    if ($c -ne 'ENABLE-SMB1') { Write-Warn "Cancelled."; return }
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -ErrorAction Stop
    } catch {
        Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
            -Name "SMB1" -Value 1 -Type DWord | Out-Null
    }
    Write-Ok "SMBv1 enabled."
}

# =============================================================================
#  REMOTE DESKTOP (RDP)
# =============================================================================

function Disable-RemoteDesktop {
    Write-Info "Disabling Remote Desktop Protocol (RDP)..."
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
        -Name "fDenyTSConnections" -Value 1 -Type DWord | Out-Null
    Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue |
        Disable-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Ok "RDP disabled and firewall rules deactivated."
}

function Enable-RemoteDesktop {
    Write-Info "Enabling Remote Desktop Protocol (RDP) with NLA + High encryption..."
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
        -Name "fDenyTSConnections" -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
        -Name "UserAuthentication" -Value 1 -Type DWord | Out-Null    # require NLA
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
        -Name "MinEncryptionLevel" -Value 3 -Type DWord | Out-Null    # 3 = High (FIPS-compatible)
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
        -Name "SecurityLayer" -Value 2 -Type DWord | Out-Null         # 2 = TLS 1.x
    Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue |
        Enable-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Ok "RDP enabled with NLA required and High encryption enforced."
}

# =============================================================================
#  WINDOWS DEFENDER (MAXIMUM PROTECTION)
# =============================================================================

function Enable-WindowsDefender {
    Write-Info "Configuring Windows Defender for maximum protection..."
    if (-not (Get-WSECapabilities).DefenderAvailable) {
        Write-Warn "Windows Defender cmdlets are not available on this system. Skipping."
        return
    }
    try {
        Set-MpPreference -DisableRealtimeMonitoring     $false           -ErrorAction Stop
        Write-Ok "Real-time monitoring enabled."

        Set-MpPreference -MAPSReporting                Advanced          -ErrorAction SilentlyContinue
        Write-Ok "Cloud-based protection (MAPS) set to Advanced."

        Set-MpPreference -DisableBlockAtFirstSeen       $false           -ErrorAction SilentlyContinue
        Write-Ok "Block at First Sight enabled."

        Set-MpPreference -PUAProtection                Enabled           -ErrorAction SilentlyContinue
        Write-Ok "Potentially Unwanted Application (PUA) protection enabled."

        Set-MpPreference -EnableNetworkProtection      Enabled           -ErrorAction SilentlyContinue
        Write-Ok "Network protection enabled."

        Set-MpPreference -EnableControlledFolderAccess Enabled           -ErrorAction SilentlyContinue
        Write-Ok "Controlled Folder Access (anti-ransomware) enabled."

        Set-MpPreference -CheckForSignaturesBeforeRunningScan $true      -ErrorAction SilentlyContinue
        Write-Ok "Signature check before running scans enabled."

        Set-MpPreference -SubmitSamplesConsent         SendSafeSamples   -ErrorAction SilentlyContinue
        Write-Ok "Automatic sample submission (safe samples) enabled."

        Set-MpPreference -DisableArchiveScanning       $false            -ErrorAction SilentlyContinue
        Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableScriptScanning        $false            -ErrorAction SilentlyContinue
        Set-MpPreference -DisableRemovableDriveScanning $false           -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBehaviorMonitoring    $false            -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIOAVProtection        $false            -ErrorAction SilentlyContinue
        Write-Ok "All Defender protection engines enabled (archive, script, removable, behaviour, IOAV)."

        # Policy-level enforcement (survives UI changes)
        $pol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
        Set-WSERegistry -Path $pol -Name "DisableAntiSpyware"    -Value 0 -Type DWord | Out-Null
        Set-WSERegistry -Path "$pol\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 0 -Type DWord | Out-Null

        Write-Ok "Windows Defender fully hardened."
    } catch {
        Write-Fail "Could not configure Windows Defender: $_"
        Write-Warn "Defender may not be available or may be managed by Group Policy / third-party AV."
    }
}

function Show-DefenderTamperStatus {
    Write-Info "Reading Windows Defender Tamper Protection state (read-only — must be toggled in Windows Security UI)..."
    try {
        $st = Get-MpComputerStatus -ErrorAction Stop
        $tp = $st.IsTamperProtected
        if ($tp) { Write-Ok "Tamper Protection is ENABLED." }
        else     { Write-Warn "Tamper Protection is DISABLED — open Windows Security > Virus & threat protection > Manage settings to turn it on." }
    } catch {
        Write-Fail "Could not read Tamper Protection status: $_"
    }
}

function Set-DefenderSchedule {
    Write-Info "Scheduling daily Defender signature update + weekly quick scan..."
    if (-not (Get-WSECapabilities).DefenderAvailable) {
        Write-Warn "Defender cmdlets unavailable. Skipping."
        return
    }
    try {
        Set-MpPreference -SignatureUpdateInterval 4 -ErrorAction SilentlyContinue   # hours
        Set-MpPreference -SignatureScheduleDay Everyday -ErrorAction SilentlyContinue
        Set-MpPreference -ScanScheduleDay Everyday -ErrorAction SilentlyContinue
        Set-MpPreference -ScanScheduleQuickScanTime 120 -ErrorAction SilentlyContinue  # 02:00
        Set-MpPreference -RemediationScheduleDay Everyday -ErrorAction SilentlyContinue
        Write-Ok "Signature update every 4 h; quick scan every day at 02:00."
    } catch {
        Write-Fail "Could not schedule Defender tasks: $_"
    }
}

# =============================================================================
#  AUTORUN / AUTOPLAY
# =============================================================================

function Disable-AutoRun {
    Write-Info "Disabling AutoRun and AutoPlay (prevents removable-media attacks)..."
    $explorerPol = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Set-WSERegistry -Path $explorerPol -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord | Out-Null
    Set-WSERegistry -Path $explorerPol -Name "NoDriveAutoRun"     -Value 67108863 -Type DWord | Out-Null
    Set-WSERegistry -Path $explorerPol -Name "NoAutorun"          -Value 1 -Type DWord | Out-Null

    $autorunInf = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf"
    Set-WSERegistry -Path $autorunInf -Name "(Default)" -Value "@SYS:DoesNotExist" -Type String | Out-Null

    $apHandlers = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"
    Set-WSERegistry -Path $apHandlers -Name "DisableAutoplay" -Value 1 -Type DWord | Out-Null

    Write-Ok "AutoRun and AutoPlay disabled on all drive types."
}

function Enable-AutoRun {
    Write-Info "Restoring AutoRun / AutoPlay to Windows defaults..."
    $explorerPol = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Set-WSERegistry -Path $explorerPol -Name "NoDriveTypeAutoRun" -Value 0x91 -Type DWord | Out-Null

    $apHandlers = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"
    Set-WSERegistry -Path $apHandlers -Name "DisableAutoplay" -Value 0 -Type DWord | Out-Null

    Write-Ok "AutoRun and AutoPlay restored."
}

# =============================================================================
#  GUEST ACCOUNT
# =============================================================================

function Disable-GuestAccount {
    Write-Info "Disabling the built-in Guest account..."
    try {
        $guest = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -match '-501$' } | Select-Object -First 1
        if ($guest) {
            Disable-LocalUser -Name $guest.Name -ErrorAction SilentlyContinue
            Write-Ok "Guest account ($($guest.Name)) disabled."
        } else { Write-Warn "Guest account not found." }
    } catch {
        & net user Guest /active:no 2>&1 | Out-Null
        Write-Ok "Guest account disabled (legacy fallback)."
    }
}

function Enable-GuestAccount {
    Write-Warn "WARNING: Enabling the Guest account reduces system security."
    & net user Guest /active:yes 2>&1 | Out-Null
    Write-Ok "Guest account enabled."
}

# =============================================================================
#  SECURITY AUDIT POLICY
# =============================================================================

function Enable-AuditPolicy {
    Write-Info "Enabling comprehensive security audit policies..."
    $categories = @(
        "Account Logon", "Account Management", "Detailed Tracking",
        "DS Access", "Logon/Logoff", "Object Access",
        "Policy Change", "Privilege Use", "System"
    )
    foreach ($cat in $categories) {
        & auditpol /set /category:"$cat" /success:enable /failure:enable 2>&1 | Out-Null
    }
    Write-Ok "Security audit policies enabled (success + failure for all categories)."

    # PowerShell script-block & module logging
    $sbLog = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    Set-WSERegistry -Path $sbLog -Name "EnableScriptBlockLogging"          -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $sbLog -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord | Out-Null
    Write-Ok "PowerShell Script-Block Logging enabled."

    $modLog = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    Set-WSERegistry -Path $modLog -Name "EnableModuleLogging" -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path "$modLog\ModuleNames" -Name "*" -Value "*" -Type String | Out-Null
    Write-Ok "PowerShell Module Logging enabled (* = all modules)."

    # PowerShell transcription
    $trans = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    Set-WSERegistry -Path $trans -Name "EnableTranscripting"    -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $trans -Name "EnableInvocationHeader" -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $trans -Name "OutputDirectory"        -Value (Join-Path $Script:WSERoot 'ps-transcripts') -Type String | Out-Null
    Write-Ok "PowerShell transcription enabled (logs to $($Script:WSERoot)\ps-transcripts)."

    & wevtutil sl Security /ms:1073741824 2>&1 | Out-Null
    Write-Ok "Security event log maximum size set to 1 GB."

    # Audit process command lines (CIS recommendation)
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
        -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord | Out-Null
    Write-Ok "Process-creation command-line auditing enabled (Event ID 4688)."
}

# =============================================================================
#  UNNECESSARY / RISKY SERVICES   (fixed — RDP services are governed by their own option)
# =============================================================================

function Disable-UnnecessaryServices {
    Write-Info "Disabling unnecessary and potentially risky services..."
    $services = @(
        @{Name='RemoteRegistry';      Display='Remote Registry'},
        @{Name='TlntSvr';             Display='Telnet'},
        @{Name='SSDPSRV';             Display='SSDP Discovery (UPnP)'},
        @{Name='upnphost';            Display='UPnP Device Host'},
        @{Name='SharedAccess';        Display='Internet Connection Sharing'},
        @{Name='lltdsvc';             Display='Link-Layer Topology Discovery'},
        @{Name='MSiSCSI';             Display='Microsoft iSCSI Initiator'},
        @{Name='WMSvc';               Display='Web Management Service (IIS)'},
        @{Name='WebClient';           Display='WebClient (WebDAV)'},
        @{Name='Browser';             Display='Computer Browser'},
        @{Name='Fax';                 Display='Fax'},
        @{Name='WerSvc';              Display='Windows Error Reporting'},
        @{Name='XblAuthManager';      Display='Xbox Live Auth Manager'},
        @{Name='XblGameSave';         Display='Xbox Live Game Save'},
        @{Name='XboxNetApiSvc';       Display='Xbox Live Networking'},
        @{Name='RetailDemo';          Display='Retail Demo Service'},
        @{Name='MapsBroker';          Display='Downloaded Maps Manager'}
    )
    foreach ($svc in $services) {
        $s = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($s) {
            try {
                Stop-Service  -Name $svc.Name -Force -ErrorAction SilentlyContinue
                Set-Service   -Name $svc.Name -StartupType Disabled -ErrorAction Stop
                Write-Ok "Disabled service: $($svc.Display)"
            } catch {
                Write-Warn "Could not disable '$($svc.Display)': $_"
            }
        }
    }
}

function Enable-UnnecessaryServices {
    Write-Info "Restoring previously disabled services to Manual startup..."
    $services = @('RemoteRegistry','SSDPSRV','upnphost','SharedAccess','lltdsvc',
                  'WebClient','Browser','Fax','WerSvc','MapsBroker')
    foreach ($name in $services) {
        $s = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($s) {
            try {
                Set-Service -Name $name -StartupType Manual -ErrorAction Stop
                Write-Ok "Restored '$name' to Manual startup."
            } catch {
                Write-Warn "Could not restore '$name': $_"
            }
        }
    }
}

# =============================================================================
#  WINDOWS SCRIPT HOST
# =============================================================================

function Disable-WindowsScriptHost {
    Write-Info "Disabling Windows Script Host (blocks .vbs / .js malware execution)..."
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -Type DWord | Out-Null
    Write-Ok "Windows Script Host disabled."
}

function Enable-WindowsScriptHost {
    Write-Info "Enabling Windows Script Host..."
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 1 -Type DWord | Out-Null
    Write-Ok "Windows Script Host enabled."
}

# =============================================================================
#  ANONYMOUS ACCESS, LLMNR & NBT-NS
# =============================================================================

function Disable-AnonymousAccess {
    Write-Info "Restricting anonymous network access..."
    $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-WSERegistry -Path $lsa -Name "RestrictAnonymous"         -Value 2 -Type DWord | Out-Null
    Set-WSERegistry -Path $lsa -Name "RestrictAnonymousSAM"      -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $lsa -Name "EveryoneIncludesAnonymous" -Value 0 -Type DWord | Out-Null
    Write-Ok "Anonymous access to shares and SAM restricted."

    Write-Info "Disabling LLMNR (prevents LLMNR-poisoning / relay attacks)..."
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord | Out-Null
    Write-Ok "LLMNR disabled."

    Write-Info "Disabling NetBIOS over TCP/IP on all adapters (prevents NBT-NS MITM)..."
    $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" -ErrorAction SilentlyContinue
    foreach ($a in $adapters) {
        Invoke-CimMethod -InputObject $a -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions = [uint32]2} -ErrorAction SilentlyContinue | Out-Null
    }
    # Default for all future adapters
    $netbt = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
    Get-ChildItem $netbt -ErrorAction SilentlyContinue | ForEach-Object {
        Set-WSERegistry -Path $_.PsPath -Name "NetbiosOptions" -Value 2 -Type DWord | Out-Null
    }
    Write-Ok "NetBIOS over TCP/IP disabled on all active adapters."

    # mDNS over UDP/5353 — modern equivalent to LLMNR poisoning surface
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableMDNS" -Value 0 -Type DWord | Out-Null
    Write-Ok "mDNS (UDP/5353) disabled."
}

# =============================================================================
#  LSA / CREDENTIAL PROTECTION
# =============================================================================

function Enable-CredentialGuard {
    Write-Info "Hardening LSA / credential storage..."
    $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-WSERegistry -Path $lsa -Name "RunAsPPL"               -Value 1 -Type DWord | Out-Null   # LSA Protection
    Set-WSERegistry -Path $lsa -Name "DisableRestrictedAdmin" -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $lsa -Name "DisableRestrictedAdminOutboundCreds" -Value 1 -Type DWord | Out-Null

    # Prevent WDigest from caching plain-text credentials in memory
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
        -Name "UseLogonCredential" -Value 0 -Type DWord | Out-Null
    Write-Ok "WDigest plain-text credential caching disabled."

    # Credential Guard via VBS
    $devGuard = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
    Set-WSERegistry -Path $devGuard -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $devGuard -Name "RequirePlatformSecurityFeatures"   -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path "$devGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path "$devGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Locked"  -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path "$devGuard\Scenarios\LsaCfg" -Name "ConfigureLsaCfgFlags" -Value 1 -Type DWord | Out-Null
    Write-Ok "Credential Guard / VBS / HVCI registry policies set."

    Write-Ok "LSA Protection enabled — credentials protected from dumping tools."
    Write-Warn "A restart is required for LSA Protection (RunAsPPL) and HVCI to take effect."
}

# =============================================================================
#  PRIVACY & TELEMETRY
# =============================================================================

function Disable-Telemetry {
    Write-Info "Disabling Windows Telemetry and data collection services..."

    foreach ($svc in @('DiagTrack','dmwappushservice','diagnosticshub.standardcollector.service','PcaSvc')) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Set-Service  -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Ok "Service '$svc' stopped and disabled."
        }
    }

    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry"        -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowDeviceNameInTelemetry" -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord | Out-Null
    Write-Ok "Telemetry level set to 0 (Security)."

    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type DWord | Out-Null
    Write-Ok "Customer Experience Improvement Program (CEIP) disabled."

    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable"             -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory"      -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR"            -Value 1 -Type DWord | Out-Null
    Write-Ok "Application Impact Telemetry / Inventory / UAR disabled."

    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord | Out-Null
    Write-Ok "Windows Error Reporting disabled."

    # Disable Activity History / Timeline / Clipboard sync
    $sys = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    Set-WSERegistry -Path $sys -Name "PublishUserActivities"        -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $sys -Name "UploadUserActivities"         -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $sys -Name "EnableActivityFeed"           -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $sys -Name "AllowClipboardHistory"        -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $sys -Name "AllowCrossDeviceClipboard"    -Value 0 -Type DWord | Out-Null
    Write-Ok "Activity History, Timeline and Clipboard sync disabled."
}

function Enable-Telemetry {
    Write-Info "Restoring Windows Telemetry to default settings..."
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 3 -Type DWord | Out-Null
    foreach ($svc in @('DiagTrack', 'dmwappushservice')) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) { Set-Service -Name $svc -StartupType Automatic -ErrorAction SilentlyContinue }
    }
    Write-Ok "Telemetry restored to default."
}

function Disable-AdvertisingID {
    Write-Info "Disabling Advertising ID and content tracking..."

    Set-WSERegistry -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"      -Name "DisabledByGroupPolicy" -Value 1 -Type DWord | Out-Null

    $cdm = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    if (Test-Path $cdm) {
        $prefs = @(
            'SubscribedContent-338389Enabled',
            'SubscribedContent-338388Enabled',
            'SubscribedContent-310093Enabled',
            'SubscribedContent-353698Enabled',
            'SilentInstalledAppsEnabled',
            'SystemPaneSuggestionsEnabled',
            'SoftLandingEnabled',
            'OemPreInstalledAppsEnabled',
            'PreInstalledAppsEnabled',
            'PreInstalledAppsEverEnabled'
        )
        foreach ($pref in $prefs) {
            Set-WSERegistry -Path $cdm -Name $pref -Value 0 -Type DWord | Out-Null
        }
    }
    Write-Ok "Advertising ID, suggested content and silent app installs disabled."
}

function Disable-Cortana {
    Write-Info "Disabling Cortana and web search integration..."
    $search = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    Set-WSERegistry -Path $search -Name "AllowCortana"              -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $search -Name "AllowSearchToUseLocation"  -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $search -Name "DisableWebSearch"          -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $search -Name "ConnectedSearchUseWeb"     -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $search -Name "AllowCloudSearch"          -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $search -Name "AllowCortanaAboveLock"     -Value 0 -Type DWord | Out-Null
    Write-Ok "Cortana and web search disabled via Group Policy."
}

# =============================================================================
#  ADVANCED SYSTEM HARDENING
# =============================================================================

function Disable-PrintSpooler {
    Write-Info "Disabling Print Spooler (mitigates PrintNightmare CVE-2021-34527)..."
    Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
    Set-Service  -Name Spooler -StartupType Disabled -ErrorAction SilentlyContinue
    # Also disable remote / network-side spooler attack surface
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "RegisterSpoolerRemoteRpcEndPoint" -Value 2 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnInstall" -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "UpdatePromptSettings" -Value 0 -Type DWord | Out-Null
    Write-Ok "Print Spooler stopped + disabled, remote RPC endpoint locked, driver installation restricted to admins."
    Write-Warn "Re-enable the Spooler (option 34) before printing."
}

function Enable-PrintSpooler {
    Write-Info "Enabling Print Spooler service..."
    Set-Service  -Name Spooler -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name Spooler -ErrorAction SilentlyContinue
    Write-Ok "Print Spooler enabled."
}

function Set-NTLMv2Only {
    Write-Info "Enforcing NTLMv2 authentication (disabling NTLMv1 and LM)..."
    $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-WSERegistry -Path $lsa -Name "LmCompatibilityLevel" -Value 5 -Type DWord | Out-Null
    Write-Ok "LmCompatibilityLevel set to 5 (NTLMv2 only; refuse LM and NTLM)."

    Set-WSERegistry -Path $lsa -Name "NoLMHash" -Value 1 -Type DWord | Out-Null
    Write-Ok "LM hash storage disabled."

    $msv = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    Set-WSERegistry -Path $msv -Name "NTLMMinClientSec" -Value 537395200 -Type DWord | Out-Null
    Set-WSERegistry -Path $msv -Name "NTLMMinServerSec" -Value 537395200 -Type DWord | Out-Null
    Set-WSERegistry -Path $msv -Name "auditreceivingntlmtraffic" -Value 2 -Type DWord | Out-Null
    Set-WSERegistry -Path $msv -Name "RestrictReceivingNTLMTraffic" -Value 0 -Type DWord | Out-Null  # audit only — 2 = deny (breaks domains)
    Write-Ok "NTLM minimum 128-bit session security enforced + NTLM auditing enabled."
}

function Disable-PowerShellv2 {
    Write-Info "Disabling PowerShell v2 (prevents script-block-logging bypass)..."
    $feat = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction SilentlyContinue
    if ($feat -and $feat.State -eq 'Enabled') {
        Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Write-Ok "PowerShell v2 disabled."
        Write-Warn "A restart may be required for the change to take full effect."
    } elseif ($feat -and $feat.State -eq 'Disabled') {
        Write-Warn "PowerShell v2 is already disabled on this system."
    } else {
        Write-Warn "PowerShell v2 optional feature not found (may not be installed)."
    }
}

function Enable-ExploitProtection {
    Write-Info "Enabling system-wide Exploit Protection (DEP, SEHOP, ASLR, heap guard)..."

    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
        -Name "DisableExceptionChainValidation" -Value 0 -Type DWord | Out-Null
    Write-Ok "SEHOP enabled."

    & bcdedit /set nx AlwaysOn 2>&1 | Out-Null
    Write-Ok "DEP (NX) set to AlwaysOn."

    if ((Get-WSECapabilities).ProcessMitigationAvailable) {
        try { Set-ProcessMitigation -System -Enable HeapTerminateOnCorruption -ErrorAction Stop; Write-Ok "Heap Terminate on Corruption enabled." } catch { Write-Warn "Heap terminate mitigation skipped." }
        try { Set-ProcessMitigation -System -Enable ForceRelocateImages -ErrorAction Stop; Write-Ok "Force ASLR enabled." } catch { Write-Warn "Force ASLR not available." }
        try { Set-ProcessMitigation -System -Enable BottomUp -ErrorAction Stop; Write-Ok "Bottom-up ASLR enabled." } catch {}
        try { Set-ProcessMitigation -System -Enable HighEntropy -ErrorAction Stop; Write-Ok "High-entropy ASLR enabled." } catch {}
        try { Set-ProcessMitigation -System -Enable CFG -ErrorAction Stop; Write-Ok "Control Flow Guard enabled." } catch {}
        try { Set-ProcessMitigation -System -Enable DEP -ErrorAction Stop; Write-Ok "Per-process DEP enabled." } catch {}
        try { Set-ProcessMitigation -System -Enable SEHOP -ErrorAction Stop } catch {}
    } else {
        Write-Warn "Set-ProcessMitigation cmdlet unavailable — using registry only."
    }

    Write-Ok "Exploit Protection configured. A restart is recommended."
}

function Enable-ClearPageFileOnShutdown {
    Write-Info "Enabling clear page file at shutdown (prevents offline data recovery)..."
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
        -Name "ClearPageFileAtShutdown" -Value 1 -Type DWord | Out-Null
    Write-Ok "Page file will be cleared on every shutdown."
    Write-Warn "Shutdown will take longer because the page file must be zeroed."
}

function Disable-ClearPageFileOnShutdown {
    Write-Info "Disabling clear page file at shutdown..."
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
        -Name "ClearPageFileAtShutdown" -Value 0 -Type DWord | Out-Null
    Write-Ok "Page file clear on shutdown disabled."
}

function Disable-RemoteAssistance {
    Write-Info "Disabling Remote Assistance..."
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp"   -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowFullControl" -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited" -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp"   -Value 0 -Type DWord | Out-Null

    Get-NetFirewallRule -DisplayGroup "Remote Assistance" -ErrorAction SilentlyContinue |
        Disable-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Ok "Remote Assistance disabled and firewall rules deactivated."
}

function Enable-RemoteAssistance {
    Write-Info "Enabling Remote Assistance..."
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 1 -Type DWord | Out-Null
    Write-Ok "Remote Assistance enabled."
}

# =============================================================================
#  NETWORK & DNS HARDENING
# =============================================================================

function Set-SecureDNS {
    Write-Info "Configuring secure DNS servers on all active adapters..."
    $dnsServers = @("1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112")  # Cloudflare + Quad9
    $adapters   = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
    if ($adapters.Count -eq 0) { Write-Warn "No active network adapters found."; return }
    foreach ($a in $adapters) {
        try {
            Set-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex -ServerAddresses $dnsServers -ErrorAction Stop
            Write-Ok "DNS set on '$($a.Name)': $($dnsServers -join ', ')."
        } catch {
            Write-Fail "Could not set DNS on '$($a.Name)': $_"
        }
    }
    Write-Ok "Secure DNS applied."
}

function Enable-DNSOverHTTPS {
    Write-Info "Configuring DNS-over-HTTPS (DoH)..."
    if (-not (Get-WSECapabilities).DohSupported) {
        Write-Warn "Set-DnsClientDohServerAddress not available — requires Windows 11 22H2 / Server 2022+."
        Write-Warn "Falling back to registry-based DoH template (will apply on next adapter reset)."
    } else {
        $servers = @(
            @{Addr='1.1.1.1';        Template='https://cloudflare-dns.com/dns-query'},
            @{Addr='1.0.0.1';        Template='https://cloudflare-dns.com/dns-query'},
            @{Addr='9.9.9.9';        Template='https://dns.quad9.net/dns-query'},
            @{Addr='149.112.112.112';Template='https://dns.quad9.net/dns-query'}
        )
        foreach ($s in $servers) {
            try {
                Add-DnsClientDohServerAddress -ServerAddress $s.Addr -DohTemplate $s.Template -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction SilentlyContinue
            } catch {}
        }
        # Force DoH for all adapters
        Get-DnsClient -ErrorAction SilentlyContinue | ForEach-Object {
            try { Set-DnsClient -InterfaceIndex $_.InterfaceIndex -UseSuffixWhenRegistering $false -ErrorAction SilentlyContinue } catch {}
        }
        Write-Ok "DoH templates added for Cloudflare and Quad9."
    }
    # Group-Policy switch to enable DoH globally
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "DoHPolicy" -Value 2 -Type DWord | Out-Null
    Write-Ok "DoH policy set to 'Required' (2). DNS queries that cannot use HTTPS will be dropped."
}

function Disable-IPv6 {
    Write-Info "Disabling IPv6 on all network adapters..."
    $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue)
    foreach ($a in $adapters) {
        Disable-NetAdapterBinding -Name $a.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
    }
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0xFF -Type DWord | Out-Null
    Write-Ok "IPv6 disabled on all adapters."
    Write-Warn "If your network uses IPv6 (or Wi-Fi captive portals), some connectivity may be affected."
}

function Enable-IPv6 {
    Write-Info "Re-enabling IPv6 on all network adapters..."
    $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue)
    foreach ($a in $adapters) {
        Enable-NetAdapterBinding -Name $a.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
    }
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0 -Type DWord | Out-Null
    Write-Ok "IPv6 re-enabled on all adapters."
}

function Disable-IPv6TransitionTech {
    Write-Info "Disabling IPv6 transition technologies (Teredo, ISATAP, 6to4)..."
    & netsh interface teredo set state disabled 2>&1 | Out-Null
    & netsh interface 6to4   set state disabled 2>&1 | Out-Null
    & netsh interface isatap set state disabled 2>&1 | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name "Teredo_State" -Value "Disabled" -Type String | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name "6to4_State"   -Value "Disabled" -Type String | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name "ISATAP_State" -Value "Disabled" -Type String | Out-Null
    Write-Ok "Teredo, 6to4 and ISATAP all disabled."
}

# =============================================================================
#  ADDITIONAL HARDENING
# =============================================================================

function Enable-AutomaticUpdates {
    Write-Info "Configuring Windows Update for automatic installation..."
    $wu = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    Set-WSERegistry -Path $wu -Name "NoAutoUpdate"            -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $wu -Name "AUOptions"               -Value 4 -Type DWord | Out-Null
    Set-WSERegistry -Path $wu -Name "AutoInstallMinorUpdates" -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $wu -Name "ScheduledInstallDay"     -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $wu -Name "ScheduledInstallTime"    -Value 3 -Type DWord | Out-Null

    # Make sure the service is running
    $wuSvc = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    if ($wuSvc) {
        Set-Service -Name wuauserv -StartupType Automatic -ErrorAction SilentlyContinue
        if ($wuSvc.Status -ne 'Running') { Start-Service -Name wuauserv -ErrorAction SilentlyContinue }
    }
    Write-Ok "Automatic Windows Updates enabled (daily download + install at 03:00)."
}

function Set-ScreenLockTimeout {
    Write-Info "Setting screen auto-lock to 5 minutes and requiring password on wake..."

    $desktop = "HKCU:\Control Panel\Desktop"
    Set-WSERegistry -Path $desktop -Name "ScreenSaveActive"    -Value "1"   -Type String | Out-Null
    Set-WSERegistry -Path $desktop -Name "ScreenSaveTimeOut"   -Value "300" -Type String | Out-Null
    Set-WSERegistry -Path $desktop -Name "ScreenSaverIsSecure" -Value "1"   -Type String | Out-Null

    $gpDesktop = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
    Set-WSERegistry -Path $gpDesktop -Name "ScreenSaveTimeOut"   -Value "300" -Type String | Out-Null
    Set-WSERegistry -Path $gpDesktop -Name "ScreenSaveActive"    -Value "1"   -Type String | Out-Null
    Set-WSERegistry -Path $gpDesktop -Name "ScreenSaverIsSecure" -Value "1"   -Type String | Out-Null

    # Machine-wide inactivity lock (CIS 2.3.7.3)
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "InactivityTimeoutSecs" -Value 300 -Type DWord | Out-Null

    & powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 1 2>&1 | Out-Null
    & powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 1 2>&1 | Out-Null
    & powercfg /setactive SCHEME_CURRENT 2>&1 | Out-Null
    Write-Ok "Screen will auto-lock after 5 minutes; password required on wake."
}

function Rename-AdminAccount {
    Write-Info "Rename the built-in Administrator account (RID 500)..."
    $admin = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -match '-500$' } | Select-Object -First 1
    if ($null -eq $admin) {
        Write-Fail "Could not locate the built-in Administrator account."
        return
    }
    Write-Host "  Current name: $($admin.Name)" -ForegroundColor Cyan
    $newName = Read-Host "  Enter new account name"
    $newName = $newName.Trim()
    if ([string]::IsNullOrWhiteSpace($newName)) { Write-Warn "No name entered — cancelled."; return }
    if ($newName -match '\s' -or $newName.Length -gt 20) {
        Write-Fail "Account name must be <= 20 chars and contain no spaces."
        return
    }
    if (Get-LocalUser -Name $newName -ErrorAction SilentlyContinue) {
        Write-Fail "An account named '$newName' already exists."
        return
    }
    try {
        Rename-LocalUser -Name $admin.Name -NewName $newName -ErrorAction Stop
        Write-Ok "Administrator account renamed: '$($admin.Name)' -> '$newName'."
    } catch {
        Write-Fail "Rename failed: $_"
    }
}

# =============================================================================
#  ATTACK SURFACE REDUCTION (ASR)
# =============================================================================

function Enable-ASRRules {
    Write-Info "Enabling Windows Defender Attack Surface Reduction (ASR) rules..."
    if (-not (Get-WSECapabilities).DefenderAvailable) {
        Write-Warn "Defender cmdlets unavailable. Skipping ASR."
        return
    }
    $rules = @(
        @{Id='BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'; Name='Block executable content from email/webmail'},
        @{Id='D4F940AB-401B-4EFC-AADC-AD5F3C50688A'; Name='Block Office apps from creating child processes'},
        @{Id='3B576869-A4EC-4529-8536-B80A7769E899'; Name='Block Office from creating executable content'},
        @{Id='75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'; Name='Block Office apps from injecting into other processes'},
        @{Id='D3E037E1-3EB8-44C8-A917-57927947596D'; Name='Block JS/VBScript from launching downloaded executables'},
        @{Id='5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'; Name='Block execution of potentially obfuscated scripts'},
        @{Id='92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'; Name='Block Win32 API calls from Office macros'},
        @{Id='C1DB55AB-C21A-4637-BB3F-A12568109D35'; Name='Advanced ransomware protection'},
        @{Id='9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2'; Name='Block credential stealing from LSASS'},
        @{Id='D1E49AAC-8F56-4280-B9BA-993A6D77406C'; Name='Block process creation from PSExec and WMI commands'},
        @{Id='B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4'; Name='Block untrusted/unsigned processes from USB'},
        @{Id='26190899-1602-49E8-8B27-EB1D0A1CE869'; Name='Block Office communication apps from creating child processes'},
        @{Id='7674BA52-37EB-4A4F-A9A1-F0F9DE45BB2F'; Name='Block Adobe Reader from creating child processes'},
        @{Id='E6DB77E5-3DF2-4CF1-B95A-636979351E5B'; Name='Block WMI event-subscription persistence'},
        @{Id='56A863A9-875E-4185-98A7-B882C64B5CE5'; Name='Block abuse of exploited vulnerable signed drivers'},
        @{Id='A8F5898E-1DC8-49A9-9878-85004B8A61E6'; Name='Block Webshell creation for Servers'}
    )
    $failed = 0
    foreach ($rule in $rules) {
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Id `
                             -AttackSurfaceReductionRules_Actions 1 -ErrorAction Stop
            Write-Ok "Enabled: $($rule.Name)"
        } catch {
            Write-Warn "Could not enable: $($rule.Name)"
            $failed++
        }
    }
    if ($failed -gt 0) {
        Write-Warn "$failed rule(s) failed. Ensure Defender real-time protection is active (option 20)."
    } else {
        Write-Ok "All $($rules.Count) ASR rules enabled in Block mode."
    }
}

function Disable-ASRRules {
    Write-Info "Disabling all Windows Defender ASR rules..."
    try {
        $current = @((Get-MpPreference -ErrorAction Stop).AttackSurfaceReductionRules_Ids)
        if ($current.Count -gt 0) {
            foreach ($id in $current) {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $id `
                    -AttackSurfaceReductionRules_Actions 0 -ErrorAction SilentlyContinue
            }
            Write-Ok "All $($current.Count) ASR rules set to Disabled."
        } else {
            Write-Warn "No ASR rules are currently configured."
        }
    } catch {
        Write-Fail "Could not read or modify ASR rules: $_"
    }
}

# =============================================================================
#  POWERSHELL HARDENING
# =============================================================================

function Set-PSExecutionRemoteSigned {
    Write-Info "Setting PowerShell execution policy to RemoteSigned (LocalMachine scope)..."
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction SilentlyContinue
    Write-Ok "Execution policy set to RemoteSigned."
}

function Set-PSExecutionAllSigned {
    Write-Warn "AllSigned blocks unsigned local scripts — this script will not be runnable again unless signed."
    $c = Read-Host "  Type ALLSIGNED to confirm (any other input cancels)"
    if ($c -ne 'ALLSIGNED') { Write-Warn "Cancelled."; return }
    Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine -Force -ErrorAction SilentlyContinue
    Write-Ok "Execution policy set to AllSigned."
}

function Restore-PSExecutionDefault {
    Write-Info "Restoring PowerShell execution policy to Undefined (LocalMachine scope)..."
    Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope LocalMachine -Force -ErrorAction SilentlyContinue
    Write-Ok "Execution policy restored to Undefined."
}

# =============================================================================
#  WIRELESS SECURITY
# =============================================================================

function Disable-Bluetooth {
    Write-Info "Disabling Bluetooth service and devices..."
    $btSvc = Get-Service -Name bthserv -ErrorAction SilentlyContinue
    if ($btSvc) {
        Stop-Service  -Name bthserv -Force          -ErrorAction SilentlyContinue
        Set-Service   -Name bthserv -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Ok "Bluetooth Support Service stopped and disabled."
    }

    $btDevices = @(Get-PnpDevice -ErrorAction SilentlyContinue |
                   Where-Object { $_.Class -eq 'Bluetooth' -and $_.Status -eq 'OK' })
    foreach ($dev in $btDevices) {
        try {
            Disable-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false -ErrorAction Stop
            Write-Ok "Disabled: $($dev.FriendlyName)"
        } catch {
            Write-Warn "Could not disable '$($dev.FriendlyName)': $_"
        }
    }
    if (-not $btSvc -and $btDevices.Count -eq 0) {
        Write-Warn "No Bluetooth service or devices found on this system."
    }
}

function Enable-Bluetooth {
    Write-Info "Enabling Bluetooth service and devices..."
    $btSvc = Get-Service -Name bthserv -ErrorAction SilentlyContinue
    if ($btSvc) {
        Set-Service  -Name bthserv -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name bthserv -ErrorAction SilentlyContinue
        Write-Ok "Bluetooth Support Service enabled."
    }
    $btDevices = @(Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.Class -eq 'Bluetooth' })
    foreach ($dev in $btDevices) {
        try {
            Enable-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false -ErrorAction Stop
            Write-Ok "Enabled: $($dev.FriendlyName)"
        } catch {
            Write-Warn "Could not enable '$($dev.FriendlyName)': $_"
        }
    }
}

# =============================================================================
#  OFFICE & APPLICATION SECURITY
# =============================================================================

function Disable-OfficeMacros {
    Write-Info "Disabling Microsoft Office macros for all installed Office versions..."
    $versions = @('12.0', '14.0', '15.0', '16.0')
    $apps     = @('Word', 'Excel', 'PowerPoint', 'Access', 'Outlook', 'Publisher', 'Visio')
    $count    = 0
    foreach ($ver in $versions) {
        foreach ($app in $apps) {
            foreach ($hive in @('HKCU:', 'HKLM:')) {
                $path = "${hive}\SOFTWARE\Policies\Microsoft\Office\$ver\$app\Security"
                try {
                    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
                    Set-WSERegistry -Path $path -Name "VBAWarnings" -Value 4 -Type DWord | Out-Null
                    # Block macros from internet (MOTW) — Office 2016+
                    Set-WSERegistry -Path $path -Name "BlockContentExecutionFromInternet" -Value 1 -Type DWord | Out-Null
                    Set-WSERegistry -Path $path -Name "DisableInternetFilesInPV" -Value 0 -Type DWord | Out-Null
                    Set-WSERegistry -Path $path -Name "DisableAttachementsInPV"  -Value 0 -Type DWord | Out-Null
                    $count++
                } catch {}
            }
        }
    }
    Write-Ok "Office macro policy applied (VBAWarnings=4, macros from internet blocked) — $count keys written."
}

function Enable-OfficeMacros {
    Write-Info "Removing Microsoft Office macro policy..."
    $versions = @('12.0', '14.0', '15.0', '16.0')
    $apps     = @('Word', 'Excel', 'PowerPoint', 'Access', 'Outlook', 'Publisher', 'Visio')
    foreach ($ver in $versions) {
        foreach ($app in $apps) {
            foreach ($hive in @('HKCU:', 'HKLM:')) {
                $path = "${hive}\SOFTWARE\Policies\Microsoft\Office\$ver\$app\Security"
                Remove-ItemProperty -Path $path -Name "VBAWarnings"                       -Force -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $path -Name "BlockContentExecutionFromInternet" -Force -ErrorAction SilentlyContinue
            }
        }
    }
    Write-Ok "Office macro policy removed — applications will use their built-in defaults."
}

# =============================================================================
#  FIREWALL ENHANCEMENTS   (fixed — no more $profile auto-var shadow)
# =============================================================================

function Enable-FirewallLogging {
    Write-Info "Enabling Windows Firewall logging on all profiles (allowed + blocked)..."
    $logFile = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
    foreach ($prof in @('Domain', 'Private', 'Public')) {
        Set-NetFirewallProfile -Profile $prof `
            -LogAllowed True `
            -LogBlocked True `
            -LogFileName $logFile `
            -LogMaxSizeKilobytes 32767 `
            -ErrorAction SilentlyContinue
    }
    Write-Ok "Firewall logging enabled for Domain, Private and Public profiles."
    Write-Ok "Log file: $logFile (32 MB)."
}

function Set-FirewallBlockOutbound {
    Write-Warn "WARNING: Blocking all outbound traffic will break most network applications."
    Write-Warn "Only use this on air-gapped or highly controlled systems."
    $c = Read-Host "  Type BLOCK-OUTBOUND to confirm (any other input cancels)"
    if ($c -ne 'BLOCK-OUTBOUND') { Write-Warn "Cancelled."; return }
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block
    Write-Ok "Default outbound action set to Block."
    Write-Warn "Add explicit allow rules for required applications to restore connectivity."
}

function Restore-FirewallDefaultOutbound {
    Write-Info "Restoring default outbound action to Allow on all profiles..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow
    Write-Ok "Default outbound action restored to Allow."
}

# =============================================================================
#  DRIVE ENCRYPTION (BITLOCKER)
# =============================================================================

function Show-BitLockerStatus {
    Write-Info "Checking BitLocker encryption status on all drives..."
    if (-not (Get-WSECapabilities).BitLockerAvailable) {
        Write-Warn "BitLocker cmdlets unavailable (requires Windows Pro/Enterprise/Education)."
        return
    }
    try {
        $volumes = Get-BitLockerVolume -ErrorAction Stop
        Write-Host ""
        foreach ($vol in $volumes) {
            $color = if ($vol.ProtectionStatus -eq 'On') { "Green" } else { "Red" }
            Write-Host ("  Drive {0,-4}: Protection={1,-3}  Encryption={2,3}%  Method={3}" -f `
                $vol.MountPoint, $vol.ProtectionStatus, $vol.EncryptionPercentage, $vol.EncryptionMethod) `
                -ForegroundColor $color
        }
        Write-Host ""
    } catch {
        Write-Fail "BitLocker query failed: $_"
    }
}

function Enable-BitLockerSystem {
    Write-Info "Enabling BitLocker on system drive (C:) with XTS-AES 256 encryption..."
    if (-not (Get-WSECapabilities).BitLockerAvailable) {
        Write-Warn "BitLocker not available on this edition."; return
    }
    try {
        $vol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
        if ($vol.ProtectionStatus -eq 'On') {
            Write-Warn "BitLocker is already enabled on C:."
            return
        }

        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        if ($tpm -and $tpm.TpmPresent -and $tpm.TpmReady) {
            Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -TpmProtector -ErrorAction Stop | Out-Null
            Write-Ok "BitLocker enabled on C: using TPM protector (XTS-AES 256)."
        } else {
            Write-Warn "TPM not available or not ready — a startup PIN is required."
            $pin = Read-Host "  Enter a 6+ digit startup PIN (blank to cancel)" -AsSecureString
            $pinPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pin))
            if ([string]::IsNullOrEmpty($pinPlain) -or $pinPlain.Length -lt 6) {
                Write-Warn "No valid PIN entered — cancelled."; return
            }
            Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 `
                -TpmAndPinProtector -Pin $pin -ErrorAction Stop | Out-Null
            Write-Ok "BitLocker enabled on C: using TPM+PIN protector (XTS-AES 256)."
        }

        # Add a recovery-password protector so we have an offline key
        Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector -ErrorAction SilentlyContinue | Out-Null

        $rk = (Get-BitLockerVolume -MountPoint "C:").KeyProtector |
              Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -First 1
        if ($rk) {
            $keyPath = "$env:USERPROFILE\Desktop\BitLocker_RecoveryKey_C.txt"
            "BitLocker Recovery Key for C:  $($rk.RecoveryPassword)" |
                Set-Content -Path $keyPath -Encoding UTF8
            Write-Ok "Recovery key saved: $keyPath"
            Write-Warn "Copy this key to a safe offline location, then delete it from the Desktop!"
        }
        Write-Ok "Encryption will proceed in the background — do not power off until complete."
    } catch {
        Write-Fail "Could not enable BitLocker: $_"
    }
}

# =============================================================================
#  REMOTE ACCESS HARDENING
# =============================================================================

function Disable-WinRM {
    Write-Info "Disabling PowerShell Remoting and WinRM service..."
    Disable-PSRemoting -Force -ErrorAction SilentlyContinue
    Remove-Item -Path WSMan:\Localhost\listener\* -Recurse -Force -ErrorAction SilentlyContinue
    Stop-Service -Name WinRM -Force          -ErrorAction SilentlyContinue
    Set-Service  -Name WinRM -StartupType Disabled -ErrorAction SilentlyContinue
    Get-NetFirewallRule -DisplayGroup "Windows Remote Management" -ErrorAction SilentlyContinue |
        Disable-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Ok "PowerShell Remoting disabled and WinRM service stopped."
}

function Enable-WinRM {
    Write-Info "Enabling PowerShell Remoting and WinRM service..."
    Set-Service -Name WinRM -StartupType Automatic -ErrorAction SilentlyContinue
    Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction SilentlyContinue
    Write-Ok "PowerShell Remoting enabled."
    Write-Warn "Ensure only trusted administrators have remote PowerShell access."
}

# =============================================================================
#  NEW IN v5  —  SChannel / TLS hardening
# =============================================================================

function Set-SChannelHardening {
    Write-Info "Hardening SChannel (disable SSL 3.0 / TLS 1.0 / 1.1 / weak ciphers)..."
    $base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
    foreach ($p in @('SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1')) {
        foreach ($r in @('Client','Server')) {
            $path = "$base\$p\$r"
            Set-WSERegistry -Path $path -Name "Enabled"           -Value 0 -Type DWord | Out-Null
            Set-WSERegistry -Path $path -Name "DisabledByDefault" -Value 1 -Type DWord | Out-Null
        }
    }
    foreach ($p in @('TLS 1.2','TLS 1.3')) {
        foreach ($r in @('Client','Server')) {
            $path = "$base\$p\$r"
            Set-WSERegistry -Path $path -Name "Enabled"           -Value 0xFFFFFFFF -Type DWord | Out-Null
            Set-WSERegistry -Path $path -Name "DisabledByDefault" -Value 0          -Type DWord | Out-Null
        }
    }
    Write-Ok "SSL 2.0/3.0 + TLS 1.0/1.1 disabled. TLS 1.2 + 1.3 enabled."

    # Disable weak ciphers and hashing algorithms
    $weakCiphers = @('DES 56/56','NULL','RC2 40/128','RC2 56/128','RC2 128/128',
                     'RC4 40/128','RC4 56/128','RC4 64/128','RC4 128/128','Triple DES 168')
    foreach ($c in $weakCiphers) {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$c"
        Set-WSERegistry -Path $path -Name "Enabled" -Value 0 -Type DWord | Out-Null
    }
    foreach ($h in @('MD5','SHA')) {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$h"
        Set-WSERegistry -Path $path -Name "Enabled" -Value 0 -Type DWord | Out-Null
    }
    Write-Ok "Weak ciphers (RC4, DES, 3DES) and weak hashes (MD5, SHA-1) disabled."

    # Force .NET to prefer strong cryptography (TLS 1.2+)
    $netv4 = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
    $netv4_wow = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319'
    foreach ($p in @($netv4,$netv4_wow)) {
        Set-WSERegistry -Path $p -Name "SchUseStrongCrypto" -Value 1 -Type DWord | Out-Null
        Set-WSERegistry -Path $p -Name "SystemDefaultTlsVersions" -Value 1 -Type DWord | Out-Null
    }
    Write-Ok ".NET 4.x forced to use strong crypto + system-default TLS."
    Write-Warn "Some very old web servers may become unreachable after this change."
}

function Restore-SChannelDefaults {
    Write-Info "Removing custom SChannel protocol restrictions (back to Windows defaults)..."
    $base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
    foreach ($p in @('SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1','TLS 1.2','TLS 1.3')) {
        foreach ($r in @('Client','Server')) {
            $path = "$base\$p\$r"
            if (Test-Path $path) {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
    Write-Ok "SChannel protocols reset to OS defaults."
}

# =============================================================================
#  NEW IN v5  —  SMB / LDAP signing
# =============================================================================

function Enforce-SMBSigning {
    Write-Info "Enforcing SMB signing (client + server, mandatory)..."
    if ((Get-WSECapabilities).SmbCmdletsAvailable) {
        Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force -ErrorAction SilentlyContinue
        Set-SmbClientConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force -ErrorAction SilentlyContinue
    }
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"   -Name "RequireSecuritySignature" -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"   -Name "EnableSecuritySignature"  -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature"  -Value 1 -Type DWord | Out-Null
    # Refuse insecure guest logons (Win10 1709+)
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -Value 0 -Type DWord | Out-Null
    Write-Ok "SMB signing enforced + insecure guest logons disabled."
}

function Enforce-LDAPSigning {
    Write-Info "Enforcing LDAP client signing & channel binding..."
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name "LDAPClientIntegrity"     -Value 2 -Type DWord | Out-Null  # require signing
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -Value 2 -Type DWord | Out-Null
    Write-Ok "LDAP signing required + channel binding enforced."
}

# =============================================================================
#  NEW IN v5  —  Memory Integrity / VBS / HVCI
# =============================================================================

function Enable-MemoryIntegrity {
    Write-Info "Enabling Memory Integrity / Core Isolation (VBS + HVCI)..."
    $dg = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
    Set-WSERegistry -Path $dg -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $dg -Name "RequirePlatformSecurityFeatures"   -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $dg -Name "HypervisorEnforcedCodeIntegrity"   -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path "$dg\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path "$dg\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Locked"  -Value 0 -Type DWord | Out-Null
    Write-Ok "VBS + HVCI registry switches enabled (requires CPU virtualization + UEFI Secure Boot)."
    Write-Warn "A restart is required.  Verify with msinfo32 -> 'Virtualization-based security'."
}

# =============================================================================
#  NEW IN v5  —  Consumer / OneDrive / Xbox / SmartScreen / Quick Assist
# =============================================================================

function Disable-ConsumerFeatures {
    Write-Info "Disabling Microsoft consumer features (Store auto-install, suggested apps, tips)..."
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding"            -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value 2 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotificationOnLockScreen" -Value 1 -Type DWord | Out-Null
    Write-Ok "Consumer features (auto-install, spotlight, lock-screen ads) disabled."
}

function Disable-OneDrive {
    Write-Info "Disabling OneDrive via policy..."
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSync"     -Value 1 -Type DWord | Out-Null
    Write-Ok "OneDrive file sync disabled by Group Policy."
}

function Disable-XboxServices {
    Write-Info "Disabling Xbox services..."
    foreach ($svc in @('XblAuthManager','XblGameSave','XboxNetApiSvc','XboxGipSvc')) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Set-Service  -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Ok "Service '$svc' disabled."
        }
    }
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -Type DWord | Out-Null
    Write-Ok "Game DVR also disabled by policy."
}

function Enable-SmartScreen {
    Write-Info "Enabling Microsoft SmartScreen (Explorer, Edge, Apps & Files, Store)..."
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Value "Block" -Type String | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenEnabled"          -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenPuaEnabled"       -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverride" -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "PreventOverride"            -Value 1 -Type DWord | Out-Null
    Write-Ok "SmartScreen enabled in 'Block' mode for Explorer, Edge and Store apps."
}

function Disable-QuickAssist {
    Write-Info "Disabling / removing Quick Assist (Win32 remote-help, abused by tech-support scammers)..."
    $pkg = Get-AppxPackage -AllUsers -Name "MicrosoftCorporationII.QuickAssist" -ErrorAction SilentlyContinue
    if ($pkg) {
        try {
            Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction SilentlyContinue
            Write-Ok "Quick Assist Appx package removed."
        } catch { Write-Warn "Could not remove Quick Assist package: $_" }
    } else {
        Write-Warn "Quick Assist not installed as an Appx package."
    }
    # Legacy WinRT app
    & dism /online /Remove-Capability /CapabilityName:App.Support.QuickAssist~~~~0.0.1.0 2>&1 | Out-Null
}

function Disable-Hibernation {
    Write-Info "Disabling hibernation (purges hiberfil.sys — removes RAM-image leakage)..."
    & powercfg /h off 2>&1 | Out-Null
    Write-Ok "Hibernation disabled and hiberfil.sys removed."
}

function Disable-WebClient {
    Write-Info "Disabling WebClient (WebDAV) service — blocks NTLM-over-WebDAV relay attacks..."
    $s = Get-Service -Name WebClient -ErrorAction SilentlyContinue
    if ($s) {
        Stop-Service -Name WebClient -Force -ErrorAction SilentlyContinue
        Set-Service  -Name WebClient -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Ok "WebClient service stopped + disabled."
    } else { Write-Warn "WebClient service not present." }
}

function Disable-WPAD {
    Write-Info "Disabling WPAD (Web Proxy Auto-Discovery) — prevents WPAD-based proxy hijacking..."
    $s = Get-Service -Name WinHttpAutoProxySvc -ErrorAction SilentlyContinue
    if ($s) {
        Stop-Service -Name WinHttpAutoProxySvc -Force -ErrorAction SilentlyContinue
        Set-Service  -Name WinHttpAutoProxySvc -StartupType Disabled -ErrorAction SilentlyContinue
    }
    Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" -Name "Start" -Value 4 -Type DWord | Out-Null
    # Add 'wpad' to the hosts file as 0.0.0.0 (defence-in-depth)
    $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (Test-Path $hosts) {
        $content = Get-Content $hosts -ErrorAction SilentlyContinue
        if ($content -notmatch '^\s*0\.0\.0\.0\s+wpad\s*$') {
            Add-Content -Path $hosts -Value "0.0.0.0 wpad" -ErrorAction SilentlyContinue
            Write-Ok "Added 'wpad' = 0.0.0.0 to hosts file."
        }
    }
    Write-Ok "WPAD service disabled."
}

# =============================================================================
#  SECURITY STATUS REPORT
# =============================================================================

function Show-SecurityStatus {
    $c = Get-WSECapabilities
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║           WINDOWS SECURITY STATUS REPORT  v$($Script:WSEVersion)         ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host "   $($c.OSName)  ($($c.OSVersion) build $($c.OSBuild))" -ForegroundColor DarkGray
    Write-Host ""

    function Row {
        param($Label, $State, $Good = $true)
        $clr = if ($Good) { 'Green' } else { 'Red' }
        Write-Host ("  {0,-22}: {1}" -f $Label, $State) -ForegroundColor $clr
    }

    # UAC
    $uacVal = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
    $uacTxt = switch ($uacVal) { 0 { "DISABLED — risk!" } 1 { "Require credentials (hardened)" } 2 { "Always Notify (hardened)" } 5 { "Default" } default { "Unknown ($uacVal)" } }
    Row "UAC Level" $uacTxt ($uacVal -ge 1 -and $uacVal -le 2)

    $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    $fwOn = ($fw | Where-Object Enabled -eq $true).Count
    Row "Firewall" "$fwOn/3 profiles enabled" ($fwOn -eq 3)

    if ($c.DefenderAvailable) {
        $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
        Row "Defender RT" $(if ($mp.RealTimeProtectionEnabled){'Enabled'}else{'DISABLED'}) ($mp.RealTimeProtectionEnabled)
        Row "Defender Tamper" $(if ($mp.IsTamperProtected){'Enabled'}else{'DISABLED'}) ($mp.IsTamperProtected)
        Row "Defender Sigs"  ([string]$mp.AntivirusSignatureLastUpdated) $true
    } else {
        Write-Host "  Defender              : cmdlets unavailable" -ForegroundColor Yellow
    }

    $rdp = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
    Row "RDP" $(if ($rdp -eq 1){'Disabled (secure)'}else{'Enabled'}) ($rdp -eq 1)

    $ra = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue).fAllowToGetHelp
    Row "Remote Assistance" $(if ($ra -eq 0){'Disabled (secure)'}else{'Enabled'}) ($ra -eq 0)

    $smb1 = $null; try { $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch {}
    if ($null -eq $smb1) {
        $r = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -ErrorAction SilentlyContinue).SMB1
        $smb1 = ($r -ne 0)
    }
    Row "SMBv1" $(if (-not $smb1){'Disabled (secure)'}else{'ENABLED — vulnerable!'}) (-not $smb1)

    $smbSigC = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature
    Row "SMB Signing (client)" $(if ($smbSigC -eq 1){'Required'}else{'Optional/Off'}) ($smbSigC -eq 1)

    $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    Row "Print Spooler" $(if ($spooler -and $spooler.StartType -eq 'Disabled'){'Disabled (secure)'}else{'Enabled'}) ($spooler -and $spooler.StartType -eq 'Disabled')

    $ntlm = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
    $ntlmTxt = switch ($ntlm) { 5 { "NTLMv2 only (secure)" } 3 { "NTLMv2 + NTLMv1 (partial)" } default { "LM/NTLMv1 allowed — weak!" } }
    Row "NTLM Level" $ntlmTxt ($ntlm -ge 5)

    $usbStart = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor" -Name "Start" -ErrorAction SilentlyContinue).Start
    Row "USB Storage" $(if ($usbStart -eq 4){'Disabled'}else{'Enabled'}) ($usbStart -eq 4)

    $guestLine = & net user Guest 2>&1 | Select-String "Account active"
    $guestEnabled = "$guestLine" -match "Yes"
    Row "Guest Account" $(if (-not $guestEnabled){'Disabled (secure)'}else{'ENABLED — risky!'}) (-not $guestEnabled)

    $ar = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
    Row "AutoRun" $(if ($ar -eq 0xFF){'Fully disabled'}else{'Not fully disabled'}) ($ar -eq 0xFF)

    $wsh = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    Row "Script Host" $(if ($wsh -eq 0){'Disabled (secure)'}else{'Enabled'}) ($wsh -eq 0)

    $llmnr = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast
    Row "LLMNR" $(if ($llmnr -eq 0){'Disabled (secure)'}else{'Enabled'}) ($llmnr -eq 0)

    $mdns = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableMDNS" -ErrorAction SilentlyContinue).EnableMDNS
    Row "mDNS" $(if ($mdns -eq 0){'Disabled'}else{'Enabled (default)'}) ($mdns -eq 0)

    $wdigest = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue).UseLogonCredential
    Row "WDigest (creds)" $(if ($wdigest -eq 0){'Disabled (secure)'}else{'ENABLED — creds at risk!'}) ($wdigest -eq 0)

    $lsaPpl = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL
    Row "LSA Protection" $(if ($lsaPpl -eq 1){'Enabled (RunAsPPL)'}else{'Disabled'}) ($lsaPpl -eq 1)

    $telem = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue).AllowTelemetry
    Row "Telemetry" $(if ($telem -eq 0){'Level 0 (Security)'}else{"Level $telem"}) ($telem -eq 0)

    $diagSvc = Get-Service -Name DiagTrack -ErrorAction SilentlyContinue
    Row "DiagTrack" $(if ($diagSvc -and $diagSvc.StartType -eq 'Disabled'){'Disabled'}else{'Running/Enabled'}) ($diagSvc -and $diagSvc.StartType -eq 'Disabled')

    $pfClear = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -ErrorAction SilentlyContinue).ClearPageFileAtShutdown
    Row "Clear Page File" $(if ($pfClear -eq 1){'On shutdown'}else{'Disabled'}) ($pfClear -eq 1)

    $sehop = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -ErrorAction SilentlyContinue).DisableExceptionChainValidation
    Row "SEHOP" $(if ($sehop -eq 0){'Enabled'}else{'Disabled'}) ($sehop -eq 0)

    $ipv6Comp = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -ErrorAction SilentlyContinue).DisabledComponents
    Row "IPv6" $(if ($ipv6Comp -eq 0xFF){'Disabled'}else{'Enabled'}) $true   # both are acceptable

    $cortana = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -ErrorAction SilentlyContinue).AllowCortana
    Row "Cortana" $(if ($cortana -eq 0){'Disabled'}else{'Enabled'}) ($cortana -eq 0)

    $asrIds = @()
    try { $asrIds = @((Get-MpPreference -ErrorAction Stop).AttackSurfaceReductionRules_Ids) } catch {}
    Row "ASR Rules" "$($asrIds.Count) rule(s)" ($asrIds.Count -ge 14)

    $psPolicy = Get-ExecutionPolicy -Scope LocalMachine
    Row "PS Exec Policy" "$psPolicy" ($psPolicy -in @('AllSigned','RemoteSigned','Restricted'))

    $btSvc = Get-Service -Name bthserv -ErrorAction SilentlyContinue
    Row "Bluetooth" $(if ($btSvc -and $btSvc.StartType -eq 'Disabled'){'Service Disabled'}elseif ($btSvc){'Enabled'}else{'Not present'}) ($btSvc -and $btSvc.StartType -eq 'Disabled')

    $macroKey = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security" -Name "VBAWarnings" -ErrorAction SilentlyContinue).VBAWarnings
    Row "Office Macros" $(if ($macroKey -eq 4){'Disabled via policy'}else{'Not policy-restricted'}) ($macroKey -eq 4)

    $bl = $null; try { $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop } catch {}
    Row "BitLocker (C:)" $(if ($bl -and $bl.ProtectionStatus -eq 'On'){'ENABLED'}elseif ($bl){'DISABLED'}else{'Unavailable'}) ($bl -and $bl.ProtectionStatus -eq 'On')

    $winrm = Get-Service -Name WinRM -ErrorAction SilentlyContinue
    Row "WinRM / PS Remote" $(if ($winrm -and $winrm.StartType -eq 'Disabled'){'Disabled'}elseif ($winrm){'Enabled'}else{'Not present'}) ($winrm -and $winrm.StartType -eq 'Disabled')

    $fwLog = (Get-NetFirewallProfile -Name Domain -ErrorAction SilentlyContinue).LogBlocked
    Row "Firewall Logging" $(if ($fwLog){'Enabled'}else{'Disabled'}) ([bool]$fwLog)

    # TLS / SChannel
    $tls10 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    Row "TLS 1.0 (client)" $(if ($tls10 -eq 0){'Disabled (secure)'}else{'Enabled — weak'}) ($tls10 -eq 0)

    $webdav = Get-Service -Name WebClient -ErrorAction SilentlyContinue
    Row "WebClient (WebDAV)" $(if ($webdav -and $webdav.StartType -eq 'Disabled'){'Disabled'}elseif ($webdav){'Enabled'}else{'Not present'}) ($webdav -and $webdav.StartType -eq 'Disabled')

    Write-Host ""
}

# =============================================================================
#  APPLY-ALL  (safe order: hardens execution policy last + uses RemoteSigned)
# =============================================================================

function Invoke-AllHardening {
    Write-Host ""
    Write-Host "  *** Applying ALL security hardening settings ***" -ForegroundColor Magenta
    Write-Host ""
    New-WSERestorePoint
    Enforce-UACPasswordPrompt
    Set-UACAlwaysNotify
    Set-AccountLockoutPolicy
    Set-StrongPasswordPolicy
    Disable-USBPorts
    Enable-WindowsFirewall
    Enable-FirewallLogging
    Disable-SMBv1
    Enforce-SMBSigning
    Enforce-LDAPSigning
    Disable-RemoteDesktop
    Enable-WindowsDefender
    Set-DefenderSchedule
    Enable-ASRRules
    Disable-AutoRun
    Disable-GuestAccount
    Enable-AuditPolicy
    Disable-UnnecessaryServices
    Disable-WindowsScriptHost
    Disable-AnonymousAccess
    Enable-CredentialGuard
    Enable-MemoryIntegrity
    Disable-Telemetry
    Disable-AdvertisingID
    Disable-Cortana
    Disable-ConsumerFeatures
    Disable-OneDrive
    Disable-XboxServices
    Enable-SmartScreen
    Disable-PrintSpooler
    Set-NTLMv2Only
    Disable-PowerShellv2
    Enable-ExploitProtection
    Enable-ClearPageFileOnShutdown
    Disable-RemoteAssistance
    Disable-WinRM
    Set-SecureDNS
    Enable-DNSOverHTTPS
    Disable-IPv6TransitionTech
    Set-SChannelHardening
    Disable-WebClient
    Disable-WPAD
    Disable-QuickAssist
    Disable-Hibernation
    Enable-AutomaticUpdates
    Set-ScreenLockTimeout
    Disable-OfficeMacros
    Disable-Bluetooth
    Set-PSExecutionRemoteSigned   # safer than AllSigned — keeps tool re-runnable

    Write-Host ""
    Write-Host "  *** All hardening tasks complete. ***" -ForegroundColor Magenta
    Write-Host "  *** A system restart is strongly recommended. ***" -ForegroundColor Yellow
    Write-Host ("     Backup of changed registry values: {0}" -f $Script:WSESessionBackup) -ForegroundColor DarkGray
    Write-Host ""
}

# =============================================================================
#  MENU
# =============================================================================

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ╔════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "  ║       W I N D O W S   S E C U R I T Y                  ║" -ForegroundColor Magenta
    Write-Host "  ║              E N H A N C E R   v$($Script:WSEVersion)                    ║" -ForegroundColor Magenta
    Write-Host "  ╚════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
    $c = Get-WSECapabilities
    Write-Host "   $($c.OSName) ($($c.Edition))   PowerShell $($c.PSVersion)" -ForegroundColor DarkGray
    Write-Host "   Log: $($Script:WSETranscript)" -ForegroundColor DarkGray
    Write-Host ""
}

function Show-Menu {
    Show-Banner
    Write-Host "  ── UAC & Authentication ─────────────────────────────────" -ForegroundColor Yellow
    Write-Host "    1.  Enforce UAC credential prompt (hardened)"
    Write-Host "    2.  Set UAC to 'Always Notify' (maximum)"
    Write-Host "    3.  Restore UAC to Windows default"
    Write-Host "    4.  Set account lockout policy  (5 attempts / 30 min)"
    Write-Host "    5.  Restore account lockout to default"
    Write-Host "    6.  Enforce strong password policy (14 chars, 90-day)"
    Write-Host ""
    Write-Host "  ── Firewall & Network ───────────────────────────────────" -ForegroundColor Yellow
    Write-Host "    7.  Enable Windows Firewall + block dangerous ports"
    Write-Host "    8.  Disable Windows Firewall  [NOT recommended]"
    Write-Host "    9.  Disable SMBv1 (WannaCry / EternalBlue prevention)"
    Write-Host "   10.  Enable  SMBv1  [NOT recommended]"
    Write-Host "   11.  Disable RDP"
    Write-Host "   12.  Enable  RDP  (with NLA + High encryption)"
    Write-Host "   13.  Disable anonymous access, LLMNR & NBT-NS (+ mDNS)"
    Write-Host ""
    Write-Host "  ── Devices & Storage ────────────────────────────────────" -ForegroundColor Yellow
    Write-Host "   14.  Disable USB storage  (HID devices unaffected)"
    Write-Host "   15.  Enable  USB storage"
    Write-Host "   16.  Disable cameras"
    Write-Host "   17.  Enable  cameras"
    Write-Host "   18.  Disable AutoRun / AutoPlay"
    Write-Host "   19.  Enable  AutoRun / AutoPlay"
    Write-Host ""
    Write-Host "  ── Defender, Accounts & Scripts ─────────────────────────" -ForegroundColor Yellow
    Write-Host "   20.  Configure Windows Defender (maximum protection)"
    Write-Host "   21.  Disable Guest account"
    Write-Host "   22.  Enable  Guest account  [NOT recommended]"
    Write-Host "   23.  Disable Windows Script Host  (blocks .vbs/.js malware)"
    Write-Host "   24.  Enable  Windows Script Host"
    Write-Host ""
    Write-Host "  ── Services, Auditing & Credentials ─────────────────────" -ForegroundColor Yellow
    Write-Host "   25.  Disable unnecessary / risky services"
    Write-Host "   26.  Restore disabled services to Manual"
    Write-Host "   27.  Enable comprehensive security audit policy"
    Write-Host "   28.  Enable LSA / Credential Guard protection"
    Write-Host ""
    Write-Host "  ── Privacy & Telemetry ──────────────────────────────────" -ForegroundColor Yellow
    Write-Host "   29.  Disable Windows Telemetry (DiagTrack + policy)"
    Write-Host "   30.  Enable  Windows Telemetry (restore)"
    Write-Host "   31.  Disable Advertising ID & content tracking"
    Write-Host "   32.  Disable Cortana & web search"
    Write-Host ""
    Write-Host "  ── Advanced System Hardening ────────────────────────────" -ForegroundColor Yellow
    Write-Host "   33.  Disable Print Spooler (PrintNightmare prevention)"
    Write-Host "   34.  Enable  Print Spooler"
    Write-Host "   35.  Force NTLMv2 only (disable LM / NTLMv1)"
    Write-Host "   36.  Disable PowerShell v2  (prevents logging bypass)"
    Write-Host "   37.  Enable  Exploit Protection (DEP/SEHOP/ASLR/CFG)"
    Write-Host "   38.  Enable  Clear Page File on Shutdown"
    Write-Host "   39.  Disable Clear Page File on Shutdown"
    Write-Host "   40.  Disable Remote Assistance"
    Write-Host "   41.  Enable  Remote Assistance"
    Write-Host ""
    Write-Host "  ── Network & DNS Hardening ──────────────────────────────" -ForegroundColor Yellow
    Write-Host "   42.  Set Secure DNS (Cloudflare + Quad9)"
    Write-Host "   43.  Disable IPv6 (reduce attack surface)"
    Write-Host "   44.  Enable  IPv6"
    Write-Host ""
    Write-Host "  ── Additional Hardening ─────────────────────────────────" -ForegroundColor Yellow
    Write-Host "   45.  Force Automatic Windows Updates"
    Write-Host "   46.  Set screen auto-lock (5-min timeout)"
    Write-Host "   47.  Rename built-in Administrator account"
    Write-Host "   48.  Create a System Restore Point"
    Write-Host "   49.  Show OS / capability detection report"
    Write-Host "   50.  Show file system locations  (logs + backups)"
    Write-Host ""
    Write-Host "  ── Attack Surface Reduction (ASR) ───────────────────────" -ForegroundColor Yellow
    Write-Host "   51.  Enable Defender ASR rules  (16 rules / Block mode)"
    Write-Host "   52.  Disable Defender ASR rules"
    Write-Host ""
    Write-Host "  ── PowerShell Hardening ─────────────────────────────────" -ForegroundColor Yellow
    Write-Host "   53.  Set execution policy to RemoteSigned"
    Write-Host "   54.  Set execution policy to AllSigned  (strictest)"
    Write-Host "   55.  Restore execution policy to default"
    Write-Host ""
    Write-Host "  ── Wireless Security ────────────────────────────────────" -ForegroundColor Yellow
    Write-Host "   56.  Disable Bluetooth"
    Write-Host "   57.  Enable  Bluetooth"
    Write-Host ""
    Write-Host "  ── Office & Application Security ────────────────────────" -ForegroundColor Yellow
    Write-Host "   58.  Disable Microsoft Office macros  (+ block MOTW macros)"
    Write-Host "   59.  Enable  Microsoft Office macros  (restore)"
    Write-Host ""
    Write-Host "  ── Firewall Enhancements ────────────────────────────────" -ForegroundColor Yellow
    Write-Host "   60.  Enable Firewall logging  (allowed + blocked)"
    Write-Host "   61.  Block all outbound traffic by default  [advanced]"
    Write-Host "   62.  Restore default outbound action  (Allow)"
    Write-Host ""
    Write-Host "  ── Drive Encryption (BitLocker) ─────────────────────────" -ForegroundColor Yellow
    Write-Host "   63.  Show BitLocker status on all drives"
    Write-Host "   64.  Enable BitLocker on system drive (C:)"
    Write-Host ""
    Write-Host "  ── Remote Access Hardening ──────────────────────────────" -ForegroundColor Yellow
    Write-Host "   65.  Disable PowerShell Remoting / WinRM"
    Write-Host "   66.  Enable  PowerShell Remoting / WinRM"
    Write-Host ""
    Write-Host "  ── NEW in v5  —  Extra Hardening ────────────────────────" -ForegroundColor Magenta
    Write-Host "   70.  Show Defender Tamper-Protection status"
    Write-Host "   71.  Schedule daily Defender quick-scan + sig-update"
    Write-Host "   72.  Disable WebClient (WebDAV) service"
    Write-Host "   73.  Disable WPAD (Web Proxy Auto-Discovery)"
    Write-Host "   74.  Disable IPv6 transition tech (Teredo/ISATAP/6to4)"
    Write-Host "   75.  Harden SChannel  (disable SSL3, TLS 1.0/1.1, weak ciphers)"
    Write-Host "   76.  Restore SChannel defaults"
    Write-Host "   77.  Configure DNS-over-HTTPS (DoH)"
    Write-Host "   78.  Enforce SMB signing (client + server)"
    Write-Host "   79.  Enforce LDAP signing + channel binding"
    Write-Host "   80.  Enable Memory Integrity / Core Isolation (VBS + HVCI)"
    Write-Host "   81.  Disable Microsoft consumer features (Store auto-install)"
    Write-Host "   82.  Disable OneDrive (policy)"
    Write-Host "   83.  Disable Xbox services + Game DVR"
    Write-Host "   84.  Enable SmartScreen everywhere"
    Write-Host "   85.  Disable Quick Assist  (tech-support-scam vector)"
    Write-Host "   86.  Disable hibernation (purge hiberfil.sys)"
    Write-Host ""
    Write-Host "  ── Utilities ────────────────────────────────────────────" -ForegroundColor Yellow
    Write-Host "   67.  Show security status report"
    Write-Host "   68.  Apply ALL hardening settings  [recommended]"
    Write-Host "   93.  ROLLBACK — restore registry from a previous backup"
    Write-Host "   69.  Exit"
    Write-Host ""
    Write-Host "  Available range: 1-50, 51-66, 67-86, 93, 69" -ForegroundColor DarkGray
    $choice = Read-Host "  Enter choice"
    return $choice
}

# =============================================================================
#  MAIN LOOP
# =============================================================================

Initialize-WSE
Get-WSECapabilities | Out-Null

# Re-show the elevation banner once on startup
Write-Host ""
Write-Host "  [+] Running as Administrator." -ForegroundColor Green
Write-Host "  [+] WSE v$($Script:WSEVersion) initialised — log: $($Script:WSETranscript)" -ForegroundColor Green

try {
    do {
        $userChoice = Show-Menu

        switch ($userChoice) {
             '1'  { Enforce-UACPasswordPrompt          }
             '2'  { Set-UACAlwaysNotify                }
             '3'  { Restore-UACToNormal                }
             '4'  { Set-AccountLockoutPolicy           }
             '5'  { Disable-AccountLockoutPolicy       }
             '6'  { Set-StrongPasswordPolicy           }
             '7'  { Enable-WindowsFirewall             }
             '8'  { Disable-WindowsFirewall            }
             '9'  { Disable-SMBv1                      }
            '10'  { Enable-SMBv1                       }
            '11'  { Disable-RemoteDesktop              }
            '12'  { Enable-RemoteDesktop               }
            '13'  { Disable-AnonymousAccess            }
            '14'  { Disable-USBPorts                   }
            '15'  { Enable-USBPorts                    }
            '16'  { Disable-Cameras                    }
            '17'  { Enable-Cameras                     }
            '18'  { Disable-AutoRun                    }
            '19'  { Enable-AutoRun                     }
            '20'  { Enable-WindowsDefender             }
            '21'  { Disable-GuestAccount               }
            '22'  { Enable-GuestAccount                }
            '23'  { Disable-WindowsScriptHost          }
            '24'  { Enable-WindowsScriptHost           }
            '25'  { Disable-UnnecessaryServices        }
            '26'  { Enable-UnnecessaryServices         }
            '27'  { Enable-AuditPolicy                 }
            '28'  { Enable-CredentialGuard             }
            '29'  { Disable-Telemetry                  }
            '30'  { Enable-Telemetry                   }
            '31'  { Disable-AdvertisingID              }
            '32'  { Disable-Cortana                    }
            '33'  { Disable-PrintSpooler               }
            '34'  { Enable-PrintSpooler                }
            '35'  { Set-NTLMv2Only                     }
            '36'  { Disable-PowerShellv2               }
            '37'  { Enable-ExploitProtection           }
            '38'  { Enable-ClearPageFileOnShutdown     }
            '39'  { Disable-ClearPageFileOnShutdown    }
            '40'  { Disable-RemoteAssistance           }
            '41'  { Enable-RemoteAssistance            }
            '42'  { Set-SecureDNS                      }
            '43'  { Disable-IPv6                       }
            '44'  { Enable-IPv6                        }
            '45'  { Enable-AutomaticUpdates            }
            '46'  { Set-ScreenLockTimeout              }
            '47'  { Rename-AdminAccount                }
            '48'  { New-WSERestorePoint                }
            '49'  { Show-CapabilityReport              }
            '50'  {
                Write-Section "File system locations"
                Write-Host "  Logs    : $Script:WSELogDir"        -ForegroundColor Cyan
                Write-Host "  Backups : $Script:WSEBackupRoot"    -ForegroundColor Cyan
                Write-Host "  This session backup file : $Script:WSEBackupFile" -ForegroundColor Cyan
            }
            '51'  { Enable-ASRRules                    }
            '52'  { Disable-ASRRules                   }
            '53'  { Set-PSExecutionRemoteSigned        }
            '54'  { Set-PSExecutionAllSigned           }
            '55'  { Restore-PSExecutionDefault         }
            '56'  { Disable-Bluetooth                  }
            '57'  { Enable-Bluetooth                   }
            '58'  { Disable-OfficeMacros               }
            '59'  { Enable-OfficeMacros                }
            '60'  { Enable-FirewallLogging             }
            '61'  { Set-FirewallBlockOutbound          }
            '62'  { Restore-FirewallDefaultOutbound    }
            '63'  { Show-BitLockerStatus               }
            '64'  { Enable-BitLockerSystem             }
            '65'  { Disable-WinRM                      }
            '66'  { Enable-WinRM                       }
            '67'  { Show-SecurityStatus                }
            '68'  { Invoke-AllHardening                }
            '70'  { Show-DefenderTamperStatus          }
            '71'  { Set-DefenderSchedule               }
            '72'  { Disable-WebClient                  }
            '73'  { Disable-WPAD                       }
            '74'  { Disable-IPv6TransitionTech         }
            '75'  { Set-SChannelHardening              }
            '76'  { Restore-SChannelDefaults           }
            '77'  { Enable-DNSOverHTTPS                }
            '78'  { Enforce-SMBSigning                 }
            '79'  { Enforce-LDAPSigning                }
            '80'  { Enable-MemoryIntegrity             }
            '81'  { Disable-ConsumerFeatures           }
            '82'  { Disable-OneDrive                   }
            '83'  { Disable-XboxServices               }
            '84'  { Enable-SmartScreen                 }
            '85'  { Disable-QuickAssist                }
            '86'  { Disable-Hibernation                }
            '93'  { Invoke-WSERollback                 }
            '69'  { Write-Host "  Exiting Windows Security Enhancer. Stay secure!" -ForegroundColor Magenta }
            default { Write-Warn "Invalid choice — enter a valid option number." }
        }

        if ($userChoice -ne '69') {
            Write-Host ""
            Read-Host "  Press ENTER to return to the menu"
        }
    } while ($userChoice -ne '69')
}
finally {
    Stop-WSE
}
