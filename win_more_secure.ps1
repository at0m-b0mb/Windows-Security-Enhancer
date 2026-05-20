# =============================================================================
#  Windows Security Enhancer  v5.1
#  Hardens Windows 10 / 11 / Server systems against modern attack techniques.
#
#  Run via runner.bat (CLI) or runner_gui.bat (graphical) - both self-elevate.
#
#  Highlights of v5.1:
#    * Full transcript logging  ->  %ProgramData%\WSE\logs\
#    * Automatic registry backup before each change (Option 93 = rollback)
#    * OS / edition / capability detection (gracefully skips unsupported ops)
#    * 20+ new hardening features (SChannel, DoH, HVCI, SMB/LDAP signing, ...)
#    * NEW: WPF graphical interface (win_more_secure_gui.ps1)
#    * NEW: Non-interactive switches (-Apply, -Status, -Rollback, -QuickWin)
#    * NEW: HTML report export (Option 90)
#    * NEW: Quick Win preset (safest hardening only - Option 87)
#    * Bug fixes: unapproved verbs renamed, SMB1 status, (Default) value,
#      Tamper-Protection check, BitLocker PIN digit validation, duplicate
#      UAC backup entries in Apply-All
# =============================================================================

# -----------------------------------------------------------------------------
#  Command-line parameters (must be the first executable statement)
# -----------------------------------------------------------------------------
[CmdletBinding()]
param(
    [switch] $Apply,        # run Apply-All non-interactively then exit
    [switch] $QuickWin,     # run the curated Quick Win preset then exit
    [switch] $Status,       # print Security Status Report then exit
    [switch] $Report,       # write HTML report then exit (-ReportPath optional)
    [string] $ReportPath,
    [switch] $Rollback,     # interactive rollback then exit
    [switch] $NoElevate,    # used internally by the GUI to suppress self-elevation
    [switch] $NoMenu,       # dot-source the file without entering the menu loop (used by GUI)
    [switch] $Quiet         # suppress the menu (used by -Apply etc.)
)

# -----------------------------------------------------------------------------
#  Global execution context
# -----------------------------------------------------------------------------
Set-StrictMode -Version 1.0   # catches uninitialized vars without breaking on $null property access
$ErrorActionPreference = 'Continue'   # don't crash the whole script on one bad call
$PSDefaultParameterValues['*:ErrorAction'] = 'SilentlyContinue'

$Script:WSEVersion       = '5.2'
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
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -and -not $NoElevate) {
    Write-Host "  [!] Administrator privileges required. Re-launching as Administrator..." -ForegroundColor Yellow
    $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
    # Forward the original command-line switches so non-interactive modes survive the relaunch
    $passThru = @()
    if ($Apply)    { $passThru += '-Apply' }
    if ($QuickWin) { $passThru += '-QuickWin' }
    if ($Status)   { $passThru += '-Status' }
    if ($Report)   { $passThru += '-Report' }
    if ($ReportPath) { $passThru += "-ReportPath `"$ReportPath`"" }
    if ($Rollback) { $passThru += '-Rollback' }
    if ($Quiet)    { $passThru += '-Quiet' }
    $argString = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" $($passThru -join ' ')"
    try {
        Start-Process powershell -ArgumentList $argString -Verb RunAs -ErrorAction Stop
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

    # ---- CPU / architecture detection ---------------------------------------
    # PROCESSOR_ARCHITECTURE is set by the OS regardless of whether we're running in WoW64
    # (an x86 PowerShell on x64 reports x86 here - so we also consult PROCESSOR_ARCHITEW6432
    # and Win32_Processor for the truth).
    $procArch = $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) { $procArch = $env:PROCESSOR_ARCHITEW6432 }
    $cpu = $null
    try { $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1 } catch {}
    $cpuVendor = if ($cpu) { "$($cpu.Manufacturer)" } else { 'Unknown' }
    $cpuName   = if ($cpu) { "$($cpu.Name)".Trim() } else { 'Unknown' }
    $isARM     = ($procArch -eq 'ARM64') -or ($procArch -eq 'ARM')
    $isIntel   = $cpuVendor -match 'Intel'
    $isAMD     = $cpuVendor -match 'AMD|Advanced Micro'

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
        ProcessorArch     = $procArch
        Is64Bit           = [System.Environment]::Is64BitOperatingSystem
        IsARM             = $isARM
        IsIntel           = [bool]$isIntel
        IsAMD             = [bool]$isAMD
        CpuVendor         = $cpuVendor
        CpuName           = $cpuName
        CpuCores          = if ($cpu) { [int]$cpu.NumberOfCores } else { 0 }
        CpuLogical        = if ($cpu) { [int]$cpu.NumberOfLogicalProcessors } else { 0 }
        VirtFwEnabled     = if ($cpu -and ($cpu.PSObject.Properties.Name -contains 'VirtualizationFirmwareEnabled')) { [bool]$cpu.VirtualizationFirmwareEnabled } else { $null }
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
    Write-Host ""
    $archTag = if ($c.IsARM) { 'ARM64' } elseif ($c.IsIntel) { 'Intel x64' } elseif ($c.IsAMD) { 'AMD x64' } else { $c.ProcessorArch }
    Write-Host ("  Architecture       : {0}  ({1})" -f $c.ProcessorArch, $archTag) -ForegroundColor Cyan
    Write-Host ("  CPU                : {0}"  -f $c.CpuName)           -ForegroundColor Cyan
    Write-Host ("  Cores / Logical    : {0} / {1}" -f $c.CpuCores, $c.CpuLogical) -ForegroundColor Cyan
    if ($null -ne $c.VirtFwEnabled) {
        Write-Host ("  Virtualisation FW  : {0}" -f $c.VirtFwEnabled)  -ForegroundColor Cyan
    }
    Write-Host ""
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
        if ($Name -eq '(Default)') {
            # The default value has no real "name" - read it via the parens-less alias
            $item = Get-ItemProperty -Path $Path -ErrorAction Stop
            $existing = $item.'(default)'
            if ($null -eq $existing) { $existedBefore = $false }
        } else {
            $prop = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
            # $obj.$name returns $null cleanly under StrictMode 1.0 if the property is missing
            $existing = $prop.$Name
        }
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

function Set-UACPasswordPrompt {
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
        # IsTamperProtected only exists on newer Defender builds; PSObject.Properties avoids StrictMode errors
        $hasProp = $st.PSObject.Properties.Name -contains 'IsTamperProtected'
        if (-not $hasProp) {
            Write-Warn "This Defender version does not expose IsTamperProtected — open Windows Security to verify."
            return
        }
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
    $caps = Get-WSECapabilities
    if ($caps.IsARM) {
        Write-Info "ARM64 detected - SEHOP and 32-bit-only mitigations don't apply; CFG / ASLR / heap terminate still do."
    } else {
        Set-WSERegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
            -Name "DisableExceptionChainValidation" -Value 0 -Type DWord | Out-Null
        Write-Ok "SEHOP enabled (32-bit exception-chain validation - x86/x64 only)."
    }

    # DEP / NX  -  bcdedit accepts AlwaysOn on every architecture, but the OS only
    # honours it on x64; on ARM64 the equivalent is intrinsic to the architecture.
    if (-not $caps.IsARM) {
        & bcdedit /set nx AlwaysOn 2>&1 | Out-Null
        Write-Ok "DEP (NX) set to AlwaysOn."
    } else {
        Write-Ok "DEP/NX is enforced by ARM64 hardware - no bcdedit toggle needed."
    }

    if ($caps.ProcessMitigationAvailable) {
        try { Set-ProcessMitigation -System -Enable HeapTerminateOnCorruption -ErrorAction Stop; Write-Ok "Heap Terminate on Corruption enabled." } catch { Write-Warn "Heap terminate mitigation skipped." }
        try { Set-ProcessMitigation -System -Enable ForceRelocateImages -ErrorAction Stop; Write-Ok "Force ASLR enabled." } catch { Write-Warn "Force ASLR not available." }
        try { Set-ProcessMitigation -System -Enable BottomUp -ErrorAction Stop; Write-Ok "Bottom-up ASLR enabled." } catch {}
        try { Set-ProcessMitigation -System -Enable HighEntropy -ErrorAction Stop; Write-Ok "High-entropy ASLR enabled." } catch {}
        try { Set-ProcessMitigation -System -Enable CFG -ErrorAction Stop; Write-Ok "Control Flow Guard enabled." } catch {}
        try { Set-ProcessMitigation -System -Enable DEP -ErrorAction Stop; Write-Ok "Per-process DEP enabled." } catch {}
        if (-not $caps.IsARM) {
            try { Set-ProcessMitigation -System -Enable SEHOP -ErrorAction Stop } catch {}
        }
    } else {
        Write-Warn "Set-ProcessMitigation cmdlet unavailable - using registry only."
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
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pin)
            try {
                $pinPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                if ([string]::IsNullOrEmpty($pinPlain) -or $pinPlain.Length -lt 6 -or $pinPlain -notmatch '^\d+$') {
                    Write-Warn "PIN must be at least 6 digits (numbers only) — cancelled."
                    return
                }
            } finally {
                # Zero out the plain-text copy before we lose the reference
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                $pinPlain = $null
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

function Set-SMBSigningRequired {
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

function Set-LDAPSigningRequired {
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
    $caps = Get-WSECapabilities

    if ($caps.IsARM) {
        Write-Info "ARM64 detected (Snapdragon / Surface Pro ARM / etc.)."
        Write-Info "VBS + HVCI work on ARM64 via the same policy keys; ensure UEFI Secure Boot + virtualisation are on."
    } elseif ($caps.IsIntel) {
        Write-Info "Intel CPU detected - VBS / HVCI use VT-x + EPT. Make sure VT-x is on in firmware."
    } elseif ($caps.IsAMD) {
        Write-Info "AMD CPU detected - VBS / HVCI use AMD-V + RVI / NPT. Make sure SVM is on in firmware."
    }

    if ($null -ne $caps.VirtFwEnabled -and -not $caps.VirtFwEnabled) {
        Write-Warn "Win32_Processor reports virtualisation extensions are DISABLED in firmware - HVCI will not engage until you enable VT-x / SVM in the BIOS."
    }

    $dg = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
    Set-WSERegistry -Path $dg -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $dg -Name "RequirePlatformSecurityFeatures"   -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $dg -Name "HypervisorEnforcedCodeIntegrity"   -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path "$dg\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path "$dg\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Locked"  -Value 0 -Type DWord | Out-Null
    Write-Ok "VBS + HVCI registry switches enabled."
    Write-Warn "A restart is required. Verify with msinfo32 -> 'Virtualization-based security'."
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
#  NEW IN v5.2  -  Firewall stealth mode (anti-recon on Public)
# =============================================================================

function Set-FirewallStealthMode {
    Write-Info "Enabling firewall stealth mode on the Public profile..."
    # Block inbound ICMP echo requests on the Public profile (drops pings from untrusted networks).
    foreach ($proto in @('ICMPv4','ICMPv6')) {
        $ruleName = "WSE-Block-$proto-Echo-Public"
        if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol $proto `
                -IcmpType 8 -Profile Public -Action Block -ErrorAction SilentlyContinue | Out-Null
            Write-Ok "Blocked inbound $proto Echo on Public profile."
        } else {
            Write-Warn "Rule '$ruleName' already exists - skipped."
        }
    }
    # File and Printer Sharing (Echo Request) - the Windows built-in rules - disabled on Public too
    Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -ErrorAction SilentlyContinue |
        Where-Object { $_.Profile -match 'Public' -and $_.Direction -eq 'Inbound' } |
        Disable-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Ok "Disabled File-and-Printer-Sharing inbound rules on Public profile."
    Write-Ok "Stealth mode on - your machine should no longer respond to pings on untrusted networks."
}

# =============================================================================
#  NEW IN v5.2  -  Microsoft Edge hardening (privacy + security)
# =============================================================================

function Set-EdgeHardening {
    Write-Info "Hardening Microsoft Edge (Chromium) policies..."
    $edge = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"

    Set-WSERegistry -Path $edge -Name "HideFirstRunExperience"        -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $edge -Name "MetricsReportingEnabled"       -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $edge -Name "DiagnosticData"                -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $edge -Name "PersonalizationReportingEnabled" -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $edge -Name "SyncDisabled"                  -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $edge -Name "BrowserSignin"                 -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $edge -Name "PasswordManagerEnabled"        -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $edge -Name "PaymentMethodQueryEnabled"     -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $edge -Name "AutofillCreditCardEnabled"     -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $edge -Name "AutofillAddressEnabled"        -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $edge -Name "EdgeShoppingAssistantEnabled"  -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $edge -Name "PromotionsEnabled"             -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $edge -Name "EnableMediaRouter"             -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $edge -Name "BlockThirdPartyCookies"        -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $edge -Name "TrackingPrevention"            -Value 3 -Type DWord | Out-Null  # Strict
    Set-WSERegistry -Path $edge -Name "DoNotTrack"                    -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $edge -Name "BackgroundModeEnabled"         -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $edge -Name "AllowFileSelectionDialogs"     -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $edge -Name "DefaultPopupsSetting"          -Value 2 -Type DWord | Out-Null  # Block popups
    Set-WSERegistry -Path $edge -Name "PreventSmartScreenPromptOverride"               -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $edge -Name "PreventSmartScreenPromptOverrideForFiles"        -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $edge -Name "BasicAuthOverHttpEnabled"      -Value 0 -Type DWord | Out-Null
    Set-WSERegistry -Path $edge -Name "BuiltInDnsClientEnabled"       -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $edge -Name "TyposquattingCheckerEnabled"   -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $edge -Name "InternetExplorerIntegrationLevel" -Value 0 -Type DWord | Out-Null
    Write-Ok "Edge: telemetry off, sync off, sign-in blocked, password manager off, payment/autofill off."
    Write-Ok "Edge: 3rd-party cookies blocked, Strict tracking prevention, DNT on, SmartScreen enforced."
}

function Restore-EdgeDefaults {
    Write-Info "Removing Microsoft Edge hardening policies (back to defaults)..."
    $edge = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    if (Test-Path $edge) {
        # Remove only the keys we set - leave any third-party policy customisation alone
        $names = @('HideFirstRunExperience','MetricsReportingEnabled','DiagnosticData','PersonalizationReportingEnabled',
                   'SyncDisabled','BrowserSignin','PasswordManagerEnabled','PaymentMethodQueryEnabled',
                   'AutofillCreditCardEnabled','AutofillAddressEnabled','EdgeShoppingAssistantEnabled',
                   'PromotionsEnabled','EnableMediaRouter','BlockThirdPartyCookies','TrackingPrevention',
                   'DoNotTrack','BackgroundModeEnabled','DefaultPopupsSetting','PreventSmartScreenPromptOverride',
                   'PreventSmartScreenPromptOverrideForFiles','BasicAuthOverHttpEnabled','TyposquattingCheckerEnabled',
                   'InternetExplorerIntegrationLevel')
        foreach ($n in $names) { Remove-ItemProperty -Path $edge -Name $n -Force -ErrorAction SilentlyContinue }
    }
    Write-Ok "Edge defaults restored."
}

# =============================================================================
#  NEW IN v5.2  -  RDP redirection hardening (when RDP must stay enabled)
# =============================================================================

function Disable-RDPRedirection {
    Write-Info "Hardening RDP - disabling clipboard / drive / printer / port redirection..."
    $ts = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    Set-WSERegistry -Path $ts -Name "fDisableClip"          -Value 1 -Type DWord | Out-Null   # clipboard
    Set-WSERegistry -Path $ts -Name "fDisableCdm"           -Value 1 -Type DWord | Out-Null   # drives
    Set-WSERegistry -Path $ts -Name "fDisableCpm"           -Value 1 -Type DWord | Out-Null   # printers
    Set-WSERegistry -Path $ts -Name "fDisableLPT"           -Value 1 -Type DWord | Out-Null   # parallel ports
    Set-WSERegistry -Path $ts -Name "fDisableCcm"           -Value 1 -Type DWord | Out-Null   # COM ports
    Set-WSERegistry -Path $ts -Name "fDisableAudioCapture"  -Value 1 -Type DWord | Out-Null   # mic capture
    Set-WSERegistry -Path $ts -Name "fDisableCameraRedir"   -Value 1 -Type DWord | Out-Null   # cameras
    Set-WSERegistry -Path $ts -Name "fDisableLocationRedir" -Value 1 -Type DWord | Out-Null   # location
    Set-WSERegistry -Path $ts -Name "fDisableWebAuthnRedirection" -Value 1 -Type DWord | Out-Null
    Set-WSERegistry -Path $ts -Name "fPromptForPassword"    -Value 1 -Type DWord | Out-Null
    Write-Ok "RDP redirection disabled - clipboard, drives, printers, ports, audio, cameras all blocked."
    Write-Warn "Existing RDP sessions need to reconnect for the changes to apply."
}

function Restore-RDPRedirection {
    Write-Info "Restoring RDP redirection defaults..."
    $ts = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    foreach ($n in @('fDisableClip','fDisableCdm','fDisableCpm','fDisableLPT','fDisableCcm','fDisableAudioCapture','fDisableCameraRedir','fDisableLocationRedir','fDisableWebAuthnRedirection','fPromptForPassword')) {
        if (Test-Path $ts) { Remove-ItemProperty -Path $ts -Name $n -Force -ErrorAction SilentlyContinue }
    }
    Write-Ok "RDP redirection defaults restored."
}

# =============================================================================
#  NEW IN v5.2  -  Block adding Microsoft accounts
# =============================================================================

function Disable-MicrosoftAccount {
    Write-Info "Preventing users from adding Microsoft accounts to the system..."
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "NoConnectedUser" -Value 3 -Type DWord | Out-Null
    Write-Ok "NoConnectedUser=3 - Microsoft accounts cannot be added or signed in to."
    Write-Warn "Users who already have a Microsoft-account-linked profile will keep working; only NEW accounts are blocked."
}

function Enable-MicrosoftAccount {
    Write-Info "Allowing Microsoft accounts on this system (default behaviour)..."
    Set-WSERegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "NoConnectedUser" -Value 0 -Type DWord | Out-Null
    Write-Ok "Microsoft accounts allowed."
}

# =============================================================================
#  NEW IN v5.2  -  Diagnostics  (read-only)
# =============================================================================

function Show-OpenListeningPorts {
    Write-Section "Listening TCP/UDP ports (process owner shown when available)"
    try {
        $tcp = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Sort-Object LocalPort -Unique
        if ($tcp) {
            Write-Host "  TCP:" -ForegroundColor Cyan
            Write-Host ("  {0,-6} {1,-22} {2,-22} {3}" -f 'Port','Local','Process','PID') -ForegroundColor DarkCyan
            foreach ($c in $tcp) {
                $p = $null
                try { $p = Get-Process -Id $c.OwningProcess -ErrorAction Stop } catch {}
                Write-Host ("  {0,-6} {1,-22} {2,-22} {3}" -f `
                    $c.LocalPort, $c.LocalAddress, $(if ($p){$p.ProcessName}else{'?'}), $c.OwningProcess) -ForegroundColor White
            }
        } else { Write-Warn "No listening TCP sockets found (Get-NetTCPConnection unavailable?)." }

        $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
            Sort-Object LocalPort -Unique
        if ($udp) {
            Write-Host ""
            Write-Host "  UDP:" -ForegroundColor Cyan
            Write-Host ("  {0,-6} {1,-22} {2,-22} {3}" -f 'Port','Local','Process','PID') -ForegroundColor DarkCyan
            foreach ($c in $udp) {
                $p = $null
                try { $p = Get-Process -Id $c.OwningProcess -ErrorAction Stop } catch {}
                Write-Host ("  {0,-6} {1,-22} {2,-22} {3}" -f `
                    $c.LocalPort, $c.LocalAddress, $(if ($p){$p.ProcessName}else{'?'}), $c.OwningProcess) -ForegroundColor White
            }
        }
        Write-Host ""
        Write-Ok "Review unexpected listeners - especially RDP (3389), SMB (445), RPC (135), and WinRM (5985-5986)."
    } catch {
        Write-Fail "Could not enumerate ports: $_"
    }
}

function Test-WSEPendingReboot {
    Write-Section "Pending-reboot diagnostic"
    $reasons = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons += 'Component-Based Servicing flag set' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons += 'Windows Update reboot required' }
    if (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue) { $reasons += 'Pending file rename operations' }
    try {
        $cn = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -Name 'ComputerName' -ErrorAction Stop
        $an = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -Name 'ComputerName' -ErrorAction Stop
        if ($cn.ComputerName -ne $an.ComputerName) { $reasons += 'Computer rename pending' }
    } catch {}
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\Pending') { $reasons += 'Windows Update services pending' }

    if ($reasons.Count -eq 0) {
        Write-Ok "No pending reboot detected. The system is in a clean state."
    } else {
        Write-Warn "Pending reboot detected. Reasons:"
        foreach ($r in $reasons) { Write-Host "    - $r" -ForegroundColor Yellow }
        Write-Warn "Some hardening changes (HVCI, LSA Protection, SMBv1, Memory Integrity) require a reboot to take effect."
    }
}

function Show-RecentLogonEvents {
    Write-Section "Recent logon events (Security log, last 20)"
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4624,4625)} -MaxEvents 20 -ErrorAction Stop
        if (-not $events) { Write-Warn "No 4624/4625 events found in the Security log."; return }
        Write-Host ("  {0,-19} {1,-6} {2,-30} {3}" -f 'When','EventID','Target Account','Logon Type') -ForegroundColor DarkCyan
        foreach ($e in $events) {
            $xml = [xml]$e.ToXml()
            $data = @{}
            foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
            $when = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
            $user = if ($data.TargetUserName) { "$($data.TargetDomainName)\$($data.TargetUserName)" } else { '?' }
            $type = if ($data.LogonType) { $data.LogonType } else { '?' }
            $color = if ($e.Id -eq 4625) { 'Red' } else { 'Green' }
            Write-Host ("  {0,-19} {1,-6} {2,-30} {3}" -f $when, $e.Id, $user, $type) -ForegroundColor $color
        }
        Write-Host ""
        Write-Ok "Green = successful logon (4624). Red = failed logon attempt (4625)."
    } catch {
        Write-Fail "Could not read Security log: $_"
        Write-Warn "Enable comprehensive audit policy (option 27) first, then come back."
    }
}

# =============================================================================
#  THREAT HUNT  -  IOC / persistence scanner + remediation
#
#  All checks are read-only.  They are heuristic - findings need a human review
#  before remediation.  The remediation helper applies fixes one at a time with
#  explicit confirmation, and only for items that have a registered fix.
#
#  Same code path on ARM64 and x64 - every check uses the registry, CIM, the
#  event log, or PowerShell cmdlets that work the same on every architecture.
# =============================================================================

$Script:WSELastThreatFindings = $null

function Add-WSEThreatFinding {
    param(
        [Parameter(Mandatory)] $List,
        [Parameter(Mandatory)] [ValidateSet('High','Medium','Low','Info')] [string] $Severity,
        [Parameter(Mandatory)] [string] $Category,
        [Parameter(Mandatory)] [string] $Finding,
        [string] $Path   = '',
        [string] $Value  = '',
        [string] $Action = '',
        [string] $FixName = 'Manual'
    )
    $List.Add([pscustomobject]@{
        Severity = $Severity
        Category = $Category
        Finding  = $Finding
        Path     = $Path
        Value    = $Value
        Action   = $Action
        FixName  = $FixName
    }) | Out-Null
}

function Invoke-WSEThreatScan {
    Write-Section "Threat hunt - heuristic indicator-of-compromise scan"
    Write-Info "Checking ~15 surfaces for persistence + tampering. Findings are heuristic - review before remediation."
    $caps = Get-WSECapabilities
    Write-Host ("  Architecture: {0}  CPU: {1}" -f $caps.ProcessorArch, $caps.CpuName) -ForegroundColor DarkGray
    Write-Host ""

    $findings = New-Object System.Collections.Generic.List[pscustomobject]

    # --- 1. AppInit_DLLs (legacy DLL injection) ----------------------------
    Write-Info "[1/15] AppInit_DLLs ..."
    foreach ($key in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
                       'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
        if (-not (Test-Path $key)) { continue }
        $val = (Get-ItemProperty $key -Name AppInit_DLLs -ErrorAction SilentlyContinue).AppInit_DLLs
        if ($val -and $val.ToString().Trim()) {
            Add-WSEThreatFinding $findings 'High' 'Persistence' 'AppInit_DLLs has a value (legacy injection vector)' $key $val 'Clear AppInit_DLLs + LoadAppInit_DLLs=0' 'Fix-AppInitDLLs'
        }
    }

    # --- 2. Image File Execution Options debugger hijacks ------------------
    Write-Info "[2/15] Image File Execution Options (debugger hijacks) ..."
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    if (Test-Path $ifeo) {
        Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
            $debugger = (Get-ItemProperty $_.PsPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
            if ($debugger) {
                $exeName = Split-Path $_.PSChildName -Leaf
                # Accessibility-tool hijack (sticky-keys / utilman) is a classic local-priv-esc trick
                $stickyKeys = @('sethc.exe','utilman.exe','osk.exe','magnify.exe','narrator.exe','displayswitch.exe','atbroker.exe')
                $sev = if ($exeName -in $stickyKeys) { 'High' } else { 'Medium' }
                Add-WSEThreatFinding $findings $sev 'Persistence' "IFEO debugger set for $exeName" $_.PsPath $debugger 'Remove the Debugger value' 'Fix-IFEO'
            }
        }
    }

    # --- 3. BootExecute non-default ----------------------------------------
    Write-Info "[3/15] BootExecute ..."
    $be = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name BootExecute -ErrorAction SilentlyContinue).BootExecute
    foreach ($line in @($be)) {
        if (-not $line) { continue }
        if ($line -notmatch '^autocheck\s' -and $line.Trim() -ne '') {
            Add-WSEThreatFinding $findings 'High' 'Persistence' 'Non-default BootExecute entry' 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' $line 'Review and remove via regedit' 'Manual'
        }
    }

    # --- 4. Run / RunOnce - obvious red flags ------------------------------
    Write-Info "[4/15] Run / RunOnce keys ..."
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($key in $runKeys) {
        if (-not (Test-Path $key)) { continue }
        $item = Get-Item $key
        foreach ($name in $item.GetValueNames()) {
            if (-not $name) { continue }
            $val = "$($item.GetValue($name))"
            if ($val -match '(?i)\\Temp\\|\\AppData\\Local\\Temp\\|\\Users\\Public\\') {
                Add-WSEThreatFinding $findings 'High' 'Persistence' "Run key '$name' points to a temp/public folder" $key $val 'Verify and delete the value' 'Manual'
            } elseif ($val -match '(?i)powershell.*-e(?:nc|ncodedcommand)?\b|powershell.*frombase64string') {
                Add-WSEThreatFinding $findings 'High' 'Persistence' "Run key '$name' executes base64-encoded PowerShell" $key $val 'Verify and delete the value' 'Manual'
            } elseif ($val -match '(?i)\bwscript\b|\bcscript\b|\bmshta\b|\brundll32.*javascript') {
                Add-WSEThreatFinding $findings 'Medium' 'Persistence' "Run key '$name' uses a script host" $key $val 'Verify and delete the value' 'Manual'
            }
        }
    }

    # --- 5. Scheduled tasks - suspicious actions ---------------------------
    Write-Info "[5/15] Scheduled tasks ..."
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop
        foreach ($t in $tasks) {
            foreach ($a in $t.Actions) {
                $exe = "$($a.Execute)"
                $args = "$($a.Arguments)"
                $cmd = "$exe $args".Trim()
                if (-not $cmd) { continue }
                if ($cmd -match '(?i)\\Temp\\|\\AppData\\Local\\Temp\\') {
                    Add-WSEThreatFinding $findings 'High' 'Persistence' "Task '$($t.TaskName)' runs from a temp folder" "$($t.TaskPath)$($t.TaskName)" $cmd 'Disable + investigate' 'Manual'
                } elseif ($cmd -match '(?i)-e(?:nc|ncodedcommand)?\b|frombase64string') {
                    Add-WSEThreatFinding $findings 'High' 'Persistence' "Task '$($t.TaskName)' runs base64-encoded PowerShell" "$($t.TaskPath)$($t.TaskName)" $cmd 'Disable + investigate' 'Manual'
                } elseif ($cmd -match '(?i)\bmshta\b\s+http|\bbitsadmin\b.*\bdownload|certutil.*-urlcache' ) {
                    Add-WSEThreatFinding $findings 'High' 'Persistence' "Task '$($t.TaskName)' uses LoLBin downloader" "$($t.TaskPath)$($t.TaskName)" $cmd 'Disable + investigate' 'Manual'
                }
            }
        }
    } catch { Write-Warn "  Scheduled-task enumeration failed: $_" }

    # --- 6. WMI permanent event subscriptions ------------------------------
    Write-Info "[6/15] WMI permanent event subscriptions ..."
    try {
        $consumers = @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction Stop)
        foreach ($c in $consumers) {
            $detail = ''
            foreach ($p in 'CommandLineTemplate','ScriptText','TargetPath','ExecutablePath') {
                if ($c.PSObject.Properties.Name -contains $p -and $c.$p) { $detail = $c.$p; break }
            }
            Add-WSEThreatFinding $findings 'High' 'Persistence' "WMI EventConsumer '$($c.Name)' (often used for stealth persistence)" 'root\subscription' $detail 'Verify and remove via Remove-CimInstance' 'Manual'
        }
    } catch {}

    # --- 7. LSA package whitelist ------------------------------------------
    Write-Info "[7/15] LSA Authentication / Security / Notification packages ..."
    $lsaExpected = @{
        'Authentication Packages' = @('msv1_0','kerberos','wdigest','tspkg','pku2u','cloudap','negoexts')
        'Security Packages'       = @('','kerberos','msv1_0','schannel','wdigest','tspkg','pku2u','cloudap','negoexts','livessp')
        'Notification Packages'   = @('','scecli','rassfm')
    }
    foreach ($n in $lsaExpected.Keys) {
        $val = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name $n -ErrorAction SilentlyContinue).$n
        if ($val) {
            foreach ($pkg in @($val)) {
                $clean = "$pkg".Trim().ToLower()
                if ($clean -and $clean -notin $lsaExpected[$n]) {
                    Add-WSEThreatFinding $findings 'High' 'Credentials' "Unexpected LSA $n entry: $pkg" 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' $pkg 'Review and remove from the multi-string value' 'Manual'
                }
            }
        }
    }

    # --- 8. Hosts file abuse ------------------------------------------------
    Write-Info "[8/15] Hosts file ..."
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (Test-Path $hostsPath) {
        $rawLines = @(Get-Content $hostsPath -ErrorAction SilentlyContinue)
        $entryLines = @($rawLines | Where-Object { $_ -and $_ -notmatch '^\s*#' -and $_.Trim() })
        if ($entryLines.Count -gt 50) {
            Add-WSEThreatFinding $findings 'Medium' 'Network' "Hosts file has $($entryLines.Count) entries (malware often blocks AV updates with huge hosts files)" $hostsPath "$($entryLines.Count) entries" 'Review or reset to default' 'Fix-HostsFile'
        }
        $blockedDomains = @('microsoft\.com','windowsupdate','update\.microsoft','defender\.microsoft','wustat\.windows','sls\.update\.microsoft')
        foreach ($line in $entryLines) {
            foreach ($d in $blockedDomains) {
                if ($line -match $d) {
                    Add-WSEThreatFinding $findings 'High' 'Network' "Hosts file blocks a Microsoft update / Defender domain" $hostsPath $line 'Reset hosts file' 'Fix-HostsFile'
                    break
                }
            }
        }
    }

    # --- 9. DNS servers not on a known-good list ---------------------------
    Write-Info "[9/15] DNS servers ..."
    $knownGood = @('1.1.1.1','1.0.0.1','8.8.8.8','8.8.4.4','9.9.9.9','149.112.112.112','208.67.222.222','208.67.220.220','94.140.14.14','94.140.15.15')
    try {
        $dns = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop
        foreach ($d in $dns) {
            if (-not $d.ServerAddresses) { continue }
            foreach ($srv in $d.ServerAddresses) {
                if (-not $srv) { continue }
                if ($srv -match '^(127\.|169\.254\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|fe80:)') { continue }
                if ($srv -notin $knownGood) {
                    Add-WSEThreatFinding $findings 'Low' 'Network' "Public DNS server on '$($d.InterfaceAlias)' is not in WSE's known-good list" "interface $($d.InterfaceIndex)" $srv 'Run option 42 to reset DNS' 'Manual'
                }
            }
        }
    } catch {}

    # --- 10. Defender exclusions and state ---------------------------------
    Write-Info "[10/15] Defender exclusions + real-time state ..."
    if ($caps.DefenderAvailable) {
        try {
            $pref = Get-MpPreference -ErrorAction Stop
            if ($pref.PSObject.Properties.Name -contains 'ExclusionPath' -and $pref.ExclusionPath) {
                $broadPaths = @('C:\','D:\','C:\Users','C:\Windows','C:\Program Files','C:\Program Files (x86)','%SystemDrive%','%USERPROFILE%')
                foreach ($p in $pref.ExclusionPath) {
                    if ($p -in $broadPaths) {
                        Add-WSEThreatFinding $findings 'High' 'Defender' "Overly broad Defender exclusion path" 'Defender Preferences' $p 'Remove-MpPreference -ExclusionPath' 'Manual'
                    }
                }
            }
            if ($pref.PSObject.Properties.Name -contains 'ExclusionProcess' -and $pref.ExclusionProcess) {
                foreach ($p in $pref.ExclusionProcess) {
                    if ($p -match '(?i)powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32') {
                        Add-WSEThreatFinding $findings 'Medium' 'Defender' "Defender excludes a script-host process: $p" 'Defender Preferences' $p 'Remove the exclusion' 'Manual'
                    }
                }
            }
        } catch {}
        try {
            $mp = Get-MpComputerStatus -ErrorAction Stop
            if ($mp.PSObject.Properties.Name -contains 'RealTimeProtectionEnabled' -and -not $mp.RealTimeProtectionEnabled) {
                Add-WSEThreatFinding $findings 'High' 'Defender' 'Defender real-time protection is OFF' 'Defender' 'RealTimeProtectionEnabled=False' 'Use option 20' 'Fix-DefenderRT'
            }
            if ($mp.PSObject.Properties.Name -contains 'AntivirusEnabled' -and -not $mp.AntivirusEnabled) {
                Add-WSEThreatFinding $findings 'High' 'Defender' 'Defender antivirus engine is DISABLED' 'Defender' 'AntivirusEnabled=False' 'Run option 20' 'Fix-DefenderRT'
            }
        } catch {}
    }

    # --- 11. Security event log enabled? -----------------------------------
    Write-Info "[11/15] Security event log ..."
    try {
        $sec = Get-WinEvent -ListLog Security -ErrorAction Stop
        if (-not $sec.IsEnabled) {
            Add-WSEThreatFinding $findings 'High' 'Logging' 'Security event log is DISABLED' 'Event Log' 'IsEnabled=False' 'wevtutil sl Security /e:true' 'Fix-EnableSecLog'
        }
        if ($sec.MaximumSizeInBytes -lt 50MB) {
            Add-WSEThreatFinding $findings 'Low' 'Logging' "Security event log is small ($([int]($sec.MaximumSizeInBytes/1MB)) MB)" 'Event Log' "$([int]($sec.MaximumSizeInBytes/1MB)) MB" 'Run option 27 to grow it to 1 GB' 'Manual'
        }
    } catch {}

    # --- 12. Remote-management software ------------------------------------
    Write-Info "[12/15] Remote-management / RMM software ..."
    $rmm = 'TeamViewer','AnyDesk','ScreenConnect','ConnectWiseControl','LogMeIn','RustDesk','Atera','Splashtop','GoToAssist','NinjaRMM','ConnectWise','Kaseya','SupRemo','Action1','Pulseway'
    foreach ($name in $rmm) {
        $svc = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match $name -or $_.Name -match $name }
        if ($svc) {
            Add-WSEThreatFinding $findings 'Info' 'RMM' "Remote-management tool detected: $name" 'Services' "$($svc.Name) - $($svc.Status)" 'Verify legitimacy - common tech-support-scam vector' 'Manual'
        }
    }

    # --- 13. Startup-folder scripts ----------------------------------------
    Write-Info "[13/15] Startup folder scripts ..."
    foreach ($p in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
                     "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")) {
        if (-not (Test-Path $p)) { continue }
        Get-ChildItem $p -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Extension -in '.ps1','.vbs','.js','.jse','.bat','.cmd','.hta','.wsf') {
                Add-WSEThreatFinding $findings 'Medium' 'Persistence' "Startup folder contains a script: $($_.Name)" $_.FullName '' 'Open and review' 'Manual'
            } elseif ($_.Extension -eq '.lnk') {
                $tgt = ''
                try {
                    $sh = New-Object -ComObject WScript.Shell
                    $tgt = ($sh.CreateShortcut($_.FullName)).TargetPath
                    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($sh) | Out-Null
                } catch {}
                if ($tgt -match '(?i)\\Temp\\|\\AppData\\Local\\Temp\\|\\Users\\Public\\') {
                    Add-WSEThreatFinding $findings 'High' 'Persistence' "Startup shortcut '$($_.Name)' targets a temp folder" $_.FullName $tgt 'Delete the shortcut' 'Manual'
                }
            }
        }
    }

    # --- 14. Winlogon Shell / Userinit -------------------------------------
    Write-Info "[14/15] Winlogon Shell / Userinit ..."
    $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $shell = (Get-ItemProperty $winlogon -Name Shell -ErrorAction SilentlyContinue).Shell
    if ($shell -and $shell.Trim().ToLower() -ne 'explorer.exe') {
        Add-WSEThreatFinding $findings 'High' 'Persistence' 'Winlogon Shell is not explorer.exe' $winlogon $shell 'Reset to explorer.exe' 'Fix-WinlogonShell'
    }
    $userinit = (Get-ItemProperty $winlogon -Name Userinit -ErrorAction SilentlyContinue).Userinit
    if ($userinit -and $userinit -notmatch '(?i)^C:\\Windows\\system32\\userinit\.exe,?\s*$') {
        Add-WSEThreatFinding $findings 'High' 'Persistence' 'Winlogon Userinit has an unexpected value' $winlogon $userinit 'Reset to default' 'Fix-WinlogonUserinit'
    }

    # --- 15. Volume Shadow Copy service (ransomware prep deletes these) ----
    Write-Info "[15/15] Volume Shadow Copy ..."
    $vss = Get-Service -Name VSS -ErrorAction SilentlyContinue
    if ($vss -and $vss.StartType -eq 'Disabled') {
        Add-WSEThreatFinding $findings 'Medium' 'Recovery' 'Volume Shadow Copy service is DISABLED (ransomware often disables this before encryption)' 'Service' "VSS StartType=$($vss.StartType)" 'Set-Service VSS -StartupType Manual' 'Fix-EnableVSS'
    }

    # ---- Render ------------------------------------------------------------
    Write-Host ""
    if ($findings.Count -eq 0) {
        Write-Ok "Scan complete - no heuristic indicators found."
        Write-Warn "Heuristic only - not a substitute for Sysmon, Autoruns, or an EDR."
    } else {
        Write-Host "  $($findings.Count) finding(s) - breakdown:" -ForegroundColor Yellow
        foreach ($g in ($findings | Group-Object Severity)) {
            $clr = switch ($g.Name) { 'High' {'Red'} 'Medium' {'Yellow'} 'Low' {'DarkYellow'} default {'Cyan'} }
            Write-Host "    {0,-7}  {1}" -ForegroundColor $clr -f $g.Name, $g.Count
        }
        Write-Host ""
        $sevOrder = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2; 'Info' = 3 }
        $sorted = $findings | Sort-Object @{Expression={$sevOrder[$_.Severity]}}, Category
        foreach ($f in $sorted) {
            $clr = switch ($f.Severity) { 'High' {'Red'} 'Medium' {'Yellow'} 'Low' {'DarkYellow'} default {'Cyan'} }
            Write-Host ("  [{0}]  {1} - {2}" -f $f.Severity, $f.Category, $f.Finding) -ForegroundColor $clr
            if ($f.Path)  { Write-Host ("           Path:  {0}" -f $f.Path)  -ForegroundColor DarkGray }
            if ($f.Value) { Write-Host ("           Value: {0}" -f $f.Value) -ForegroundColor DarkGray }
            if ($f.Action){ Write-Host ("           Fix:   {0}" -f $f.Action) -ForegroundColor DarkGray }
            if ($f.FixName -and $f.FixName -ne 'Manual') {
                Write-Host "           Auto-fix is available - run option 104." -ForegroundColor DarkGreen
            }
            Write-Host ""
        }
        $auto = @($findings | Where-Object { $_.FixName -and $_.FixName -ne 'Manual' }).Count
        Write-Host ("  $auto of $($findings.Count) finding(s) have an auto-fix. Run option 104 to apply them (each one is confirmed individually).") -ForegroundColor Cyan
    }
    $Script:WSELastThreatFindings = $findings
    return $findings
}

function Invoke-WSEThreatRemediation {
    if (-not $Script:WSELastThreatFindings -or $Script:WSELastThreatFindings.Count -eq 0) {
        Write-Warn "No scan results in memory. Run the threat scan (option 103) first."
        return
    }
    $autoFixable = @($Script:WSELastThreatFindings | Where-Object { $_.FixName -and $_.FixName -ne 'Manual' })
    if ($autoFixable.Count -eq 0) {
        Write-Warn "None of the current findings have an auto-fix. Review the scan output and remediate manually."
        return
    }
    Write-Section "Threat remediation"
    Write-Host "  $($autoFixable.Count) finding(s) have an auto-fix. Each one is confirmed individually." -ForegroundColor Cyan

    foreach ($f in $autoFixable) {
        Write-Host ""
        $clr = switch ($f.Severity) { 'High' {'Red'} 'Medium' {'Yellow'} 'Low' {'DarkYellow'} default {'Cyan'} }
        Write-Host ("  [{0}] {1} - {2}" -f $f.Severity, $f.Category, $f.Finding) -ForegroundColor $clr
        if ($f.Path)  { Write-Host ("        Path:  {0}" -f $f.Path)  -ForegroundColor DarkGray }
        if ($f.Value) { Write-Host ("        Value: {0}" -f $f.Value) -ForegroundColor DarkGray }
        $ans = Read-Host "  Apply the auto-fix? (y/N)"
        if ($ans -notmatch '^(y|yes)$') { Write-Warn "Skipped."; continue }

        try {
            switch ($f.FixName) {
                'Fix-AppInitDLLs' {
                    Set-WSERegistry -Path $f.Path -Name AppInit_DLLs      -Value '' -Type String | Out-Null
                    Set-WSERegistry -Path $f.Path -Name LoadAppInit_DLLs  -Value 0  -Type DWord  | Out-Null
                    Write-Ok "AppInit_DLLs cleared at $($f.Path)."
                }
                'Fix-IFEO' {
                    Remove-ItemProperty -Path $f.Path -Name 'Debugger' -Force -ErrorAction Stop
                    Write-Ok "IFEO Debugger removed from $($f.Path)."
                }
                'Fix-HostsFile' {
                    $hp = "$env:SystemRoot\System32\drivers\etc\hosts"
                    $backup = "$hp.wse_$($Script:WSESessionStamp).bak"
                    Copy-Item $hp $backup -Force -ErrorAction SilentlyContinue
                    @'
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# For more information, see "127.0.0.1 localhost".

# localhost name resolution is handled within DNS itself.
#  127.0.0.1       localhost
#  ::1             localhost
'@ | Set-Content -Path $hp -Encoding ASCII -Force -ErrorAction Stop
                    Write-Ok "Hosts file reset to default. Backup saved at $backup."
                }
                'Fix-DefenderRT' {
                    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
                    Write-Ok "Defender real-time protection re-enabled."
                }
                'Fix-EnableSecLog' {
                    & wevtutil sl Security /e:true 2>&1 | Out-Null
                    Write-Ok "Security event log enabled."
                }
                'Fix-WinlogonShell' {
                    Set-WSERegistry -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Shell -Value 'explorer.exe' -Type String | Out-Null
                    Write-Ok "Winlogon Shell reset to 'explorer.exe'."
                }
                'Fix-WinlogonUserinit' {
                    Set-WSERegistry -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Userinit -Value 'C:\Windows\system32\userinit.exe,' -Type String | Out-Null
                    Write-Ok "Winlogon Userinit reset to default."
                }
                'Fix-EnableVSS' {
                    Set-Service -Name VSS -StartupType Manual -ErrorAction Stop
                    Write-Ok "Volume Shadow Copy service set to Manual start."
                }
                default {
                    Write-Warn "No automated fix registered for $($f.FixName)."
                }
            }
        } catch {
            Write-Fail "Fix failed: $_"
        }
    }
    Write-Host ""
    Write-Ok "Remediation pass complete. Re-run option 103 to verify."
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
        if ($mp) {
            $rtOn = $false
            if ($mp.PSObject.Properties.Name -contains 'RealTimeProtectionEnabled') {
                $rtOn = [bool]$mp.RealTimeProtectionEnabled
            }
            Row "Defender RT" $(if ($rtOn){'Enabled'}else{'DISABLED'}) $rtOn

            if ($mp.PSObject.Properties.Name -contains 'IsTamperProtected') {
                $tp = [bool]$mp.IsTamperProtected
                Row "Defender Tamper" $(if ($tp){'Enabled'}else{'DISABLED'}) $tp
            } else {
                Write-Host "  Defender Tamper       : property unavailable on this build" -ForegroundColor DarkYellow
            }

            if ($mp.PSObject.Properties.Name -contains 'AntivirusSignatureLastUpdated') {
                Row "Defender Sigs" ([string]$mp.AntivirusSignatureLastUpdated) $true
            }
        }
    } else {
        Write-Host "  Defender              : cmdlets unavailable" -ForegroundColor Yellow
    }

    $rdp = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
    Row "RDP" $(if ($rdp -eq 1){'Disabled (secure)'}else{'Enabled'}) ($rdp -eq 1)

    $ra = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue).fAllowToGetHelp
    Row "Remote Assistance" $(if ($ra -eq 0){'Disabled (secure)'}else{'Enabled'}) ($ra -eq 0)

    $smb1 = $null; try { $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch {}
    if ($null -eq $smb1) {
        # SMB1 registry value: 0 = disabled, 1 (or missing) = legacy default. Treat "missing" as
        # the OS default which on modern Windows 10/11 is disabled - but we cannot be sure, so
        # we look at the LanmanServer\Parameters "SMB1" key only when it was explicitly set.
        $regProp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -ErrorAction SilentlyContinue
        if ($null -ne $regProp -and $null -ne $regProp.SMB1) {
            $smb1 = ($regProp.SMB1 -ne 0)
        } else {
            # Fall back to the optional feature status
            $feat = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
            $smb1 = ($feat -and $feat.State -eq 'Enabled')
        }
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
    # Set-UACAlwaysNotify supersedes Set-UACPasswordPrompt - calling both writes the same key twice
    Set-UACAlwaysNotify
    Set-AccountLockoutPolicy
    Set-StrongPasswordPolicy
    Disable-USBPorts
    Enable-WindowsFirewall
    Enable-FirewallLogging
    Disable-SMBv1
    Set-SMBSigningRequired
    Set-LDAPSigningRequired
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
#  QUICK WIN PRESET   -   the safest subset that almost never breaks anything
# =============================================================================

function Invoke-QuickWinHardening {
    Write-Host ""
    Write-Host "  *** Applying Quick Win preset (safe defaults) ***" -ForegroundColor Magenta
    Write-Host "    Skips: USB-storage block, IPv6 disable, outbound-block, AllSigned, BitLocker," -ForegroundColor DarkGray
    Write-Host "           hibernation off, Bluetooth off, IPv6-transition off." -ForegroundColor DarkGray
    Write-Host ""
    New-WSERestorePoint
    Set-UACAlwaysNotify
    Set-AccountLockoutPolicy
    Set-StrongPasswordPolicy
    Enable-WindowsFirewall
    Enable-FirewallLogging
    Disable-SMBv1
    Set-SMBSigningRequired
    Disable-RemoteDesktop
    Enable-WindowsDefender
    Set-DefenderSchedule
    Enable-ASRRules
    Disable-AutoRun
    Disable-GuestAccount
    Enable-AuditPolicy
    Disable-AnonymousAccess
    Enable-CredentialGuard
    Disable-Telemetry
    Disable-AdvertisingID
    Enable-SmartScreen
    Set-NTLMv2Only
    Disable-PowerShellv2
    Enable-ExploitProtection
    Disable-RemoteAssistance
    Disable-WinRM
    Set-SecureDNS
    Set-SChannelHardening
    Disable-WebClient
    Disable-WPAD
    Enable-AutomaticUpdates
    Set-ScreenLockTimeout
    Disable-OfficeMacros
    Set-PSExecutionRemoteSigned
    Write-Host ""
    Write-Host "  *** Quick Win preset applied. ***" -ForegroundColor Magenta
    Write-Host "  *** A restart is recommended. ***" -ForegroundColor Yellow
    Write-Host ""
}

# =============================================================================
#  HTML REPORT EXPORT
# =============================================================================

function Get-WSEStatusData {
    # Returns an ordered list of [Label, State, IsGood] tuples for both the CLI status
    # report and the HTML/GUI consumers. Encapsulates the registry lookups so neither
    # caller has to duplicate them.
    $c = Get-WSECapabilities
    $rows = New-Object System.Collections.Generic.List[pscustomobject]
    function Add-Row { param($Label,$State,$Good) $rows.Add([pscustomobject]@{Label=$Label;State=$State;Good=[bool]$Good}) | Out-Null }

    $uacVal = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
    $uacTxt = switch ($uacVal) { 0 { "Disabled - risk" } 1 { "Require credentials" } 2 { "Always Notify" } 5 { "Default" } default { "Unknown" } }
    Add-Row "UAC Level" $uacTxt ($uacVal -ge 1 -and $uacVal -le 2)

    $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    $fwOn = @($fw | Where-Object { $_.Enabled -eq $true }).Count
    Add-Row "Firewall" "$fwOn/3 profiles enabled" ($fwOn -eq 3)

    if ($c.DefenderAvailable) {
        $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($mp) {
            $rtOn = $false
            if ($mp.PSObject.Properties.Name -contains 'RealTimeProtectionEnabled') { $rtOn = [bool]$mp.RealTimeProtectionEnabled }
            Add-Row "Defender RT" $(if ($rtOn){'Enabled'}else{'DISABLED'}) $rtOn
            if ($mp.PSObject.Properties.Name -contains 'IsTamperProtected') {
                $tp = [bool]$mp.IsTamperProtected
                Add-Row "Defender Tamper" $(if ($tp){'Enabled'}else{'DISABLED'}) $tp
            }
        }
    }

    $rdp = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
    Add-Row "RDP" $(if ($rdp -eq 1){'Disabled'}else{'Enabled'}) ($rdp -eq 1)

    $smb1 = $null
    try { $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch {}
    if ($null -eq $smb1) {
        $regProp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -ErrorAction SilentlyContinue
        if ($null -ne $regProp -and $null -ne $regProp.SMB1) { $smb1 = ($regProp.SMB1 -ne 0) }
        else {
            $feat = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
            $smb1 = ($feat -and $feat.State -eq 'Enabled')
        }
    }
    Add-Row "SMBv1" $(if (-not $smb1){'Disabled'}else{'ENABLED'}) (-not $smb1)

    $smbSigC = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature
    Add-Row "SMB Signing (client)" $(if ($smbSigC -eq 1){'Required'}else{'Optional'}) ($smbSigC -eq 1)

    $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    Add-Row "Print Spooler" $(if ($spooler -and $spooler.StartType -eq 'Disabled'){'Disabled'}else{'Enabled'}) ($spooler -and $spooler.StartType -eq 'Disabled')

    $ntlm = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
    $ntlmTxt = switch ($ntlm) { 5 { "NTLMv2 only" } 3 { "NTLMv2 + NTLMv1" } default { "LM/NTLMv1 allowed" } }
    Add-Row "NTLM Level" $ntlmTxt ($ntlm -ge 5)

    $usbStart = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor" -Name "Start" -ErrorAction SilentlyContinue).Start
    Add-Row "USB Storage" $(if ($usbStart -eq 4){'Disabled'}else{'Enabled'}) ($usbStart -eq 4)

    $guestLine = & net user Guest 2>&1 | Select-String "Account active"
    $guestEnabled = "$guestLine" -match "Yes"
    Add-Row "Guest Account" $(if (-not $guestEnabled){'Disabled'}else{'ENABLED'}) (-not $guestEnabled)

    $ar = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
    Add-Row "AutoRun" $(if ($ar -eq 0xFF){'Fully disabled'}else{'Partial'}) ($ar -eq 0xFF)

    $wsh = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    Add-Row "Script Host" $(if ($wsh -eq 0){'Disabled'}else{'Enabled'}) ($wsh -eq 0)

    $llmnr = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast
    Add-Row "LLMNR" $(if ($llmnr -eq 0){'Disabled'}else{'Enabled'}) ($llmnr -eq 0)

    $mdns = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableMDNS" -ErrorAction SilentlyContinue).EnableMDNS
    Add-Row "mDNS" $(if ($mdns -eq 0){'Disabled'}else{'Enabled'}) ($mdns -eq 0)

    $wdigest = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue).UseLogonCredential
    Add-Row "WDigest (creds)" $(if ($wdigest -eq 0){'Disabled'}else{'ENABLED'}) ($wdigest -eq 0)

    $lsaPpl = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL
    Add-Row "LSA Protection" $(if ($lsaPpl -eq 1){'Enabled'}else{'Disabled'}) ($lsaPpl -eq 1)

    $telem = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue).AllowTelemetry
    Add-Row "Telemetry" $(if ($telem -eq 0){'Level 0 (Security)'}else{"Level $telem"}) ($telem -eq 0)

    $sehop = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -ErrorAction SilentlyContinue).DisableExceptionChainValidation
    Add-Row "SEHOP" $(if ($sehop -eq 0){'Enabled'}else{'Disabled'}) ($sehop -eq 0)

    $cortana = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -ErrorAction SilentlyContinue).AllowCortana
    Add-Row "Cortana" $(if ($cortana -eq 0){'Disabled'}else{'Enabled'}) ($cortana -eq 0)

    $asrIds = @()
    try { $asrIds = @((Get-MpPreference -ErrorAction Stop).AttackSurfaceReductionRules_Ids) } catch {}
    Add-Row "ASR Rules" "$($asrIds.Count) rule(s)" ($asrIds.Count -ge 14)

    $psPolicy = Get-ExecutionPolicy -Scope LocalMachine
    Add-Row "PS Exec Policy" "$psPolicy" ($psPolicy -in @('AllSigned','RemoteSigned','Restricted'))

    $tls10 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    Add-Row "TLS 1.0 (client)" $(if ($tls10 -eq 0){'Disabled'}else{'Enabled'}) ($tls10 -eq 0)

    $webdav = Get-Service -Name WebClient -ErrorAction SilentlyContinue
    Add-Row "WebClient (WebDAV)" $(if ($webdav -and $webdav.StartType -eq 'Disabled'){'Disabled'}elseif ($webdav){'Enabled'}else{'Not present'}) ($webdav -and $webdav.StartType -eq 'Disabled')

    $bl = $null; try { $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop } catch {}
    Add-Row "BitLocker (C:)" $(if ($bl -and $bl.ProtectionStatus -eq 'On'){'Enabled'}elseif ($bl){'Disabled'}else{'Unavailable'}) ($bl -and $bl.ProtectionStatus -eq 'On')

    return $rows
}

function Export-WSEHtmlReport {
    param([string] $Path)
    if (-not $Path) {
        $Path = Join-Path $Script:WSELogDir ("wse_report_{0}.html" -f $Script:WSESessionStamp)
    }
    # Load System.Web before any HtmlEncode call below - on full Windows PowerShell 5.1 the
    # assembly is typically already available but on PowerShell 7 it has to be loaded explicitly.
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    $c = Get-WSECapabilities
    $rows = Get-WSEStatusData
    $good = @($rows | Where-Object { $_.Good }).Count
    $total = $rows.Count
    $score = if ($total -gt 0) { [int](($good / $total) * 100) } else { 0 }
    $scoreColor = if ($score -ge 80) { '#3fbf60' } elseif ($score -ge 50) { '#e9c34d' } else { '#ef4747' }
    $generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')

    # Local fallback - if for some reason the System.Web type still isn't reachable
    # (PowerShell 7 on Server Core, for example), strip the few characters we care about
    # so the HTML is still well-formed.
    $encode = {
        param([string] $s)
        if ($null -eq $s) { return '' }
        try { return [System.Web.HttpUtility]::HtmlEncode($s) } catch {
            return ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' -replace "'",'&#39;')
        }
    }

    $rowsHtml = ($rows | ForEach-Object {
        $cls = if ($_.Good) { 'good' } else { 'bad' }
        $icon = if ($_.Good) { 'OK' } else { 'X' }
        "        <tr class=`"$cls`"><td class=`"icon`">$icon</td><td>$(& $encode $_.Label)</td><td>$(& $encode $_.State)</td></tr>"
    }) -join "`r`n"

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Windows Security Enhancer - Report</title>
<style>
  :root { color-scheme: dark light; }
  body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #1a1d24; color: #e6e9ef; margin: 0; padding: 0; }
  .wrap { max-width: 980px; margin: 0 auto; padding: 32px 24px; }
  header { display: flex; align-items: center; justify-content: space-between; gap: 24px; flex-wrap: wrap; padding-bottom: 24px; border-bottom: 1px solid #2c313c; }
  h1 { margin: 0; font-size: 28px; font-weight: 600; letter-spacing: 0.3px; }
  h1 span { color: #7c8b9f; font-weight: 400; font-size: 18px; margin-left: 8px; }
  .sub { color: #95a0b3; font-size: 13px; margin-top: 6px; }
  .score { background: linear-gradient(135deg, #232734 0%, #1a1d24 100%); border-radius: 16px; padding: 18px 26px; display: flex; align-items: center; gap: 18px; border: 1px solid #2c313c; }
  .score .num { font-size: 44px; font-weight: 700; color: $scoreColor; line-height: 1; }
  .score .label { color: #95a0b3; font-size: 12px; text-transform: uppercase; letter-spacing: 1.5px; }
  section { margin-top: 28px; }
  .panel { background: #232734; border: 1px solid #2c313c; border-radius: 12px; padding: 18px 22px; }
  .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px 22px; }
  .meta-grid div { font-size: 13px; color: #c4cad6; }
  .meta-grid b { color: #95a0b3; font-weight: 500; }
  table { width: 100%; border-collapse: collapse; margin-top: 12px; }
  th, td { padding: 10px 12px; text-align: left; }
  th { font-size: 11px; text-transform: uppercase; letter-spacing: 1.1px; color: #95a0b3; border-bottom: 1px solid #2c313c; }
  tr.good td { color: #cfe9d6; }
  tr.bad  td { color: #f4c4c4; }
  td.icon { font-weight: 700; width: 32px; text-align: center; border-radius: 6px; }
  tr.good td.icon { background: rgba(63, 191, 96, 0.16); color: #3fbf60; }
  tr.bad  td.icon { background: rgba(239, 71, 71, 0.16); color: #ef4747; }
  tbody tr + tr td { border-top: 1px solid #2c313c; }
  footer { margin-top: 36px; padding-top: 18px; border-top: 1px solid #2c313c; color: #7c8b9f; font-size: 12px; }
  code { background: #2c313c; padding: 2px 6px; border-radius: 4px; font-size: 12px; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>Windows Security Enhancer <span>v$($Script:WSEVersion)</span></h1>
      <div class="sub">$(& $encode $c.OSName) - build $(& $encode $c.OSBuild) - $(& $encode $env:COMPUTERNAME)</div>
      <div class="sub">Generated $generated</div>
    </div>
    <div class="score">
      <div><div class="num">$score%</div><div class="label">Hardening score</div></div>
      <div><div style="font-size: 22px; font-weight: 600;">$good / $total</div><div class="label">Controls passing</div></div>
    </div>
  </header>
  <section>
    <div class="panel">
      <div class="meta-grid">
        <div><b>Edition</b><br>$(& $encode ([string]$c.Edition))</div>
        <div><b>PowerShell</b><br>$(& $encode ([string]$c.PSVersion))</div>
        <div><b>TPM</b><br>Present: $($c.TpmPresent) - Ready: $($c.TpmReady)</div>
        <div><b>Defender</b><br>Cmdlets: $($c.DefenderAvailable)</div>
        <div><b>BitLocker</b><br>Cmdlets: $($c.BitLockerAvailable)</div>
        <div><b>Process Mitigation</b><br>$($c.ProcessMitigationAvailable)</div>
      </div>
    </div>
  </section>
  <section>
    <div class="panel">
      <table>
        <thead><tr><th></th><th>Control</th><th>State</th></tr></thead>
        <tbody>
$rowsHtml
        </tbody>
      </table>
    </div>
  </section>
  <footer>
    Backup directory: <code>$(& $encode $Script:WSESessionBackup)</code><br>
    Transcript: <code>$(& $encode $Script:WSETranscript)</code><br>
    Report file: <code>$(& $encode $Path)</code>
  </footer>
</div>
</body>
</html>
"@
    try {
        $html | Set-Content -Path $Path -Encoding UTF8 -Force
        Write-Ok "HTML report written: $Path"
        return $Path
    } catch {
        Write-Fail "Could not write report: $_"
        return $null
    }
}

# =============================================================================
#  NEW IN v5.2  -  Feature explanations  ("what does this do, why does it help?")
# =============================================================================
#
#  Each entry maps an engine function name to a four-field record:
#    Title  - short human-readable name
#    What   - technical description of the change
#    Why    - the threat / class of attack this mitigates
#    Risk   - compatibility / trade-off notes
#
#  Consumed by the CLI 'Explain' option, the GUI info popup, and (optionally)
#  the HTML report tooltips.
# =============================================================================

$Script:FeatureExplanations = @{

    # ---- UAC & Authentication ----
    'Set-UACPasswordPrompt' = @{
        Title='UAC: require credential prompt'
        What ='Sets ConsentPromptBehaviorAdmin=1, EnableLUA=1, PromptOnSecureDesktop=1. UAC will require the admin user to type their password (not just click Yes) on the secure desktop before allowing elevation.'
        Why  ='Default UAC lets an admin elevate by clicking "Yes" - so a single phishing click can grant malware full admin rights. Requiring credentials forces the user to actively type a password, making drive-by elevation attacks much harder. The secure desktop further protects the prompt from being spoofed.'
        Risk ='Every elevation now needs a password. Slightly more friction when installing apps; no impact on already-elevated processes.'
    }
    'Set-UACAlwaysNotify' = @{
        Title='UAC: Always Notify (maximum)'
        What ='Sets ConsentPromptBehaviorAdmin=2 - UAC prompts on the secure desktop for every elevation, including changes Windows itself initiates.'
        Why  ='This is the strictest UAC level. It catches scenarios where built-in Windows tools (e.g., scheduled tasks, COM elevation) silently elevate, giving the user visibility into every change.'
        Risk ='Very prompt-heavy during initial setup or large software installs. Once the system is stable it almost never prompts.'
    }
    'Restore-UACToNormal' = @{
        Title='UAC: restore Windows default'
        What ='Sets ConsentPromptBehaviorAdmin=5 - the Windows default ("notify me only when apps try to make changes").'
        Why  ='Reverses any custom UAC tightening done by this tool. Use if you find the hardened prompts impractical.'
        Risk ='You lose the credential-prompt protection. Acceptable on personal machines where admin convenience matters more than malware-vs-UAC defence.'
    }
    'Set-AccountLockoutPolicy' = @{
        Title='Account lockout policy'
        What ='5 failed sign-in attempts trigger a 30-minute lockout (with a 30-minute observation window). Configured via "net accounts".'
        Why  ='Without lockout, an attacker can brute-force passwords against the local Administrator or any other account at full network speed. Lockout caps an attacker to roughly 10 attempts per hour - making most online password guessing impractical.'
        Risk ='A forgetful user (or a fat-fingered admin) can lock themselves out for 30 minutes. Service accounts may need exemption.'
    }
    'Disable-AccountLockoutPolicy' = @{
        Title='Restore account lockout to default'
        What ='Removes the lockout threshold (net accounts /lockoutthreshold:0).'
        Why  ='Restores Windows pre-policy behaviour. Use only if a critical workflow keeps locking users out.'
        Risk ='Brute-force attacks against passwords become possible again.'
    }
    'Set-StrongPasswordPolicy' = @{
        Title='Strong password policy'
        What ='Minimum 14-character passwords, complexity required, 90-day max age, 1-day min age, history of 10 previous passwords stored.'
        Why  ='14 characters with complexity defeats almost all rainbow-table and brute-force attacks. Min-age stops users from cycling through the history to get back to a known password. History prevents reuse.'
        Risk ='Users must remember longer passwords - encourage a password manager. NIST guidance now favours length over rotation; the 90-day rotation here is a defence-in-depth compromise.'
    }
    'Rename-AdminAccount' = @{
        Title='Rename built-in Administrator'
        What ='Renames the RID-500 local Administrator account to something non-obvious. The SID stays the same.'
        Why  ='Many credential-guessing tools target the account literally named "Administrator". Renaming forces an attacker to also discover the new name before they can start guessing passwords, slowing them down measurably.'
        Risk ='Some legacy scripts hard-code "Administrator". Document the new name somewhere safe (a password manager is fine).'
    }

    # ---- Firewall & Network ----
    'Enable-WindowsFirewall' = @{
        Title='Enable Windows Firewall + block hostile ports'
        What ='Turns the firewall on for Domain, Private and Public profiles, sets the default inbound action to Block, and adds explicit Block rules on the Public profile for Telnet (23), RPC (135), NetBIOS (137-139), SMB (445), MSSQL (1433-1434), RDP (3389), and WinRM (5985-5986).'
        Why  ='Untrusted networks (coffee shops, hotels, conferences) are full of hostile peers running automated scanners. Blocking these high-value ports on Public is one of the cheapest, most effective hardening steps - it neutralises whole families of remote attacks (EternalBlue, BlueKeep, ...) before they can even reach the service.'
        Risk ='Negligible. If you legitimately need RDP or SMB from another network, you can either join that network as Private or add a more specific Allow rule.'
    }
    'Disable-WindowsFirewall' = @{
        Title='Disable Windows Firewall (NOT recommended)'
        What ='Turns the firewall OFF for all three profiles.'
        Why  ='Sometimes needed for debugging or specific lab setups. Never recommended for a production system.'
        Risk ='Removes a critical defence-in-depth layer. Even endpoints behind a perimeter firewall benefit from a host firewall: it stops lateral movement and rogue-peer attacks.'
    }
    'Enable-FirewallLogging' = @{
        Title='Enable Firewall logging'
        What ='Enables logging of both allowed and dropped packets on all three profiles. 32 MB log file at C:\Windows\System32\LogFiles\Firewall\pfirewall.log.'
        Why  ='Without logs you have no idea what was blocked, what hit you, or whether a rule is too permissive. Logs feed incident response and ASR-rule validation.'
        Risk ='Disk writes are small (logs rotate). Logs may contain IPs of legitimate connections, so treat them as moderately sensitive.'
    }
    'Set-FirewallBlockOutbound' = @{
        Title='Block all outbound by default (advanced)'
        What ='Sets the default outbound action on all profiles to Block. Only explicit Allow rules will let traffic out.'
        Why  ='Most malware needs to phone home. Block-by-default outbound stops command-and-control, data exfiltration, and beaconing from any process you have not already authorised.'
        Risk ='Will break most applications until you add explicit Allow rules. Only practical on air-gapped, kiosk, or single-purpose systems where you can enumerate every legitimate outbound flow.'
    }
    'Restore-FirewallDefaultOutbound' = @{
        Title='Restore default outbound (Allow)'
        What ='Sets the outbound default back to Allow on all profiles.'
        Why  ='Reverses the Block-Outbound mode.'
        Risk ='You lose the egress-protection benefit - normal Windows default.'
    }
    'Disable-SMBv1' = @{
        Title='Disable SMBv1'
        What ='Disables the SMBv1 protocol on both the server and the client (Set-SmbServerConfiguration + registry + mrxsmb10 driver Start=4 + optional-feature removal).'
        Why  ='SMBv1 is the protocol exploited by WannaCry, NotPetya, and the entire EternalBlue family. It has no cryptographic protection of authentication, supports trivial downgrade attacks, and Microsoft has been telling people to remove it since 2014.'
        Risk ='Breaks file sharing with very old NAS appliances, Windows XP/Server 2003, and some pre-2010 networked printers.'
    }
    'Enable-SMBv1' = @{
        Title='Enable SMBv1 (NOT recommended)'
        What ='Turns SMBv1 back on. Requires typed confirmation.'
        Why  ='Sometimes needed to talk to a pre-Vista appliance you cannot retire.'
        Risk ='Opens the WannaCry/EternalBlue/NotPetya attack surface. Only do this on an isolated network segment.'
    }
    'Disable-RemoteDesktop' = @{
        Title='Disable RDP'
        What ='Sets fDenyTSConnections=1 and disables the firewall rule group "Remote Desktop".'
        Why  ='Internet-facing RDP is the single most common ransomware entry point. If you do not actively use RDP, leave it off.'
        Risk ='You cannot connect remotely via RDP. Use a VPN + bastion + jump-host model when remote access is required.'
    }
    'Enable-RemoteDesktop' = @{
        Title='Enable RDP (NLA + High encryption)'
        What ='Enables RDP with Network Level Authentication required (UserAuthentication=1), High (FIPS-compatible) encryption (MinEncryptionLevel=3) and TLS security layer (SecurityLayer=2).'
        Why  ='NLA forces the client to authenticate BEFORE a session is created, eliminating the pre-auth attack surface that BlueKeep abused. High encryption + TLS prevents passive sniffing and downgrade attacks.'
        Risk ='Very old RDP clients (Windows XP, 2003) cannot connect. Combine with a VPN for any internet exposure.'
    }
    'Disable-AnonymousAccess' = @{
        Title='Disable anonymous, LLMNR, NBT-NS, mDNS'
        What ='Restricts anonymous SAM enumeration (RestrictAnonymous=2/SAM=1), turns off LLMNR (EnableMulticast=0), disables NetBIOS over TCP/IP on every adapter, and disables mDNS (EnableMDNS=0).'
        Why  ='LLMNR/NBT-NS/mDNS are name-resolution protocols that broadcast queries on the local network. An attacker on the same network can answer those broadcasts and trick Windows into authenticating to them with NTLM hashes - the foundation of Responder.py and ntlmrelayx attacks. Killing them off the LAN is the single most effective LAN-pentest defence.'
        Risk ='Some single-label hostnames (no DNS suffix) stop resolving. AirPrint, Bonjour and some IoT devices on the local network may not be discoverable.'
    }

    # ---- Devices & Storage ----
    'Disable-USBPorts' = @{
        Title='Disable USB storage'
        What ='Sets the UsbStor and cdrom drivers to Start=4 (disabled), and enforces a RemovableStorageDevices Deny_All policy. HID devices, USB-Ethernet, audio, etc are unaffected.'
        Why  ='Removable media is a classic infection vector: BadUSB, rubber-ducky payloads, infected USB sticks dropped in parking lots. Blocking the storage class neutralises drive-letter-based attacks while keeping keyboards and mice working.'
        Risk ='You cannot use USB flash drives or external HDDs. Use option 15 to re-enable temporarily.'
    }
    'Enable-USBPorts' = @{
        Title='Enable USB storage'
        What ='Re-enables UsbStor (Start=3) and cdrom (Start=1) and clears the Deny_All policy.'
        Why  ='You need USB sticks again.'
        Risk ='Returns to the default attack surface.'
    }
    'Disable-Cameras' = @{
        Title='Disable cameras'
        What ='Disables every PnP device of class Camera/Image and sets the per-user CapabilityAccessManager webcam ConsentStore value to "Deny".'
        Why  ='Webcam access is a common spyware capability. Hardware-disabling at the driver level beats relying on app permissions.'
        Risk ='Video calls (Teams, Zoom) will not work until cameras are re-enabled.'
    }
    'Enable-Cameras' = @{
        Title='Enable cameras'
        What ='Re-enables disabled camera devices.'
        Why  ='Restores video-conferencing.'
        Risk ='None beyond normal webcam exposure.'
    }
    'Disable-AutoRun' = @{
        Title='Disable AutoRun / AutoPlay'
        What ='Sets NoDriveTypeAutoRun=0xFF (every drive type), NoAutorun=1, and pins Autorun.inf to "@SYS:DoesNotExist" via IniFileMapping. AutoplayHandlers DisableAutoplay=1 in HKCU.'
        Why  ='Conficker, Stuxnet, and a long tail of USB-borne worms relied on Windows auto-executing autorun.inf or shortcut payloads when a drive is inserted. Killing AutoRun closes that vector entirely.'
        Risk ='AutoPlay prompts no longer appear for inserted media. Manual file-explorer access still works.'
    }
    'Enable-AutoRun' = @{
        Title='Enable AutoRun / AutoPlay'
        What ='Restores the Windows defaults for AutoRun and AutoPlay.'
        Why  ='Restore convenience.'
        Risk ='Returns to the default attack surface.'
    }
    'Disable-Bluetooth' = @{
        Title='Disable Bluetooth'
        What ='Stops the bthserv (Bluetooth Support) service, sets it to Disabled, and disables every Bluetooth-class PnP device.'
        Why  ='Bluetooth has a long history of pre-auth driver bugs (BlueBorne, BleedingTooth, KNOB) that allow remote code execution from a nearby attacker. If you do not use Bluetooth, disabling it removes that entire attack surface.'
        Risk ='Bluetooth peripherals (keyboards, mice, headsets, AirPods) stop working until re-enabled.'
    }
    'Enable-Bluetooth' = @{
        Title='Enable Bluetooth'
        What ='Re-enables bthserv and Bluetooth devices.'
        Why  ='Restore Bluetooth functionality.'
        Risk ='Returns to the default attack surface.'
    }
    'Disable-Hibernation' = @{
        Title='Disable hibernation (purge hiberfil.sys)'
        What ='Runs powercfg /h off, which disables hibernation and deletes the C:\hiberfil.sys file.'
        Why  ='hiberfil.sys is an unencrypted (on non-BitLocker systems) snapshot of RAM at sleep time. If a laptop is stolen, hiberfil contains all credentials, browser sessions and encryption keys that were in memory. Disabling hibernation removes that exposure entirely.'
        Risk ='Also removes Fast Startup. Boot becomes slightly slower; laptops with broken Modern Standby will drain the battery faster.'
    }
    'Enable-BitLockerSystem' = @{
        Title='Enable BitLocker on C:'
        What ='Encrypts the system drive with XTS-AES 256. Uses the TPM if present and ready, otherwise prompts for a 6+ digit numeric PIN (TPM+PIN protector). Adds a recovery-password protector and saves the key to the Desktop.'
        Why  ='Without full-disk encryption, a stolen laptop is one boot-from-USB away from leaking every file. BitLocker with XTS-AES 256 + TPM is the gold standard for at-rest protection on Windows.'
        Risk ='Lose the recovery key and your data is gone. Copy the key to a safe offline location, then delete the file from the Desktop.'
    }

    # ---- Defender / ASR / SmartScreen ----
    'Enable-WindowsDefender' = @{
        Title='Configure Defender (maximum protection)'
        What ='Turns on every Defender knob: real-time protection, cloud-based protection (MAPS Advanced), Block-At-First-Sight, PUA Protection, Network Protection, Controlled Folder Access, script/archive/removable/IOAV/behaviour scanning, automatic safe-sample submission. Plus policy-level enforcement so the UI cannot silently turn them off.'
        Why  ='Defender defaults are already strong; this maxes out the cloud and exploit-class detection knobs. Controlled Folder Access in particular is one of the cheapest anti-ransomware controls available - it blocks unknown processes from modifying user document folders.'
        Risk ='CFA can block legitimate apps (some backup tools, archivers). Add specific apps to the CFA allowlist if needed.'
    }
    'Set-DefenderSchedule' = @{
        Title='Schedule Defender daily scan + signature updates'
        What ='Signature update every 4 hours, quick scan every day at 02:00, full remediation scheduled daily.'
        Why  ='Hourly signature updates close the window between a new threat being published by Microsoft and your endpoint protecting against it. A daily quick scan catches files that landed before the signatures.'
        Risk ='Tiny CPU usage during the 02:00 scan window. If your machine is off at 02:00, the scan runs at next idle.'
    }
    'Show-DefenderTamperStatus' = @{
        Title='Defender Tamper-Protection status'
        What ='Read-only check of Get-MpComputerStatus.IsTamperProtected.'
        Why  ='Tamper Protection prevents malicious processes (and admins) from silently disabling Defender. Verifying it is ON is essential before relying on the rest of the Defender hardening.'
        Risk ='None - this is read-only. If it shows OFF, toggle it in Windows Security UI - it cannot be set programmatically.'
    }
    'Enable-ASRRules' = @{
        Title='Enable 16 ASR rules (Block mode)'
        What ='Adds 16 Attack-Surface-Reduction rules in Block mode: block executable content from email, block Office child processes, block Office macros from injecting code, block JS/VBScript from launching downloads, block obfuscated scripts, block LSASS credential theft, block PSExec/WMI lateral movement, block USB-loaded unsigned processes, block exploited vulnerable signed drivers, block webshell creation on servers, and more.'
        Why  ='ASR rules are pre-deployed behaviour-based detections that cover the techniques most commonly used by ransomware, info-stealers, and post-exploitation frameworks (Cobalt Strike, Sliver, etc). Block-mode ASR has stopped real-world attacks at the kernel layer.'
        Risk ='Some legitimate workflows trip rules (e.g., admin scripts that look like obfuscated PowerShell). Check Event Log "Microsoft-Windows-Windows Defender/Operational" for blocks and add exclusions as needed.'
    }
    'Disable-ASRRules' = @{
        Title='Disable ASR rules'
        What ='Sets every configured ASR rule action to 0 (Disabled).'
        Why  ='Use only when an ASR rule is causing demonstrable production breakage you cannot work around.'
        Risk ='Reopens the post-exploitation kill-chain detection holes that ASR closes.'
    }
    'Enable-SmartScreen' = @{
        Title='Enable SmartScreen everywhere'
        What ='Configures SmartScreen in Block mode for Explorer, Edge (with PUA enabled), Store apps, and the legacy Edge filter. Sets PreventOverride so users cannot click past warnings.'
        Why  ='SmartScreen blocks known-bad downloads, phishing pages and PUA installers. Forcing PreventOverride stops users from clicking through a malware warning - a common social-engineering bypass.'
        Risk ='Brand-new legitimate downloads occasionally trip reputation-based blocking. Users have no override - they have to bring the file from a trusted source.'
    }
    'Disable-QuickAssist' = @{
        Title='Disable Quick Assist'
        What ='Removes the MicrosoftCorporationII.QuickAssist Appx package and the App.Support.QuickAssist DISM capability.'
        Why  ='Quick Assist is the most-abused remote-help tool in 2024-2026 tech-support scams ("Microsoft is calling - give me the 6-digit code"). Removing it forecloses the social-engineering vector entirely.'
        Risk ='If a legitimate help-desk uses Quick Assist, they will have to switch to a different remote-help tool.'
    }

    # ---- Accounts / Scripts / Services ----
    'Disable-GuestAccount' = @{
        Title='Disable Guest account'
        What ='Disables the built-in Guest account (SID ending in -501) via Disable-LocalUser.'
        Why  ='The Guest account, when enabled, allows network connections without a password. Many lateral-movement techniques and SMB-relay attacks rely on Guest being enabled.'
        Risk ='None - Guest is disabled by default on modern Windows. This option exists to be safe.'
    }
    'Disable-WindowsScriptHost' = @{
        Title='Disable Windows Script Host'
        What ='Sets HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings\Enabled=0. Blocks .vbs/.js/.wsf execution by wscript/cscript.'
        Why  ='Windows Script Host is the runtime that runs malicious .vbs and .js email attachments. Disabling it blocks an entire class of script-based malware without affecting browsers or Office.'
        Risk ='Some legitimate logon scripts and a handful of installers use WSH. If you administer such an environment, leave this off.'
    }
    'Disable-UnnecessaryServices' = @{
        Title='Disable unnecessary services'
        What ='Disables a curated list of risky services that are rarely needed on workstations: Remote Registry, Telnet, SSDP/UPnP, Internet Connection Sharing, Link-Layer Topology Discovery, iSCSI, Web Management Service, WebClient, Computer Browser, Fax, Windows Error Reporting, Xbox, Retail Demo, Downloaded Maps Manager.'
        Why  ='Every running service is attack surface. Many of these (Remote Registry, WebClient, UPnP) have been used in real-world exploitation chains. Turning them off when you do not need them is pure win.'
        Risk ='If you DO use one of these (e.g., printer sharing relies on Browser on legacy networks), restore it with option 26 or the Services console.'
    }
    'Enable-AuditPolicy' = @{
        Title='Comprehensive security audit policy'
        What ='Enables success+failure auditing for every category, turns on PowerShell script-block / module / transcription logging, enables process-creation cmdline auditing (Event ID 4688), and sets the Security event log to 1 GB.'
        Why  ='No visibility = no detection. With these auditing settings on, you record the evidence needed to investigate a compromise: what processes ran, what commands they invoked, which accounts authenticated, which privileges were used.'
        Risk ='1 GB Security log uses disk. Process-creation cmdline auditing can also expose secrets if a sysadmin pastes a password into a command line - manage accordingly.'
    }
    'Disable-PrintSpooler' = @{
        Title='Disable Print Spooler (PrintNightmare)'
        What ='Stops the Spooler service, sets it to Disabled, blocks the remote RPC endpoint, and restricts driver installation to administrators.'
        Why  ='The PrintNightmare family (CVE-2021-34527 and friends) lets a remote user become SYSTEM through the Print Spooler. The vulnerable code surface is huge and Microsoft has shipped multiple incomplete patches. If you do not need to print FROM this machine, disable the Spooler.'
        Risk ='You cannot print, locally or over the network. Re-enable with option 34 before printing.'
    }
    'Set-NTLMv2Only' = @{
        Title='Force NTLMv2 only (disable LM/NTLMv1)'
        What ='LmCompatibilityLevel=5 (refuse LM and NTLMv1), NoLMHash=1 (do not store LM hashes), NTLMMinClientSec/MinServerSec=0x20080000 (128-bit session security required), audit-only RestrictReceivingNTLMTraffic=0.'
        Why  ='LM and NTLMv1 are trivially crackable by modern hardware. NTLMv2 with 128-bit session security raises the bar. NoLMHash prevents the storage of LM hashes in SAM - a classic offline cracking target after disk-image theft.'
        Risk ='Very old clients (NT4, Win95 with patches) cannot authenticate. Audit-only restrict-receiving lets you discover lingering NTLMv1 traffic before flipping to deny.'
    }
    'Disable-PowerShellv2' = @{
        Title='Disable PowerShell v2'
        What ='Removes the MicrosoftWindowsPowerShellV2Root Windows optional feature.'
        Why  ='PowerShell v2 is the "downgrade target" used by attackers to bypass script-block logging and AMSI. If v2 is installed, malicious payloads can opt into the older, untraced engine. Removing v2 forces everything through v5+, where script-block logging captures every command.'
        Risk ='Anything that explicitly depends on PowerShell v2 (very rare) breaks. v5.1 stays installed.'
    }
    'Enable-ExploitProtection' = @{
        Title='Exploit Protection (DEP/SEHOP/ASLR/CFG)'
        What ='Enables DEP (NX) AlwaysOn via bcdedit, enables SEHOP, system-wide Force-Relocate-Images (forced ASLR), Bottom-up ASLR, High-Entropy ASLR, Control Flow Guard, Heap-Terminate-on-Corruption, per-process DEP.'
        Why  ='These are the exploit-mitigation mechanisms that make memory-corruption bugs significantly harder to weaponise. Forced ASLR + High Entropy in particular defeats most pre-2015 exploit techniques and complicates modern ones.'
        Risk ='Tiny perf hit. Some legacy 32-bit binaries that lack /DYNAMICBASE may refuse to start under Force-Relocate-Images - rare, and these are usually old games or out-of-support apps.'
    }
    'Disable-OfficeMacros' = @{
        Title='Disable Office macros (+ block MOTW macros)'
        What ='Sets VBAWarnings=4 (disable all macros, no notification) for Word, Excel, PowerPoint, Access, Outlook, Publisher and Visio across Office 2007-365. Also sets BlockContentExecutionFromInternet=1 - macros in files marked-of-the-web (MOTW) cannot run at all.'
        Why  ='Macro-enabled Office documents are still the #1 initial-access vector for ransomware and info-stealers. Disabling macros system-wide closes that door; blocking MOTW macros adds defence-in-depth against social-engineering ("the file says Enable Editing").'
        Risk ='Legitimate macro-enabled spreadsheets / templates stop working. If you genuinely need macros, sign them and trust the publisher instead.'
    }

    # ---- Credentials / LSA ----
    'Enable-CredentialGuard' = @{
        Title='Enable LSA Protection / Credential Guard'
        What ='RunAsPPL=1 (LSA runs as Protected Process Light), WDigest UseLogonCredential=0 (no plain-text creds in memory), Credential-Guard VBS / HVCI policy keys.'
        Why  ='LSA is the process that holds Windows authentication secrets (NTLM hashes, Kerberos tickets, cached domain creds). Without protection, any admin-level malware can dump LSA memory with Mimikatz. RunAsPPL forces attackers to disable PPL first (which is loud and signed-driver-required); Credential Guard moves the secrets out of LSA entirely into a hypervisor-isolated container.'
        Risk ='Some single-sign-on systems and old credential-helpers break. Test in your environment before deploying broadly.'
    }
    'Enable-MemoryIntegrity' = @{
        Title='Memory Integrity / Core Isolation (VBS + HVCI)'
        What ='Enables Virtualization Based Security and Hypervisor-protected Code Integrity. Kernel code must be signed AND validated by the hypervisor before it can execute.'
        Why  ='HVCI defeats classic kernel-mode rootkits and BYOVD (Bring-Your-Own-Vulnerable-Driver) attacks. The hypervisor enforces W^X for kernel pages and prevents in-memory tampering of code pages.'
        Risk ='Requires CPU virtualisation + UEFI Secure Boot. Some older third-party drivers (audio, antivirus, VPN) without HVCI-compliant code refuse to load.'
    }

    # ---- Privacy ----
    'Disable-Telemetry' = @{
        Title='Disable Windows Telemetry'
        What ='Stops + disables DiagTrack, dmwappushservice, DiagnosticsHub and PCA services. Sets AllowTelemetry=0 (Security) at policy level. Disables CEIP, AIT, Inventory, UAR, Windows Error Reporting, Activity History, Timeline and Clipboard sync.'
        Why  ='Reduces the amount of data Windows transmits to Microsoft to the absolute minimum (Security level). Useful in privacy-sensitive environments and reduces background network traffic.'
        Risk ='Some Microsoft support features (problem reports, store hints) become less useful. Does not affect Defender cloud lookups, which use a separate channel.'
    }
    'Disable-AdvertisingID' = @{
        Title='Disable Advertising ID + content suggestions'
        What ='Clears the per-user Advertising ID, applies GP DisabledByGroupPolicy=1, disables Spotlight, lock-screen tips, OEM pre-installed apps, suggested apps and silent installs from the Store.'
        Why  ='Stops apps from correlating user behaviour for ad targeting. Also stops Windows from silently installing third-party apps (Candy Crush et al.) from the Store.'
        Risk ='Cosmetic only - you see fewer "suggestions" on the Start menu and lock screen.'
    }
    'Disable-Cortana' = @{
        Title='Disable Cortana + web search'
        What ='Sets AllowCortana=0, AllowCloudSearch=0, DisableWebSearch=1, ConnectedSearchUseWeb=0, AllowCortanaAboveLock=0.'
        Why  ='Local search no longer sends queries to Bing. Cortana stops listening and stops storing voice/typing data.'
        Risk ='Loss of voice assistant features and web-search-from-Start integration.'
    }
    'Disable-OneDrive' = @{
        Title='Disable OneDrive (policy)'
        What ='Sets DisableFileSyncNGSC=1 and DisableFileSync=1 in the OneDrive policy key.'
        Why  ='Blocks user files from being silently synced to a Microsoft cloud account. Important for organisations with data-residency or DLP requirements.'
        Risk ='Users cannot sign in to OneDrive. Existing personal-account file sync stops.'
    }

    # ---- Network crypto ----
    'Set-SecureDNS' = @{
        Title='Set secure DNS (Cloudflare + Quad9)'
        What ='Configures every active adapter to use 1.1.1.1, 1.0.0.1 (Cloudflare) and 9.9.9.9, 149.112.112.112 (Quad9) as DNS resolvers.'
        Why  ='Default ISP DNS often does not block known-malicious domains. Quad9 specifically blocks resolutions to known phishing/malware infrastructure. Cloudflare provides high performance + DoH support.'
        Risk ='You lose ISP-level DNS-based filtering (e.g., parental controls bundled with the router). On a corporate network, keep the corporate DNS instead so internal name resolution still works.'
    }
    'Enable-DNSOverHTTPS' = @{
        Title='Enable DNS-over-HTTPS (DoH)'
        What ='Adds DoH templates for Cloudflare and Quad9, sets DoHPolicy=2 (Required) at policy level. DNS queries that cannot use HTTPS are dropped.'
        Why  ='DNS over HTTPS encrypts your DNS queries so a passive observer on the network (coffee-shop Wi-Fi operator, ISP, intermediate router) cannot see which domains you visit. Required mode prevents fallback to plain DNS.'
        Risk ='Captive-portal Wi-Fi (hotels, airports) sometimes hijacks DNS to redirect to a login page; with Required DoH, those captive portals fail.'
    }
    'Set-SChannelHardening' = @{
        Title='Harden SChannel (TLS)'
        What ='Disables SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1, and weak ciphers (RC4 in every variant, DES 56, 3DES 168) plus weak hashes (MD5, SHA-1). Enables TLS 1.2 and TLS 1.3. Forces .NET 4.x to use strong crypto and system-default TLS versions.'
        Why  ='Old TLS versions and weak ciphers are vulnerable to POODLE, BEAST, LUCKY13, SWEET32, and downgrade attacks. TLS 1.2/1.3 with modern AEAD ciphers is what HTTPS should look like in 2026. Forcing .NET to use system TLS prevents legacy apps from sneakily negotiating TLS 1.0.'
        Risk ='Very old HTTPS servers (TLS 1.0/1.1 only) become unreachable. Some embedded devices may also drop off. Usually the right call.'
    }
    'Set-SMBSigningRequired' = @{
        Title='Enforce SMB signing'
        What ='Sets RequireSecuritySignature=1 and EnableSecuritySignature=1 on both LanmanServer and LanmanWorkstation, and AllowInsecureGuestAuth=0.'
        Why  ='SMB signing prevents SMB-relay attacks (one of the most common LAN-pentest techniques). With signing required, an attacker who relays your credentials to another server cannot complete the handshake.'
        Risk ='Slight perf overhead (negligible on modern CPUs). Some pre-Vista clients cannot sign.'
    }
    'Set-LDAPSigningRequired' = @{
        Title='Enforce LDAP signing + channel binding'
        What ='LDAPClientIntegrity=2 (signing required), LdapEnforceChannelBinding=2 (channel binding required on the DC side too).'
        Why  ='Like SMB-relay, LDAP-relay attacks (PetitPotam, NTLM-to-LDAPS) become impossible when signing and channel binding are required.'
        Risk ='Legacy LDAP clients that cannot sign break. Modern Windows + modern AD admins do not notice.'
    }

    # ---- Services hardening ----
    'Disable-WebClient' = @{
        Title='Disable WebClient (WebDAV)'
        What ='Stops the WebClient service and disables it.'
        Why  ='The WebClient service implements WebDAV. The "NTLM-over-WebDAV" relay technique uses WebClient to coerce a victim into authenticating to an attacker-controlled UNC path - the start of many lateral-movement chains. Most workstations never use WebDAV.'
        Risk ='You cannot mount HTTP/HTTPS file shares with the "net use" command. Rarely used outside SharePoint power users.'
    }
    'Disable-WPAD' = @{
        Title='Disable WPAD'
        What ='Stops the WinHttpAutoProxySvc service and adds "0.0.0.0 wpad" to the hosts file as defence-in-depth.'
        Why  ='Web Proxy Auto-Discovery uses LLMNR/NetBIOS/DNS to find a wpad host on the local network and then trust whatever proxy.pac it serves. An attacker on the LAN can hijack WPAD and silently MITM all HTTP/HTTPS traffic. Disabling closes the vector.'
        Risk ='If your corporate network legitimately uses WPAD, configure the proxy manually via Internet Options or GPO instead.'
    }
    'Set-ScreenLockTimeout' = @{
        Title='Screen auto-lock (5 min)'
        What ='5-minute screensaver lock, password required on resume, machine-wide InactivityTimeoutSecs=300, AC + DC powercfg console-lock both on.'
        Why  ='Tailgating and shoulder-surfing are real - especially in shared workspaces. A 5-minute lock prevents an unattended workstation from being walked up to and used.'
        Risk ='Frequent annoyance for users who step away briefly. Many users adapt; consider 10 minutes if 5 is too aggressive.'
    }

    # ---- v5.1 additions ----
    'Invoke-QuickWinHardening' = @{
        Title='Apply Quick Win preset'
        What ='Runs a curated subset of about 25 hardening controls that are universally safe: UAC, lockout, firewall, SMB hardening, Defender + ASR, AutoRun, Guest, WSH, anonymous, telemetry, Advertising ID, SmartScreen, NTLMv2, Exploit Protection, Remote Assistance off, WebClient off, WPAD off, SChannel, secure DNS, screen lock, RemoteSigned PowerShell.'
        Why  ='Aggressive hardening (USB off, Bluetooth off, IPv6 off, outbound block) is great for some environments but breaks usability in many. Quick Win covers the low-risk / high-impact controls that almost no workstation will notice but most attackers will.'
        Risk ='None for a typical workstation. Reboot recommended.'
    }
    'Invoke-AllHardening' = @{
        Title='Apply ALL hardening (aggressive)'
        What ='Runs 45+ hardening controls in a safe order: creates a restore point first, applies everything, finishes with PowerShell execution policy = RemoteSigned (so this tool can still run again).'
        Why  ='If you understand the trade-offs and want the strongest defensible posture from one click.'
        Risk ='USB storage off, Bluetooth off, hibernation purged, IPv6 transition off, Memory Integrity on, etc. Some apps and peripherals will break until selectively re-enabled.'
    }
    'Invoke-WSERollback' = @{
        Title='Rollback (registry restore)'
        What ='Interactively picks a past WSE session and restores every registry value to whatever it was before that session ran. Values that did not exist before the session are removed.'
        Why  ='Confidence to apply hardening without fear. If something breaks, you can put the registry back exactly as it was.'
        Risk ='Service-state changes, firewall rules, and Group-Policy-style behaviours are NOT automatically reverted by rollback. Use the matching Enable-* option for those.'
    }
    'New-WSERestorePoint' = @{
        Title='Create a System Restore Point'
        What ='Bypasses the 24-hour Windows throttle and creates a MODIFY_SETTINGS restore point named after the WSE session.'
        Why  ='Provides a coarse "back to before" lifeline that covers registry, drivers and many system files. Complements the WSE registry backup.'
        Risk ='System Protection must be enabled on the drive (it is by default on Windows 10/11, but disabled on some Server SKUs).'
    }
    'Export-WSEHtmlReport' = @{
        Title='Export HTML security report'
        What ='Computes the live hardening score and writes a stand-alone HTML report (no external resources) to %ProgramData%\WSE\logs\.'
        Why  ='Audit evidence. Auditors and security reviewers can be given the HTML file as-is.'
        Risk ='None - read-only.'
    }

    # ---- v5.2 additions ----
    'Set-FirewallStealthMode' = @{
        Title='Firewall stealth mode (Public profile)'
        What ='Adds explicit Block rules for ICMPv4 / ICMPv6 echo requests on the Public profile, and disables the built-in "File and Printer Sharing" inbound rules on Public.'
        Why  ='Stops your machine from responding to pings or to broadcast file-share discovery on untrusted networks. The first step of most network scans (nmap -sn) becomes blind to your machine.'
        Risk ='Other devices on the same Public network cannot ping you or discover SMB shares. If you trust the network, set it to Private instead.'
    }
    'Set-EdgeHardening' = @{
        Title='Microsoft Edge: privacy + security hardening'
        What ='Applies ~25 Edge GPO policy values: telemetry off, sync off, sign-in blocked, password manager off, payment/autofill off, Strict tracking prevention, DoNotTrack on, third-party cookies blocked, popups blocked, SmartScreen with PreventOverride, BasicAuth-over-HTTP off, Shopping/Promotions/MediaRouter off.'
        Why  ='Edge is a major data-collection surface in stock Windows. These policies give you a privacy-respecting, security-focused browser closer to a Brave/LibreWolf profile - while still working with corporate SSO if you re-enable BrowserSignin.'
        Risk ='Users who rely on Edge sync or its built-in password manager need to switch to a stand-alone password manager (1Password, Bitwarden, KeePassXC).'
    }
    'Restore-EdgeDefaults' = @{
        Title='Restore Microsoft Edge defaults'
        What ='Removes the ~25 Edge policy keys WSE wrote. Other Edge policies (corporate / GPO) are left untouched.'
        Why  ='Reverses the Edge hardening if it interferes with a workflow.'
        Risk ='Returns to the default Edge privacy posture.'
    }
    'Disable-RDPRedirection' = @{
        Title='Disable RDP redirection (clipboard / drives / printers / ports)'
        What ='Sets fDisableClip, fDisableCdm, fDisableCpm, fDisableLPT, fDisableCcm, fDisableAudioCapture, fDisableCameraRedir, fDisableLocationRedir, fDisableWebAuthnRedirection = 1 in the Terminal Services policy key.'
        Why  ='When RDP must stay enabled, redirection is the largest remaining attack surface: RDP-clipboard exfiltration, drive-share lateral-movement, malicious printer driver upload, plus several CVE chains in COM/LPT redirection. Turning these off keeps RDP usable for remote admin but kills the data-flow vectors.'
        Risk ='You cannot paste between your local machine and the RDP session, and you cannot map your local drives into the session. For most remote-admin work this is exactly what you want.'
    }
    'Restore-RDPRedirection' = @{
        Title='Restore RDP redirection defaults'
        What ='Removes the redirection-disable policies.'
        Why  ='If you really need clipboard / drive sharing in RDP, undo the hardening.'
        Risk ='Reopens the redirection-based attack surfaces.'
    }
    'Disable-MicrosoftAccount' = @{
        Title='Block adding Microsoft accounts'
        What ='Sets HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser = 3.'
        Why  ='Forces every account on this PC to be a local account. Important for privacy (no MS-account telemetry tied to the user), for forensic clarity (no MS-account auto-sync of files/clipboard/passwords), and for environments where regulatory data residency matters.'
        Risk ='Users cannot link a Microsoft account or sign in with one. Existing MS-account-linked profiles keep working.'
    }
    'Enable-MicrosoftAccount' = @{
        Title='Allow Microsoft accounts'
        What ='Sets NoConnectedUser=0 - the default behaviour.'
        Why  ='Re-allows MS account sign-in if a user needs Store apps or Office 365 personal sign-in.'
        Risk ='Returns to the default privacy posture for accounts.'
    }
    'Show-OpenListeningPorts' = @{
        Title='Show open listening ports'
        What ='Lists every TCP listener and UDP endpoint with its local address, port, owning process name and PID. Read-only.'
        Why  ='You cannot defend what you do not know about. This diagnostic surfaces unexpected listeners - the very first thing to check after a hardening pass and a great periodic sanity check.'
        Risk ='None.'
    }
    'Test-WSEPendingReboot' = @{
        Title='Pending-reboot check'
        What ='Inspects four pending-reboot indicators: Component-Based Servicing flag, Windows Update RebootRequired, PendingFileRenameOperations, and ComputerName mismatch.'
        Why  ='Many hardening controls (HVCI, LSA Protection, SMBv1 driver disable, Memory Integrity) only take effect after reboot. This tells you whether you need to reboot before they engage.'
        Risk ='None.'
    }
    'Show-RecentLogonEvents' = @{
        Title='Show recent logon events'
        What ='Reads the Security event log for the last 20 events of ID 4624 (successful logon) and 4625 (failed logon) and prints them with timestamp, account and logon type. Failed logons in red.'
        Why  ='Quick spot-check for brute-force attempts, lateral movement attempts, or unexpected logons. A run of 4625s with type 3 (network) is a classic credential-spray signature.'
        Risk ='None. Requires that the Security log has actually captured these events - run the comprehensive audit policy (option 27) first if it has not.'
    }
    'Invoke-WSEThreatScan' = @{
        Title='Threat hunt - heuristic IOC sweep'
        What ='Reads ~15 persistence + tampering surfaces: AppInit_DLLs, IFEO debugger hijacks (sticky-keys backdoor classic), BootExecute, Run/RunOnce keys, scheduled-task actions that run from %TEMP% or base64-encoded PowerShell, WMI permanent event subscriptions, LSA package whitelist, hosts-file abuse (size + AV/update domain blocks), DNS-server whitelist, Defender exclusions, Defender real-time state, Security event-log state, RMM tools, startup-folder scripts and shortcuts, Winlogon Shell + Userinit, and Volume Shadow Copy state. Findings are kept in memory for the remediation step. Works the same on ARM64 / Intel / AMD.'
        Why  ='Hardening alone does not detect an existing compromise. This scan catches the highest-signal persistence patterns - the things that show up in incident-response reports week after week (RID-500 IFEO hijacks, AppInit DLLs, WMI event subscriptions, broad Defender exclusions, hosts-file blocks of Windows Update / Defender domains, Volume Shadow Copy disabled in pre-ransomware staging).'
        Risk ='Read-only. False positives are possible (RMM tools may be legitimate IT software; a non-default DNS may be a corporate resolver). Review each finding before remediating.'
    }
    'Invoke-WSEThreatRemediation' = @{
        Title='Threat remediation (apply auto-fixes)'
        What ='Iterates the findings from the most recent threat scan and offers an auto-fix for each one that has a registered remediation: clearing AppInit_DLLs, removing IFEO Debugger values, resetting the hosts file (backup kept next to it), re-enabling Defender real-time + the Security event log, resetting Winlogon Shell / Userinit, and bringing Volume Shadow Copy back to Manual start. Every fix is confirmed individually - no silent changes.'
        Why  ='Most IOC removal needs registry surgery that is fiddly to get right by hand. Auto-fixes are scoped to the exact value the scan flagged; nothing else is touched. Every change is recorded in the session backup so option 93 (Rollback) can undo it.'
        Risk ='Resetting the hosts file removes legitimate custom entries (a backup copy is saved). Removing an IFEO debugger value will break a debugging configuration if someone actually wanted it. Run option 103 first and review the report.'
    }
}

function Show-FeatureExplanation {
    param([string] $FunctionName)

    if (-not $FunctionName) {
        Write-Section "Explain a hardening feature"
        Write-Host "  Enter the menu option number you want explained (or the function name)." -ForegroundColor Cyan
        Write-Host "  Examples:  20    Enable-WindowsDefender    51    Set-SChannelHardening" -ForegroundColor DarkGray
        # Avoid $input - PowerShell reserves it as the pipeline enumerator
        $token = Read-Host "  Option/function"
        if ([string]::IsNullOrWhiteSpace($token)) { Write-Warn "Cancelled."; return }
        $FunctionName = Resolve-WSEMenuToFunction -Token $token.Trim()
        if (-not $FunctionName) { Write-Fail "No explanation registered for '$token'."; return }
    }

    if (-not $Script:FeatureExplanations.ContainsKey($FunctionName)) {
        Write-Fail "No explanation registered for function '$FunctionName'."
        Write-Warn "Tip: only hardening controls have explanations - utility functions like Show-Banner do not."
        return
    }

    $e = $Script:FeatureExplanations[$FunctionName]
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host ("  ║  {0,-64} ║" -f $e.Title) -ForegroundColor Magenta
    Write-Host "  ╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "  WHAT IT DOES" -ForegroundColor Cyan
    Write-Wrapped $e.What
    Write-Host ""
    Write-Host "  WHY IT MAKES YOU SAFER" -ForegroundColor Green
    Write-Wrapped $e.Why
    Write-Host ""
    Write-Host "  TRADE-OFFS / RISK" -ForegroundColor Yellow
    Write-Wrapped $e.Risk
    Write-Host ""
    Write-Host "  Engine function: $FunctionName" -ForegroundColor DarkGray
    Write-Host ""
}

function Write-Wrapped {
    param([string] $Text, [int] $Width = 76, [string] $Indent = '  ')
    if ([string]::IsNullOrWhiteSpace($Text)) { return }
    $words = $Text -split '\s+'
    $line = $Indent
    foreach ($w in $words) {
        if (($line.Length + $w.Length + 1) -gt $Width) {
            Write-Host $line -ForegroundColor White
            $line = "$Indent$w"
        } else {
            $line += if ($line -eq $Indent) { $w } else { " $w" }
        }
    }
    if ($line.Trim()) { Write-Host $line -ForegroundColor White }
}

function Resolve-WSEMenuToFunction {
    param([string] $Token)
    # Mapping from menu option number (string) to the engine function name.
    $map = @{
        '1'='Set-UACPasswordPrompt'; '2'='Set-UACAlwaysNotify'; '3'='Restore-UACToNormal';
        '4'='Set-AccountLockoutPolicy'; '5'='Disable-AccountLockoutPolicy'; '6'='Set-StrongPasswordPolicy';
        '7'='Enable-WindowsFirewall'; '8'='Disable-WindowsFirewall';
        '9'='Disable-SMBv1'; '10'='Enable-SMBv1';
        '11'='Disable-RemoteDesktop'; '12'='Enable-RemoteDesktop';
        '13'='Disable-AnonymousAccess';
        '14'='Disable-USBPorts'; '15'='Enable-USBPorts';
        '16'='Disable-Cameras'; '17'='Enable-Cameras';
        '18'='Disable-AutoRun'; '19'='Enable-AutoRun';
        '20'='Enable-WindowsDefender';
        '21'='Disable-GuestAccount'; '22'='Enable-GuestAccount';
        '23'='Disable-WindowsScriptHost'; '24'='Enable-WindowsScriptHost';
        '25'='Disable-UnnecessaryServices'; '26'='Enable-UnnecessaryServices';
        '27'='Enable-AuditPolicy';
        '28'='Enable-CredentialGuard';
        '29'='Disable-Telemetry'; '30'='Enable-Telemetry';
        '31'='Disable-AdvertisingID'; '32'='Disable-Cortana';
        '33'='Disable-PrintSpooler'; '34'='Enable-PrintSpooler';
        '35'='Set-NTLMv2Only'; '36'='Disable-PowerShellv2';
        '37'='Enable-ExploitProtection';
        '38'='Enable-ClearPageFileOnShutdown'; '39'='Disable-ClearPageFileOnShutdown';
        '40'='Disable-RemoteAssistance'; '41'='Enable-RemoteAssistance';
        '42'='Set-SecureDNS'; '43'='Disable-IPv6'; '44'='Enable-IPv6';
        '45'='Enable-AutomaticUpdates'; '46'='Set-ScreenLockTimeout';
        '47'='Rename-AdminAccount'; '48'='New-WSERestorePoint';
        '51'='Enable-ASRRules'; '52'='Disable-ASRRules';
        '53'='Set-PSExecutionRemoteSigned'; '54'='Set-PSExecutionAllSigned'; '55'='Restore-PSExecutionDefault';
        '56'='Disable-Bluetooth'; '57'='Enable-Bluetooth';
        '58'='Disable-OfficeMacros'; '59'='Enable-OfficeMacros';
        '60'='Enable-FirewallLogging'; '61'='Set-FirewallBlockOutbound'; '62'='Restore-FirewallDefaultOutbound';
        '63'='Show-BitLockerStatus'; '64'='Enable-BitLockerSystem';
        '65'='Disable-WinRM'; '66'='Enable-WinRM';
        '68'='Invoke-AllHardening'; '87'='Invoke-QuickWinHardening'; '90'='Export-WSEHtmlReport'; '93'='Invoke-WSERollback';
        '70'='Show-DefenderTamperStatus'; '71'='Set-DefenderSchedule';
        '72'='Disable-WebClient'; '73'='Disable-WPAD';
        '74'='Disable-IPv6TransitionTech';
        '75'='Set-SChannelHardening'; '76'='Restore-SChannelDefaults';
        '77'='Enable-DNSOverHTTPS';
        '78'='Set-SMBSigningRequired'; '79'='Set-LDAPSigningRequired';
        '80'='Enable-MemoryIntegrity';
        '81'='Disable-ConsumerFeatures'; '82'='Disable-OneDrive'; '83'='Disable-XboxServices';
        '84'='Enable-SmartScreen'; '85'='Disable-QuickAssist'; '86'='Disable-Hibernation';
        '88'='Set-FirewallStealthMode';
        '94'='Set-EdgeHardening'; '95'='Restore-EdgeDefaults';
        '96'='Disable-RDPRedirection'; '97'='Restore-RDPRedirection';
        '98'='Disable-MicrosoftAccount'; '99'='Enable-MicrosoftAccount';
        '100'='Show-OpenListeningPorts'; '101'='Test-WSEPendingReboot'; '102'='Show-RecentLogonEvents';
        '103'='Invoke-WSEThreatScan'; '104'='Invoke-WSEThreatRemediation';
    }
    if ($map.ContainsKey($Token)) { return $map[$Token] }
    # Allow callers to pass the function name directly
    if ($Script:FeatureExplanations.ContainsKey($Token)) { return $Token }
    return $null
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
    Write-Host "  ── NEW in v5.1  —  Additional Hardening ─────────────────" -ForegroundColor Magenta
    Write-Host "   88.  Firewall stealth mode (block ping on Public profile)"
    Write-Host "   94.  Harden Microsoft Edge (privacy + security policies)"
    Write-Host "   95.  Restore Edge defaults"
    Write-Host "   96.  Harden RDP (block clipboard / drive / printer redirect)"
    Write-Host "   97.  Restore RDP redirection defaults"
    Write-Host "   98.  Block adding Microsoft accounts"
    Write-Host "   99.  Allow Microsoft accounts (default)"
    Write-Host "  100.  Show open / listening ports"
    Write-Host "  101.  Test for pending reboot"
    Write-Host "  102.  Show recent logon events (4624 / 4625)"
    Write-Host ""
    Write-Host "  ── Threat Hunt (NEW in v5.2) ────────────────────────────" -ForegroundColor Red
    Write-Host "  103.  Threat scan  (heuristic IOC sweep - ARM + Intel + AMD)"
    Write-Host "  104.  Threat remediation  (applies confirmed auto-fixes)"
    Write-Host ""
    Write-Host "  ── Utilities ────────────────────────────────────────────" -ForegroundColor Yellow
    Write-Host "   67.  Show security status report"
    Write-Host "   68.  Apply ALL hardening settings  [aggressive]"
    Write-Host "   87.  Apply Quick Win preset  [safe defaults - recommended]"
    Write-Host "   89.  Explain a hardening feature  (what / why / risk)"
    Write-Host "   90.  Export HTML security report"
    Write-Host "   93.  ROLLBACK — restore registry from a previous backup"
    Write-Host "   69.  Exit"
    Write-Host ""
    Write-Host "  Available range: 1-50, 51-66, 67-86, 87-104, 93, 69" -ForegroundColor DarkGray
    $choice = Read-Host "  Enter choice"
    return $choice
}

# =============================================================================
#  MAIN LOOP
# =============================================================================

Initialize-WSE
Get-WSECapabilities | Out-Null

# -----------------------------------------------------------------------------
#  -NoMenu: stop here so the GUI (or another host) can dot-source this file
#  to gain access to every Verb-Noun function without entering the menu loop.
# -----------------------------------------------------------------------------
if ($NoMenu) { return }

# Re-show the elevation banner once on startup
Write-Host ""
Write-Host "  [+] Running as Administrator." -ForegroundColor Green
Write-Host "  [+] WSE v$($Script:WSEVersion) initialised — log: $($Script:WSETranscript)" -ForegroundColor Green

# -----------------------------------------------------------------------------
#  Non-interactive entry points — handle CLI switches and exit
# -----------------------------------------------------------------------------
$nonInteractive = $Apply -or $QuickWin -or $Status -or $Report -or $Rollback
if ($nonInteractive) {
    try {
        if ($Status)   { Show-SecurityStatus }
        if ($Apply)    { Invoke-AllHardening }
        if ($QuickWin) { Invoke-QuickWinHardening }
        if ($Rollback) { Invoke-WSERollback }
        if ($Report) {
            $p = Export-WSEHtmlReport -Path $ReportPath
            if ($p) { Write-Host "  Report: $p" -ForegroundColor Green }
        }
    } finally {
        Stop-WSE
    }
    return
}

try {
    do {
        $userChoice = Show-Menu

        switch ($userChoice) {
             '1'  { Set-UACPasswordPrompt          }
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
            '78'  { Set-SMBSigningRequired                 }
            '79'  { Set-LDAPSigningRequired                }
            '80'  { Enable-MemoryIntegrity             }
            '81'  { Disable-ConsumerFeatures           }
            '82'  { Disable-OneDrive                   }
            '83'  { Disable-XboxServices               }
            '84'  { Enable-SmartScreen                 }
            '85'  { Disable-QuickAssist                }
            '86'  { Disable-Hibernation                }
            '87'  { Invoke-QuickWinHardening           }
            '88'  { Set-FirewallStealthMode            }
            '89'  { Show-FeatureExplanation            }
            '90'  {
                $p = Export-WSEHtmlReport
                if ($p) { Write-Host "  Open with: start `"`" `"$p`"" -ForegroundColor DarkGray }
            }
            '93'  { Invoke-WSERollback                 }
            '94'  { Set-EdgeHardening                  }
            '95'  { Restore-EdgeDefaults               }
            '96'  { Disable-RDPRedirection             }
            '97'  { Restore-RDPRedirection             }
            '98'  { Disable-MicrosoftAccount           }
            '99'  { Enable-MicrosoftAccount            }
            '100' { Show-OpenListeningPorts            }
            '101' { Test-WSEPendingReboot              }
            '102' { Show-RecentLogonEvents             }
            '103' { Invoke-WSEThreatScan | Out-Null    }
            '104' { Invoke-WSEThreatRemediation        }
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
