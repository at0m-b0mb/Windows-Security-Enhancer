# =============================================================================
#  Windows Security Enhancer
#  Hardens Windows systems against common attack vectors.
#  Run via runner.bat (requires Administrator privileges).
# =============================================================================

# ─── Privilege Check / Self-Elevation ────────────────────────────────────────
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "  [!] Administrator privileges required. Re-launching as Administrator..." -ForegroundColor Yellow
    $script = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
    try {
        Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$script`"" -Verb RunAs -ErrorAction Stop
    } catch {
        Write-Host "  [-] Could not elevate privileges: $_" -ForegroundColor Red
        Write-Host "  [!] Please right-click runner.bat and select 'Run as administrator'." -ForegroundColor Yellow
        Read-Host "  Press ENTER to exit"
        exit 1
    }
    exit
}

# ─── Colored Output Helpers ──────────────────────────────────────────────────
function Write-Info { param([string]$m) Write-Host "  [*] $m" -ForegroundColor Cyan    }
function Write-Ok   { param([string]$m) Write-Host "  [+] $m" -ForegroundColor Green   }
function Write-Warn { param([string]$m) Write-Host "  [!] $m" -ForegroundColor Yellow  }
function Write-Fail { param([string]$m) Write-Host "  [-] $m" -ForegroundColor Red     }

# =============================================================================
#  UAC FUNCTIONS
# =============================================================================

function Enforce-UACPasswordPrompt {
    Write-Info "Enforcing UAC to require credentials for admin tasks..."
    $p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-ItemProperty -Path $p -Name "ConsentPromptBehaviorAdmin" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $p -Name "PromptOnSecureDesktop"      -Value 1 -Type DWord -Force
    Write-Ok "UAC configured to require credentials for admin tasks."
}

function Set-UACAlwaysNotify {
    Write-Info "Setting UAC to 'Always Notify'..."
    $p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-ItemProperty -Path $p -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord -Force
    Set-ItemProperty -Path $p -Name "PromptOnSecureDesktop"      -Value 1 -Type DWord -Force
    Write-Ok "UAC set to 'Always Notify'."
}

function Restore-UACToNormal {
    Write-Info "Restoring UAC to Windows default settings..."
    $p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-ItemProperty -Path $p -Name "ConsentPromptBehaviorAdmin" -Value 5 -Type DWord -Force
    Set-ItemProperty -Path $p -Name "PromptOnSecureDesktop"      -Value 0 -Type DWord -Force
    Write-Ok "UAC restored to default (notify on app changes)."
}

# =============================================================================
#  ACCOUNT & PASSWORD POLICY
# =============================================================================

function Set-AccountLockoutPolicy {
    Write-Info "Setting account lockout policy (5 attempts / 30-min lockout)..."
    net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 | Out-Null
    Write-Ok "Account lockout policy applied."
}

function Disable-AccountLockoutPolicy {
    Write-Info "Restoring account lockout policy to default (no lockout)..."
    net accounts /lockoutthreshold:0 | Out-Null
    Write-Ok "Account lockout policy restored to default."
}

function Set-StrongPasswordPolicy {
    Write-Info "Enforcing strong password policy (12+ chars, complexity, 90-day expiry)..."
    net accounts /minpwlen:12 /maxpwage:90 /minpwage:1 /uniquepw:5 | Out-Null

    # Enable password complexity via secedit
    $tmpCfg = "$env:TEMP\secpol_tmp.cfg"
    $tmpSdb = "$env:TEMP\secpol_tmp.sdb"
    secedit /export /cfg $tmpCfg /quiet
    if (Test-Path $tmpCfg) {
        (Get-Content $tmpCfg) -replace 'PasswordComplexity\s*=\s*\d', 'PasswordComplexity = 1' |
            Set-Content $tmpCfg
        secedit /configure /db $tmpSdb /cfg $tmpCfg /quiet
        Remove-Item $tmpCfg -Force -ErrorAction SilentlyContinue
        Remove-Item $tmpSdb -Force -ErrorAction SilentlyContinue
    }
    Write-Ok "Strong password policy applied."
}

# =============================================================================
#  CAMERA MANAGEMENT
# =============================================================================

function Disable-Cameras {
    Write-Info "Detecting and disabling connected camera devices..."
    $cameras = @(Get-PnpDevice -ErrorAction SilentlyContinue |
                 Where-Object { $_.Class -in @('Camera','Image') -or
                                $_.FriendlyName -match 'camera|webcam' })
    if ($cameras.Count -eq 0) {
        Write-Warn "No camera devices found."
    } else {
        foreach ($cam in $cameras) {
            try {
                Disable-PnpDevice -InstanceId $cam.InstanceId -Confirm:$false -ErrorAction Stop
                Write-Ok "Disabled: $($cam.FriendlyName)"
            } catch {
                Write-Fail "Could not disable '$($cam.FriendlyName)': $_"
            }
        }
    }
}

function Enable-Cameras {
    Write-Info "Enabling connected camera devices..."
    $cameras = @(Get-PnpDevice -ErrorAction SilentlyContinue |
                 Where-Object { $_.Class -in @('Camera','Image') -or
                                $_.FriendlyName -match 'camera|webcam' })
    if ($cameras.Count -eq 0) {
        Write-Warn "No camera devices found."
    } else {
        foreach ($cam in $cameras) {
            try {
                Enable-PnpDevice -InstanceId $cam.InstanceId -Confirm:$false -ErrorAction Stop
                Write-Ok "Enabled: $($cam.FriendlyName)"
            } catch {
                Write-Fail "Could not enable '$($cam.FriendlyName)': $_"
            }
        }
    }
}

# =============================================================================
#  USB MANAGEMENT
# =============================================================================

function Disable-USBPorts {
    Write-Info "Disabling USB storage (UsbStor service)..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor" `
        -Name "Start" -Value 4 -Type DWord -Force
    Write-Ok "USB storage devices disabled."

    Write-Info "Disabling USB Root Hubs..."
    $hubs = @(Get-PnpDevice -ErrorAction SilentlyContinue |
              Where-Object { $_.InstanceId -match 'ROOT_HUB' -and $_.Status -eq 'OK' })
    foreach ($hub in $hubs) {
        try {
            Disable-PnpDevice -InstanceId $hub.InstanceId -Confirm:$false -ErrorAction Stop
            Write-Ok "Disabled hub: $($hub.FriendlyName)"
        } catch {
            Write-Fail "Could not disable hub '$($hub.InstanceId)': $_"
        }
    }
}

function Enable-USBPorts {
    Write-Info "Enabling USB storage (UsbStor service)..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor" `
        -Name "Start" -Value 3 -Type DWord -Force
    Write-Ok "USB storage devices enabled."

    Write-Info "Enabling USB Root Hubs..."
    $hubs = @(Get-PnpDevice -ErrorAction SilentlyContinue |
              Where-Object { $_.InstanceId -match 'ROOT_HUB' })
    foreach ($hub in $hubs) {
        try {
            Enable-PnpDevice -InstanceId $hub.InstanceId -Confirm:$false -ErrorAction Stop
            Write-Ok "Enabled hub: $($hub.FriendlyName)"
        } catch {
            Write-Fail "Could not enable hub '$($hub.InstanceId)': $_"
        }
    }
}

# =============================================================================
#  WINDOWS FIREWALL
# =============================================================================

function Enable-WindowsFirewall {
    Write-Info "Enabling Windows Firewall for all profiles..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
    Write-Ok "Windows Firewall enabled; default inbound action set to Block."

    Write-Info "Blocking commonly exploited inbound ports..."
    $ports = @(
        @{Port=23;   Name='Telnet'},
        @{Port=135;  Name='RPC-DCOM'},
        @{Port=137;  Name='NetBIOS-NS'},
        @{Port=138;  Name='NetBIOS-DGM'},
        @{Port=139;  Name='NetBIOS-SSN'},
        @{Port=445;  Name='SMB'},
        @{Port=1433; Name='MSSQL'},
        @{Port=3389; Name='RDP'},
        @{Port=5985; Name='WinRM-HTTP'},
        @{Port=5986; Name='WinRM-HTTPS'}
    )
    foreach ($p in $ports) {
        $rule = "WSE-Block-$($p.Name)-Inbound"
        if (-not (Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $rule -Direction Inbound -Protocol TCP `
                -LocalPort $p.Port -Action Block -Profile Any -ErrorAction SilentlyContinue | Out-Null
            Write-Ok "Blocked inbound TCP $($p.Port) ($($p.Name))."
        } else {
            Write-Warn "Rule '$rule' already exists — skipped."
        }
    }
}

function Disable-WindowsFirewall {
    Write-Warn "WARNING: Disabling the Windows Firewall reduces system security."
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    Write-Ok "Windows Firewall disabled for all profiles."
}

# =============================================================================
#  SMBv1 (PREVENTS WANNACRY / ETERNALBLUE ATTACKS)
# =============================================================================

function Disable-SMBv1 {
    Write-Info "Disabling SMBv1 (prevents WannaCry / EternalBlue attacks)..."
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
        Write-Ok "SMBv1 server protocol disabled via Set-SmbServerConfiguration."
    } catch {
        Write-Warn "Set-SmbServerConfiguration unavailable — using registry fallback."
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
            -Name "SMB1" -Value 0 -Type DWord -Force
        Write-Ok "SMBv1 disabled via registry."
    }

    $feat = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
    if ($feat -and $feat.State -eq 'Enabled') {
        Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Write-Ok "SMBv1 Windows optional feature disabled."
    }
    Write-Warn "A restart may be required for all SMBv1 changes to take full effect."
}

function Enable-SMBv1 {
    Write-Warn "WARNING: SMBv1 is a legacy, insecure protocol. Enabling it is not recommended."
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -ErrorAction Stop
    } catch {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
            -Name "SMB1" -Value 1 -Type DWord -Force
    }
    Write-Ok "SMBv1 enabled."
}

# =============================================================================
#  REMOTE DESKTOP PROTOCOL (RDP)
# =============================================================================

function Disable-RemoteDesktop {
    Write-Info "Disabling Remote Desktop Protocol (RDP)..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
        -Name "fDenyTSConnections" -Value 1 -Type DWord -Force
    Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue |
        Disable-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Ok "RDP disabled and firewall rules deactivated."
}

function Enable-RemoteDesktop {
    Write-Info "Enabling Remote Desktop Protocol (RDP)..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
        -Name "fDenyTSConnections" -Value 0 -Type DWord -Force
    Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue |
        Enable-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Ok "RDP enabled and firewall rules activated."
}

# =============================================================================
#  WINDOWS DEFENDER (MAXIMUM PROTECTION)
# =============================================================================

function Enable-WindowsDefender {
    Write-Info "Configuring Windows Defender for maximum protection..."
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

        Set-MpPreference -SubmitSamplesConsent         SendAllSamples    -ErrorAction SilentlyContinue
        Write-Ok "Automatic sample submission enabled."

        Write-Ok "Windows Defender fully hardened."
    } catch {
        Write-Fail "Could not configure Windows Defender: $_"
        Write-Warn "Defender may not be available or may be managed by Group Policy."
    }
}

# =============================================================================
#  AUTORUN / AUTOPLAY
# =============================================================================

function Disable-AutoRun {
    Write-Info "Disabling AutoRun and AutoPlay (prevents removable-media attacks)..."
    $explorerPol = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Set-ItemProperty -Path $explorerPol -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord -Force
    Set-ItemProperty -Path $explorerPol -Name "NoDriveAutoRun"     -Value 67108863 -Type DWord -Force

    $autorunInf = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf"
    if (-not (Test-Path $autorunInf)) { New-Item -Path $autorunInf -Force | Out-Null }
    Set-ItemProperty -Path $autorunInf -Name "(Default)" -Value "@SYS:DoesNotExist" -Type String -Force

    $apHandlers = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"
    if (-not (Test-Path $apHandlers)) { New-Item -Path $apHandlers -Force | Out-Null }
    Set-ItemProperty -Path $apHandlers -Name "DisableAutoplay" -Value 1 -Type DWord -Force

    Write-Ok "AutoRun and AutoPlay disabled on all drive types."
}

function Enable-AutoRun {
    Write-Info "Restoring AutoRun / AutoPlay to Windows defaults..."
    $explorerPol = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Set-ItemProperty -Path $explorerPol -Name "NoDriveTypeAutoRun" -Value 0x91 -Type DWord -Force

    $apHandlers = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"
    Set-ItemProperty -Path $apHandlers -Name "DisableAutoplay" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue

    Write-Ok "AutoRun and AutoPlay restored."
}

# =============================================================================
#  GUEST ACCOUNT
# =============================================================================

function Disable-GuestAccount {
    Write-Info "Disabling the built-in Guest account..."
    net user Guest /active:no | Out-Null
    Write-Ok "Guest account disabled."
}

function Enable-GuestAccount {
    Write-Warn "WARNING: Enabling the Guest account reduces system security."
    net user Guest /active:yes | Out-Null
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

    # PowerShell script block logging
    $sbLog = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not (Test-Path $sbLog)) { New-Item -Path $sbLog -Force | Out-Null }
    Set-ItemProperty -Path $sbLog -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
    Write-Ok "PowerShell Script Block Logging enabled."

    # PowerShell module logging
    $modLog = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    if (-not (Test-Path $modLog)) { New-Item -Path $modLog -Force | Out-Null }
    Set-ItemProperty -Path $modLog -Name "EnableModuleLogging" -Value 1 -Type DWord -Force
    Write-Ok "PowerShell Module Logging enabled."

    # Increase Security event log size to 1 GB
    & wevtutil sl Security /ms:1073741824 2>&1 | Out-Null
    Write-Ok "Security event log maximum size set to 1 GB."
}

# =============================================================================
#  UNNECESSARY / RISKY SERVICES
# =============================================================================

function Disable-UnnecessaryServices {
    Write-Info "Disabling unnecessary and potentially risky services..."
    $services = @(
        @{Name='RemoteRegistry'; Display='Remote Registry'},
        @{Name='TlntSvr';        Display='Telnet'},
        @{Name='SSDPSRV';        Display='SSDP Discovery (UPnP)'},
        @{Name='upnphost';       Display='UPnP Device Host'},
        @{Name='SharedAccess';   Display='Internet Connection Sharing'},
        @{Name='lltdsvc';        Display='Link-Layer Topology Discovery'},
        @{Name='MSiSCSI';        Display='Microsoft iSCSI Initiator'},
        @{Name='WinRM';          Display='Windows Remote Management'},
        @{Name='SessionEnv';     Display='Remote Desktop Configuration'},
        @{Name='TermService';    Display='Remote Desktop Services'},
        @{Name='UmRdpService';   Display='RDP UserMode Port Redirector'}
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
        } else {
            Write-Warn "Service not installed: $($svc.Display)"
        }
    }
}

function Enable-UnnecessaryServices {
    Write-Info "Restoring previously disabled services to Manual startup..."
    $services = @('RemoteRegistry','SSDPSRV','upnphost','SharedAccess','lltdsvc')
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
    $wsh = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
    if (-not (Test-Path $wsh)) { New-Item -Path $wsh -Force | Out-Null }
    Set-ItemProperty -Path $wsh -Name "Enabled" -Value 0 -Type DWord -Force
    Write-Ok "Windows Script Host disabled."
}

function Enable-WindowsScriptHost {
    Write-Info "Enabling Windows Script Host..."
    $wsh = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
    if (-not (Test-Path $wsh)) { New-Item -Path $wsh -Force | Out-Null }
    Set-ItemProperty -Path $wsh -Name "Enabled" -Value 1 -Type DWord -Force
    Write-Ok "Windows Script Host enabled."
}

# =============================================================================
#  ANONYMOUS ACCESS, LLMNR & NBT-NS
# =============================================================================

function Disable-AnonymousAccess {
    Write-Info "Restricting anonymous network access..."
    $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $lsa -Name "RestrictAnonymous"        -Value 2 -Type DWord -Force
    Set-ItemProperty -Path $lsa -Name "RestrictAnonymousSAM"     -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $lsa -Name "EveryoneIncludesAnonymous" -Value 0 -Type DWord -Force
    Write-Ok "Anonymous access to shares and SAM restricted."

    Write-Info "Disabling LLMNR (prevents LLMNR-poisoning / relay attacks)..."
    $dns = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    if (-not (Test-Path $dns)) { New-Item -Path $dns -Force | Out-Null }
    Set-ItemProperty -Path $dns -Name "EnableMulticast" -Value 0 -Type DWord -Force
    Write-Ok "LLMNR disabled."

    Write-Info "Disabling NetBIOS over TCP/IP on all adapters (prevents MITM attacks)..."
    $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" -ErrorAction SilentlyContinue
    foreach ($a in $adapters) {
        Invoke-CimMethod -InputObject $a -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions = [uint32]2} -ErrorAction SilentlyContinue | Out-Null
    }  # TcpipNetbiosOptions 2 = Disable NetBIOS over TCP/IP
    Write-Ok "NetBIOS over TCP/IP disabled on all active adapters."
}

# =============================================================================
#  LSA / CREDENTIAL PROTECTION
# =============================================================================

function Enable-CredentialGuard {
    Write-Info "Enabling LSA Protection (RunAsPPL) to harden credential storage..."
    $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $lsa -Name "RunAsPPL"              -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $lsa -Name "DisableRestrictedAdmin" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $lsa -Name "DisableDomainCreds"     -Value 1 -Type DWord -Force

    # Prevent WDigest from caching plain-text credentials in memory
    $wdigest = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    if (-not (Test-Path $wdigest)) { New-Item -Path $wdigest -Force | Out-Null }
    Set-ItemProperty -Path $wdigest -Name "UseLogonCredential" -Value 0 -Type DWord -Force
    Write-Ok "WDigest plain-text credential caching disabled."

    Write-Ok "LSA Protection enabled — credentials protected from dumping tools."
    Write-Warn "A restart is required for LSA Protection (RunAsPPL) to take effect."
}

# =============================================================================
#  PRIVACY & TELEMETRY
# =============================================================================

function Disable-Telemetry {
    Write-Info "Disabling Windows Telemetry and data collection services..."

    # Stop and disable telemetry services
    foreach ($svc in @('DiagTrack', 'dmwappushservice')) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Set-Service  -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Ok "Service '$svc' stopped and disabled."
        }
    }

    # Set telemetry level to 0 (Security) via policy
    $dc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    if (-not (Test-Path $dc)) { New-Item -Path $dc -Force | Out-Null }
    Set-ItemProperty -Path $dc -Name "AllowTelemetry" -Value 0 -Type DWord -Force
    Write-Ok "Telemetry level set to 0 (Security)."

    # Disable Customer Experience Improvement Program (CEIP)
    $ceip = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"
    if (-not (Test-Path $ceip)) { New-Item -Path $ceip -Force | Out-Null }
    Set-ItemProperty -Path $ceip -Name "CEIPEnable" -Value 0 -Type DWord -Force
    Write-Ok "Customer Experience Improvement Program (CEIP) disabled."

    # Disable Application Impact Telemetry (AIT)
    $ait = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
    if (-not (Test-Path $ait)) { New-Item -Path $ait -Force | Out-Null }
    Set-ItemProperty -Path $ait -Name "AITEnable" -Value 0 -Type DWord -Force
    Write-Ok "Application Impact Telemetry (AIT) disabled."

    # Disable Windows Error Reporting
    $wer = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
    if (-not (Test-Path $wer)) { New-Item -Path $wer -Force | Out-Null }
    Set-ItemProperty -Path $wer -Name "Disabled" -Value 1 -Type DWord -Force
    Write-Ok "Windows Error Reporting disabled."
}

function Enable-Telemetry {
    Write-Info "Restoring Windows Telemetry to default settings..."
    $dc = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    Set-ItemProperty -Path $dc -Name "AllowTelemetry" -Value 3 -Type DWord -Force -ErrorAction SilentlyContinue
    foreach ($svc in @('DiagTrack', 'dmwappushservice')) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) { Set-Service -Name $svc -StartupType Automatic -ErrorAction SilentlyContinue }
    }
    Write-Ok "Telemetry restored to default."
}

function Disable-AdvertisingID {
    Write-Info "Disabling Advertising ID and content tracking..."

    # Per-user advertising ID
    $advInfo = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
    if (-not (Test-Path $advInfo)) { New-Item -Path $advInfo -Force | Out-Null }
    Set-ItemProperty -Path $advInfo -Name "Enabled" -Value 0 -Type DWord -Force
    Write-Ok "Advertising ID disabled (per user)."

    # System-wide policy
    $advPol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
    if (-not (Test-Path $advPol)) { New-Item -Path $advPol -Force | Out-Null }
    Set-ItemProperty -Path $advPol -Name "DisabledByGroupPolicy" -Value 1 -Type DWord -Force
    Write-Ok "Advertising ID policy disabled."

    # Disable suggested content and silent app installs
    $cdm = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    if (Test-Path $cdm) {
        $prefs = @(
            'SubscribedContent-338389Enabled',
            'SubscribedContent-338388Enabled',
            'SilentInstalledAppsEnabled',
            'SystemPaneSuggestionsEnabled',
            'SoftLandingEnabled'
        )
        foreach ($pref in $prefs) {
            Set-ItemProperty -Path $cdm -Name $pref -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        }
        Write-Ok "Suggested content and silent app installs disabled."
    }
}

function Disable-Cortana {
    Write-Info "Disabling Cortana and web search integration..."
    $search = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    if (-not (Test-Path $search)) { New-Item -Path $search -Force | Out-Null }
    Set-ItemProperty -Path $search -Name "AllowCortana"              -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $search -Name "AllowSearchToUseLocation"  -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $search -Name "DisableWebSearch"           -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $search -Name "ConnectedSearchUseWeb"      -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $search -Name "AllowCloudSearch"           -Value 0 -Type DWord -Force
    Write-Ok "Cortana and web search disabled via Group Policy."
}

# =============================================================================
#  ADVANCED SYSTEM HARDENING
# =============================================================================

function Disable-PrintSpooler {
    Write-Info "Disabling Print Spooler (mitigates PrintNightmare CVE-2021-34527)..."
    Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
    Set-Service  -Name Spooler -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Ok "Print Spooler service stopped and disabled."
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
    # Level 5 = send NTLMv2 responses only; refuse LM and NTLM
    Set-ItemProperty -Path $lsa -Name "LmCompatibilityLevel" -Value 5 -Type DWord -Force
    Write-Ok "LmCompatibilityLevel set to 5 (NTLMv2 only; refuse LM and NTLM)."

    # Do not store LAN Manager hash on next password change
    Set-ItemProperty -Path $lsa -Name "NoLMHash" -Value 1 -Type DWord -Force
    Write-Ok "LM hash storage disabled."

    # Require 128-bit session security for NTLM
    $msv = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    if (-not (Test-Path $msv)) { New-Item -Path $msv -Force | Out-Null }
    # 537395200 = Require 128-bit + NTLMv2 session security
    Set-ItemProperty -Path $msv -Name "NTLMMinClientSec" -Value 537395200 -Type DWord -Force
    Set-ItemProperty -Path $msv -Name "NTLMMinServerSec" -Value 537395200 -Type DWord -Force
    Write-Ok "NTLM minimum 128-bit session security enforced on client and server."
}

function Disable-PowerShellv2 {
    Write-Info "Disabling PowerShell v2 (prevents script-block logging bypass)..."
    $feat = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" `
            -ErrorAction SilentlyContinue
    if ($feat -and $feat.State -eq 'Enabled') {
        Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" `
            -NoRestart -ErrorAction SilentlyContinue | Out-Null
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

    # SEHOP (Structured Exception Handler Overwrite Protection)
    $kernel = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
    Set-ItemProperty -Path $kernel -Name "DisableExceptionChainValidation" -Value 0 -Type DWord -Force
    Write-Ok "SEHOP enabled."

    # DEP (Data Execution Prevention) — AlwaysOn
    & bcdedit /set nx AlwaysOn 2>&1 | Out-Null
    Write-Ok "DEP (NX) set to AlwaysOn."

    # Heap termination on corruption — system-wide via Set-ProcessMitigation
    try {
        Set-ProcessMitigation -System -Enable HeapTerminateOnCorruption -ErrorAction Stop
        Write-Ok "Heap Terminate on Corruption enabled (system-wide)."
    } catch {
        Write-Warn "Set-ProcessMitigation unavailable — heap mitigation skipped."
    }

    # Force ASLR — mandatory randomisation for images not compiled with ASLR
    try {
        Set-ProcessMitigation -System -Enable ForceRelocateImages -ErrorAction Stop
        Write-Ok "Force ASLR (mandatory image relocation) enabled."
    } catch {
        Write-Warn "Force ASLR via Set-ProcessMitigation not available on this system."
    }

    Write-Ok "Exploit Protection configured. A restart is recommended."
}

function Enable-ClearPageFileOnShutdown {
    Write-Info "Enabling clear page file at shutdown (prevents offline data recovery)..."
    $mm = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    Set-ItemProperty -Path $mm -Name "ClearPageFileAtShutdown" -Value 1 -Type DWord -Force
    Write-Ok "Page file will be cleared on every shutdown."
    Write-Warn "Shutdown will take longer because the page file must be zeroed."
}

function Disable-ClearPageFileOnShutdown {
    Write-Info "Disabling clear page file at shutdown (restoring default)..."
    $mm = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    Set-ItemProperty -Path $mm -Name "ClearPageFileAtShutdown" -Value 0 -Type DWord -Force
    Write-Ok "Page file clear on shutdown disabled."
}

function Disable-RemoteAssistance {
    Write-Info "Disabling Remote Assistance..."
    $ra = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
    if (-not (Test-Path $ra)) { New-Item -Path $ra -Force | Out-Null }
    Set-ItemProperty -Path $ra -Name "fAllowToGetHelp"   -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $ra -Name "fAllowFullControl" -Value 0 -Type DWord -Force

    $ts = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    if (-not (Test-Path $ts)) { New-Item -Path $ts -Force | Out-Null }
    Set-ItemProperty -Path $ts -Name "fAllowUnsolicited" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $ts -Name "fAllowToGetHelp"   -Value 0 -Type DWord -Force

    Get-NetFirewallRule -DisplayGroup "Remote Assistance" -ErrorAction SilentlyContinue |
        Disable-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Ok "Remote Assistance disabled and firewall rules deactivated."
}

function Enable-RemoteAssistance {
    Write-Info "Enabling Remote Assistance..."
    $ra = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
    if (-not (Test-Path $ra)) { New-Item -Path $ra -Force | Out-Null }
    Set-ItemProperty -Path $ra -Name "fAllowToGetHelp" -Value 1 -Type DWord -Force
    Write-Ok "Remote Assistance enabled."
}

# =============================================================================
#  NETWORK & DNS HARDENING
# =============================================================================

function Set-SecureDNS {
    Write-Info "Configuring secure DNS servers (Cloudflare 1.1.1.1 + Google 8.8.8.8) on all active adapters..."
    $dnsServers = @("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4")
    $adapters   = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
    if ($adapters.Count -eq 0) {
        Write-Warn "No active network adapters found."
        return
    }
    foreach ($a in $adapters) {
        try {
            Set-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex `
                -ServerAddresses $dnsServers -ErrorAction Stop
            Write-Ok "DNS set on '$($a.Name)': $($dnsServers -join ', ')."
        } catch {
            Write-Fail "Could not set DNS on '$($a.Name)': $_"
        }
    }
    Write-Ok "Secure DNS applied. Encrypted DNS (DoH) can be configured in Windows Settings > Network."
}

function Disable-IPv6 {
    Write-Info "Disabling IPv6 on all network adapters (reduces attack surface)..."
    $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue)
    foreach ($a in $adapters) {
        Disable-NetAdapterBinding -Name $a.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
    }
    # Registry fallback — disable all IPv6 components
    $ipv6 = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    if (-not (Test-Path $ipv6)) { New-Item -Path $ipv6 -Force | Out-Null }
    Set-ItemProperty -Path $ipv6 -Name "DisabledComponents" -Value 0xFF -Type DWord -Force
    Write-Ok "IPv6 disabled on all adapters."
    Write-Warn "If your network uses IPv6, some connectivity may be affected."
}

function Enable-IPv6 {
    Write-Info "Re-enabling IPv6 on all network adapters..."
    $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue)
    foreach ($a in $adapters) {
        Enable-NetAdapterBinding -Name $a.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
    }
    $ipv6 = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    Set-ItemProperty -Path $ipv6 -Name "DisabledComponents" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Ok "IPv6 re-enabled on all adapters."
}

# =============================================================================
#  ADDITIONAL HARDENING
# =============================================================================

function Enable-AutomaticUpdates {
    Write-Info "Configuring Windows Update for automatic installation..."
    $wu = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    if (-not (Test-Path $wu)) { New-Item -Path $wu -Force | Out-Null }
    Set-ItemProperty -Path $wu -Name "NoAutoUpdate"              -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $wu -Name "AUOptions"                 -Value 4 -Type DWord -Force  # Auto download and install
    Set-ItemProperty -Path $wu -Name "AutoInstallMinorUpdates"   -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $wu -Name "ScheduledInstallDay"      -Value 0 -Type DWord -Force  # Every day
    Set-ItemProperty -Path $wu -Name "ScheduledInstallTime"     -Value 3 -Type DWord -Force  # 03:00
    Write-Ok "Automatic Windows Updates enabled (daily at 03:00)."

    # Ensure Windows Update service is set to automatic
    $wuSvc = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    if ($wuSvc) {
        Set-Service -Name wuauserv -StartupType Automatic -ErrorAction SilentlyContinue
        Write-Ok "Windows Update service set to Automatic."
    }
}

function Set-ScreenLockTimeout {
    Write-Info "Setting screen auto-lock to 5 minutes and requiring password on wake..."

    # Screensaver with password lock
    $desktop = "HKCU:\Control Panel\Desktop"
    Set-ItemProperty -Path $desktop -Name "ScreenSaveActive"    -Value "1"   -Type String -Force
    Set-ItemProperty -Path $desktop -Name "ScreenSaveTimeOut"   -Value "300" -Type String -Force
    Set-ItemProperty -Path $desktop -Name "ScreenSaverIsSecure" -Value "1"   -Type String -Force
    Write-Ok "Screensaver timeout set to 5 minutes with password required."

    # Group Policy enforcement
    $gpDesktop = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
    if (-not (Test-Path $gpDesktop)) { New-Item -Path $gpDesktop -Force | Out-Null }
    Set-ItemProperty -Path $gpDesktop -Name "ScreenSaveTimeOut"   -Value "300" -Type String -Force
    Set-ItemProperty -Path $gpDesktop -Name "ScreenSaveActive"    -Value "1"   -Type String -Force
    Set-ItemProperty -Path $gpDesktop -Name "ScreenSaverIsSecure" -Value "1"   -Type String -Force

    # Require password on wake from sleep/hibernate
    & powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 1 2>&1 | Out-Null
    & powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 1 2>&1 | Out-Null
    & powercfg /setactive SCHEME_CURRENT 2>&1 | Out-Null
    Write-Ok "Password required on wake from sleep/hibernate."
}

function Rename-AdminAccount {
    Write-Info "Rename the built-in Administrator account (RID 500)..."
    $admin = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -match 'S-1-5-21-.*-500$' } | Select-Object -First 1
    if ($null -eq $admin) {
        Write-Fail "Could not locate the built-in Administrator account."
        return
    }
    Write-Host "  Current name: $($admin.Name)" -ForegroundColor Cyan
    $newName = Read-Host "  Enter new account name"
    $newName = $newName.Trim()
    if ([string]::IsNullOrWhiteSpace($newName)) {
        Write-Warn "No name entered — operation cancelled."
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
#  ATTACK SURFACE REDUCTION (ASR) RULES
# =============================================================================

function Enable-ASRRules {
    Write-Info "Enabling Windows Defender Attack Surface Reduction (ASR) rules..."
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
        @{Id='E6DB77E5-3DF2-4CF1-B95A-636979351E5B'; Name='Block WMI event subscription persistence'}
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
        Write-Warn "Some rules failed. Ensure Defender real-time protection is active (option 20)."
    } else {
        Write-Ok "All $($rules.Count) ASR rules enabled in Block mode."
    }
}

function Disable-ASRRules {
    Write-Info "Disabling all Windows Defender Attack Surface Reduction (ASR) rules..."
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
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
    Write-Ok "Execution policy set to RemoteSigned — local scripts run; downloaded scripts must be signed."
}

function Set-PSExecutionAllSigned {
    Write-Info "Setting PowerShell execution policy to AllSigned (LocalMachine scope)..."
    Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine -Force
    Write-Ok "Execution policy set to AllSigned — all scripts must carry a digital signature."
}

function Restore-PSExecutionDefault {
    Write-Info "Restoring PowerShell execution policy to Undefined (inherits system default)..."
    Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope LocalMachine -Force
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
    $apps     = @('Word', 'Excel', 'PowerPoint', 'Access', 'Outlook')
    $count    = 0
    foreach ($ver in $versions) {
        foreach ($app in $apps) {
            foreach ($hive in @('HKCU:', 'HKLM:')) {
                $path = "${hive}\SOFTWARE\Policies\Microsoft\Office\$ver\$app\Security"
                try {
                    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
                    # VBAWarnings 4 = disable all macros without notification
                    Set-ItemProperty -Path $path -Name "VBAWarnings" -Value 4 -Type DWord -Force -ErrorAction Stop
                    $count++
                } catch {}
            }
        }
    }
    Write-Ok "Office macro policy applied (VBAWarnings=4) — $count registry keys written."
    Write-Ok "Covers Office 2007–2016/365 for Word, Excel, PowerPoint, Access, Outlook."
}

function Enable-OfficeMacros {
    Write-Info "Removing Microsoft Office macro policy (restoring application defaults)..."
    $versions = @('12.0', '14.0', '15.0', '16.0')
    $apps     = @('Word', 'Excel', 'PowerPoint', 'Access', 'Outlook')
    foreach ($ver in $versions) {
        foreach ($app in $apps) {
            foreach ($hive in @('HKCU:', 'HKLM:')) {
                $path = "${hive}\SOFTWARE\Policies\Microsoft\Office\$ver\$app\Security"
                Remove-ItemProperty -Path $path -Name "VBAWarnings" -Force -ErrorAction SilentlyContinue
            }
        }
    }
    Write-Ok "Office macro policy removed — applications will use their built-in defaults."
}

# =============================================================================
#  FIREWALL ENHANCEMENTS
# =============================================================================

function Enable-FirewallLogging {
    Write-Info "Enabling Windows Firewall logging on all profiles (allowed + blocked)..."
    $logFile = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
    foreach ($profile in @('Domain', 'Private', 'Public')) {
        Set-NetFirewallProfile -Profile $profile `
            -LogAllowed True `
            -LogBlocked True `
            -LogFileName $logFile `
            -LogMaxSizeKilobytes 32767 `
            -ErrorAction SilentlyContinue
    }
    Write-Ok "Firewall logging enabled (allowed + blocked) for Domain, Private, Public profiles."
    Write-Ok "Log location: $logFile  (32767 KB max size per-profile setting; all profiles share the same file)."
}

function Set-FirewallBlockOutbound {
    Write-Warn "WARNING: Blocking all outbound traffic will break most network applications."
    Write-Warn "Only use this on air-gapped or highly controlled systems."
    Write-Info "Setting default outbound action to Block on all firewall profiles..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block
    Write-Ok "Default outbound action set to Block."
    Write-Warn "Add explicit outbound allow rules for required applications to restore connectivity."
}

function Restore-FirewallDefaultOutbound {
    Write-Info "Restoring default outbound action to Allow on all firewall profiles..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow
    Write-Ok "Default outbound action restored to Allow."
}

# =============================================================================
#  DRIVE ENCRYPTION (BITLOCKER)
# =============================================================================

function Show-BitLockerStatus {
    Write-Info "Checking BitLocker encryption status on all drives..."
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
        Write-Fail "BitLocker cmdlets unavailable: $_"
        Write-Warn "BitLocker requires Windows Pro/Enterprise/Education."
    }
}

function Enable-BitLockerSystem {
    Write-Info "Enabling BitLocker on system drive (C:) with XTS-AES 256 encryption..."
    try {
        $vol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
        if ($vol.ProtectionStatus -eq 'On') {
            Write-Warn "BitLocker is already enabled on C:."
            return
        }

        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        if ($tpm -and $tpm.TpmPresent -and $tpm.TpmReady) {
            Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 `
                -TpmProtector -ErrorAction Stop | Out-Null
            Write-Ok "BitLocker enabled on C: using TPM protector (XTS-AES 256)."
        } else {
            Write-Warn "TPM not available or not ready — a startup PIN is required."
            $pin = Read-Host "  Enter a 6+ digit startup PIN (blank to cancel)" -AsSecureString
            $pinPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pin))
            if ([string]::IsNullOrEmpty($pinPlain)) {
                Write-Warn "No PIN entered — operation cancelled."
                return
            }
            Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 `
                -TpmAndPinProtector -Pin $pin -ErrorAction Stop | Out-Null
            Write-Ok "BitLocker enabled on C: using TPM+PIN protector (XTS-AES 256)."
        }

        # Save recovery key to Desktop
        $rk = (Get-BitLockerVolume -MountPoint "C:").KeyProtector |
              Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -First 1
        if ($rk) {
            $keyPath = "$env:USERPROFILE\Desktop\BitLocker_RecoveryKey_C.txt"
            "BitLocker Recovery Key for C:  $($rk.RecoveryPassword)" | Set-Content -Path $keyPath
            Write-Ok "Recovery key saved: $keyPath"
            Write-Warn "Copy this key to a safe offline location, then delete it from the Desktop!"
        }

        Write-Ok "Encryption will proceed in the background — do not power off until complete."
    } catch {
        Write-Fail "Could not enable BitLocker: $_"
        Write-Warn "BitLocker requires Windows Pro/Enterprise/Education and a compatible TPM or startup key."
    }
}

# =============================================================================
#  REMOTE ACCESS HARDENING
# =============================================================================

function Disable-WinRM {
    Write-Info "Disabling PowerShell Remoting and WinRM service..."
    # Disable PS Remoting
    Disable-PSRemoting -Force -ErrorAction SilentlyContinue

    # Remove all WinRM listeners
    Remove-Item -Path WSMan:\Localhost\listener\* -Recurse -Force -ErrorAction SilentlyContinue

    # Stop and disable WinRM service
    Stop-Service -Name WinRM -Force          -ErrorAction SilentlyContinue
    Set-Service  -Name WinRM -StartupType Disabled -ErrorAction SilentlyContinue

    # Disable firewall rules for WinRM
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
#  SECURITY STATUS REPORT
# =============================================================================

function Show-SecurityStatus {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║           WINDOWS SECURITY STATUS REPORT                 ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    # UAC
    $uacVal = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
               -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
    $uacTxt = switch ($uacVal) {
        0 { "DISABLED — critical risk!"         }
        1 { "Require credentials (hardened)"    }
        2 { "Always Notify (hardened)"          }
        5 { "Default — notify on app changes"   }
        default { "Unknown ($uacVal)"           }
    }
    $uacColor = if ($uacVal -ge 1) { "Green" } else { "Red" }
    Write-Host "  UAC Level          : $uacTxt" -ForegroundColor $uacColor

    # Firewall
    $fw      = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    $fwOn    = ($fw | Where-Object Enabled -eq $true).Count
    $fwColor = if ($fwOn -eq 3) { "Green" } elseif ($fwOn -gt 0) { "Yellow" } else { "Red" }
    Write-Host "  Firewall           : $fwOn/3 profiles enabled" -ForegroundColor $fwColor

    # Defender
    $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mp) {
        $rtColor = if ($mp.RealTimeProtectionEnabled) { "Green" } else { "Red" }
        Write-Host "  Defender RT        : $(if ($mp.RealTimeProtectionEnabled){'Enabled'}else{'DISABLED'})" -ForegroundColor $rtColor
        Write-Host "  Def. Signatures    : $($mp.AntivirusSignatureLastUpdated)" -ForegroundColor Cyan
    } else {
        Write-Host "  Defender           : Status unavailable" -ForegroundColor Yellow
    }

    # RDP
    $rdp      = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
                 -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
    $rdpColor = if ($rdp -eq 1) { "Green" } else { "Yellow" }
    Write-Host "  RDP                : $(if ($rdp -eq 1){'Disabled (secure)'}else{'Enabled'})" -ForegroundColor $rdpColor

    # Remote Assistance
    $ra      = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" `
                -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue).fAllowToGetHelp
    $raColor = if ($ra -eq 0) { "Green" } else { "Yellow" }
    Write-Host "  Remote Assistance  : $(if ($ra -eq 0){'Disabled (secure)'}else{'Enabled'})" -ForegroundColor $raColor

    # SMBv1
    $smb1 = $null
    try { $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch {}
    if ($null -eq $smb1) {
        $r    = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
                 -Name "SMB1" -ErrorAction SilentlyContinue).SMB1
        $smb1 = ($r -ne 0)
    }
    $smb1Color = if (-not $smb1) { "Green" } else { "Red" }
    Write-Host "  SMBv1              : $(if (-not $smb1){'Disabled (secure)'}else{'ENABLED — vulnerable!'})" -ForegroundColor $smb1Color

    # Print Spooler
    $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    $spoolerOk = $spooler -and $spooler.StartType -eq 'Disabled'
    $spoolerColor = if ($spoolerOk) { "Green" } else { "Yellow" }
    Write-Host "  Print Spooler      : $(if ($spoolerOk){'Disabled (secure)'}else{'Enabled'})" -ForegroundColor $spoolerColor

    # NTLMv2
    $ntlm      = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
                  -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
    $ntlmColor = if ($ntlm -ge 5) { "Green" } elseif ($ntlm -ge 3) { "Yellow" } else { "Red" }
    $ntlmTxt   = switch ($ntlm) {
        5 { "NTLMv2 only (secure)"   }
        3 { "NTLMv2 + NTLMv1 (partial hardening)" }
        default { "LM/NTLMv1 allowed — weak!" }
    }
    Write-Host "  NTLM Level         : $ntlmTxt" -ForegroundColor $ntlmColor

    # USB Storage
    $usbStart = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor" `
                 -Name "Start" -ErrorAction SilentlyContinue).Start
    $usbColor = if ($usbStart -eq 4) { "Green" } else { "Yellow" }
    Write-Host "  USB Storage        : $(if ($usbStart -eq 4){'Disabled'}else{'Enabled'})" -ForegroundColor $usbColor

    # Guest Account
    $guestLine    = & net user Guest 2>&1 | Select-String "Account active"
    $guestEnabled = "$guestLine" -match "Yes"
    $guestColor   = if (-not $guestEnabled) { "Green" } else { "Red" }
    Write-Host "  Guest Account      : $(if (-not $guestEnabled){'Disabled (secure)'}else{'ENABLED — risky!'})" -ForegroundColor $guestColor

    # AutoRun
    $ar      = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
                -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
    $arColor = if ($ar -eq 0xFF) { "Green" } else { "Yellow" }
    Write-Host "  AutoRun            : $(if ($ar -eq 0xFF){'Fully disabled (secure)'}else{'Not fully disabled'})" -ForegroundColor $arColor

    # Windows Script Host
    $wsh      = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" `
                 -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    $wshColor = if ($wsh -eq 0) { "Green" } else { "Yellow" }
    Write-Host "  Script Host        : $(if ($wsh -eq 0){'Disabled (secure)'}else{'Enabled'})" -ForegroundColor $wshColor

    # LLMNR
    $llmnr      = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
                   -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast
    $llmnrColor = if ($llmnr -eq 0) { "Green" } else { "Yellow" }
    Write-Host "  LLMNR              : $(if ($llmnr -eq 0){'Disabled (secure)'}else{'Enabled'})" -ForegroundColor $llmnrColor

    # WDigest
    $wdigest      = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
                     -Name "UseLogonCredential" -ErrorAction SilentlyContinue).UseLogonCredential
    $wdigestColor = if ($wdigest -eq 0) { "Green" } else { "Red" }
    Write-Host "  WDigest (creds)    : $(if ($wdigest -eq 0){'Disabled (secure)'}else{'ENABLED — credentials at risk!'})" -ForegroundColor $wdigestColor

    # Telemetry
    $telem      = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
                   -Name "AllowTelemetry" -ErrorAction SilentlyContinue).AllowTelemetry
    $telemColor = if ($telem -eq 0) { "Green" } else { "Yellow" }
    Write-Host "  Telemetry          : $(if ($telem -eq 0){'Disabled (level 0)'}else{"Level $telem"})" -ForegroundColor $telemColor

    # Telemetry DiagTrack service
    $diagSvc   = Get-Service -Name DiagTrack -ErrorAction SilentlyContinue
    $diagColor = if ($diagSvc -and $diagSvc.StartType -eq 'Disabled') { "Green" } else { "Yellow" }
    Write-Host "  DiagTrack Service  : $(if ($diagSvc -and $diagSvc.StartType -eq 'Disabled'){'Disabled'}else{'Running/Enabled'})" -ForegroundColor $diagColor

    # Page file clear on shutdown
    $pfClear      = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
                     -Name "ClearPageFileAtShutdown" -ErrorAction SilentlyContinue).ClearPageFileAtShutdown
    $pfClearColor = if ($pfClear -eq 1) { "Green" } else { "Yellow" }
    Write-Host "  Clear Page File    : $(if ($pfClear -eq 1){'Enabled on shutdown'}else{'Disabled'})" -ForegroundColor $pfClearColor

    # SEHOP
    $sehop      = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
                   -Name "DisableExceptionChainValidation" -ErrorAction SilentlyContinue).DisableExceptionChainValidation
    $sehopColor = if ($sehop -eq 0) { "Green" } else { "Yellow" }
    Write-Host "  SEHOP              : $(if ($sehop -eq 0){'Enabled (secure)'}else{'Disabled'})" -ForegroundColor $sehopColor

    # IPv6
    $ipv6Comp  = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
                  -Name "DisabledComponents" -ErrorAction SilentlyContinue).DisabledComponents
    $ipv6Color = if ($ipv6Comp -eq 0xFF) { "Green" } else { "Cyan" }
    Write-Host "  IPv6               : $(if ($ipv6Comp -eq 0xFF){'Disabled'}else{'Enabled'})" -ForegroundColor $ipv6Color

    # Cortana
    $cortana      = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" `
                     -Name "AllowCortana" -ErrorAction SilentlyContinue).AllowCortana
    $cortanaColor = if ($cortana -eq 0) { "Green" } else { "Yellow" }
    Write-Host "  Cortana            : $(if ($cortana -eq 0){'Disabled (policy)'}else{'Enabled'})" -ForegroundColor $cortanaColor

    # ASR Rules
    $asrIds   = @()
    try { $asrIds = @((Get-MpPreference -ErrorAction Stop).AttackSurfaceReductionRules_Ids) } catch {}
    $asrColor = if ($asrIds.Count -ge 10) { "Green" } elseif ($asrIds.Count -gt 0) { "Yellow" } else { "Red" }
    Write-Host "  ASR Rules          : $($asrIds.Count) rule(s) configured$(if ($asrIds.Count -ge 10){' (hardened)'}elseif ($asrIds.Count -gt 0){' (partial)'}else{' — NONE configured!'})" -ForegroundColor $asrColor

    # PowerShell Execution Policy
    $psPolicy      = (Get-ExecutionPolicy -Scope LocalMachine)
    $psPolicyColor = if ($psPolicy -in @('AllSigned','RemoteSigned','Restricted')) { "Green" } else { "Yellow" }
    Write-Host "  PS Exec Policy     : $psPolicy$(if ($psPolicy -in @('AllSigned','RemoteSigned','Restricted')){' (secure)'}else{' — consider hardening'})" -ForegroundColor $psPolicyColor

    # Bluetooth
    $btSvc      = Get-Service -Name bthserv -ErrorAction SilentlyContinue
    $btColor    = if ($btSvc -and $btSvc.StartType -eq 'Disabled') { "Green" } else { "Yellow" }
    Write-Host "  Bluetooth          : $(if ($btSvc -and $btSvc.StartType -eq 'Disabled'){'Service Disabled'}elseif ($btSvc){'Service Enabled'}else{'Not present'})" -ForegroundColor $btColor

    # Office Macros
    $macroKey   = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security" `
                   -Name "VBAWarnings" -ErrorAction SilentlyContinue).VBAWarnings
    $macroColor = if ($macroKey -eq 4) { "Green" } else { "Yellow" }
    Write-Host "  Office Macros      : $(if ($macroKey -eq 4){'Disabled via policy'}else{'Not restricted by policy'})" -ForegroundColor $macroColor

    # BitLocker (C:)
    $bl = $null
    try { $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop } catch {}
    $blColor = if ($bl -and $bl.ProtectionStatus -eq 'On') { "Green" } else { "Red" }
    Write-Host "  BitLocker (C:)     : $(if ($bl -and $bl.ProtectionStatus -eq 'On'){'ENABLED (encrypted)'}elseif ($bl){'DISABLED — drive unencrypted!'}else{'Status unavailable (requires Pro/Enterprise)'})" -ForegroundColor $blColor

    # WinRM / PS Remoting
    $winrm      = Get-Service -Name WinRM -ErrorAction SilentlyContinue
    $winrmColor = if ($winrm -and $winrm.StartType -eq 'Disabled') { "Green" } else { "Yellow" }
    Write-Host "  WinRM / PS Remote  : $(if ($winrm -and $winrm.StartType -eq 'Disabled'){'Disabled (secure)'}elseif ($winrm){'Enabled'}else{'Not present'})" -ForegroundColor $winrmColor

    # Firewall Logging
    $fwLog      = (Get-NetFirewallProfile -Name Domain -ErrorAction SilentlyContinue).LogBlocked
    $fwLogColor = if ($fwLog -eq $true) { "Green" } else { "Yellow" }
    Write-Host "  Firewall Logging   : $(if ($fwLog -eq $true){'Enabled'}else{'Disabled'})" -ForegroundColor $fwLogColor

    Write-Host ""
}

# =============================================================================
#  APPLY ALL HARDENING
# =============================================================================

function Invoke-AllHardening {
    Write-Host ""
    Write-Host "  *** Applying ALL security hardening settings ***" -ForegroundColor Magenta
    Write-Host ""
    Enforce-UACPasswordPrompt
    Set-UACAlwaysNotify
    Set-AccountLockoutPolicy
    Set-StrongPasswordPolicy
    Disable-Cameras
    Disable-USBPorts
    Enable-WindowsFirewall
    Enable-FirewallLogging
    Disable-SMBv1
    Disable-RemoteDesktop
    Enable-WindowsDefender
    Enable-ASRRules
    Disable-AutoRun
    Disable-GuestAccount
    Enable-AuditPolicy
    Disable-UnnecessaryServices
    Disable-WindowsScriptHost
    Disable-AnonymousAccess
    Enable-CredentialGuard
    Disable-Telemetry
    Disable-AdvertisingID
    Disable-Cortana
    Disable-PrintSpooler
    Set-NTLMv2Only
    Disable-PowerShellv2
    Enable-ExploitProtection
    Enable-ClearPageFileOnShutdown
    Disable-RemoteAssistance
    Disable-WinRM
    Set-SecureDNS
    Disable-IPv6
    Enable-AutomaticUpdates
    Set-ScreenLockTimeout
    Disable-OfficeMacros
    Disable-Bluetooth
    Set-PSExecutionAllSigned
    Write-Host ""
    Write-Host "  *** All hardening tasks complete. ***" -ForegroundColor Magenta
    Write-Host "  *** A system restart is strongly recommended. ***" -ForegroundColor Yellow
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
    Write-Host "  ║              E N H A N C E R   v4.0                    ║" -ForegroundColor Magenta
    Write-Host "  ╚════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
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
    Write-Host "    6.  Enforce strong password policy (12 chars, 90-day)"
    Write-Host ""
    Write-Host "  ── Firewall & Network ───────────────────────────────────" -ForegroundColor Yellow
    Write-Host "    7.  Enable Windows Firewall + block dangerous ports"
    Write-Host "    8.  Disable Windows Firewall  [NOT recommended]"
    Write-Host "    9.  Disable SMBv1  (WannaCry / EternalBlue prevention)"
    Write-Host "   10.  Enable SMBv1  [NOT recommended]"
    Write-Host "   11.  Disable RDP"
    Write-Host "   12.  Enable  RDP"
    Write-Host "   13.  Disable anonymous access, LLMNR & NBT-NS"
    Write-Host ""
    Write-Host "  ── Devices & Storage ────────────────────────────────────" -ForegroundColor Yellow
    Write-Host "   14.  Disable USB storage"
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
    Write-Host "  ── Privacy & Telemetry ───────────────────────────────────" -ForegroundColor Yellow
    Write-Host "   29.  Disable Windows Telemetry (DiagTrack + policy)"
    Write-Host "   30.  Enable  Windows Telemetry (restore)"
    Write-Host "   31.  Disable Advertising ID & content tracking"
    Write-Host "   32.  Disable Cortana & web search"
    Write-Host ""
    Write-Host "  ── Advanced System Hardening ─────────────────────────────" -ForegroundColor Yellow
    Write-Host "   33.  Disable Print Spooler  (PrintNightmare prevention)"
    Write-Host "   34.  Enable  Print Spooler"
    Write-Host "   35.  Force NTLMv2 only  (disable LM / NTLMv1)"
    Write-Host "   36.  Disable PowerShell v2  (prevents logging bypass)"
    Write-Host "   37.  Enable  Exploit Protection  (DEP, SEHOP, ASLR, heap guard)"
    Write-Host "   38.  Enable  Clear Page File on Shutdown"
    Write-Host "   39.  Disable Clear Page File on Shutdown"
    Write-Host "   40.  Disable Remote Assistance"
    Write-Host "   41.  Enable  Remote Assistance"
    Write-Host ""
    Write-Host "  ── Network & DNS Hardening ───────────────────────────────" -ForegroundColor Yellow
    Write-Host "   42.  Set Secure DNS  (Cloudflare 1.1.1.1 + Google 8.8.8.8)"
    Write-Host "   43.  Disable IPv6  (reduce network attack surface)"
    Write-Host "   44.  Enable  IPv6"
    Write-Host ""
    Write-Host "  ── Additional Hardening ──────────────────────────────────" -ForegroundColor Yellow
    Write-Host "   45.  Force Automatic Windows Updates"
    Write-Host "   46.  Set screen auto-lock  (5-minute timeout)"
    Write-Host "   47.  Rename built-in Administrator account"
    Write-Host ""
    Write-Host "  ── Attack Surface Reduction (ASR) ────────────────────────" -ForegroundColor Yellow
    Write-Host "   51.  Enable Windows Defender ASR rules  (14 rules / Block mode)"
    Write-Host "   52.  Disable Windows Defender ASR rules"
    Write-Host ""
    Write-Host "  ── PowerShell Hardening ──────────────────────────────────" -ForegroundColor Yellow
    Write-Host "   53.  Set execution policy to RemoteSigned"
    Write-Host "   54.  Set execution policy to AllSigned  (strictest)"
    Write-Host "   55.  Restore execution policy to default"
    Write-Host ""
    Write-Host "  ── Wireless Security ─────────────────────────────────────" -ForegroundColor Yellow
    Write-Host "   56.  Disable Bluetooth"
    Write-Host "   57.  Enable  Bluetooth"
    Write-Host ""
    Write-Host "  ── Office & Application Security ─────────────────────────" -ForegroundColor Yellow
    Write-Host "   58.  Disable Microsoft Office macros  (all versions)"
    Write-Host "   59.  Enable  Microsoft Office macros  (restore)"
    Write-Host ""
    Write-Host "  ── Firewall Enhancements ─────────────────────────────────" -ForegroundColor Yellow
    Write-Host "   60.  Enable Firewall logging  (allowed + blocked, 32 MB)"
    Write-Host "   61.  Block all outbound traffic by default  [advanced]"
    Write-Host "   62.  Restore default outbound action  (Allow)"
    Write-Host ""
    Write-Host "  ── Drive Encryption (BitLocker) ──────────────────────────" -ForegroundColor Yellow
    Write-Host "   63.  Show BitLocker status on all drives"
    Write-Host "   64.  Enable BitLocker on system drive (C:)"
    Write-Host ""
    Write-Host "  ── Remote Access Hardening ───────────────────────────────" -ForegroundColor Yellow
    Write-Host "   65.  Disable PowerShell Remoting / WinRM"
    Write-Host "   66.  Enable  PowerShell Remoting / WinRM"
    Write-Host ""
    Write-Host "  ── Utilities ─────────────────────────────────────────────" -ForegroundColor Yellow
    Write-Host "   67.  Show security status report"
    Write-Host "   68.  Apply ALL hardening settings  [recommended]"
    Write-Host "   69.  Exit"
    Write-Host ""
    $choice = Read-Host "  Enter choice (1-47, 51-69)"
    return $choice
}

# =============================================================================
#  MAIN LOOP
# =============================================================================

do {
    $userChoice = Show-Menu

    switch ($userChoice) {
         1  { Enforce-UACPasswordPrompt          }
         2  { Set-UACAlwaysNotify                }
         3  { Restore-UACToNormal                }
         4  { Set-AccountLockoutPolicy           }
         5  { Disable-AccountLockoutPolicy       }
         6  { Set-StrongPasswordPolicy           }
         7  { Enable-WindowsFirewall             }
         8  { Disable-WindowsFirewall            }
         9  { Disable-SMBv1                      }
        10  { Enable-SMBv1                       }
        11  { Disable-RemoteDesktop              }
        12  { Enable-RemoteDesktop               }
        13  { Disable-AnonymousAccess            }
        14  { Disable-USBPorts                   }
        15  { Enable-USBPorts                    }
        16  { Disable-Cameras                    }
        17  { Enable-Cameras                     }
        18  { Disable-AutoRun                    }
        19  { Enable-AutoRun                     }
        20  { Enable-WindowsDefender             }
        21  { Disable-GuestAccount               }
        22  { Enable-GuestAccount                }
        23  { Disable-WindowsScriptHost          }
        24  { Enable-WindowsScriptHost           }
        25  { Disable-UnnecessaryServices        }
        26  { Enable-UnnecessaryServices         }
        27  { Enable-AuditPolicy                 }
        28  { Enable-CredentialGuard             }
        29  { Disable-Telemetry                  }
        30  { Enable-Telemetry                   }
        31  { Disable-AdvertisingID              }
        32  { Disable-Cortana                    }
        33  { Disable-PrintSpooler               }
        34  { Enable-PrintSpooler                }
        35  { Set-NTLMv2Only                     }
        36  { Disable-PowerShellv2               }
        37  { Enable-ExploitProtection           }
        38  { Enable-ClearPageFileOnShutdown     }
        39  { Disable-ClearPageFileOnShutdown    }
        40  { Disable-RemoteAssistance           }
        41  { Enable-RemoteAssistance            }
        42  { Set-SecureDNS                      }
        43  { Disable-IPv6                       }
        44  { Enable-IPv6                        }
        45  { Enable-AutomaticUpdates            }
        46  { Set-ScreenLockTimeout              }
        47  { Rename-AdminAccount                }
        51  { Enable-ASRRules                    }
        52  { Disable-ASRRules                   }
        53  { Set-PSExecutionRemoteSigned        }
        54  { Set-PSExecutionAllSigned           }
        55  { Restore-PSExecutionDefault         }
        56  { Disable-Bluetooth                  }
        57  { Enable-Bluetooth                   }
        58  { Disable-OfficeMacros               }
        59  { Enable-OfficeMacros                }
        60  { Enable-FirewallLogging             }
        61  { Set-FirewallBlockOutbound          }
        62  { Restore-FirewallDefaultOutbound    }
        63  { Show-BitLockerStatus               }
        64  { Enable-BitLockerSystem             }
        65  { Disable-WinRM                      }
        66  { Enable-WinRM                       }
        67  { Show-SecurityStatus                }
        68  { Invoke-AllHardening                }
        69  { Write-Host "  Exiting Windows Security Enhancer. Stay secure!" -ForegroundColor Magenta; break }
        default { Write-Warn "Invalid choice. Please enter a valid option number." }
    }

    if ($userChoice -ne 69) {
        Write-Host ""
        Read-Host "  Press ENTER to return to the menu"
    }
} while ($userChoice -ne 69)

