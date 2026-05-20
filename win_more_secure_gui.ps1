# =============================================================================
#  Windows Security Enhancer - WPF GUI  v5.2
#
#  Built on top of win_more_secure.ps1 (the engine).  Uses Windows Presentation
#  Foundation, which is built in to every supported Windows release - nothing
#  needs to be installed.
#
#  Launched via runner_gui.bat (auto-elevates).
# =============================================================================

[CmdletBinding()]
param([switch] $NoElevate)

# -----------------------------------------------------------------------------
#  Self-elevation
# -----------------------------------------------------------------------------
$identity   = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal  = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -and -not $NoElevate) {
    $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
    try {
        Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs -ErrorAction Stop
    } catch {
        # User cancelled the UAC prompt (or it could not be displayed).  WPF / Forms
        # aren't loaded yet, so report through the console - the GUI never gets to start.
        Write-Host ""
        Write-Host "  [-] Administrator privileges are required to run Windows Security Enhancer." -ForegroundColor Red
        Write-Host "  [!] Re-run as Administrator, or accept the UAC prompt." -ForegroundColor Yellow
        Read-Host "  Press ENTER to exit"
    }
    exit
}

# -----------------------------------------------------------------------------
#  Load engine
# -----------------------------------------------------------------------------
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$enginePath = Join-Path $scriptDir 'win_more_secure.ps1'
if (-not (Test-Path $enginePath)) {
    Add-Type -AssemblyName PresentationFramework
    [System.Windows.MessageBox]::Show("Engine file not found:`n$enginePath","Windows Security Enhancer","OK","Error") | Out-Null
    exit 1
}

# Dot-source the engine with -NoElevate (skip self-elevation, we already did it)
# and -NoMenu (don't enter the CLI menu loop - we own the UI here).  This makes
# every Verb-Noun function (Set-*, Enable-*, Disable-*, ...) available in scope.
. $enginePath -NoElevate -NoMenu

# -----------------------------------------------------------------------------
#  Load WPF assemblies (all built in to Windows since Vista)
# -----------------------------------------------------------------------------
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml

# =============================================================================
#  XAML for the main window
# =============================================================================
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Windows Security Enhancer"
        Height="760" Width="1180"
        MinHeight="600" MinWidth="980"
        WindowStartupLocation="CenterScreen"
        Background="#1A1D24" FontFamily="Segoe UI" FontSize="13"
        TextOptions.TextFormattingMode="Display"
        TextOptions.TextRenderingMode="ClearType">

    <Window.Resources>
        <SolidColorBrush x:Key="BgDark"     Color="#1A1D24"/>
        <SolidColorBrush x:Key="BgPanel"    Color="#232734"/>
        <SolidColorBrush x:Key="BgCard"     Color="#2A2F3D"/>
        <SolidColorBrush x:Key="BgHover"    Color="#323848"/>
        <SolidColorBrush x:Key="Stroke"     Color="#2C313C"/>
        <SolidColorBrush x:Key="Text"       Color="#E6E9EF"/>
        <SolidColorBrush x:Key="SubText"    Color="#95A0B3"/>
        <SolidColorBrush x:Key="MutedText"  Color="#7C8B9F"/>
        <SolidColorBrush x:Key="Accent"     Color="#5B9DF9"/>
        <SolidColorBrush x:Key="AccentHover" Color="#7AB1FA"/>
        <SolidColorBrush x:Key="Good"       Color="#3FBF60"/>
        <SolidColorBrush x:Key="Bad"        Color="#EF4747"/>
        <SolidColorBrush x:Key="Warn"       Color="#E9C34D"/>

        <!-- Section button -->
        <Style x:Key="NavButton" TargetType="RadioButton">
            <Setter Property="Foreground" Value="{StaticResource SubText}"/>
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Padding" Value="18,12"/>
            <Setter Property="HorizontalContentAlignment" Value="Left"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="RadioButton">
                        <Border x:Name="bd" Background="{TemplateBinding Background}" Padding="{TemplateBinding Padding}" CornerRadius="6">
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="4"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <Border x:Name="accent" Grid.Column="0" Background="Transparent" CornerRadius="2"/>
                                <ContentPresenter Grid.Column="1" Margin="12,0,0,0" VerticalAlignment="Center"/>
                            </Grid>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="bd" Property="Background" Value="{StaticResource BgHover}"/>
                            </Trigger>
                            <Trigger Property="IsChecked" Value="True">
                                <Setter TargetName="bd" Property="Background" Value="{StaticResource BgPanel}"/>
                                <Setter TargetName="accent" Property="Background" Value="{StaticResource Accent}"/>
                                <Setter Property="Foreground" Value="{StaticResource Text}"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Primary action button -->
        <Style x:Key="ActionButton" TargetType="Button">
            <Setter Property="Background" Value="{StaticResource Accent}"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Padding" Value="14,7"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" CornerRadius="6" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="{StaticResource AccentHover}"/>
                </Trigger>
                <Trigger Property="IsEnabled" Value="False">
                    <Setter Property="Opacity" Value="0.45"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <Style x:Key="SecondaryButton" TargetType="Button" BasedOn="{StaticResource ActionButton}">
            <Setter Property="Background" Value="{StaticResource BgCard}"/>
            <Setter Property="Foreground" Value="{StaticResource Text}"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="{StaticResource BgHover}"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <Style x:Key="DangerButton" TargetType="Button" BasedOn="{StaticResource ActionButton}">
            <Setter Property="Background" Value="#5b2d2d"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#7c3838"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <Style TargetType="ScrollBar">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Width" Value="10"/>
        </Style>
    </Window.Resources>

    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- HEADER -->
        <Border Grid.Row="0" Background="{StaticResource BgPanel}" BorderBrush="{StaticResource Stroke}" BorderThickness="0,0,0,1">
            <Grid Margin="20,14">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Center">
                    <Border Width="34" Height="34" Background="{StaticResource Accent}" CornerRadius="8" Margin="0,0,12,0">
                        <TextBlock Text="W" Foreground="White" FontWeight="Bold" FontSize="20" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                    </Border>
                    <StackPanel VerticalAlignment="Center">
                        <TextBlock Text="Windows Security Enhancer" FontSize="17" FontWeight="SemiBold" Foreground="{StaticResource Text}"/>
                        <TextBlock x:Name="HeaderSub" Text="Loading system information..." FontSize="11" Foreground="{StaticResource SubText}"/>
                    </StackPanel>
                </StackPanel>
                <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
                    <Border Background="{StaticResource BgCard}" CornerRadius="20" Padding="14,7" Margin="0,0,10,0">
                        <StackPanel Orientation="Horizontal">
                            <TextBlock Text="Score: " Foreground="{StaticResource SubText}" FontSize="11" VerticalAlignment="Center"/>
                            <TextBlock x:Name="ScoreBadge" Text="--%" Foreground="{StaticResource Text}" FontWeight="Bold" FontSize="13" VerticalAlignment="Center"/>
                        </StackPanel>
                    </Border>
                    <Button x:Name="BtnRefresh"  Style="{StaticResource SecondaryButton}" Content="Refresh status" Margin="0,0,8,0"/>
                    <Button x:Name="BtnReport"   Style="{StaticResource SecondaryButton}" Content="Export HTML report" Margin="0,0,8,0"/>
                    <Button x:Name="BtnRollback" Style="{StaticResource DangerButton}"    Content="Rollback..."/>
                </StackPanel>
            </Grid>
        </Border>

        <!-- BODY -->
        <Grid Grid.Row="1">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="240"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="340"/>
            </Grid.ColumnDefinitions>

            <!-- LEFT: Navigation -->
            <Border Grid.Column="0" Background="{StaticResource BgDark}" BorderBrush="{StaticResource Stroke}" BorderThickness="0,0,1,0">
                <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
                    <StackPanel x:Name="NavPanel" Margin="10,12"/>
                </ScrollViewer>
            </Border>

            <!-- MIDDLE: Features -->
            <Grid Grid.Column="1" Background="{StaticResource BgDark}">
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="*"/>
                </Grid.RowDefinitions>
                <Border Grid.Row="0" Padding="20,16" BorderBrush="{StaticResource Stroke}" BorderThickness="0,0,0,1">
                    <StackPanel>
                        <TextBlock x:Name="CategoryTitle" Text="" FontSize="20" FontWeight="SemiBold" Foreground="{StaticResource Text}"/>
                        <TextBlock x:Name="CategoryDesc"  Text="" FontSize="12" Foreground="{StaticResource SubText}" Margin="0,4,0,0" TextWrapping="Wrap"/>
                    </StackPanel>
                </Border>
                <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled" Padding="20,16">
                    <StackPanel x:Name="FeaturePanel"/>
                </ScrollViewer>
            </Grid>

            <!-- RIGHT: Status + Log -->
            <Border Grid.Column="2" Background="{StaticResource BgPanel}" BorderBrush="{StaticResource Stroke}" BorderThickness="1,0,0,0">
                <Grid>
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="220"/>
                    </Grid.RowDefinitions>
                    <Border Grid.Row="0" Padding="18,14" BorderBrush="{StaticResource Stroke}" BorderThickness="0,0,0,1">
                        <StackPanel>
                            <TextBlock Text="SECURITY POSTURE" FontSize="11" Foreground="{StaticResource MutedText}" FontWeight="SemiBold"/>
                            <TextBlock x:Name="StatusSummary" Text="-" FontSize="13" Foreground="{StaticResource Text}" Margin="0,4,0,0"/>
                        </StackPanel>
                    </Border>
                    <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled" Padding="14,8">
                        <StackPanel x:Name="StatusPanel"/>
                    </ScrollViewer>
                    <Border Grid.Row="2" Background="#161922" BorderBrush="{StaticResource Stroke}" BorderThickness="0,1,0,0">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>
                            <TextBlock Grid.Row="0" Text="ACTIVITY LOG" FontSize="11" Foreground="{StaticResource MutedText}" FontWeight="SemiBold" Margin="14,10,14,4"/>
                            <ScrollViewer Grid.Row="1" x:Name="LogScroll" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" Padding="14,0,14,10">
                                <TextBlock x:Name="LogText" FontFamily="Consolas" FontSize="11" Foreground="{StaticResource SubText}" TextWrapping="NoWrap"/>
                            </ScrollViewer>
                        </Grid>
                    </Border>
                </Grid>
            </Border>
        </Grid>

        <!-- FOOTER -->
        <Border Grid.Row="2" Background="{StaticResource BgPanel}" BorderBrush="{StaticResource Stroke}" BorderThickness="0,1,0,0">
            <Grid Margin="20,10">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <TextBlock Grid.Column="0" x:Name="FooterText" Text="Ready" Foreground="{StaticResource SubText}" FontSize="11" VerticalAlignment="Center"/>
                <StackPanel Grid.Column="1" Orientation="Horizontal">
                    <Button x:Name="BtnQuickWin"  Style="{StaticResource ActionButton}" Content="Apply Quick Win" Margin="0,0,8,0"/>
                    <Button x:Name="BtnApplyAll"  Style="{StaticResource DangerButton}" Content="Apply ALL hardening"/>
                </StackPanel>
            </Grid>
        </Border>
    </Grid>
</Window>
'@

# Load XAML
$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

# Pull controls
$ctrls = @{}
foreach ($n in 'HeaderSub','ScoreBadge','BtnRefresh','BtnReport','BtnRollback','NavPanel',
               'CategoryTitle','CategoryDesc','FeaturePanel','StatusSummary','StatusPanel',
               'LogText','LogScroll','FooterText','BtnQuickWin','BtnApplyAll') {
    $ctrls[$n] = $window.FindName($n)
}

# =============================================================================
#  Feature catalogue   -   pairs each menu option with a callable script block
# =============================================================================
$catalogue = [ordered]@{
    'Overview' = @{
        Desc = 'A quick-glance dashboard of your hardening posture. Use the side menu to drill into individual controls or run a preset from the footer.'
        Items = @()
    }
    'UAC & Authentication' = @{
        Desc = 'Tighten User Account Control prompts and password / lockout policy.'
        Items = @(
            @{Title='Enforce UAC credential prompt'; Note='Require admins to enter their password for elevation.'; Action={Set-UACPasswordPrompt}; Risk='safe'},
            @{Title='UAC Always Notify'; Note='Maximum UAC level (cannot be silently bypassed).'; Action={Set-UACAlwaysNotify}; Risk='safe'},
            @{Title='Restore UAC default'; Note='Reset to the Windows default level.'; Action={Restore-UACToNormal}; Risk='restore'},
            @{Title='Account lockout policy'; Note='5 failed attempts = 30-minute lockout.'; Action={Set-AccountLockoutPolicy}; Risk='safe'},
            @{Title='Restore lockout default'; Note='Remove the lockout policy.'; Action={Disable-AccountLockoutPolicy}; Risk='restore'},
            @{Title='Strong password policy'; Note='14 characters, complexity, 90-day expiry, history 10.'; Action={Set-StrongPasswordPolicy}; Risk='safe'}
        )
    }
    'Firewall & Network' = @{
        Desc = 'Windows Firewall configuration, SMB, RDP, LLMNR/NBT-NS/mDNS poisoning prevention.'
        Items = @(
            @{Title='Enable Windows Firewall + block hostile ports'; Note='Telnet, RPC, NetBIOS, SMB, RDP, MSSQL, WinRM blocked on Public.'; Action={Enable-WindowsFirewall}; Risk='safe'},
            @{Title='Disable Windows Firewall'; Note='Removes a critical defence layer.'; Action={Disable-WindowsFirewall}; Risk='danger'},
            @{Title='Disable SMBv1'; Note='Prevents WannaCry / EternalBlue.'; Action={Disable-SMBv1}; Risk='safe'},
            @{Title='Enable SMBv1'; Note='Legacy compatibility - insecure.'; Action={Enable-SMBv1}; Risk='danger'},
            @{Title='Disable RDP'; Note='Block remote desktop entirely.'; Action={Disable-RemoteDesktop}; Risk='safe'},
            @{Title='Enable RDP (NLA + High encryption)'; Note='Only enable if you actually use RDP.'; Action={Enable-RemoteDesktop}; Risk='restore'},
            @{Title='Disable anonymous + LLMNR + NBT-NS + mDNS'; Note='Mitigates network credential-relay attacks.'; Action={Disable-AnonymousAccess}; Risk='safe'},
            @{Title='Enable firewall logging'; Note='Logs allowed + blocked traffic (32 MB).'; Action={Enable-FirewallLogging}; Risk='safe'},
            @{Title='Firewall stealth mode'; Note='Block ICMP echo on the Public profile (drops pings).'; Action={Set-FirewallStealthMode}; Risk='safe'},
            @{Title='Harden RDP redirection'; Note='Block clipboard / drive / printer / port redirection.'; Action={Disable-RDPRedirection}; Risk='safe'},
            @{Title='Restore RDP redirection'; Note='Allow clipboard / drive sharing again.'; Action={Restore-RDPRedirection}; Risk='restore'},
            @{Title='Block all outbound (advanced)'; Note='Type BLOCK-OUTBOUND in console to confirm.'; Action={Set-FirewallBlockOutbound}; Risk='danger'},
            @{Title='Restore default outbound'; Note='Allow outbound traffic again.'; Action={Restore-FirewallDefaultOutbound}; Risk='restore'}
        )
    }
    'Devices & Storage' = @{
        Desc = 'USB mass storage, cameras, AutoRun/AutoPlay.'
        Items = @(
            @{Title='Disable USB storage'; Note='HID devices (keyboard / mouse) remain working.'; Action={Disable-USBPorts}; Risk='safe'},
            @{Title='Enable USB storage'; Note='Restore USB sticks / external drives.'; Action={Enable-USBPorts}; Risk='restore'},
            @{Title='Disable cameras'; Note='PnP disable + policy lockdown.'; Action={Disable-Cameras}; Risk='safe'},
            @{Title='Enable cameras'; Note=''; Action={Enable-Cameras}; Risk='restore'},
            @{Title='Disable AutoRun / AutoPlay'; Note='Blocks removable-media autorun malware.'; Action={Disable-AutoRun}; Risk='safe'},
            @{Title='Enable AutoRun / AutoPlay'; Note=''; Action={Enable-AutoRun}; Risk='restore'},
            @{Title='Disable Bluetooth'; Note='Disables service + paired devices.'; Action={Disable-Bluetooth}; Risk='safe'},
            @{Title='Enable Bluetooth'; Note=''; Action={Enable-Bluetooth}; Risk='restore'}
        )
    }
    'Defender & ASR' = @{
        Desc = 'Maximum-protection Defender config + Attack Surface Reduction rules.'
        Items = @(
            @{Title='Configure Defender (max)'; Note='RT, cloud, BAFS, PUA, network, CFA, behaviour, IOAV.'; Action={Enable-WindowsDefender}; Risk='safe'},
            @{Title='Schedule Defender quick-scan + sigs'; Note='Daily 02:00 quick scan, sigs every 4 h.'; Action={Set-DefenderSchedule}; Risk='safe'},
            @{Title='Show Tamper-Protection status'; Note='Read-only - toggle in Windows Security UI.'; Action={Show-DefenderTamperStatus}; Risk='info'},
            @{Title='Enable 16 ASR rules (Block mode)'; Note='Office, scripts, LSASS, USB, Adobe Reader, drivers.'; Action={Enable-ASRRules}; Risk='safe'},
            @{Title='Disable all ASR rules'; Note=''; Action={Disable-ASRRules}; Risk='restore'},
            @{Title='Enable SmartScreen everywhere'; Note='Explorer, Edge, Apps & Files, Store.'; Action={Enable-SmartScreen}; Risk='safe'}
        )
    }
    'Accounts & Scripts' = @{
        Desc = 'Built-in accounts, scripting hosts, Office macros.'
        Items = @(
            @{Title='Disable Guest account'; Note=''; Action={Disable-GuestAccount}; Risk='safe'},
            @{Title='Enable Guest account'; Note='Weakens security.'; Action={Enable-GuestAccount}; Risk='danger'},
            @{Title='Disable Windows Script Host'; Note='Blocks .vbs / .js malware.'; Action={Disable-WindowsScriptHost}; Risk='safe'},
            @{Title='Enable Windows Script Host'; Note=''; Action={Enable-WindowsScriptHost}; Risk='restore'},
            @{Title='Rename built-in Administrator'; Note='Interactive - prompts in the console.'; Action={Rename-AdminAccount}; Risk='info'},
            @{Title='Disable Office macros (+ MOTW)'; Note='Word / Excel / PowerPoint / Outlook / Access / Publisher / Visio.'; Action={Disable-OfficeMacros}; Risk='safe'},
            @{Title='Enable Office macros'; Note=''; Action={Enable-OfficeMacros}; Risk='restore'},
            @{Title='Set PowerShell -> RemoteSigned'; Note=''; Action={Set-PSExecutionRemoteSigned}; Risk='safe'},
            @{Title='Set PowerShell -> AllSigned'; Note='Strictest. Type ALLSIGNED in console.'; Action={Set-PSExecutionAllSigned}; Risk='danger'},
            @{Title='Restore PowerShell policy'; Note=''; Action={Restore-PSExecutionDefault}; Risk='restore'}
        )
    }
    'Services & Audit' = @{
        Desc = 'Stop risky services, enable comprehensive logging, harden LSA.'
        Items = @(
            @{Title='Disable risky services'; Note='Remote Reg, Telnet, SSDP, UPnP, ICS, LLTD, iSCSI, WebClient...'; Action={Disable-UnnecessaryServices}; Risk='safe'},
            @{Title='Restore disabled services'; Note='Set them back to Manual start.'; Action={Enable-UnnecessaryServices}; Risk='restore'},
            @{Title='Enable comprehensive audit policy'; Note='+ PS script-block / module / transcription logs.'; Action={Enable-AuditPolicy}; Risk='safe'},
            @{Title='Enable LSA / Credential Guard'; Note='RunAsPPL, WDigest off, VBS keys.'; Action={Enable-CredentialGuard}; Risk='safe'},
            @{Title='Enable Memory Integrity (VBS + HVCI)'; Note='Requires CPU virt + Secure Boot.'; Action={Enable-MemoryIntegrity}; Risk='safe'},
            @{Title='Disable Print Spooler'; Note='PrintNightmare prevention. Disables ALL printing.'; Action={Disable-PrintSpooler}; Risk='danger'},
            @{Title='Enable Print Spooler'; Note='Re-enable printing.'; Action={Enable-PrintSpooler}; Risk='restore'},
            @{Title='Force NTLMv2 only'; Note='Disables LM + NTLMv1.'; Action={Set-NTLMv2Only}; Risk='safe'},
            @{Title='Disable PowerShell v2'; Note='Closes script-block-logging bypass.'; Action={Disable-PowerShellv2}; Risk='safe'},
            @{Title='Enable Exploit Protection'; Note='DEP, SEHOP, ASLR, CFG, heap guard.'; Action={Enable-ExploitProtection}; Risk='safe'},
            @{Title='Disable WebClient (WebDAV)'; Note='Blocks NTLM-over-WebDAV relay.'; Action={Disable-WebClient}; Risk='safe'},
            @{Title='Disable WPAD'; Note='Stops WinHttpAutoProxy + hosts entry.'; Action={Disable-WPAD}; Risk='safe'},
            @{Title='Disable Quick Assist'; Note='Tech-support-scam vector.'; Action={Disable-QuickAssist}; Risk='safe'}
        )
    }
    'Privacy & Telemetry' = @{
        Desc = 'Cut off telemetry, advertising tracking, Cortana, OneDrive, Xbox, Consumer features.'
        Items = @(
            @{Title='Disable Windows Telemetry'; Note='DiagTrack + dmwappushservice + CEIP + AIT.'; Action={Disable-Telemetry}; Risk='safe'},
            @{Title='Enable Telemetry'; Note='Restore Microsoft defaults.'; Action={Enable-Telemetry}; Risk='restore'},
            @{Title='Disable Advertising ID'; Note='+ Suggested apps / spotlight / silent installs.'; Action={Disable-AdvertisingID}; Risk='safe'},
            @{Title='Disable Cortana + web search'; Note=''; Action={Disable-Cortana}; Risk='safe'},
            @{Title='Disable consumer features'; Note='Store auto-install, spotlight, lock-screen ads.'; Action={Disable-ConsumerFeatures}; Risk='safe'},
            @{Title='Disable OneDrive (policy)'; Note=''; Action={Disable-OneDrive}; Risk='safe'},
            @{Title='Disable Xbox + Game DVR'; Note=''; Action={Disable-XboxServices}; Risk='safe'},
            @{Title='Harden Microsoft Edge'; Note='Telemetry off, sync off, sign-in blocked, strict tracking.'; Action={Set-EdgeHardening}; Risk='safe'},
            @{Title='Restore Edge defaults'; Note=''; Action={Restore-EdgeDefaults}; Risk='restore'},
            @{Title='Block adding Microsoft accounts'; Note='Existing MS-account-linked profiles still work.'; Action={Disable-MicrosoftAccount}; Risk='safe'},
            @{Title='Allow Microsoft accounts'; Note='Default behaviour.'; Action={Enable-MicrosoftAccount}; Risk='restore'}
        )
    }
    'Network Crypto' = @{
        Desc = 'TLS / SChannel, SMB and LDAP signing, DNS over HTTPS, IPv6 transition tech.'
        Items = @(
            @{Title='Set Secure DNS (Cloudflare + Quad9)'; Note=''; Action={Set-SecureDNS}; Risk='safe'},
            @{Title='Enable DNS-over-HTTPS'; Note='Requires Windows 11 22H2 or Server 2022+.'; Action={Enable-DNSOverHTTPS}; Risk='safe'},
            @{Title='Harden SChannel (TLS)'; Note='Disable SSL3/TLS1.0/1.1 + weak ciphers.'; Action={Set-SChannelHardening}; Risk='safe'},
            @{Title='Restore SChannel defaults'; Note=''; Action={Restore-SChannelDefaults}; Risk='restore'},
            @{Title='Enforce SMB signing'; Note='Client + server.'; Action={Set-SMBSigningRequired}; Risk='safe'},
            @{Title='Enforce LDAP signing'; Note='+ Channel binding.'; Action={Set-LDAPSigningRequired}; Risk='safe'},
            @{Title='Disable IPv6'; Note='May break IPv6-only networks.'; Action={Disable-IPv6}; Risk='danger'},
            @{Title='Enable IPv6'; Note=''; Action={Enable-IPv6}; Risk='restore'},
            @{Title='Disable IPv6 transition (Teredo / ISATAP / 6to4)'; Note=''; Action={Disable-IPv6TransitionTech}; Risk='safe'}
        )
    }
    'Encryption & Storage' = @{
        Desc = 'BitLocker, page-file clearing, hibernation.'
        Items = @(
            @{Title='Show BitLocker status'; Note=''; Action={Show-BitLockerStatus}; Risk='info'},
            @{Title='Enable BitLocker on C:'; Note='Interactive - prompts for PIN in console if no TPM.'; Action={Enable-BitLockerSystem}; Risk='safe'},
            @{Title='Clear page file on shutdown'; Note='Longer shutdown but prevents data recovery.'; Action={Enable-ClearPageFileOnShutdown}; Risk='safe'},
            @{Title='Disable clear page file'; Note=''; Action={Disable-ClearPageFileOnShutdown}; Risk='restore'},
            @{Title='Disable hibernation'; Note='Purges hiberfil.sys.'; Action={Disable-Hibernation}; Risk='safe'}
        )
    }
    'Remote Access' = @{
        Desc = 'PowerShell Remoting, Remote Assistance.'
        Items = @(
            @{Title='Disable PowerShell Remoting / WinRM'; Note=''; Action={Disable-WinRM}; Risk='safe'},
            @{Title='Enable PowerShell Remoting / WinRM'; Note=''; Action={Enable-WinRM}; Risk='restore'},
            @{Title='Disable Remote Assistance'; Note=''; Action={Disable-RemoteAssistance}; Risk='safe'},
            @{Title='Enable Remote Assistance'; Note=''; Action={Enable-RemoteAssistance}; Risk='restore'}
        )
    }
    'Maintenance' = @{
        Desc = 'Updates, screen lock, restore points.'
        Items = @(
            @{Title='Force Automatic Windows Updates'; Note='Daily install at 03:00.'; Action={Enable-AutomaticUpdates}; Risk='safe'},
            @{Title='Screen auto-lock (5 min)'; Note=''; Action={Set-ScreenLockTimeout}; Risk='safe'},
            @{Title='Create System Restore Point'; Note='Use before big changes.'; Action={New-WSERestorePoint}; Risk='safe'},
            @{Title='Show OS / capability report'; Note=''; Action={Show-CapabilityReport}; Risk='info'},
            @{Title='Show security status report (console)'; Note=''; Action={Show-SecurityStatus}; Risk='info'}
        )
    }
    'Diagnostics' = @{
        Desc = 'Read-only inspection of system state. Useful before and after applying hardening.'
        Items = @(
            @{Title='Show open / listening ports'; Note='Lists TCP & UDP listeners with owning process names.'; Action={Show-OpenListeningPorts}; Risk='info'},
            @{Title='Test for pending reboot'; Note='Many controls (HVCI, LSA Protection) only engage after a reboot.'; Action={Test-WSEPendingReboot}; Risk='info'},
            @{Title='Show recent logon events'; Note='Last 20 successful + failed logons from the Security log.'; Action={Show-RecentLogonEvents}; Risk='info'}
        )
    }
    'Threat Hunt' = @{
        Desc = 'Heuristic indicator-of-compromise sweep with optional auto-remediation. Same code path on ARM64 and x64 (Intel + AMD).'
        Items = @(
            @{Title='Threat scan (heuristic IOC sweep)'; Note='AppInit_DLLs, IFEO hijacks, BootExecute, Run keys, scheduled tasks, WMI subscriptions, LSA packages, hosts file, DNS, Defender exclusions, Security log state, RMM tools, startup-folder scripts, Winlogon Shell/Userinit, VSS.'; Action={Invoke-WSEThreatScan | Out-Null}; Risk='info'},
            @{Title='Threat remediation (apply auto-fixes)'; Note='Iterates the latest scan findings and offers an auto-fix for each one with a registered remediation. Each fix is confirmed individually.'; Action={Invoke-WSEThreatRemediation}; Risk='danger'}
        )
    }
}

# -----------------------------------------------------------------------------
#  UI helpers
# -----------------------------------------------------------------------------
$Script:Busy       = $false
$Script:LogBuffer  = New-Object System.Text.StringBuilder
$Script:NavLookup  = @{}

function Append-Log {
    param([string] $line, [string] $kind = 'info')
    $stamp = (Get-Date).ToString('HH:mm:ss')
    $prefix = switch ($kind) { 'ok' {'[+]'} 'warn' {'[!]'} 'fail' {'[-]'} default {'[*]'} }
    [void]$Script:LogBuffer.AppendLine("$stamp  $prefix $line")
    $ctrls.LogText.Text = $Script:LogBuffer.ToString()
    $ctrls.LogScroll.ScrollToEnd()
}

function Set-Busy {
    param([bool] $on, [string] $msg = '')
    $Script:Busy = $on
    $ctrls.BtnApplyAll.IsEnabled = -not $on
    $ctrls.BtnQuickWin.IsEnabled = -not $on
    $ctrls.BtnRollback.IsEnabled = -not $on
    $ctrls.BtnReport.IsEnabled   = -not $on
    $ctrls.BtnRefresh.IsEnabled  = -not $on
    if ($on) { $ctrls.FooterText.Text = $msg } else { $ctrls.FooterText.Text = "Ready" }
}

function Invoke-WithCapture {
    param([scriptblock] $Body, [string] $Label)
    Append-Log "$Label..." 'info'
    Set-Busy $true "Running: $Label"
    try {
        # Capture host output so we can mirror it into the activity log
        $out = & {
            $ErrorActionPreference = 'Continue'
            & $Body 6>&1 2>&1 | Out-String
        }
        if ($out) {
            foreach ($ln in ($out -split "`r?`n")) {
                if ([string]::IsNullOrWhiteSpace($ln)) { continue }
                $kind = 'info'
                if     ($ln -match '\[\+\]') { $kind = 'ok' }
                elseif ($ln -match '\[!\]') { $kind = 'warn' }
                elseif ($ln -match '\[-\]') { $kind = 'fail' }
                Append-Log $ln.TrimStart() $kind
            }
        }
        Append-Log "$Label done." 'ok'
    } catch {
        Append-Log "$Label failed: $_" 'fail'
    } finally {
        Set-Busy $false
        Update-Status
    }
}

# -----------------------------------------------------------------------------
#  Status panel
# -----------------------------------------------------------------------------
function Update-Status {
    try {
        $rows = Get-WSEStatusData
        $ctrls.StatusPanel.Children.Clear()
        $good = 0; $total = $rows.Count
        foreach ($r in $rows) {
            if ($r.Good) { $good++ }
            $row = New-Object System.Windows.Controls.Border
            $row.CornerRadius = 6
            $row.Padding = '10,7'
            $row.Margin  = '0,0,0,6'
            $row.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#2A2F3D')

            $grid = New-Object System.Windows.Controls.Grid
            $col1 = New-Object System.Windows.Controls.ColumnDefinition; $col1.Width = 'Auto'
            $col2 = New-Object System.Windows.Controls.ColumnDefinition; $col2.Width = '*'
            $col3 = New-Object System.Windows.Controls.ColumnDefinition; $col3.Width = 'Auto'
            $grid.ColumnDefinitions.Add($col1) | Out-Null
            $grid.ColumnDefinitions.Add($col2) | Out-Null
            $grid.ColumnDefinitions.Add($col3) | Out-Null

            $dot = New-Object System.Windows.Shapes.Ellipse
            $dot.Width = 8; $dot.Height = 8; $dot.Margin = '0,0,10,0'
            $dot.VerticalAlignment = 'Center'
            $dot.Fill = if ($r.Good) {
                [System.Windows.Media.BrushConverter]::new().ConvertFrom('#3FBF60')
            } else {
                [System.Windows.Media.BrushConverter]::new().ConvertFrom('#EF4747')
            }
            [System.Windows.Controls.Grid]::SetColumn($dot, 0)
            $grid.Children.Add($dot) | Out-Null

            $lbl = New-Object System.Windows.Controls.TextBlock
            $lbl.Text = $r.Label
            $lbl.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#E6E9EF')
            $lbl.VerticalAlignment = 'Center'
            $lbl.FontSize = 12
            [System.Windows.Controls.Grid]::SetColumn($lbl, 1)
            $grid.Children.Add($lbl) | Out-Null

            $state = New-Object System.Windows.Controls.TextBlock
            $state.Text = $r.State
            $state.FontSize = 11
            $state.VerticalAlignment = 'Center'
            $state.Foreground = if ($r.Good) {
                [System.Windows.Media.BrushConverter]::new().ConvertFrom('#3FBF60')
            } else {
                [System.Windows.Media.BrushConverter]::new().ConvertFrom('#EF4747')
            }
            [System.Windows.Controls.Grid]::SetColumn($state, 2)
            $grid.Children.Add($state) | Out-Null

            $row.Child = $grid
            $ctrls.StatusPanel.Children.Add($row) | Out-Null
        }
        $pct = if ($total -gt 0) { [int](($good / $total) * 100) } else { 0 }
        $ctrls.ScoreBadge.Text = "$pct%"
        $ctrls.ScoreBadge.Foreground = if ($pct -ge 80) {
            [System.Windows.Media.BrushConverter]::new().ConvertFrom('#3FBF60')
        } elseif ($pct -ge 50) {
            [System.Windows.Media.BrushConverter]::new().ConvertFrom('#E9C34D')
        } else {
            [System.Windows.Media.BrushConverter]::new().ConvertFrom('#EF4747')
        }
        $ctrls.StatusSummary.Text = "$good / $total controls passing"
    } catch {
        Append-Log "Status refresh failed: $_" 'fail'
    }
}

# -----------------------------------------------------------------------------
#  Render features for a category
# -----------------------------------------------------------------------------
function Show-Category {
    param([string] $Name)
    $cat = $catalogue[$Name]
    $ctrls.CategoryTitle.Text = $Name
    $ctrls.CategoryDesc.Text  = $cat.Desc
    $ctrls.FeaturePanel.Children.Clear()

    if ($Name -eq 'Overview') {
        $overview = New-Object System.Windows.Controls.TextBlock
        $overview.Text = @"
Use the navigation on the left to choose a category, then click a feature card to apply it.

Apply Quick Win  - the curated, low-risk default. Most users want this.
Apply ALL        - the aggressive sweep (blocks USB storage, disables Bluetooth, etc.)
Rollback         - restore every registry change made by a previous session.
Export HTML      - generates a colour-coded report you can share.

Every change is backed up to %ProgramData%\WSE\backups\<timestamp>\registry_backup.json
and every session is transcribed to %ProgramData%\WSE\logs\.
"@
        $overview.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#C4CAD6')
        $overview.TextWrapping = 'Wrap'
        $overview.FontSize = 13
        $overview.LineHeight = 22
        $ctrls.FeaturePanel.Children.Add($overview) | Out-Null
        return
    }

    foreach ($item in $cat.Items) {
        $card = New-Object System.Windows.Controls.Border
        $card.CornerRadius = 8
        $card.Padding = '14,12'
        $card.Margin  = '0,0,0,10'
        $card.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#232734')
        $card.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#2C313C')
        $card.BorderThickness = 1

        $grid = New-Object System.Windows.Controls.Grid
        $c1 = New-Object System.Windows.Controls.ColumnDefinition; $c1.Width = '*'
        $c2 = New-Object System.Windows.Controls.ColumnDefinition; $c2.Width = 'Auto'
        $grid.ColumnDefinitions.Add($c1) | Out-Null
        $grid.ColumnDefinitions.Add($c2) | Out-Null

        $stack = New-Object System.Windows.Controls.StackPanel
        [System.Windows.Controls.Grid]::SetColumn($stack, 0)

        $titleRow = New-Object System.Windows.Controls.StackPanel
        $titleRow.Orientation = 'Horizontal'
        $title = New-Object System.Windows.Controls.TextBlock
        $title.Text = $item.Title
        $title.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#E6E9EF')
        $title.FontSize = 13
        $title.FontWeight = 'SemiBold'
        $titleRow.Children.Add($title) | Out-Null

        $tagText = switch ($item.Risk) { 'safe' {'safe'} 'restore' {'restore'} 'danger' {'caution'} 'info' {'info'} default {''} }
        if ($tagText) {
            $tag = New-Object System.Windows.Controls.Border
            $tag.CornerRadius = 10
            $tag.Padding = '6,1'
            $tag.Margin = '8,1,0,0'
            switch ($item.Risk) {
                'safe'    { $tag.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#1f3d2a'); $fg='#3FBF60' }
                'restore' { $tag.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#26334a'); $fg='#7AB1FA' }
                'danger'  { $tag.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#4a1f1f'); $fg='#EF4747' }
                'info'    { $tag.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#3a2e1f'); $fg='#E9C34D' }
            }
            $tagText2 = New-Object System.Windows.Controls.TextBlock
            $tagText2.Text = $tagText
            $tagText2.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom($fg)
            $tagText2.FontSize = 10
            $tagText2.FontWeight = 'SemiBold'
            $tag.Child = $tagText2
            $titleRow.Children.Add($tag) | Out-Null
        }
        $stack.Children.Add($titleRow) | Out-Null

        if ($item.Note) {
            $note = New-Object System.Windows.Controls.TextBlock
            $note.Text = $item.Note
            $note.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#95A0B3')
            $note.FontSize = 11
            $note.Margin = '0,4,0,0'
            $note.TextWrapping = 'Wrap'
            $stack.Children.Add($note) | Out-Null
        }
        $grid.Children.Add($stack) | Out-Null

        $btn = New-Object System.Windows.Controls.Button
        $btn.Content = "Apply"
        $btn.VerticalAlignment = 'Center'
        $btn.MinWidth = 90
        $btn.Margin = '12,0,0,0'
        $styleKey = switch ($item.Risk) { 'danger' {'DangerButton'} 'restore' {'SecondaryButton'} default {'ActionButton'} }
        $btn.Style = $window.FindResource($styleKey)
        $action = $item.Action
        $label  = $item.Title
        $btn.Add_Click({
            param($sender,$ev)
            if ($Script:Busy) { return }
            Invoke-WithCapture -Body $action -Label $label
        }.GetNewClosure())
        [System.Windows.Controls.Grid]::SetColumn($btn, 1)
        $grid.Children.Add($btn) | Out-Null

        $card.Child = $grid
        $ctrls.FeaturePanel.Children.Add($card) | Out-Null
    }
}

# -----------------------------------------------------------------------------
#  Build the navigation
# -----------------------------------------------------------------------------
$first = $true
foreach ($key in $catalogue.Keys) {
    $rb = New-Object System.Windows.Controls.RadioButton
    $rb.Content = $key
    $rb.Style = $window.FindResource('NavButton')
    $rb.Margin = '0,2'
    $rb.GroupName = 'WSENav'
    if ($first) { $rb.IsChecked = $true; $first = $false }
    $catName = $key
    $rb.Add_Checked({
        param($sender,$ev)
        Show-Category -Name $sender.Content.ToString()
    })
    $Script:NavLookup[$key] = $rb
    $ctrls.NavPanel.Children.Add($rb) | Out-Null
}

# -----------------------------------------------------------------------------
#  Wire footer + header buttons
# -----------------------------------------------------------------------------
$ctrls.BtnQuickWin.Add_Click({
    if ($Script:Busy) { return }
    $res = [System.Windows.MessageBox]::Show(
        "Apply the curated Quick Win preset?`n`nThis runs ~30 safe controls (no USB lockout, no IPv6 disable, no Bluetooth disable, no outbound block).`n`nA System Restore Point is created first.",
        "Confirm",
        "OKCancel", "Question")
    if ($res -eq 'OK') {
        Invoke-WithCapture -Body { Invoke-QuickWinHardening } -Label "Quick Win preset"
    }
})

$ctrls.BtnApplyAll.Add_Click({
    if ($Script:Busy) { return }
    $res = [System.Windows.MessageBox]::Show(
        "Apply the FULL hardening sweep?`n`nThis is aggressive: USB storage is disabled, Bluetooth is disabled, hibernation is purged, IPv6 transition tech is turned off, etc.`n`nA System Restore Point is created first and every registry change is recorded for rollback.",
        "Confirm aggressive hardening",
        "OKCancel", "Warning")
    if ($res -eq 'OK') {
        Invoke-WithCapture -Body { Invoke-AllHardening } -Label "Apply ALL hardening"
    }
})

$ctrls.BtnRefresh.Add_Click({
    if ($Script:Busy) { return }
    Append-Log "Refreshing security status..." 'info'
    Update-Status
})

$ctrls.BtnReport.Add_Click({
    if ($Script:Busy) { return }
    Invoke-WithCapture -Body {
        $path = Export-WSEHtmlReport
        if ($path -and (Test-Path $path)) {
            Start-Process $path
        }
    } -Label "Export HTML report"
})

$ctrls.BtnRollback.Add_Click({
    if ($Script:Busy) { return }
    if (-not (Test-Path $Script:WSEBackupRoot)) {
        [System.Windows.MessageBox]::Show("No backup directory yet at`n$Script:WSEBackupRoot","Rollback") | Out-Null
        return
    }
    $backups = @(Get-ChildItem -Path $Script:WSEBackupRoot -Directory -ErrorAction SilentlyContinue |
                 Where-Object { Test-Path (Join-Path $_.FullName 'registry_backup.json') } |
                 Sort-Object Name -Descending)
    if ($backups.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No registry backups exist yet.","Rollback") | Out-Null
        return
    }

    # Pop a quick chooser window
    $win = New-Object System.Windows.Window
    $win.Title = "Rollback - choose a backup"
    $win.Width = 520; $win.Height = 420
    $win.WindowStartupLocation = 'CenterOwner'
    $win.Owner = $window
    $win.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#1A1D24')
    $grid = New-Object System.Windows.Controls.Grid
    $grid.Margin = '20'
    $r1 = New-Object System.Windows.Controls.RowDefinition; $r1.Height = 'Auto'
    $r2 = New-Object System.Windows.Controls.RowDefinition; $r2.Height = '*'
    $r3 = New-Object System.Windows.Controls.RowDefinition; $r3.Height = 'Auto'
    $grid.RowDefinitions.Add($r1) | Out-Null
    $grid.RowDefinitions.Add($r2) | Out-Null
    $grid.RowDefinitions.Add($r3) | Out-Null

    $lbl = New-Object System.Windows.Controls.TextBlock
    $lbl.Text = "Pick a session to roll back. Only registry changes are reverted; service / firewall changes need to be undone with the matching Enable-* feature."
    $lbl.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#95A0B3')
    $lbl.TextWrapping = 'Wrap'
    $lbl.Margin = '0,0,0,12'
    [System.Windows.Controls.Grid]::SetRow($lbl, 0)
    $grid.Children.Add($lbl) | Out-Null

    $list = New-Object System.Windows.Controls.ListBox
    $list.Background = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#232734')
    $list.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#E6E9EF')
    $list.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFrom('#2C313C')
    $list.FontFamily = 'Consolas'
    foreach ($b in $backups) { $list.Items.Add($b.Name) | Out-Null }
    if ($list.Items.Count -gt 0) { $list.SelectedIndex = 0 }
    [System.Windows.Controls.Grid]::SetRow($list, 1)
    $grid.Children.Add($list) | Out-Null

    $bp = New-Object System.Windows.Controls.StackPanel
    $bp.Orientation = 'Horizontal'
    $bp.HorizontalAlignment = 'Right'
    $bp.Margin = '0,12,0,0'
    $bCancel = New-Object System.Windows.Controls.Button
    $bCancel.Content = 'Cancel'; $bCancel.MinWidth = 90; $bCancel.Margin = '0,0,8,0'
    $bCancel.Style = $window.FindResource('SecondaryButton')
    $bOk = New-Object System.Windows.Controls.Button
    $bOk.Content = 'Roll back'; $bOk.MinWidth = 110
    $bOk.Style = $window.FindResource('DangerButton')
    $bp.Children.Add($bCancel) | Out-Null
    $bp.Children.Add($bOk) | Out-Null
    [System.Windows.Controls.Grid]::SetRow($bp, 2)
    $grid.Children.Add($bp) | Out-Null

    $win.Content = $grid
    $bCancel.Add_Click({ $win.DialogResult = $false; $win.Close() })
    $bOk.Add_Click({
        if ($list.SelectedIndex -lt 0) { return }
        $sel = $backups[$list.SelectedIndex]
        $confirm = [System.Windows.MessageBox]::Show("Restore registry values from $($sel.Name)?","Confirm rollback","OKCancel","Warning")
        if ($confirm -ne 'OK') { return }
        $win.DialogResult = $true; $win.Close()
        Invoke-WithCapture -Body {
            $file = Join-Path $sel.FullName 'registry_backup.json'
            $entries = Get-Content $file -Raw | ConvertFrom-Json
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
                } catch { $errors++ }
            }
            Write-Host "  [+] Rollback complete: $restored restored, $deleted removed, $errors errors."
        }.GetNewClosure() -Label "Rollback $($sel.Name)"
    })
    $win.ShowDialog() | Out-Null
})

# -----------------------------------------------------------------------------
#  Initial render
# -----------------------------------------------------------------------------
$caps = Get-WSECapabilities
$archTag = if ($caps.IsARM) { 'ARM64' } elseif ($caps.IsIntel) { 'Intel x64' } elseif ($caps.IsAMD) { 'AMD x64' } else { $caps.ProcessorArch }
$ctrls.HeaderSub.Text = "$($caps.OSName) - $($caps.Edition) - $archTag - PowerShell $($caps.PSVersion)"
Show-Category -Name 'Overview'
Update-Status
Append-Log "WSE GUI v$($Script:WSEVersion) ready." 'ok'
Append-Log "Log: $Script:WSETranscript" 'info'
Append-Log "Backups: $Script:WSESessionBackup" 'info'

$window.Add_Closed({ try { Stop-WSE } catch {} })
[void]$window.ShowDialog()
