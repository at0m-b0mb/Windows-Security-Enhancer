
<div align="center">

# 🛡️ Windows Security Enhancer

**A PowerShell-based interactive toolkit that hardens Windows systems against real-world attack techniques.**  
Apply every hardening setting at once, or pick and choose features individually — all from a simple numbered menu.

[![Version](https://img.shields.io/badge/version-4.0-blue?style=flat-square)](#)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20%7C%20Server-0078D4?style=flat-square&logo=windows)](#)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?style=flat-square&logo=powershell)](#)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Requires Admin](https://img.shields.io/badge/requires-Administrator-red?style=flat-square)](#)

</div>

---

## 📋 Table of Contents

- [✨ What It Does](#-what-it-does)
- [⚡ Quick Start](#-quick-start)
- [📦 Requirements](#-requirements)
- [📁 File Overview](#-file-overview)
- [🔧 Feature Reference](#-feature-reference)
  - [🔐 UAC & Authentication (1–6)](#-uac--authentication)
  - [🔥 Firewall & Network (7–13)](#-firewall--network)
  - [💾 Devices & Storage (14–19)](#-devices--storage)
  - [🦠 Defender, Accounts & Scripts (20–24)](#-defender-accounts--scripts)
  - [⚙️ Services, Auditing & Credentials (25–28)](#%EF%B8%8F-services-auditing--credentials)
  - [🕵️ Privacy & Telemetry (29–32)](#%EF%B8%8F-privacy--telemetry)
  - [🏰 Advanced System Hardening (33–41)](#-advanced-system-hardening)
  - [🌐 Network & DNS Hardening (42–44)](#-network--dns-hardening)
  - [🔄 Additional Hardening (45–47)](#-additional-hardening)
  - [⚔️ Attack Surface Reduction — ASR (51–52)](#%EF%B8%8F-attack-surface-reduction--asr)
  - [🖥️ PowerShell Hardening (53–55)](#%EF%B8%8F-powershell-hardening)
  - [📶 Wireless Security (56–57)](#-wireless-security)
  - [📄 Office & Application Security (58–59)](#-office--application-security)
  - [🔥 Firewall Enhancements (60–62)](#-firewall-enhancements)
  - [🔐 Drive Encryption — BitLocker (63–64)](#-drive-encryption--bitlocker)
  - [🖧 Remote Access Hardening (65–66)](#-remote-access-hardening)
  - [🛠️ Utilities (67–69)](#%EF%B8%8F-utilities)
- [⚠️ Warnings & Compatibility Notes](#%EF%B8%8F-warnings--compatibility-notes)
- [🤝 Contributing](#-contributing)
- [📜 License](#-license)

---

## ✨ What It Does

Windows Security Enhancer gives you **66 security controls** across 16 categories, all accessible through a colour-coded interactive menu. It covers:

| Domain | What's included |
|--------|-----------------|
| 🔐 Authentication | UAC levels, account lockout, strong password policy |
| 🔥 Network | Firewall rules & logging, SMBv1, RDP, LLMNR, DNS hardening |
| 💾 Devices | USB, cameras, AutoRun/AutoPlay |
| 🦠 Endpoint Protection | Windows Defender max settings, ASR rules, Script Host |
| ⚙️ Services | Disable risky services, audit policy, Credential Guard |
| 🕵️ Privacy | Telemetry, Advertising ID, Cortana |
| 🏰 System Hardening | PrintNightmare, NTLMv2, Exploit Protection, DEP/SEHOP/ASLR |
| 🖥️ PowerShell | Execution policy, disable legacy PowerShell v2 |
| 📶 Wireless | Bluetooth service + devices |
| 📄 Application | Office macro policy (Word, Excel, PowerPoint, Access, Outlook) |
| 🔐 Encryption | BitLocker status and enablement with TPM/PIN |
| 🖧 Remote Access | WinRM / PowerShell Remoting |

> 💡 **Option 68 — Apply ALL** runs every hardening function in a single sweep. Ideal for quickly locking down a new machine.

---

## ⚡ Quick Start

> **No installation required.** Just double-click and follow the menu.

**Step 1 — Download the repository**

```
git clone https://github.com/at0m-b0mb/Windows-Security-Enhancer.git
```

**Step 2 — Launch the toolkit**

Double-click **`runner.bat`** — it automatically requests Administrator privileges and opens the interactive menu.

**Step 3 — Choose what to harden**

```
  ╔════════════════════════════════════════════════════════╗
  ║       W I N D O W S   S E C U R I T Y                  ║
  ║              E N H A N C E R   v4.0                    ║
  ╚════════════════════════════════════════════════════════╝

  ── UAC & Authentication ─────────────────────────────────
    1.  Enforce UAC credential prompt (hardened)
    2.  Set UAC to 'Always Notify' (maximum)
    ...
   68.  Apply ALL hardening settings  [recommended]
   69.  Exit

  Enter choice (1-47, 51-69):
```

- Enter a **single number** to apply one feature.
- Enter **68** to apply all 37 hardening settings at once.
- A **system restart** is recommended after running the full suite.

---

## 📦 Requirements

| Requirement | Details |
|-------------|---------|
| **Operating System** | Windows 10, Windows 11, or Windows Server 2016 / 2019 / 2022 |
| **PowerShell** | Version 5.1 or later (included with Windows 10+) |
| **Privileges** | Administrator — `runner.bat` handles the UAC elevation automatically |
| **BitLocker** (option 64) | Requires Windows Pro, Enterprise, or Education edition |

---

## 📁 File Overview

```
Windows-Security-Enhancer/
├── runner.bat            ← Double-click this to start (handles UAC elevation)
└── win_more_secure.ps1   ← All security functions and the interactive menu
```

| File | Purpose |
|------|---------|
| `runner.bat` | Detects if already elevated; if not, re-launches itself with `runas` / UAC |
| `win_more_secure.ps1` | 1,500+ line PowerShell script — 66 security functions + status report + menu |

---

## 🔧 Feature Reference

Options marked 🔒 are **hardening actions** (recommended). Options marked ↩️ **restore** a setting to its default. Options marked ⚠️ are advanced or carry risk — read the note before using them.

---

### 🔐 UAC & Authentication

| # | Action | Notes |
|---|--------|-------|
| 1 | **Enforce UAC credential prompt** | Sets `ConsentPromptBehaviorAdmin=1` — password required for all admin tasks |
| 2 | **Set UAC to "Always Notify"** | Maximum UAC level — prompts for every change |
| 3 | ↩️ Restore UAC to Windows default | Sets value back to 5 |
| 4 | 🔒 **Set account lockout policy** | 5 failed attempts → 30-minute lockout |
| 5 | ↩️ Restore account lockout to default | Removes lockout threshold |
| 6 | 🔒 **Enforce strong password policy** | 12-char minimum, complexity on, 90-day expiry via `secedit` |

---

### 🔥 Firewall & Network

| # | Action | Notes |
|---|--------|-------|
| 7  | 🔒 **Enable Windows Firewall** | Enables all 3 profiles + blocks dangerous inbound ports: Telnet (23), RPC (135), NetBIOS (137–139), SMB (445), MSSQL (1433), RDP (3389), WinRM (5985–5986) |
| 8  | ⚠️ Disable Windows Firewall | **Not recommended** — leaves system fully exposed |
| 9  | 🔒 **Disable SMBv1** | Eliminates the WannaCry / EternalBlue attack surface |
| 10 | ⚠️ Enable SMBv1 | **Not recommended** — known critical vulnerabilities |
| 11 | 🔒 **Disable RDP** | Closes Remote Desktop; use only if RDP is not required |
| 12 | ↩️ Enable RDP | Re-enables Remote Desktop |
| 13 | 🔒 **Disable anonymous access, LLMNR & NBT-NS** | Prevents LLMNR relay attacks and NetBIOS MITM |

---

### 💾 Devices & Storage

| # | Action | Notes |
|---|--------|-------|
| 14 | 🔒 **Disable USB storage** | Disables `UsbStor` driver — blocks USB drives from mounting |
| 15 | ↩️ Enable USB storage | Re-enables USB mass storage |
| 16 | 🔒 **Disable cameras** | Disables all PnP devices in the Camera / Image class |
| 17 | ↩️ Enable cameras | Re-enables camera devices |
| 18 | 🔒 **Disable AutoRun / AutoPlay** | Sets `NoDriveTypeAutoRun=0xFF` — prevents auto-execution from any drive |
| 19 | ↩️ Enable AutoRun / AutoPlay | Restores AutoPlay behaviour |

---

### 🦠 Defender, Accounts & Scripts

| # | Action | Notes |
|---|--------|-------|
| 20 | 🔒 **Configure Windows Defender (max protection)** | Real-time protection, Cloud MAPS Advanced, Block at First Sight, PUA protection, Network Protection, Controlled Folder Access (anti-ransomware), sample submission |
| 21 | 🔒 **Disable Guest account** | Prevents unauthenticated local access |
| 22 | ⚠️ Enable Guest account | **Not recommended** — opens unauthenticated access |
| 23 | 🔒 **Disable Windows Script Host** | Blocks `.vbs` / `.js` malware from running |
| 24 | ↩️ Enable Windows Script Host | Restores WSH for legacy scripts |

---

### ⚙️ Services, Auditing & Credentials

| # | Action | Notes |
|---|--------|-------|
| 25 | 🔒 **Disable risky services** | Stops & disables: Remote Registry, Telnet, SSDP/UPnP discovery, Internet Connection Sharing, WinRM, Remote Desktop Helper |
| 26 | ↩️ Restore disabled services to Manual | Sets all disabled services back to Manual start |
| 27 | 🔒 **Enable comprehensive audit policy** | Logs success + failure for: logon events, account management, object access, privilege use, policy changes. Enables PowerShell Script Block & Module Logging. Expands Security event log to 1 GB |
| 28 | 🔒 **Enable LSA / Credential Guard** | Sets `RunAsPPL=1`, disables WDigest plain-text credential caching, disables Restricted Admin mode |

---

### 🕵️ Privacy & Telemetry

| # | Action | Notes |
|---|--------|-------|
| 29 | 🔒 **Disable Windows Telemetry** | Stops `DiagTrack` & `dmwappushservice`, sets `AllowTelemetry=0`, disables CEIP, AIT, and Windows Error Reporting |
| 30 | ↩️ Enable Windows Telemetry | Restores telemetry to Windows default |
| 31 | 🔒 **Disable Advertising ID** | Removes per-user and policy-level ad tracking; suppresses suggested content and silent app installs |
| 32 | 🔒 **Disable Cortana & web search** | Blocks cloud search, location-based search, and web results in Start menu |

---

### 🏰 Advanced System Hardening

| # | Action | Notes |
|---|--------|-------|
| 33 | 🔒 **Disable Print Spooler** | Mitigates PrintNightmare (CVE-2021-34527) — stops and disables the Spooler service |
| 34 | ↩️ Enable Print Spooler | Re-enables printing |
| 35 | 🔒 **Force NTLMv2 only** | `LmCompatibilityLevel=5`, disables LM hash storage, enforces 128-bit NTLM session security on both client and server |
| 36 | 🔒 **Disable PowerShell v2** | Removes the legacy PS engine that bypasses modern Script Block Logging |
| 37 | 🔒 **Enable Exploit Protection** | DEP `AlwaysOn` (`bcdedit`), SEHOP (registry), Force ASLR, Heap Terminate on Corruption (`Set-ProcessMitigation`) |
| 38 | 🔒 **Enable page file clear on shutdown** | Zeros the page file at every shutdown — prevents offline memory forensics |
| 39 | ↩️ Disable page file clear on shutdown | Restores default (faster shutdown) |
| 40 | 🔒 **Disable Remote Assistance** | Closes RA firewall rules, sets `fAllowToGetHelp=0` |
| 41 | ↩️ Enable Remote Assistance | Re-enables Remote Assistance |

---

### 🌐 Network & DNS Hardening

| # | Action | Notes |
|---|--------|-------|
| 42 | 🔒 **Set Secure DNS** | Configures Cloudflare (1.1.1.1 / 1.0.0.1) and Google (8.8.8.8 / 8.8.4.4) on all active network adapters |
| 43 | 🔒 **Disable IPv6** | Disables IPv6 binding on all adapters and sets `DisabledComponents=0xFF` in the registry |
| 44 | ↩️ Enable IPv6 | Re-enables IPv6 |

---

### 🔄 Additional Hardening

| # | Action | Notes |
|---|--------|-------|
| 45 | 🔒 **Force Automatic Windows Updates** | Sets `AUOptions=4` (auto download + install), schedules daily at 03:00, ensures `wuauserv` is set to Automatic |
| 46 | 🔒 **Set screen auto-lock (5 min)** | Screensaver + Group Policy timeout of 5 minutes with password-on-resume; also requires password on wake from sleep |
| 47 | 🔒 **Rename built-in Administrator account** | Targets the RID-500 account by SID — makes brute-force attacks harder |

---

### ⚔️ Attack Surface Reduction — ASR

> Requires Windows Defender real-time protection to be active (option 20).

| # | Action | Notes |
|---|--------|-------|
| 51 | 🔒 **Enable 14 ASR rules (Block mode)** | Covers: email executable content, Office child processes, Office executable output, Office code injection, JS/VBScript launching downloads, obfuscated scripts, Office Win32 API calls, advanced ransomware protection, LSASS credential theft, PSExec/WMI process spawning, unsigned USB processes, Office comms child processes, Adobe Reader child processes, WMI event-subscription persistence |
| 52 | ↩️ Disable all ASR rules | Sets all configured rules to `0` (Disabled) |

---

### 🖥️ PowerShell Hardening

| # | Action | Notes |
|---|--------|-------|
| 53 | 🔒 **Set execution policy to RemoteSigned** | Local scripts run freely; downloaded scripts must carry a digital signature |
| 54 | 🔒 **Set execution policy to AllSigned** | Every script — local and remote — must be signed; strictest setting |
| 55 | ↩️ Restore execution policy to default | Sets policy to `Undefined` at the LocalMachine scope |

---

### 📶 Wireless Security

| # | Action | Notes |
|---|--------|-------|
| 56 | 🔒 **Disable Bluetooth** | Stops and disables the `bthserv` Bluetooth Support Service, then disables all `Class=Bluetooth` PnP devices |
| 57 | ↩️ Enable Bluetooth | Re-enables the Bluetooth service and devices |

---

### 📄 Office & Application Security

| # | Action | Notes |
|---|--------|-------|
| 58 | 🔒 **Disable Office macros** | Writes `VBAWarnings=4` (disable all macros, no notification) to both `HKCU` and `HKLM` for Office 2007–2016/365 across Word, Excel, PowerPoint, Access, and Outlook |
| 59 | ↩️ Enable Office macros | Removes the `VBAWarnings` policy key — applications revert to their built-in defaults |

---

### 🔥 Firewall Enhancements

| # | Action | Notes |
|---|--------|-------|
| 60 | 🔒 **Enable Firewall logging** | Logs both allowed and blocked connections on all 3 profiles (Domain, Private, Public); log stored at `%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log` |
| 61 | ⚠️ **Block all outbound traffic by default** | Sets `DefaultOutboundAction=Block` — **will break most apps**. Only use on air-gapped or tightly controlled systems, with explicit allow rules already in place |
| 62 | ↩️ Restore default outbound action | Sets `DefaultOutboundAction=Allow` on all profiles |

---

### 🔐 Drive Encryption — BitLocker

> Requires Windows **Pro**, **Enterprise**, or **Education** edition.

| # | Action | Notes |
|---|--------|-------|
| 63 | 🔒 **Show BitLocker status** | Displays protection status, encryption percentage, and encryption method for every mounted drive |
| 64 | 🔒 **Enable BitLocker on C:** | Uses TPM protector if TPM is ready; otherwise prompts for a TPM+PIN. Encryption method: XTS-AES 256. Recovery key is automatically saved to the Desktop with a reminder to move it offline |

---

### 🖧 Remote Access Hardening

| # | Action | Notes |
|---|--------|-------|
| 65 | 🔒 **Disable PowerShell Remoting / WinRM** | Runs `Disable-PSRemoting`, removes all WinRM listeners, stops and disables the WinRM service, and disables WinRM firewall rules |
| 66 | ↩️ Enable PowerShell Remoting / WinRM | Runs `Enable-PSRemoting -Force -SkipNetworkProfileCheck` |

---

### 🛠️ Utilities

| # | Action | Notes |
|---|--------|-------|
| 67 | 📊 **Security Status Report** | Colour-coded live dashboard covering 27 controls: UAC, Firewall, Defender RT, RDP, Remote Assistance, SMBv1, Print Spooler, NTLM level, USB, Guest account, AutoRun, Script Host, LLMNR, WDigest, Telemetry, DiagTrack, Page File clear, SEHOP, IPv6, Cortana, ASR rules count, PS execution policy, Bluetooth service, Office macros, BitLocker (C:), WinRM, and Firewall logging |
| 68 | 🚀 **Apply ALL hardening settings** | Runs all 37 hardening functions in sequence — ideal for a fresh machine or a full lockdown |
| 69 | 🚪 Exit | Exits the toolkit |

---

## ⚠️ Warnings & Compatibility Notes

| Setting | Potential impact |
|---------|-----------------|
| **USB storage disable** (14) | Blocks all USB mass storage drives — does not affect USB keyboards, mice, or other HID devices |
| **SMBv1 disable** (9) | Breaks communication with very old devices (pre-Windows Vista NAS, old printers) |
| **Print Spooler disable** (33) | Disables all local and network printing |
| **IPv6 disable** (43) | Some modern corporate networks and VPNs require IPv6 |
| **Block outbound by default** (61) | Breaks all outbound connections — only use with explicit allow rules already configured |
| **AllSigned execution policy** (54) | Prevents unsigned scripts from running — test your environment first |
| **BitLocker** (64) | **Always back up the recovery key** before encrypting a drive — losing it means losing all data |
| **Disable Bluetooth** (56) | Disconnects Bluetooth peripherals (keyboards, mice, headsets) |
| **Office macros disable** (58) | Will block legitimate macro-enabled spreadsheets and documents |

> **Best practice:** Run option **67** (Security Status Report) before and after applying changes to see exactly what changed.

---

## 🤝 Contributing

Contributions are welcome! To add a new hardening feature:

1. **Fork** the repository and create a new branch.
2. Add a new `function` to `win_more_secure.ps1` following the existing naming convention (`Verb-Noun`).
3. Add the function to the `Show-Menu` display block with a new option number.
4. Add the corresponding `case` to the `switch` in the main loop.
5. Add the function to `Invoke-AllHardening` if it should be part of the full sweep.
6. Add status-check logic to `Show-SecurityStatus` if the setting can be read back.
7. Update `README.md` with a new row in the appropriate feature table.
8. Open a **Pull Request** with a clear description of what the feature hardens and why.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).  
Use at your own risk. Test in a controlled or lab environment before deploying to production systems.
