
<div align="center">

# Windows Security Enhancer

**A PowerShell-based interactive toolkit that hardens Windows systems against real-world attack techniques.**
Apply every hardening setting at once, or pick and choose features individually — all from a simple numbered menu.

[![Version](https://img.shields.io/badge/version-5.0-blue?style=flat-square)](#)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20%7C%20Server-0078D4?style=flat-square&logo=windows)](#)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?style=flat-square&logo=powershell)](#)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Requires Admin](https://img.shields.io/badge/requires-Administrator-red?style=flat-square)](#)

</div>

---

## What's new in v5.0

| Area | What changed |
|------|--------------|
| **Audit trail** | Every session is recorded to `%ProgramData%\WSE\logs\wse_<timestamp>.log` via `Start-Transcript`. |
| **Rollback support** | Every registry change is captured to `%ProgramData%\WSE\backups\<timestamp>\registry_backup.json`. Option **93** restores any previous backup. |
| **System Restore Point** | Option **48** creates a checkpoint before risky changes; `Apply ALL` does it automatically. |
| **OS / capability detection** | Option **49** shows OS, edition, PowerShell version, TPM state and available cmdlets. Features gracefully skip when unsupported. |
| **Critical bug fixes** | USB hardening no longer disables USB root hubs (which would brick HID devices). Firewall logging no longer shadows the PowerShell `$profile` automatic variable. `Apply ALL` no longer ends with the AllSigned execution policy (which would lock the script out of subsequent runs). |
| **20+ new hardening controls** | SChannel TLS hardening, DNS-over-HTTPS, SMB / LDAP signing, Memory Integrity (HVCI), RDP NLA, Tamper-Protection check, WebDAV / WPAD / Quick Assist / hibernation, OneDrive / Xbox / Consumer features, SmartScreen everywhere, IPv6 transition tech, mDNS, and more. |
| **Stronger confirmations** | Destructive operations (`Disable-WindowsFirewall`, `Enable-SMBv1`, `Block-Outbound`, `AllSigned`) now require typed confirmation. |
| **Hardened launcher** | `runner.bat` verifies the PowerShell file exists, uses `fltmc` for reliable elevation detection, and surfaces non-zero exit codes. |

---

## Table of Contents

- [What It Does](#what-it-does)
- [Quick Start](#quick-start)
- [Requirements](#requirements)
- [File Overview](#file-overview)
- [Feature Reference](#feature-reference)
  - [UAC & Authentication (1–6)](#uac--authentication)
  - [Firewall & Network (7–13)](#firewall--network)
  - [Devices & Storage (14–19)](#devices--storage)
  - [Defender, Accounts & Scripts (20–24)](#defender-accounts--scripts)
  - [Services, Auditing & Credentials (25–28)](#services-auditing--credentials)
  - [Privacy & Telemetry (29–32)](#privacy--telemetry)
  - [Advanced System Hardening (33–41)](#advanced-system-hardening)
  - [Network & DNS Hardening (42–44)](#network--dns-hardening)
  - [Additional Hardening (45–50)](#additional-hardening)
  - [Attack Surface Reduction — ASR (51–52)](#attack-surface-reduction--asr)
  - [PowerShell Hardening (53–55)](#powershell-hardening)
  - [Wireless Security (56–57)](#wireless-security)
  - [Office & Application Security (58–59)](#office--application-security)
  - [Firewall Enhancements (60–62)](#firewall-enhancements)
  - [Drive Encryption — BitLocker (63–64)](#drive-encryption--bitlocker)
  - [Remote Access Hardening (65–66)](#remote-access-hardening)
  - [Utilities (67–68)](#utilities)
  - [v5.0 Hardening Pack (70–86)](#v50-hardening-pack-7086)
  - [Rollback (93)](#rollback-93)
- [Warnings & Compatibility Notes](#warnings--compatibility-notes)
- [Contributing](#contributing)
- [License](#license)

---

## What It Does

Windows Security Enhancer gives you **85+ security controls** across 17 categories, all accessible through a colour-coded interactive menu. It covers:

| Domain | What's included |
|--------|-----------------|
| Authentication | UAC levels, account lockout, strong password policy |
| Network | Firewall rules & logging, SMBv1, RDP (NLA + High encryption), LLMNR / NBT-NS / mDNS, IPv6 transition tech, DoH |
| Devices | USB storage (HID safe), cameras, AutoRun / AutoPlay |
| Endpoint Protection | Defender max settings, ASR (16 rules), Script Host, Tamper-Protection status, scheduled scans |
| Services | Disable risky services, audit policy, Credential Guard, WebDAV, WPAD |
| Privacy | Telemetry, Activity History, Clipboard sync, Advertising ID, Cortana, OneDrive, Xbox, Consumer features |
| System Hardening | PrintNightmare mitigations, NTLMv2 + auditing, Exploit Protection (DEP/SEHOP/ASLR/CFG), HVCI / VBS |
| PowerShell | Execution policy, disable legacy PowerShell v2, script-block / module / transcription logging |
| Wireless | Bluetooth service + devices |
| Application | Office macros + macros-from-internet block (Word, Excel, PowerPoint, Access, Outlook, Publisher, Visio) |
| Encryption | BitLocker (XTS-AES 256, TPM or TPM+PIN, recovery key saved) |
| Remote Access | WinRM / PowerShell Remoting, Remote Assistance, Quick Assist |
| Transport Security | SChannel — disable SSL 3.0 / TLS 1.0 / 1.1, disable RC4 / DES / MD5 / SHA-1, force TLS 1.2 + 1.3 |
| Auth Protocols | SMB signing (required), LDAP signing + channel binding |
| Phishing | SmartScreen for Explorer, Edge, Apps & Files, Store |
| Storage Hygiene | Page-file zero-on-shutdown, hibernation purge (`hiberfil.sys`) |
| Recovery | Automatic registry backup per session + System Restore Point creation + interactive rollback |

> **Option 68 — Apply ALL** runs the curated hardening sweep (45+ controls). It creates a System Restore Point first, so you can roll back if anything misbehaves.

---

## Quick Start

> **No installation required.** Just double-click and follow the menu.

**Step 1 — Download the repository**

```
git clone https://github.com/at0m-b0mb/Windows-Security-Enhancer.git
```

**Step 2 — Launch the toolkit**

Double-click **`runner.bat`** — it automatically requests Administrator privileges and opens the interactive menu.

**Step 3 — Choose what to harden**

- Enter a **single number** to apply one feature.
- Enter **68** to apply the entire hardening sweep at once.
- Enter **49** to inspect what your OS supports first.
- Enter **67** before and after to see what changed.
- A **system restart** is recommended after running the full suite.

**Step 4 — Recover if needed**

- Open `%ProgramData%\WSE\logs\` to inspect the transcript.
- Open `%ProgramData%\WSE\backups\<timestamp>\registry_backup.json` to see exactly which values changed.
- Run option **93** to interactively roll back any session's registry changes.

---

## Requirements

| Requirement | Details |
|-------------|---------|
| **Operating System** | Windows 10, Windows 11, or Windows Server 2016 / 2019 / 2022 / 2025 |
| **PowerShell** | Version 5.1 or later (included with Windows 10+) |
| **Privileges** | Administrator — `runner.bat` handles the UAC elevation automatically |
| **BitLocker** (opt. 64) | Requires Windows Pro, Enterprise, or Education edition |
| **Memory Integrity** (opt. 80) | Requires CPU virtualisation + UEFI Secure Boot |
| **DoH** (opt. 77) | Native DoH cmdlets require Windows 11 22H2 / Server 2022+; older builds fall back to policy keys |

---

## File Overview

```
Windows-Security-Enhancer/
├── runner.bat            ← Double-click this to start (handles UAC elevation)
└── win_more_secure.ps1   ← All security functions + interactive menu (~2.3 K lines)

%ProgramData%\WSE\        ← Created at first run (ACL: Administrators + SYSTEM only)
├── logs\                 ← Per-session transcripts
├── backups\              ← Per-session registry-value snapshots (used by option 93)
└── ps-transcripts\       ← PowerShell module/script-block transcripts (option 27)
```

| File | Purpose |
|------|---------|
| `runner.bat` | Verifies the script exists, detects elevation with `fltmc`, re-launches with `runas` if needed |
| `win_more_secure.ps1` | All security functions, the interactive menu, logging, backup, rollback |

---

## Feature Reference

Options marked 🔒 are **hardening actions** (recommended). Options marked ↩️ **restore** a setting to its default. Options marked ⚠️ are advanced or carry risk — read the note before using them.

---

### UAC & Authentication

| # | Action | Notes |
|---|--------|-------|
| 1 | 🔒 **Enforce UAC credential prompt** | `ConsentPromptBehaviorAdmin=1`, `EnableLUA=1` |
| 2 | 🔒 **UAC "Always Notify"** | Maximum UAC level |
| 3 | ↩️ Restore UAC to Windows default | Value 5 |
| 4 | 🔒 **Account lockout** | 5 failed attempts → 30-minute lockout |
| 5 | ↩️ Restore account lockout to default | |
| 6 | 🔒 **Strong password policy** | 14-char minimum, complexity on, 90-day expiry, history 10 |

### Firewall & Network

| # | Action | Notes |
|---|--------|-------|
| 7  | 🔒 **Enable Windows Firewall** | All 3 profiles + block dangerous inbound ports on Public profile (23, 135, 137-139, 445, 1433, 1434, 3389, 5985, 5986) |
| 8  | ⚠️ Disable Windows Firewall | Typed confirmation required |
| 9  | 🔒 **Disable SMBv1** | Server + client + optional feature |
| 10 | ⚠️ Enable SMBv1 | Typed confirmation required |
| 11 | 🔒 **Disable RDP** | |
| 12 | ↩️ Enable RDP | **NLA required + High (FIPS) encryption + TLS security layer** |
| 13 | 🔒 **Disable anonymous, LLMNR, NBT-NS, mDNS** | Stops LLMNR / NBT-NS / mDNS poisoning and limits anonymous SAM lookup |

### Devices & Storage

| # | Action | Notes |
|---|--------|-------|
| 14 | 🔒 **Disable USB storage** | UsbStor + cdrom + RemovableStorageDevices policy. **HID devices (keyboard/mouse) are NOT affected** — v5 fix |
| 15 | ↩️ Enable USB storage | |
| 16 | 🔒 **Disable cameras** | Disables PnP + sets capability access to Deny |
| 17 | ↩️ Enable cameras | |
| 18 | 🔒 **Disable AutoRun / AutoPlay** | `NoDriveTypeAutoRun=0xFF` + `NoAutorun=1` + `IniFileMapping` |
| 19 | ↩️ Enable AutoRun / AutoPlay | |

### Defender, Accounts & Scripts

| # | Action | Notes |
|---|--------|-------|
| 20 | 🔒 **Configure Defender (max)** | RT, MAPS Advanced, BAFS, PUA, Network Protection, Controlled Folder Access, sample submission, archive / script / removable / behaviour / IOAV scanning, policy-level enforcement |
| 21 | 🔒 Disable Guest account | Uses LocalUser cmdlets where available |
| 22 | ⚠️ Enable Guest account | |
| 23 | 🔒 Disable Windows Script Host | |
| 24 | ↩️ Enable Windows Script Host | |

### Services, Auditing & Credentials

| # | Action | Notes |
|---|--------|-------|
| 25 | 🔒 **Disable risky services** | Remote Registry, Telnet, SSDP, UPnP, ICS, LLTD, iSCSI, IIS Mgmt, WebClient, Browser, Fax, WER, Xbox, RetailDemo, Downloaded Maps |
| 26 | ↩️ Restore disabled services to Manual | |
| 27 | 🔒 **Comprehensive audit policy** | Success + failure for all categories, PowerShell Script-Block / Module / Transcription logging, process-creation cmdline (4688), Security log set to 1 GB |
| 28 | 🔒 **LSA / Credential Guard** | `RunAsPPL=1`, WDigest off, VBS + HVCI keys, LsaCfg flag |

### Privacy & Telemetry

| # | Action | Notes |
|---|--------|-------|
| 29 | 🔒 **Disable Telemetry** | DiagTrack, dmwappushservice, DiagnosticsHub, PcaSvc + policy level 0 + CEIP + AIT + Inventory + WER + Activity History + Clipboard sync + Timeline |
| 30 | ↩️ Enable Telemetry | |
| 31 | 🔒 Disable Advertising ID & content tracking | Suggested apps, silent installs, OEM pre-installed apps, spotlight, lock-screen tips |
| 32 | 🔒 Disable Cortana & web search | |

### Advanced System Hardening

| # | Action | Notes |
|---|--------|-------|
| 33 | 🔒 **Disable Print Spooler** | + lock remote RPC endpoint + restrict driver install to admins (PrintNightmare) |
| 34 | ↩️ Enable Print Spooler | |
| 35 | 🔒 **NTLMv2 only** | `LmCompatibilityLevel=5`, no LM hash, 128-bit NTLM session security, NTLM auditing |
| 36 | 🔒 Disable PowerShell v2 | |
| 37 | 🔒 **Exploit Protection** | DEP AlwaysOn, SEHOP, Heap Terminate, Force ASLR, Bottom-up ASLR, High-entropy ASLR, CFG, per-process DEP |
| 38 | 🔒 Enable page file clear on shutdown | |
| 39 | ↩️ Disable page file clear on shutdown | |
| 40 | 🔒 Disable Remote Assistance | |
| 41 | ↩️ Enable Remote Assistance | |

### Network & DNS Hardening

| # | Action | Notes |
|---|--------|-------|
| 42 | 🔒 **Secure DNS** | Cloudflare 1.1.1.1 + Quad9 9.9.9.9 |
| 43 | 🔒 Disable IPv6 | Adapter binding + `DisabledComponents=0xFF` |
| 44 | ↩️ Enable IPv6 | |

### Additional Hardening

| # | Action | Notes |
|---|--------|-------|
| 45 | 🔒 Force Automatic Windows Updates | Daily at 03:00 |
| 46 | 🔒 Screen auto-lock (5 min) | Screensaver + GP + `InactivityTimeoutSecs` + power-config console lock |
| 47 | 🔒 Rename built-in Administrator | RID-500 detection by SID |
| 48 | 🛠️ Create a System Restore Point | Uses `Checkpoint-Computer`, bypasses 24-h throttle |
| 49 | 🛠️ OS / capability report | Shows OS, edition, PSv, TPM, available cmdlets |
| 50 | 🛠️ Show log / backup locations | |

### Attack Surface Reduction — ASR

| # | Action | Notes |
|---|--------|-------|
| 51 | 🔒 **Enable 16 ASR rules (Block)** | Now includes "Block vulnerable signed drivers" and "Block webshell creation for servers" |
| 52 | ↩️ Disable all ASR rules | |

### PowerShell Hardening

| # | Action | Notes |
|---|--------|-------|
| 53 | 🔒 Execution policy → RemoteSigned | |
| 54 | 🔒 Execution policy → AllSigned | Typed confirmation required (warns it will block re-running this script) |
| 55 | ↩️ Restore execution policy to default | |

### Wireless Security

| # | Action | Notes |
|---|--------|-------|
| 56 | 🔒 Disable Bluetooth | |
| 57 | ↩️ Enable Bluetooth | |

### Office & Application Security

| # | Action | Notes |
|---|--------|-------|
| 58 | 🔒 **Disable Office macros + block MOTW** | `VBAWarnings=4` and `BlockContentExecutionFromInternet=1` across Word, Excel, PowerPoint, Access, Outlook, Publisher, Visio (Office 2007 → 365) |
| 59 | ↩️ Enable Office macros (remove policy) | |

### Firewall Enhancements

| # | Action | Notes |
|---|--------|-------|
| 60 | 🔒 Enable Firewall logging | Allowed + blocked, 32 MB, all 3 profiles |
| 61 | ⚠️ **Block all outbound by default** | Typed confirmation required |
| 62 | ↩️ Restore default outbound action | |

### Drive Encryption — BitLocker

> Requires Windows **Pro**, **Enterprise**, or **Education** edition.

| # | Action | Notes |
|---|--------|-------|
| 63 | 🔒 Show BitLocker status | Per-volume protection / % / method |
| 64 | 🔒 Enable BitLocker on C: | TPM if ready, else TPM+PIN (≥6 digits validated). Adds a recovery-password protector; key file saved to Desktop |

### Remote Access Hardening

| # | Action | Notes |
|---|--------|-------|
| 65 | 🔒 Disable PowerShell Remoting / WinRM | |
| 66 | ↩️ Enable PowerShell Remoting / WinRM | |

### Utilities

| # | Action | Notes |
|---|--------|-------|
| 67 | 📊 **Security Status Report** | 35+ controls, colour-coded |
| 68 | 🚀 **Apply ALL hardening settings** | 45+ controls; creates a restore point first; ends with RemoteSigned (NOT AllSigned) so the tool can run again |
| 69 | 🚪 Exit | |

### v5.0 Hardening Pack (70–86)

| # | Action | Notes |
|---|--------|-------|
| 70 | 📊 Defender Tamper-Protection status | Read-only — must be toggled in the Windows Security UI |
| 71 | 🔒 Schedule Defender quick-scan + signature update | Daily at 02:00, sigs every 4 h |
| 72 | 🔒 **Disable WebClient (WebDAV)** | Closes the NTLM-over-WebDAV relay vector |
| 73 | 🔒 **Disable WPAD** | Stops WinHttpAutoProxySvc + adds `0.0.0.0 wpad` to the hosts file |
| 74 | 🔒 **Disable IPv6 transition tech** | Teredo, ISATAP, 6to4 (netsh + policy) |
| 75 | 🔒 **Harden SChannel** | Disables SSL 2/3, TLS 1.0/1.1, RC4 / DES / 3DES / MD5 / SHA-1. Enables TLS 1.2 + 1.3. Forces .NET 4.x strong crypto |
| 76 | ↩️ Restore SChannel defaults | |
| 77 | 🔒 **DNS-over-HTTPS** | Adds Cloudflare + Quad9 DoH templates, sets `DoHPolicy=2` (required) |
| 78 | 🔒 **Enforce SMB signing** | Client + server, refuses insecure guest logons |
| 79 | 🔒 **Enforce LDAP signing + channel binding** | Both directions; channel binding required |
| 80 | 🔒 **Memory Integrity / Core Isolation (VBS + HVCI)** | Requires CPU virtualisation + UEFI Secure Boot |
| 81 | 🔒 Disable Microsoft consumer features | Store auto-install, Spotlight, lock-screen ads |
| 82 | 🔒 Disable OneDrive (policy) | Blocks file sync |
| 83 | 🔒 Disable Xbox services + Game DVR | |
| 84 | 🔒 **Enable SmartScreen everywhere** | Explorer (`Block` mode), Edge (PUA on), Store apps (`PreventOverride`) |
| 85 | 🔒 Disable Quick Assist | Removes the Appx package + DISM capability |
| 86 | 🔒 **Disable hibernation** | Purges `hiberfil.sys` so RAM contents can't be recovered offline |

### Rollback (93)

Interactive selector for any previous `%ProgramData%\WSE\backups\<timestamp>\registry_backup.json`.
Re-applies the captured *old* value for each registry entry (or removes the entry entirely if it didn't exist beforehand). Services, firewall rules and Group-Policy-style behaviours are **not** automatically reverted by 93 — use the matching `Enable-*` option (e.g. **34**, **41**, **44**, **57**) for those.

---

## Warnings & Compatibility Notes

| Setting | Potential impact |
|---------|-----------------|
| **USB storage disable** (14) | Blocks USB mass-storage and CD/DVD; **HID and other classes are unaffected** (v5 fix) |
| **SMBv1 disable** (9) | Breaks communication with very old NAS / printers (pre-Vista) |
| **Print Spooler disable** (33) | Disables all local and network printing |
| **IPv6 disable** (43) | Modern corporate networks and some VPNs may require IPv6 |
| **Block outbound by default** (61) | Breaks all outbound connections — requires `BLOCK-OUTBOUND` typed confirmation |
| **AllSigned execution policy** (54) | Prevents unsigned scripts from running — requires `ALLSIGNED` typed confirmation. Apply-All deliberately uses `RemoteSigned` to keep this toolkit re-runnable |
| **BitLocker** (64) | **Always back up the recovery key** before encrypting a drive |
| **Disable Bluetooth** (56) | Disconnects Bluetooth peripherals (keyboards, mice, headsets) |
| **Office macros disable** (58) | Will block legitimate macro-enabled spreadsheets and documents |
| **Memory Integrity / HVCI** (80) | Some older third-party drivers will refuse to load |
| **SChannel hardening** (75) | Very old HTTPS servers (TLS 1.0/1.1 only) become unreachable |
| **DoH required** (77) | DNS queries fall back to drop when DoH is unreachable — may break captive-portal Wi-Fi |
| **Enforce SMB signing** (78) | Some legacy file servers (Samba < 4.x) won't be reachable |
| **NTLM auditing** (35) | Audit-only by default; switch `RestrictReceivingNTLMTraffic` to `2` (deny) only after reviewing audit events |
| **Hibernation disable** (86) | Removes the Fast-Startup hybrid-shutdown feature too |

> **Best practice:** run **67** (Security Status Report) before and after, and **48** (System Restore Point) before applying the big sweep.

---

## Contributing

Contributions are welcome. To add a new hardening feature:

1. **Fork** the repository and create a new branch.
2. Add a new `function` to `win_more_secure.ps1` following the existing naming convention (`Verb-Noun`). Use `Set-WSERegistry` for any registry write — it auto-backs-up the previous value.
3. Add the function to the `Show-Menu` display block with a new option number.
4. Add the corresponding `case` to the `switch` in the main loop.
5. Add the function to `Invoke-AllHardening` if it should be part of the full sweep.
6. Add status-check logic to `Show-SecurityStatus` if the setting can be read back.
7. Update `README.md` with a new row in the appropriate feature table.
8. Open a **Pull Request** with a clear description of what the feature hardens and why.

---

## License

This project is licensed under the [MIT License](LICENSE).
Use at your own risk. Test in a controlled or lab environment before deploying to production systems.
