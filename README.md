<div align="center">

# Windows Security Enhancer

**A self-contained Windows hardening toolkit with both a beautiful graphical interface and a powerful command-line menu.**
Apply 90+ security controls in one click, hunt for indicators of compromise, generate a colour-coded HTML report, and roll any change back from a registry snapshot — all without installing anything. Runs on **ARM64 and Intel/AMD x64**.

[![Version](https://img.shields.io/badge/version-5.2-blue?style=flat-square)](#)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20%7C%20Server-0078D4?style=flat-square&logo=windows)](#)
[![Architecture](https://img.shields.io/badge/arch-ARM64%20%7C%20x64%20(Intel%20%7C%20AMD)-orange?style=flat-square)](#)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?style=flat-square&logo=powershell)](#)
[![Interface](https://img.shields.io/badge/interface-GUI%20%2B%20CLI-9333ea?style=flat-square)](#)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Zero-install](https://img.shields.io/badge/installer-none%20required-22c55e?style=flat-square)](#)

</div>

---

## Why this exists

Default Windows is convenient, but it is not configured for an adversary. **Windows Security Enhancer** (WSE) is one batch file and one PowerShell engine you can drop on any Windows 10 / 11 / Server machine to make it materially harder to attack — without commercial tooling, group-policy infrastructure, or hours of manual registry edits.

- **Zero install.** Everything ships with Windows: PowerShell 5.1, .NET, WPF. Just unzip and double-click.
- **90+ controls** across 17 hardening domains (UAC, firewall, SMB, RDP, NTLMv2, ASR, SChannel/TLS, LSA, BitLocker, DoH, HVCI, telemetry, autorun, ...).
- **Cross-architecture.** Architecture-aware: detects **ARM64**, **Intel x64**, and **AMD x64**, skips Intel-only mitigations on ARM, and prints CPU-specific guidance for virtualisation-based features. The same threat scan + remediation runs on all three.
- **GUI _and_ CLI.** A dark-themed WPF interface for click-driven work, a colour-coded terminal menu for SSH/headless boxes.
- **Threat hunt.** Heuristic IOC sweep (`option 103`) reads ~15 persistence + tampering surfaces — IFEO sticky-keys hijacks, AppInit_DLLs, WMI event subscriptions, scheduled tasks running base64-encoded PowerShell, broad Defender exclusions, hosts-file abuse, Volume Shadow Copy disabled (ransomware staging), and more. `option 104` applies confirmed auto-fixes.
- **Total reversibility.** Every registry write is captured to a JSON snapshot. One click restores the previous values from any session.
- **HTML report.** Generates a shareable, score-card style report from the live system posture.
- **Scriptable.** `-Apply`, `-QuickWin`, `-Status`, `-Report`, `-Rollback` switches let you fold it into provisioning pipelines.

---

## Quick start

> **No download? No installation? No problem.** Double-click `runner.bat` and pick how you want to run it.

```text
git clone https://github.com/at0m-b0mb/Windows-Security-Enhancer.git
cd Windows-Security-Enhancer
runner.bat            (interactive selector: GUI / CLI / preset / report)
```

You will see:

```
============================================================
   W I N D O W S   S E C U R I T Y   E N H A N C E R   v5.1
============================================================

  How would you like to run it?

    [1]  Graphical interface  (recommended)
    [2]  Classic terminal menu
    [3]  Quick Win preset  (run safe defaults right now)
    [4]  Show security status only
    [5]  Export HTML security report
    [6]  Help / command-line usage
    [Q]  Quit
```

The launcher auto-elevates via UAC, so you never need to remember "Run as administrator" — accept the prompt and you're in.

---

## Table of contents

- [Two ways to run it](#two-ways-to-run-it)
- [Requirements](#requirements)
- [File layout](#file-layout)
- [Command-line reference](#command-line-reference)
- [Feature catalogue](#feature-catalogue)
- [The Quick Win preset](#the-quick-win-preset)
- [Logging, backups & rollback](#logging-backups--rollback)
- [HTML report](#html-report)
- [Compatibility notes & warnings](#compatibility-notes--warnings)
- [What's new in v5.1](#whats-new-in-v51)
- [Contributing](#contributing)
- [License](#license)

---

## Two ways to run it

### Graphical interface (`runner_gui.bat`)

A dark-themed WPF window with:

- **Left pane** — 11 category navigation buttons (UAC, Firewall, Devices, Defender, ...).
- **Centre pane** — feature cards with title, description, risk-level chip (`safe` / `restore` / `caution` / `info`), and one-click apply.
- **Right pane** — live security posture panel: each control shows its current state, plus an aggregate **hardening score**. Refreshes automatically after every action.
- **Bottom log** — colour-coded activity log capturing every change. Same content as the on-disk transcript.
- **Footer buttons** — "Apply Quick Win" (safe sweep) and "Apply ALL" (aggressive sweep).
- **Header buttons** — Refresh status, Export HTML report, Rollback (opens a session-picker).

Nothing is installed: WPF (Windows Presentation Foundation) ships with every Windows release since Vista, and PowerShell 5.1 ships with Windows 10/11.

### Terminal menu (`runner.bat` → CLI option)

A numbered menu with 90+ options grouped by category. Identical hardening capabilities to the GUI, plus a few power-user actions (typed confirmations for destructive operations, interactive rollback selector, capability report).

Pick the GUI if you want speed and visibility. Pick the CLI for SSH sessions, Server Core, or scripted runs.

---

## Requirements

| Requirement | Details |
|-------------|---------|
| **Operating System** | Windows 10, Windows 11, Windows Server 2016 / 2019 / 2022 / 2025 |
| **PowerShell** | 5.1+ (preinstalled on Windows 10+). PowerShell 7 works too. |
| **Privileges** | Administrator — `runner.bat` handles UAC elevation automatically. |
| **WPF (for GUI)** | Ships with .NET Framework, preinstalled on every supported Windows release. **No download required.** |
| **BitLocker (opt.)** | Windows Pro / Enterprise / Education |
| **Memory Integrity (opt.)** | CPU virtualisation + UEFI Secure Boot |
| **DoH (opt.)** | Native cmdlets need Windows 11 22H2 / Server 2022+; older builds fall back to policy registry keys |

---

## File layout

```
Windows-Security-Enhancer/
+- runner.bat                 (interactive launcher: GUI / CLI / preset / report)
+- runner_gui.bat             (skip the menu, launch the WPF GUI directly)
+- win_more_secure.ps1        (engine: every Verb-Noun function + CLI menu)
+- win_more_secure_gui.ps1    (WPF GUI; dot-sources the engine for its functions)
+- README.md

%ProgramData%\WSE\            (created at first run, ACL'd to Admins + SYSTEM)
+- logs\                      (per-session Start-Transcript output .log)
+- backups\<timestamp>\       (per-session registry_backup.json)
+- ps-transcripts\            (PowerShell module / script-block transcripts)
```

| File | Purpose |
|------|---------|
| `runner.bat` | Self-elevates, parses CLI args, presents the GUI/CLI/preset/report selector. Routes to the right entry point. |
| `runner_gui.bat` | One-shot launcher straight into the GUI (for desktop shortcuts). |
| `win_more_secure.ps1` | All hardening functions, the CLI menu, logging, backup, rollback. Can be invoked non-interactively. |
| `win_more_secure_gui.ps1` | WPF interface. Dot-sources the engine with `-NoElevate -NoMenu` so every Verb-Noun function is callable from the UI. |

---

## Command-line reference

`runner.bat` is the recommended entry point — it handles elevation and forwards arguments cleanly.

| Command | Effect |
|---------|--------|
| `runner.bat`               | Interactive launcher menu |
| `runner.bat gui`           | Launch the WPF GUI |
| `runner.bat cli`           | Launch the classic terminal menu |
| `runner.bat quick`         | Apply the Quick Win preset (safe defaults) then exit |
| `runner.bat apply`         | Apply the full hardening sweep (aggressive) then exit |
| `runner.bat status`        | Print the security status report then exit |
| `runner.bat report`        | Export the HTML security report then exit |
| `runner.bat help`          | Show CLI usage |

The PowerShell engine itself accepts the same switches:

```powershell
powershell -ExecutionPolicy Bypass -File win_more_secure.ps1 -Status
powershell -ExecutionPolicy Bypass -File win_more_secure.ps1 -QuickWin
powershell -ExecutionPolicy Bypass -File win_more_secure.ps1 -Apply
powershell -ExecutionPolicy Bypass -File win_more_secure.ps1 -Report -ReportPath "C:\Reports\wse.html"
powershell -ExecutionPolicy Bypass -File win_more_secure.ps1 -Rollback
```

The engine self-elevates on launch unless invoked with `-NoElevate`. The GUI uses that internally to avoid a recursive UAC loop.

---

## Feature catalogue

Numbers below match the CLI menu options. The GUI groups them by category and adds a one-click "Apply" button.

Legend: **harden** = hardening action, **restore** = revert to default, **caution** = aggressive (typed confirmation required), **info** = read-only, **util** = utility.

<details open>
<summary><b>UAC &amp; Authentication (1-6, 47)</b></summary>

| # | Action | Notes |
|---|--------|-------|
| 1 | harden — Enforce UAC credential prompt | `ConsentPromptBehaviorAdmin=1`, `EnableLUA=1` |
| 2 | harden — UAC "Always Notify" | Maximum level (`ConsentPromptBehaviorAdmin=2`) |
| 3 | restore — UAC to Windows default | Value 5 |
| 4 | harden — Account lockout policy | 5 failed attempts -> 30-min lockout |
| 5 | restore — Account lockout to default | |
| 6 | harden — Strong password policy | 14 chars min, complexity, 90-day expiry, history 10 |
| 47 | harden — Rename built-in Administrator | RID-500 by SID, prompts for the new name |

</details>

<details>
<summary><b>Firewall &amp; Network (7-13, 40-44, 60-62, 65-66, 74-79, 88, 96-97)</b></summary>

| # | Action | Notes |
|---|--------|-------|
| 7 | harden — Enable Windows Firewall + block hostile ports | All 3 profiles; blocks Telnet/135/137-9/445/1433-4/3389/5985-6 on Public |
| 8 | caution — Disable Windows Firewall | Typed confirmation required |
| 9 | harden — Disable SMBv1 | Server + client + optional feature |
| 10 | caution — Enable SMBv1 | `ENABLE-SMB1` typed confirmation |
| 11 | harden — Disable RDP | |
| 12 | restore — Enable RDP | NLA required + High (FIPS) encryption + TLS security layer |
| 13 | harden — Disable anonymous + LLMNR + NBT-NS + mDNS | Stops poisoning / relay attacks |
| 40 | harden — Disable Remote Assistance | |
| 41 | restore — Enable Remote Assistance | |
| 42 | harden — Set secure DNS | Cloudflare 1.1.1.1 + Quad9 9.9.9.9 |
| 43 | harden — Disable IPv6 | Adapter binding + `DisabledComponents=0xFF` |
| 44 | restore — Enable IPv6 | |
| 60 | harden — Enable Firewall logging | Allowed + blocked, 32 MB, all profiles |
| 61 | caution — Block all outbound by default | `BLOCK-OUTBOUND` confirmation |
| 62 | restore — Default outbound action | |
| 65 | harden — Disable PowerShell Remoting / WinRM | |
| 66 | restore — Enable PowerShell Remoting / WinRM | |
| 74 | harden — Disable IPv6 transition tech | Teredo / ISATAP / 6to4 |
| 75 | harden — Harden SChannel | Disable SSL 2/3, TLS 1.0/1.1, RC4/DES/3DES/MD5/SHA-1 |
| 76 | restore — SChannel defaults | |
| 77 | harden — Enable DNS-over-HTTPS | Cloudflare + Quad9 templates, `DoHPolicy=Required` |
| 78 | harden — Enforce SMB signing | Client + server, refuse insecure guest logons |
| 79 | harden — Enforce LDAP signing + channel binding | |
| 88 | harden — **Firewall stealth mode** | Block ICMP echo on the Public profile (drops untrusted pings) |
| 96 | harden — **Harden RDP redirection** | Block clipboard / drive / printer / port / camera / audio redirection |
| 97 | restore — RDP redirection defaults | |

</details>

<details>
<summary><b>Devices &amp; Storage (14-19, 56-57, 63-64, 86)</b></summary>

| # | Action | Notes |
|---|--------|-------|
| 14 | harden — Disable USB storage | UsbStor + cdrom + RemovableStorageDevices policy. **HID safe.** |
| 15 | restore — Enable USB storage | |
| 16 | harden — Disable cameras | PnP disable + CapabilityAccess Deny |
| 17 | restore — Enable cameras | |
| 18 | harden — Disable AutoRun / AutoPlay | All drive types |
| 19 | restore — Enable AutoRun / AutoPlay | |
| 56 | harden — Disable Bluetooth | bthserv + per-device PnP |
| 57 | restore — Enable Bluetooth | |
| 63 | info — Show BitLocker status | Per-volume |
| 64 | harden — Enable BitLocker on C: | XTS-AES 256, TPM or TPM+PIN, recovery key saved to Desktop |
| 86 | harden — Disable hibernation | Purges `hiberfil.sys` |

</details>

<details>
<summary><b>Defender, ASR &amp; SmartScreen (20, 51-52, 70-71, 84-85)</b></summary>

| # | Action | Notes |
|---|--------|-------|
| 20 | harden — Configure Defender (max) | RT, MAPS Advanced, BAFS, PUA, network/folder/sample/archive/script/IOAV/behaviour scanning |
| 51 | harden — Enable 16 ASR rules (Block) | LSASS theft, Office macros, drivers, webshells, USB unsigned, PSExec/WMI, ... |
| 52 | restore — Disable all ASR rules | |
| 70 | info — Defender Tamper-Protection status | Read-only — toggle in Windows Security UI |
| 71 | harden — Schedule Defender daily scan + sigs | Quick scan 02:00 daily; signature update every 4 h |
| 84 | harden — Enable SmartScreen everywhere | Explorer (Block), Edge (PUA on), Store apps (PreventOverride) |
| 85 | harden — Disable Quick Assist | Removes Appx + DISM capability (scam vector) |

</details>

<details>
<summary><b>Accounts, Scripts &amp; Services (21-27, 33-36, 53-55, 58-59)</b></summary>

| # | Action | Notes |
|---|--------|-------|
| 21 | harden — Disable Guest account | |
| 22 | caution — Enable Guest account | |
| 23 | harden — Disable Windows Script Host | Blocks .vbs / .js / .wsf malware |
| 24 | restore — Enable Windows Script Host | |
| 25 | harden — Disable unnecessary services | Remote Reg, Telnet, SSDP, UPnP, ICS, LLTD, iSCSI, WebClient, Xbox, ... |
| 26 | restore — Disabled services to Manual | |
| 27 | harden — Comprehensive audit policy | Success+failure all categories + PS script-block / module / transcription logs + 4688 cmdline + 1 GB Security log |
| 33 | harden — Disable Print Spooler | + lock remote RPC + restrict driver install (PrintNightmare) |
| 34 | restore — Enable Print Spooler | |
| 35 | harden — Force NTLMv2 only | `LmCompatibilityLevel=5`, no LM hash, 128-bit NTLM, NTLM auditing |
| 36 | harden — Disable PowerShell v2 | |
| 53 | harden — Set PowerShell -> RemoteSigned | LocalMachine scope |
| 54 | caution — Set PowerShell -> AllSigned | `ALLSIGNED` typed confirmation — blocks ALL unsigned local scripts |
| 55 | restore — PowerShell policy | Undefined |
| 58 | harden — Disable Office macros (+ block MOTW) | Word/Excel/PowerPoint/Access/Outlook/Publisher/Visio, Office 2007 - 365 |
| 59 | restore — Enable Office macros | Remove policy |

</details>

<details>
<summary><b>Hardening &amp; Credential Protection (28, 37-39, 80)</b></summary>

| # | Action | Notes |
|---|--------|-------|
| 28 | harden — Enable LSA / Credential Guard | `RunAsPPL=1`, WDigest off, VBS + HVCI keys, LsaCfg flag |
| 37 | harden — Enable Exploit Protection | DEP AlwaysOn, SEHOP, Heap Terminate, Force ASLR, Bottom-up, High-entropy, CFG |
| 38 | harden — Clear page file on shutdown | |
| 39 | restore — Disable page-file clear | |
| 80 | harden — Enable Memory Integrity (VBS + HVCI) | Requires CPU virt + UEFI Secure Boot |

</details>

<details>
<summary><b>Privacy &amp; Telemetry (29-32, 81-83, 94-95, 98-99)</b></summary>

| # | Action | Notes |
|---|--------|-------|
| 29 | harden — Disable Windows Telemetry | DiagTrack + dmwappushservice + AllowTelemetry=0 + CEIP + AIT + Inventory + WER + Activity History + Clipboard sync + Timeline |
| 30 | restore — Enable Telemetry | |
| 31 | harden — Disable Advertising ID | + Suggested apps, silent installs, OEM pre-installs, lock-screen spotlight |
| 32 | harden — Disable Cortana + web search | |
| 81 | harden — Disable consumer features | Store auto-install, spotlight, lock-screen ads |
| 82 | harden — Disable OneDrive (policy) | |
| 83 | harden — Disable Xbox + Game DVR | |
| 94 | harden — **Harden Microsoft Edge** | Telemetry / sync / sign-in off; payment, autofill, password manager off; strict tracking, DNT on, SmartScreen enforced; IE integration off |
| 95 | restore — Edge defaults | |
| 98 | harden — **Block adding Microsoft accounts** | `NoConnectedUser=3` — existing MS-account profiles still work |
| 99 | restore — Allow Microsoft accounts | |

</details>

<details>
<summary><b>Maintenance &amp; Utilities (45-46, 48-50, 67-68, 72-73, 87, 89-90, 93, 100-102)</b></summary>

| # | Action | Notes |
|---|--------|-------|
| 45 | harden — Force automatic Windows Updates | Daily install at 03:00 |
| 46 | harden — Screen auto-lock (5 min) | Screensaver + GP + `InactivityTimeoutSecs` + powercfg console lock |
| 48 | util — Create a System Restore Point | Bypasses 24-h throttle |
| 49 | info — OS / capability report | OS, edition, PSv, TPM, available cmdlets |
| 50 | info — Show log / backup locations | |
| 67 | info — Security Status Report | 35+ controls, colour-coded |
| 68 | harden — Apply ALL hardening | 50+ controls; creates a restore point first; ends with RemoteSigned |
| 72 | harden — Disable WebClient (WebDAV) | Closes NTLM-over-WebDAV relay vector |
| 73 | harden — Disable WPAD | Stops WinHttpAutoProxySvc + adds `0.0.0.0 wpad` to hosts |
| 87 | harden — **Apply Quick Win preset** | Curated safe defaults — see below |
| 89 | info — **Explain a hardening feature** | Prints colour-coded *What / Why / Risk* for any control |
| 90 | util — Export HTML security report | Saved to `%ProgramData%\WSE\logs\` |
| 93 | util — ROLLBACK | Interactive registry-snapshot restore |
| 100 | info — **Show listening TCP/UDP ports** | With owning process names — spot unexpected services |
| 101 | info — **Test for pending reboot** | Four-source check (CBS / WU / pending rename / computer rename) |
| 102 | info — **Show recent logon events** | Last 20 of EventID 4624 / 4625 from the Security log |

</details>

<details open>
<summary><b>🔎 Threat Hunt — IOC scan + remediation (103-104)</b></summary>

| # | Action | Notes |
|---|--------|-------|
| 103 | info — **Threat scan (heuristic IOC sweep)** | Reads ~15 persistence + tampering surfaces — see table below. Runs identically on ARM64, Intel x64, and AMD x64. Findings stored in memory for option 104. |
| 104 | caution — **Threat remediation** | Iterates the latest scan findings and applies confirmed auto-fixes. Each one prompts individually. Every change is registry-tracked so option 93 (rollback) can undo it. |

**Surfaces inspected by the threat scan:**

| Surface | What's flagged |
|---|---|
| AppInit_DLLs | Any non-empty value (legacy DLL injection vector) |
| Image File Execution Options | A `Debugger` value on any executable. Sticky-keys / utilman / osk / magnify / narrator hijacks are marked High |
| BootExecute | Any non-default entry under `Session Manager\BootExecute` |
| Run / RunOnce | Entries pointing to `%TEMP%` / `\AppData\Local\Temp` / `\Users\Public`, or executing base64-encoded PowerShell, or invoking script hosts (wscript / cscript / mshta / rundll32 javascript) |
| Scheduled tasks | Actions running from `%TEMP%`, base64-encoded PowerShell, or LoLBin downloaders (bitsadmin, certutil -urlcache, mshta http) |
| WMI | Any permanent `__EventConsumer` (often used for stealth persistence) |
| LSA packages | Authentication / Security / Notification packages outside the known-good whitelist |
| Hosts file | More than 50 entries (often malware blocks AV / Windows Update); explicit blocks of Microsoft update or Defender domains |
| DNS servers | Public DNS not in the known-good list (Cloudflare, Quad9, Google, OpenDNS, AdGuard) |
| Defender exclusions | Overly broad paths (`C:\`, `C:\Users`, `C:\Windows`, ...) and script-host process exclusions (powershell, cmd, wscript, ...) |
| Defender state | Real-time protection or antivirus engine disabled |
| Security event log | Disabled or smaller than 50 MB |
| RMM tools | TeamViewer, AnyDesk, ScreenConnect, ConnectWise, LogMeIn, RustDesk, Atera, Splashtop, GoToAssist, Kaseya, NinjaRMM, etc. (informational — they're sometimes legitimate IT software, but commonly abused by tech-support scammers) |
| Startup folders | Scripts (`.ps1`, `.vbs`, `.js`, `.bat`, `.hta`, `.wsf`) and `.lnk` shortcuts pointing to temp folders |
| Winlogon | `Shell` value not `explorer.exe`; `Userinit` not `C:\Windows\system32\userinit.exe,` |
| Volume Shadow Copy | VSS service disabled (commonly disabled before ransomware encryption) |

**Auto-fixes registered (option 104 confirms each one separately):**

| Fix | What it does |
|---|---|
| `Fix-AppInitDLLs` | Clears `AppInit_DLLs` and sets `LoadAppInit_DLLs=0` on both HKLM hives |
| `Fix-IFEO` | Removes the `Debugger` value from the affected IFEO subkey |
| `Fix-HostsFile` | Backs the hosts file up, writes the stock Microsoft default |
| `Fix-DefenderRT` | Re-enables Defender real-time protection |
| `Fix-EnableSecLog` | Enables the Security event log via `wevtutil` |
| `Fix-WinlogonShell` | Resets `HKLM\...\Winlogon\Shell` to `explorer.exe` |
| `Fix-WinlogonUserinit` | Resets `HKLM\...\Winlogon\Userinit` to the default |
| `Fix-EnableVSS` | Sets the Volume Shadow Copy service back to Manual start |

> Findings without a registered auto-fix (suspicious scheduled tasks, WMI event consumers, unknown LSA packages, broad Defender exclusions, RMM tools) are flagged with the exact path and value so you can verify and remove them by hand — automated removal of those would be too dangerous.

</details>

---

## The Quick Win preset

Option **87** in the CLI menu, or the **"Apply Quick Win"** button in the GUI.

Aggressive hardening can be too noisy for most users (USB storage off, Bluetooth off, hibernation off, IPv6 disabled, ...). The Quick Win preset includes only the **low-risk, high-impact** controls that almost never break a typical workstation:

- UAC -> Always Notify, lockout policy, firewall + logging
- SMBv1 off, SMB signing required
- Defender (max) + daily scans + 16 ASR rules
- AutoRun off, Guest off, WSH off, anonymous off
- Telemetry, Advertising ID, Consumer features off
- SmartScreen on, NTLMv2-only, Exploit Protection
- Remote Assistance off, WebClient off, WPAD off
- SChannel hardening, secure DNS, screen lock, RemoteSigned

Everything is still recorded for one-click rollback — but the **aggressive controls are deliberately skipped**.

---

## Logging, backups &amp; rollback

Every session writes three things under `%ProgramData%\WSE\`:

```
%ProgramData%\WSE\
+- logs\wse_20260514_134205.log           (Start-Transcript of the session)
+- backups\20260514_134205\
|   +- registry_backup.json               (every registry value about to change,
|                                          with type, old value, and "did it exist?")
+- ps-transcripts\                        (only if option 27 was used)
```

The `%ProgramData%\WSE\` directory is ACL'd at first creation to **Administrators + SYSTEM only** (no users, no Everyone). Logs may contain sensitive details from your registry, so they stay locked down.

**Rolling back** is two steps from anywhere:

- **GUI** -> click **Rollback...** in the header -> pick the session you want to undo -> confirm.
- **CLI** -> option **93** -> pick the session index -> type `YES`.

Rollback restores every registry value to whatever it was before that session ran, and removes any value that did not exist beforehand. **Service-state changes, firewall rules, and Group-Policy-style behaviours are not automatically reverted** — for those, use the matching `Enable-*` option (34 for the Spooler, 41 for Remote Assistance, etc.).

---

## HTML report

Option **90** in the CLI menu, or the **"Export HTML report"** button in the GUI, writes a stand-alone HTML file with:

- A circular **hardening score** (good >= 80, warning 50-79, bad < 50) computed from the live registry/service state.
- Per-category sections (Authentication, Network, Endpoint, Credentials, Privacy, ...) with a colour-coded indicator for each control.
- System metadata: OS name, edition, build, PowerShell version, TPM status, Defender / BitLocker / Process-Mitigation cmdlet availability.
- Embedded CSS — no external resources, no internet required. Send it to your auditor as-is.

---

## Compatibility notes &amp; warnings

| Setting | Potential impact |
|---------|-----------------|
| **USB storage disable** (14) | Blocks USB mass-storage & CD/DVD. HID and other classes unaffected. |
| **SMBv1 disable** (9) | Breaks communication with pre-Vista NAS / printers. |
| **Print Spooler disable** (33) | Disables all local and network printing. |
| **IPv6 disable** (43) | Modern corporate networks and some VPNs require IPv6. |
| **Block outbound by default** (61) | Breaks all outbound connections. Typed confirmation required. |
| **AllSigned execution policy** (54) | Blocks all unsigned local scripts. Typed confirmation. **Apply-All deliberately uses RemoteSigned.** |
| **BitLocker** (64) | **Back up the recovery key** before encrypting. |
| **Disable Bluetooth** (56) | Disconnects Bluetooth peripherals. |
| **Office macros disable** (58) | Blocks legitimate macro-enabled documents. |
| **Memory Integrity / HVCI** (80) | Older third-party drivers may refuse to load. |
| **SChannel hardening** (75) | Very old HTTPS servers (TLS 1.0/1.1 only) become unreachable. |
| **DoH required** (77) | DNS queries fall back to drop when DoH is unreachable. May break captive portals. |
| **Enforce SMB signing** (78) | Some legacy file servers (Samba < 4.x) won't be reachable. |
| **NTLM auditing** (35) | Audit-only by default; switch `RestrictReceivingNTLMTraffic` to `2` only after reviewing audit events. |
| **Hibernation disable** (86) | Also removes the Fast-Startup hybrid-shutdown feature. |

> **Best practice:** run the **Status report (67)** before and after, and create a **System Restore Point (48)** before applying the big sweep. The Apply-All option does both for you automatically.

---

## Cross-architecture support (ARM64 + Intel + AMD)

WSE detects the running architecture and adapts:

| Detection | What it does |
|---|---|
| `PROCESSOR_ARCHITECTURE` / `PROCESSOR_ARCHITEW6432` | Identifies `ARM64`, `AMD64` (x64), or legacy `x86` even when PowerShell itself is running in WoW64. |
| `Win32_Processor.Manufacturer` | Resolves to **Intel**, **AMD**, or other (Qualcomm Snapdragon, Apple, etc.). |
| `Win32_Processor.VirtualizationFirmwareEnabled` | Surfaces whether VT-x / SVM is enabled in firmware — required for HVCI / VBS. |

| Adaptation | Behaviour |
|---|---|
| Exploit Protection (37) | Skips SEHOP and the SEHOP mitigation on ARM64 (32-bit-only). Skips `bcdedit /set nx AlwaysOn` on ARM (NX is intrinsic to the ARMv8 spec). |
| Memory Integrity / HVCI (80) | Prints architecture-specific guidance — VT-x + EPT on Intel, AMD-V + RVI/NPT on AMD, virtualisation + Secure Boot on ARM. Warns when firmware virtualisation is reported off. |
| Threat scan + remediation (103, 104) | Identical code path on every architecture — every check uses the registry, CIM, the event log, or PowerShell cmdlets that exist everywhere. |
| Capability report (49) | Surfaces architecture, CPU name, core counts, and the firmware-virtualisation flag in plain text. The GUI header shows the same. |

The capability detection is exposed in `Get-WSECapabilities`:

```text
ProcessorArch  : ARM64
Is64Bit        : True
IsARM          : True
IsIntel        : False
IsAMD          : False
CpuVendor      : Qualcomm Technologies, Inc
CpuName        : Snapdragon (R) X 12-core X1E80100 @ 3.40 GHz
CpuCores       : 12
CpuLogical     : 12
VirtFwEnabled  : True
```

---

## What's new in v5.2

| Area | Change |
|------|--------|
| **🔎 Threat Hunt** | Brand-new heuristic IOC scanner (option 103) inspects ~15 persistence + tampering surfaces — IFEO sticky-keys hijacks, AppInit_DLLs, BootExecute, Run keys, scheduled tasks running base64 PowerShell, WMI event subscriptions, LSA package whitelist, hosts-file abuse, DNS whitelist, broad Defender exclusions, Security log state, RMM tools, startup-folder scripts, Winlogon Shell/Userinit, and Volume Shadow Copy. Companion remediation (option 104) applies confirmed auto-fixes one at a time. Same code path on ARM64 and x64. |
| **⚙️ Architecture awareness** | `Get-WSECapabilities` now reports CPU architecture, vendor, cores, and firmware-virtualisation state. Exploit Protection skips 32-bit-only mitigations on ARM. Memory Integrity prints vendor-specific guidance. The GUI header surfaces "ARM64 / Intel x64 / AMD x64" at a glance. |
| **GUI category** | New **Threat Hunt** category in the WPF interface with one-click scan + remediate. |
| **Explanations registry** | The *What / Why / Risk* registry now covers the threat-hunt entries too. |

## What's new in v5.1

| Area | Change |
|------|--------|
| **GUI** | Full WPF graphical front-end (`win_more_secure_gui.ps1` + `runner_gui.bat`). Dark theme, live status panel, hardening score, integrated activity log, point-and-click rollback. |
| **CLI parameters** | `-Apply`, `-QuickWin`, `-Status`, `-Report`, `-Rollback`, `-NoMenu`, `-NoElevate` — fold WSE into provisioning pipelines. |
| **Quick Win preset** | New CLI option 87 / GUI button — runs the curated safe-defaults subset. |
| **HTML report** | New CLI option 90 / GUI button — colour-coded score-card HTML, no external resources. |
| **Unified launcher** | `runner.bat` now has an interactive selector and forwards every CLI verb (`gui`, `cli`, `quick`, `apply`, `status`, `report`, `help`). |
| **Explain-a-feature** | CLI option 89 prints a colour-coded *What / Why / Risk* paragraph for any hardening control. The same registry powers the GUI's contextual info popup. |
| **10 new controls** | Firewall stealth mode (88), Edge hardening (94/95), RDP redirection lockdown (96/97), Microsoft-account block (98/99), open-ports diagnostic (100), pending-reboot test (101), recent-logon-events viewer (102). |
| **Bug fixes** | Three unapproved-verb functions renamed (`Enforce-*` -> `Set-*`). SMB1 status check no longer false-positives on a default Windows 11. `Backup-RegistryValue` now handles the `(Default)` value correctly. Tamper-Protection / RealTime checks no longer error under StrictMode on older Defender builds. BitLocker PIN validation enforces digits-only and length >= 6. `Apply-All` no longer writes duplicate UAC backup entries. |

### Earlier highlights (v5.0)

- Full transcript logging to `%ProgramData%\WSE\logs\`
- Automatic registry backup before every change + interactive rollback
- OS / edition / capability detection — features gracefully skip when unsupported
- 20+ hardening controls: SChannel TLS, DoH, HVCI, SMB / LDAP signing, Tamper-Protection check, WebDAV / WPAD / Quick Assist / hibernation, OneDrive / Xbox / Consumer features, SmartScreen everywhere, IPv6 transition tech, mDNS
- Typed confirmations for destructive operations
- Hardened launcher (verifies the script, uses `fltmc` for elevation detection)
- Critical bug fixes from v4.x (USB root-hub safety, `$profile` shadow, AllSigned-lockout)

---

## Contributing

To add a new hardening control:

1. Add a `Verb-Noun` function to `win_more_secure.ps1` (use `Set-WSERegistry` for every registry write so it gets auto-backed-up).
2. Add a CLI menu option in `Show-Menu` and route it in the `switch` block.
3. Add an entry to `$catalogue` in `win_more_secure_gui.ps1` (Title / Note / Action / Risk).
4. If the setting is readable back, add a status row to `Get-WSEStatusData` so the HTML report and GUI status panel pick it up.
5. Add a row to the README's feature catalogue.
6. Open a Pull Request describing what it hardens and why.

PowerShell guidelines:
- Use approved verbs (`Get-Verb` lists them — avoid `Enforce`, `Configure`, `Apply`).
- Keep every registry write going through `Set-WSERegistry` (it backs up the old value).
- For destructive operations, require a typed confirmation (`Read-Host` with a specific string).

---

## License

[MIT](LICENSE). Use at your own risk. Test in a controlled environment before deploying to production fleets. WSE writes to the registry, modifies services, and changes firewall rules — by design.

> **Disclaimer.** No security tool is a substitute for defence in depth: patching, MFA, endpoint detection, network segmentation, and user education matter far more than any single hardening sweep. WSE is one layer in that stack, not the whole stack.
