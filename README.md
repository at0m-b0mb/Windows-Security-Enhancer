
# Windows Security Enhancer

A PowerShell-based interactive toolkit that hardens Windows systems against
real-world attack techniques. Run it once to lock down a workstation, or apply
individual features à la carte.

---

## Features

### UAC & Authentication
| # | Action |
|---|--------|
| 1 | Enforce UAC credential prompt (value 1 — password required for admin tasks) |
| 2 | Set UAC to "Always Notify" (value 2 — maximum notification) |
| 3 | Restore UAC to Windows default |
| 4 | Set account lockout policy — 5 attempts, 30-minute lockout |
| 5 | Restore account lockout policy to default (no lockout) |
| 6 | Enforce strong password policy — 12-char minimum, complexity, 90-day expiry via `secedit` |

### Firewall & Network
| # | Action |
|---|--------|
| 7 | Enable Windows Firewall on all profiles + block dangerous inbound ports (Telnet, RPC, NetBIOS, SMB, MSSQL, RDP, WinRM) |
| 8 | Disable Windows Firewall *(not recommended)* |
| 9 | **Disable SMBv1** — eliminates the WannaCry / EternalBlue attack surface |
| 10 | Enable SMBv1 *(not recommended)* |
| 11 | Disable Remote Desktop (RDP) |
| 12 | Enable Remote Desktop (RDP) |
| 13 | Disable anonymous network access, LLMNR (relay-attack prevention) & NBT-NS (MITM prevention) |

### Devices & Storage
| # | Action |
|---|--------|
| 14 | Disable USB storage (UsbStor service + Root Hubs) |
| 15 | Enable USB storage |
| 16 | Disable connected cameras (PnP class Camera / Image) |
| 17 | Enable connected cameras |
| 18 | Disable AutoRun / AutoPlay on all drive types (prevents infected-drive attacks) |
| 19 | Enable AutoRun / AutoPlay |

### Defender, Accounts & Scripts
| # | Action |
|---|--------|
| 20 | Configure **Windows Defender** — real-time protection, cloud MAPS (Advanced), Block at First Sight, PUA protection, Network Protection, Controlled Folder Access (anti-ransomware), sample submission |
| 21 | Disable Guest account |
| 22 | Enable Guest account *(not recommended)* |
| 23 | **Disable Windows Script Host** — prevents execution of malicious `.vbs` / `.js` files |
| 24 | Enable Windows Script Host |

### Services, Auditing & Credentials
| # | Action |
|---|--------|
| 25 | Disable risky services — Remote Registry, Telnet, SSDP/UPnP, Internet Connection Sharing, WinRM, Remote Desktop services |
| 26 | Restore disabled services to Manual startup |
| 27 | Enable comprehensive **Security Audit Policy** — logs success+failure for logon, account management, object access, privilege use, policy changes + PowerShell Script Block & Module Logging + expands Security event log to 1 GB |
| 28 | Enable **LSA / Credential Guard protection** — RunAsPPL, disable WDigest plain-text credential caching, disable Restricted Admin mode |

### Privacy & Telemetry *(new in v3.0)*
| # | Action |
|---|--------|
| 29 | **Disable Windows Telemetry** — stops DiagTrack & dmwappushservice, sets AllowTelemetry=0, disables CEIP, AIT, and Windows Error Reporting |
| 30 | Enable Windows Telemetry (restore default) |
| 31 | **Disable Advertising ID** — removes per-user and policy-level ad tracking; disables suggested content and silent app installs |
| 32 | **Disable Cortana & web search** — blocks cloud search, location-based search, and web results in the Start menu |

### Advanced System Hardening *(new in v3.0)*
| # | Action |
|---|--------|
| 33 | **Disable Print Spooler** — mitigates PrintNightmare (CVE-2021-34527); stops and disables the Spooler service |
| 34 | Enable Print Spooler |
| 35 | **Force NTLMv2 only** — sets LmCompatibilityLevel=5, disables LM hash storage, enforces 128-bit NTLM session security |
| 36 | **Disable PowerShell v2** — removes the legacy engine that bypasses Script Block Logging |
| 37 | **Enable Exploit Protection** — DEP (AlwaysOn), SEHOP, Force ASLR, Heap Terminate on Corruption |
| 38 | **Enable clear page file on shutdown** — zeros the page file at every shutdown to prevent offline data recovery |
| 39 | Disable clear page file on shutdown (restore default) |
| 40 | **Disable Remote Assistance** — closes RA firewall rules and sets fAllowToGetHelp=0 |
| 41 | Enable Remote Assistance |

### Network & DNS Hardening *(new in v3.0)*
| # | Action |
|---|--------|
| 42 | **Set Secure DNS** — configures Cloudflare (1.1.1.1 / 1.0.0.1) and Google (8.8.8.8 / 8.8.4.4) on all active adapters |
| 43 | **Disable IPv6** — disables IPv6 binding on all adapters + registry flag, reducing network attack surface |
| 44 | Enable IPv6 |

### Additional Hardening *(new in v3.0)*
| # | Action |
|---|--------|
| 45 | **Force Automatic Windows Updates** — sets AUOptions=4 (auto download + install), daily at 03:00, ensures wuauserv is Automatic |
| 46 | **Set screen auto-lock** — screensaver + Group Policy timeout of 5 minutes with password-on-resume; requires password on wake from sleep |
| 47 | **Rename built-in Administrator account** — renames the RID-500 account to a custom name, making it harder for attackers to target |

### Utilities
| # | Action |
|---|--------|
| 48 | **Security Status Report** — colour-coded dashboard of 20 security controls: UAC, Firewall, Defender, RDP, Remote Assistance, SMBv1, Print Spooler, NTLM level, USB, Guest account, AutoRun, Script Host, LLMNR, WDigest, Telemetry, DiagTrack, Page File, SEHOP, IPv6, Cortana |
| 49 | **Apply ALL hardening settings** — runs every security function in sequence (31 total) |
| 50 | Exit |

---

## Prerequisites
- **Windows 10 / 11** or Windows Server 2016+ with PowerShell 5.1+
- **Administrator privileges** (the launcher enforces this automatically)

## How to Use
1. Double-click **`runner.bat`** — it auto-elevates to Administrator.
2. Use the on-screen menu to choose a feature, or select **49** to apply all
   hardening settings at once.
3. A **system restart** is recommended after running the full hardening suite.

## Files
| File | Purpose |
|------|---------|
| `runner.bat` | Launcher — elevates to Administrator, then calls the PowerShell script |
| `win_more_secure.ps1` | Main script — all security functions and interactive menu |

## Disclaimer
- Use at your own risk.
- Test in a controlled environment before deploying to production systems.
- Some features (e.g. SMBv1 disable, USB disable, IPv6 disable, Print Spooler disable) may affect legitimate workflows — review before applying.

---

## License
This project is licensed under the [MIT License](LICENSE).
