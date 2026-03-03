
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
| 6 | Enforce strong password policy — 12-char minimum, complexity, 90-day expiry |

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

### Utilities
| # | Action |
|---|--------|
| 29 | **Security Status Report** — colour-coded dashboard of current UAC, Firewall, Defender, RDP, SMBv1, USB, Guest account, AutoRun, Script Host, LLMNR, and WDigest status |
| 30 | **Apply ALL hardening settings** — runs every security function above in sequence |
| 31 | Exit |

---

## Prerequisites
- **Windows 10 / 11** or Windows Server 2016+ with PowerShell 5.1+
- **Administrator privileges** (the launcher enforces this automatically)

## How to Use
1. Double-click **`runner.bat`** — it auto-elevates to Administrator.
2. Use the on-screen menu to choose a feature, or select **30** to apply all
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
- Some features (e.g. SMBv1 disable, USB disable) may affect legitimate workflows — review before applying.

---

## License
This project is licensed under the [MIT License](LICENSE).
