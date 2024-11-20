
# Windows Security Enhancer

## Overview
This project includes scripts to enhance Windows security by:
- Managing UAC settings to require passwords.
- Disabling/enabling USB ports to prevent unauthorized device usage.
- Managing camera access to prevent malware from exploiting cameras.
- Lockout policies for failed login attempts.

## Features
1. Enforce or disable UAC password requirements.
2. Set or restore account lockout policies.
3. Detect and disable/enable connected cameras.
4. Set UAC to "Always Notify."
5. Disable/enable USB ports to prevent HID injection attacks.

## Prerequisites
- **Windows OS** with PowerShell support.
- Administrator privileges to run scripts.

## How to Use
1. Run the `runner.bat` script to launch the project:
   - It ensures the `win_more_secure.ps1` script runs as Administrator.
2. Follow the on-screen menu to choose a task.

## Disclaimer
- Use at your own risk.
- Test in a controlled environment before deploying.

---

## License
This project is licensed under the [MIT License](LICENSE).
