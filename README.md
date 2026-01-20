# D365FO One-box Setup Script

Automates setup of a Dynamics 365 Finance and Operations development machine with installations, optimizations, and configurations.  
Forked from dodiggitydag, updated for SQL Server, Windows Server, and Chocolatey compatibility.

## Compatibility
Tested on one-box VM, version 10.0.46 and earlier.

## What it does?

### Software installation
- **Chocolatey packages**: Google Chrome, Notepad++, 7-Zip, Postman, Agent Ransack, WizTree, smtp4dev, Greenshot, NuGet CLI, **VS Code**, **Git**
- Installs **SSMS 22** (SQL Server Management Studio 2022) if not installed
- Installs the `d365fo.tools` PowerShell module

### Development optimization (`d365fo.tools`)
- Disables Management Reporter / Batch services
- Adds Microsoft Defender exclusions and rules
- **Enables IIS preload**
- Re-arms Windows license

### SQL optimization
- Installs the `dbatools` PowerShell module
- For local SQL Server:
  - Sets max memory to 4 GB
  - Enables trace flags: `174`, `834`, `1204`, `1222`, `1224`, `2505`, `7412`
  - Restarts SQL Server service
  - Sets the `AxDB` database recovery model to `SIMPLE`

### Privacy and system configuration
- Clears Event Viewer logs
- Local user policy: password never expires and disables password changes
- Disables telemetry, SmartScreen, Bing in Start, Wi‑Fi Sense, activity tracking, Cortana
- **Debloats Edge** using marlock9/edge-debloat to disable telemetry and bloat (keeps Favorites Bar enabled)
- Sets High Performance power plan

### Updates
- Enables Microsoft Update for all products
- Updates Visual Studio 2019/2022 (if installed)
- Runs Windows Update (with auto-reboot)

## Usage

1. Run "Generate Self-Signed Certificates".
2. Run "AdminUserProvisioning".
3. (For 10.0.39 or earlier) Install .NET Framework 4.8, then reboot.

Run as Administrator:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force;iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/Oglaf/D365FO-Prepare-D365DevelopmentMachine/master/src/Prepare-D365DevelopmentMachine.ps1'))
```