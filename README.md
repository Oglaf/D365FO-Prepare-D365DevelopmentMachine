# D365FO One-box Setup Script

Automates setup of a Dynamics 365 Finance and Operations development machine with installations, optimizations, and configurations.
Forked from [dodiggitydag](https://github.com/dodiggitydag), updated for SQL Server, Windows Server, and Chocolatey compatibility.

## Compatibility

Tested on one-box VM, version 10.0.44 and earlier.

## What it does?

### Software Installation

- Chocolatey and packages: Google Chrome, Notepad++, 7-Zip, Postman, Agent Ransack, WizTree, smtp4dev, Greenshot, NuGet CLI.
- SSMS 2022 (if not installed, versions 19.x/20.x).
- `d365fo.tools` PowerShell module.

### Development Optimization

- `d365fo.tools`: Disables Management Reporter/Batch services, adds Defender rules, re-arms Windows license.

### SQL Optimization

- Installs `dbatools` module.
- Local SQL Server: Sets 4GB max memory, trace flags (174, 834, 1204, 1222, 1224, 2505, 7412), restarts service, sets `AxDB` recovery model to Simple.

### Privacy and System Configuration

- Clears Event Viewer logs.
- Local user policy: Password never expires, disables password changes.
- Disables Telemetry, SmartScreen, Bing in Start, WiFi Sense, activity tracking, Cortana.
- Debloats Edge (disables telemetry, autofill, Cortana, Bing, promotions).
- Sets High Performance power plan.

### Updates

- Enables Microsoft Update for all products.
- Updates Visual Studio 2019/2022 (if installed).
- Runs Windows Update with auto-reboot.

## Usage

1. Run "Generate Self-Signed Certificates".
2. Run "AdminUserProvisioning".
3. (10.0.39 or earlier) Install .NET Framework 4.8, reboot.

Run as administrator:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/Oglaf/D365FO-Prepare-D365DevelopmentMachine/master/Prepare-D365DevelopmentMachine.ps1'))
```
