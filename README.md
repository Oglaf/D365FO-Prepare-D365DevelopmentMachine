# D365FO One-box Setup script

This PowerShell script automates the preparation of a D365 development machine. It performs various optimizations, installations, and configurations to ensure an efficient and streamlined development environment for Dynamics 365 Finance and Operations.
This version is a fork of the original repository created by [dodiggitydag](https://github.com/dodiggitydag), and it has undergone significant changes to address bugs and ensure compatibility with the latest versions of SQL Server, Windows 2019, and Chocolatey. 

## Compatibility

The script has been tested on one-box virtual machine, version 10.0.32 and earlier versions.

## What it does?

The script performs the following actions:

### Software installation
- Installs Chocolatey and a list of software packages commonly used in development environments, including .NET Core, Google Chrome, Notepad++, 7-Zip, Postman, Visual Studio Code, WinMerge, Agent Ransack, WizTree, smtp4dev, and Greenshot.

### Development optimization
- Uses d365fo.tools to optimize the development environment. Sets the web browser homepage to the local environment, changes the startup type of Management Reporter and Batch services to Disabled (it is recommended to enable them only when necessary), adds Windows Defender rules to speed up compilation time, and re-arms the Windows license.

### SQL optimization
- Optimizes SQL Server by installing the dbatools PowerShell module, setting max memory (4GB), adding trace flags, setting recovery model and database options, purging disposable and staging table data, deleting specific references, and reclaiming database space.

### Miscellaneous
- Clears all logs from the Event Viewer to ensure a clean starting point.
- Modifies the local user policy by setting the password to never expire and disabling password changes.
- Disables various privacy-related features in Windows, including Windows Telemetry, Bing search results in the Start Menu, and Cortana.
- Sets the power settings to High Performance to ensure optimal performance during development.

## Usage

Before running the script, prepare the machine by following these steps:

1. Run the "Generate Self-Signed Certificates" script.
2. Run "AdminUserProvisioning".
3. Restore the database, if you have it, but keep the name AxDB.
4. Install [.NET Framework 4.8](https://support.microsoft.com/en-us/topic/microsoft-net-framework-4-8-offline-installer-for-windows-9d23f658-3b97-68ab-d013-aa3c3e7495e0) and reboot.

Either download the repository and execute PowerShell as an administrator or download and execute directly from GitHub:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/Oglaf/D365FO-Prepare-D365DevelopmentMachine/master/Prepare-D365DevelopmentMachine.ps1'))
```
