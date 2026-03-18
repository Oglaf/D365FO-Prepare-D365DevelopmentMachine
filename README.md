# D365FO One-box Setup Script

[![GitHub](https://img.shields.io/github/license/Oglaf/D365FO-Prepare-D365DevelopmentMachine)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://docs.microsoft.com/en-us/powershell/)

Automates setup of a Dynamics 365 Finance and Operations development machine with installations, optimizations, and configurations.

> Forked from [dodiggitydag](https://github.com/dodiggitydag), updated for SQL Server, Windows Server, and Chocolatey compatibility.

## Compatibility

| Component | Version |
|-----------|---------|
| D365FO | 10.0.46 and earlier |
| .NET Framework | 4.8+ |
| PowerShell | 5.1+ |

Tested on one-box VM environments.

## Prerequisites

Before running the script:

1. Run **Generate Self-Signed Certificates**
2. Run **AdminUserProvisioning**
3. (For 10.0.39 or earlier) Install .NET Framework 4.8, then reboot

## Quick Start

Run as Administrator:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force;iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/Oglaf/D365FO-Prepare-D365DevelopmentMachine/master/src/Prepare-D365DevelopmentMachine.ps1'))
```

Or run locally:

```powershell
.\src\Prepare-D365DevelopmentMachine.ps1
```

## Available Switches

| Switch | Description |
|--------|-------------|
| `-SkipChocolatey` | Skip software installation via Chocolatey |
| `-SkipPrivacy` | Skip privacy/telemetry settings |
| `-SkipSSMS` | Skip SSMS installation |
| `-SkipSqlOptimization` | Skip SQL Server optimizations |
| `-SkipWindowsUpdate` | Skip Windows Update |

### Examples

```powershell
# Skip Chocolatey packages
.\src\Prepare-D365DevelopmentMachine.ps1 -SkipChocolatey

# Skip privacy and Windows Update
.\src\Prepare-D365DevelopmentMachine.ps1 -SkipPrivacy -SkipWindowsUpdate

# Skip SSMS and SQL optimization
.\src\Prepare-D365DevelopmentMachine.ps1 -SkipSSMS -SkipSqlOptimization
```

## What It Does

### Software Installation

- **Chocolatey packages**: Google Chrome, Notepad++, 7-Zip, Postman, Agent Ransack, WizTree, smtp4dev, Greenshot, NuGet CLI, VS Code, Git
- **SSMS 22** (SQL Server Management Studio 2022) if not installed
- **`d365fo.tools`** PowerShell module for D365FO management

### Development Optimization

Using `d365fo.tools`:
- Disables Management Reporter / Batch services
- Adds Microsoft Defender exclusions and rules
- Enables IIS preload
- Re-arms Windows license

### SQL Optimization

- Installs the `dbatools` PowerShell module
- For local SQL Server:
  - Sets max memory to 4 GB
  - Enables trace flags: `174`, `834`, `1204`, `1222`, `1224`, `2505`, `7412`
  - Restarts SQL Server service
  - Sets `AxDB` database recovery model to `SIMPLE`

### Privacy & System Configuration

- Clears Event Viewer logs
- Local user policy: password never expires, disables password changes
- Disables telemetry, SmartScreen, Bing in Start, Wi‑Fi Sense, activity tracking, Cortana
- Debloats Edge using [marlock9/edge-debloat](https://github.com/marlock9/edge-debloat)
- Sets High Performance power plan

### Updates

- Enables Microsoft Update for all products
- Updates Visual Studio 2019/2022 (if installed)
- Runs Windows Update with auto-reboot

## Project Structure

```
D365FO-Prepare-D365DevelopmentMachine/
├── src/
│   └── Prepare-D365DevelopmentMachine.ps1   # Main script
├── LICENSE                                    # MIT License
└── README.md                                  # This file
```

## Credits

- Original author: [Dag Calafell, III](https://github.com/dodiggitydag)
- `d365fo.tools`: [d365collaborative/d365fo.tools](https://github.com/d365collaborative/d365fo.tools)
- Edge debloat: [marlock9/edge-debloat](https://github.com/marlock9/edge-debloat)

## License

MIT License - see [LICENSE](LICENSE) for details.
