# Prepare-D365DevelopmentMachine
This repository contains a script for preparing a development machine for Dynamics 365 for Finance and Operations by installing additional tools and configuring the operating system automatically. The script was originally created by [dodiggitydag](https://github.com/dodiggitydag), and this is a fork of the original repository.

### Purpose
The purpose of this fork is to update the script to support Visual Studio 2019. All credit goes to the original author, and any contributions or suggestions are welcome.

### Utilities
*	[Azure PowerShell](https://docs.microsoft.com/en-us/powershell/azure/overview?view=azurermps-6.11.0)
*	[Azure Command Line Interface (CLI)](https://docs.microsoft.com/en-us/cli/azure/get-started-with-azure-cli?view=azure-cli-latest)
*	[d365fo.tools](https://github.com/d365collaborative/d365fo.tools), PowerShell commands for Dynamics 365 for Finance and Operations
*	[dbatools](https://dbatools.io/), PowerShell commands for T-SQL
*	[Edge](https://www.microsoft.com/en-us/edge)
*	[Notepad++](https://notepad-plus-plus.org/)
*	[Ola Hallengren's SQL maintenance solution](https://ola.hallengren.com/)
*	[Peazip](http://www.peazip.org/)
*	[Sysinternals tools](https://docs.microsoft.com/en-us/sysinternals/)
*	[WinMerge](http://winmerge.org/) comparison tool

### Integrations/Interface Testing Utilities
*	[Fiddler](https://www.telerik.com/fiddler)
*	[Postman](https://www.getpostman.com/)
*	[Visual Studio Code](https://code.visualstudio.com/) w/Azure and SQL add-ins

### Performance Enhancements
* Rebuilds/Reorganizes SQL Server indexes on all databases
* Sets Windows Defender rules to speed up compilation time
* Prevents Management Reporter from automatically starting

### Miscellaneous
* Sets the web browser homepage to the local environment URL
* Set the password to never expire and disable change password menu item
* Configures Windows Updates
* Creates a logoff link on the desktop
* Disables Bing search results
* Disables Cortana
* Disables Windows telemetry
* Removes Metro apps on Windows 10
* Sets power settings to high performance
* Sets some privacy settings
* Updates PowerShell command line help

## Usage
Before running this script, you should create the VM, either using LCS or the VHD, and start the environment.  The first hour may be Windows Updates and the "antimalware" executable doing a virus scan on the drive.  Once that has completed (possible reboot required), run the following command to execute the PowerShell script on the VM:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliomutley/D365FO-Prepare-D365DevelopmentMachine/master/Prepare-D365DevelopmentMachine.ps1'))
```
Please record any problems encountered as issues to this repository.  Occasionally the tool used for automatic installations, Chocolately, will have an invlalid link to the installer for the software.  This is nothing we can change, however, it can be reported to the Chocolately project team.

## d365fo.tools
If you are not already using [d365fo.tools](https://github.com/d365collaborative/d365fo.tools) you should!  You can use the Install-D365SupportingSoftware command to install the packages this script does, quickly.

## Contributions are encouraged
There are several ways to contribute or give thanks:

A. Fork this repository, commit the necessary changes to your forked repository, then issue a pull request.

B. Comment on the blog post at [Calafell.me](http://calafell.me/automatically-prepare-a-development-vm-for-microsoft-dynamics-365-for-finance-and-operations/).

C. Tweet the original author at [@dodiggitydag](https://twitter.com/dodiggitydag).
