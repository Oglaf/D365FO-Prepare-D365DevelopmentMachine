<# Prepare-D365DevelopmentMachine
 #
 # Preparation:
 # .NET Framework 4.8 or above required.
 #
 # Compatibility:
 # The script has been tested on OneBox virtual machine, version 10.0.37 and earlier versions.
 #>

 #region Check if required .NET version is installed

$requiredVersion = '4.8'

$dotNetVersion = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse |
                Get-ItemProperty -name Version -EA 0 |
                Where-Object { $_.PSChildName -match '^(?!S)\p{L}'} |
                Select-Object -ExpandProperty Version |
                Sort-Object -Descending |
                Select-Object -First 1

if ([string]::IsNullOrEmpty($dotNetVersion) -or [version]$dotNetVersion -lt [version]$requiredVersion) {
    Write-Host "Error: .NET Framework $requiredVersion or a higher version is not installed on this computer."
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyUp')
    Exit 1
}
#endregion

# Clean all logs from Event Viewer
Write-Host "Clearing logs from event viewer"
wevtutil el | Foreach-Object {wevtutil cl "$_"}

#region Installing d365fo.tools

# This is required by Find-Module, by doing it beforehand we remove some warning messages
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

if (Get-Module -ListAvailable -Name d365fo.tools) {
	Write-Host "Updating d365fo.tools"
    Update-Module -Name d365fo.tools
}
else {
    Write-Host "Installing d365fo.tools"
    Write-Host "Documentation: https://github.com/d365collaborative/d365fo.tools"
    Install-Module -Name d365fo.tools -SkipPublisherCheck -AllowClobber -Scope AllUsers
    Import-Module d365fo.tools
}

# Pausing D365FO to optimize CPU and RAM usage
Stop-D365Environment

#endregion

#region Installing additional software using Chocolatey
If (Test-Path -Path "$env:ProgramData\Chocolatey") {
    choco upgrade chocolatey -y -r
    choco upgrade all --ignore-checksums -y -r
}
Else {
    Write-Host "Installing Chocolatey"

    Set-ExecutionPolicy Bypass -Scope Process -Force; 
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; 
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

    # Determine choco executable location
    # This is needed because the path variable is not updated
    # This part is copied from https://chocolatey.org/install.ps1
    $chocoPath = [Environment]::GetEnvironmentVariable("ChocolateyInstall")
    if ($chocoPath -eq $null -or $chocoPath -eq '') {
        $chocoPath = "$env:ALLUSERSPROFILE\Chocolatey"
    }
    if (!(Test-Path ($chocoPath))) {
        $chocoPath = "$env:SYSTEMDRIVE\ProgramData\Chocolatey"
    }
    $chocoExePath = Join-Path $chocoPath 'bin\choco.exe'

    $packages = @(
        "dotnetcore"
        "googlechrome"
        "notepadplusplus.install"
        "7zip"
        "postman"
        "vscode"
        "winmerge"
        "agentransack"
        "wiztree"
        "smtp4dev"
        "greenshot"
        "nuget.commandline"
    )

    # Install each program
    foreach ($packageToInstall in $packages) {
        Write-Host "Installing $packageToInstall" -ForegroundColor Green
        & $chocoExePath "install" $packageToInstall "--ignore-checksums" "-y" "-r"
    }
}
#endregion

#region Optimizing using d365fo.tools
if (Get-Module -ListAvailable -Name d365fo.tools) {
    Write-Host "Setting web browser homepage to the local environment"
    Get-D365Url | Set-D365StartPage

    Write-Host "Setting Management Reporter to Disabled to reduce churn and Event Log messages"
    Get-D365Environment -FinancialReporter | Set-Service -StartupType Disabled

    Write-Host "Setting Batch to Disabled to speed up compilation time"
    Get-D365Environment -Batch | Set-Service -StartupType Disabled

    Write-Host "Setting Windows Defender rules to speed up compilation time"
    Add-D365WindowsDefenderRules -Silent

    Write-Host "Rearming Windows license"
    Invoke-D365ReArmWindows
}
#endregion

#region Local User Policy
# Set the password to never expire
Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" | Where-Object { $_.SID -Like "S-1-5-21-*-500" } | Set-LocalUser -PasswordNeverExpires 1

# Disable changing the password
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$name = "DisableChangePassword"
$value = "1"

if (!(Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
}
else {
    $passwordChangeRegKey = Get-ItemProperty -Path $registryPath -Name $name -ErrorAction SilentlyContinue

    if (-Not $passwordChangeRegKey) {
        New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    }
    else {
        Set-ItemProperty -Path $registryPath -Name $name -Value $value
    }
}

#endregion

#region Privacy
# Disable Windows Telemetry (requires a reboot to take effect)
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -Type DWord -Value 0
Get-Service DiagTrack, Dmwappushservice | Stop-Service | Set-Service -StartupType Disabled

# SmartScreen Filter for Store Apps: Disable
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost -Name EnableWebContentEvaluation -Type DWord -Value 0

# Start Menu: Disable Bing Search Results
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 0

# WiFi Sense: Shared HotSpot Auto-Connect: Disable
Set-ItemProperty -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots -Name value -Type DWord -Value 0

# Activity Tracking: Disable
@('EnableActivityFeed','PublishUserActivities','UploadUserActivities') |% { Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System -Name $_ -Type DWord -Value 0 }

# Start Menu: Disable Cortana
if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0

#endregion

#region SQL optimization
Function Execute-Sql {
    Param(
        [Parameter(Mandatory = $true)][string]$server,
        [Parameter(Mandatory = $true)][string]$database,
        [Parameter(Mandatory = $true)][string]$command
    )
    Process {
        $scon = New-Object System.Data.SqlClient.SqlConnection
        $scon.ConnectionString = "Data Source=$server;Initial Catalog=$database;Integrated Security=true"

        $cmd = New-Object System.Data.SqlClient.SqlCommand
        $cmd.Connection = $scon
        $cmd.CommandTimeout = 0
        $cmd.CommandText = $command

        try {
            $scon.Open()
            $cmd.ExecuteNonQuery()
        }
        catch [Exception] {
            Write-Warning $_.Exception.Message
        }
        finally {
            $scon.Dispose()
            $cmd.Dispose()
        }
    }
}

If (Test-Path "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL") {
    if (Get-Module -ListAvailable -Name dbatools) {
        Write-Host "Updating dbatools"
        Update-Module -Name dbatools
    }
    else {
        Write-Host "Installing dbatools PowerShell module"
        Install-Module -Name dbatools -SkipPublisherCheck -Scope AllUsers
        Import-Module dbatools
    }

    Set-DbatoolsInsecureConnection -SessionOnly

    Write-Host "Setting max memory to 4GB"
    Set-DbaMaxMemory -SqlInstance . -Max 4096
    
    Write-Host "Adding trace flags"
    Enable-DbaTraceFlag -SqlInstance . -TraceFlag 174, 834, 1204, 1222, 1224, 2505, 7412

    Write-Host "Restarting service"
    Restart-DbaService -Type Engine -Force

    Write-Host "Setting recovery model"
    Set-DbaDbRecoveryModel -SqlInstance . -RecoveryModel Simple -Database AxDB -Confirm:$false

    Write-Host "Setting database options"
    $sql = "ALTER DATABASE [AxDB] SET AUTO_CLOSE OFF"
    Execute-Sql -server "." -database "AxDB" -command $sql

    $sql = "ALTER DATABASE [AxDB] SET AUTO_UPDATE_STATISTICS_ASYNC OFF"
    Execute-Sql -server "." -database "AxDB" -command $sql

    Write-Host "Setting batchservergroup options"
    $sql = "delete batchservergroup where SERVERID <> 'Batch:'+@@servername

    insert into batchservergroup(GROUPID, SERVERID, RECID, RECVERSION, CREATEDDATETIME, CREATEDBY)
    select GROUP_, 'Batch:'+@@servername, 5900000000 + cast(CRYPT_GEN_RANDOM(4) as bigint), 1, GETUTCDATE(), '-admin-' from batchgroup
        where not EXISTS (select recid from batchservergroup where batchservergroup.GROUPID = batchgroup.GROUP_)"
    Execute-Sql -server "." -database "AxDB" -command $sql

    Write-Host "purging disposable data"
    $sql = "truncate table batchjobhistory
    truncate table batchhistory
    truncate table eventcud
    truncate table sysdatabaselog
    delete batchjob where status in (3, 4, 8)
    delete batch where not exists (select recid from batchjob where batch.BATCHJOBID = BATCHJOB.recid)

    EXEC sp_msforeachtable
    @command1 ='truncate table ?'
    ,@whereand = ' And Object_id In (Select Object_id From sys.objects
    Where name like ''%tmp'')'"

    Execute-Sql -server "." -database "AxDB" -command $sql

    Write-Host "purging staging tables data"
    $sql = "EXEC sp_msforeachtable
    @command1 ='truncate table ?'
    ,@whereand = ' And Object_id In (Select Object_id From sys.objects
    Where name like ''%staging'')'"

    Execute-Sql -server "." -database "AxDB" -command $sql

    $sql = "DELETE [REFERENCES] FROM [REFERENCES]
    JOIN Names ON (Names.Id = [REFERENCES].SourceId OR Names.Id = [REFERENCES].TargetId)
    JOIN Modules ON Names.ModuleId = Modules.Id
    WHERE Module LIKE '%Test%' AND Module <> 'TestEssentials'"

    Execute-Sql -server "." -database "DYNAMICSXREFDB" -command $sql

    Write-Host "Reclaiming freed database space"
    Invoke-DbaDbShrink -SqlInstance . -Database "AxDb", "DYNAMICSXREFDB" -FileType Data

    Write-Host "Reclaiming database log space"
    Invoke-DbaDbShrink -SqlInstance . -Database "AxDb", "DYNAMICSXREFDB" -FileType Log -ShrinkMethod TruncateOnly
}
Else {
    Write-Verbose "SQL not installed. Skipping SLQ optimization"
}

#endregion

#region Update power settings
# Set power settings to High Performance
Write-Host "Setting power settings to High Performance"
powercfg.exe /SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
#endregion

#region Updating OS and installed software
# Update Visual Studio 2022
$filepath = "C:\Program Files\Microsoft Visual Studio\2022\Professional"

if (Test-Path $filepath) {
    Start-Process -Wait `
        -FilePath "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vs_installer.exe" `
        -ArgumentList "update --passive --norestart --installpath `"$filepath`""
}

# Update Visual Studio 2019
Start-Process -Wait `
    -FilePath "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vs_installer.exe" `
    -ArgumentList 'update --passive --norestart --installpath "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional"'

# Set file and folder path for SSMS installer .exe
$folderpath = "c:\windows\temp"
$filepath = "$folderpath\SSMS-Setup-ENU.exe"

# If SSMS not present, download
if (!(Test-Path $filepath)) {
    Write-Host "Downloading SQL Server SSMS..."
    $URL = "https://aka.ms/ssmsfullsetup"
    $clnt = New-Object System.Net.WebClient
    $clnt.DownloadFile($URL, $filepath)
    Write-Host "SSMS installer download complete" -ForegroundColor Green
}
else {
    Write-Host "Located the SQL SSMS Installer binaries, moving on to install..."
}

# Start the SSMS installer
Write-Host "Beginning SSMS install..." -NoNewline
$Parms = " /Install /Quiet /Norestart /Logs log.txt"
$Prms = $Parms.Split(" ")
& "$filepath" $Prms | Out-Null
Write-Host "SSMS installation complete" -ForegroundColor Green

# Run Windows update
Install-Module PSWindowsUpdate
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot
#endregion