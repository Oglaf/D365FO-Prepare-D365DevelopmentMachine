<# Prepare-D365DevelopmentMachine
 #
 # Preparation:
 # .NET Framework 4.8 or above required.
 #
 # Compatibility:
 # The script has been tested on OneBox virtual machine, version 10.0.46 and earlier versions.
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
    Write-Host "Error: .NET Framework $requiredVersion or a higher version is not installed on this computer." -ForegroundColor Red
    Write-Host "Press any key to exit..."
    $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyUp') | Out-Null
    Exit 1
}
#endregion

# Clean all logs from Event Viewer
Write-Host "Clearing logs from event viewer" -ForegroundColor Cyan
wevtutil el | ForEach-Object { wevtutil cl "$_" }

#region Install NuGet provider
Write-Host "Installing NuGet provider..." -ForegroundColor Cyan
Install-PackageProvider -Name NuGet -Force -Confirm:$false | Out-Null
#endregion

#region Installing d365fo.tools
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

if (Get-Module -ListAvailable -Name d365fo.tools) {
    Write-Host "Updating d365fo.tools" -ForegroundColor Cyan
    Update-Module -Name d365fo.tools
}
else {
    Write-Host "Installing d365fo.tools" -ForegroundColor Cyan
    Write-Host "Documentation: https://github.com/d365collaborative/d365fo.tools"
    Install-Module -Name d365fo.tools -SkipPublisherCheck -AllowClobber -Scope AllUsers
    Import-Module d365fo.tools
}

# Pausing D365FO to optimize CPU and RAM usage
Stop-D365Environment
#endregion

#region Installing additional software using Chocolatey
If (Test-Path -Path "$env:ProgramData\Chocolatey") {
    choco upgrade chocolatey -y -r --no-progress --exitwhenrebootdetected
    choco upgrade all --ignore-checksums -y -r --no-progress --exitwhenrebootdetected
}
Else {
    Write-Host "Installing Chocolatey" -ForegroundColor Cyan

    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

    $chocoPath = [Environment]::GetEnvironmentVariable("ChocolateyInstall")
    if ([string]::IsNullOrWhiteSpace($chocoPath)) {
        $chocoPath = "$env:ALLUSERSPROFILE\Chocolatey"
    }
    if (!(Test-Path ($chocoPath))) {
        $chocoPath = "$env:SYSTEMDRIVE\ProgramData\Chocolatey"
    }
    $chocoExePath = Join-Path $chocoPath 'bin\choco.exe'

    $packages = @(
        "googlechrome",
        "notepadplusplus.install",
        "7zip",
        "postman",
        "agentransack",
        "wiztree",
        "smtp4dev",
        "greenshot",
        "nuget.commandline",
        "microsoftazurestorageexplorer",
        "vscode",
        "git.install"
    )

    foreach ($packageToInstall in $packages) {
        Write-Host "Installing $packageToInstall" -ForegroundColor Green
        & $chocoExePath "install" $packageToInstall "--ignore-checksums" "-y" "-r" "--no-progress" "--exitwhenrebootdetected"
    }
}
#endregion

#region Optimizing using d365fo.tools
if (Get-Module -ListAvailable -Name d365fo.tools) {
    Write-Host "Setting Management Reporter to Disabled to reduce churn and Event Log messages" -ForegroundColor Cyan
    Get-D365Environment -FinancialReporter | Set-Service -StartupType Disabled

    Write-Host "Setting Batch to Disabled to speed up compilation time" -ForegroundColor Cyan
    Get-D365Environment -Batch | Set-Service -StartupType Disabled

    Write-Host "Setting Windows Defender rules to speed up compilation time" -ForegroundColor Cyan
    Add-D365WindowsDefenderRules -Silent

    Write-Host "Enabling IIS Preload" -ForegroundColor Cyan
    Enable-D365IISPreload

    Write-Host "Rearming Windows license" -ForegroundColor Cyan
    Invoke-D365ReArmWindows
}
#endregion

#region Local User Policy
Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" | Where-Object { $_.SID -Like "S-1-5-21-*-500" } | Set-LocalUser -PasswordNeverExpires 1

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
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -Type DWord -Value 0
Get-Service DiagTrack, Dmwappushservice -ErrorAction SilentlyContinue | Stop-Service -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled

Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost -Name EnableWebContentEvaluation -Type DWord -Value 0
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 0
Set-ItemProperty -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots -Name value -Type DWord -Value 0

@('EnableActivityFeed','PublishUserActivities','UploadUserActivities') | ForEach-Object { 
    Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System -Name $_ -Type DWord -Value 0 -ErrorAction SilentlyContinue 
}

if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) { New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null }
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0

if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) { New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null }
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1

if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) { New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null }
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0

# Debloat Microsoft Edge
Write-Host "Applying Microsoft Edge debloat settings..." -ForegroundColor Cyan
$edgeRegUrl = "https://raw.githubusercontent.com/marlock9/edge-debloat/main/edge-debloat.reg"
$edgeRegFile = "$env:TEMP\edge-debloat.reg"

try {
    # Added -UseBasicParsing and -ErrorAction Stop
    Invoke-WebRequest -Uri $edgeRegUrl -OutFile $edgeRegFile -UseBasicParsing -ErrorAction Stop
    Write-Host "Downloaded edge-debloat.reg"

    Start-Process -FilePath "reg.exe" -ArgumentList "import `"$edgeRegFile`"" -Wait -NoNewWindow
    Write-Host "Applied edge-debloat.reg"

    $edgeRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    if (!(Test-Path $edgeRegPath)) { New-Item -Path $edgeRegPath -Force | Out-Null }
    Set-ItemProperty -Path $edgeRegPath -Name "FavoritesBarEnabled" -Value 1 -Type DWord -Force

    Remove-Item -Path $edgeRegFile -Force -ErrorAction SilentlyContinue
}
catch {
    Write-Warning "Failed to download or apply Edge debloat registry file: $_"
}

# Debloat Google Chrome
Write-Host "Applying Google Chrome debloat settings..." -ForegroundColor Cyan
$chromeRegUrl = "https://raw.githubusercontent.com/yashgorana/chrome-debloat/main/generated/windows/chrome.reg"
$chromeRegFile = "$env:TEMP\chrome.reg"

try {
    # Added -UseBasicParsing and -ErrorAction Stop
    Invoke-WebRequest -Uri $chromeRegUrl -OutFile $chromeRegFile -UseBasicParsing -ErrorAction Stop
    Write-Host "Downloaded chrome.reg"

    Start-Process -FilePath "reg.exe" -ArgumentList "import `"$chromeRegFile`"" -Wait -NoNewWindow
    Write-Host "Applied chrome.reg"

    Remove-Item -Path $chromeRegFile -Force -ErrorAction SilentlyContinue
}
catch {
    Write-Warning "Failed to download or apply Chrome debloat registry file: $_"
}
#endregion

#region Update power settings
Write-Host "Setting power settings to High Performance" -ForegroundColor Cyan
powercfg.exe /SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
#endregion

#region Updating OS and installed software
$vs2022Path = "C:\Program Files\Microsoft Visual Studio\2022\Professional"
if (Test-Path $vs2022Path) {
    Start-Process -Wait `
        -FilePath "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vs_installer.exe" `
        -ArgumentList "update --passive --norestart --installpath `"$vs2022Path`""
}

$vs2019Path = "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional"
if (Test-Path $vs2019Path) {
    Start-Process -Wait `
        -FilePath "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vs_installer.exe" `
        -ArgumentList "update --passive --norestart --installpath `"$vs2019Path`""
}

function Test-SSMSInstalled {
    $ssmsPaths = @(
        "C:\Program Files (x86)\Microsoft SQL Server Management Studio 22\Common7\IDE\Ssms.exe",
        "C:\Program Files (x86)\Microsoft SQL Server Management Studio 22\Release\Common7\IDE\Ssms.exe",
        "C:\Program Files\Microsoft SQL Server Management Studio 22\Common7\IDE\Ssms.exe",
        "C:\Program Files\Microsoft SQL Server Management Studio 22\Release\Common7\IDE\Ssms.exe"
    )

    foreach ($path in $ssmsPaths) {
        if (Test-Path $path) {
            $version = (Get-Item $path).VersionInfo.ProductVersion
            Write-Host "SSMS 22 found at $path (Version: $version)"
            return $true
        }
    }

    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($regPath in $registryPaths) {
        $ssmsReg = Get-ItemProperty $regPath -ErrorAction SilentlyContinue | 
                   Where-Object { $_.DisplayName -like "*SQL Server Management Studio*" -and $_.DisplayVersion -like "22.*" }
        
        if ($ssmsReg) {
            Write-Host "SSMS 22 found in registry: $($ssmsReg.DisplayName) (Version: $($ssmsReg.DisplayVersion))"
            return $true
        }
    }

    Write-Host "No SSMS 22 installation detected."
    return $false
}

$folderpath = "C:\Windows\Temp"
$filepath = "$folderpath\vs_SSMS.exe"

if (-not (Test-Path $folderpath)) {
    New-Item -ItemType Directory -Force -Path $folderpath | Out-Null
}

if (-not (Test-SSMSInstalled)) {
    if (!(Test-Path $filepath)) {
        Write-Host "Downloading SQL Server SSMS..." -ForegroundColor Cyan
        try {
            $URL = "https://aka.ms/ssms/22/release/vs_SSMS.exe"
            Invoke-WebRequest -Uri $URL -OutFile $filepath -UseBasicParsing -ErrorAction Stop
            Write-Host "SSMS installer download complete" -ForegroundColor Green
        } catch {
            Write-Host "Error downloading SSMS installer: $_" -ForegroundColor Red
            Exit 1
        }
    } else {
        Write-Host "Located the SQL SSMS Installer binaries, moving on to installation..."
    }

    Write-Host "Installing SSMS..." -ForegroundColor Cyan
    try {
        $Parms = "--installPath `"C:\Program Files (x86)\Microsoft SQL Server Management Studio 22`" --quiet --wait"
        $process = Start-Process -FilePath $filepath -ArgumentList $Parms -Wait -PassThru -ErrorAction Stop
        
        if ($process.ExitCode -eq 0) {
            Write-Host "SSMS installation complete" -ForegroundColor Green
        } else {
            Write-Host "SSMS installation failed with exit code: $($process.ExitCode)" -ForegroundColor Red
            Exit 1
        }
    } catch {
        Write-Host "Error during SSMS installation: $_" -ForegroundColor Red
        Exit 1
    }

    Remove-Item $filepath -Force -ErrorAction SilentlyContinue
} else {
    Write-Host "SSMS 22 is already installed. Updates will be handled by Windows Update." -ForegroundColor Green
}
#endregion

#region SQL optimization
Function Invoke-Sql {
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
            $cmd.ExecuteNonQuery() | Out-Null
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
        Write-Host "Updating dbatools" -ForegroundColor Cyan
        Update-Module -Name dbatools
    }
    else {
        Write-Host "Installing dbatools PowerShell module" -ForegroundColor Cyan
        Install-Module -Name dbatools -SkipPublisherCheck -Scope AllUsers -Force
        Import-Module dbatools
    }

    Write-Host "Disabling 'Build metadata cache when AOS starts' to speed up restart times after compile"
    $sql = "UPDATE SystemParameters SET ODataBuildMetadataCacheOnAosStartup = 0"
    Invoke-Sql -server "." -database "AxDB" -command $sql
    
    Set-DbatoolsInsecureConnection -SessionOnly
    Write-Host "Setting max memory to 4GB"
    Set-DbaMaxMemory -SqlInstance . -Max 4096
    
    Write-Host "Adding trace flags"
    Enable-DbaTraceFlag -SqlInstance . -TraceFlag 174, 834, 1204, 1222, 1224, 2505, 7412
    
    Write-Host "Restarting service"
    Restart-DbaService -Type Engine -Force
    
    Write-Host "Setting recovery model"
    Set-DbaDbRecoveryModel -SqlInstance . -RecoveryModel Simple -Database AxDB -Confirm:$false
}
#endregion

#region Windows update
Write-Host "Enabling updates for all Microsoft products..." -ForegroundColor Cyan
try {
    $ServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager" -ErrorAction Stop
    $ServiceManager.AddService2("7971f918-a847-4430-9279-4a52d1efe18d", 7, "") | Out-Null
    Write-Host "Microsoft Update service enabled." -ForegroundColor Green
} catch {
    Write-Warning "Could not enable Microsoft Update service via COM object. Moving on."
}

Install-Module PSWindowsUpdate -Force -SkipPublisherCheck -AllowClobber
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot
#endregion