<# Prepare-D365DevelopmentMachine
 #
 # Preparation:
 # .NET Framework 4.8 or above required.
 #
 # Compatibility:
 # The script has been tested on OneBox virtual machine, version 10.0.43 and earlier versions.
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
wevtutil el | Foreach-Object { wevtutil cl "$_" }

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
        "googlechrome"
        "notepadplusplus.install"
        "7zip"
        "postman"
        "agentransack"
        "wiztree"
        "smtp4dev"
        "greenshot"
        "nuget.commandline"
        "microsoftazurestorageexplorer"
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
@('EnableActivityFeed','PublishUserActivities','UploadUserActivities') | ForEach-Object { Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System -Name $_ -Type DWord -Value 0 }

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

# Debloat Microsoft Edge
Write-Host "Applying Microsoft Edge debloat settings"
$edgeRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
if (!(Test-Path $edgeRegPath)) {
    New-Item -Path $edgeRegPath -Force | Out-Null
}

$edgeSettings = @{
    "HideFirstRunExperience" = 1
    "SearchInSidebarEnabled" = 2
    "HubsSidebarEnabled" = 0
    "ReadAloudEnabled" = 0
    "DiagnosticData" = 0
    "PinBrowserEssentialsToolbarButton" = 0
    "EdgeCollectionsEnabled" = 0
    "PersonalizationReportingEnabled" = 0
    "SplitScreenEnabled" = 0
    "ImplicitSignInEnabled" = 0
    "GuidedSwitchEnabled" = 0
    "EdgeDefaultProfileEnabled" = "Default"
    "BrowserSignin" = 0
    "ShowMicrosoftRewards" = 0
    "AutoImportAtFirstRun" = 4
    "EdgeWorkspacesEnabled" = 0
    "EdgeWalletCheckoutEnabled" = 0
    "EdgeWalletEtreeEnabled" = 0
    "BuiltInDnsClientEnabled" = 0
    "AADWebSiteSSOUsingThisProfileEnabled" = 0
    "AccessibilityImageLabelsEnabled" = 0
    "AddressBarMicrosoftSearchInBingProviderEnabled" = 0
    "AllowGamesMenu" = 0
    "AutomaticHttpsDefault" = 2
    "BrowserAddProfileEnabled" = 0
    "BrowserGuestModeEnabled" = 0
    "ComposeInlineEnabled" = 0
    "ConfigureOnPremisesAccountAutoSignIn" = 0
    "ConfigureOnlineTextToSpeech" = 0
    "ConfigureShare" = 0
    "DefaultBrowserSettingsCampaignEnabled" = 0
    "Edge3PSerpTelemetryEnabled" = 0
    "EdgeEDropEnabled" = 0
    "SyncDisabled" = 1
    "WalletDonationEnabled" = 0
    "NonRemovableProfileEnabled" = 0
    "ImportOnEachLaunch" = 0
    "InAppSupportEnabled" = 0
    "LocalBrowserDataShareEnabled" = 0
    "LiveCaptionsAllowed" = 0
    "MSAWebSiteSSOUsingThisProfileAllowed" = 0
    "MicrosoftEdgeInsiderPromotionEnabled" = 0
    "MicrosoftEditorSynonymsEnabled" = 0
    "MicrosoftEditorProofingEnabled" = 0
    "RelatedWebsiteSetsEnabled" = 0
    "PaymentMethodQueryEnabled" = 0
    "PinningWizardAllowed" = 0
    "PromotionalTabsEnabled" = 0
    "QuickSearchShowMiniMenu" = 0
    "QuickViewOfficeFilesEnabled" = 0
    "RemoteDebuggingAllowed" = 0
    "ResolveNavigationErrorsUseWebService" = 0
    "RoamingProfileSupportEnabled" = 0
    "SearchForImageEnabled" = 0
    "SearchFiltersEnabled" = 0
    "SearchSuggestEnabled" = 0
    "SearchbarAllowed" = 0
    "SearchbarIsEnabledOnStartup" = 0
    "SharedLinksEnabled" = 0
    "ShowAcrobatSubscriptionButton" = 0
    "ShowOfficeShortcutInFavoritesBar" = 0
    "ShowRecommendationsEnabled" = 0
    "SpeechRecognitionEnabled" = 0
    "StandaloneHubsSidebarEnabled" = 0
    "TabServicesEnabled" = 0
    "TextPredictionEnabled" = 0
    "UploadFromPhoneEnabled" = 0
    "VisualSearchEnabled" = 0
    "NewTabPageSearchBox" = "redirect"
    "PasswordGeneratorEnabled" = 0
    "PasswordManagerEnabled" = 0
    "PasswordMonitorAllowed" = 0
    "PasswordProtectionWarningTrigger" = 0
    "AlternateErrorPagesEnabled" = 0
    "AskBeforeCloseEnabled" = 0
    "AutofillAddressEnabled" = 0
    "AutofillCreditCardEnabled" = 0
    "AutofillMembershipsEnabled" = 0
    "AADWebSSOAllowed" = 0
    "AIGenThemesEnabled" = 0
    "AccessCodeCastEnabled" = 0
    "AdditionalDnsQueryTypesEnabled" = 0
    "AdsTransparencyEnabled" = 0
    "EdgeAdminCenterEnabled" = 0
    "BingAdsSuppression" = 1
    "ConfigureDoNotTrack" = 1
    "EdgeAssetDeliveryServiceEnabled" = 0
    "EdgeShoppingAssistantEnabled" = 0
    "ExperimentationAndConfigurationServiceControl" = 0
    "NetworkPredictionOptions" = 0
    "UserFeedbackAllowed" = 0
    "WebWidgetAllowed" = 0
    "TyposquattingCheckerEnabled" = 0
    "TrackingPrevention" = 3
    "SigninInterceptionEnabled" = 0
    "SideSearchEnabled" = 0
    "ShowPDFDefaultRecommendationsEnabled" = 0
    "ShowHomeButton" = 0
    "ShoppingListEnabled" = 0
    "SafeBrowsingSurveysEnabled" = 0
    "SafeBrowsingDeepScanningEnabled" = 0
    "SafeBrowsingProxiedRealTimeChecksAllowed" = 0
    "PasswordDismissCompromisedAlertEnabled" = 0
    "MAMEnabled" = 0
    "HighEfficiencyModeEnabled" = 0
    "EdgeManagementEnabled" = 0
    "DesktopSharingHubEnabled" = 0
    "CopilotPageContextEnabled" = 0
    "ProactiveAuthWorkflowEnabled" = 0
    "CopilotPageContext" = 0
    "NewTabPageContentEnabled" = 0
    "NewTabPageAppLauncherEnabled" = 0
    "NewTabPageBingChatEnabled" = 0
    "NewTabPageQuickLinksEnabled" = 0
    "QRCodeGeneratorEnabled" = 0
    "TranslateEnabled" = 0
    "SpotlightExperiencesAndRecommendationsEnabled" = 0
    "ApplicationGuardFavoritesSyncEnabled" = 0
    "ApplicationGuardTrafficIdentificationEnabled" = 0
    "WebToBrowserSignInEnabled" = 0
    "SeamlessWebToBrowserSignInEnabled" = 0
    "EdgeAutofillMlEnabled" = 0
    "GenAILocalFoundationalModelSettings" = 1
    "PersonalizeTopSitesInCustomizeSidebarEnabled" = 0
    "ExtensionsPerformanceDetectorEnabled" = 0
    "PerformanceDetectorEnabled" = 0
    "EdgeEntraCopilotPageContext" = 0
    "MouseGestureEnabled" = 0
    "DisableScreenshots" = 0
    "WebCaptureEnabled" = 0
    "SpellcheckEnabled" = 0
    "AddressBarWorkSearchResultsEnabled" = 0
    "ScarewareBlockerProtectionEnabled" = 0
    "AddressBarTrendingSuggestEnabled" = 0
}

foreach ($key in $edgeSettings.GetEnumerator()) {
    if ($key.Value -is [string]) {
        Set-ItemProperty -Path $edgeRegPath -Name $key.Name -Value $key.Value -Type String -Force
    } else {
        Set-ItemProperty -Path $edgeRegPath -Name $key.Name -Value $key.Value -Type DWord -Force
    }
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

# Check and install SSMS if not present
function Test-SSMSInstalled {
    $ssmsPaths = @(
        "C:\Program Files (x86)\Microsoft SQL Server Management Studio 19\Common7\IDE\Ssms.exe", # SSMS 2019
        "C:\Program Files (x86)\Microsoft SQL Server Management Studio 20\Common7\IDE\Ssms.exe"  # SSMS 2022
    )

    foreach ($path in $ssmsPaths) {
        if (Test-Path $path) {
            $version = (Get-Item $path).VersionInfo.ProductVersion
            Write-Host "SSMS found at $path (Version: $version)"
            return $true
        }
    }

    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($regPath in $registryPaths) {
        $ssmsReg = Get-ItemProperty $regPath -ErrorAction SilentlyContinue | 
                    Where-Object { $_.DisplayName -like "*SQL Server Management Studio*" -and 
                                   ($_.DisplayVersion -like "19.*" -or $_.DisplayVersion -like "20.*") }
        if ($ssmsReg) {
            Write-Host "SSMS found in registry: $($ssmsReg.DisplayName) (Version: $($ssmsReg.DisplayVersion))"
            return $true
        }
    }

    Write-Host "No SSMS 2019 or 2022 installation detected."
    return $false
}

# Set file and folder path for SSMS installer
$folderpath = "C:\Windows\Temp"
$filepath = "$folderpath\SSMS-Setup-ENU.exe"

# Install SSMS only if not already installed
if (-not (Test-SSMSInstalled)) {
    # Download SSMS installer if not present
    if (!(Test-Path $filepath)) {
        Write-Host "Downloading SQL Server SSMS..."
        try {
            $URL = "https://aka.ms/ssmsfullsetup"
            $clnt = New-Object System.Net.WebClient
            $clnt.DownloadFile($URL, $filepath)
            Write-Host "SSMS installer download complete" -ForegroundColor Green
        } catch {
            Write-Host "Error downloading SSMS installer: $_" -ForegroundColor Red
            Exit 1
        }
    } else {
        Write-Host "Located the SQL SSMS Installer binaries, moving on to installation..."
    }

    # Start the SSMS installer
    Write-Host "Installing SSMS..."
    try {
        $Parms = "/Install /Quiet /Norestart /Logs `"$folderpath\ssms_install_log.txt`" SSMSInstallRoot=`"C:\Program Files (x86)\Microsoft SQL Server Management Studio 20`""
        $process = Start-Process -FilePath $filepath -ArgumentList $Parms -Wait -PassThru
        if ($process.ExitCode -eq 0) {
            Write-Host "SSMS installation complete" -ForegroundColor Green
        } else {
            Write-Host "SSMS installation failed with exit code: $($process.ExitCode)" -ForegroundColor Red
            Write-Host "Check logs at $folderpath\ssms_install_log.txt for details"
            Exit 1
        }
    } catch {
        Write-Host "Error during SSMS installation: $_" -ForegroundColor Red
        Exit 1
    }

    # Clean up installer
    Remove-Item $filepath -Force -ErrorAction SilentlyContinue
} else {
    Write-Host "SSMS is already installed. Updates will be handled by Windows Update."
}

# SQL Optimization section
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

    Write-Host "Disabling 'Build metadata cache when AOS starts' to speed up restart times after compile"
    $sql = "UPDATE SystemParameters SET ODataBuildMetadataCacheOnAosStartup = 0"
    Execute-Sql -server "." -database "AxDB" -command $sql
    
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

# Enable updates for all Microsoft updates
Write-Host "Enabling updates for all Microsoft products..."
$ServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager"; 
$ServiceManager.AddService2("7971f918-a847-4430-9279-4a52d1efe18d", 7, "") | Out-Null; 
Write-Host "Microsoft Update service enabled."

# Run Windows update
Install-Module PSWindowsUpdate -Force -SkipPublisherCheck
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot
#endregion