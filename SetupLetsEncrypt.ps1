if ($PSVersionTable.PSVersion -lt [version]'5.1') {
    throw "This script requires PowerShell 5.1. Please install Windows Management Framework 5.1 from Microsoft. https://www.microsoft.com/en-us/download/details.aspx?id=54616"
}
if ($PSVersionTable.PSVersion -ge [version]'5.2') {
    throw "This script requires PowerShell 5.1. The MilestonePSTools module requires Windows PowerShell 5.1 due to a dependency on .NET Framework and it is not compatible with PowerShell $($PSVersionTable.PSVersion)"
}
Add-Type -AssemblyName System.Management.Automation, System.Windows.Forms

###
###  Check for admin prileges and prompt user to re-run as administrator if necessary
###
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $principal.IsInRole($adminRole)) {
    
    $options = [System.Management.Automation.Host.ChoiceDescription[]]@(
        [System.Management.Automation.Host.ChoiceDescription]::new('&No', 'Re-launch this script with admin privileges'),
        [System.Management.Automation.Host.ChoiceDescription]::new('&Yes', 'Exit this script')
    )
    $result = $host.UI.PromptForChoice('Administrator privileges are required', 'Re-run this script as Administrator?', $options, 0)
    if ($result) {
        Start-Process -FilePath powershell.exe -ArgumentList "-file $PSCommandPath" -Verb RunAs
    }
    exit
}



###
### Make sure we have the path to the Milestone Server Configurator utility which should be present if you have at least Management Server, Recording Server, or Mobile Server installed.
### Note: The command-line interface for Server Configurator was introduced in 2020 R3 so even if we find Server Configurator, it might not work until you upgrade to 2020 R3 or greater.
$configuratorPath = 'C:\Program Files\Milestone\Server Configurator\ServerConfigurator.exe'
if (-not (Test-Path $configuratorPath)) {
    $timeout = (Get-Date).AddMinutes(2)
    while (-not (Test-Path $configuratorPath) -and (Get-Date) -lt $timeout) {
        Write-Host 'Failed to locate Server Configurator. Please launch Server Configurator from your Mobile Server tray controller icon.' -ForegroundColor Yellow
        Start-Sleep -Seconds 3
        $p = (Get-Process -Name ServerConfigurator -ErrorAction Ignore).Path
        if ($p) {
            $configuratorPath = $p
        }
    }
    if (-not (Test-Path $configuratorPath)) {
        Write-Error "Could not find the Server Configurator. Please make sure you're running a recent version of Milestone Mobile Server."
        exit
    }
    else {
        Write-Host 'Found Server Configurator. The process will now be terminated so we can proceed.' -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        Get-Process -Name ServerConfigurator -ErrorAction Ignore | Stop-Process -Force
    }
}


###
### Locate the Mobile Server Service to ensure it's installed, and also so we can find the service account user to which read access must be granted for the certificate private key
###
$mobileServer = Get-CimInstance -ClassName win32_service -Filter "Name = 'Milestone XProtect Mobile Server'"
if ($null -eq $mobileServer) {
    throw 'Milestone XProtect Mobile Server service not found'
}
$serviceAccountName = $mobileServer.StartName



###
### Install dependencies like MilestonePSTools, and Posh-ACME
###
$ProgressPreference = 'SilentlyContinue'
Write-Host 'Setting SecurityProtocol to TLS 1.2, Execution Policy to RemoteSigned' -ForegroundColor Green
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

if ($null -eq (Get-PackageSource -Name NuGet -ErrorAction Ignore)) {
    Write-Host 'Registering the NuGet package source' -ForegroundColor Green
    $null = Register-PackageSource -Name NuGet -Location https://www.nuget.org/api/v2 -ProviderName NuGet -Trusted -Force
}

$nugetProvider = Get-PackageProvider -Name NuGet -ErrorAction Ignore
$requiredVersion = [Microsoft.PackageManagement.Internal.Utility.Versions.FourPartVersion]::Parse('2.8.5.201')
if ($null -eq $nugetProvider -or $nugetProvider.Version -lt $requiredVersion) {
    Write-Host 'Installing the NuGet package provider' -ForegroundColor Green
    $null = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
}

if ($null -eq (Get-Module -ListAvailable PowerShellGet | Where-Object Version -ge 2.2.5)) {
    Write-Host 'Installing PowerShellGet 2.2.5 or greater' -ForegroundColor Green
    $null = Install-Module PowerShellGet -MinimumVersion 2.2.5 -Force
}
# Hide progress as it can obscure user prompts later if run from PowerShell ISE
$ProgressPreference = 'SilentlyContinue'
foreach ($module in 'Posh-ACME', 'MilestonePSTools') {
    if ($null -eq (Get-Module -ListAvailable $module)) {
        Write-Host "Installing $module" -ForegroundColor Green
        Install-Module $module
    }
    else {
        Write-Host "Updating $module" -ForegroundColor Green
        Update-Module $module
    }
}
$ProgressPreference = 'Continue'


###
### Collect information required to use Posh-ACME and the Dynu API
###
$domain = Read-Host -Prompt 'Domain name'
$contact = Read-Host -Prompt 'Email address for expiration warnings (optional)'
$dnsPlugin = 'Dynu'
$pluginArgs = @{
    DynuClientID = Read-Host -Prompt 'Dynu API client ID'
    DynuSecretSecure = Read-Host 'Dynu API secret' -AsSecureString
}
$certParams = @{
    Domain = $domain
    FriendlyName = $domain
    DnsPlugin = $dnsPlugin
    PluginArgs = $pluginArgs
    Force = $true
    Install = $true
    AcceptTOS = $true
}
if (![string]::IsNullOrWhiteSpace($contact)) {
    $certParams.Contact = $contact
}


###
### Attempt to request and install a certificate
###
Set-PAServer LE_PROD
Write-Host "Requesting and installing certificate for $domain from Let's Encrypt" -ForegroundColor Green
$cert = New-PACertificate @certParams
if ($null -eq $cert) {
    Write-Error "Requesting a certificate for $domain failed. Please inspect the error(s) and try again."
    exit
}
$certStoreCert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object Thumbprint -eq $cert.Thumbprint
if ($null -eq $certStoreCert) {
    Write-Error "Certificate was not successfully installed into the certificate store at Cert:\LocalMachine\My. This is sometimes caused by a Windows bug and if you try again it may succeed."
    exit
}
$cert | Set-XProtectCertificate -VmsComponent MobileServer -Force -UserName $serviceAccountName -RemoveOldCert -ServerConfiguratorPath $configuratorPath


$renewalScript = {
    param([string]$Domain, [string]$ServerConfiguratorPath, [string]$ServiceAccountName)
    try {
        $logPath = Join-Path ([system.environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData)) -ChildPath ([io.path]::combine('Milestone', 'certificate-renewal.log'))
        Start-Transcript -Path $logPath
        $oldCert = Get-PACertificate -MainDomain $Domain
        if ($null -eq $oldCert) {
            throw "Posh-ACME certificate not found for domain $Domain"
        }
        Set-PAServer LE_PROD
        $newCert = Submit-Renewal -MainDomain $Domain
        if ($null -ne $newCert) {
            $newCert | Set-XProtectCertificate -VmsComponent MobileServer -Force -UserName $ServiceAccountName -RemoveOldCert -ServerConfiguratorPath $ServerConfiguratorPath -ErrorAction Stop
        }
    }
    catch {
        exit -1
    }
    finally {
        Stop-Transcript
    }
}

$jobParams = @{
    Name = 'Lets Encrypt Certificate Renewal for Milestone'
    ScriptBlock = $renewalScript
    ArgumentList = $domain, $configuratorPath, $serviceAccountName
    Trigger = New-JobTrigger -Daily -At (Get-Date).Date -RandomDelay (New-TimeSpan -Minutes 1)
    ScheduledJobOption = New-ScheduledJobOption -RunElevated -RequireNetwork -MultipleInstancePolicy IgnoreNew
    Credential = Get-Credential -Message 'Enter credentials for the scheduled task'
}
Get-ScheduledJob -Name $jobParams.Name -ErrorAction Ignore | Unregister-ScheduledJob -Force -Confirm:$false
$null = Register-ScheduledJob @jobParams -ErrorAction Stop

Write-Host @"
Done! A scheduled job has been registered in Windows Task Scheduler under
\Microsoft\Windows\PowerShell\ScheduledJobs and it will run daily, shortly after midnight. When
your Lets Encrypt certificate for $domain is eligible for renewal, the certificate will be renewed,
applied to the Mobile Server, and the old certificate will be removed to prevent a large collection
of old certficates accumulating in your certificate store.

The scheduled task will write a PowerShell transaction log to C:\ProgramData\Milestone\certificate-renewal.log
on each run, overwriting the previous log each time. Check this log file to verify that the task is
running daily, and behaving as expected.
"@ -ForegroundColor Green

#Client ID: 02949202-fb43-4fcf-8c88-672203ccbbe7
#Secret: JcKghcc6K7JMgUDpvQW2YKJhQ9DUJD