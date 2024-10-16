<#
.SYNOPSIS
Request and install a publicly signed certificate from Let's Encrypt for your Milestone XProtect Mobile Server.

.DESCRIPTION
This script is an all(most)-in-one tool to register a publicly signed certificate from Let's Encrypt
based on a DDNS domain name registered at Dynu.com. Before you run this script, please visit
Dynu.com, register, add a DDNS domain name to your account, and visit your Dynu.com control panel
to generate and take note of your OAuth2 ClientID and Secret.

This script will prompt you to provide your desired certificate domain name, your email address
(optional) for email notifications when a certificate is nearing expiration, and your Dynu client ID
and secret.

A folder will be created at C:\ProgramData\Milestone\MilestonePSTools, and a script will be saved
there under the name "Renew-VmsLECertificate.ps1". This script will be called by the
"Renew-VmsLECertificate" scheduled task which will be created in Task Scheduler under the path
"\Milestone".

You will be prompted to provide your Windows or AD account password so that the scheduled task can
run whether you are logged on or not, and the task will be registered with elevated privileges as
it will need to be able to add/remove certificates from the local machine certificate store.

The scheduled task will run daily, and when the current certificate is at least 60 days old, a new
certificate will be issued. When the task runs, it will log to a file under
"C:\ProgramData\Milestone\MilestonePSTools\Logs". There will be one log file per day and they
will be removed after 7 days. You will also find messages in the Windows Event Logs under the log
name "Milestone" and the source name "Renew-VmsLECertificate".

If the scheduled task stops running for any reason, or it fails to renew the certificate, Let's
Encrypt will send expiration notices to the provided email address if you choose to supply one.
Make sure to check the log files or Windows Event Logs if you unexpectedly receive an expiration
warning.

.PARAMETER StagingOnly
Specified when only staging server certificates are desired such as when performing frequent tests.
The production certificate authority has a low rate limit which, when triggered, will refuse to
accept certificate requests. The staging server is more forgiving and safe to use for test automation.

.EXAMPLE
.\New-VmsLECertificate.ps1

.EXAMPLE
.\New-VmsLECertificate.ps1 -StagingOnly

Run the script without switching to the production certificate authority after an initial successful request against
the staging server.

.NOTES
If you are hoping to use this script for automating certificate installation and renewals for all Milestone XProtect
VMS components, unfortunately it is not as easy to enable "Server encryption" as it is to enable encryption for the
mobile server today. It can be done, technically, but until XProtect products depend less on the hostname of the host
they are installed on, the process is not practical to automate without a foundational understanding of PKI and deep
familiarity with XProtect. See this community forum thread for reference: https://supportcommunity.milestonesys.com/s/question/0D53X0000A7RkgPSQS/securing-existing-xprotect-2022r1-installation?language=en_US
#>
param(
    [switch]$StagingOnly
)

Add-Type -AssemblyName System.Management.Automation, System.Security

#region Functions

function Test-IsElevated {
    Add-Type -AssemblyName System.Management.Automation
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
    $principal.IsInRole($adminRole)
}

function Invoke-PowerShellFile {
    param(
        [Parameter()]
        [ValidateSet('powershell', 'pwsh', IgnoreCase = $false)]
        [string]
        $Shell = 'pwsh',

        [Parameter()]
        [string]
        $File,

        [Parameter()]
        [switch]
        $AsAdmin,

        [Parameter()]
        [string[]]
        $ArgumentList
    )

    process {
        $processParams = @{
            FilePath = 'powershell.exe'
            ArgumentList = @(
                '-NoProfile',
                '-ExecutionPolicy', 'Bypass',
                '-File', $File
            )
        }
        if ($ArgumentList) {
            $processParams.ArgumentList += $ArgumentList
        }
        if ($AsAdmin) {
            $processParams.Verb = 'RunAs'
        }
        Start-Process @processParams
    }
}

function Find-ServerConfigurator {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    process {
        $defaultPath = 'C:\Program Files\Milestone\Server Configurator\ServerConfigurator.exe'
        if (Test-Path $defaultPath) {
            $defaultPath
            return
        }

        $path = $null
        try {
            $stopwatch = [diagnostics.stopwatch]::StartNew()
            Write-Host 'Failed to locate Server Configurator. Please launch Server Configurator from your Mobile Server tray controller icon within 2 minutes. If the process is not started by then, this script will exit.' -ForegroundColor Yellow
            
            do {
                if ([int]$stopwatch.Elapsed.TotalSeconds % 10) {
                    Write-Host "Time remaining before exit: $(120 - [int]$stopwatch.Elapsed.TotalSeconds) seconds"
                }
                Start-Sleep -Seconds 1
                $path = (Get-Process -Name ServerConfigurator -ErrorAction Ignore | Select-Object -First 1).Path
            } while ($null -eq $path -and $stopwatch.Elapsed.Seconds -lt 120)
        } finally {
            if (-not (Test-Path $path)) {
                throw "Could not find the Server Configurator. Please make sure you're running a recent version of Milestone Mobile Server."
            } else {
                Write-Host "ServerConfigurator.exe located at '$path'." -ForegroundColor Green
                Get-Process -Name ServerConfigurator -ErrorAction Ignore | Stop-Process -Force
                $path
            }
        }
    }
}

function Install-LECertificate {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]
        $Domain,

        [Parameter()]
        [switch]
        $NoEmail,

        [Parameter()]
        [string]
        $ClientId,

        [Parameter()]
        [securestring]
        $Secret,

        [Parameter()]
        [switch]
        $StagingOnly
    )

    process {
        $paServer = 'LE_STAGE'
        Set-PAServer $paServer

        while ($true) {
            if ($paServer -eq 'LE_STAGE') {
                if ($Domain.Count -eq 0) {
                    $Domain = Read-Host -Prompt 'Domain name'
                } else {
                    Write-Host "Domain is $($Domain -join ', ')"
                }
                $script:domainName = $Domain | Select-Object -First 1
                if (-not $NoEmail) {
                    $contact = Read-Host -Prompt 'Email address for expiration warnings (recommended)'
                }
                if ([string]::IsNullOrWhiteSpace($ClientId)) {
                    $ClientId = Read-Host -Prompt 'Dynu API client ID'
                }
                if ([string]::IsNullOrWhiteSpace($Secret)) {
                    $Secret = Read-Host 'Dynu API secret' -AsSecureString
                }
                $certParams = @{
                    Domain       = $domain
                    FriendlyName = $domain | Select-Object -First 1
                    DnsPlugin    = 'Dynu'
                    PluginArgs   = @{
                        DynuClientID     = $ClientId
                        DynuSecretSecure = $Secret
                    }
                    Force        = $true
                    # Install into the Windows Local Machine Certificate Store under "Personal"
                    AcceptTOS    = $true
                }
                if (-not [string]::IsNullOrWhiteSpace($contact)) {
                    $certParams.Contact = $contact
                }
                Write-Host "[TEST] Requesting certificate for $domain from Let's Encrypt" -ForegroundColor Magenta
            } else {
                Write-Host "Requesting and installing certificate for $domain from Let's Encrypt" -ForegroundColor Green
                $certParams.Install = $true
            }

            $cert = New-PACertificate @certParams
            if ($cert) {
                if ($StagingOnly) {
                    Write-Host "The StagingOnly switch is set - proceeding with the LE_STAGE certificate" -ForegroundColor Yellow
                    break
                }
                if ($paServer -eq 'LE_PROD') {
                    $certStoreCert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object Thumbprint -EQ $cert.Thumbprint
                    if ($null -eq $certStoreCert) {
                        Write-Error 'Certificate was not successfully installed into the certificate store at Cert:\LocalMachine\My. This is sometimes caused by a Windows bug and if you try again it may succeed.'
                        exit
                    }
                    break
                } else {
                    Write-Host "[TEST] Certificate request successful against Let's Encrypt staging server." -ForegroundColor Magenta
                    $paServer = 'LE_PROD'
                    Set-PAServer $paServer
                }
            } elseif ($paServer -eq 'LE_STAGE') {
                Write-Warning 'Certificate request failed. Please re-enter the request details or press CTRL+C to exit.'
            }
        }
        if ($cert) {
            $cert
        } else {
            throw "Let's Encrypt certificate request failed"
        }
    }
}

#endregion

try {
    $extraParams = @{}
    if ($StagingOnly) {
        $extraParams.ArgumentList = '-StagingOnly'
    }

    ###
    ###  Check for admin prileges and prompt user to re-run as administrator if necessary
    ###
    if (-not (Test-IsElevated)) {
        $options = [System.Management.Automation.Host.ChoiceDescription[]]@(
            [System.Management.Automation.Host.ChoiceDescription]::new('&No', 'Quit, and make no changes.'),
            [System.Management.Automation.Host.ChoiceDescription]::new('&Yes', 'Re-run this script with administrative privileges.')
        )
        $result = $host.UI.PromptForChoice('Administrator privileges are required', 'Re-run this script as Administrator?', $options, 0)
        if ($result) {
            Invoke-PowerShellFile -Shell powershell -File $PSCommandPath -AsAdmin @extraParams
        }
        exit
    }

    ###
    ###  Run PowerShell 5.1 if this is PowerShell 6+, or bail if PowerShell 5.1 is not available.
    ###
    if ($PSVersionTable.PSVersion -ge '5.2') {
        Write-Host "Re-running script with PowerShell.exe"
        Invoke-PowerShellFile -Shell powershell -File $PSCommandPath -AsAdmin @extraParams
    }

    if ($PSVersionTable.PSVersion -lt '5.1') {
        throw 'This script requires PowerShell 5.1. Please install Windows Management Framework 5.1 from Microsoft. More information: https://www.microsoft.com/en-us/download/details.aspx?id=54616'
    }


    ###
    ### Make sure we have the path to the Milestone Server Configurator utility which should be present if you have at least Management Server, Recording Server, or Mobile Server installed.
    ### Note: The command-line interface for Server Configurator was introduced in 2020 R3 so even if we find Server Configurator, it might not work until you upgrade to 2020 R3 or greater.
    ###
    $configuratorPath = Find-ServerConfigurator -ErrorAction Stop
    Write-Host "Server Configurator found at '$configuratorPath'" -ForegroundColor Green

    ###
    ### Locate the Mobile Server Service to ensure it's installed, and also so we can find the service account user to which read access must be granted for the certificate private key
    ###
    $mobileServer = Get-CimInstance -ClassName Win32_Service -Filter "Name = 'Milestone XProtect Mobile Server'"
    if ($null -eq $mobileServer) {
        throw 'Milestone XProtect Mobile Server service not found. Please run this script on a system with Mobile Server installed and running.'
    }
    $serviceAccountName = $mobileServer.StartName
    Write-Host "Milestone XProtect Mobile Server service account is '$serviceAccountName'" -ForegroundColor Green


    ###
    ### Install dependencies like MilestonePSTools, and Posh-ACME
    ###
    $ProgressPreference = 'SilentlyContinue'

    Write-Host 'Enabling TLS 1.1 and greater' -ForegroundColor Green
    [Net.SecurityProtocolType] | Get-Member -Static -MemberType Property | Where-Object Name -Match '^Tls\d' | ForEach-Object {
        $protocol = [Net.SecurityProtocolType]::($_.Name)
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor $protocol
    }

    if ($null -eq (Get-PackageSource -Name NuGet -ErrorAction Ignore)) {
        Write-Host 'Registering the NuGet package source' -ForegroundColor Green
        $null = Register-PackageSource -Name NuGet -Location https://www.nuget.org/api/v2 -ProviderName NuGet -Trusted -Force -ErrorAction Stop
    }

    $nugetProvider = Get-PackageProvider -Name NuGet -ErrorAction Ignore
    if ($null -eq $nugetProvider -or $nugetProvider.Version -lt 2.8.5.201) {
        Write-Host 'Installing the NuGet package provider' -ForegroundColor Green
        $null = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    }

    if ($null -eq (Get-Module -ListAvailable PowerShellGet | Where-Object Version -GE 2.2.5)) {
        Write-Host 'Installing PowerShellGet 2.2.5 or greater' -ForegroundColor Green
        $null = Install-Module PowerShellGet -MinimumVersion 2.2.5 -Force -SkipPublisherCheck
    }

    $reloadPowerShellSession = $false
    foreach ($module in 'Posh-ACME', 'MilestonePSTools', 'PSFramework') {
        $reloadPowerShellSession = $module -in (Get-Module).Name
        $latestVersion = (Find-Module -Name $module).Version
        $installRequired = $null -eq (Get-Module -Name $module -ListAvailable | Where-Object Version -EQ $latestVersion)
        if ($installRequired) {
            Write-Host "Installing the latest version of $module..." -ForegroundColor Green
            Install-Module $module -Force -SkipPublisherCheck -AllowClobber -ErrorAction Stop
        } else {
            Write-Host "The latest version of $module is already installed" -ForegroundColor Green
        }
    }
    if ($reloadPowerShellSession) {
        Write-Host 'Starting new PowerShell session to ensure we use the latest version of the required modules'
        Invoke-PowerShellFile -Shell powershell -File $PSCommandPath -AsAdmin @extraParams
    }

    $ProgressPreference = 'Continue'

    ###
    ### Collect information required to use Posh-ACME and the Dynu API
    ###
    $certParams = @{}
    if ($env:LE_DEBUG -eq $true) {
        $certParams.NoEmail = $true
        if (Get-Module Microsoft.PowerShell.SecretStore -ListAvailable -ErrorAction SilentlyContinue) {
            $secrets = Get-SecretInfo
            'LE_Domain', 'LE_ClientId', 'LE_Secret' | Where-Object { $_ -in $secrets.Name } | ForEach-Object {
                if ($_ -eq 'LE_Secret') {
                    $certParams.Secret = Get-Secret -Name $_
                } else {
                    $certParams[$_ -replace 'LE_'] = Get-Secret -Name $_ -AsPlainText
                }
            }
        }
    }
    $script:domainName = $null
    $cert = Install-LECertificate @certParams -StagingOnly:$StagingOnly
    $domain = $script:domainName
    Write-Host "Configuring Mobile Server to use certificate with thumbprint $($cert.Thumbprint)" -ForegroundColor Green
    Write-Host "You will see all Milestone services restart on this host while Server Configurator applies the certificate." -ForegroundColor Green
    $cert | Set-XProtectCertificate -VmsComponent MobileServer -Force -UserName $serviceAccountName -RemoveOldCert -ServerConfiguratorPath $configuratorPath
    


    $renewalScript = {
        param(
            [string]$Domain,
            [string]$ServerConfiguratorPath,
            [string]$ServiceAccountName,
            [string]$PAServer
        )
        try {
            # Setup PSFramework logger
            # Setup PSFramework logger to log to file and Windows Event Log
            $paramSetPSFLoggingProvider = @{
                Name            = 'eventlog'
                InstanceName    = 'Renew-VmsLECertificate'
                LogName         = 'Milestone'
                Source          = 'Renew-VmsLECertificate'
                Enabled         = $true
                Wait            = $true
                ExcludeTags     = 'logfile'
            }
            Set-PSFLoggingProvider @paramSetPSFLoggingProvider
            
            $logFolder = (New-Item -Path (Join-Path $PWD 'Logs') -ItemType Directory -Force).FullName
            $paramSetPSFLoggingProvider = @{
                Name            = 'logfile'
                InstanceName    = '<taskname>'
                FilePath        = Join-Path $logFolder 'renewal-log-%Date%.csv'
                Enabled         = $true
                EnableException = $true
                Wait            = $true
                ExcludeTags     = 'eventlog'
            }
            Set-PSFLoggingProvider @paramSetPSFLoggingProvider
            
            $scriptParams = [pscustomobject]@{
                PSCommandPath          = $PSCommandPath
                Domain                 = $Domain
                ServerConfiguratorPath = $ServerConfiguratorPath
                ServiceAccountName     = $ServiceAccountName
                PAServer               = $PAServer
            }
            Write-PSFMessage -Message ($scriptParams | ConvertTo-Json) -Tag eventlog
            
            $ErrorActionPreference = 'Stop'
            'Domain', 'ServerConfiguratorPath', 'ServiceAccountName', 'PAServer' | ForEach-Object {
                if ([string]::IsNullOrWhiteSpace((Get-Variable -Name $_).Value)) {
                    throw "The parameter '$_' was not provided. Check the arguments for the action in the scheduled task calling this renewal script."
                }
            }
        
            Set-PAServer $PAServer
            $order = Get-PAOrder -MainDomain $Domain
            if ($null -eq $order) {
                throw "Posh-ACME did not find an order for domain $Domain. Please re-run the original setup script."
            }
            $renewAfter = [datetimeoffset]$order.RenewAfter
            if ($renewAfter -gt [datetimeoffset]::UtcNow) {
                Write-PSFMessage -Message "The certificate for domain '$Domain' is not ready for renewal until after $($renewAfter.ToLocalTime())"
                return
            }
            
            $newCert = Submit-Renewal -MainDomain $Domain -WarningAction SilentlyContinue -WarningVariable renewalWarnings
            foreach ($warning in $renewalWarnings) {
                Write-PSFMessage -Level Warning -Message $warning
            }
            if ($newCert) {
                Write-PSFMessage -Message "Certificate renewal succeeded"
                Write-PSFMessage -Message "Applying certificate with thumbprint '$($newCert.Thumbprint)' to Milestone XProtect Mobile Server..."
                $newCert | Set-XProtectCertificate -VmsComponent MobileServer -Force -UserName $ServiceAccountName -RemoveOldCert -ServerConfiguratorPath $ServerConfiguratorPath
                Write-PSFMessage -Message "New certificate applied successfully."
            }
            Wait-PSFMessage
        } catch {
            Write-PSFMessage -Level Error -Message 'Certificate renewal failed.' -ErrorRecord $_
            Wait-PSFMessage
            throw
        }
    }
    $programData = [system.environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData)
    $workingDirectory = (New-Item -Path ([io.path]::Combine($programData, 'Milestone', 'MilestonePSTools')) -ItemType Directory -Force).FullName
    $renewalScriptPath = Join-Path $workingDirectory 'Renew-VmsLECertificate.ps1'
    ($renewalScript.tostring() -split "`n") -replace '^\s{8}' | Set-Content $renewalScriptPath -Force

    $actionParams = @{
        WorkingDirectory = $workingDirectory
        Execute          = (Get-Command powershell.exe).Path
        Argument         = @(
            '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', "`"$renewalScriptPath`"",
            '-Domain', $domain,
            '-ServerConfiguratorPath', "`"$configuratorPath`"",
            '-ServiceAccountName', "`"$serviceAccountName`"",
            '-PAServer', (Get-PAServer).Name
        ) -join ' '
    }
    $action = New-ScheduledTaskAction @actionParams
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 1) -RunOnlyIfNetworkAvailable -MultipleInstances IgnoreNew -DontStopIfGoingOnBatteries

    while ($true) {
        try {
            $username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            if ($env:LE_DEBUG -eq $true -and (Get-Module Microsoft.PowerShell.SecretStore -ListAvailable -ErrorAction SilentlyContinue)) {
                if ('LE_CREDENTIAL' -in $secrets.Name) {
                    $credential = Get-Secret -Name LE_CREDENTIAL
                }
            } else {
                $credential = Get-Credential -Message 'Please enter your password to register a scheduled task for certificate renewals.' -UserName $username
                if ($credential.UserName -ne $username) {
                    Write-Warning "Posh-ACME stores certificate renewal information under the current user profile. If you want to run the scheduled task as $($credential.UserName), you must cancel and re-run this script under that user account."
                    continue
                }
            }
            if ($null -eq $credential) {
                Write-Warning 'User account credentials are required to register a scheduled task.'
                exit
            }
            $registerParams = @{
                TaskName = 'Renew-VmsLECertificate'
                TaskPath = '\Milestone'
                User     = $credential.UserName
                Password = $credential.GetNetworkCredential().Password
                Trigger  = New-ScheduledTaskTrigger -Daily -At (Get-Date).Date -RandomDelay (New-TimeSpan -Hours 1)
                Action   = $action
                Settings = $settings
                RunLevel = 'Highest'
                Force    = $true
            }
            
            $task = Register-ScheduledTask @registerParams

            Write-Host "Testing the renewal task..." -ForegroundColor Green
            $task | Start-ScheduledTask
            Start-Sleep -Seconds 5
            while ('Ready' -ne ($task | Get-ScheduledTask).State) {
                Start-Sleep -Seconds 1
            }
            $taskResult = ($task | Get-ScheduledTask | Get-ScheduledTaskInfo).LastTaskResult
            if ($taskResult) {
                Write-Warning "The scheduled task exited with $taskResult while a normal exit code is 0. Check the log messages in $workingDirectory for more information."
                exit
            }
            Write-Host "The scheduled task has been registered and tested successfully." -ForegroundColor Green
        } catch {
            Write-Warning "Failed to register or test the scheduled task."
            Write-Error -ErrorRecord $_
            continue
        }

        break
    }


    Write-Host -ForegroundColor Green @"


Good news! A scheduled task named 'Renew-VmsLECertificate' has been registered in Windows Task
Scheduler under '\Milestone' and it will run daily, at a random time between 12am and 1am, under
$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) with elevated privileges. When
your Lets Encrypt certificate for $domain is eligible for renewal, the certificate will be renewed,
applied to the Mobile Server, and the old certificate will be removed from the local machine
certificate store.

The daily renewal task will write event log entries under the log name "Milestone" with the source
"Renew-VmsLECertificate". You will also find log files under "C:\ProgramData\Milestone\MilestonePSTools\Logs\"
which will be kept for 7 days. If you start seeing renewal reminder emails when there are less than
30 days remaining before the certificate expires, these logs are the first place to check.

Please note that your scheduled task will fail to run or log anything at all if the password for
this user account is updated without updating the scheduled task in Task Scheduler.

The 'Renew-VmsLECertificate' scheduled task executes the script at '$renewalScriptPath' daily
at midnight, with a random additional delay of up to one hour to avoid many customers attempting
renewals at the exact same time.

The Posh-ACME module will only allow the renewal to proceed when the current certificate is at least
60 days old, unless overridden with "Submit-Renewal -Force". As a result, you will see daily
messages in logs about the certificate not being ready for renewal. This is normal.

You may re-run this script at any time to re-create the scheduled task with updated parameters. Take
care not to run it too often with the same domain name however, as you will be rate limited by
Let's Encrypt if you forcefully request several certificates for the same domain name within a set
period of time. Their rate limits are documented online for reference.
"@

} catch {
    Write-Error -ErrorRecord $_
}

Write-Host "`n`nPress any key to quit."
$null = [console]::ReadKey($true)
