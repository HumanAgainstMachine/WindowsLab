#Requires -RunAsAdministrator
<#
.SYNOPSIS
    ComputerRoom tools

.NOTES
    Script variables are essentially module variables
#>

# get path to config.json
$configPath = Join-Path -Path $PSScriptRoot -ChildPath 'config.json'

# read config file
$config = Get-Content -Raw -Path $configPath | ConvertFrom-Json

$remotecomputers = $config.remotecomputers
$macs = $config.macs


function Show-Config {
    <#
    .SYNOPSIS
        Shows imported config.json content and if mac addresses are missing get them for you

    .EXAMPLE
        Read-Config

    .NOTES
        Filtering the adapters with status: `Up` should be enaught to select the 
        adapter used for PS Remoting        
    #>
    [CmdletBinding()]
    param ()
    $t = "
===========================================
---     Imported from config.json       ---
===========================================
"

    Write-Host $t.Trim() -ForegroundColor DarkYellow

    Write-Host 'Remote Computer: ' -NoNewline
    Write-Host $remotecomputers -Separator ', '

    Write-Host 'Mac Addresses  : ' -NoNewline
    Write-Host $macs -Separator ', '

    $t = "
===========================
-- Mac Addresses check   --
===========================
"

    Write-Host $t.Trim() -ForegroundColor DarkYellow
    Write-Host 'Trying to find Mac Addresses ...' 
    foreach ($pc in $remotecomputers) {
        $macAddress = Get-NetAdapter -CimSession $PC | Where-Object {$_.Status -eq 'Up'} | Select-Object MacAddress

        Write-Host "$pc " -ForegroundColor DarkYellow -NoNewline
        if ($macAddress.Length -gt 1) {
            Write-Host $macAddress.MacAddress, "=== $($macAddress.Length) Net Adapters here, choose one ===" -Separator ', '
        } else {
            Write-Host $macAddress.MacAddress
        }
    }

}


function Start-EveryComputer {
    <#
    .SYNOPSIS
        Turn on every computers if WoL setting is present and enabled in BIOS/UEFI

    .EXAMPLE
        Start-EveryComputer

    .NOTES
        https://www.pdq.com/blog/wake-on-lan-wol-magic-packet-powershell/
    #>
    [CmdletBinding()]
    param ()
    # send Magic Packet over LAN
    foreach ($Mac in $macs) {
        $MacByteArray = $Mac -split "[:-]" | ForEach-Object { [Byte] "0x$_"}
        [Byte[]] $MagicPacket = (,0xFF * 6) + ($MacByteArray * 16)
        $UdpClient = New-Object System.Net.Sockets.UdpClient
        $UdpClient.Connect(([System.Net.IPAddress]::Broadcast),7)
        $UdpClient.Send($MagicPacket,$MagicPacket.Length)
        $UdpClient.Close()
    }
    
}

function Restart-EveryComputer {
    <#
    .SYNOPSIS
        Force an immediate restart of every computer and wait for them to be on again

    .EXAMPLE
        Restart-EveryComputer

    .NOTES
    #>    
    [CmdletBinding()]
    param()
    Restart-Computer -ComputerName $remotecomputers -Wait -Force
}

function Stop-EveryComputer {
    <#
    .SYNOPSIS
        Force an immediate shut down of every computer

    .EXAMPLE
        Stop-EveryComputer

    .NOTES
    #>    
    [CmdletBinding()]
    param()
    Stop-Computer -ComputerName $remotecomputers -Force
}

function Disconnect-AnyUser {
    <#
    .SYNOPSIS
        Disconnect any connected user from each remote computer

    .EXAMPLE
        Disconnect-AnyUser -ComputerName PC01
    
    .NOTES
        Windows 10 Home doesn't include query.exe (https://superuser.com/a/1646775)

        Quser.exe emit a non-terminating error in case of no user logged-in,
        to catch the error force PS to raise an exception, set $ErrorActionPreference = 'Stop'
        because quser, being not a cmdlet, has not -ErrorAction parameter.
    #>        
    [CmdletBinding()]
    param(
        [Parameter(HelpMessage="Enter remote PC name")]
        [string]$ComputerName  = 'All'
    )

    if ($ComputerName -ne 'All') {$remotecomputers = $ComputerName}

    Invoke-Command -ComputerName $remotecomputers -ScriptBlock {
        $ErrorActionPreference = 'Stop' # NOTE: it is valid only for this function scope 
        try {
            # get array of logged-in users, skip 1st row (the head)
            quser | Select-Object -Skip 1 |
            ForEach-Object {
                # logoff by session ID
                logoff ($_ -split "\s+")[2]
                Write-Host "User" ($_ -split "\s+")[1] "logged out $($env:COMPUTERNAME)"  -ForegroundColor Green
            }
        }
        catch {
            <#Do this if a terminating exception happens#>
            Write-host "No user logged in $($env:COMPUTERNAME)" -ForegroundColor Yellow
        }
    }
}

function New-CommonUser {
    <#
    .SYNOPSIS
        Create a Standard CommonUser with a blank never-expiring password

    .EXAMPLE
        New-CommonUser -UserName "Alunno"

    .NOTES
        Avoid Confusion: Microsoft says that -NoPassword Switch parameter 'Indicates that the 
        user account doesn't have a password' and as I tested that the user must provide one when
        signing-in the first time. 
        This behavior plus -UserMayNotChangePassword switch parameter cause a deadlock.
        -NoPassword is different from a blank password
        
        Windows Groups' description: https://ss64.com/nt/syntax-security_groups.html
    #>    
    [CmdletBinding()]
    param (
      [Parameter(Mandatory=$True, HelpMessage="Enter username for Common User")]
      [string]$UserName
    )
    
    Invoke-Command -ComputerName $remotecomputers -ScriptBlock {
        try {
            $blankPassword = [securestring]::new()
            New-LocalUser -Name $Using:UserName -Password $blankPassword -PasswordNeverExpires `
            -UserMayNotChangePassword -AccountNeverExpires -ErrorAction Stop
            Add-LocalGroupMember -Group "Users" -Member $Using:UserName
            Write-Host "$Using:UserName created on $env:computername" -ForegroundColor Green
        }
        catch [Microsoft.PowerShell.Commands.UserExistsException] {
          Write-Host "$Using:UserName already exist on $env:computername" -ForegroundColor Yellow
        }
    }
}

function Remove-CommonUser {
    <#
    .SYNOPSIS
        Remove specified CommonUser, also remove registry entry and user profile folder if they exist

    .EXAMPLE
        Remove-CommonUser -Username "Alunno"
    
    .NOTES
        Inspiration: https://adamtheautomator.com/powershell-delete-user-profile/
    #>    
    [CmdletBinding()]
    param (
      [Parameter(Mandatory=$True, HelpMessage="Enter username for Common User")]
      [string]$UserName
    )
    
    Invoke-Command -ComputerName $remotecomputers -ScriptBlock {
        try {
            $localUser = Get-LocalUser -Name $Using:UserName -ErrorAction Stop
            # Remove the sign-in entry in Windows
            Remove-LocalUser -SID $localUser.SID.Value
            # Remove %USERPROFILE% folder and registry entry if exist
            Get-CimInstance -Class Win32_UserProfile | Where-Object { $_.SID -eq $localUser.SID.Value } | Remove-CimInstance
    
            Write-Host "$Using:UserName removed on $env:computername" -ForegroundColor Green
        }
        catch [Microsoft.PowerShell.Commands.UserNotFoundException] {
            <#Do this if a terminating exception happens#>
            Write-Host "$Using:UserName NOT exist on $env:computername" -ForegroundColor Yellow
        }
    }
}

function Set-CommonUser {
    <#
    .SYNOPSIS
        Set password and account type for the CommonUser specified

    .EXAMPLE
        Set-CommonUser -UserName "Alunno"
        Set-CommonUser -UserName "Alunno" -SetPassword
        Set-CommonUser -UserName "Alunno" -SetPassword -AccountType Administrator
    
    .NOTES
        CommonUser Administrators can't change the password like standard users
        
        Windows Groups description: https://ss64.com/nt/syntax-security_groups.html
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True, HelpMessage="Enter the username for Common User")]
        [string]$UserName,
        [switch]$SetPassword,
        [validateSet('StandardUser', 'Administrator')]
        [string]$AccountType
    )

    $password = $null
    if ($SetPassword.IsPresent) {
        # Prompt and read new password
        $password = Read-Host -Prompt 'Enter the new password' -AsSecureString
    }
    Invoke-Command -ComputerName $remotecomputers  -ScriptBlock {
        try {
            if ($Using:SetPassword.IsPresent) {
                # change password
                Set-LocalUser -Name $Using:UserName -Password $Using:Password -PasswordNeverExpires $True `
                -UserMayChangePassword $False -ErrorAction Stop
                Write-Host "$Using:UserName on $env:computername password changed" -ForegroundColor Green
            }
            if ($Using:AccountType -eq 'Administrator') {
                # change to an Administrator
                Add-LocalGroupMember -Group "Administrators" -Member $Using:UserName -ErrorAction Stop
                Write-Host "$Using:UserName on $env:computername is now an Administrator" -ForegroundColor Green
            } 
            if ($Using:AccountType -eq 'StandardUser') {
                # change to a Standard User
                Remove-LocalGroupMember -Group "Administrators" -Member $Using:UserName -ErrorAction Stop
                Write-Host "$Using:UserName on $env:computername is now a Standard User" -ForegroundColor Green
            }
        }
        catch [Microsoft.PowerShell.Commands.UserNotFoundException] {
            Write-Host "$Using:UserName NOT exist on $env:computername" -ForegroundColor Yellow
        }
        catch [Microsoft.PowerShell.Commands.MemberExistsException] {
            Write-Host "$Using:UserName on $env:computername is already an Administrator" -ForegroundColor Yellow
        }
        catch [Microsoft.PowerShell.Commands.MemberNotFoundException] {
            Write-Host "$Using:UserName on $env:computername is already a Standard User" -ForegroundColor Yellow
        }
        catch {
                    $formatstring = "{0} : {1}`n{2}`n" +
                    "    + CategoryInfo          : {3}`n" +
                    "    + FullyQualifiedErrorId : {4}`n"
        $fields = $_.InvocationInfo.MyCommand.Name,
            $_.ErrorDetails.Message,
            $_.InvocationInfo.PositionMessage,
            $_.CategoryInfo.ToString(),
            $_.FullyQualifiedErrorId   

            Write-Host -Foreground Red -Background Black ($formatstring -f $fields)
        }
    }   
}

function Sync-EveryComputerDate {
    <#
    .SYNOPSIS
        Sync date with NTP time for every computer
    
        .EXAMPLE
        Sync-EveryComputerDate

    .NOTES
        The NtpTime module is required on MasterComputer (https://www.powershellgallery.com/packages/NtpTime/1.1)
    
        Set-Date requires admin privilege to run
    #>
    [CmdletBinding()]
    param ()
    # check if NtpTime module is installed
    if ($null -eq (Get-Module -ListAvailable -Name NtpTime)) {
        Write-Host "`nNtpTime Module missing. Install the module with:" -ForegroundColor Yellow
        Write-Host "    Install-Module -Name NtpTime`n"
        Break
    } 

    # get datetime from default NTP server
    try {
        $currentDate = (Get-NtpTime -MaxOffset 60000).NtpTime
        Write-Host "`n(NTP time: $currentdate)`n" -ForegroundColor Yellow

        Set-Date -Date $currentDate | Out-Null
        Write-Host "MasterComputer synchronized" -ForegroundColor Green
        Invoke-Command -ComputerName $remotecomputers -ScriptBlock {
            Set-Date -Date $Using:currentDate | Out-Null
            Write-Host "$env:computername synchronized" -ForegroundColor Green
        }        
    }
    catch {
        Write-Host "`nTry again later ..." -ForegroundColor Yellow
    }
}

function Copy-ToCommonUserDesktop {
    <#
    .SYNOPSIS
        Copy a file or folder from one location to CommonUser Desktop

    .DESCRIPTION
        Copy a file or folder from one location to CommonUser Desktop, folders are copied recursively.
        This cmdlet can copy over a read-only file or alias.
    

    .EXAMPLE
        Copy-ToCommonUserDesktop -Path filename.txt -UserName Alunno

        Copy-ToCommonUserDesktop -Path C:\Logfiles -UserName Concorso
    
    .NOTES
        Inspiration: https://lazyadmin.nl/powershell/copy-file/#copy-file-to-remote-computer-with-powershell
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True, HelpMessage="Enter Path to file or folder")]
        [string]$Path,
        [Parameter(Mandatory=$True, HelpMessage="Enter CommonUser name")]
        [string]$UserName        
    )

    Write-Host "Start copying to CommonUser Desktops ..." -ForegroundColor Yellow

    foreach ($computerName in $remotecomputers) {
        $session = New-PSSession -ComputerName $computerName

            $userprofile = Invoke-Command -Session $session -ScriptBlock {
                try {
                    $localUser = Get-LocalUser -Name $Using:UserName -ErrorAction Stop

                    # Get %USERPROFILE% path
                    $userprofile = (Get-CimInstance -Class Win32_UserProfile | Where-Object { $_.SID -eq $localUser.SID.Value }).LocalPath
                    if ($null -eq $userprofile) {
                        Write-Host "$Using:UserName exist but never signed-in on $env:computername" -ForegroundColor Yellow
                        Write-Host "Copy to $env:computername failed" -ForegroundColor Red
                        $userprofile = ""
                    }
                }
                catch [Microsoft.PowerShell.Commands.UserNotFoundException] {
                    Write-Host "$Using:UserName NOT exist on $env:computername" -ForegroundColor Yellow
                    Write-Host "Copy to $env:computername failed" -ForegroundColor Red
                    $userprofile = $null
                }
                finally {
                    Write-Output $userprofile
                }
                
            }
            if ($userprofile -ne "" -and $null -ne $userprofile) {
                $desktopPath = Join-Path -Path $userprofile -ChildPath 'Desktop'
                Copy-Item -Path $path -Destination $desktopPath -ToSession $session -Recurse -Force
                Write-host "copy to $computerName success" -ForegroundColor Green
            }

        Remove-PSSession -Session $session
    }
    
}