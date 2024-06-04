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

$labComputerList = $config.labComputerList
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

    Write-Host 'Lab Computer: ' -NoNewline
    Write-Host $labComputerList -Separator ', '

    Write-Host 'Mac Addresses  : ' -NoNewline
    Write-Host $macs -Separator ', '

    $t = "
===========================
-- Mac Addresses check   --
===========================
"

    Write-Host $t.Trim() -ForegroundColor DarkYellow
    Write-Host 'Trying to find Mac Addresses ...' 
    foreach ($pc in $labComputerList) {
        $macAddress = Get-NetAdapter -CimSession $PC | Where-Object {$_.Status -eq 'Up'} | Select-Object MacAddress

        Write-Host "$pc " -ForegroundColor DarkYellow -NoNewline
        if ($macAddress.Length -gt 1) {
            Write-Host $macAddress.MacAddress, "=== $($macAddress.Length) Net Adapters here, choose one ===" -Separator ', '
        } else {
            Write-Host $macAddress.MacAddress
        }
    }

}


function Start-LabComputer {
    <#
    .SYNOPSIS
        Turn on each computers if WoL setting is present and enabled in BIOS/UEFI

    .EXAMPLE
        Start-LabComputer

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

function Restart-LabComputer {
    <#
    .SYNOPSIS
        Force an immediate restart of each computer and wait for them to be on again

    .EXAMPLE
        Restart-LabComputer

    .NOTES
    #>    
    [CmdletBinding()]
    param()
    Restart-Computer -ComputerName $labComputerList -Force
}

function Stop-LabComputer {
    <#
    .SYNOPSIS
        Force an immediate shut down of each computer

    .EXAMPLE
        Stop-LabComputer

    .NOTES
    #>    
    [CmdletBinding()]
    param()
    Stop-Computer -ComputerName $labComputerList -Force
}

function Disconnect-AnyUser {
    <#
    .SYNOPSIS
        Disconnect any connected user from each Lab computer

    .EXAMPLE
        Disconnect-AnyUser -ComputerName PC01
    
    .NOTES
        Windows Home doesn't include query.exe (https://superuser.com/a/1646775)

        Quser.exe emit a non-terminating error in case of no user logged-in,
        to catch the error force PS to raise an exception, set $ErrorActionPreference = 'Stop'
        because quser, being not a cmdlet, has not -ErrorAction parameter.
    #>        
    [CmdletBinding()]
    param(
        [Parameter(HelpMessage="Enter Lab computer name")]
        [string]$ComputerName  = 'All'
    )

    if ($ComputerName -ne 'All') {$labComputerList = $ComputerName}

    Invoke-Command -ComputerName $labComputerList -ScriptBlock {
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

function New-LabUser {
    <#
    .SYNOPSIS
        Create a Standard LabUser with a blank never-expiring password

    .EXAMPLE
        New-LabUser -UserName "Alunno"

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
      [Parameter(Mandatory=$True, HelpMessage="Enter username for Lab User")]
      [string]$UserName
    )
    
    Invoke-Command -ComputerName $labComputerList -ScriptBlock {
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

function Remove-LabUser {
    <#
    .SYNOPSIS
        Remove specified LabUser, also remove registry entry and user profile folder if they exist

    .EXAMPLE
        Remove-LabUser -Username "Alunno"
    
    .NOTES
        Inspiration: https://adamtheautomator.com/powershell-delete-user-profile/
    #>    
    [CmdletBinding()]
    param (
      [Parameter(Mandatory=$True, HelpMessage="Enter username for Lab User")]
      [string]$UserName
    )
    
    Invoke-Command -ComputerName $labComputerList -ScriptBlock {
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

function Set-LabUser {
    <#
    .SYNOPSIS
        Set password and account type for the LabUser specified

    .EXAMPLE
        Set-LabUser -UserName "Alunno"
        Set-LabUser -UserName "Alunno" -SetPassword
        Set-LabUser -UserName "Alunno" -SetPassword -AccountType Administrator
    
    .NOTES
        LabUser Administrators can't change the password like standard users
        
        Windows Groups description: https://ss64.com/nt/syntax-security_groups.html
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True, HelpMessage="Enter the username for Lab User")]
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
    Invoke-Command -ComputerName $labComputerList  -ScriptBlock {
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
            $_.exception.GetType().fullname
        }
    }   
}

function Sync-LabComputerDate {
    <#
    .SYNOPSIS
        Sync the date with the NTP time for each computer.
    
        .EXAMPLE
        Sync-LabComputerDate

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
        Invoke-Command -ComputerName $labComputerList -ScriptBlock {
            Set-Date -Date $Using:currentDate | Out-Null
            Write-Host "$env:computername synchronized" -ForegroundColor Green
        }        
    }
    catch {
        Write-Host "`nTry again later ..." -ForegroundColor Yellow
    }
}

function Copy-ToLabUserDesktop {
    <#
    .SYNOPSIS
        Copy a file or folder from one location to LabUser Desktop

    .DESCRIPTION
        Copy a file or folder from one location to LabUser Desktop, folders are copied recursively.
        This cmdlet can copy over a read-only file or alias.
    
    .EXAMPLE
        Copy-ToLabUserDesktop -Path filename.txt -UserName Alunno

        Copy-ToLabUserDesktop -Path C:\Logfiles -UserName Concorso
    
    .NOTES
        Inspiration: https://lazyadmin.nl/powershell/copy-file/#copy-file-to-remote-computer-with-powershell
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True, HelpMessage="Enter Path to file or folder")]
        [string]$Path,
        [Parameter(Mandatory=$True, HelpMessage="Enter LabUser name")]
        [string]$UserName        
    )

    Write-Host "Start copying to LabUser Desktops ..." -ForegroundColor Yellow

    foreach ($computerName in $labComputerList) {
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

function Test-LabComputerPrompt {
    <#
    .SYNOPSIS
        Tests for each Lab computer if the WinRM service is running.

    .DESCRIPTION
        This cmdlet informs you which Lab computers are ready to accept cmdlets from Main computer.

    .EXAMPLE
        Test-LabComputerPrompt
    #>
    [CmdletBinding()]
    param ()

    foreach ($pc in $labComputerList) {       
        try {
            Test-WSMan -ComputerName $pc -ErrorAction Stop | Out-Null
            Write-Host "$pc " -ForegroundColor DarkYellow -NoNewline
            Write-Host "ready" -ForegroundColor Green 
        }
        catch [System.InvalidOperationException] {
            Write-Host "$pc " -ForegroundColor DarkYellow -NoNewline
            Write-Host "not ready" -ForegroundColor Red
        }
    }
}

function Backup-LabComputerDesktop {
    <#
    .SYNOPSIS
        Backup desktop folder for the specified Lab user

    .DESCRIPTION
        Save a copy of desktop folder for the specified user to Lab computer $env:SYSTEMDRIVE/LabComputerBackup

    .EXAMPLE
        Backup-LabComputerDesktop -UserName Alunno
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, HelpMessage="Enter LabUser name")]
        [string]$UserName        
    )
    invoke-Command -ComputerName $labComputerList -ScriptBlock {
        try {
            # get specified Lab user
            $localUser = Get-LocalUser -Name $Using:UserName -ErrorAction Stop

            # get Lab user USERPROFILE path
            $userProfilePath = (Get-CimInstance -Class Win32_UserProfile | Where-Object { $_.SID -eq $localUser.SID.Value }).LocalPath
            Test-Path $userProfilePath -ErrorAction Stop | Out-Null

            $desktopPath = Join-Path -Path $userprofilePath -ChildPath 'Desktop'
            $labComputerDesktopBackupPath = Join-Path -Path $env:SystemDrive -ChildPath 'LabComputerDesktopBackup'
            # create backup folder if not exist
            if (-Not (Test-Path -Path $labComputerDesktopBackupPath -PathType Container)) {
                New-Item -Path $labComputerDesktopBackupPath -ItemType "directory"
            }            

            $backupPath = Join-Path -Path $labComputerDesktopBackupPath -ChildPath $Using:UserName
            Copy-Item -Path "$desktopPath\*" -Destination $backupPath -Recurse -Force
            Write-Host "$Using:Username on $env:computername backup done" -ForegroundColor Green
        }
        catch [Microsoft.PowerShell.Commands.UserNotFoundException] {
            Write-Host "$Using:UserName NOT exist on $env:computername" -ForegroundColor Yellow
            Write-Host "Copy to $env:computername failed" -ForegroundColor Red
        }        
        catch [System.ArgumentNullException] { # user exist USERPROFILE path no
            Write-Host "$Using:UserName exist but never signed-in on $env:computername" -ForegroundColor Yellow
            Write-Host "Copy to $env:computername failed" -ForegroundColor Red        
        }
    }
}