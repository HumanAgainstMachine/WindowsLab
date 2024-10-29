#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Script for getting the lab ready.
.LINK
    https://github.com/HumanAgainstMachine/WindowsLab
#>
try {
    Write-Host @"

---------------------
* Getting Lab Ready *
---------------------
"@ -ForegroundColor DarkYellow

    # Update Winget
    Write-Host "Trying to update Winget ...`n" -ForegroundColor DarkYellow
    winget upgrade winget

    # Update Powershell
    Write-Host "Trying to update Powershell 7 ...`n" -ForegroundColor DarkYellow
    winget install --id Microsoft.Powershell --source winget 

    # Set Network(s) to Private
    Write-Host "Trying to set Network to private ...`n" -ForegroundColor DarkYellow
    Set-NetConnectionProfile -NetworkCategory Private

    $privateNetProfiles = Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq "Private"}

    if ($null -eq $privateNetProfiles) {
        Write-Host "You are not connected to any Network!" -ForegroundColor Red        
    }
    elseif ($privateNetProfiles.Name.Count -eq 1) {
        Write-Host "Trying to enable PowerShell Remoting ...`n" -ForegroundColor DarkYellow
        Enable-PSRemoting -WarningAction SilentlyContinue
        
        Write-Host "This PC ($env:COMPUTERNAME) is now ready!" -ForegroundColor Green
    } 
    else {
        Write-Host "This PC ($env:COMPUTERNAME) is connected to more than one Networks, disable all but one" -ForegroundColor Red
    }
}
catch {
    Write-Host "Something went wrong" -ForegroundColor Red
    $_.exception.GetType().fullname
}