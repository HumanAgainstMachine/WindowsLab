#Requires -RunAsAdministrator
<#
.SYNOPSIS
    
#>
try {
    Write-Host @"

---------------------
* Getting Lab Ready *
---------------------
"@ -ForegroundColor DarkYellow

    winget upgrade winget
    Write-Host "Winget is OK.`n" -ForegroundColor DarkYellow

    winget install --id Microsoft.Powershell --source winget 
    Write-Host "Powershell 7 or later is installed.`n" -ForegroundColor DarkYellow
    
    $netAdapter = Get-NetAdapter -Physical -CimSession $env:COMPUTERNAME | 
                    Where-Object {$_.Status -eq "Up"} -ErrorAction Stop
    
    Write-Host "Found phiscal connected net adapter:" -ForegroundColor DarkYellow
    $netAdapter | Format-Table -Property Name, InterfaceIndex, Status
    
    Set-NetConnectionProfile -InterfaceIndex $netAdapter.InterfaceIndex -NetworkCategory Private -ErrorAction Stop
    Write-Host "Network set to private.`n" -ForegroundColor DarkYellow

    Enable-PSRemoting -WarningAction SilentlyContinue
    Write-Host "PowerShell Remoting enabled.`n" -ForegroundColor DarkYellow
    
    Write-Host "This PC ($env:COMPUTERNAME) is now ready!" -ForegroundColor Green
}
catch {
    Write-Host "Something went wrong" -ForegroundColor Red
    $_.exception.GetType().fullname
}