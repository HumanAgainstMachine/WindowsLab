try {
    Write-Host @"
Getting Lab Ready
-----------------
"@ -ForegroundColor DarkYellow

    Write-Host "Upgrading winget ..." -ForegroundColor DarkYellow
    winget upgrade winget
    Write-Host "Installing Powershell 7 or later ..." -ForegroundColor DarkYellow
    winget install --id Microsoft.Powershell --source winget 
    
    $netAdapter = Get-NetAdapter -Physical -CimSession $env:COMPUTERNAME | Where-Object {$_.Status -eq "Up"} -ErrorAction Stop
    
    Write-Host "Searching for phiscal connected net adapter ..." -ForegroundColor DarkYellow
    
    $netAdapter
    
    Write-Host "Setting network to private ..." -ForegroundColor DarkYellow
    Set-NetConnectionProfile -InterfaceIndex $netAdapter.InterfaceIndex -NetworkCategory Private -ErrorAction Stop
    
    Write-Host "Done" -ForegroundColor DarkYellow
}
catch {
    Write-Host "Something went wrong" -ForegroundColor Red
    $_.exception.GetType().fullname
}