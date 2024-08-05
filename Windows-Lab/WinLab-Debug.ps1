# Remove stop time trigger

$DailyTime = '23:00'
$dailyTimeObj = [DateTime]::ParseExact($DailyTime, "HH:mm", [System.Globalization.CultureInfo]::InvariantCulture)

$dailyStopTime = $dailyTimeObj.TimeOfDay 

try {
    # Get scheduled StopThisComputer task if exist
    $stopThisComputerTask = Get-ScheduledTask -TaskName:'StopThisComputer' -TaskPath:'\WinLabAdmin\' -ErrorAction Stop
}
catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException] {
    # $_.exception.GetType().fullname
    Write-Host "StopThisComputer task not exist, nothing to remove so"
    Return $null
}            

# Set principal contex for SYSTEM account to run as a service with with the highest privileges
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest            

# Remove the given time stop trigger 
$triggers = @()
foreach ($trg in $stopThisComputerTask.Triggers) {
    if (([datetime] $trg.StartBoundary).TimeOfDay -ne $dailyStopTime) {
        $triggers += $trg
    }
}

if ($triggers.count -lt $stopThisComputerTask.Triggers.count) {
    Set-ScheduledTask -TaskName:'StopThisComputer' -TaskPath:'\WinLabAdmin\' -Trigger $triggers -Principal $principal | Out-Null
    Write-Host "Stop daily time $DailyTime removed on $env:computername" -ForegroundColor Green    
} else {
    Write-Host "Stop daily time $DailyTime not exist on $env:computername" -ForegroundColor Red
}
