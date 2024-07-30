# Remove stop time trigger

$DailyTime = '22:00'
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

# Get preset daily stop times as TimeSpan objets
$presetDailyStopTimes = @()
foreach ($trg in $stopThisComputerTask.Triggers) {
    $presetDailyStopTimes += ([datetime] $trg.StartBoundary).TimeOfDay
}

# Check if the stop time to remove is present
if ($dailyStopTime -in $presetDailyStopTimes) {
    $indx = $presetDailyStopTimes.IndexOf($dailyStopTime)
    $stopTriggers = $stopThisComputerTask.Triggers | Where-Object {$stopThisComputerTask.Triggers.IndexOf($_) -ne $indx}
    Set-ScheduledTask -TaskName:'StopThisComputer' -TaskPath:'\WinLabAdmin\' -Trigger $stopTriggers -Principal $principal | Out-Null
    Write-Host "Stop daily time $DailyTime removed on $env:computername" -ForegroundColor Green
} else {
    Write-Host "Stop daily time $DailyTime not exist on $env:computername" -ForegroundColor Red
}                 
