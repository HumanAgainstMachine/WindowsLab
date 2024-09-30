# Define a list of computer names
$computerNames = @("LENO", "CUBO")

# Create sessions for each computer
$sessions = New-PSSession -ComputerName $computerNames

# Run the command on each session and pass session details
Invoke-Command -Session $sessions -ScriptBlock {
    "Connected to: $env:COMPUTERNAME"
    "Connected User: $($PSSenderInfo.ConnectedUser)"
    "Client Machine: $($PSSenderInfo.ClientMachine)"
    $PSSenderInfo | Get-Member
}

# Clean up sessions after use
Remove-PSSession $sessions
