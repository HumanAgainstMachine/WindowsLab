function Test-Credential {
    param(
        [parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Credential
    )

    # Make sure to load necessary assembly for PrincipalContext
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    # Create a PrincipalContext object for the local machine
    $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)

    # Validate credentials against the local machine
    $principalContext.ValidateCredentials($credential.UserName, $credential.GetNetworkCredential().Password)
}

$credential = Get-Credential -UserName $env:USERNAME

Test-Credential -Credential:$credential