#Requires -RunAsAdministrator
<#
.SYNOPSIS
    WindowsLab, tools to admin a Windows based Lab
#>

# -- Init Module Vars ---

# Get this script name without extension
$thisModuleName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Path)

# Set path to $HOME\AppData\Roaming\config.json
New-Item -Path $env:APPDATA -Name "$thisModuleName" -ItemType Directory -ErrorAction SilentlyContinue
$configPath = Join-Path -Path $env:APPDATA -ChildPath $thisModuleName 'config.json'
$selectedIconPath = Join-Path -Path $PSScriptRoot -ChildPath "selectedTab.ico"

if (Test-Path -Path $configPath -PathType Leaf) {
    # Import config.json
    $config = Get-Content -Path $configPath -Raw | ConvertFrom-Json
    $currentLab = $config.Labs[$config.LastSelectedLab]
}
else {
    $currentLab = $null
}

# -- End Init Vars --

function Test-NoLabPcName {
    # Test if LabPc names are not set in config.json
    param ()
    Write-Host "Selected Lab: $($currentLab.Name) `n"  -ForegroundColor DarkCyan
    if ($currentlab.PcNames.Length -eq 0) {
        Write-Host "LabPc names not found" -ForegroundColor Red
        Write-Host "Run Set-LabPcName to set LabPc names`n" -ForegroundColor DarkYellow
        break
    }
}

function Set-LabPcName {# the GUI cmdlet
    <#
    .SYNOPSIS
        GUI to manage LabPcs names

    .DESCRIPTION
        Allows to set/update config.json file through a GUI
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    # Load the Windows Forms assembly
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # Create the form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "WindowsLab - Lab Settings"
    $form.Size = New-Object System.Drawing.Size(800, 600)
    $form.StartPosition = "CenterScreen"

    # Create TabControl
    $tabControl = New-Object System.Windows.Forms.TabControl
    $tabControl.Location = New-Object System.Drawing.Point(10, 10)
    $tabControl.Size = New-Object System.Drawing.Size(765, 500)
    $form.Controls.Add($tabControl)

    # Create an ImageList, set icon size, and load an icon
    $imageList = New-Object System.Windows.Forms.ImageList
    $imageList.ImageSize = New-Object System.Drawing.Size(10, 10)
    $imageList.Images.Add([System.Drawing.Image]::FromFile($selectedIconPath))

    # Assign the ImageList to the TabControl
    $tabControl.ImageList = $imageList

    # Create "Add Lab" button
    $addLabButton = New-Object System.Windows.Forms.Button
    $addLabButton.Location = New-Object System.Drawing.Point(10, 520)
    $addLabButton.Size = New-Object System.Drawing.Size(100, 30)
    $addLabButton.Text = "Add Lab"
    $form.Controls.Add($addLabButton)

    # Create "Remove Lab" button
    $removeLabButton = New-Object System.Windows.Forms.Button
    $removeLabButton.Location = New-Object System.Drawing.Point(120, 520)
    $removeLabButton.Size = New-Object System.Drawing.Size(100, 30)
    $removeLabButton.Text = "Remove Lab"
    $form.Controls.Add($removeLabButton)

    # Add Save button
    $saveNamesButton = New-Object System.Windows.Forms.Button
    $saveNamesButton.Location = New-Object System.Drawing.Point(230, 520)
    $saveNamesButton.Size = New-Object System.Drawing.Size(100, 30)
    $saveNamesButton.Text = "Save"
    $form.Controls.Add($saveNamesButton)

    # Function to create embedded PowerShell console
    function New-EmbeddedConsole {
        param (
            [System.Windows.Forms.Control]$parent,
            [int]$x,
            [int]$y,
            [int]$width,
            [int]$height
        )

        $richTextBox = New-Object System.Windows.Forms.RichTextBox
        $richTextBox.Location = New-Object System.Drawing.Point($x, $y)
        $richTextBox.Size = New-Object System.Drawing.Size($width, $height)
        $richTextBox.BackColor = [System.Drawing.Color]::Black
        $richTextBox.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#45C4B0")
        $richTextBox.Font = New-Object System.Drawing.Font("Consolas", 11)
        $richTextBox.ReadOnly = $true
        $richTextBox.Multiline = $true
        $richTextBox.ScrollBars = "Vertical"
        $richTextBox.WordWrap = $true

        $parent.Controls.Add($richTextBox)
        return $richTextBox
    }

    function Update-Config {
        <#
        Update config module var (non-persistent memory)
        #>

        $cfg = @{
            Labs = @()
            LastSelectedLab = $tabControl.SelectedIndex
        }

        foreach ($tab in $tabControl.TabPages) {
            $textField = $tab.Controls | Where-Object { $_ -is [System.Windows.Forms.TextBox] }
            if ($textField.Text -eq "Enter comma separated LabPc Names") { $pcNames = @() }
            else {
                # Split up names to an array
                $pcNames = $textField.Text -split ",\s*"

                # Remove empty values
                $pcNames = $pcNames | Where-Object {$_ -ne ""}

                # Force PS treating a single name as an array
                $pcNames = $pcNames -as [System.Array]
            }

            $pcMacs = $config.Labs[$tab.TabIndex].PcMacs
            if ($pcMacs) {
                # Force PS treating a single MAC as an array
                $pcMacs = $pcMacs -as [System.Array]
            }
            else {$pcMacs = @()}


            $cfg.Labs += @{
                # Take values from GUI
                Name = $tab.Text
                PcNames = $pcNames
                # Keep saved MACs
                PcMacs = $pcMacs
            }
        }

        $Script:config = $cfg
        $script:currentLab = $config.Labs[$config.LastSelectedLab]
    }

    # Function to create a new tab
    function Add-NewTab {
        param(
            [string]$tabName = "",
            [string]$textContent = ""
        )

        # LabName mini input form
        if ([string]::IsNullOrWhiteSpace($tabName)) {
            $labNameForm = New-Object System.Windows.Forms.Form
            $labNameForm.Text = "Enter Lab Name"
            $labNameForm.Size = New-Object System.Drawing.Size(300, 150)
            $labNameForm.StartPosition = "CenterScreen"

            $labNameField = New-Object System.Windows.Forms.TextBox
            $labNameField.Location = New-Object System.Drawing.Point(10, 20)
            $labNameField.Size = New-Object System.Drawing.Size(260, 20)
            $labNameForm.Controls.Add($labNameField)

            $okButton = New-Object System.Windows.Forms.Button
            $okButton.Location = New-Object System.Drawing.Point(100, 70)
            $okButton.Size = New-Object System.Drawing.Size(75, 23)
            $okButton.Text = "OK"
            $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $labNameForm.Controls.Add($okButton)
            $labNameForm.AcceptButton = $okButton

            $result = $labNameForm.ShowDialog()

            if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
                $tabName = $labNameField.Text
                if ([string]::IsNullOrWhiteSpace($tabName)) {
                    $randomLabName = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 3 | ForEach-Object { [char]$_ })
                    $tabName = $randomLabName
                }
            } else {
                return
            }
        }

        # Create new TabPage
        $tabPage = New-Object System.Windows.Forms.TabPage
        $tabPage.Text = $tabName

        # Add (single line) TextField to the tab
        $textField = New-Object System.Windows.Forms.TextBox
        $textField.Multiline = $false
        $textField.Location = New-Object System.Drawing.Point(10, 10)
        $textField.Size = New-Object System.Drawing.Size(730, 20)
        $textField.Text = $textContent

        # Add placeholder text to single-line field
        if ([string]::IsNullOrWhiteSpace($textContent)) {
            $textField.ForeColor = [System.Drawing.Color]::Gray
            $textField.Text = "Enter comma separated LabPc Names"

            $textField.Add_GotFocus({
                if ($this.Text -eq "Enter comma separated LabPc Names") {
                    $this.Text = ""
                    $this.ForeColor = [System.Drawing.Color]::Black
                }
            })

            $textField.Add_LostFocus({
                if ([string]::IsNullOrWhiteSpace($this.Text)) {
                    $this.Text = "Enter comma separated LabPc Names"
                    $this.ForeColor = [System.Drawing.Color]::Gray
                }
            })
        }

        $tabPage.Controls.Add($textField)

        # Add [Get MAcs] button to the tab
        $showMacsButton = New-Object System.Windows.Forms.Button
        $showMacsButton.Location = New-Object System.Drawing.Point(10, 40)
        $showMacsButton.Text = "Get MACs"
        $w = ($showMacsButton.Text.Length + 4)*6
        $showMacsButton.Size = New-Object System.Drawing.Size($w, 25)
        $tabPage.Controls.Add($showMacsButton)

        # Add embedded console to the tab
        $console = New-EmbeddedConsole -parent $tabPage -x 10 -y 72 -width 730 -height 378

        # Get [MAcs button] click event
        $showMacsButton.Add_Click({
            if ($tabControl.TabCount -gt 0) {

                $currentTab = $tabControl.SelectedTab
                $console = $currentTab.Controls | Where-Object { $_ -is [System.Windows.Forms.RichTextBox] }

                # Clear previous output
                $console.Clear()

                # Add new output
                $console.AppendText("Lab $($currentLab.Name)")
                if ($currentLab.PcNames) {
                    $console.AppendText("`n`nSearching for MAC addresses of physically connected Ethernet adapters")
                    $console.AppendText("`n`nWait ...`n")

                    # Display Get-LabPcMac output to console
                    $output = Get-LabPcMac
                    $console.AppendText($output)
                }
                else {
                    $console.AppendText("`n`nFirst, enter the LabPC names, then press the [Get MACs] button again.")
                }
            }
        })

        # Add the new tab to TabControl
        $tabControl.TabPages.Add($tabPage)
    }

    # Add Lab button click event
    $addLabButton.Add_Click({
        Add-NewTab
        $tabControl.SelectedIndex = $tabControl.TabCount - 1
        $tabControl.Focus() # move focus out of single-line field to see the placeholder text
        Update-Config
    })

    # Delete Lab button click event
    $removeLabButton.Add_Click({
        if ($tabControl.TabCount -gt 0) {
            $currentTabName = $tabControl.SelectedTab.Text
            $result = [System.Windows.Forms.MessageBox]::Show(
                "Are you sure you want to remove '$currentTabName'?",
                "Confirm Remove",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question)

            if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
                $tabControl.TabPages.RemoveAt($tabControl.SelectedIndex)
                Update-Config
            }
        }
    })

    # Save button click event
    $saveNamesButton.Add_Click({
        Update-Config
        $config | ConvertTo-Json -Depth 3 | Set-Content -Path $configPath -Encoding UTF8
        [System.Windows.Forms.MessageBox]::Show(
            "LabPc Names saved!",
            "Success",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information)
    })

    # Tab selection change event
    $tabControl.Add_Selected({ # fires after tab change
        # Remove Icon from the previuos selected tab if exist
        if ($tabControl.TabPages[[Int32]$config.LastSelectedLab]) {
            $tabControl.TabPages[[Int32]$config.LastSelectedLab].ImageIndex = -1
        }

        # Add the icon for the new selected tab
        if ($tabControl.SelectedTab) {
            $tabControl.SelectedTab.ImageIndex = 0
        }

        Update-Config
    })

    # Form closing event - save configuration
    $form.Add_FormClosing({
        Update-Config
        $config | ConvertTo-Json -Depth 3 | Set-Content -Path $configPath -Encoding UTF8
    })

    # Display tabs saved in config
    if ($config -and $config.Labs) {
        foreach ($tab in $config.Labs) {
            Add-NewTab -tabName $tab.Name -textContent ($tab.PcNames -join ', ')
        }

        # Restore last selected tab
        $tabControl.SelectedIndex = $config.LastSelectedLab

        # Add the icon for the new selected tab
        $tabControl.TabPages[[Int32]$config.LastSelectedLab].ImageIndex = 0
    }

    # Show the form
    $form.ShowDialog()
}


function Test-LabPcPrompt {
    <#
    .SYNOPSIS
        Tests for each LabPC if the WinRM service is running.

    .DESCRIPTION
        This cmdlet informs you which LabPCs are ready to accept cmdlets from Main computer.

    .EXAMPLE
        Test-LabPcPrompt
    #>
    [CmdletBinding()]
    param ()

    Test-NoLabPcName
    foreach ($pc in $currentlab.PcNames) {
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

function Sync-LabPcDate {
    <#
    .SYNOPSIS
        Sync the date with the NTP time for each computer.

        .EXAMPLE
        Sync-LabPcDate

    .NOTES
        The NtpTime module is required on MasterComputer (https://www.powershellgallery.com/packages/NtpTime/1.1)

        Set-Date requires admin privilege to run
    #>
    [CmdletBinding()]
    param ()

    Test-NoLabPcName

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
        Invoke-Command -ComputerName $currentLab.PcNames -ScriptBlock {
            Set-Date -Date $Using:currentDate | Out-Null
            Write-Host "$env:computername synchronized" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "`nTry again later ..." -ForegroundColor Yellow
    }
}

function Deploy-Item {
    <#
    .SYNOPSIS
        Deploy a file or folder from AdminPC to LabPCs

    .DESCRIPTION
        Copy a file or folder to all LabUser desktops, folders are copied recursively.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, HelpMessage="Enter Path to file or folder")]
        [string]$Path,
        [Parameter(Mandatory=$True, HelpMessage="Enter LabUser name")]
        [string]$UserName
    )

    Test-NoLabPcName
    Resolve-Path -Path $Path -ErrorAction Stop | Out-Null

    $currentlab.PcNames | ForEach-Object -Parallel {
        $session = New-PSSession -ComputerName $_
        $labUserprofilePath = Invoke-Command -Session $session -ScriptBlock {
            param($UName)
            try {
                # LabUser exist?
                $labUser = Get-LocalUser -Name $UName -ErrorAction Stop

                # LabUser signed-in?
                $labUserProfilePath = (Get-CimInstance -Class Win32_UserProfile |
                                    Where-Object { $_.SID -eq $labUser.SID.Value }).LocalPath

                if ($null -eq $labUserProfilePath) {
                    Write-Host "$UName exist but never signed-in on $env:computername" -ForegroundColor Yellow
                    Write-Host "Deployment to $env:computername failed" -ForegroundColor Red
                }
            }
            catch [Microsoft.PowerShell.Commands.UserNotFoundException] {
                Write-Host "$UName NOT exist on $env:computername" -ForegroundColor Yellow
                Write-Host "Deployment to $env:computername failed" -ForegroundColor Red
                $labUserProfilePath = $null
            }
            finally {
                $labUserProfilePath
            }
        } -ArgumentList $using:UserName

        if ($null -ne $labUserprofilePath) {
            $labUserDesktopPath = Join-Path -Path $labUserprofilePath -ChildPath 'Desktop'
            Copy-Item -Path $using:Path -Destination $labUserDesktopPath -ToSession $session -Recurse -Force
            Write-Host "Deployment to $_ success" -ForegroundColor Green
        }
        Remove-PSSession $session
    } -ThrottleLimit 5
}

function Disconnect-User {
    <#
    .SYNOPSIS
        Disconnect any connected user from each LabPC

    .EXAMPLE
        Disconnect-User

    .NOTES
        Windows Home edition doesn't include query.exe (https://superuser.com/a/1646775)

        Quser.exe emit a non-terminating error in case of no user logged-in,
        to catch the error force PS to raise an exception, set $ErrorActionPreference = 'Stop'
        because quser, being not a cmdlet, has not -ErrorAction parameter.
    #>
    [CmdletBinding()]
    param()

    Test-NoLabPcName
    Invoke-Command -ComputerName $currentLab.PcNames -ScriptBlock {
        $ErrorActionPreference = 'Stop' # NOTE: it is valid only for this function scope
        try {
            # check if quser command exist
            Get-Command -Name quser -ErrorAction Stop | Out-Null

            # get array of logged-in users, skip 1st row (the head)
            quser | Select-Object -Skip 1 |
            ForEach-Object {
                # logoff by session ID
                logoff ($_ -split "\s+")[2]
                Write-Host "User", ($_ -split "\s+")[1], "logged out $($env:COMPUTERNAME)"  -ForegroundColor Green
            }
        }
        catch [System.Management.Automation.CommandNotFoundException] {
            Write-Host "Cannot disconnect any user: quser command not found on $env:computername" -ForegroundColor Red
            Write-Host "is it a windows Home edition?"
        }
        catch {
            Write-host "No user logged in $($env:COMPUTERNAME)" -ForegroundColor Yellow
        }
    }
}

# -- LabUser section --

function New-LabUser {
    <#
    .SYNOPSIS
        Create a Standard Lab user with a blank never-expiring password

    .EXAMPLE
        New-LabUser -UserName "Alunno"

    .NOTES
        I just want to clarify the usage of the New-LocalUser cmdlet's switch parameters
        -NoPassword and -UserMayNotChangePassword. According to Microsoft, the -NoPassword
        parameter indicates that the user account doesn't have a password. However, in my
        tests, the user was prompted to provide a password when signing in for the first time.
        This indicates that -NoPassword is different from a blank password. Consequently, using
        -NoPassword along with -UserMayNotChangePassword results in a deadlock.

        Windows Groups' description: https://ss64.com/nt/syntax-security_groups.html
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
      [Parameter(Mandatory=$True, HelpMessage="Enter username for Lab User")]
      [string]$UserName
    )

    Test-NoLabPcName
    Invoke-Command -ComputerName $currentLab.PcNames -ScriptBlock {
        try {
            $blankPassword = [securestring]::new()
            New-LocalUser -Name $Using:UserName -Password $blankPassword -PasswordNeverExpires `
            -UserMayNotChangePassword -AccountNeverExpires -ErrorAction Stop | Out-Null

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
        Remove specified Lab User, also remove registry entry and user profile folder if they exist

    .DESCRIPTION
        This cmdlet log out the lab user if he is logged in and completely remove it

    .EXAMPLE
        Remove-LabUser -Username "Alunno"

    .NOTES
        Inspiration: https://adamtheautomator.com/powershell-delete-user-profile/
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
      [Parameter(Mandatory=$True, HelpMessage="Enter username for Lab User")]
      [string]$UserName
    )

    Test-NoLabPcName
    Invoke-Command -ComputerName $currentLab.PcNames -ScriptBlock {
        try {
            # check if quser command exist
            Get-Command -Name quser -ErrorAction Stop | Out-Null

            # log out if logged in otherwise silently continue
            $ErrorActionPreference = 'SilentlyContinue'
            quser $Using:UserName | Select-Object -Skip 1 |
            ForEach-Object {
                # logoff by session ID
                logoff ($_ -split "\s+")[2]
                Write-Host "User", ($_ -split "\s+")[1], "logged out $($env:COMPUTERNAME)"  -ForegroundColor Green
            }
            $ErrorActionPreference = 'Continue'
        }
        catch [System.Management.Automation.CommandNotFoundException] {
            Write-Host "quser command not found on $env:computername" -ForegroundColor Red
            Write-Host "is it a windows Home edition? I'll try to remove $using:UserName anyway ...`n"
        }

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
    [CmdletBinding(DefaultParameterSetName = 'Set0', SupportsShouldProcess = $True)]
    param (
        [Parameter(Mandatory=$True, HelpMessage="Enter the username for Lab User")]
        [string]$UserName,
        [switch]$SetPassword,
        [validateSet('StandardUser', 'Administrator')]
        [string]$AccountType,
        [Parameter(ParameterSetName = 'Set1')]
        [switch]$BackupDesktop,
        [Parameter(ParameterSetName = 'Set2')]
        [switch]$RestoreDesktop
    )

    Test-NoLabPcName
    switch ($PSCmdlet.ParameterSetName) {
        'Set0' {$password = $null
                if ($SetPassword.IsPresent) {
                    # Prompt and read new password
                    $password = Read-Host -Prompt 'Enter the new password' -AsSecureString
                }
                Invoke-Command -ComputerName $currentlab.PcNames  -ScriptBlock {
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
        'Set1' {Backup-LabUserDesktop -UserName $UserName} # -BackupDesktop provided
        'Set2' {Restore-LabUserDesktop -UserName $UserName} # -RestoreDesktop provided
    }
}

function Backup-LabUserDesktop {
    <#
        Back up LabUser desktop into ROOT:\LabPc folder

        This cmdlet copies LabUser desktop files and folders into into ROOT:|LabPc folder and deletes any previous item.

        Backup-LabUserDesktop -UserName Alunno
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, HelpMessage="Enter LabUser name")]
        [string]$UserName
    )
    Invoke-Command -ComputerName $currentLab.PcNames -ScriptBlock {
        try {
            # get specified Lab user
            $localUser = Get-LocalUser -Name $Using:UserName -ErrorAction Stop

            # get Lab user USERPROFILE path
            $userProfilePath = (Get-CimInstance -Class Win32_UserProfile | Where-Object { $_.SID -eq $localUser.SID.Value }).LocalPath
            # Test-Path -Path $userProfilePath -ErrorAction Stop | Out-Null

            $userDesktopPath = Join-Path -Path $userprofilePath -ChildPath 'Desktop'

            # create LabPc folder if not exist
            $labPcPath = Join-Path -Path $env:SystemDrive -ChildPath 'LabPc'
            New-Item -Path $labPcPath -ItemType "directory" -ErrorAction SilentlyContinue

            # copy labuser desktop
            Remove-Item -Path $labPcPath -Force -Recurse -ErrorAction SilentlyContinue # delete any previous saved desktop
            Copy-Item -Path "$userDesktopPath\" -Destination $labPcPath -Recurse -Force

            Write-Host "$Using:Username Desktop saved for $env:computername" -ForegroundColor Green
        }
        catch [Microsoft.PowerShell.Commands.UserNotFoundException] {
            Write-Host "$Using:UserName @ $env:computername does NOT exist" -ForegroundColor Yellow
            Write-Host "$Using:Username Desktop save failed for $env:computername" -ForegroundColor Red
        }
        catch [System.Management.Automation.ParameterBindingException] {
            # user exist USERPROFILE path no
            Write-Host "$Using:UserName exist but never signed-in on $env:computername" -ForegroundColor Yellow
            Write-Host "$Using:Username Desktop save failed for $env:computername" -ForegroundColor Red
        }
    }
}

function Restore-LabUserDesktop {
    <#
        Restore LabUser desktop backup from ROOT:\LabPc

        This cmdlet copies back the LabUser desktop backup from ROOT:\LabPc folder, overwrite any existing items.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, HelpMessage="Enter LabUser name")]
        [string]$UserName
    )
    Invoke-Command -ComputerName $currentLab.PcNames -ScriptBlock {
        try {
            # get specified Lab user
            $localUser = Get-LocalUser -Name $Using:UserName -ErrorAction Stop

            # get Lab user USERPROFILE path
            $userProfilePath = (Get-CimInstance -Class Win32_UserProfile | Where-Object { $_.SID -eq $localUser.SID.Value }).LocalPath
            Test-Path -Path $userProfilePath -ErrorAction Stop | Out-Null

            $userDesktopPath = Join-Path -Path $userprofilePath -ChildPath 'Desktop'

            # copy lab user desktop back
            $sourcePath = Join-Path -Path $env:SystemDrive -ChildPath "LabPc"
            Copy-Item -Path "$sourcePath\*" -Destination $userDesktopPath -Recurse -Force

            Write-Host "$Using:Username Desktop restored for $env:computername" -ForegroundColor Green
        }
        catch [Microsoft.PowerShell.Commands.UserNotFoundException] {
            Write-Host "$Using:UserName @ $env:computername does NOT exist" -ForegroundColor Yellow
            Write-Host "$Using:Username Desktop restore failed for $env:computername" -ForegroundColor Red
        }
        catch [System.Management.Automation.ParameterBindingException] {
            Write-Host "$Using:UserName exist but never signed-in on $env:computername" -ForegroundColor Yellow
            Write-Host "$Using:Username Desktop restore failed for $env:computername" -ForegroundColor Red
        }
    }
}


# -- LabPc section --

function Get-LabPcMac {
    <#
    .SYNOPSIS
        Show info into GUI console about Ethernet PcLab MAC addresses.

    .DESCRIPTION
        Get-LabPcMac searches for LabPC Ethernet MAC addresses. When
        a MAC address is found, it is saved to the configuration file.
        MAC addresses are required for the Start-LabPc cmdlet to use
        Wake-on-LAN (WoL).

    .NOTES
        This cmdlet uses Write-Output to send messages to the pipeline,
        allowing them to be displayed in the GUI console.
    #>

    Update-Config
    $foundMacs = @()
    $currentlab.PcNames | ForEach-Object {
        try {
            Write-Output "`n$_"
            $pcNameLen = $_.Length

            # Search for Physical, connected (Up), ethernet (standard 802.3) adapter
            $netAdapter = Get-NetAdapter -Physical -CimSession $_ -ErrorAction Stop |
            Where-Object {
                $_.Status -eq "Up" -and ($_.PhysicalMediaType -like "*802.3*" -or $_.Name -like "*Ethernet*")
            } | Select-Object MacAddress

            if ($netAdapter.Length -eq 0) {
                # Connected, but not via an Ethernet adapter.
                $foundMacs += $null
                Write-Output "is not connected via an Ethernet adapter. Please connect.`n$('-' * $pcNameLen)"
            }
            elseif ($netAdapter.Length -eq 1) {
                # Connected via an Ethernet adapter.
                $foundMacs += $netAdapter.MacAddress
                Write-Output "$($netAdapter.MacAddress)`n$('-' * $pcNameLen)"
            }
            else {
                # Connected via multiple adapters, including Ethernet.
                $foundMacs += $null
                Write-Output "appears to have $($netAdapter.MacAddress.count) Ethernet adapters. Disconnect all but one.`n$('-' * $pcNameLen)"
            }

        }
        catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException] {
            # LabPC is unreachable because it is either off, not connected, or not ready.
            $foundMacs += $null
            Write-Output "is unreachable because it is either off, not connected, or not ready.`n$('-' * $pcNameLen)"
        }
        catch {
            Write-Output $_.exception.GetType().fullname
        }
    }

    $script:currentLab.PcMacs = $foundMacs
    $script:config.Labs[$config.LastSelectedLab] = $currentLab

    # Save to JSON file
    $config | ConvertTo-Json -Depth 10 | Set-Content -Path $configPath
    Write-Output "`n`nAny found MAC addresses have been saved and are available for Start-LabPc cmdlet."
    if ($foundMacs -contains $null) {
        Write-Output "`nTo retrieve any missing MAC addresses, resolve the issues above and press again [Get MACs] button."
    }
}

function Start-LabPc {
    <#
    .SYNOPSIS
        Turn on each computers if WoL setting is present and enabled in BIOS/UEFI

    .EXAMPLE
        Start-LabPc

    .NOTES
        https://www.pdq.com/blog/wake-on-lan-wol-magic-packet-powershell/
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param ()

    Test-NoLabPcName
    Write-Host "Remember, Start-LabPc works only if the LabPCs support WoL (Wake-on-LAN)." -ForegroundColor DarkYellow

    # Send Magic Packet over LAN
    for ($i = 0; $i -lt $currentlab.PcNames.Count; $i++) {
        $PcName = $currentlab.PcNames[$i]
        $Mac = $currentlab.PcMacs[$i]
        if ($Mac) {
            $MacByteArray = $Mac -split "[:-]" | ForEach-Object { [Byte] "0x$_"}
            [Byte[]] $MagicPacket = (,0xFF * 6) + ($MacByteArray * 16)
            $UdpClient = New-Object System.Net.Sockets.UdpClient
            $UdpClient.Connect(([System.Net.IPAddress]::Broadcast),7)
            $UdpClient.Send($MagicPacket,$MagicPacket.Length) | Out-Null
            $UdpClient.Close()
            Write-Host $PcName, "Started" -ForegroundColor Green
        }
        else {
            Write-Host $PcName, "is missing MAC Address." -ForegroundColor Red
            Write-host "(Run Set-LabPcNames and press [Get MACs] button for more information.)" -ForegroundColor Gray
        }
    }

}

function Stop-LabPc {
    <#
    .SYNOPSIS
        Force an immediate shut down of each computer

    .EXAMPLE
        Stop-LabPc

    .NOTES
    #>
    [CmdletBinding(DefaultParameterSetName = 'Set0', SupportsShouldProcess = $true)]
    param (
        [Parameter(ParameterSetName = 'Set1')]
        [switch]$When, # Get scheduled LabPcs daily stops

        [Parameter(ParameterSetName = 'Set2')]
        [string]$DailyAt, # Schedule a new LabPc daily stop

        [Parameter(ParameterSetName = 'Set3')]
        [string]$NoMoreAt, # Remove a LabPc daily stop

        [Parameter(ParameterSetName = 'Set4')]
        [switch]$AndRestart # Restart LabPcs
    )

    Test-NoLabPcName
    Rename-TaskPath
    switch ($PSCmdlet.ParameterSetName) {
        'Set0' {Stop-Computer -ComputerName $currentlab.PcNames -Force} # no parameter provided
        'Set1' {Get-LabPcStop} # -When provided
        'Set2' {New-LabPcStop -DailyTime $DailyAt} # -DailyAt provided
        'Set3' {Remove-LabPcStop -DailyTime $NoMoreAt} # -NoMoreAt provided
        'Set4' {Restart-LabPc} # -AndRestart provided
    }
}

function Rename-TaskPath {
    <#
    This function exists for backward compatibility and will be silently executed
    for six months (November 15, 2024 - May 15, 2025) during each Stop-LabPc call.

    - Moves the StopThisComputer task to the new folder and deletes the old folder.
    - If the old folder is not found, no action is taken.
    - If the old folder is empty, it is deleted.
    #>
    param ()

    $oldFolderPath = "\WinLabAdmin\"
    $newFolderPath = "\WindowsLab\"

    Invoke-Command -ComputerName $currentLab.PcNames -ScriptBlock {

        try {
            # In both cases folder not exist or is empty raise an exception
            $tasks = Get-ScheduledTask -TaskPath $using:oldFolderPath -ErrorAction Stop

            # Create the new folder by adding and removing a temporary task, the new folder remain
            $action = New-ScheduledTaskAction -Execute "cmd.exe"
            $trigger = New-ScheduledTaskTrigger -AtStartup
            Register-ScheduledTask -TaskName "TempTask" -TaskPath $using:newFolderPath -Action $action -Trigger $trigger -Force
            Unregister-ScheduledTask -TaskName "TempTask" -TaskPath $using:newFolderPath -Confirm:$false

            # Move tasks from the old folder to the new folder
            $tasks = Get-ScheduledTask -TaskPath $using:oldFolderPath -ErrorAction SilentlyContinue
            foreach ($task in $tasks) {
                Register-ScheduledTask -TaskName $task.TaskName -TaskPath $using:newFolderPath -InputObject $task -Force
                Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $using:oldFolderPath -Confirm:$false
            }
        }
        catch {
            # Catch exception and do nothing, this avoid display exception to console
        }
        finally {# At this point the task folder not exist or is empty

            # Delete the folder if empty, returns error if not exixt
            & schtasks.exe /DELETE /TN "$using:oldFolderPath".Trim('\') /F 2>&1
        }
    } | Out-Null
}

function Restart-LabPc {
    <#
        Force an immediate restart of each computer and wait for them to be on again

        Restart-LabPc
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()
    Restart-Computer -ComputerName $currentlab.PcNames -Force
}


function New-LabPcStop {
    <#
        Schedule a new LabPC daily stop at given local-time i.e. the
        task’s execution time will adjust automatically with DST changes.

        This cmdlet creates the StopThisComputer task with the specified stop time as a trigger.
        If the task already exists, it adds the stop time as an additional trigger.

        New-LabPcStop -DailyTime '14:15'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory=$True, HelpMessage="Enter the daily stop time")]
        [string]$DailyTime
    )

    # -DailyTime parsing
    try {
        # Validate the time format
        if (-not ($DailyTime -match "^\d{1,2}:\d{2}$")) {
            throw "Invalid time format. Please use HH:mm format (e.g., '09:00')"
        }

        $hours = [int]($DailyTime.Split(":")[0])
        $minutes = [int]($DailyTime.Split(":")[1])

        # Validate hours and minutes ranges
        if (($hours -lt 0 -or $hours -gt 23) -or ($minutes -lt 0 -or $minutes -gt 59)) {
            throw "Hours must be between 0 and 23 and minutes must be between 0 and 59"
        }

        # Create a local [DateTime] object based on the provided DailyTime parameter.
        $dailyTimeObj = Get-Date -Hour $hours -Minute $minutes -Second 0 -Millisecond 0
    }
    catch {
        Write-Host "$_" -ForegroundColor Red
        return $null
    }

    # Set the trigger
    $trigger = New-ScheduledTaskTrigger -Daily -At $dailyTimeObj

    # Set the action
    $action = New-ScheduledTaskAction -Execute 'Powershell' -Argument '-NoProfile -ExecutionPolicy Bypass -Command "& {Stop-Computer -Force}"'

    # Extract the time from DateTime obj as TimeSpan object
    $givenTimeTrigger = $dailyTimeObj.TimeOfDay

    Invoke-Command -ComputerName $currentLab.PcNames -ScriptBlock {

        # Set principal contex for SYSTEM account to run as a service with the highest privileges
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        try {
            # Get scheduled StopThisComputer task if exist
            $stopThisComputerTask = Get-ScheduledTask -TaskName:'StopThisComputer' -TaskPath:'\WindowsLab\' -ErrorAction Stop
        }
        catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException] {
            # Register the task (-TaskPath is the folder)
            Register-ScheduledTask -TaskName:'StopThisComputer' -TaskPath:'\WindowsLab\' -Action $using:action -Trigger $using:trigger -Principal $principal | Out-Null
            Write-Host "First stop daily time $using:DailyTime just set on $env:computername" -ForegroundColor Green
            Write-Host " ... and StopThisComputer task set`n"
            Return $null
        }

        # Get all time triggers as TimeSpan objects
        $allTimeTriggers = @()
        foreach ($trg in $stopThisComputerTask.Triggers) {
            $allTimeTriggers += ([datetime] $trg.StartBoundary).TimeOfDay
        }

        # Check if the new time trigger is already present
        if ($using:givenTimeTrigger -in $allTimeTriggers) {
            Write-Host "A stop at daily time $using:DailyTime already exist on $env:computername" -ForegroundColor Red
        } else {
            # Add the new stop time
            $stopThisComputerTask.Triggers += $using:trigger
            Set-ScheduledTask -TaskName:'StopThisComputer' -TaskPath:'\WindowsLab\' -Trigger $stopThisComputerTask.Triggers -Principal $principal | Out-Null
            Write-Host "A stop at daily time $using:DailyTime added to $env:computername" -ForegroundColor Green
        }
    }
}

function Get-LabPcStop {
    <#
        Gets LabPC daily stops

        This cmdlet gets all trigger times for StopThisComputer scheduled task

        Get-LabPcStop
    #>
    [CmdletBinding()]
    param ()

    Invoke-Command -ComputerName $currentLab.PcNames -ScriptBlock {

        $formattedTime = "${env:COMPUTERNAME} stop(s):`n  "
        try {
            # Get scheduled StopThisComputer task if exist
            $stopThisComputerTask = Get-ScheduledTask -TaskName:'StopThisComputer' -TaskPath:'\WindowsLab\' -ErrorAction Stop
        }
        catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException] {
            # $_.exception.GetType().fullname
            $formattedTime += "None"
            Write-Host $formattedTime
            Return $null
        }

        # Get all time triggers as TimeSpan objects
        $allTimeTriggers = @()
        foreach ($trg in $stopThisComputerTask.Triggers) {
            $allTimeTriggers += ([datetime] $trg.StartBoundary).TimeOfDay
        }

        # Print the array in "hh:mm" format
        foreach ($timeSpan in $allTimeTriggers) {
            $formattedTime += "{0:hh\:mm\,\ }" -f $timeSpan
        }
        $formattedTime = $formattedTime.Substring(0, $formattedTime.Length - 2)
        Write-Host $formattedTime "(local time)"
    }
}

function Remove-LabPcStop {
    <#
        Removes a LabPC daily stop

        This cmdlet removes if exist the trigger from StopThisComputer scheduled task with time -DailyTime

        Remove-LabPcStop -DailyTime '14:14'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory=$True, HelpMessage="Enter daily stop time to remove")]
        [string]$DailyTime
    )

    # Time parameter parsing
    try {
        $dailyTimeObj = [DateTime]::ParseExact($DailyTime, "HH:mm", [System.Globalization.CultureInfo]::InvariantCulture)
    }
    catch {
        Write-Error "-DailyTime $DailyTime must be in HH:mm format"
        return $null
    }

    # Extract the time from DateTime obj as TimeSpan object
    $givenTimeTrigger = $dailyTimeObj.TimeOfDay

    Invoke-Command -ComputerName $currentLab.PcNames -ScriptBlock {

        try {
            # Get scheduled StopThisComputer task if exist
            $stopThisComputerTask = Get-ScheduledTask -TaskName:'StopThisComputer' -TaskPath:'\WindowsLab\' -ErrorAction Stop
        }
        catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException] {
            # $_.exception.GetType().fullname
            Write-Host "Stop daily time $Using:DailyTime not exist on $env:computername" -ForegroundColor Red
            Return $null
        }

        # Set principal contex for SYSTEM account to run as a service with with the highest privileges
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        # Remove the given time trigger
        $allTriggersButTheGiven = @()
        foreach ($trg in $stopThisComputerTask.Triggers) {
            if (([datetime] $trg.StartBoundary).TimeOfDay -ne $Using:givenTimeTrigger) {
                $allTriggersButTheGiven += $trg
            }
        }

        if ($allTriggersButTheGiven.Count -eq 0) {
            Unregister-ScheduledTask -TaskName:'StopThisComputer' -TaskPath:'\WindowsLab\' -Confirm:$false
            Write-Host "Last Stop daily time $Using:DailyTime removed on $env:computername" -ForegroundColor Green
            Write-Host " ... and StopThisComputer Task deleted`n"
        }
        elseif ($allTriggersButTheGiven.count -lt $stopThisComputerTask.Triggers.count) {
            Set-ScheduledTask -TaskName:'StopThisComputer' -TaskPath:'\WindowsLab\' -Trigger $allTriggersButTheGiven -Principal $principal | Out-Null
            Write-Host "Stop daily time $Using:DailyTime removed on $env:computername" -ForegroundColor Green
        } else {
            Write-Host "Stop daily time $Using:DailyTime not exist on $env:computername" -ForegroundColor Red
        }

    }
}