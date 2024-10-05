# Load the Windows Forms assembly
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create the form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Lab Settings"
$form.Size = New-Object System.Drawing.Size(500, 350)  # Reduced height

# Create a label for the computer names
$labelNames = New-Object System.Windows.Forms.Label
$labelNames.Text = "Set LabComputers Names (comma-separated):"
$labelNames.AutoSize = $true
$labelNames.Location = New-Object System.Drawing.Point(10, 10)
$form.Controls.Add($labelNames)

# Create a TextBox to display and edit the computer names
$textboxNames = New-Object System.Windows.Forms.TextBox
$textboxNames.Multiline = $false
$textboxNames.ScrollBars = 'Horizontal'
$textboxNames.Size = New-Object System.Drawing.Size(465, 30)  # Increased width
$textboxNames.Location = New-Object System.Drawing.Point(10, 35)
$form.Controls.Add($textboxNames)

# Create a label for the computer MAC addresses
$labelMACs = New-Object System.Windows.Forms.Label
$labelMACs.Text = "MAC Addresses:"
$labelMACs.AutoSize = $true
$labelMACs.Location = New-Object System.Drawing.Point(10, 75)
$form.Controls.Add($labelMACs)

# Create a panel to hold computer name and MAC address labels with border and darker background
$macPanel = New-Object System.Windows.Forms.Panel
$macPanel.AutoScroll = $true
$macPanel.Size = New-Object System.Drawing.Size(465, 103)  # Reduced panel height to fit in the smaller window
$macPanel.Location = New-Object System.Drawing.Point(10, 100)

# Set background color and border style
$macPanel.BackColor = [System.Drawing.Color]::LightGray  # Slightly darker background
$macPanel.BorderStyle = 'FixedSingle'  # Add a border around the panel
$form.Controls.Add($macPanel)

# Create Save button
$saveButton = New-Object System.Windows.Forms.Button
$saveButton.Text = "Save"
$saveButton.Location = New-Object System.Drawing.Point(10, 230)  # Moved buttons down to create more room
$form.Controls.Add($saveButton)

# Create Refresh button
$refreshButton = New-Object System.Windows.Forms.Button
$refreshButton.Text = "Refresh"
$refreshButton.Location = New-Object System.Drawing.Point(100, 230)  # Moved buttons down to create more room
$form.Controls.Add($refreshButton)

# Create Get MACs button
$getMacsButton = New-Object System.Windows.Forms.Button
$getMacsButton.Text = "Get MACs"
$getMacsButton.Location = New-Object System.Drawing.Point(190, 230)  # Moved buttons down to create more room
$form.Controls.Add($getMacsButton)

# Create a status label for success/failure messages
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.AutoSize = $true
$statusLabel.Location = New-Object System.Drawing.Point(10, 270)
$form.Controls.Add($statusLabel)

# File path
$jsonFilePath = "config.json"

# Function to initialize JSON file if it doesn't exist
function Initialize-JsonFile {
    if (-not (Test-Path -Path $jsonFilePath)) {
        # Create an empty JSON structure with default values
        $emptyJson = @{
            labComputerNames = @()
            labComputerMACs  = @()
        }
        
        # Convert to JSON format and save to file
        $emptyJson | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonFilePath
    }
}

# Function to load JSON content
function Load-JsonContent {
    try {
        # Read the JSON file content
        $jsonContent = Get-Content -Path $jsonFilePath -Raw | ConvertFrom-Json
        
        # Extract and display values from the 'labComputerNames' key (array of values)
        $names = $jsonContent.labComputerNames -join ", "
        $textboxNames.Text = $names
        
        # Extract and display the computer names and MAC addresses
        DisplayComputerNamesAndMacs $jsonContent.labComputerNames $jsonContent.labComputerMACs
        
        # Clear status label on successful load
        $statusLabel.Text = ""
        
    } catch {
        # Show error message in red
        $statusLabel.Text = "Failed to load JSON."
        $statusLabel.ForeColor = 'Red'
    }
}

# Function to display computer names and MAC addresses (including leftovers)
function DisplayComputerNamesAndMacs {
    param ($computerNames, $macAddresses)
    
    # Clear existing labels in the panel
    $macPanel.Controls.Clear()
    
    $yOffset = 0  # Starting Y position for each name/MAC label

    # Iterate over both computer names and MAC addresses
    $totalEntries = [Math]::Max($computerNames.Count, $macAddresses.Count)

    for ($i = 0; $i -lt $totalEntries; $i++) {
        $name = if ($i -lt $computerNames.Count) { $computerNames[$i] } else { "leftover" }
        $mac = if ($i -lt $macAddresses.Count) { $macAddresses[$i] } else { "N/A" }
        
        # Create label showing the computer name (or "leftover") and full MAC address
        $macLabel = New-Object System.Windows.Forms.Label
        $macLabel.Text = "$name - $mac"
        $macLabel.AutoSize = $true
        $macLabel.Location = New-Object System.Drawing.Point(0, $yOffset)
        $macPanel.Controls.Add($macLabel)

        # Increase Y position for next label
        $yOffset += 20
    }
}

# Save JSON function
$saveButton.Add_Click({
    try {
        # Get the updated computer names from the textbox (comma-separated)
        $newNames = $textboxNames.Text -split ",\s*"
        
        # Silently remove empty values
        $newNames = $newNames | Where-Object { $_ -ne "" }
        
        # Cast to array to avoid PowerShell treating a single element as a string
        $newNames = $newNames -as [System.Array]
        
        # Load the original JSON, update the 'labComputerNames' key with new values
        $jsonContent = Get-Content -Path $jsonFilePath -Raw | ConvertFrom-Json
        $jsonContent.labComputerNames = $newNames
        
        # Save the updated JSON back to the file
        $jsonContent | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonFilePath
        
        # Show success message in green
        $statusLabel.Text = "JSON file saved successfully."
        $statusLabel.ForeColor = 'Green'
        
        # Refresh the displayed MAC addresses after saving
        DisplayComputerNamesAndMacs $jsonContent.labComputerNames $jsonContent.labComputerMACs
    } catch {
        # Show error message in red
        $statusLabel.Text = "Failed to save JSON."
        $statusLabel.ForeColor = 'Red'
    }
})

# Refresh function (reloading JSON)
$refreshButton.Add_Click({
    Load-JsonContent
})

# Function to simulate getting MAC addresses and return them as a comma-separated string
function Get-LabComputerMac {
    # # Simulate the shell process and return a comma-separated MAC address string
    # Start-Process powershell -ArgumentList "-NoExit", "-Command `"Write-Host 'Hey! I am running!'`""
    
    return '3C-97-0E-D5-5E-A4, 94-C6-91-32-55-E5, B8-27-EB-55-FF-FF, 94-C6-91-32-55-E5, B8-27-EB-55-FF-FF'  
}

# Get MACs button click event
$getMacsButton.Add_Click({
    try {
        # Get the comma-separated MAC address string
        $macString = Get-LabComputerMac
        
        # Split the MAC string into an array
        $macAddresses = $macString -split ",\s*"
        
        # Cast to array to avoid PowerShell treating a single element as a string
        $macAddresses = $macAddresses -as [System.Array]
        
        # Load the original JSON, update the 'labComputerMACs' key with new values
        $jsonContent = Get-Content -Path $jsonFilePath -Raw | ConvertFrom-Json
        $jsonContent.labComputerMACs = $macAddresses
        
        # Save the updated JSON back to the file
        $jsonContent | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonFilePath
        
        # Display the computer names and MAC addresses in the panel
        DisplayComputerNamesAndMacs $jsonContent.labComputerNames $macAddresses
        
        # Show success message in green
        $statusLabel.Text = "MAC addresses updated successfully."
        $statusLabel.ForeColor = 'Green'
    } catch {
        # Show error message in red
        $statusLabel.Text = "Failed to get MAC addresses."
        $statusLabel.ForeColor = 'Red'
    }
})

# Load the JSON content as soon as the form pops up
$form.Add_Shown({
    Initialize-JsonFile  # Ensure the file exists before loading
    Load-JsonContent      # Then load the content
})

# Show the form
$form.ShowDialog()
