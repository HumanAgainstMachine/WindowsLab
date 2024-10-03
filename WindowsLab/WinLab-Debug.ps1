# Load the Windows Forms assembly
Add-Type -AssemblyName System.Windows.Forms

# Create the form
$form = New-Object System.Windows.Forms.Form
$form.Text = "JSON File Editor"
$form.Size = New-Object System.Drawing.Size(533, 400)  # Increased width and height

# Create a label for the computer names
$labelNames = New-Object System.Windows.Forms.Label
$labelNames.Text = "Edit Computer Names (comma-separated):"
$labelNames.AutoSize = $true
$labelNames.Location = New-Object System.Drawing.Point(10, 10)
$form.Controls.Add($labelNames)

# Create a TextBox to display and edit the computer names
$textboxNames = New-Object System.Windows.Forms.TextBox
$textboxNames.Multiline = $false
$textboxNames.ScrollBars = 'Horizontal'
$textboxNames.Size = New-Object System.Drawing.Size(467, 30)  # Increased width
$textboxNames.Location = New-Object System.Drawing.Point(10, 30)
$form.Controls.Add($textboxNames)

# Create a label for the computer MAC addresses (read-only)
$labelMACs = New-Object System.Windows.Forms.Label
$labelMACs.Text = "Computer MAC Addresses (read-only):"
$labelMACs.AutoSize = $true
$labelMACs.Location = New-Object System.Drawing.Point(10, 80)
$form.Controls.Add($labelMACs)

# Create a TextBox to display the MAC addresses (read-only)
$textboxMACs = New-Object System.Windows.Forms.TextBox
$textboxMACs.Multiline = $false
$textboxMACs.ScrollBars = 'Horizontal'
$textboxMACs.ReadOnly = $true  # Set as read-only
$textboxMACs.Size = New-Object System.Drawing.Size(467, 30)  # Increased width
$textboxMACs.Location = New-Object System.Drawing.Point(10, 100)
$form.Controls.Add($textboxMACs)

# Create Save button
$saveButton = New-Object System.Windows.Forms.Button
$saveButton.Text = "Save"
$saveButton.Location = New-Object System.Drawing.Point(10, 150)
$form.Controls.Add($saveButton)

# Create Refresh button
$refreshButton = New-Object System.Windows.Forms.Button
$refreshButton.Text = "Refresh"
$refreshButton.Location = New-Object System.Drawing.Point(100, 150)
$form.Controls.Add($refreshButton)

# File path
$jsonFilePath = "config.json"

# Function to load JSON content
function Load-JsonContent {
    try {
        # Read the JSON file content
        $jsonContent = Get-Content -Path $jsonFilePath -Raw | ConvertFrom-Json
        
        # Extract and display values from the 'labComputerNames' key (array of values)
        $names = $jsonContent.labComputerNames -join ", "
        $textboxNames.Text = $names
        
        # Extract and display values from the 'labComputerMACs' key (read-only array of values)
        $macs = $jsonContent.labComputerMACs -join ", "
        $textboxMACs.Text = $macs
        
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to load JSON.")
    }
}

# Save JSON function
$saveButton.Add_Click({
    try {
        # Get the updated computer names from the textbox (comma-separated)
        $newNames = $textboxNames.Text -split ",\s*"
        
        # Silently remove empty values
        $newNames = $newNames | Where-Object { $_ -ne "" }
        
        # Load the original JSON, update the 'labComputerNames' key with new values
        $jsonContent = Get-Content -Path $jsonFilePath -Raw | ConvertFrom-Json
        $jsonContent.labComputerNames = $newNames
        
        # Save the updated JSON back to the file
        $jsonContent | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonFilePath
        [System.Windows.Forms.MessageBox]::Show("JSON file saved successfully.")
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to save JSON.")
    }
})

# Refresh function (reloading JSON)
$refreshButton.Add_Click({
    Load-JsonContent
})

# Load the JSON content as soon as the form pops up
$form.Add_Shown({
    Load-JsonContent
})

# Show the form
$form.ShowDialog()
