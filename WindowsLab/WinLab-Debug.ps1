
# Read the content of a binary file into a byte array
$filePath = "C:\Users\Admin\Desktop\CV.odt"
$fileContent = [System.IO.File]::ReadAllBytes($filePath)

# Now $fileContent holds the binary content of the file

[System.IO.File]::WriteAllBytes("C:\Users\Admin\Desktop\mamt.odt", $filecontent) 

