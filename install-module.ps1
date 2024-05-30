<#
.SYNOPSIS
    Current module offline install

.NOTES
    Copy module and config files to user specific modules path in PowerShell
#>

$moduleName = Split-Path -Path $PSScriptRoot -Leaf
$userProfileEscapedPath = [RegEx]::Escape($env:USERPROFILE)

$modulePaths = $env:PSModulePath.split(';') | Select-String -Pattern $userProfileEscapedPath

if ($null -ne $modulePaths) {
    $modulePath = Join-Path -Path $modulePaths -ChildPath $moduleName
    # create folder if not exist
    if (-Not (Test-Path -Path $modulePath -PathType Container)) {
        Copy-Item -path $PSScriptRoot -Destination $modulePath 
    }
    # test if config.json exist
    if (Test-Path -Path 'config.json' -PathType Leaf) {
        Copy-Item -Path '*.psm1', 'config.json' -Destination $modulePath -Force
        Write-Host "Module Installed" -ForegroundColor Green
    }
    else {
        Write-Host "config.json missing ... Create that file to install the module" -ForegroundColor Yellow
    }
} else {
    Write-Host "Specific User PSModulePath not found" -ForegroundColor Red
}

