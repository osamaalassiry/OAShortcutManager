<#
.SYNOPSIS
  Simple entry point for OAShortcutManager.

.DESCRIPTION
  This script provides a simplified command-line interface to the OAShortcutManager module.
  It can generate snapshots of installed applications and rebuild shortcuts.

.PARAMETER Snapshot
  Generate a snapshot of installed applications.

.PARAMETER Rebuild
  Rebuild shortcuts from a snapshot file.

.PARAMETER JsonFile
  Path to the snapshot JSON file for rebuild operation.

.PARAMETER ConfigPath
  Path to the configuration file.

.PARAMETER DetailedWhatIf
  Show what would happen if the command runs without making any changes.

.PARAMETER Verbose
  Enable verbose output.

.EXAMPLE
  # Generate a snapshot
  .\OAShortcutManager.ps1 -Snapshot

.EXAMPLE
  # Rebuild shortcuts from a snapshot
  .\OAShortcutManager.ps1 -Rebuild -JsonFile "C:\path\to\apps_snapshot.json"

.EXAMPLE
  # Test rebuilding shortcuts without making changes
  .\OAShortcutManager.ps1 -Rebuild -JsonFile "C:\path\to\apps_snapshot.json" -WhatIf

.NOTES
  OAShortcutManager — https://github.com/osamaalassiry/OAShortcutManager
#>

param (
    [switch]$Snapshot,
    [switch]$Rebuild,
    [string]$JsonFile,
    [string]$ConfigPath,
    [switch]$DetailedWhatIf,  
    [switch]$Verbose
)

# Set verbose preference if needed
if ($Verbose) {
    $VerbosePreference = "Continue"
}

# Import the module - look in the same directory as this script
$moduleDir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$modulePath = Join-Path -Path $moduleDir -ChildPath "OAShortcutManager.psm1"
if (-not (Test-Path -Path $modulePath)) {
    # Try the regular module import
    if (-not (Get-Module -Name OAShortcutManager -ListAvailable)) {
        Write-Error "OAShortcutManager module not found. Please install it first."
        exit 1
    }
}
else {
    # Import from local path
    Import-Module $modulePath -Force
}

# Define common parameters
$params = @{}
if (-not [string]::IsNullOrEmpty($ConfigPath)) {
    $params["ConfigPath"] = $ConfigPath
}

# Generate snapshot
if ($Snapshot) {
    New-ShortcutSnapshot @params
    exit 0
}

# Rebuild shortcuts
if ($Rebuild) {
    if (-not [string]::IsNullOrEmpty($JsonFile)) {
        $params["JsonFile"] = $JsonFile
    }
    
    # Pass DetailedWhatIf instead of DetailedWhatIf
    if ($DetailedWhatIf) {
        $params["DetailedWhatIf"] = $true
    }
    
    Rebuild-ShortcutsFromSnapshot @params
    exit 0
}
# If no action was specified, show help
Write-Host "Please specify an action: -Snapshot or -Rebuild" -ForegroundColor Yellow
Write-Host "For help, run: Get-Help $($MyInvocation.MyCommand.Path) -Detailed"
