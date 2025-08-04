# config.ps1
<#
.SYNOPSIS
  Configuration file for OAShortcutManager.

.NOTES
  OAShortcutManager — https://github.com/osamah/OAShortcutManager
#>

# File paths
$OutputFolder = "C:\ProgramData\OAShortcutManager"

$Config = @{
    # Output paths
    OutputFolder = $OutputFolder
    SnapshotJsonPath = "$OutputFolder\apps_snapshot.json"
    
    # Registry paths to scan
    RegistryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        "HKLM:\SOFTWARE\Microsoft\WindowsApps"
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\WindowsApps"
    )
    
    # System folders
    SystemFolders = @{
        Desktop = [System.Environment]::GetFolderPath('Desktop')
        StartMenu = [System.Environment]::GetFolderPath('StartMenu')
        ProgramFiles = [System.Environment]::GetFolderPath('ProgramFiles')
        ProgramFilesX86 = [System.Environment]::GetFolderPath('ProgramFilesX86')
        ProgramFilesCommon = [System.Environment]::GetFolderPath('ProgramFilesCommon')
        ProgramFilesCommonX86 = [System.Environment]::GetFolderPath('ProgramFilesCommonX86')
    }
    
    # Search settings
    SearchSettings = @{
        ExeRecursive = $true
        LnkRecursive = $true
        MaxDepth = 3
        HashAlgorithm = "SHA256"
        ExcludeFolders = @(
            "$env:SystemRoot\WinSxS"
            "$env:SystemRoot\assembly"
        )
    }
    
    # Rebuild settings
    RebuildSettings = @{
        DefaultTargetFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs"
        CreateBackups = $true
        BackupFolder = "$PSScriptRoot\backups"
        OverwriteExisting = $false
    }
}

# Validate and create necessary folders
if (-not (Test-Path -Path $Config.OutputFolder)) {
    New-Item -Path $Config.OutputFolder -ItemType Directory -Force | Out-Null
}

if ($Config.RebuildSettings.CreateBackups -and -not (Test-Path -Path $Config.RebuildSettings.BackupFolder)) {
    New-Item -Path $Config.RebuildSettings.BackupFolder -ItemType Directory -Force | Out-Null
}

# Return the configuration
return $Config
