<#
.SYNOPSIS
  PowerShell module for managing application shortcuts.

.DESCRIPTION
  OAShortcutManager provides tools to create snapshots of installed applications and shortcuts,
  and rebuild them with customizations. It scans registry, Program Files, and user folders
  for applications and their shortcuts.

.EXAMPLE
  # Generate a snapshot of installed applications
  New-ShortcutSnapshot
  
.EXAMPLE
  # Rebuild shortcuts from a snapshot file
  Rebuild-ShortcutsFromSnapshot -JsonFile "C:\path\to\snapshot.json"

.NOTES
  OAShortcutManager — https://github.com/osamaalassiry/OAShortcutManager
#>

#region Configuration Functions

# Get configuration from file or create default
function Get-ShortcutManagerConfig {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0)]
        [string]$ConfigPath,
        
        [Parameter()]
        [switch]$CreateDefault
    )
    
    try {
        if (-not [string]::IsNullOrEmpty($ConfigPath) -and (Test-Path -Path $ConfigPath)) {
            # Load from provided path
            $config = & $ConfigPath
            Write-Verbose "Loaded configuration from $ConfigPath"
            return $config
        }
        elseif ($CreateDefault) {
            # Create a default configuration
            $OutputFolder = Join-Path -Path $env:ProgramData -ChildPath "OAShortcutManager"
            
            $Config = @{
                # Output paths
                OutputFolder = $OutputFolder
                SnapshotJsonPath = Join-Path -Path $OutputFolder -ChildPath "apps_snapshot.json"
                
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
                    CommonProgramFiles = [System.Environment]::GetFolderPath('CommonProgramFiles')
                    CommonProgramFilesX86 = [System.Environment]::GetFolderPath('CommonProgramFilesX86')
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
                    DefaultTargetFolder = Join-Path -Path $env:APPDATA -ChildPath "Microsoft\Windows\Start Menu\Programs"
                    CreateBackups = $true
                    BackupFolder = Join-Path -Path $OutputFolder -ChildPath "backups"
                    OverwriteExisting = $false
                }
            }
            
            # Create necessary folders
            if (-not (Test-Path -Path $Config.OutputFolder)) {
                New-Item -Path $Config.OutputFolder -ItemType Directory -Force | Out-Null
            }
            
            if ($Config.RebuildSettings.CreateBackups -and -not (Test-Path -Path $Config.RebuildSettings.BackupFolder)) {
                New-Item -Path $Config.RebuildSettings.BackupFolder -ItemType Directory -Force | Out-Null
            }
            
            # Save default config if ConfigPath was provided
            if (-not [string]::IsNullOrEmpty($ConfigPath)) {
                $configDir = Split-Path -Path $ConfigPath -Parent
                if (-not (Test-Path -Path $configDir)) {
                    New-Item -Path $configDir -ItemType Directory -Force | Out-Null
                }
                
                $Config | ConvertTo-Json -Depth 5 | Out-File -FilePath $ConfigPath -Encoding UTF8
                Write-Verbose "Created default configuration at $ConfigPath"
            }
            
            return $Config
        }
        else {
            Write-Error "Configuration file not found at $ConfigPath and CreateDefault not specified."
            return $null
        }
    }
    catch {
        Write-Error "Error in Get-ShortcutManagerConfig: $_"
        return $null
    }
}

# Export configuration to file
function Export-ShortcutManagerConfig {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [PSCustomObject]$Config,
        
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$ConfigPath
    )
    
    try {
        $configDir = Split-Path -Path $ConfigPath -Parent
        if (-not (Test-Path -Path $configDir)) {
            New-Item -Path $configDir -ItemType Directory -Force | Out-Null
        }
        
        $Config | ConvertTo-Json -Depth 5 | Out-File -FilePath $ConfigPath -Encoding UTF8
        Write-Verbose "Exported configuration to $ConfigPath"
        return $true
    }
    catch {
        Write-Error "Error exporting configuration: $_"
        return $false
    }
}

#endregion

#region Shortcut Management Functions

# Create a shortcut
function New-Shortcut {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$TargetPath,
        
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$ShortcutPath,
        
        [Parameter()]
        [string]$Arguments = "",
        
        [Parameter()]
        [string]$WorkingDirectory = "",
        
        [Parameter()]
        [string]$Description = "",
        
        [Parameter()]
        [string]$IconLocation = "",
        
        [Parameter()]
        [int]$IconIndex = 0,
        
        [Parameter()]
        [switch]$Force
    )
    
    try {
        # Check if shortcut already exists and Force is not specified
        if ((Test-Path -Path $ShortcutPath) -and -not $Force) {
            Write-Host "Shortcut already exists: $ShortcutPath (Use -Force to overwrite)" -ForegroundColor Yellow
            return $false
        }
        
        # Create directory if it doesn't exist
        $shortcutDir = Split-Path -Path $ShortcutPath -Parent
        if (-not (Test-Path -Path $shortcutDir)) {
            New-Item -Path $shortcutDir -ItemType Directory -Force | Out-Null
        }
        
        # Create the shortcut
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
        $Shortcut.TargetPath = $TargetPath
        
        if (-not [string]::IsNullOrEmpty($Arguments)) {
            $Shortcut.Arguments = $Arguments
        }
        
        if (-not [string]::IsNullOrEmpty($WorkingDirectory)) {
            $Shortcut.WorkingDirectory = $WorkingDirectory
        }
        else {
            # Default to the target's directory if TargetPath is not null
            if (-not [string]::IsNullOrEmpty($TargetPath)) {
                $Shortcut.WorkingDirectory = Split-Path -Path $TargetPath -Parent
            }
        }

        
        if (-not [string]::IsNullOrEmpty($Description)) {
            $Shortcut.Description = $Description
        }
        
        if (-not [string]::IsNullOrEmpty($IconLocation)) {
            $Shortcut.IconLocation = "$IconLocation,$IconIndex"
        }
        
        $Shortcut.Save()
        
        Write-Host "Created shortcut: $ShortcutPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Error creating shortcut: $_"
        return $false
    }
}

# Backup a shortcut
function Backup-Shortcut {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$ShortcutPath,
        
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$BackupFolder
    )
    
    if (-not (Test-Path -Path $ShortcutPath)) {
        return $false
    }
    
    try {
        # Create backup directory if it doesn't exist
        if (-not (Test-Path -Path $BackupFolder)) {
            New-Item -Path $BackupFolder -ItemType Directory -Force | Out-Null
        }
        
        # Generate backup file name with timestamp
        $fileName = Split-Path -Path $ShortcutPath -Leaf
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupPath = Join-Path -Path $BackupFolder -ChildPath "${fileName}_${timestamp}.bak"
        
        # Copy the file to backup
        Copy-Item -Path $ShortcutPath -Destination $backupPath -Force
        
        Write-Verbose "Backed up shortcut to: $backupPath"
        return $true
    }
    catch {
        Write-Error "Error backing up shortcut: $_"
        return $false
    }
}

#endregion

#region Application Scanning Functions

# Get applications from registry
function Get-RegistryInstalledApps {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$RegistryPaths
    )
    
    $results = @()
    
    foreach ($path in $RegistryPaths) {
        if (Test-Path -Path $path) {
            $results += Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $key = $_.PSPath
                    $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                    [PSCustomObject]@{
                        DisplayName     = $props.DisplayName
                        InstallLocation = $props.InstallLocation
                        Source          = $path
                    }
                }
                catch {
                    Write-Verbose "Error processing registry key: $($_.PSPath)"
                }
            }
        }
        else {
            Write-Verbose "Registry path not found: $path"
        }
    }
    
    return $results | Where-Object { $_.DisplayName -ne $null }
}

# Get executable files from folders
function Get-ExeInstalledApps {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$FolderPaths,
        
        [Parameter()]
        [bool]$Recursive = $true,
        
        [Parameter()]
        [string[]]$ExcludeFolders = @(),
        
        [Parameter()]
        [string]$HashAlgorithm = "SHA256"
    )
    
    $results = @()
    foreach ($folder in $FolderPaths) {
        if (Test-Path -Path $folder) {
            # Skip excluded folders
            if ($ExcludeFolders -contains $folder) {
                continue
            }
            
            $params = @{
                Path = $folder
                Filter = "*.exe"
                ErrorAction = "SilentlyContinue"
            }
            
            if ($Recursive) {
                $params["Recurse"] = $true
            }
            
            $results += Get-ChildItem @params | Where-Object {
                # Skip files in excluded folders
                foreach ($excludeFolder in $ExcludeFolders) {
                    if ($_.FullName -like "$excludeFolder*") {
                        return $false
                    }
                }
                return $true
            } | ForEach-Object {
                try {
                    $file = $_.FullName
                    if (-not [string]::IsNullOrEmpty($file)) {
                        $parentFolder = Split-Path -Path $file -Parent
                    } else {
                        $parentFolder = "Unknown"
                    }
    
                    # Get a better display name - remove the .exe extension
                    $displayName = [System.IO.Path]::GetFileNameWithoutExtension($_.Name)
    
                    # Create object with all required properties
                    [PSCustomObject]@{
                        FileName = $_.Name
                        Path = $file
                        Hash = (Get-FileHash -Path $file -Algorithm $HashAlgorithm).Hash
                        DisplayName = $displayName
                        InstallLocation = $parentFolder
                        Source = "File scan"
                    }
                }

                catch {
                    Write-Verbose "Error processing file: $($_.FullName): $_"
                }
            }
        }
        else {
            Write-Verbose "Folder path not found: $folder"
        }
    }
    return $results
}


# Get shortcut files from folders
function Get-LnkInstalledApps {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$FolderPaths,
        
        [Parameter()]
        [bool]$Recursive = $true,
        
        [Parameter()]
        [string]$HashAlgorithm = "SHA256"
    )
    
    $results = @()
    foreach ($folder in $FolderPaths) {
        if (Test-Path -Path $folder) {
            $params = @{
                Path = $folder
                Filter = "*.lnk"
                ErrorAction = "SilentlyContinue"
            }
            
            if ($Recursive) {
                $params["Recurse"] = $true
            }
            
            $results += Get-ChildItem @params | ForEach-Object {
                try {
                    $file = $_.FullName
                    $shortcutFolder = Split-Path -Path $file -Parent
                    
                    # Get display name from shortcut filename without extension
                    $displayName = [System.IO.Path]::GetFileNameWithoutExtension($_.Name)
                    
                    $shortcutInfo = [PSCustomObject]@{
                        FileName = $_.Name
                        Path = $file
                        Hash = (Get-FileHash -Path $file -Algorithm $HashAlgorithm).Hash
                        DisplayName = $displayName
                        InstallLocation = $shortcutFolder
                        Source = "Shortcut scan"
                    }
                    
                    # Try to extract target information from the shortcut
                    try {
                        $shell = New-Object -ComObject WScript.Shell
                        $shortcut = $shell.CreateShortcut($file)
                        $shortcutInfo | Add-Member -MemberType NoteProperty -Name "TargetPath" -Value $shortcut.TargetPath
                        $shortcutInfo | Add-Member -MemberType NoteProperty -Name "WorkingDirectory" -Value $shortcut.WorkingDirectory
                        $shortcutInfo | Add-Member -MemberType NoteProperty -Name "Arguments" -Value $shortcut.Arguments
                        $shortcutInfo | Add-Member -MemberType NoteProperty -Name "Description" -Value $shortcut.Description
                        $shortcutInfo | Add-Member -MemberType NoteProperty -Name "IconLocation" -Value $shortcut.IconLocation
                        
                        # Extract install location from target path
                        if (-not [string]::IsNullOrEmpty($shortcut.TargetPath)) {
                            $installDir = Split-Path -Path $shortcut.TargetPath -Parent
                            $shortcutInfo.InstallLocation = $installDir
    
                            # If the shortcut has a description, use it for DisplayName
                            if (-not [string]::IsNullOrEmpty($shortcut.Description)) {
                                $shortcutInfo.DisplayName = $shortcut.Description
                            }
                        }
                    }
                    catch {
                        Write-Verbose "Could not extract shortcut information from $file : $_"
                    }
                    
                    $shortcutInfo
                }
                catch {
                    Write-Verbose "Error processing file: $($_.FullName): $_"
                }
            }
        }
        else {
            Write-Verbose "Folder path not found: $folder"
        }
    }
    return $results
}



#endregion

#region Core Public Functions

# Generate a snapshot of installed applications and shortcuts
function New-ShortcutSnapshot {
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$CheckOnly,
        
        [Parameter()]
        [switch]$ExportOnly,
        
        [Parameter()]
        [switch]$ExportAndRebuild,
        
        [Parameter()]
        [string]$ConfigPath,
        
        [Parameter()]
        [PSCustomObject]$Config
    )
    
    Write-Host "Running OAShortcutManager snapshot scan..." -ForegroundColor Cyan
    
    # Load configuration if not provided
    if ($null -eq $Config) {
        $Config = Get-ShortcutManagerConfig -ConfigPath $ConfigPath -CreateDefault
    }
    
    if ($null -eq $Config) {
        Write-Error "Failed to load or create configuration."
        return $false
    }
    
    # Prepare paths
    $programFilesPaths = @(
        $Config.SystemFolders.ProgramFiles,
        $Config.SystemFolders.ProgramFilesX86,
        $Config.SystemFolders.CommonProgramFiles,
        $Config.SystemFolders.CommonProgramFilesX86
    )
    
    # Get all installed applications
    Write-Verbose "Scanning registry for installed applications..."
    $registryApps = Get-RegistryInstalledApps -RegistryPaths $Config.RegistryPaths
    
    Write-Verbose "Scanning file system for executable files..."
    $exeInstalledApps = Get-ExeInstalledApps -FolderPaths $programFilesPaths `
                                            -Recursive $Config.SearchSettings.ExeRecursive `
                                            -ExcludeFolders $Config.SearchSettings.ExcludeFolders `
                                            -HashAlgorithm $Config.SearchSettings.HashAlgorithm
    
    Write-Verbose "Scanning for shortcuts..."
    $lnkInstalledApps = Get-LnkInstalledApps -FolderPaths @($Config.SystemFolders.Desktop, $Config.SystemFolders.StartMenu) `
                                             -Recursive $Config.SearchSettings.LnkRecursive `
                                             -HashAlgorithm $Config.SearchSettings.HashAlgorithm
    
    # Enhance the exe applications with registry information when possible
    Write-Verbose "Enhancing executable information with registry data..."
    for ($i = 0; $i -lt $exeInstalledApps.Count; $i++) {
        $exeApp = $exeInstalledApps[$i]
        # Try to find a matching application in registry entries
        foreach ($regApp in $registryApps) {
            if ((-not [string]::IsNullOrEmpty($regApp.InstallLocation)) -and 
                (-not [string]::IsNullOrEmpty($regApp.DisplayName)) -and 
                ($exeApp.Path -like "$($regApp.InstallLocation)*")) {
                # Match found - use registry information instead of defaults
                $exeApp.DisplayName = $regApp.DisplayName
                $exeApp.Source = $regApp.Source
                break
            }
        }
    
        # Additional fallback - if we still don't have a display name, use the file name
        if ([string]::IsNullOrEmpty($exeApp.DisplayName)) {
            $exeApp.DisplayName = [System.IO.Path]::GetFileNameWithoutExtension($exeApp.FileName)
        }
    
        # Make sure Source is always populated
        if ([string]::IsNullOrEmpty($exeApp.Source)) {
            $exeApp.Source = "File scan"
        }
    }
    
    # Combine all installed applications
    Write-Verbose "Combining all application data..."
    $installedApps = @()
    $installedApps += $registryApps
    $installedApps += $exeInstalledApps
    $installedApps += $lnkInstalledApps
    # After combining all data in New-ShortcutSnapshot function
        foreach ($app in $installedApps) {
            # Ensure DisplayName is never null
            if ([string]::IsNullOrEmpty($app.DisplayName)) {
                if (-not [string]::IsNullOrEmpty($app.FileName)) {
                    $app.DisplayName = [System.IO.Path]::GetFileNameWithoutExtension($app.FileName)
                } else {
                    $app.DisplayName = "Unknown Application"
                }
            }
    
            # Ensure InstallLocation is never null
            if ([string]::IsNullOrEmpty($app.InstallLocation)) {
                if (-not [string]::IsNullOrEmpty($app.Path)) {
                    $app.InstallLocation = Split-Path -Path $app.Path -Parent
                } else {
                    $app.InstallLocation = "Unknown"
                }
            }
    
            # Ensure Source is never null
            if ([string]::IsNullOrEmpty($app.Source)) {
                if (-not [string]::IsNullOrEmpty($app.Path)) {
                    if ($app.Path -like "*.lnk") {
                        $app.Source = "Shortcut scan"
                    } else {
                        $app.Source = "File scan"
                    }
                } else {
                    $app.Source = "Unknown"
                }
            }
        }

    
        # Ensure InstallLocation is never null
        if ([string]::IsNullOrEmpty($app.InstallLocation)) {
            if (-not [string]::IsNullOrEmpty($app.Path)) {
                $app.InstallLocation = Split-Path -Path $app.Path -Parent
            } else {
                $app.InstallLocation = "Unknown"
            }
        }

    
        # Ensure Source is never null
        if ([string]::IsNullOrEmpty($app.Source)) {
            if ($app.Path -like "*.lnk") {
                $app.Source = "Shortcut scan"
            } else {
                $app.Source = "File scan"
            }
        }
    }

    # Remove duplicates based on FileName and Path
    $installedApps = $installedApps | Select-Object -Unique FileName, Path, Hash, DisplayName, InstallLocation, Source
    

    # Create a hash table to store the snapshot
    $appsSnapshot = @{}
    foreach ($app in $installedApps) {
        $hash = $app.Hash
        if (-not $hash) {
            # Skip items without a hash
            continue
        }
        
        if (-not $appsSnapshot.ContainsKey($hash)) {
            $appsSnapshot[$hash] = @()
        }
        $appsSnapshot[$hash] += $app
    }
    
    # Add timestamp and metadata
    $jsonObject = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ComputerName = $env:COMPUTERNAME
        UserName = $env:USERNAME
        Apps = $appsSnapshot
    }
    
    # Convert the hash table to JSON
    $jsonSnapshot = $jsonObject | ConvertTo-Json -Depth 5
    
    # Export and check for changes
    Export-SnapshotToJson -JsonFilePath $Config.SnapshotJsonPath `
                            -JsonContent $jsonSnapshot `
                            -CheckOnly:$CheckOnly `
                            -ExportOnly:$ExportOnly `
                            -ExportAndRebuild:$ExportAndRebuild `
                            -Config $Config
    
    return $true
}

# Export a JSON snapshot with options
function script:Export-SnapshotToJson {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$JsonFilePath,
        
        [Parameter(Mandatory = $true)]
        [string]$JsonContent,
        
        [Parameter()]
        [switch]$CheckOnly,
        
        [Parameter()]
        [switch]$ExportOnly,
        
        [Parameter()]
        [switch]$ExportAndRebuild,
        
        [Parameter()]
        [PSCustomObject]$Config
    )
    
    # Create output directory if it doesn't exist
    $outputDir = Split-Path -Path $JsonFilePath -Parent
    if (-not (Test-Path -Path $outputDir)) {
        New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
    }
    
    if (Test-Path -Path $JsonFilePath) {
        # Read the existing JSON file
        $existingJson = Get-Content -Path $JsonFilePath -Raw | ConvertFrom-Json
        # Compare with the new snapshot
        if ($existingJson -ne $JsonContent) {
            Write-Host "Changes detected in installed applications." -ForegroundColor Yellow
            if ($ExportOnly -or $ExportAndRebuild) {
                # Export the new JSON
                $JsonContent | Out-File -FilePath $JsonFilePath -Encoding UTF8
                Write-Host "New snapshot exported to $JsonFilePath" -ForegroundColor Green
            }
            if ($ExportAndRebuild) {
                # Call the rebuild function
                Rebuild-ShortcutsFromSnapshot -JsonFile $JsonFilePath -Config $Config
            }
        }
        else {
            Write-Host "No changes detected in installed applications." -ForegroundColor Green
        }
    }
    else {
        # Export the new JSON as it doesn't exist yet
        $JsonContent | Out-File -FilePath $JsonFilePath -Encoding UTF8
        Write-Host "Initial snapshot exported to $JsonFilePath" -ForegroundColor Green
    }
}

# Rebuild shortcuts from a JSON snapshot
function Rebuild-ShortcutsFromSnapshot {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Position = 0)]
        [string]$JsonFile,
        
        [Parameter()]
        [string]$ConfigPath,
        
        [Parameter()]
        [PSCustomObject]$Config,
        
        # Remove this explicit DetailedWhatIf parameter since SupportsShouldProcess already adds one
        # [Parameter(HelpMessage="Test mode - show what would happen without making changes")]
        # [switch]$WhatIf
        
        [Parameter(HelpMessage="Detailed dry-run mode with more information than standard DetailedWhatIf")]
        [switch]$DetailedWhatIf
    )
    
    # Load configuration if not provided
    if ($null -eq $Config) {
        $Config = Get-ShortcutManagerConfig -ConfigPath $ConfigPath -CreateDefault
    }
    
    if ($null -eq $Config) {
        Write-Error "Failed to load or create configuration."
        return $false
    }
    
    # If JsonFile is not specified, use the one from config
    if ([string]::IsNullOrEmpty($JsonFile)) {
        $JsonFile = $Config.SnapshotJsonPath
    }
    
    Write-Host "Rebuilding shortcuts from JSON: $JsonFile" -ForegroundColor Cyan
    if ($WhatIfPreference -or $DetailedWhatIf) {
        Write-Host "Running in DetailedWhatIf mode - no changes will be made" -ForegroundColor Yellow
    }
    
    # Check if JSON file exists
    if (-not (Test-Path -Path $JsonFile)) {
        Write-Error "JSON file not found: $JsonFile"
        return $false
    }
    
    # Read the JSON file
    try {
        $snapshotData = Get-Content -Path $JsonFile -Raw | ConvertFrom-Json
    }
    catch {
        Write-Error "Error reading JSON file: $_"
        return $false
    }
    
    # Initialize counters
    $totalApps = 0
    $processedApps = 0
    $createdShortcuts = 0
    $skippedShortcuts = 0
    $errorShortcuts = 0
    
    # Process apps from JSON
    Write-Host "Processing applications from snapshot..." -ForegroundColor Cyan
    
    # Handle different JSON structures - check if we have a newer format with metadata
    if ($snapshotData.Apps) {
        $apps = $snapshotData.Apps
    }
    else {
        # Assume older format where the whole object is the apps collection
        $apps = $snapshotData
    }
    
    # Count total apps
    foreach ($hash in $apps.PSObject.Properties.Name) {
        $totalApps += $apps.$hash.Count
    }
    
    Write-Host "Found $totalApps applications in snapshot" -ForegroundColor Cyan
    
    # Process each app
    foreach ($hash in $apps.PSObject.Properties.Name) {
        $appGroup = $apps.$hash
        
        foreach ($app in $appGroup) {
            $processedApps++
            
            # Skip if no rebuild info
            if (-not ($app.RebuildLnk -or $app.CustomLnk)) {
                $skippedShortcuts++
                continue
            }
            
            # Determine target information
            $targetPath = $app.Path
            if (-not $targetPath -and $app.InstallLocation) {
                # Try to find an executable in the install location
                $possibleExe = Get-ChildItem -Path $app.InstallLocation -Filter "*.exe" -Recurse -Depth 1 -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($possibleExe) {
                    $targetPath = $possibleExe.FullName
                }
            }
            
            if (-not $targetPath) {
                Write-Host "Skipping app $($app.DisplayName): No target path found" -ForegroundColor Yellow
                $skippedShortcuts++
                continue
            }
            
            # Determine shortcut path
            $shortcutName = $app.FileName -replace '\.exe$', '.lnk'
            if (-not $shortcutName) {
                $shortcutName = "$($app.DisplayName).lnk"
            }
            
            $shortcutFolder = $Config.RebuildSettings.DefaultTargetFolder
            if ($app.ShortcutLocation) {
                $shortcutFolder = $app.ShortcutLocation
            }
            
            $shortcutPath = Join-Path -Path $shortcutFolder -ChildPath $shortcutName
            
            # In DetailedWhatIf mode, provide more information
            if ($DetailedWhatIf) {
                Write-Host "Would create shortcut for $($app.DisplayName)" -ForegroundColor Cyan
                Write-Host "  Target: $targetPath" -ForegroundColor DarkGray
                Write-Host "  Shortcut: $shortcutPath" -ForegroundColor DarkGray
                if ((Test-Path -Path $shortcutPath) -and $Config.RebuildSettings.CreateBackups) {
                    Write-Host "  Would backup existing shortcut" -ForegroundColor DarkGray
                }
                $createdShortcuts++
                continue
            }
            
            # Backup existing shortcuts if enabled
            if ($Config.RebuildSettings.CreateBackups -and (Test-Path -Path $shortcutPath)) {
                # Use ShouldProcess for standard DetailedWhatIf behavior
                if ($PSCmdlet.ShouldProcess("$shortcutPath", "Backup shortcut")) {
                    Backup-Shortcut -ShortcutPath $shortcutPath -BackupFolder $Config.RebuildSettings.BackupFolder
                }
            }
            
            # Create the shortcut
            $shortcutParams = @{
                TargetPath = $targetPath
                ShortcutPath = $shortcutPath
                Force = $Config.RebuildSettings.OverwriteExisting
            }
            
            if ($app.Arguments) {
                $shortcutParams['Arguments'] = $app.Arguments
            }
            
            if ($app.WorkingDirectory) {
                $shortcutParams['WorkingDirectory'] = $app.WorkingDirectory
            }
            
            if ($app.Description) {
                $shortcutParams['Description'] = $app.Description
            }
            elseif ($app.DisplayName) {
                $shortcutParams['Description'] = $app.DisplayName
            }
            
            if ($app.IconLocation) {
                $shortcutParams['IconLocation'] = $app.IconLocation
                
                if ($app.IconIndex -ne $null) {
                    $shortcutParams['IconIndex'] = $app.IconIndex
                }
            }
            
            # Use ShouldProcess for PowerShell standard DetailedWhatIf behavior
            if ($PSCmdlet.ShouldProcess("$shortcutPath", "Create shortcut")) {
                $result = New-Shortcut @shortcutParams
                
                if ($result) {
                    $createdShortcuts++
                }
                else {
                    $errorShortcuts++
                }
            }
            else {
                # This branch is taken when using the standard -WhatIf parameter
                $createdShortcuts++
            }
            
            # Show progress
            Write-Progress -Activity "Rebuilding Shortcuts" -Status "Processed $processedApps of $totalApps" -PercentComplete (($processedApps / $totalApps) * 100)
        }
    }
    
    Write-Progress -Activity "Rebuilding Shortcuts" -Completed
    
    # Report results
    if ($WhatIfPreference -or $DetailedWhatIf) {
        Write-Host "WhatIf Shortcut Rebuild Summary (no changes were made):" -ForegroundColor Green
    }
    else {
        Write-Host "Shortcut Rebuild Complete" -ForegroundColor Green
    }
    Write-Host "Processed: $processedApps applications" -ForegroundColor Cyan
    Write-Host "Would create/Created: $createdShortcuts shortcuts" -ForegroundColor Green
    Write-Host "Skipped: $skippedShortcuts shortcuts" -ForegroundColor Yellow
    if (-not ($WhatIfPreference -or $DetailedWhatIf)) {
        Write-Host "Errors: $errorShortcuts shortcuts" -ForegroundColor Red
    }
    
    return $true
}

#endregion

# Export functions
Export-ModuleMember -Function 'New-Shortcut', 'Backup-Shortcut', 'Get-ShortcutManagerConfig', 
                              'Export-ShortcutManagerConfig', 'New-ShortcutSnapshot', 
                              'Rebuild-ShortcutsFromSnapshot'