@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'OAShortcutManager.psm1'
    
    # Version number of this module.
    ModuleVersion = '1.0.0'
    
    # ID used to uniquely identify this module
    GUID = '11223344-5566-7788-99aa-bbccddeeff00'  # Generate a new GUID for your module
    
    # Author of this module
    Author = 'Osamah'
    
    # Company or vendor of this module
    CompanyName = 'OAShortcutManager'
    
    # Copyright statement for this module
    Copyright = '(c) 2025 Osamah. All rights reserved.'
    
    # Description of the functionality provided by this module
    Description = 'PowerShell module for managing application shortcuts. Create snapshots of installed applications, and rebuild shortcuts with customizations.'
    
    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'
    
    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry
    FunctionsToExport = @(
        'New-Shortcut',
        'Backup-Shortcut',
        'Get-ShortcutManagerConfig',
        'Export-ShortcutManagerConfig',
        'New-ShortcutSnapshot',
        'Rebuild-ShortcutsFromSnapshot'
    )
    
    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry
    CmdletsToExport = @()
    
    # Variables to export from this module
    VariablesToExport = @()
    
    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry
    AliasesToExport = @()
    
    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @('Shortcuts', 'Management', 'Applications', 'Windows')
            
            # A URL to the license for this module.
            LicenseUri = 'https://github.com/osamah/OAShortcutManager/blob/main/LICENSE'
            
            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/osamah/OAShortcutManager'
            
            # ReleaseNotes of this module
            ReleaseNotes = 'Initial release of OAShortcutManager'
        }
    }
}
