# Config.psm1 - Configuration management module for AD Entitlement Review

#region Private Functions

function Resolve-PathRelative {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )
    
    try {
        # Get the directory where this module is located
        $moduleDir = Split-Path -Parent $PSScriptRoot
        
        # Resolve the relative path from the module's parent directory
        $fullPath = Join-Path -Path $moduleDir -ChildPath $RelativePath
        
        # Convert to absolute path
        $resolvedPath = [System.IO.Path]::GetFullPath($fullPath)
        
        return $resolvedPath
    }
    catch {
        throw "Failed to resolve relative path '$RelativePath': $($_.Exception.Message)"
    }
}

function Test-ConfigFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $true)]
        [string]$ConfigType
    )
    
    if (-not (Test-Path -Path $FilePath)) {
        throw "Configuration file not found: $FilePath. Please ensure the $ConfigType configuration file exists."
    }
    
    try {
        $content = Get-Content -Path $FilePath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($content)) {
            throw "Configuration file is empty: $FilePath"
        }
    }
    catch {
        throw "Failed to read configuration file '$FilePath': $($_.Exception.Message)"
    }
}

function ConvertFrom-JsonSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$JsonContent,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        return $JsonContent | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Invalid JSON format in configuration file '$FilePath': $($_.Exception.Message)"
    }
}

function Validate-ConfigKeys {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Config,
        
        [Parameter(Mandatory = $true)]
        [string[]]$RequiredKeys,
        
        [Parameter(Mandatory = $true)]
        [string]$ConfigType
    )
    
    $missingKeys = @()
    
    foreach ($key in $RequiredKeys) {
        if (-not $Config.PSObject.Properties.Name -contains $key) {
            $missingKeys += $key
        }
    }
    
    if ($missingKeys.Count -gt 0) {
        throw "Missing required keys in $ConfigType configuration: $($missingKeys -join ', ')"
    }
}

#endregion

#region Public Functions

function Get-Config {
    <#
    .SYNOPSIS
        Loads the main configuration file for the AD Entitlement Review system.
    
    .DESCRIPTION
        Reads the config.json file and returns a strongly-typed configuration object
        with properties like OutputFolder, LogLevel, DomainController, etc.
    
    .EXAMPLE
        $config = Get-Config
        Write-Host "Output folder: $($config.OutputFolder)"
    
    .OUTPUTS
        PSCustomObject with configuration properties
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Resolve path to config.json
        $configPath = Resolve-PathRelative -RelativePath "configs/config.json"
        
        # Test if file exists and is readable
        Test-ConfigFile -FilePath $configPath -ConfigType "main"
        
        # Read and parse JSON
        $jsonContent = Get-Content -Path $configPath -Raw -ErrorAction Stop
        $configObject = ConvertFrom-JsonSafe -JsonContent $jsonContent -FilePath $configPath
        
        # Define required keys for main configuration
        $requiredKeys = @('DomainController', 'OutputFolder', 'LogLevel')
        
        # Validate required keys exist
        Validate-ConfigKeys -Config $configObject -RequiredKeys $requiredKeys -ConfigType "main"
        
        # Create strongly-typed configuration object
        $config = [PSCustomObject]@{
            DomainController = [string]$configObject.DomainController
            OutputFolder = [string]$configObject.OutputFolder
            LogLevel = [string]$configObject.LogLevel
            DefaultCredentialProfile = if ($configObject.PSObject.Properties.Name -contains 'DefaultCredentialProfile') { 
                [string]$configObject.DefaultCredentialProfile 
            } else { 
                [string]::Empty 
            }
        }
        
        # Validate LogLevel is valid
        $validLogLevels = @('Error', 'Warning', 'Info', 'Debug', 'Verbose')
        if ($config.LogLevel -notin $validLogLevels) {
            throw "Invalid LogLevel '$($config.LogLevel)'. Valid values are: $($validLogLevels -join ', ')"
        }
        
        Write-Verbose "Successfully loaded main configuration from: $configPath"
        return $config
    }
    catch {
        throw "Failed to load main configuration: $($_.Exception.Message)"
    }
}

function Get-GroupsDefinition {
    <#
    .SYNOPSIS
        Loads the groups configuration file for the AD Entitlement Review system.
    
    .DESCRIPTION
        Reads the groups.json file and returns the groups definition object
        containing organizational units, logical groupings, and processing options.
    
    .EXAMPLE
        $groupsConfig = Get-GroupsDefinition
        foreach ($ou in $groupsConfig.organizationalUnits) {
            Write-Host "Processing OU: $($ou.name) at $($ou.path)"
        }
    
    .OUTPUTS
        PSCustomObject with groups configuration properties
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Resolve path to groups.json
        $groupsPath = Resolve-PathRelative -RelativePath "configs/groups.json"
        
        # Test if file exists and is readable
        Test-ConfigFile -FilePath $groupsPath -ConfigType "groups"
        
        # Read and parse JSON
        $jsonContent = Get-Content -Path $groupsPath -Raw -ErrorAction Stop
        $groupsObject = ConvertFrom-JsonSafe -JsonContent $jsonContent -FilePath $groupsPath
        
        # Define required keys for groups configuration
        $requiredKeys = @('groups', 'ownerRegexPatterns')
        
        # Validate required keys exist
        Validate-ConfigKeys -Config $groupsObject -RequiredKeys $requiredKeys -ConfigType "groups"
        
        # Validate groups structure
        if (-not $groupsObject.groups -or $groupsObject.groups -isnot [System.Array]) {
            throw "Groups configuration must contain a 'groups' array"
        }
        
        if ($groupsObject.groups.Count -eq 0) {
            throw "Groups configuration must contain at least one group"
        }
        
        foreach ($g in $groupsObject.groups) {
            # Validate required keys for each group
            if (-not $g.path -or -not $g.category -or -not $g.Logical) {
                throw "Each group must have 'path', 'category', and 'Logical' properties"
            }
            
            # Validate Logical object structure
            if (-not $g.Logical.PSObject.Properties.Name -contains 'isLogical') {
                throw "Each group's 'Logical' object must have an 'isLogical' boolean property"
            }
            
            if ($g.Logical.isLogical -isnot [bool]) {
                throw "Each group's 'Logical.isLogical' property must be a boolean"
            }
            
            if (-not $g.Logical.PSObject.Properties.Name -contains 'grouping') {
                throw "Each group's 'Logical' object must have a 'grouping' property"
            }
            
            if ($g.Logical.grouping -isnot [PSCustomObject] -and $g.Logical.grouping -isnot [hashtable]) {
                throw "Each group's 'Logical.grouping' property must be a hashtable or object"
            }
            
            # If isLogical is true, ensure grouping has at least one entry
            if ($g.Logical.isLogical -eq $true) {
                $groupingCount = 0
                if ($g.Logical.grouping -is [PSCustomObject]) {
                    $groupingCount = ($g.Logical.grouping.PSObject.Properties | Measure-Object).Count
                } elseif ($g.Logical.grouping -is [hashtable]) {
                    $groupingCount = $g.Logical.grouping.Count
                }
                
                if ($groupingCount -eq 0) {
                    throw "Groups with 'isLogical' set to true must have at least one entry in their 'grouping' object"
                }
            }
        }
        
        # Validate owner regex patterns structure
        if ($groupsObject.ownerRegexPatterns -and $groupsObject.ownerRegexPatterns.Count -gt 0) {
            foreach ($pattern in $groupsObject.ownerRegexPatterns) {
                if (-not $pattern.name -or -not $pattern.pattern) {
                    throw "Each owner regex pattern must have 'name' and 'pattern' properties"
                }
            }
        }
        
        Write-Verbose "Successfully loaded groups configuration from: $groupsPath"
        return $groupsObject
    }
    catch {
        throw "Failed to load groups configuration: $($_.Exception.Message)"
    }
}

function Get-PrivilegeDefinition {
    <#
    .SYNOPSIS
        Loads the privilege configuration file for the AD Entitlement Review system.
    
    .DESCRIPTION
        Reads the privilege.json file and returns the privilege definition object
        containing OU paths, exclusion lists, and user attributes to process.
    
    .EXAMPLE
        $privilegeConfig = Get-PrivilegeDefinition
        foreach ($ouPath in $privilegeConfig.ouPaths) {
            Write-Host "Processing users in OU: $ouPath"
        }
    
    .OUTPUTS
        PSCustomObject with privilege configuration properties
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Resolve path to privilege.json
        $privilegePath = Resolve-PathRelative -RelativePath "configs/privilege.json"
        
        # Test if file exists and is readable
        Test-ConfigFile -FilePath $privilegePath -ConfigType "privilege"
        
        # Read and parse JSON
        $jsonContent = Get-Content -Path $privilegePath -Raw -ErrorAction Stop
        $privilegeObject = ConvertFrom-JsonSafe -JsonContent $jsonContent -FilePath $privilegePath
        
        # Define required keys for privilege configuration
        $requiredKeys = @('ouPaths', 'exclude', 'userAttributes')
        
        # Validate required keys exist
        Validate-ConfigKeys -Config $privilegeObject -RequiredKeys $requiredKeys -ConfigType "privilege"
        
        # Validate OU paths structure
        if (-not $privilegeObject.ouPaths -or $privilegeObject.ouPaths.Count -eq 0) {
            throw "Privilege configuration must contain at least one OU path"
        }
        
        foreach ($ouPath in $privilegeObject.ouPaths) {
            if ([string]::IsNullOrWhiteSpace($ouPath)) {
                throw "OU paths cannot be null or empty"
            }
        }
        
        # Validate user attributes structure
        if (-not $privilegeObject.userAttributes -or $privilegeObject.userAttributes.Count -eq 0) {
            throw "Privilege configuration must specify at least one user attribute"
        }
        
        # Ensure exclude is an array (can be empty)
        if (-not $privilegeObject.exclude) {
            $privilegeObject | Add-Member -NotePropertyName 'exclude' -NotePropertyValue @() -Force
        }
        
        Write-Verbose "Successfully loaded privilege configuration from: $privilegePath"
        return $privilegeObject
    }
    catch {
        throw "Failed to load privilege configuration: $($_.Exception.Message)"
    }
}

#endregion

#region Module Exports

Export-ModuleMember -Function @(
    'Get-Config',
    'Get-GroupsDefinition', 
    'Get-PrivilegeDefinition'
)

#endregion
