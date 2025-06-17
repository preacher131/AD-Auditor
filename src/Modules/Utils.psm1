# Utils.psm1 - Shared utility functions for AD entitlement review
# Provides common helpers without AD dependencies to avoid circular references

#region Module Variables
$script:LogLevels = @{
    'Error' = 0
    'Warning' = 1
    'Info' = 2
    'Debug' = 3
    'Verbose' = 4
}

$script:CurrentLogLevel = 'Info'
#endregion

#region Public Functions

<#
.SYNOPSIS
    Generates a new GUID for ReviewPackageId correlation
.DESCRIPTION
    Creates a new GUID that can be used to correlate packages and members across datasets
.OUTPUTS
    [System.Guid] - A new GUID
.EXAMPLE
    $packageId = New-ReviewPackageId
#>
function New-ReviewPackageId {
    [CmdletBinding()]
    [OutputType([System.Guid])]
    param()
    
    return [System.Guid]::NewGuid()
}

<#
.SYNOPSIS
    Tests if a group name follows logical group naming conventions with suffixes
.DESCRIPTION
    Checks if a group name contains recognized suffixes that indicate logical access levels
.PARAMETER GroupName
    The AD group name to test
.PARAMETER GroupingMap
    Optional hashtable of suffix to access level mappings from configuration. If not provided, uses common patterns
.OUTPUTS
    [System.Boolean] - True if group appears to be a logical group with suffix
.EXAMPLE
    Test-IsLogicalGroup -GroupName "Finance-Payroll-ro"
    Test-IsLogicalGroup -GroupName "HR-Benefits-ch" -GroupingMap $group.Logical.grouping
#>
function Test-IsLogicalGroup {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$GroupingMap
    )
    
    if ([string]::IsNullOrWhiteSpace($GroupName)) {
        return $false
    }
    
    # Default common suffixes if none provided
    $defaultSuffixes = @('-ro', '-ch', '-rw', '-r', '-fc', '-admin', '-mgr', '-read', '-write', '-modify', '-full')
    
    if ($GroupingMap -and $GroupingMap.Count -gt 0) {
        $suffixesToCheck = $GroupingMap.Keys
    } else {
        $suffixesToCheck = $defaultSuffixes
    }
    
    foreach ($suffix in $suffixesToCheck) {
        if ($GroupName -match "$([regex]::Escape($suffix))$") {
            Write-Log -Message "Group '$GroupName' matches logical suffix '$suffix'" -Level 'Debug'
            return $true
        }
    }
    
    return $false
}

<#
.SYNOPSIS
    Maps a group suffix to its corresponding access level label
.DESCRIPTION
    Takes a group name or suffix and returns the human-readable access level from configuration
.PARAMETER GroupName
    The full group name to analyze
.PARAMETER Suffix
    The specific suffix to look up (alternative to GroupName)
.PARAMETER GroupingMap
    The hashtable mapping suffixes to access levels
.OUTPUTS
    [System.String] - The access level label, or empty string if no mapping found
.EXAMPLE
    Get-LogicalAccessLabel -GroupName "Finance-Payroll-ro" -GroupingMap $group.Logical.grouping
    Get-LogicalAccessLabel -Suffix "-ch" -GroupingMap $group.Logical.grouping
#>
function Get-LogicalAccessLabel {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'ByGroupName')]
        [string]$GroupName,
        
        [Parameter(Mandatory = $false, ParameterSetName = 'BySuffix')]
        [string]$Suffix,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$GroupingMap
    )
    
    # Return empty string if no grouping map provided
    if (-not $GroupingMap -or $GroupingMap.Count -eq 0) {
        return ""
    }
    
    $targetSuffix = $null
    
    if ($PSCmdlet.ParameterSetName -eq 'ByGroupName') {
        if ([string]::IsNullOrWhiteSpace($GroupName)) {
            return ""
        }
        
        # Extract suffix from group name using the grouping map keys
        foreach ($suffix in $GroupingMap.Keys) {
            if ($GroupName -match "$([regex]::Escape($suffix))$") {
                $targetSuffix = $suffix
                break
            }
        }
    } else {
        $targetSuffix = $Suffix
    }
    
    if ([string]::IsNullOrWhiteSpace($targetSuffix)) {
        Write-Log -Message "No suffix found for group '$GroupName'" -Level 'Debug'
        return ""
    }
    
    # Look up access level in grouping map
    if ($GroupingMap.ContainsKey($targetSuffix)) {
        $accessLevel = $GroupingMap[$targetSuffix]
        Write-Log -Message "Found access level '$accessLevel' for suffix '$targetSuffix'" -Level 'Debug'
        return $accessLevel
    }
    
    Write-Log -Message "No access level mapping found for suffix '$targetSuffix', returning empty string" -Level 'Debug'
    return ""
}

<#
.SYNOPSIS
    Parses owner information from group info/description fields using regex patterns
.DESCRIPTION
    Extracts primary and secondary owner email addresses from AD group info fields using configurable regex patterns
.PARAMETER InfoText
    The text content from the group's info/description field
.PARAMETER OwnerRegexPatterns
    Array of regex pattern objects from configuration
.OUTPUTS
    [System.Collections.Hashtable] - Hash table with PrimaryOwner and SecondaryOwner keys
.EXAMPLE
    $owners = Parse-Owners -InfoText "Primary Owner: john.doe@contoso.com Secondary Owner: jane.smith@contoso.com" -OwnerRegexPatterns $config.ownerRegexPatterns
#>
function Parse-Owners {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$InfoText,
        
        [Parameter(Mandatory = $true)]
        [array]$OwnerRegexPatterns
    )
    
    $result = @{
        PrimaryOwner = $null
        SecondaryOwner = $null
    }
    
    if ([string]::IsNullOrWhiteSpace($InfoText)) {
        Write-Log -Message "No info text provided for owner parsing" -Level 'Debug'
        return $result
    }
    
    Write-Log -Message "Parsing owners from info text: $($InfoText.Substring(0, [Math]::Min(100, $InfoText.Length)))" -Level 'Debug'
    
    foreach ($pattern in $OwnerRegexPatterns) {
        if (-not $pattern.pattern) {
            Write-Log -Message "Skipping pattern with no regex defined" -Level 'Warning'
            continue
        }
        
        try {
            $match = [regex]::Match($InfoText, $pattern.pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            
            if ($match.Success) {
                $captureGroup = if ($pattern.captureGroup) { $pattern.captureGroup } else { 1 }
                
                if ($match.Groups.Count -gt $captureGroup) {
                    $extractedValue = $match.Groups[$captureGroup].Value.Trim()
                    
                    # Determine owner type based on pattern name
                    switch -Regex ($pattern.name) {
                        'Primary.*Owner' {
                            if (-not $result.PrimaryOwner) {
                                $result.PrimaryOwner = $extractedValue
                                Write-Log -Message "Found primary owner: $extractedValue" -Level 'Debug'
                            }
                        }
                        'Secondary.*Owner' {
                            if (-not $result.SecondaryOwner) {
                                $result.SecondaryOwner = $extractedValue
                                Write-Log -Message "Found secondary owner: $extractedValue" -Level 'Debug'
                            }
                        }
                        'Owner.*Generic|Contact' {
                            # Use as primary if not already set
                            if (-not $result.PrimaryOwner) {
                                $result.PrimaryOwner = $extractedValue
                                Write-Log -Message "Found generic owner (using as primary): $extractedValue" -Level 'Debug'
                            }
                        }
                        default {
                            # Default to primary if pattern type unclear
                            if (-not $result.PrimaryOwner) {
                                $result.PrimaryOwner = $extractedValue
                                Write-Log -Message "Found owner (pattern: $($pattern.name)): $extractedValue" -Level 'Debug'
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-Log -Message "Error processing regex pattern '$($pattern.name)': $($_.Exception.Message)" -Level 'Warning'
        }
    }
    
    return $result
}

<#
.SYNOPSIS
    Writes log messages with level-aware filtering
.DESCRIPTION
    Centralized logging function that respects log level settings and provides consistent formatting
.PARAMETER Message
    The message to log
.PARAMETER Level
    The log level (Error, Warning, Info, Debug, Verbose)
.PARAMETER Exception
    Optional exception object to include in error logs
.EXAMPLE
    Write-Log -Message "Processing group: Finance-Payroll" -Level 'Info'
    Write-Log -Message "Failed to connect to AD" -Level 'Error' -Exception $_.Exception
#>
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Error', 'Warning', 'Info', 'Debug', 'Verbose')]
        [string]$Level = 'Info',
        
        [Parameter(Mandatory = $false)]
        [System.Exception]$Exception
    )
    
    # Check if we should log this level
    $currentLevelValue = $script:LogLevels[$script:CurrentLogLevel]
    $messageLevelValue = $script:LogLevels[$Level]
    
    if ($messageLevelValue -gt $currentLevelValue) {
        return
    }
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    
    if ($Exception) {
        $logMessage += " | Exception: $($Exception.Message)"
        if ($Exception.InnerException) {
            $logMessage += " | Inner: $($Exception.InnerException.Message)"
        }
    }
    
    # Output to appropriate stream based on level
    switch ($Level) {
        'Error' {
            Write-Error $logMessage
        }
        'Warning' {
            Write-Warning $logMessage
        }
        'Debug' {
            Write-Debug $logMessage
        }
        'Verbose' {
            Write-Verbose $logMessage
        }
        default {
            Write-Host $logMessage
        }
    }
}

<#
.SYNOPSIS
    Sets the current log level for the module
.DESCRIPTION
    Configures the minimum log level that will be output by Write-Log
.PARAMETER Level
    The minimum log level to output
.EXAMPLE
    Set-LogLevel -Level 'Debug'
#>
function Set-LogLevel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Error', 'Warning', 'Info', 'Debug', 'Verbose')]
        [string]$Level
    )
    
    $script:CurrentLogLevel = $Level
    Write-Log -Message "Log level set to: $Level" -Level 'Info'
}

<#
.SYNOPSIS
    Gets the base name of a logical group by removing known suffixes
.DESCRIPTION
    Helper function to extract the base group name for logical grouping correlation
.PARAMETER GroupName
    The full group name
.PARAMETER GroupingMap
    Optional hashtable of suffix to access level mappings from configuration
.OUTPUTS
    [System.String] - The base group name without suffix
.EXAMPLE
    Get-LogicalGroupBaseName -GroupName "Finance-Payroll-ro"
    Get-LogicalGroupBaseName -GroupName "Finance-Payroll-ro" -GroupingMap $group.Logical.grouping
#>
function Get-LogicalGroupBaseName {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$GroupingMap
    )
    
    if ([string]::IsNullOrWhiteSpace($GroupName)) {
        return $GroupName
    }
    
    # Default common suffixes if none provided
    $defaultSuffixes = @('-ro', '-ch', '-rw', '-r', '-fc', '-admin', '-mgr', '-read', '-write', '-modify', '-full')
    
    if ($GroupingMap -and $GroupingMap.Count -gt 0) {
        $suffixesToCheck = $GroupingMap.Keys
    } else {
        $suffixesToCheck = $defaultSuffixes
    }
    
    # Sort by length descending to match longest suffix first
    $suffixesToCheck = $suffixesToCheck | Sort-Object Length -Descending
    
    foreach ($suffix in $suffixesToCheck) {
        if ($GroupName -match "$([regex]::Escape($suffix))$") {
            $baseName = $GroupName -replace "$([regex]::Escape($suffix))$", ""
            Write-Log -Message "Extracted base name '$baseName' from '$GroupName' (removed suffix '$suffix')" -Level 'Debug'
            return $baseName
        }
    }
    
    # No suffix found, return original name
    return $GroupName
}

#endregion

#region Module Exports
Export-ModuleMember -Function @(
    'New-ReviewPackageId',
    'Test-IsLogicalGroup', 
    'Get-LogicalAccessLabel',
    'Parse-Owners',
    'Write-Log',
    'Set-LogLevel',
    'Get-LogicalGroupBaseName'
)
#endregion
