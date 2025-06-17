#Requires -Modules ActiveDirectory
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ReviewID,
    
    [Parameter(Mandatory=$false)]
    [switch]$GroupsOnly,
    
    [Parameter(Mandatory=$false)]
    [switch]$PrivilegeOnly
)

# Import required modules and functions
$ErrorActionPreference = "Stop"
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$configPath = Join-Path $scriptPath "..\configs"

# Load configuration files
$config = Get-Content (Join-Path $configPath "config.json") | ConvertFrom-Json
$groupsConfig = Get-Content (Join-Path $configPath "groups.json") | ConvertFrom-Json
$privilegeConfig = Get-Content (Join-Path $configPath "privilege.json") | ConvertFrom-Json

# Function to establish AD connection
function Connect-AD {
    $server = $config.DomainController
    
    # Build server string based on LDAPS/LDAP
    if ($config.Connection.UseLDAPS) {
        $server = "$server:636"
    }
    
    # Handle credentials
    if ($config.Connection.UseCurrentUser) {
        Write-Verbose "Using current user credentials"
        $credential = $null
    } else {
        Write-Verbose "Using specified credentials"
        $securePassword = ConvertTo-SecureString $config.Connection.CredentialProfile.Password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential(
            "$($config.Connection.CredentialProfile.Domain)\$($config.Connection.CredentialProfile.Username)",
            $securePassword
        )
    }
    
    # Set AD connection parameters
    $adParams = @{ Server = $server }
    if ($credential) {
        $adParams.Credential = $credential
    }
    
    # Test connection
    try {
        $testConnection = Get-ADDomain @adParams
        Write-Verbose "Successfully connected to $server"
        return $adParams
    }
    catch {
        Write-Error "Failed to connect to $server : $_"
        exit 1
    }
}

# Initialize output arrays
$packages1 = @()
$packageMembers1 = @()
$packages2 = @()
$privilegeGroups = @()

# Function to extract owner names using regex patterns
function Get-OwnerNames {
    param(
        [string]$Info,
        [hashtable]$ADParams
    )
    
    $primaryOwner = $null
    $secondaryOwner = $null
    
    # Regex patterns for different name formats
    $patterns = @(
        "Primary:\s*([A-Za-z]+)\s+([A-Za-z]+)",
        "P:\s*([A-Za-z]+)\s+([A-Za-z]+)",
        "Primary Owner:\s*([A-Za-z]+)\s+([A-Za-z]+)",
        "Secondary:\s*([A-Za-z]+)\s+([A-Za-z]+)",
        "S:\s*([A-Za-z]+)\s+([A-Za-z]+)",
        "Secondary Owner:\s*([A-Za-z]+)\s+([A-Za-z]+)"
    )
    
    foreach ($pattern in $patterns) {
        if ($Info -match $pattern) {
            $firstName = $matches[1]
            $lastName = $matches[2]
            
            # Search AD for matching user
            $users = Get-ADUser -Filter "Surname -eq '$lastName'" -Properties mail @ADParams
            $user = $users | Where-Object { $_.GivenName -eq $firstName } | Select-Object -First 1
            
            if ($user) {
                if ($pattern -match "Primary|P:") {
                    $primaryOwner = $user.mail
                }
                elseif ($pattern -match "Secondary|S:") {
                    $secondaryOwner = $user.mail
                }
            }
        }
    }
    
    return @{
        PrimaryOwner = $primaryOwner
        SecondaryOwner = $secondaryOwner
    }
}

# Function to process logical groups
function Get-LogicalGroupInfo {
    param(
        [string]$GroupName,
        [hashtable]$LogicalGrouping
    )
    
    foreach ($suffix in $LogicalGrouping.Keys) {
        if ($GroupName -like "*$suffix") {
            return @{
                BaseName = $GroupName -replace "$suffix$"
                Access = $LogicalGrouping[$suffix]
            }
        }
    }
    return $null
}

# Function to generate a deterministic GUID
function Get-DeterministicGuid {
    param(
        [string]$InputString
    )
    
    # Create a deterministic hash from the input string
    $hash = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $hash.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($InputString))
    
    # Create a new GUID using the hash bytes
    $guid = [System.Guid]::new($hashBytes)
    return $guid
}

# Function to process groups
function Process-Groups {
    param(
        [hashtable]$ADParams
    )
    
    foreach ($groupConfig in $groupsConfig.groups) {
        $groups = Get-ADGroup -Filter * -SearchBase $groupConfig.path -Properties Description, info, member @ADParams
        
        foreach ($group in $groups) {
            $logicalInfo = $null
            if ($groupConfig.Logical.isLogical) {
                $logicalInfo = Get-LogicalGroupInfo -GroupName $group.Name -LogicalGrouping $groupConfig.Logical.grouping
            }
            
            $owners = Get-OwnerNames -Info $group.info -ADParams $ADParams
            
            # Generate a deterministic GUID for this group
            $baseName = if ($logicalInfo) { $logicalInfo.BaseName } else { $group.Name }
            $reviewPackageID = Get-DeterministicGuid -InputString "$baseName|$ReviewID|$($group.ObjectGUID)"
            
            $package = [PSCustomObject]@{
                ReviewID = $ReviewID
                GroupID = $group.ObjectGUID
                ReviewPackageID = $reviewPackageID
                GroupName = $baseName
                PrimaryOwnerEmail = $owners.PrimaryOwner
                SecondaryOwnerEmail = $owners.SecondaryOwner
                OUPath = $groupConfig.path
                Tag = $groupConfig.category
                Description = $group.Description
                LogicalGrouping = $groupConfig.Logical.isLogical
                LogicalAccess = if ($logicalInfo) { $logicalInfo.Access } else { "" }
            }
            
            $packages1 += $package
            
            # Process group members
            $members = Get-ADGroupMember -Identity $group -Recursive @ADParams
            foreach ($member in $members) {
                if ($member.objectClass -eq "user") {
                    $user = Get-ADUser -Identity $member.distinguishedName -Properties Department, Title, Manager @ADParams
                    $manager = if ($user.Manager) { Get-ADUser -Identity $user.Manager -Properties DisplayName, mail @ADParams } else { $null }
                    
                    $memberObj = [PSCustomObject]@{
                        FirstName = $user.GivenName
                        LastName = $user.Surname
                        Email = $user.mail
                        UserID = $user.ObjectGUID
                        Username = "$($user.GivenName) $($user.Surname)"
                        Department = $user.Department
                        JobTitle = $user.Title
                        ManagerName = if ($manager) { "$($manager.GivenName) $($manager.Surname)" } else { "" }
                        ManagerEmail = if ($manager) { $manager.mail } else { "" }
                        ReviewPackageID = $reviewPackageID
                        DerivedGroup = $group.Name
                        LogicalAccess = if ($logicalInfo) { $logicalInfo.Access } else { "" }
                    }
                    
                    $packageMembers1 += $memberObj
                }
            }
        }
    }
}

# Function to process privilege
function Process-Privilege {
    param(
        [hashtable]$ADParams
    )
    
    foreach ($ouPath in $privilegeConfig.ouPaths) {
        $users = Get-ADUser -Filter * -SearchBase $ouPath -Properties memberOf @ADParams
        
        foreach ($user in $users) {
            # Generate a deterministic GUID for this user
            $reviewPackageID = Get-DeterministicGuid -InputString "$($user.SamAccountName)|$ReviewID|$($user.ObjectGUID)"
            
            $package = [PSCustomObject]@{
                ReviewID = $ReviewID
                GroupID = $user.ObjectGUID
                GroupName = $user.DisplayName
                OUPath = $ouPath
                ReviewPackageID = $reviewPackageID
            }
            
            $packages2 += $package
            
            # Process user's group memberships
            foreach ($groupDN in $user.memberOf) {
                if ($groupDN -notin $privilegeConfig.exclude) {
                    $group = Get-ADGroup -Identity $groupDN -Properties Description @ADParams
                    
                    $privilegeGroup = [PSCustomObject]@{
                        GroupName = $group.Name
                        GroupID = $group.ObjectGUID
                        ReviewPackageID = $reviewPackageID
                        Description = $group.Description
                    }
                    
                    $privilegeGroups += $privilegeGroup
                }
            }
        }
    }
}

# Main execution
try {
    # Establish AD connection
    $adParams = Connect-AD
    
    if (-not $PrivilegeOnly) {
        Process-Groups -ADParams $adParams
    }
    
    if (-not $GroupsOnly) {
        Process-Privilege -ADParams $adParams
    }
    
    # Export to CSV
    $outputPath = Join-Path $scriptPath "..\output"
    if (-not (Test-Path $outputPath)) {
        New-Item -ItemType Directory -Path $outputPath | Out-Null
    }
    
    # Replace {ReviewId} in filenames
    $packages1File = $config.OutputFiles.Packages1 -replace '{ReviewId}', $ReviewID
    $packageMembers1File = $config.OutputFiles.PackageMembers1 -replace '{ReviewId}', $ReviewID
    $packages2File = $config.OutputFiles.Packages2 -replace '{ReviewId}', $ReviewID
    $privilegeGroupsFile = $config.OutputFiles.PrivilegeGroups -replace '{ReviewId}', $ReviewID
    
    $packages1 | Export-Csv -Path (Join-Path $outputPath $packages1File) -NoTypeInformation
    $packageMembers1 | Export-Csv -Path (Join-Path $outputPath $packageMembers1File) -NoTypeInformation
    $packages2 | Export-Csv -Path (Join-Path $outputPath $packages2File) -NoTypeInformation
    $privilegeGroups | Export-Csv -Path (Join-Path $outputPath $privilegeGroupsFile) -NoTypeInformation
    
    Write-Host "Processing completed successfully. Output files have been created in the output directory:"
    Write-Host "  - $packages1File"
    Write-Host "  - $packageMembers1File"
    Write-Host "  - $packages2File"
    Write-Host "  - $privilegeGroupsFile"
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
} 