[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ReviewID,
    [Parameter(Mandatory=$false)]
    [switch]$GroupsOnly,
    [Parameter(Mandatory=$false)]
    [switch]$PrivilegeOnly
)

# Import the LDAP helper module
Import-Module "$PSScriptRoot/Modules/LDAP.psm1"

$ErrorActionPreference = "Stop"
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$configPath = Join-Path $scriptPath "..\configs"

# Load configuration files
$config = Get-Content (Join-Path $configPath "config.json") | ConvertFrom-Json
$groupsConfig = Get-Content (Join-Path $configPath "groups.json") | ConvertFrom-Json
$privilegeConfig = Get-Content (Join-Path $configPath "privilege.json") | ConvertFrom-Json

# Debug output for config
Write-Host "Loaded DomainController: '$($config.DomainController)'"
Write-Host "Loaded Connection.Type: '$($config.Connection.Type)'"
Write-Host "Loaded UseLDAPS: '$($config.Connection.UseLDAPS)'"
Write-Host "Loaded UseCurrentUser: '$($config.Connection.UseCurrentUser)'"

# Failsafe for DomainController
if (-not $config.DomainController -or $config.DomainController -eq "") {
    throw "DomainController is not set in configs/config.json! (Current value: '$($config.DomainController)')"
}

# Connection type logic
$connectionType = if ($config.Connection.Type) { $config.Connection.Type.ToUpper() } else { if ($config.Connection.UseLDAPS) { "LDAPS" } else { "LDAP" } }
Write-Host "Using connection type: $connectionType"

# Global variables for connection
$global:ldap = $null
$global:adParams = $null
$global:useADModule = $false

switch ($connectionType) {
    "LDAP" {
        $global:ldap = New-LdapConnection `
            -Server $config.DomainController `
            -UseLDAPS:$false `
            -UseCurrentUser $config.Connection.UseCurrentUser `
            -Username $config.Connection.CredentialProfile.Username `
            -Password $config.Connection.CredentialProfile.Password `
            -Domain $config.Connection.CredentialProfile.Domain
        $global:useADModule = $false
    }
    "LDAPS" {
        $global:ldap = New-LdapConnection `
            -Server $config.DomainController `
            -UseLDAPS:$true `
            -UseCurrentUser $config.Connection.UseCurrentUser `
            -Username $config.Connection.CredentialProfile.Username `
            -Password $config.Connection.CredentialProfile.Password `
            -Domain $config.Connection.CredentialProfile.Domain
        $global:useADModule = $false
    }
    "ACTIVEDIRECTORY" {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
        } catch {
            throw "ActiveDirectory module is not available. Please install RSAT or use LDAP/LDAPS instead."
        }
        
        # Build AD connection parameters
        $global:adParams = @{ Server = $config.DomainController }
        
        if (-not $config.Connection.UseCurrentUser) {
            $securePassword = ConvertTo-SecureString $config.Connection.CredentialProfile.Password -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential(
                "$($config.Connection.CredentialProfile.Domain)\$($config.Connection.CredentialProfile.Username)",
                $securePassword
            )
            $global:adParams.Credential = $credential
        }
        
        # Test connection
        try {
            $testConnection = Get-ADDomain @global:adParams
            Write-Host "Successfully connected to AD using ActiveDirectory module"
        } catch {
            throw "Failed to connect to AD using ActiveDirectory module: $_"
        }
        
        $global:useADModule = $true
    }
    default {
        throw "Connection type '$connectionType' is not supported. Please use 'LDAP', 'LDAPS', or 'ACTIVEDIRECTORY'."
    }
}

# Helper: Generate deterministic GUID (simplified)
function Get-DeterministicGuid {
    param([string]$InputString)
    $hash = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $hash.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($InputString))
    # Take only the first 16 bytes for GUID (SHA256 produces 32 bytes)
    $guidBytes = $hashBytes[0..15]
    $guid = [System.Guid]::new($guidBytes)
    return $guid.ToString()
}

# Helper: Get GUID as string (simplified approach)
function Get-ObjectGuidString {
    param($Object, $IsLdap = $false)
    
    if ($IsLdap) {
        # For LDAP, create a simple hash-based ID from the DN
        $dn = $Object.Attributes["distinguishedName"][0]
        return Get-DeterministicGuid $dn
    } else {
        # For AD module, use the ObjectGUID directly
        return $Object.ObjectGUID.ToString()
    }
}

# Helper: Extract owner names from info and search for email
function Get-OwnerNames {
    param(
        [string]$Info,
        [string]$BaseDN
    )
    $primaryOwner = $null
    $secondaryOwner = $null
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
            
            if ($global:useADModule) {
                $users = Get-ADUser -Filter "Surname -eq '$lastName'" -Properties mail @global:adParams
                $user = $users | Where-Object { $_.GivenName -eq $firstName } | Select-Object -First 1
                if ($user) {
                    if ($pattern -match "Primary|P:") {
                        $primaryOwner = $user.mail
                    } elseif ($pattern -match "Secondary|S:") {
                        $secondaryOwner = $user.mail
                    }
                }
            } else {
                $filter = "(&(objectClass=user)(sn=$lastName))"
                $users = Invoke-LdapSearch -Ldap $global:ldap -BaseDN $BaseDN -Filter $filter -Attributes @("givenName","sn","mail")
                $user = $users | Where-Object { $_.Attributes["givenName"][0] -eq $firstName } | Select-Object -First 1
                if ($user) {
                    if ($pattern -match "Primary|P:") {
                        $primaryOwner = $user.Attributes["mail"][0]
                    } elseif ($pattern -match "Secondary|S:") {
                        $secondaryOwner = $user.Attributes["mail"][0]
                    }
                }
            }
        }
    }
    return @{ PrimaryOwner = $primaryOwner; SecondaryOwner = $secondaryOwner }
}

# Output arrays
$packages1 = @()
$packageMembers1 = @()
$packages2 = @()
$privilegeGroups = @()

# Process Groups
function Process-Groups {
    foreach ($groupConfig in $groupsConfig.groups) {
        $baseDN = $groupConfig.path
        
        if ($global:useADModule) {
            $groups = Get-ADGroup -Filter * -SearchBase $baseDN -Properties Description, info, member @global:adParams
            
            foreach ($group in $groups) {
                $logicalInfo = $null
                if ($groupConfig.Logical.isLogical) {
                    foreach ($suffix in $groupConfig.Logical.grouping.PSObject.Properties.Name) {
                        if ($group.Name -like "*$suffix") {
                            $logicalInfo = @{ BaseName = $group.Name -replace "$suffix$"; Access = $groupConfig.Logical.grouping.$suffix }
                        }
                    }
                }
                
                $owners = Get-OwnerNames -Info $group.info -BaseDN $baseDN
                $baseName = if ($logicalInfo) { $logicalInfo.BaseName } else { $group.Name }
                $groupGuidString = Get-ObjectGuidString $group $false
                $reviewPackageID = Get-DeterministicGuid "$baseName|$ReviewID|$groupGuidString"
                
                $package = [PSCustomObject]@{
                    ReviewID = $ReviewID
                    GroupID = $groupGuidString
                    ReviewPackageID = $reviewPackageID
                    GroupName = $baseName
                    PrimaryOwnerEmail = $owners.PrimaryOwner
                    SecondaryOwnerEmail = $owners.SecondaryOwner
                    OUPath = $baseDN
                    Tag = $groupConfig.category
                    Description = $group.Description
                    LogicalGrouping = $groupConfig.Logical.isLogical
                    LogicalAccess = if ($logicalInfo) { $logicalInfo.Access } else { "" }
                }
                $packages1 += $package
                
                # Members using AD module
                $members = Get-ADGroupMember -Identity $group -Recursive @global:adParams
                foreach ($member in $members) {
                    if ($member.objectClass -eq "user") {
                        $user = Get-ADUser -Identity $member.distinguishedName -Properties Department, Title, Manager @global:adParams
                        $manager = if ($user.Manager) { Get-ADUser -Identity $user.Manager -Properties DisplayName, mail @global:adParams } else { $null }
                        
                        $userGuidString = Get-ObjectGuidString $user $false
                        $memberObj = [PSCustomObject]@{
                            FirstName = $user.GivenName
                            LastName = $user.Surname
                            Email = $user.mail
                            UserID = $userGuidString
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
        } else {
            # LDAP logic
            $groupFilter = "(objectClass=group)"
            $groups = Invoke-LdapSearch -Ldap $global:ldap -BaseDN $baseDN -Filter $groupFilter -Attributes @("cn","description","info","distinguishedName","member")
            foreach ($group in $groups) {
                $groupName = $group.Attributes["cn"][0]
                $description = if ($group.Attributes["description"]) { $group.Attributes["description"][0] } else { "" }
                $info = if ($group.Attributes["info"]) { $group.Attributes["info"][0] } else { "" }
                $dn = $group.Attributes["distinguishedName"][0]
                
                $logicalInfo = $null
                if ($groupConfig.Logical.isLogical) {
                    foreach ($suffix in $groupConfig.Logical.grouping.PSObject.Properties.Name) {
                        if ($groupName -like "*$suffix") {
                            $logicalInfo = @{ BaseName = $groupName -replace "$suffix$"; Access = $groupConfig.Logical.grouping.$suffix }
                        }
                    }
                }
                
                $owners = Get-OwnerNames -Info $info -BaseDN $baseDN
                $baseName = if ($logicalInfo) { $logicalInfo.BaseName } else { $groupName }
                $groupGuidString = Get-ObjectGuidString $group $true
                $reviewPackageID = Get-DeterministicGuid "$baseName|$ReviewID|$groupGuidString"
                
                $package = [PSCustomObject]@{
                    ReviewID = $ReviewID
                    GroupID = $groupGuidString
                    ReviewPackageID = $reviewPackageID
                    GroupName = $baseName
                    PrimaryOwnerEmail = $owners.PrimaryOwner
                    SecondaryOwnerEmail = $owners.SecondaryOwner
                    OUPath = $baseDN
                    Tag = $groupConfig.category
                    Description = $description
                    LogicalGrouping = $groupConfig.Logical.isLogical
                    LogicalAccess = if ($logicalInfo) { $logicalInfo.Access } else { "" }
                }
                $packages1 += $package
                
                # Members using LDAP
                $members = if ($group.Attributes["member"]) { $group.Attributes["member"] } else { @() }
                foreach ($memberDN in $members) {
                    $userEntries = Invoke-LdapSearch -Ldap $global:ldap -BaseDN $memberDN -Filter "(objectClass=user)" -Attributes @("givenName","sn","mail","sAMAccountName","department","title","manager","distinguishedName")
                    foreach ($user in $userEntries) {
                        $managerName = ""; $managerEmail = ""
                        if ($user.Attributes["manager"]) {
                            $managerDN = $user.Attributes["manager"][0]
                            $managerEntry = Invoke-LdapSearch -Ldap $global:ldap -BaseDN $managerDN -Filter "(objectClass=user)" -Attributes @("givenName","sn","mail") | Select-Object -First 1
                            if ($managerEntry) {
                                $managerName = "$($managerEntry.Attributes["givenName"][0]) $($managerEntry.Attributes["sn"][0])"
                                $managerEmail = $managerEntry.Attributes["mail"][0]
                            }
                        }
                        
                        $userGuidString = Get-ObjectGuidString $user $true
                        $memberObj = [PSCustomObject]@{
                            FirstName = $user.Attributes["givenName"][0]
                            LastName = $user.Attributes["sn"][0]
                            Email = $user.Attributes["mail"][0]
                            UserID = $userGuidString
                            Username = "$($user.Attributes["givenName"][0]) $($user.Attributes["sn"][0])"
                            Department = if ($user.Attributes["department"]) { $user.Attributes["department"][0] } else { "" }
                            JobTitle = if ($user.Attributes["title"]) { $user.Attributes["title"][0] } else { "" }
                            ManagerName = $managerName
                            ManagerEmail = $managerEmail
                            ReviewPackageID = $reviewPackageID
                            DerivedGroup = $groupName
                            LogicalAccess = if ($logicalInfo) { $logicalInfo.Access } else { "" }
                        }
                        $packageMembers1 += $memberObj
                    }
                }
            }
        }
    }
}

# Process Privilege
function Process-Privilege {
    foreach ($ouPath in $privilegeConfig.ouPaths) {
        if ($global:useADModule) {
            $users = Get-ADUser -Filter * -SearchBase $ouPath -Properties memberOf @global:adParams
            
            foreach ($user in $users) {
                $userGuidString = Get-ObjectGuidString $user $false
                $reviewPackageID = Get-DeterministicGuid "$($user.SamAccountName)|$ReviewID|$userGuidString"
                
                $package = [PSCustomObject]@{
                    ReviewID = $ReviewID
                    GroupID = $userGuidString
                    GroupName = $user.DisplayName
                    OUPath = $ouPath
                    ReviewPackageID = $reviewPackageID
                }
                $packages2 += $package
                
                # Privilege Groups using AD module
                foreach ($groupDN in $user.memberOf) {
                    if ($groupDN -notin $privilegeConfig.exclude) {
                        $group = Get-ADGroup -Identity $groupDN -Properties Description @global:adParams
                        $groupGuidString = Get-ObjectGuidString $group $false
                        
                        $privilegeGroup = [PSCustomObject]@{
                            GroupName = $group.Name
                            GroupID = $groupGuidString
                            ReviewPackageID = $reviewPackageID
                            Description = $group.Description
                        }
                        $privilegeGroups += $privilegeGroup
                    }
                }
            }
        } else {
            # LDAP logic
            $userFilter = "(objectClass=user)"
            $users = Invoke-LdapSearch -Ldap $global:ldap -BaseDN $ouPath -Filter $userFilter -Attributes @("sAMAccountName","displayName","distinguishedName","memberOf")
            foreach ($user in $users) {
                $userGuidString = Get-ObjectGuidString $user $true
                $reviewPackageID = Get-DeterministicGuid "$($user.Attributes["sAMAccountName"][0])|$ReviewID|$userGuidString"
                
                $package = [PSCustomObject]@{
                    ReviewID = $ReviewID
                    GroupID = $userGuidString
                    GroupName = if ($user.Attributes["displayName"]) { $user.Attributes["displayName"][0] } else { $user.Attributes["sAMAccountName"][0] }
                    OUPath = $ouPath
                    ReviewPackageID = $reviewPackageID
                }
                $packages2 += $package
                
                # Privilege Groups using LDAP
                $memberOf = if ($user.Attributes["memberOf"]) { $user.Attributes["memberOf"] } else { @() }
                foreach ($groupDN in $memberOf) {
                    $groupEntry = Invoke-LdapSearch -Ldap $global:ldap -BaseDN $groupDN -Filter "(objectClass=group)" -Attributes @("cn","description","distinguishedName") | Select-Object -First 1
                    if ($groupEntry) {
                        $groupName = $groupEntry.Attributes["cn"][0]
                        $description = if ($groupEntry.Attributes["description"]) { $groupEntry.Attributes["description"][0] } else { "" }
                        
                        if ($groupDN -notin $privilegeConfig.exclude) {
                            $groupGuidString = Get-ObjectGuidString $groupEntry $true
                            
                            $privilegeGroup = [PSCustomObject]@{
                                GroupName = $groupName
                                GroupID = $groupGuidString
                                ReviewPackageID = $reviewPackageID
                                Description = $description
                            }
                            $privilegeGroups += $privilegeGroup
                        }
                    }
                }
            }
        }
    }
}

# Main execution
try {
    if (-not $PrivilegeOnly) {
        Process-Groups
    }
    if (-not $GroupsOnly) {
        Process-Privilege
    }
    
    $outputPath = Join-Path $scriptPath "..\output"
    if (-not (Test-Path $outputPath)) {
        New-Item -ItemType Directory -Path $outputPath | Out-Null
    }
    
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