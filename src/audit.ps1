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

# Establish LDAP connection
$ldap = New-LdapConnection `
    -Server $config.DomainController `
    -UseLDAPS $config.Connection.UseLDAPS `
    -UseCurrentUser $config.Connection.UseCurrentUser `
    -Username $config.Connection.CredentialProfile.Username `
    -Password $config.Connection.CredentialProfile.Password `
    -Domain $config.Connection.CredentialProfile.Domain

# Helper: Generate deterministic GUID
function Get-DeterministicGuid {
    param([string]$InputString)
    $hash = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $hash.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($InputString))
    $guid = [System.Guid]::new($hashBytes)
    return $guid
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
            $filter = "(&(objectClass=user)(sn=$lastName))"
            $users = Invoke-LdapSearch -Ldap $ldap -BaseDN $BaseDN -Filter $filter -Attributes @("givenName","sn","mail")
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
        $groupFilter = "(objectClass=group)"
        $groups = Invoke-LdapSearch -Ldap $ldap -BaseDN $baseDN -Filter $groupFilter -Attributes @("cn","description","info","distinguishedName","objectGUID","member")
        foreach ($group in $groups) {
            $groupName = $group.Attributes["cn"][0]
            $objectGUID = [guid]::New($group.Attributes["objectGUID"][0])
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
            $reviewPackageID = Get-DeterministicGuid "$baseName|$ReviewID|$objectGUID"
            $package = [PSCustomObject]@{
                ReviewID = $ReviewID
                GroupID = $objectGUID
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
            # Members
            $members = if ($group.Attributes["member"]) { $group.Attributes["member"] } else { @() }
            foreach ($memberDN in $members) {
                $userEntries = Invoke-LdapSearch -Ldap $ldap -BaseDN $memberDN -Filter "(objectClass=user)" -Attributes @("givenName","sn","mail","objectGUID","sAMAccountName","department","title","manager","distinguishedName")
                foreach ($user in $userEntries) {
                    $userGUID = [guid]::New($user.Attributes["objectGUID"][0])
                    $managerName = ""; $managerEmail = ""
                    if ($user.Attributes["manager"]) {
                        $managerDN = $user.Attributes["manager"][0]
                        $managerEntry = Invoke-LdapSearch -Ldap $ldap -BaseDN $managerDN -Filter "(objectClass=user)" -Attributes @("givenName","sn","mail") | Select-Object -First 1
                        if ($managerEntry) {
                            $managerName = "$($managerEntry.Attributes["givenName"][0]) $($managerEntry.Attributes["sn"][0])"
                            $managerEmail = $managerEntry.Attributes["mail"][0]
                        }
                    }
                    $memberObj = [PSCustomObject]@{
                        FirstName = $user.Attributes["givenName"][0]
                        LastName = $user.Attributes["sn"][0]
                        Email = $user.Attributes["mail"][0]
                        UserID = $userGUID
                        Username = "$($user.Attributes["givenName"][0]) $($user.Attributes["sn"][0])"
                        Department = $user.Attributes["department"][0]
                        JobTitle = $user.Attributes["title"][0]
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

# Process Privilege
function Process-Privilege {
    foreach ($ouPath in $privilegeConfig.ouPaths) {
        $userFilter = "(objectClass=user)"
        $users = Invoke-LdapSearch -Ldap $ldap -BaseDN $ouPath -Filter $userFilter -Attributes @("sAMAccountName","displayName","objectGUID","distinguishedName","memberOf")
        foreach ($user in $users) {
            $userGUID = [guid]::New($user.Attributes["objectGUID"][0])
            $reviewPackageID = Get-DeterministicGuid "$($user.Attributes["sAMAccountName"][0])|$ReviewID|$userGUID"
            $package = [PSCustomObject]@{
                ReviewID = $ReviewID
                GroupID = $userGUID
                GroupName = $user.Attributes["displayName"][0]
                OUPath = $ouPath
                ReviewPackageID = $reviewPackageID
            }
            $packages2 += $package
            # Privilege Groups
            $memberOf = if ($user.Attributes["memberOf"]) { $user.Attributes["memberOf"] } else { @() }
            foreach ($groupDN in $memberOf) {
                $groupEntry = Invoke-LdapSearch -Ldap $ldap -BaseDN $groupDN -Filter "(objectClass=group)" -Attributes @("cn","objectGUID","description") | Select-Object -First 1
                if ($groupEntry) {
                    $groupName = $groupEntry.Attributes["cn"][0]
                    $groupGUID = [guid]::New($groupEntry.Attributes["objectGUID"][0])
                    $description = if ($groupEntry.Attributes["description"]) { $groupEntry.Attributes["description"][0] } else { "" }
                    if ($groupDN -notin $privilegeConfig.exclude) {
                        $privilegeGroup = [PSCustomObject]@{
                            GroupName = $groupName
                            GroupID = $groupGUID
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