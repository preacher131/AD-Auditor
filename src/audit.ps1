[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Unique identifier for this review run")]
    [string]$ReviewID,
    
    [Parameter(Mandatory=$false, HelpMessage="Process groups only, skip privilege analysis")]
    [switch]$GroupsOnly,
    
    [Parameter(Mandatory=$false, HelpMessage="Process privileges only, skip group analysis")]
    [switch]$PrivilegeOnly,
    
    [Parameter(Mandatory=$false, HelpMessage="Path to configuration directory")]
    [string]$ConfigPath = $null
)

# PowerShell 5.1 compatibility settings
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Script initialization
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

# Determine config path
if (-not $ConfigPath) {
    $ConfigPath = Join-Path -Path $scriptPath -ChildPath "..\configs"
}

Write-Host "=== AD Entitlement Review System ===" -ForegroundColor Cyan
Write-Host "PowerShell Version: $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)" -ForegroundColor Yellow

#region Module Import
Write-Host "Loading required modules..." -ForegroundColor Cyan
try {
    $ldapModulePath = Join-Path -Path $scriptPath -ChildPath "Modules\LDAP.psm1"
    if (Test-Path $ldapModulePath) {
        Import-Module $ldapModulePath -Force
        Write-Host "✓ LDAP module loaded successfully" -ForegroundColor Green
    } else {
        throw "LDAP module not found at: $ldapModulePath"
    }
} catch {
    Write-Error "Failed to load LDAP module: $($_.Exception.Message)"
    exit 1
}
#endregion

#region Configuration Loading
Write-Host "Loading configuration files..." -ForegroundColor Cyan

# Load main configuration
$configFile = Join-Path -Path $ConfigPath -ChildPath "config.json"
if (-not (Test-Path $configFile)) {
    Write-Error "Configuration file not found: $configFile"
    exit 1
}

try {
    $configContent = Get-Content -Path $configFile -Raw
    $config = ConvertFrom-Json $configContent
    Write-Host "✓ Main configuration loaded" -ForegroundColor Green
} catch {
    Write-Error "Failed to load main configuration: $($_.Exception.Message)"
    exit 1
}

# Load groups configuration
$groupsFile = Join-Path -Path $ConfigPath -ChildPath "groups.json"
if (-not (Test-Path $groupsFile)) {
    Write-Error "Groups configuration file not found: $groupsFile"
    exit 1
}

try {
    $groupsContent = Get-Content -Path $groupsFile -Raw
    $groupsConfig = ConvertFrom-Json $groupsContent
    Write-Host "✓ Groups configuration loaded" -ForegroundColor Green
} catch {
    Write-Error "Failed to load groups configuration: $($_.Exception.Message)"
    exit 1
}

# Load privilege configuration
$privilegeFile = Join-Path -Path $ConfigPath -ChildPath "privilege.json"
if (-not (Test-Path $privilegeFile)) {
    Write-Error "Privilege configuration file not found: $privilegeFile"
    exit 1
}

try {
    $privilegeContent = Get-Content -Path $privilegeFile -Raw
    $privilegeConfig = ConvertFrom-Json $privilegeContent
    Write-Host "✓ Privilege configuration loaded" -ForegroundColor Green
} catch {
    Write-Error "Failed to load privilege configuration: $($_.Exception.Message)"
    exit 1
}
#endregion

#region Helper Functions
function Get-SafeString {
    param(
        [Parameter(Position=0)]
        $Value,
        [Parameter(Position=1)]
        [string]$Default = ""
    )
    
    if ($Value -eq $null) {
        return $Default
    }
    
    if ([string]::IsNullOrEmpty($Value)) {
        return $Default
    }
    
    return $Value.ToString()
}

function New-DeterministicGuid {
    param(
        [Parameter(Mandatory=$true)]
        [string]$InputString
    )
    
    if ([string]::IsNullOrWhiteSpace($InputString)) {
        # Fallback to random GUID if input is invalid
        return [System.Guid]::NewGuid().ToString()
    }
    
    try {
        # Create SHA256 hash
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        $inputBytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
        $hashBytes = $hasher.ComputeHash($inputBytes)
        
        # Take first 16 bytes for GUID
        $guidBytes = New-Object byte[] 16
        [Array]::Copy($hashBytes, 0, $guidBytes, 0, 16)
        
        # Create GUID from bytes
        $guid = New-Object System.Guid @($guidBytes)
        $hasher.Dispose()
        
        return $guid.ToString()
    } catch {
        Write-Warning "Failed to generate deterministic GUID for input '$InputString': $($_.Exception.Message)"
        return [System.Guid]::NewGuid().ToString()
    }
}

function Get-ObjectGuid {
    param(
        [Parameter(Mandatory=$true)]
        $Object,
        [Parameter(Mandatory=$false)]
        [bool]$IsLdapObject = $false
    )
    
    try {
        if ($IsLdapObject) {
            # LDAP object handling
            if ($Object.Attributes -and $Object.Attributes.ContainsKey("objectGUID")) {
                $guidBytes = $Object.Attributes["objectGUID"]
                                 if ($guidBytes -and $guidBytes.Count -gt 0) {
                     $guid = New-Object System.Guid @($guidBytes[0])
                     return $guid.ToString()
                 }
            }
            
            # Fallback to DN-based GUID for LDAP
            if ($Object.Attributes -and $Object.Attributes.ContainsKey("distinguishedName")) {
                $dn = $Object.Attributes["distinguishedName"][0]
                return New-DeterministicGuid -InputString $dn
            }
        } else {
            # AD Module object handling
            if ($Object.ObjectGUID) {
                return $Object.ObjectGUID.ToString()
            }
        }
        
        # Final fallback
        return New-DeterministicGuid -InputString $Object.ToString()
    } catch {
        Write-Warning "Failed to get object GUID: $($_.Exception.Message)"
        return New-DeterministicGuid -InputString $Object.ToString()
    }
}

function Get-OwnerInfo {
    param(
        [Parameter(Mandatory=$false)]
        [string]$InfoText = "",
        [Parameter(Mandatory=$false)]
        [string]$BaseDN = ""
    )
    
    $result = @{
        PrimaryOwner = ""
        SecondaryOwner = ""
    }
    
    if ([string]::IsNullOrWhiteSpace($InfoText)) {
        return $result
    }
    
    # Process regex patterns if available
    if ($groupsConfig.ownerRegexPatterns) {
        foreach ($pattern in $groupsConfig.ownerRegexPatterns) {
            try {
                if ($InfoText -match $pattern.pattern) {
                    $email = $matches[$pattern.captureGroup]
                    
                    if ($pattern.name -like "*Primary*" -and [string]::IsNullOrEmpty($result.PrimaryOwner)) {
                        $result.PrimaryOwner = $email
                    } elseif ($pattern.name -like "*Secondary*" -and [string]::IsNullOrEmpty($result.SecondaryOwner)) {
                        $result.SecondaryOwner = $email
                    } elseif ([string]::IsNullOrEmpty($result.PrimaryOwner)) {
                        $result.PrimaryOwner = $email
                    }
                }
            } catch {
                Write-Warning "Failed to process owner pattern '$($pattern.name)': $($_.Exception.Message)"
            }
        }
    }
    
    return $result
}

function Get-LogicalInfo {
    param(
        [Parameter(Mandatory=$true)]
        [string]$GroupName,
        [Parameter(Mandatory=$true)]
        $GroupConfig
    )
    
    $result = @{
        IsLogical = $false
        BaseName = $GroupName
        Access = Get-SafeString $GroupConfig.category
    }
    
    if (-not $GroupConfig.Logical.isLogical) {
        return $result
    }
    
    # Check for logical grouping suffixes
    if ($GroupConfig.Logical.grouping) {
        $groupingProperties = $GroupConfig.Logical.grouping | Get-Member -MemberType NoteProperty
        foreach ($prop in $groupingProperties) {
            $suffix = $prop.Name
            if ($GroupName -like "*$suffix") {
                $result.IsLogical = $true
                $result.BaseName = $GroupName -replace [regex]::Escape($suffix) + '$', ''
                $result.Access = Get-SafeString $GroupConfig.Logical.grouping.$suffix
                break
            }
        }
    }
    
    if (-not $result.IsLogical -and $GroupConfig.Logical.isLogical) {
        $result.IsLogical = $true
    }
    
    return $result
}
#endregion

#region Connection Setup
Write-Host "Establishing Active Directory connection..." -ForegroundColor Cyan

# Initialize connection variables
$useADModule = $false
$ldapConnection = $null
$adParams = @{}

# Determine connection type
$connectionType = "LDAP"
if ($config.Connection.Type) {
    $connectionType = $config.Connection.Type.ToUpper()
} elseif ($config.Connection.UseLDAPS) {
    $connectionType = "LDAPS"
}

Write-Host "Connection type: $connectionType" -ForegroundColor Yellow
Write-Host "Domain Controller: $($config.DomainController)" -ForegroundColor Yellow

try {
    switch ($connectionType) {
        "ACTIVEDIRECTORY" {
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
                
                $adParams.Server = $config.DomainController
                
                if (-not $config.Connection.UseCurrentUser) {
                    $securePassword = ConvertTo-SecureString $config.Connection.CredentialProfile.Password -AsPlainText -Force
                    $domainUser = "$($config.Connection.CredentialProfile.Domain)\$($config.Connection.CredentialProfile.Username)"
                    $credential = New-Object System.Management.Automation.PSCredential($domainUser, $securePassword)
                    $adParams.Credential = $credential
                }
                
                # Test connection
                $null = Get-ADDomain @adParams
                $useADModule = $true
                Write-Host "✓ Connected using ActiveDirectory module" -ForegroundColor Green
                
            } catch {
                Write-Warning "ActiveDirectory module failed, falling back to LDAP: $($_.Exception.Message)"
                $connectionType = "LDAP"
            }
        }
        
        { $_ -in @("LDAP", "LDAPS") } {
            $useLDAPS = ($connectionType -eq "LDAPS")
            
            $ldapConnection = New-LdapConnection -Server $config.DomainController -UseLDAPS $useLDAPS -UseCurrentUser $config.Connection.UseCurrentUser -Username $config.Connection.CredentialProfile.Username -Password $config.Connection.CredentialProfile.Password -Domain $config.Connection.CredentialProfile.Domain
            
            $useADModule = $false
            $connectionTypeDisplay = if ($useLDAPS) { "LDAPS" } else { "LDAP" }
            Write-Host "✓ Connected using $connectionTypeDisplay" -ForegroundColor Green
        }
        
        default {
            throw "Unsupported connection type: $connectionType"
        }
    }
} catch {
    Write-Error "Failed to establish AD connection: $($_.Exception.Message)"
    exit 1
}
#endregion

#region Processing Functions
function Process-GroupEntitlements {
    Write-Host "Processing group entitlements..." -ForegroundColor Cyan
    
    $packages1 = @()
    $packageMembers1 = @()
    
    foreach ($groupConfig in $groupsConfig.groups) {
        $baseDN = Get-SafeString $groupConfig.path
        Write-Host "  Processing OU: $baseDN" -ForegroundColor Yellow
        
        try {
            if ($useADModule) {
                # ActiveDirectory module processing
                $groups = Get-ADGroup -Filter * -SearchBase $baseDN -Properties Description, info @adParams
                
                foreach ($group in $groups) {
                    $logicalInfo = Get-LogicalInfo -GroupName $group.Name -GroupConfig $groupConfig
                    $owners = Get-OwnerInfo -InfoText (Get-SafeString $group.info) -BaseDN $baseDN
                    $groupGuid = Get-ObjectGuid -Object $group -IsLdapObject $false
                    $reviewPackageID = New-DeterministicGuid -InputString "$($logicalInfo.BaseName)|$ReviewID|$groupGuid"
                    
                    # Create package record
                    $package = New-Object PSObject -Property @{
                        ReviewID = $ReviewID
                        GroupID = $groupGuid
                        ReviewPackageID = $reviewPackageID
                        GroupName = $logicalInfo.BaseName
                        PrimaryOwnerEmail = Get-SafeString $owners.PrimaryOwner
                        SecondaryOwnerEmail = Get-SafeString $owners.SecondaryOwner
                        OUPath = $baseDN
                        Tag = Get-SafeString $groupConfig.category
                        Description = Get-SafeString $group.Description
                        LogicalGrouping = $logicalInfo.IsLogical
                        LogicalAccess = Get-SafeString $logicalInfo.Access
                    }
                    $packages1 += $package
                    
                    # Process group members
                    try {
                        $members = Get-ADGroupMember -Identity $group -Recursive @adParams | Where-Object { $_.objectClass -eq "user" }
                        
                        foreach ($member in $members) {
                            try {
                                $user = Get-ADUser -Identity $member.distinguishedName -Properties Department, Title, Manager, mail, givenName, surname @adParams
                                
                                # Get manager information
                                $managerName = ""
                                $managerEmail = ""
                                
                                if ($user.Manager) {
                                    try {
                                        $mgr = Get-ADUser -Identity $user.Manager -Properties DisplayName, mail @adParams
                                        $managerName = Get-SafeString $mgr.DisplayName
                                        $managerEmail = Get-SafeString $mgr.mail
                                    } catch {
                                        # Manager lookup failed, continue with empty values
                                    }
                                }
                                
                                $firstName = Get-SafeString $user.givenName
                                $lastName = Get-SafeString $user.surname
                                $fullName = "$firstName $lastName".Trim()
                                
                                $memberObj = New-Object PSObject -Property @{
                                    FirstName = $firstName
                                    LastName = $lastName
                                    Email = Get-SafeString $user.mail
                                    UserID = $user.ObjectGUID.ToString()
                                    Username = $fullName
                                    Department = Get-SafeString $user.Department
                                    JobTitle = Get-SafeString $user.Title
                                    ManagerName = $managerName
                                    ManagerEmail = $managerEmail
                                    ReviewPackageID = $reviewPackageID
                                    DerivedGroup = $group.Name
                                    LogicalAccess = Get-SafeString $logicalInfo.Access
                                }
                                $packageMembers1 += $memberObj
                                
                            } catch {
                                Write-Warning "Failed to process user '$($member.distinguishedName)': $($_.Exception.Message)"
                            }
                        }
                    } catch {
                        Write-Warning "Failed to get members for group '$($group.Name)': $($_.Exception.Message)"
                    }
                }
                
            } else {
                # LDAP processing
                $groupFilter = "(objectClass=group)"
                $groups = Invoke-LdapSearch -Ldap $ldapConnection -BaseDN $baseDN -Filter $groupFilter -Attributes @("cn","description","info","distinguishedName","member")
                
                foreach ($group in $groups) {
                    $groupName = ""
                    if ($group.Attributes.ContainsKey("cn")) {
                        $groupName = $group.Attributes["cn"][0]
                    }
                    
                    if ([string]::IsNullOrEmpty($groupName)) {
                        continue
                    }
                    
                    $logicalInfo = Get-LogicalInfo -GroupName $groupName -GroupConfig $groupConfig
                    
                    $infoText = ""
                    if ($group.Attributes.ContainsKey("info")) {
                        $infoText = $group.Attributes["info"][0]
                    }
                    
                    $owners = Get-OwnerInfo -InfoText $infoText -BaseDN $baseDN
                    $groupGuid = Get-ObjectGuid -Object $group -IsLdapObject $true
                    $reviewPackageID = New-DeterministicGuid -InputString "$($logicalInfo.BaseName)|$ReviewID|$groupGuid"
                    
                    $groupDescription = ""
                    if ($group.Attributes.ContainsKey("description")) {
                        $groupDescription = Get-SafeString $group.Attributes["description"][0]
                    }
                    
                    # Create package record
                    $package = New-Object PSObject -Property @{
                        ReviewID = $ReviewID
                        GroupID = $groupGuid
                        ReviewPackageID = $reviewPackageID
                        GroupName = $logicalInfo.BaseName
                        PrimaryOwnerEmail = Get-SafeString $owners.PrimaryOwner
                        SecondaryOwnerEmail = Get-SafeString $owners.SecondaryOwner
                        OUPath = $baseDN
                        Tag = Get-SafeString $groupConfig.category
                        Description = $groupDescription
                        LogicalGrouping = $logicalInfo.IsLogical
                        LogicalAccess = Get-SafeString $logicalInfo.Access
                    }
                    $packages1 += $package
                    
                    # Process group members
                    try {
                        if ($group.Attributes.ContainsKey("member")) {
                            foreach ($memberDN in $group.Attributes["member"]) {
                                try {
                                    $userEntry = Invoke-LdapSearch -Ldap $ldapConnection -BaseDN $memberDN -Filter "(objectClass=user)" -Attributes @("givenName","sn","mail","department","title","manager","displayName") | Select-Object -First 1
                                    
                                    if ($userEntry) {
                                        # Get manager information
                                        $managerName = ""
                                        $managerEmail = ""
                                        
                                        if ($userEntry.Attributes.ContainsKey("manager")) {
                                            try {
                                                $managerDN = $userEntry.Attributes["manager"][0]
                                                $managerEntry = Invoke-LdapSearch -Ldap $ldapConnection -BaseDN $managerDN -Filter "(objectClass=user)" -Attributes @("displayName","mail") | Select-Object -First 1
                                                if ($managerEntry) {
                                                    if ($managerEntry.Attributes.ContainsKey("displayName")) {
                                                        $managerName = Get-SafeString $managerEntry.Attributes["displayName"][0]
                                                    }
                                                    if ($managerEntry.Attributes.ContainsKey("mail")) {
                                                        $managerEmail = Get-SafeString $managerEntry.Attributes["mail"][0]
                                                    }
                                                }
                                            } catch {
                                                # Manager lookup failed, continue with empty values
                                            }
                                        }
                                        
                                        $firstName = ""
                                        $lastName = ""
                                        $email = ""
                                        $department = ""
                                        $jobTitle = ""
                                        
                                        if ($userEntry.Attributes.ContainsKey("givenName")) {
                                            $firstName = Get-SafeString $userEntry.Attributes["givenName"][0]
                                        }
                                        if ($userEntry.Attributes.ContainsKey("sn")) {
                                            $lastName = Get-SafeString $userEntry.Attributes["sn"][0]
                                        }
                                        if ($userEntry.Attributes.ContainsKey("mail")) {
                                            $email = Get-SafeString $userEntry.Attributes["mail"][0]
                                        }
                                        if ($userEntry.Attributes.ContainsKey("department")) {
                                            $department = Get-SafeString $userEntry.Attributes["department"][0]
                                        }
                                        if ($userEntry.Attributes.ContainsKey("title")) {
                                            $jobTitle = Get-SafeString $userEntry.Attributes["title"][0]
                                        }
                                        
                                        $fullName = "$firstName $lastName".Trim()
                                        
                                        $memberObj = New-Object PSObject -Property @{
                                            FirstName = $firstName
                                            LastName = $lastName
                                            Email = $email
                                            UserID = Get-ObjectGuid -Object $userEntry -IsLdapObject $true
                                            Username = $fullName
                                            Department = $department
                                            JobTitle = $jobTitle
                                            ManagerName = $managerName
                                            ManagerEmail = $managerEmail
                                            ReviewPackageID = $reviewPackageID
                                            DerivedGroup = $groupName
                                            LogicalAccess = Get-SafeString $logicalInfo.Access
                                        }
                                        $packageMembers1 += $memberObj
                                    }
                                } catch {
                                    Write-Warning "Failed to process member '$memberDN': $($_.Exception.Message)"
                                }
                            }
                        }
                    } catch {
                        Write-Warning "Failed to process members for group '$groupName': $($_.Exception.Message)"
                    }
                }
            }
            
        } catch {
            Write-Warning "Failed to process OU '$baseDN': $($_.Exception.Message)"
        }
    }
    
    Write-Host "  Found $($packages1.Count) groups with $($packageMembers1.Count) total members" -ForegroundColor Green
    
    return @{
        Packages1 = $packages1
        PackageMembers1 = $packageMembers1
    }
}

function Process-PrivilegeEntitlements {
    Write-Host "Processing privilege entitlements..." -ForegroundColor Cyan
    
    $packages2 = @()
    $privilegeGroups = @()
    
    foreach ($ouPath in $privilegeConfig.ouPaths) {
        Write-Host "  Processing OU: $ouPath" -ForegroundColor Yellow
        
        try {
            if ($useADModule) {
                # ActiveDirectory module processing
                $users = Get-ADUser -Filter * -SearchBase $ouPath -Properties memberOf, DisplayName @adParams
                
                foreach ($user in $users) {
                    $userGuid = Get-ObjectGuid -Object $user -IsLdapObject $false
                    $reviewPackageID = New-DeterministicGuid -InputString "$($user.SamAccountName)|$ReviewID|$userGuid"
                    
                    # Create user package record
                    $package = New-Object PSObject -Property @{
                        ReviewID = $ReviewID
                        GroupID = $userGuid
                        GroupName = Get-SafeString $user.DisplayName
                        OUPath = $ouPath
                        ReviewPackageID = $reviewPackageID
                    }
                    $packages2 += $package
                    
                    # Process user's group memberships
                    $memberOfGroups = @()
                    if ($user.memberOf) {
                        $memberOfGroups = $user.memberOf
                    }
                    
                    foreach ($groupDN in $memberOfGroups) {
                        $shouldExclude = $false
                        foreach ($excludePattern in $privilegeConfig.exclude) {
                            if ($groupDN -like $excludePattern) {
                                $shouldExclude = $true
                                break
                            }
                        }
                        
                        if (-not $shouldExclude) {
                            try {
                                $group = Get-ADGroup -Identity $groupDN -Properties Description @adParams
                                $groupGuid = Get-ObjectGuid -Object $group -IsLdapObject $false
                                
                                $privilegeGroup = New-Object PSObject -Property @{
                                    GroupName = Get-SafeString $group.Name
                                    GroupID = $groupGuid
                                    ReviewPackageID = $reviewPackageID
                                    Description = Get-SafeString $group.Description
                                }
                                $privilegeGroups += $privilegeGroup
                            } catch {
                                Write-Warning "Failed to get group info for '$groupDN': $($_.Exception.Message)"
                            }
                        }
                    }
                }
                
            } else {
                # LDAP processing
                $userFilter = "(objectClass=user)"
                $users = Invoke-LdapSearch -Ldap $ldapConnection -BaseDN $ouPath -Filter $userFilter -Attributes @("sAMAccountName","displayName","distinguishedName","memberOf")
                
                foreach ($user in $users) {
                    $userGuid = Get-ObjectGuid -Object $user -IsLdapObject $true
                    
                    $samAccountName = ""
                    if ($user.Attributes.ContainsKey("sAMAccountName")) {
                        $samAccountName = Get-SafeString $user.Attributes["sAMAccountName"][0]
                    }
                    
                    $reviewPackageID = New-DeterministicGuid -InputString "$samAccountName|$ReviewID|$userGuid"
                    
                    $displayName = $samAccountName
                    if ($user.Attributes.ContainsKey("displayName")) {
                        $displayName = Get-SafeString $user.Attributes["displayName"][0]
                    }
                    
                    # Create user package record
                    $package = New-Object PSObject -Property @{
                        ReviewID = $ReviewID
                        GroupID = $userGuid
                        GroupName = $displayName
                        OUPath = $ouPath
                        ReviewPackageID = $reviewPackageID
                    }
                    $packages2 += $package
                    
                    # Process user's group memberships
                    $memberOfGroups = @()
                    if ($user.Attributes.ContainsKey("memberOf")) {
                        $memberOfGroups = $user.Attributes["memberOf"]
                    }
                    
                    foreach ($groupDN in $memberOfGroups) {
                        $shouldExclude = $false
                        foreach ($excludePattern in $privilegeConfig.exclude) {
                            if ($groupDN -like $excludePattern) {
                                $shouldExclude = $true
                                break
                            }
                        }
                        
                        if (-not $shouldExclude) {
                            try {
                                $groupEntry = Invoke-LdapSearch -Ldap $ldapConnection -BaseDN $groupDN -Filter "(objectClass=group)" -Attributes @("cn","description","distinguishedName") | Select-Object -First 1
                                if ($groupEntry) {
                                    $groupGuid = Get-ObjectGuid -Object $groupEntry -IsLdapObject $true
                                    
                                    $groupName = ""
                                    if ($groupEntry.Attributes.ContainsKey("cn")) {
                                        $groupName = Get-SafeString $groupEntry.Attributes["cn"][0]
                                    }
                                    
                                    $groupDescription = ""
                                    if ($groupEntry.Attributes.ContainsKey("description")) {
                                        $groupDescription = Get-SafeString $groupEntry.Attributes["description"][0]
                                    }
                                    
                                    $privilegeGroup = New-Object PSObject -Property @{
                                        GroupName = $groupName
                                        GroupID = $groupGuid
                                        ReviewPackageID = $reviewPackageID
                                        Description = $groupDescription
                                    }
                                    $privilegeGroups += $privilegeGroup
                                }
                            } catch {
                                Write-Warning "Failed to get group info for '$groupDN': $($_.Exception.Message)"
                            }
                        }
                    }
                }
            }
            
        } catch {
            Write-Warning "Failed to process OU '$ouPath': $($_.Exception.Message)"
        }
    }
    
    Write-Host "  Found $($packages2.Count) users with $($privilegeGroups.Count) total group memberships" -ForegroundColor Green
    
    return @{
        Packages2 = $packages2
        PrivilegeGroups = $privilegeGroups
    }
}
#endregion

#region Main Execution
try {
    Write-Host ""
    Write-Host "Starting AD Entitlement Review for ReviewID: $ReviewID" -ForegroundColor Green
    Write-Host ("=" * 60) -ForegroundColor Green
    
    # Initialize result collections
    $allResults = @{
        Packages1 = @()
        PackageMembers1 = @()
        Packages2 = @()
        PrivilegeGroups = @()
    }
    
    # Process groups if not privilege-only
    if (-not $PrivilegeOnly) {
        $groupResults = Process-GroupEntitlements
        $allResults.Packages1 = $groupResults.Packages1
        $allResults.PackageMembers1 = $groupResults.PackageMembers1
    }
    
    # Process privileges if not groups-only
    if (-not $GroupsOnly) {
        $privilegeResults = Process-PrivilegeEntitlements
        $allResults.Packages2 = $privilegeResults.Packages2
        $allResults.PrivilegeGroups = $privilegeResults.PrivilegeGroups
    }
    
    # Determine output path
    $outputPath = $config.OutputFolder
    if ($config.OutputFolder -match "^\.\.") {
        $outputPath = Join-Path -Path $scriptPath -ChildPath $config.OutputFolder
    }
    
    # Create output directory if needed
    if (-not (Test-Path $outputPath)) {
        New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
        Write-Host "Created output directory: $outputPath" -ForegroundColor Yellow
    }
    
    # Generate output file names
    Write-Host ""
    Write-Host "Generating output files..." -ForegroundColor Cyan
    
    $outputFiles = @{
        Packages1 = $config.OutputFiles.Packages1 -replace '{ReviewId}', $ReviewID
        PackageMembers1 = $config.OutputFiles.PackageMembers1 -replace '{ReviewId}', $ReviewID
        Packages2 = $config.OutputFiles.Packages2 -replace '{ReviewId}', $ReviewID
        PrivilegeGroups = $config.OutputFiles.PrivilegeGroups -replace '{ReviewId}', $ReviewID
    }
    
    # Export CSV files
    if ($allResults.Packages1.Count -gt 0) {
        $filePath = Join-Path -Path $outputPath -ChildPath $outputFiles.Packages1
        $allResults.Packages1 | Export-Csv -Path $filePath -NoTypeInformation
        Write-Host "  ✓ $($outputFiles.Packages1) ($($allResults.Packages1.Count) records)" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ No group packages to export" -ForegroundColor Yellow
    }
    
    if ($allResults.PackageMembers1.Count -gt 0) {
        $filePath = Join-Path -Path $outputPath -ChildPath $outputFiles.PackageMembers1
        $allResults.PackageMembers1 | Export-Csv -Path $filePath -NoTypeInformation
        Write-Host "  ✓ $($outputFiles.PackageMembers1) ($($allResults.PackageMembers1.Count) records)" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ No package members to export" -ForegroundColor Yellow
    }
    
    if ($allResults.Packages2.Count -gt 0) {
        $filePath = Join-Path -Path $outputPath -ChildPath $outputFiles.Packages2
        $allResults.Packages2 | Export-Csv -Path $filePath -NoTypeInformation
        Write-Host "  ✓ $($outputFiles.Packages2) ($($allResults.Packages2.Count) records)" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ No privilege packages to export" -ForegroundColor Yellow
    }
    
    if ($allResults.PrivilegeGroups.Count -gt 0) {
        $filePath = Join-Path -Path $outputPath -ChildPath $outputFiles.PrivilegeGroups
        $allResults.PrivilegeGroups | Export-Csv -Path $filePath -NoTypeInformation
        Write-Host "  ✓ $($outputFiles.PrivilegeGroups) ($($allResults.PrivilegeGroups.Count) records)" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ No privilege groups to export" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Green
    Write-Host "✓ AD Entitlement Review completed successfully!" -ForegroundColor Green
    Write-Host "Output files saved to: $outputPath" -ForegroundColor Yellow
    
} catch {
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Red
    Write-Error "❌ AD Entitlement Review failed: $($_.Exception.Message)"
    Write-Host "Error Details: $($_.Exception.ToString())" -ForegroundColor Red
    exit 1
} finally {
    # Cleanup connections
    if ($ldapConnection) {
        try { 
            $ldapConnection.Dispose() 
        } catch { 
            # Ignore disposal errors
        }
    }
    Write-Host "Cleanup completed." -ForegroundColor Gray
}
