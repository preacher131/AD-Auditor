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

#region Module Imports and Setup
$ErrorActionPreference = "Stop"
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

# Determine config path
if (-not $ConfigPath) {
    $ConfigPath = Join-Path $scriptPath "..\configs"
}

# Import required modules
try {
    Import-Module "$scriptPath\Modules\LDAP.psm1" -Force
    Write-Host "✓ Successfully imported LDAP module" -ForegroundColor Green
} catch {
    Write-Error "Failed to import LDAP module: $_"
    exit 1
}
#endregion

#region Configuration Loading
Write-Host "Loading configurations..." -ForegroundColor Cyan

try {
    # Load main configuration
    $configFile = Join-Path $ConfigPath "config.json"
    if (-not (Test-Path $configFile)) {
        throw "Configuration file not found: $configFile"
    }
    $config = Get-Content $configFile | ConvertFrom-Json
    Write-Host "✓ Loaded main configuration" -ForegroundColor Green
    
    # Load groups configuration  
    $groupsFile = Join-Path $ConfigPath "groups.json"
    if (-not (Test-Path $groupsFile)) {
        throw "Groups configuration file not found: $groupsFile"
    }
    $groupsConfig = Get-Content $groupsFile | ConvertFrom-Json
    Write-Host "✓ Loaded groups configuration" -ForegroundColor Green
    
    # Load privilege configuration
    $privilegeFile = Join-Path $ConfigPath "privilege.json"
    if (-not (Test-Path $privilegeFile)) {
        throw "Privilege configuration file not found: $privilegeFile"
    }
    $privilegeConfig = Get-Content $privilegeFile | ConvertFrom-Json
    Write-Host "✓ Loaded privilege configuration" -ForegroundColor Green
    
} catch {
    Write-Error "Configuration loading failed: $_"
    exit 1
}
#endregion

#region Connection Setup
Write-Host "Establishing Active Directory connection..." -ForegroundColor Cyan

# Global connection variables
$global:useADModule = $false
$global:ldapConnection = $null
$global:adParams = @{}

try {
    # Determine connection type
    $connectionType = if ($config.Connection.Type) { 
        $config.Connection.Type.ToUpper() 
    } else { 
        if ($config.Connection.UseLDAPS) { "LDAPS" } else { "LDAP" } 
    }
    
    Write-Host "Connection type: $connectionType" -ForegroundColor Yellow
    Write-Host "Domain Controller: $($config.DomainController)" -ForegroundColor Yellow
    
    switch ($connectionType) {
        "ACTIVEDIRECTORY" {
            # Try to use AD module first
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
                
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
                $null = Get-ADDomain @global:adParams
                $global:useADModule = $true
                Write-Host "✓ Connected using ActiveDirectory module" -ForegroundColor Green
                
            } catch {
                Write-Warning "ActiveDirectory module failed, falling back to LDAP: $_"
                $connectionType = "LDAP"
            }
        }
        
        { $_ -in @("LDAP", "LDAPS") } {
            $useLDAPS = ($connectionType -eq "LDAPS")
            
            $global:ldapConnection = New-LdapConnection `
                -Server $config.DomainController `
                -UseLDAPS $useLDAPS `
                -UseCurrentUser $config.Connection.UseCurrentUser `
                -Username $config.Connection.CredentialProfile.Username `
                -Password $config.Connection.CredentialProfile.Password `
                -Domain $config.Connection.CredentialProfile.Domain
            
            $global:useADModule = $false
            Write-Host "✓ Connected using LDAP$(if($useLDAPS){'S'}else{''})" -ForegroundColor Green
        }
        
        default {
            throw "Unsupported connection type: $connectionType"
        }
    }
    
} catch {
    Write-Error "Failed to establish AD connection: $_"
    exit 1
}
#endregion

#region Helper Functions
function Get-DeterministicGuid {
    param([string]$InputString)
    
    if ([string]::IsNullOrWhiteSpace($InputString)) {
        throw "Input string cannot be null or empty for GUID generation"
    }
    
    try {
        $hash = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $hash.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($InputString))
        # Take first 16 bytes for GUID
        $guidBytes = $hashBytes[0..15]
        $guid = [System.Guid]::new($guidBytes)
        $hash.Dispose()
        return $guid.ToString()
    } catch {
        Write-Warning "Failed to generate deterministic GUID for '$InputString': $_"
        # Fallback to random GUID
        return [System.Guid]::NewGuid().ToString()
    }
}

function Get-SafeObjectGuid {
    param($Object, $IsLdap = $false)
    
    try {
        if ($IsLdap) {
            # For LDAP, try to get objectGUID first, then fall back to DN-based GUID
            if ($Object.Attributes["objectGUID"] -and $Object.Attributes["objectGUID"].Count -gt 0) {
                return [System.Guid]::new($Object.Attributes["objectGUID"][0]).ToString()
            } else {
                $dn = $Object.Attributes["distinguishedName"][0]
                return Get-DeterministicGuid $dn
            }
        } else {
            # For AD module, use ObjectGUID directly
            return $Object.ObjectGUID.ToString()
        }
    } catch {
        Write-Warning "Failed to get object GUID, using fallback: $_"
        # Fallback: use object's string representation
        return Get-DeterministicGuid $Object.ToString()
    }
}

function Get-OwnerEmails {
    param(
        [string]$InfoText,
        [string]$BaseDN
    )
    
    $result = @{
        PrimaryOwner = ""
        SecondaryOwner = ""
    }
    
    if ([string]::IsNullOrWhiteSpace($InfoText)) {
        return $result
    }
    
    # Use the regex patterns from groups config
    if ($groupsConfig.ownerRegexPatterns) {
        foreach ($pattern in $groupsConfig.ownerRegexPatterns) {
            try {
                if ($InfoText -match $pattern.pattern) {
                    $email = $matches[$pattern.captureGroup]
                    
                    if ($pattern.name -match "Primary" -and [string]::IsNullOrEmpty($result.PrimaryOwner)) {
                        $result.PrimaryOwner = $email
                    } elseif ($pattern.name -match "Secondary" -and [string]::IsNullOrEmpty($result.SecondaryOwner)) {
                        $result.SecondaryOwner = $email
                    } elseif ([string]::IsNullOrEmpty($result.PrimaryOwner)) {
                        $result.PrimaryOwner = $email
                    }
                }
            } catch {
                Write-Warning "Failed to process owner pattern '$($pattern.name)': $_"
            }
        }
    }
    
    return $result
}

function Get-LogicalGroupInfo {
    param(
        [string]$GroupName,
        [object]$GroupConfig
    )
    
    if (-not $GroupConfig.Logical.isLogical) {
        return @{
            IsLogical = $false
            BaseName = $GroupName
            Access = $GroupConfig.category
        }
    }
    
    foreach ($suffix in $GroupConfig.Logical.grouping.PSObject.Properties.Name) {
        if ($GroupName -like "*$suffix") {
            return @{
                IsLogical = $true
                BaseName = $GroupName -replace "$([regex]::Escape($suffix))$", ""
                Access = $GroupConfig.Logical.grouping.$suffix
            }
        }
    }
    
    return @{
        IsLogical = $GroupConfig.Logical.isLogical
        BaseName = $GroupName
        Access = $GroupConfig.category
    }
}

function Get-SafeValue {
    param($Value, $Default = "")
    if ($Value -and $Value -ne $null) { return $Value.ToString() } else { return $Default }
}
#endregion

#region Data Processing Functions
function Process-Groups {
    Write-Host "Processing groups..." -ForegroundColor Cyan
    
    $packages1 = @()
    $packageMembers1 = @()
    
    foreach ($groupConfig in $groupsConfig.groups) {
        $baseDN = $groupConfig.path
        Write-Host "  Processing OU: $baseDN" -ForegroundColor Yellow
        
        try {
            if ($global:useADModule) {
                $groups = Get-ADGroup -Filter * -SearchBase $baseDN -Properties Description, info @global:adParams
                
                foreach ($group in $groups) {
                    $logicalInfo = Get-LogicalGroupInfo -GroupName $group.Name -GroupConfig $groupConfig
                    $owners = Get-OwnerEmails -InfoText $group.info -BaseDN $baseDN
                    $groupGuid = Get-SafeObjectGuid $group $false
                    $reviewPackageID = Get-DeterministicGuid "$($logicalInfo.BaseName)|$ReviewID|$groupGuid"
                    
                    # Create package record
                    $package = [PSCustomObject]@{
                        ReviewID = $ReviewID
                        GroupID = $groupGuid
                        ReviewPackageID = $reviewPackageID
                        GroupName = $logicalInfo.BaseName
                        PrimaryOwnerEmail = Get-SafeValue $owners.PrimaryOwner
                        SecondaryOwnerEmail = Get-SafeValue $owners.SecondaryOwner
                        OUPath = $baseDN
                        Tag = $groupConfig.category
                        Description = Get-SafeValue $group.Description
                        LogicalGrouping = $logicalInfo.IsLogical
                        LogicalAccess = Get-SafeValue $logicalInfo.Access
                    }
                    $packages1 += $package
                    
                    # Process members
                    try {
                        $members = Get-ADGroupMember -Identity $group -Recursive @global:adParams | Where-Object { $_.objectClass -eq "user" }
                        
                        foreach ($member in $members) {
                            try {
                                $user = Get-ADUser -Identity $member.distinguishedName -Properties Department, Title, Manager, mail, givenName, surname @global:adParams
                                $manager = if ($user.Manager) { 
                                    try { 
                                        $mgr = Get-ADUser -Identity $user.Manager -Properties DisplayName, mail @global:adParams
                                        @{
                                            Name = Get-SafeValue $mgr.DisplayName
                                            Email = Get-SafeValue $mgr.mail
                                        }
                                    } catch { 
                                        @{ Name = ""; Email = "" }
                                    }
                                } else { 
                                    @{ Name = ""; Email = "" }
                                }
                                
                                $memberObj = [PSCustomObject]@{
                                    FirstName = Get-SafeValue $user.givenName
                                    LastName = Get-SafeValue $user.surname
                                    Email = Get-SafeValue $user.mail
                                    UserID = $user.ObjectGUID.ToString()
                                    Username = "$(Get-SafeValue $user.givenName) $(Get-SafeValue $user.surname)".Trim()
                                    Department = Get-SafeValue $user.Department
                                    JobTitle = Get-SafeValue $user.Title
                                    ManagerName = $manager.Name
                                    ManagerEmail = $manager.Email
                                    ReviewPackageID = $reviewPackageID
                                    DerivedGroup = $group.Name
                                    LogicalAccess = Get-SafeValue $logicalInfo.Access
                                }
                                $packageMembers1 += $memberObj
                            } catch {
                                Write-Warning "Failed to process user '$($member.distinguishedName)': $_"
                            }
                        }
                    } catch {
                        Write-Warning "Failed to get members for group '$($group.Name)': $_"
                    }
                }
                
            } else {
                # LDAP processing
                $groupFilter = "(objectClass=group)"
                $groups = Invoke-LdapSearch -Ldap $global:ldapConnection -BaseDN $baseDN -Filter $groupFilter -Attributes @("cn","description","info","distinguishedName","member")
                
                foreach ($group in $groups) {
                    $groupName = $group.Attributes["cn"][0]
                    $logicalInfo = Get-LogicalGroupInfo -GroupName $groupName -GroupConfig $groupConfig
                    $infoText = if ($group.Attributes["info"]) { $group.Attributes["info"][0] } else { "" }
                    $owners = Get-OwnerEmails -InfoText $infoText -BaseDN $baseDN
                    $groupGuid = Get-SafeObjectGuid $group $true
                    $reviewPackageID = Get-DeterministicGuid "$($logicalInfo.BaseName)|$ReviewID|$groupGuid"
                    
                    # Create package record
                    $package = [PSCustomObject]@{
                        ReviewID = $ReviewID
                        GroupID = $groupGuid
                        ReviewPackageID = $reviewPackageID
                        GroupName = $logicalInfo.BaseName
                        PrimaryOwnerEmail = Get-SafeValue $owners.PrimaryOwner
                        SecondaryOwnerEmail = Get-SafeValue $owners.SecondaryOwner
                        OUPath = $baseDN
                        Tag = $groupConfig.category
                        Description = Get-SafeValue (if ($group.Attributes["description"]) { $group.Attributes["description"][0] } else { "" })
                        LogicalGrouping = $logicalInfo.IsLogical
                        LogicalAccess = Get-SafeValue $logicalInfo.Access
                    }
                    $packages1 += $package
                    
                    # Process members
                    try {
                        if ($group.Attributes["member"]) {
                            foreach ($memberDN in $group.Attributes["member"]) {
                                try {
                                    $userEntry = Invoke-LdapSearch -Ldap $global:ldapConnection -BaseDN $memberDN -Filter "(objectClass=user)" -Attributes @("givenName","sn","mail","department","title","manager","displayName") | Select-Object -First 1
                                    
                                    if ($userEntry) {
                                        $managerName = ""
                                        $managerEmail = ""
                                        
                                        if ($userEntry.Attributes["manager"]) {
                                            try {
                                                $managerEntry = Invoke-LdapSearch -Ldap $global:ldapConnection -BaseDN $userEntry.Attributes["manager"][0] -Filter "(objectClass=user)" -Attributes @("displayName","mail") | Select-Object -First 1
                                                if ($managerEntry) {
                                                    $managerName = Get-SafeValue (if ($managerEntry.Attributes["displayName"]) { $managerEntry.Attributes["displayName"][0] } else { "" })
                                                    $managerEmail = Get-SafeValue (if ($managerEntry.Attributes["mail"]) { $managerEntry.Attributes["mail"][0] } else { "" })
                                                }
                                            } catch {
                                                # Manager lookup failed, continue with empty values
                                            }
                                        }
                                        
                                        $firstName = Get-SafeValue (if ($userEntry.Attributes["givenName"]) { $userEntry.Attributes["givenName"][0] } else { "" })
                                        $lastName = Get-SafeValue (if ($userEntry.Attributes["sn"]) { $userEntry.Attributes["sn"][0] } else { "" })
                                        
                                        $memberObj = [PSCustomObject]@{
                                            FirstName = $firstName
                                            LastName = $lastName
                                            Email = Get-SafeValue (if ($userEntry.Attributes["mail"]) { $userEntry.Attributes["mail"][0] } else { "" })
                                            UserID = Get-SafeObjectGuid $userEntry $true
                                            Username = "$firstName $lastName".Trim()
                                            Department = Get-SafeValue (if ($userEntry.Attributes["department"]) { $userEntry.Attributes["department"][0] } else { "" })
                                            JobTitle = Get-SafeValue (if ($userEntry.Attributes["title"]) { $userEntry.Attributes["title"][0] } else { "" })
                                            ManagerName = $managerName
                                            ManagerEmail = $managerEmail
                                            ReviewPackageID = $reviewPackageID
                                            DerivedGroup = $groupName
                                            LogicalAccess = Get-SafeValue $logicalInfo.Access
                                        }
                                        $packageMembers1 += $memberObj
                                    }
                                } catch {
                                    Write-Warning "Failed to process member '$memberDN': $_"
                                }
                            }
                        }
                    } catch {
                        Write-Warning "Failed to process members for group '$groupName': $_"
                    }
                }
            }
            
        } catch {
            Write-Warning "Failed to process OU '$baseDN': $_"
        }
    }
    
    Write-Host "  Found $($packages1.Count) groups with $($packageMembers1.Count) total members" -ForegroundColor Green
    return @{
        Packages1 = $packages1
        PackageMembers1 = $packageMembers1
    }
}

function Process-Privileges {
    Write-Host "Processing privileges..." -ForegroundColor Cyan
    
    $packages2 = @()
    $privilegeGroups = @()
    
    foreach ($ouPath in $privilegeConfig.ouPaths) {
        Write-Host "  Processing OU: $ouPath" -ForegroundColor Yellow
        
        try {
            if ($global:useADModule) {
                $users = Get-ADUser -Filter * -SearchBase $ouPath -Properties memberOf, DisplayName @global:adParams
                
                foreach ($user in $users) {
                    $userGuid = Get-SafeObjectGuid $user $false
                    $reviewPackageID = Get-DeterministicGuid "$($user.SamAccountName)|$ReviewID|$userGuid"
                    
                    # Create user package record
                    $package = [PSCustomObject]@{
                        ReviewID = $ReviewID
                        GroupID = $userGuid
                        GroupName = Get-SafeValue $user.DisplayName
                        OUPath = $ouPath
                        ReviewPackageID = $reviewPackageID
                    }
                    $packages2 += $package
                    
                    # Process user's group memberships
                    foreach ($groupDN in (if ($user.memberOf) { $user.memberOf } else { @() })) {
                        if ($groupDN -notin $privilegeConfig.exclude) {
                            try {
                                $group = Get-ADGroup -Identity $groupDN -Properties Description @global:adParams
                                $groupGuid = Get-SafeObjectGuid $group $false
                                
                                $privilegeGroup = [PSCustomObject]@{
                                    GroupName = Get-SafeValue $group.Name
                                    GroupID = $groupGuid
                                    ReviewPackageID = $reviewPackageID
                                    Description = Get-SafeValue $group.Description
                                }
                                $privilegeGroups += $privilegeGroup
                            } catch {
                                Write-Warning "Failed to get group info for '$groupDN': $_"
                            }
                        }
                    }
                }
                
            } else {
                # LDAP processing
                $userFilter = "(objectClass=user)"
                $users = Invoke-LdapSearch -Ldap $global:ldapConnection -BaseDN $ouPath -Filter $userFilter -Attributes @("sAMAccountName","displayName","distinguishedName","memberOf")
                
                foreach ($user in $users) {
                    $userGuid = Get-SafeObjectGuid $user $true
                    $samAccountName = Get-SafeValue (if ($user.Attributes["sAMAccountName"]) { $user.Attributes["sAMAccountName"][0] } else { "" })
                    $reviewPackageID = Get-DeterministicGuid "$samAccountName|$ReviewID|$userGuid"
                    
                    # Create user package record
                    $package = [PSCustomObject]@{
                        ReviewID = $ReviewID
                        GroupID = $userGuid
                        GroupName = Get-SafeValue (if ($user.Attributes["displayName"]) { $user.Attributes["displayName"][0] } else { $samAccountName })
                        OUPath = $ouPath
                        ReviewPackageID = $reviewPackageID
                    }
                    $packages2 += $package
                    
                    # Process user's group memberships
                    $memberOf = if ($user.Attributes["memberOf"]) { $user.Attributes["memberOf"] } else { @() }
                    foreach ($groupDN in $memberOf) {
                        if ($groupDN -notin $privilegeConfig.exclude) {
                            try {
                                $groupEntry = Invoke-LdapSearch -Ldap $global:ldapConnection -BaseDN $groupDN -Filter "(objectClass=group)" -Attributes @("cn","description","distinguishedName") | Select-Object -First 1
                                if ($groupEntry) {
                                    $groupGuid = Get-SafeObjectGuid $groupEntry $true
                                    
                                    $privilegeGroup = [PSCustomObject]@{
                                        GroupName = Get-SafeValue (if ($groupEntry.Attributes["cn"]) { $groupEntry.Attributes["cn"][0] } else { "" })
                                        GroupID = $groupGuid
                                        ReviewPackageID = $reviewPackageID
                                        Description = Get-SafeValue (if ($groupEntry.Attributes["description"]) { $groupEntry.Attributes["description"][0] } else { "" })
                                    }
                                    $privilegeGroups += $privilegeGroup
                                }
                            } catch {
                                Write-Warning "Failed to get group info for '$groupDN': $_"
                            }
                        }
                    }
                }
            }
            
        } catch {
            Write-Warning "Failed to process OU '$ouPath': $_"
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
    Write-Host "`nStarting AD Entitlement Review for ReviewID: $ReviewID" -ForegroundColor Green
    Write-Host "=" * 60 -ForegroundColor Green
    
    # Initialize result collections
    $allResults = @{
        Packages1 = @()
        PackageMembers1 = @()
        Packages2 = @()
        PrivilegeGroups = @()
    }
    
    # Process groups if not privilege-only
    if (-not $PrivilegeOnly) {
        $groupResults = Process-Groups
        $allResults.Packages1 = $groupResults.Packages1
        $allResults.PackageMembers1 = $groupResults.PackageMembers1
    }
    
    # Process privileges if not groups-only
    if (-not $GroupsOnly) {
        $privilegeResults = Process-Privileges
        $allResults.Packages2 = $privilegeResults.Packages2
        $allResults.PrivilegeGroups = $privilegeResults.PrivilegeGroups
    }
    
    # Create output directory
    $outputPath = if ($config.OutputFolder -match "^\.\.") {
        Join-Path $scriptPath $config.OutputFolder
    } else {
        $config.OutputFolder
    }
    
    if (-not (Test-Path $outputPath)) {
        New-Item -ItemType Directory -Path $outputPath | Out-Null
        Write-Host "Created output directory: $outputPath" -ForegroundColor Yellow
    }
    
    # Generate output files
    Write-Host "`nGenerating output files..." -ForegroundColor Cyan
    
    $outputFiles = @{
        Packages1 = ($config.OutputFiles.Packages1 -replace '{ReviewId}', $ReviewID)
        PackageMembers1 = ($config.OutputFiles.PackageMembers1 -replace '{ReviewId}', $ReviewID)
        Packages2 = ($config.OutputFiles.Packages2 -replace '{ReviewId}', $ReviewID)
        PrivilegeGroups = ($config.OutputFiles.PrivilegeGroups -replace '{ReviewId}', $ReviewID)
    }
    
    # Export CSV files
    if ($allResults.Packages1.Count -gt 0) {
        $allResults.Packages1 | Export-Csv -Path (Join-Path $outputPath $outputFiles.Packages1) -NoTypeInformation
        Write-Host "  ✓ $($outputFiles.Packages1) ($($allResults.Packages1.Count) records)" -ForegroundColor Green
    }
    
    if ($allResults.PackageMembers1.Count -gt 0) {
        $allResults.PackageMembers1 | Export-Csv -Path (Join-Path $outputPath $outputFiles.PackageMembers1) -NoTypeInformation
        Write-Host "  ✓ $($outputFiles.PackageMembers1) ($($allResults.PackageMembers1.Count) records)" -ForegroundColor Green
    }
    
    if ($allResults.Packages2.Count -gt 0) {
        $allResults.Packages2 | Export-Csv -Path (Join-Path $outputPath $outputFiles.Packages2) -NoTypeInformation
        Write-Host "  ✓ $($outputFiles.Packages2) ($($allResults.Packages2.Count) records)" -ForegroundColor Green
    }
    
    if ($allResults.PrivilegeGroups.Count -gt 0) {
        $allResults.PrivilegeGroups | Export-Csv -Path (Join-Path $outputPath $outputFiles.PrivilegeGroups) -NoTypeInformation
        Write-Host "  ✓ $($outputFiles.PrivilegeGroups) ($($allResults.PrivilegeGroups.Count) records)" -ForegroundColor Green
    }
    
    Write-Host "`n" + "=" * 60 -ForegroundColor Green
    Write-Host "✓ AD Entitlement Review completed successfully!" -ForegroundColor Green
    Write-Host "Output files saved to: $outputPath" -ForegroundColor Yellow
    
} catch {
    Write-Host "`n" + "=" * 60 -ForegroundColor Red
    Write-Error "❌ AD Entitlement Review failed: $_"
    Write-Host "Check the error details above and verify your configuration." -ForegroundColor Red
    exit 1
} finally {
    # Cleanup connections
    if ($global:ldapConnection) {
        try { $global:ldapConnection.Dispose() } catch { }
    }
}
#endregion 