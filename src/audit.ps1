# AD Entitlement Review Script - PowerShell 5.1 Compatible
# Simple, clean implementation without modern syntax

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ReviewID,
    
    [switch]$GroupsOnly,
    [switch]$PrivilegeOnly,
    [string]$ConfigPath
)

$ErrorActionPreference = "Stop"

# Get script path
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

# Set config path
if (-not $ConfigPath) {
    $ConfigPath = Join-Path $scriptPath "..\configs"
}

Write-Host "=== AD Entitlement Review System ===" -ForegroundColor Cyan
Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Yellow
Write-Host "Review ID: $ReviewID" -ForegroundColor Green

# Import LDAP module
try {
    $ldapModulePath = Join-Path $scriptPath "Modules\LDAP.psm1"
    Import-Module $ldapModulePath -Force
    Write-Host "LDAP module loaded successfully" -ForegroundColor Green
}
catch {
    Write-Error "Failed to load LDAP module: $($_.Exception.Message)"
    exit 1
}

# Load configurations
Write-Host "Loading configurations..." -ForegroundColor Cyan

try {
    $configFile = Join-Path $ConfigPath "config.json"
    $configContent = Get-Content $configFile -Raw
    $config = ConvertFrom-Json $configContent
    Write-Host "Main config loaded" -ForegroundColor Green
    
    $groupsFile = Join-Path $ConfigPath "groups.json"
    $groupsContent = Get-Content $groupsFile -Raw
    $groupsConfig = ConvertFrom-Json $groupsContent
    Write-Host "Groups config loaded" -ForegroundColor Green
    
    $privilegeFile = Join-Path $ConfigPath "privilege.json"
    $privilegeContent = Get-Content $privilegeFile -Raw
    $privilegeConfig = ConvertFrom-Json $privilegeContent
    Write-Host "Privilege config loaded" -ForegroundColor Green
}
catch {
    Write-Error "Configuration loading failed: $($_.Exception.Message)"
    exit 1
}

# Helper functions
function Get-SafeValue {
    param($Value, $Default = "")
    if ($Value -eq $null) { return $Default }
    if ([string]::IsNullOrEmpty($Value)) { return $Default }
    return $Value.ToString()
}

function New-SimpleGuid {
    param([string]$Input)
    
    if ([string]::IsNullOrWhiteSpace($Input)) {
        return [System.Guid]::NewGuid().ToString()
    }
    
    try {
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        $inputBytes = [System.Text.Encoding]::UTF8.GetBytes($Input)
        $hashBytes = $hasher.ComputeHash($inputBytes)
        
        $guidBytes = New-Object byte[] 16
        for ($i = 0; $i -lt 16; $i++) {
            $guidBytes[$i] = $hashBytes[$i]
        }
        
        $guid = New-Object System.Guid -ArgumentList $guidBytes
        $hasher.Dispose()
        return $guid.ToString()
    }
    catch {
        return [System.Guid]::NewGuid().ToString()
    }
}

function Get-SimpleObjectGuid {
    param($Object, [bool]$IsLdap = $false)
    
    try {
        if ($IsLdap) {
            if ($Object.Attributes["objectGUID"] -and $Object.Attributes["objectGUID"].Count -gt 0) {
                $guidBytes = $Object.Attributes["objectGUID"][0]
                $guid = New-Object System.Guid -ArgumentList $guidBytes
                return $guid.ToString()
            }
            if ($Object.Attributes["distinguishedName"] -and $Object.Attributes["distinguishedName"].Count -gt 0) {
                return New-SimpleGuid $Object.Attributes["distinguishedName"][0]
            }
        }
        else {
            if ($Object.ObjectGUID) {
                return $Object.ObjectGUID.ToString()
            }
        }
        return New-SimpleGuid $Object.ToString()
    }
    catch {
        return New-SimpleGuid $Object.ToString()
    }
}

# Connection setup
Write-Host "Establishing connection..." -ForegroundColor Cyan

$useADModule = $false
$ldapConnection = $null
$adParams = @{}

$connectionType = "LDAP"
if ($config.Connection.Type) {
    $connectionType = $config.Connection.Type.ToUpper()
}

Write-Host "Connection type: $connectionType" -ForegroundColor Yellow

try {
    if ($connectionType -eq "ACTIVEDIRECTORY") {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $adParams.Server = $config.DomainController
            
            if (-not $config.Connection.UseCurrentUser) {
                $securePassword = ConvertTo-SecureString $config.Connection.CredentialProfile.Password -AsPlainText -Force
                $domainUser = "$($config.Connection.CredentialProfile.Domain)\$($config.Connection.CredentialProfile.Username)"
                $credential = New-Object System.Management.Automation.PSCredential($domainUser, $securePassword)
                $adParams.Credential = $credential
            }
            
            $null = Get-ADDomain @adParams
            $useADModule = $true
            Write-Host "Connected using ActiveDirectory module" -ForegroundColor Green
        }
        catch {
            Write-Warning "ActiveDirectory module failed, using LDAP"
            $connectionType = "LDAP"
        }
    }
    
    if ($connectionType -eq "LDAP" -or $connectionType -eq "LDAPS") {
        $useLDAPS = ($connectionType -eq "LDAPS")
        $ldapConnection = New-LdapConnection -Server $config.DomainController -UseLDAPS $useLDAPS -UseCurrentUser $config.Connection.UseCurrentUser -Username $config.Connection.CredentialProfile.Username -Password $config.Connection.CredentialProfile.Password -Domain $config.Connection.CredentialProfile.Domain
        $useADModule = $false
        Write-Host "Connected using $connectionType" -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to establish connection: $($_.Exception.Message)"
    exit 1
}

# Initialize data arrays
$packages1 = @()           # Reverification System Packages 1
$packageMembers1 = @()     # Reverification Package Members 1
$packages2 = @()           # Reverification System Packages 1-2 (privilege users)
$privilegeGroups = @()     # Reverification Privilege Groups 1

# Helper function to extract owner information using regex
function Get-OwnerInformation {
    param(
        [string]$InfoText,
        [array]$RegexPatterns
    )
    
    $result = @{
        PrimaryOwnerEmail = ""
        SecondaryOwnerEmail = ""
    }
    
    if ([string]::IsNullOrEmpty($InfoText)) {
        return $result
    }
    
    # Try different regex patterns for primary owner email
    $primaryPatterns = @(
        "Primary Owner:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        "P:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        "Primary:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
    )
    
    foreach ($pattern in $primaryPatterns) {
        if ($InfoText -match $pattern) {
            $result.PrimaryOwnerEmail = $Matches[1]
            break
        }
    }
    
    # Try different regex patterns for secondary owner email
    $secondaryPatterns = @(
        "Secondary Owner:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        "S:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        "Secondary:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
    )
    
    foreach ($pattern in $secondaryPatterns) {
        if ($InfoText -match $pattern) {
            $result.SecondaryOwnerEmail = $Matches[1]
            break
        }
    }
    
    return $result
}

# Helper function to determine logical grouping
function Get-LogicalGroupInfo {
    param(
        [string]$GroupName,
        [object]$LogicalConfig
    )
    
    $result = @{
        IsLogical = $false
        BaseName = $GroupName
        LogicalAccess = ""
        Suffix = ""
    }
    
    if (-not $LogicalConfig.isLogical) {
        return $result
    }
    
    foreach ($suffix in $LogicalConfig.grouping.PSObject.Properties.Name) {
        if ($GroupName.EndsWith($suffix)) {
            $result.IsLogical = $true
            $result.BaseName = $GroupName.Substring(0, $GroupName.Length - $suffix.Length)
            $result.LogicalAccess = $LogicalConfig.grouping.$suffix
            $result.Suffix = $suffix
            break
        }
    }
    
    return $result
}

# Process groups
Write-Host "Processing groups..." -ForegroundColor Cyan

foreach ($groupConfig in $groupsConfig.groups) {
    $ouPath = $groupConfig.path
    $category = $groupConfig.category
    $logicalConfig = $groupConfig.Logical
    
    Write-Host "Processing OU: $ouPath (Category: $category)" -ForegroundColor Yellow
    
    try {
        if ($useADModule) {
            # Get all groups in the OU
            $groups = Get-ADGroup -Filter * -SearchBase $ouPath -Properties Name, Description, Info, Members @adParams
            
            # Group logical groups together
            $logicalGroups = @{}
            $standaloneGroups = @()
            
            foreach ($group in $groups) {
                $logicalInfo = Get-LogicalGroupInfo -GroupName $group.Name -LogicalConfig $logicalConfig
                
                if ($logicalInfo.IsLogical) {
                    if (-not $logicalGroups.ContainsKey($logicalInfo.BaseName)) {
                        $logicalGroups[$logicalInfo.BaseName] = @{
                            BaseName = $logicalInfo.BaseName
                            Groups = @()
                            Category = $category
                            OUPath = $ouPath
                        }
                    }
                    $logicalGroups[$logicalInfo.BaseName].Groups += @{
                        Group = $group
                        LogicalAccess = $logicalInfo.LogicalAccess
                        Suffix = $logicalInfo.Suffix
                    }
                } else {
                    $standaloneGroups += $group
                }
            }
            
            # Process logical groups
            foreach ($logicalGroupName in $logicalGroups.Keys) {
                $logicalGroup = $logicalGroups[$logicalGroupName]
                
                # Use the first group for common properties like description and owners
                $primaryGroup = $logicalGroup.Groups[0].Group
                $groupGuid = Get-SimpleObjectGuid $primaryGroup $false
                $reviewPackageID = New-SimpleGuid "$($logicalGroup.BaseName)|$ReviewID|$groupGuid"
                
                # Extract owner information
                $ownerInfo = Get-OwnerInformation -InfoText (Get-SafeValue $primaryGroup.Info) -RegexPatterns $groupsConfig.ownerRegexPatterns
                
                # Create package record
                $package = New-Object PSObject
                $package | Add-Member -MemberType NoteProperty -Name "ReviewID" -Value $ReviewID
                $package | Add-Member -MemberType NoteProperty -Name "GroupID" -Value $groupGuid
                $package | Add-Member -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                $package | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $logicalGroup.BaseName
                $package | Add-Member -MemberType NoteProperty -Name "PrimaryOwnerEmail" -Value $ownerInfo.PrimaryOwnerEmail
                $package | Add-Member -MemberType NoteProperty -Name "SecondaryOwnerEmail" -Value $ownerInfo.SecondaryOwnerEmail
                $package | Add-Member -MemberType NoteProperty -Name "OUPath" -Value $ouPath
                $package | Add-Member -MemberType NoteProperty -Name "Tag" -Value $category
                $package | Add-Member -MemberType NoteProperty -Name "Description" -Value (Get-SafeValue $primaryGroup.Description)
                $package | Add-Member -MemberType NoteProperty -Name "LogicalGrouping" -Value $true
                $package | Add-Member -MemberType NoteProperty -Name "LogicalAccess" -Value ""  # Empty for logical parent
                
                $packages1 += $package
                
                # Process members from all subgroups
                foreach ($subGroupInfo in $logicalGroup.Groups) {
                    $subGroup = $subGroupInfo.Group
                    $logicalAccess = $subGroupInfo.LogicalAccess
                    
                    try {
                        # Get direct members first
                        $directMembers = Get-ADGroupMember -Identity $subGroup @adParams
                        
                        foreach ($directMember in $directMembers) {
                            if ($directMember.objectClass -eq "user") {
                                # Direct user member
                                try {
                                    $user = Get-ADUser -Identity $directMember.distinguishedName -Properties mail, givenName, surname, SamAccountName, Department, Title, Manager @adParams
                                    
                                    # Get manager information
                                    $managerName = ""
                                    $managerEmail = ""
                                    if ($user.Manager) {
                                        try {
                                            $manager = Get-ADUser -Identity $user.Manager -Properties DisplayName, mail @adParams
                                            $managerName = Get-SafeValue $manager.DisplayName
                                            $managerEmail = Get-SafeValue $manager.mail
                                        } catch {
                                            Write-Warning "Failed to get manager info: $($_.Exception.Message)"
                                        }
                                    }
                                    
                                    $memberObj = New-Object PSObject
                                    $memberObj | Add-Member -MemberType NoteProperty -Name "FirstName" -Value (Get-SafeValue $user.givenName)
                                    $memberObj | Add-Member -MemberType NoteProperty -Name "LastName" -Value (Get-SafeValue $user.surname)
                                    $memberObj | Add-Member -MemberType NoteProperty -Name "Username" -Value "$((Get-SafeValue $user.givenName)) $((Get-SafeValue $user.surname))"
                                    $memberObj | Add-Member -MemberType NoteProperty -Name "Email" -Value (Get-SafeValue $user.mail)
                                    $memberObj | Add-Member -MemberType NoteProperty -Name "UserID" -Value $user.ObjectGUID.ToString()
                                    $memberObj | Add-Member -MemberType NoteProperty -Name "Department" -Value (Get-SafeValue $user.Department)
                                    $memberObj | Add-Member -MemberType NoteProperty -Name "JobTitle" -Value (Get-SafeValue $user.Title)
                                    $memberObj | Add-Member -MemberType NoteProperty -Name "ManagerName" -Value $managerName
                                    $memberObj | Add-Member -MemberType NoteProperty -Name "ManagerEmail" -Value $managerEmail
                                    $memberObj | Add-Member -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                                    $memberObj | Add-Member -MemberType NoteProperty -Name "DerivedGroup" -Value ""  # Direct member
                                    $memberObj | Add-Member -MemberType NoteProperty -Name "LogicalAccess" -Value $logicalAccess
                                    
                                    $packageMembers1 += $memberObj
                                }
                                catch {
                                    Write-Warning "Failed to process user: $($_.Exception.Message)"
                                }
                            }
                            elseif ($directMember.objectClass -eq "group") {
                                # Nested group - get its members
                                try {
                                    $nestedGroup = Get-ADGroup -Identity $directMember.distinguishedName @adParams
                                    $nestedMembers = Get-ADGroupMember -Identity $nestedGroup -Recursive @adParams | Where-Object { $_.objectClass -eq "user" }
                                    
                                    foreach ($nestedMember in $nestedMembers) {
                                        try {
                                            $user = Get-ADUser -Identity $nestedMember.distinguishedName -Properties mail, givenName, surname, SamAccountName, Department, Title, Manager @adParams
                                            
                                            # Get manager information
                                            $managerName = ""
                                            $managerEmail = ""
                                            if ($user.Manager) {
                                                try {
                                                    $manager = Get-ADUser -Identity $user.Manager -Properties DisplayName, mail @adParams
                                                    $managerName = Get-SafeValue $manager.DisplayName
                                                    $managerEmail = Get-SafeValue $manager.mail
                                                } catch {
                                                    Write-Warning "Failed to get manager info: $($_.Exception.Message)"
                                                }
                                            }
                                            
                                            $memberObj = New-Object PSObject
                                            $memberObj | Add-Member -MemberType NoteProperty -Name "FirstName" -Value (Get-SafeValue $user.givenName)
                                            $memberObj | Add-Member -MemberType NoteProperty -Name "LastName" -Value (Get-SafeValue $user.surname)
                                            $memberObj | Add-Member -MemberType NoteProperty -Name "Username" -Value "$((Get-SafeValue $user.givenName)) $((Get-SafeValue $user.surname))"
                                            $memberObj | Add-Member -MemberType NoteProperty -Name "Email" -Value (Get-SafeValue $user.mail)
                                            $memberObj | Add-Member -MemberType NoteProperty -Name "UserID" -Value $user.ObjectGUID.ToString()
                                            $memberObj | Add-Member -MemberType NoteProperty -Name "Department" -Value (Get-SafeValue $user.Department)
                                            $memberObj | Add-Member -MemberType NoteProperty -Name "JobTitle" -Value (Get-SafeValue $user.Title)
                                            $memberObj | Add-Member -MemberType NoteProperty -Name "ManagerName" -Value $managerName
                                            $memberObj | Add-Member -MemberType NoteProperty -Name "ManagerEmail" -Value $managerEmail
                                            $memberObj | Add-Member -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                                            $memberObj | Add-Member -MemberType NoteProperty -Name "DerivedGroup" -Value $nestedGroup.Name  # Intermediate group
                                            $memberObj | Add-Member -MemberType NoteProperty -Name "LogicalAccess" -Value $logicalAccess
                                            
                                            $packageMembers1 += $memberObj
                                        }
                                        catch {
                                            Write-Warning "Failed to process nested user: $($_.Exception.Message)"
                                        }
                                    }
                                }
                                catch {
                                    Write-Warning "Failed to process nested group: $($_.Exception.Message)"
                                }
                            }
                        }
                    }
                    catch {
                        Write-Warning "Failed to get group members: $($_.Exception.Message)"
                    }
                }
            }
            
            # Process standalone (non-logical) groups
            foreach ($group in $standaloneGroups) {
                $groupGuid = Get-SimpleObjectGuid $group $false
                $reviewPackageID = New-SimpleGuid "$($group.Name)|$ReviewID|$groupGuid"
                
                # Extract owner information
                $ownerInfo = Get-OwnerInformation -InfoText (Get-SafeValue $group.Info) -RegexPatterns $groupsConfig.ownerRegexPatterns
                
                # Create package record
                $package = New-Object PSObject
                $package | Add-Member -MemberType NoteProperty -Name "ReviewID" -Value $ReviewID
                $package | Add-Member -MemberType NoteProperty -Name "GroupID" -Value $groupGuid
                $package | Add-Member -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                $package | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $group.Name
                $package | Add-Member -MemberType NoteProperty -Name "PrimaryOwnerEmail" -Value $ownerInfo.PrimaryOwnerEmail
                $package | Add-Member -MemberType NoteProperty -Name "SecondaryOwnerEmail" -Value $ownerInfo.SecondaryOwnerEmail
                $package | Add-Member -MemberType NoteProperty -Name "OUPath" -Value $ouPath
                $package | Add-Member -MemberType NoteProperty -Name "Tag" -Value $category
                $package | Add-Member -MemberType NoteProperty -Name "Description" -Value (Get-SafeValue $group.Description)
                $package | Add-Member -MemberType NoteProperty -Name "LogicalGrouping" -Value $false
                $package | Add-Member -MemberType NoteProperty -Name "LogicalAccess" -Value ""
                
                $packages1 += $package
                
                # Process group members (same logic as above but without logical access)
                try {
                    $directMembers = Get-ADGroupMember -Identity $group @adParams
                    
                    foreach ($directMember in $directMembers) {
                        if ($directMember.objectClass -eq "user") {
                            try {
                                $user = Get-ADUser -Identity $directMember.distinguishedName -Properties mail, givenName, surname, SamAccountName, Department, Title, Manager @adParams
                                
                                # Get manager information
                                $managerName = ""
                                $managerEmail = ""
                                if ($user.Manager) {
                                    try {
                                        $manager = Get-ADUser -Identity $user.Manager -Properties DisplayName, mail @adParams
                                        $managerName = Get-SafeValue $manager.DisplayName
                                        $managerEmail = Get-SafeValue $manager.mail
                                    } catch {
                                        Write-Warning "Failed to get manager info: $($_.Exception.Message)"
                                    }
                                }
                                
                                $memberObj = New-Object PSObject
                                $memberObj | Add-Member -MemberType NoteProperty -Name "FirstName" -Value (Get-SafeValue $user.givenName)
                                $memberObj | Add-Member -MemberType NoteProperty -Name "LastName" -Value (Get-SafeValue $user.surname)
                                $memberObj | Add-Member -MemberType NoteProperty -Name "Username" -Value "$((Get-SafeValue $user.givenName)) $((Get-SafeValue $user.surname))"
                                $memberObj | Add-Member -MemberType NoteProperty -Name "Email" -Value (Get-SafeValue $user.mail)
                                $memberObj | Add-Member -MemberType NoteProperty -Name "UserID" -Value $user.ObjectGUID.ToString()
                                $memberObj | Add-Member -MemberType NoteProperty -Name "Department" -Value (Get-SafeValue $user.Department)
                                $memberObj | Add-Member -MemberType NoteProperty -Name "JobTitle" -Value (Get-SafeValue $user.Title)
                                $memberObj | Add-Member -MemberType NoteProperty -Name "ManagerName" -Value $managerName
                                $memberObj | Add-Member -MemberType NoteProperty -Name "ManagerEmail" -Value $managerEmail
                                $memberObj | Add-Member -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                                $memberObj | Add-Member -MemberType NoteProperty -Name "DerivedGroup" -Value ""
                                $memberObj | Add-Member -MemberType NoteProperty -Name "LogicalAccess" -Value ""
                                
                                $packageMembers1 += $memberObj
                            }
                            catch {
                                Write-Warning "Failed to process user: $($_.Exception.Message)"
                            }
                        }
                        elseif ($directMember.objectClass -eq "group") {
                            try {
                                $nestedGroup = Get-ADGroup -Identity $directMember.distinguishedName @adParams
                                $nestedMembers = Get-ADGroupMember -Identity $nestedGroup -Recursive @adParams | Where-Object { $_.objectClass -eq "user" }
                                
                                foreach ($nestedMember in $nestedMembers) {
                                    try {
                                        $user = Get-ADUser -Identity $nestedMember.distinguishedName -Properties mail, givenName, surname, SamAccountName, Department, Title, Manager @adParams
                                        
                                        # Get manager information
                                        $managerName = ""
                                        $managerEmail = ""
                                        if ($user.Manager) {
                                            try {
                                                $manager = Get-ADUser -Identity $user.Manager -Properties DisplayName, mail @adParams
                                                $managerName = Get-SafeValue $manager.DisplayName
                                                $managerEmail = Get-SafeValue $manager.mail
                                            } catch {
                                                Write-Warning "Failed to get manager info: $($_.Exception.Message)"
                                            }
                                        }
                                        
                                        $memberObj = New-Object PSObject
                                        $memberObj | Add-Member -MemberType NoteProperty -Name "FirstName" -Value (Get-SafeValue $user.givenName)
                                        $memberObj | Add-Member -MemberType NoteProperty -Name "LastName" -Value (Get-SafeValue $user.surname)
                                        $memberObj | Add-Member -MemberType NoteProperty -Name "Username" -Value "$((Get-SafeValue $user.givenName)) $((Get-SafeValue $user.surname))"
                                        $memberObj | Add-Member -MemberType NoteProperty -Name "Email" -Value (Get-SafeValue $user.mail)
                                        $memberObj | Add-Member -MemberType NoteProperty -Name "UserID" -Value $user.ObjectGUID.ToString()
                                        $memberObj | Add-Member -MemberType NoteProperty -Name "Department" -Value (Get-SafeValue $user.Department)
                                        $memberObj | Add-Member -MemberType NoteProperty -Name "JobTitle" -Value (Get-SafeValue $user.Title)
                                        $memberObj | Add-Member -MemberType NoteProperty -Name "ManagerName" -Value $managerName
                                        $memberObj | Add-Member -MemberType NoteProperty -Name "ManagerEmail" -Value $managerEmail
                                        $memberObj | Add-Member -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                                        $memberObj | Add-Member -MemberType NoteProperty -Name "DerivedGroup" -Value $nestedGroup.Name
                                        $memberObj | Add-Member -MemberType NoteProperty -Name "LogicalAccess" -Value ""
                                        
                                        $packageMembers1 += $memberObj
                                    }
                                    catch {
                                        Write-Warning "Failed to process nested user: $($_.Exception.Message)"
                                    }
                                }
                            }
                            catch {
                                Write-Warning "Failed to process nested group: $($_.Exception.Message)"
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Failed to get group members: $($_.Exception.Message)"
                }
            }
        }
        else {
            # LDAP processing would go here - similar logic but using LDAP calls
            Write-Host "LDAP processing for new specification not yet implemented" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Warning "Failed to process OU: $($_.Exception.Message)"
    }
}

Write-Host "Found $($packages1.Count) groups with $($packageMembers1.Count) members" -ForegroundColor Green

# Process privileges
if (-not $GroupsOnly) {
    Write-Host "Processing privileges..." -ForegroundColor Cyan
    
    foreach ($ouPath in $privilegeConfig.ouPaths) {
        Write-Host "Processing OU: $ouPath" -ForegroundColor Yellow
        
        try {
            if ($useADModule) {
                # Get all users in the OU with required attributes
                $users = Get-ADUser -Filter * -SearchBase $ouPath -Properties $privilegeConfig.userAttributes @adParams
                
                foreach ($user in $users) {
                    # Skip disabled users if configured
                    if (-not $privilegeConfig.processingOptions.includeDisabledUsers -and -not $user.enabled) {
                        continue
                    }
                    
                    $userGuid = Get-SimpleObjectGuid $user $false
                    $reviewPackageID = New-SimpleGuid "$($user.SamAccountName)|$ReviewID|$userGuid"
                    
                    # Create user package (Reverification System Packages 1-2)
                    $package = New-Object PSObject
                    $package | Add-Member -MemberType NoteProperty -Name "ReviewID" -Value $ReviewID
                    $package | Add-Member -MemberType NoteProperty -Name "GroupID" -Value $userGuid
                    $package | Add-Member -MemberType NoteProperty -Name "GroupName" -Value (Get-SafeValue $user.DisplayName)
                    $package | Add-Member -MemberType NoteProperty -Name "OUPath" -Value $ouPath
                    
                    $packages2 += $package
                    
                    # Process user's group memberships
                    if ($user.memberOf) {
                        foreach ($groupDN in $user.memberOf) {
                            # Check if group should be excluded
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
                                    $groupGuid = Get-SimpleObjectGuid $group $false
                                    
                                    # Create privilege group record (Reverification Privilege Groups 1)
                                    $privilegeGroup = New-Object PSObject
                                    $privilegeGroup | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $group.Name
                                    $privilegeGroup | Add-Member -MemberType NoteProperty -Name "GroupID" -Value $groupGuid
                                    $privilegeGroup | Add-Member -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                                    $privilegeGroup | Add-Member -MemberType NoteProperty -Name "Description" -Value (Get-SafeValue $group.Description)
                                    
                                    $privilegeGroups += $privilegeGroup
                                }
                                catch {
                                    Write-Warning "Failed to get group info for $groupDN : $($_.Exception.Message)"
                                }
                            }
                        }
                    }
                }
            }
            else {
                # LDAP processing for privileges would go here
                Write-Host "LDAP processing for privilege specification not yet implemented" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Warning "Failed to process privilege OU: $($_.Exception.Message)"
        }
    }
    
    Write-Host "Found $($packages2.Count) users with $($privilegeGroups.Count) group memberships" -ForegroundColor Green
}

# Generate output
Write-Host "Generating output files..." -ForegroundColor Cyan

$outputPath = $config.OutputFolder
if ($config.OutputFolder -match "^\.\.") {
    $outputPath = Join-Path $scriptPath $config.OutputFolder
}

if (-not (Test-Path $outputPath)) {
    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
    Write-Host "Created output directory: $outputPath" -ForegroundColor Yellow
}

$outputFiles = @{
    Packages1 = $config.OutputFiles.Packages1 -replace '{ReviewId}', $ReviewID
    PackageMembers1 = $config.OutputFiles.PackageMembers1 -replace '{ReviewId}', $ReviewID
    Packages2 = $config.OutputFiles.Packages2 -replace '{ReviewId}', $ReviewID
    PrivilegeGroups = $config.OutputFiles.PrivilegeGroups -replace '{ReviewId}', $ReviewID
}

if ($packages1.Count -gt 0) {
    $filePath = Join-Path $outputPath $outputFiles.Packages1
    $packages1 | Export-Csv -Path $filePath -NoTypeInformation
    Write-Host "Exported $($outputFiles.Packages1) with $($packages1.Count) records" -ForegroundColor Green
}

if ($packageMembers1.Count -gt 0) {
    $filePath = Join-Path $outputPath $outputFiles.PackageMembers1
    $packageMembers1 | Export-Csv -Path $filePath -NoTypeInformation
    Write-Host "Exported $($outputFiles.PackageMembers1) with $($packageMembers1.Count) records" -ForegroundColor Green
}

if ($packages2.Count -gt 0) {
    $filePath = Join-Path $outputPath $outputFiles.Packages2
    $packages2 | Export-Csv -Path $filePath -NoTypeInformation
    Write-Host "Exported $($outputFiles.Packages2) with $($packages2.Count) records" -ForegroundColor Green
}

if ($privilegeGroups.Count -gt 0) {
    $filePath = Join-Path $outputPath $outputFiles.PrivilegeGroups
    $privilegeGroups | Export-Csv -Path $filePath -NoTypeInformation
    Write-Host "Exported $($outputFiles.PrivilegeGroups) with $($privilegeGroups.Count) records" -ForegroundColor Green
}

Write-Host ""
Write-Host "AD Entitlement Review completed successfully!" -ForegroundColor Green
Write-Host "Output files saved to: $outputPath" -ForegroundColor Yellow

# Cleanup
if ($ldapConnection) {
    try {
        $ldapConnection.Dispose()
    }
    catch {
        # Ignore disposal errors
    }
}

Write-Host "Script execution completed." -ForegroundColor Gray 
