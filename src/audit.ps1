# AD Entitlement Review Script (PS5.1)

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ReviewID,
    
    [switch]$GroupsOnly,
    [switch]$PrivilegeOnly,
    [switch]$Skip,
    [string]$ConfigPath,
    [string]$Output,
    [string]$Name
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

# Display output configuration
if ($Output) {
    Write-Host "Output Folder: $Output (custom)" -ForegroundColor Yellow
} else {
    Write-Host "Output Folder: Using config.json setting" -ForegroundColor Yellow
}

if ($Name) {
    Write-Host "File Names: Using custom prefix '$Name'" -ForegroundColor Yellow
} else {
    Write-Host "File Names: Using config.json templates" -ForegroundColor Yellow
}

# Display processing mode
if ($PrivilegeOnly) {
    Write-Host "Processing Mode: PRIVILEGE ONLY" -ForegroundColor Magenta
} elseif ($GroupsOnly) {
    Write-Host "Processing Mode: GROUPS ONLY" -ForegroundColor Magenta
} else {
    Write-Host "Processing Mode: FULL AUDIT (Groups + Privileges)" -ForegroundColor Magenta
}

# Import LDAP module
try {
    $ldapModulePath = Join-Path $scriptPath "Modules\LDAP.psm1"
    Import-Module $ldapModulePath -Force
    Write-Host "LDAP module loaded successfully" -ForegroundColor Green

    # Import utility helpers (Get-SafeValue, New-SimpleGuid, etc.)
    $utilsModulePath = Join-Path $scriptPath "Modules\Utils.psm1"
    Import-Module $utilsModulePath -Force
    Write-Host "Utils module loaded successfully" -ForegroundColor Green
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

    # Start transcript logging to file

    $logFolder = $config.OutputFolder
    if ($logFolder -match "^\.\.") {
        $logFolder = Join-Path $scriptPath $logFolder
    }

    if (-not (Test-Path $logFolder)) {
        New-Item -ItemType Directory -Path $logFolder -Force | Out-Null
        }
        
    $Global:AuditLogFile = Join-Path $logFolder ("AuditLog_" + $ReviewID + ".log")
    
    try {
        Start-Transcript -Path $Global:AuditLogFile -Append | Out-Null
        Write-Host "Transcript logging started → $Global:AuditLogFile" -ForegroundColor Yellow
        $TranscriptStarted = $true
    }
    catch {
        Write-Warning "Failed to start transcript logging: $($_.Exception.Message)"
    }
    }
    catch {
    Write-Error "Configuration loading failed: $($_.Exception.Message)"
    exit 1
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
            Write-Warning "ActiveDirectory module failed, falling back to LDAP/LDAPS"
            $connectionType = if ($config.Connection.UseLDAPS) { "LDAPS" } else { "LDAP" }
        }
    }
    
    if ($connectionType -eq "LDAP" -or $connectionType -eq "LDAPS") {
        # Honour explicit setting from config when present
        $useLDAPS = if ($null -ne $config.Connection.UseLDAPS) { [bool]$config.Connection.UseLDAPS } else { ($connectionType -eq "LDAPS") }
        $ldapConnection = New-LdapConnection -Server $config.DomainController -UseLDAPS $useLDAPS -UseCurrentUser $config.Connection.UseCurrentUser -Username $config.Connection.CredentialProfile.Username -Password $config.Connection.CredentialProfile.Password -Domain $config.Connection.CredentialProfile.Domain
        $useADModule = $false
        Write-Host "Connected using $connectionType" -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to establish connection: $($_.Exception.Message)"
    exit 1
}

# Display configuration summary and get user confirmation
Write-Host ""
Write-Host "=== CONFIGURATION SUMMARY ===" -ForegroundColor Cyan
Write-Host ""

# Display general configuration
Write-Host "GENERAL CONFIGURATION:" -ForegroundColor Yellow
Write-Host "────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "Review ID: $ReviewID" -ForegroundColor White
Write-Host "Connection Type: $connectionType" -ForegroundColor White
Write-Host "Domain Controller: $($config.DomainController)" -ForegroundColor White

$processingModeText = if ($PrivilegeOnly) { "PRIVILEGE ONLY" } elseif ($GroupsOnly) { "GROUPS ONLY" } else { "FULL AUDIT (Groups + Privileges)" }
Write-Host "Processing Mode: $processingModeText" -ForegroundColor White
Write-Host "────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""

# Display groups configuration
if (-not $PrivilegeOnly) {
    Write-Host "GROUPS CONFIGURATION:" -ForegroundColor Yellow
    Write-Host "────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    
    foreach ($groupConfig in $groupsConfig.groups) {
        Write-Host ""
        Write-Host "OU Path: $($groupConfig.path)" -ForegroundColor White
        Write-Host "Category: $($groupConfig.category)" -ForegroundColor White
        
        $logicalConfig = $groupConfig.Logical
        if ($logicalConfig.isLogical) {
            Write-Host "Logical Grouping: YES" -ForegroundColor Green
            Write-Host "Immutable: $($logicalConfig.Immutable)" -ForegroundColor $(if ($logicalConfig.Immutable) { "Green" } else { "Yellow" })
            
            if ($logicalConfig.Supercede -and -not $logicalConfig.Immutable) {
                Write-Host "Supercede Access: $($logicalConfig.Supercede)" -ForegroundColor Cyan
            } elseif ($logicalConfig.Immutable) {
                Write-Host "Supercede Access: IGNORED (Immutable=true)" -ForegroundColor DarkGray
            }
            
            Write-Host ""
            Write-Host "Logical Access Mappings:" -ForegroundColor Cyan
            Write-Host "┌─────────────────┬─────────────────────┐" -ForegroundColor DarkGray
            Write-Host "│ Suffix          │ Access Level        │" -ForegroundColor DarkGray
            Write-Host "├─────────────────┼─────────────────────┤" -ForegroundColor DarkGray
            
            foreach ($suffix in $logicalConfig.grouping.PSObject.Properties.Name | Sort-Object) {
                $accessLevel = $logicalConfig.grouping.$suffix
                $suffixPadded = $suffix.PadRight(15)
                $accessPadded = $accessLevel.PadRight(19)
                Write-Host "│ $suffixPadded │ $accessPadded │" -ForegroundColor White
            }
            Write-Host "└─────────────────┴─────────────────────┘" -ForegroundColor DarkGray
        } else {
            Write-Host "Logical Grouping: NO" -ForegroundColor Yellow
            Write-Host "Immutable: N/A" -ForegroundColor DarkGray
        }
        
        Write-Host "────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    }
}

# Display privilege configuration
if (-not $GroupsOnly) {
    Write-Host ""
    Write-Host "PRIVILEGE CONFIGURATION:" -ForegroundColor Yellow
    Write-Host "────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    
    foreach ($ouPath in $privilegeConfig.ouPaths) {
        Write-Host "OU Path: $ouPath" -ForegroundColor White
    }
    
    Write-Host ""
    Write-Host "Processing Options:" -ForegroundColor Cyan
    Write-Host "• Include Disabled Users: $($privilegeConfig.processingOptions.includeDisabledUsers)" -ForegroundColor White
    Write-Host "• Max Users Per OU: $($privilegeConfig.processingOptions.maxUsersPerOU)" -ForegroundColor White
    Write-Host "• Query Timeout: $($privilegeConfig.processingOptions.queryTimeoutSeconds) seconds" -ForegroundColor White
    
    Write-Host "────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
}

Write-Host ""

# Confirmation prompt (skip if -Skip flag is used)
if ($Skip) {
    Write-Host "Confirmation prompt skipped (using -Skip flag)" -ForegroundColor Cyan
} else {
    do {
        $confirmation = Read-Host "Do you want to continue with this configuration? (y/n)"
        $confirmation = $confirmation.ToLower().Trim()
        
        if ($confirmation -eq 'n' -or $confirmation -eq 'no') {
            Write-Host "Script execution cancelled by user." -ForegroundColor Yellow
            exit 0
        }
    } while ($confirmation -ne 'y' -and $confirmation -ne 'yes')
}

Write-Host "Starting audit execution..." -ForegroundColor Green
Write-Host ""

# Temp arrays
$packages1 = @()           # Reverification System Packages 1
$packageMembers1 = @()     # Reverification Package Members 1
$packages2 = @()           # Reverification System Packages 1-2 (privilege users)
$privilegeGroups = @()     # Reverification Privilege Groups 1

# Exempt user check
function Test-ExemptUser {
    param(
        [object]$User,
        [array]$ExemptTerms
    )
    
    if (-not $ExemptTerms -or $ExemptTerms.Count -eq 0) {
        return $false
    }
    
    # Check firstname (givenName)
    $firstName = Get-SafeValue $User.givenName
    if (-not [string]::IsNullOrEmpty($firstName)) {
        foreach ($term in $ExemptTerms) {
            if ($firstName -like "*$term*") {
                Write-Host "    User $($User.SamAccountName) marked exempt: firstname '$firstName' contains '$term'" -ForegroundColor Yellow
                return $true
            }
        }
    }
    
    # Check SamAccountName
    $samAccount = Get-SafeValue $User.SamAccountName
    if (-not [string]::IsNullOrEmpty($samAccount)) {
        foreach ($term in $ExemptTerms) {
            if ($samAccount -like "*$term*") {
                Write-Host "    User $($User.SamAccountName) marked exempt: SamAccountName contains '$term'" -ForegroundColor Yellow
                return $true
            }
        }
    }
    
    # Check description
    $description = Get-SafeValue $User.Description
    if (-not [string]::IsNullOrEmpty($description)) {
        foreach ($term in $ExemptTerms) {
            if ($description -like "*$term*") {
                Write-Host "    User $($User.SamAccountName) marked exempt: description '$description' contains '$term'" -ForegroundColor Yellow
                return $true
            }
        }
    }
    
    return $false
}

# Helper function to get group members that works for both security and distribution groups
function Get-GroupMembers {
    param(
        [object]$Group,
        [hashtable]$AdParams
    )
    
    $members = @()
    
    # Check if this is a security group
    if ($Group.GroupCategory -eq "Security") {
        Write-Host "      Processing security group: $($Group.Name)" -ForegroundColor DarkGray
        try {
            $directMembers = Get-ADGroupMember -Identity $Group @AdParams
            if ($null -ne $directMembers) {
                $members = $directMembers
                Write-Host "      Found $($members.Count) members in security group" -ForegroundColor DarkGray
            } else {
                Write-Host "      No members found in security group" -ForegroundColor DarkGray
            }
        }
        catch {
            Write-Warning "Failed to get members for security group '$($Group.Name)': $($_.Exception.Message)"
        }
    }
    else {
        # For distribution groups, we need to use a different approach
        Write-Host "      Processing distribution group: $($Group.Name)" -ForegroundColor DarkGray
        # Get the group with member attribute
        try {
            $groupWithMembers = Get-ADGroup -Identity $Group.DistinguishedName -Properties members @AdParams
            if ($groupWithMembers.members) {
                Write-Host "      Found $($groupWithMembers.members.Count) member DNs in distribution group" -ForegroundColor DarkGray
                foreach ($memberDN in $groupWithMembers.members) {
                    try {
                        # First get basic object info to determine type
                        $member = Get-ADObject -Identity $memberDN -Properties objectClass, sAMAccountName @AdParams
                        if ($member -and $member.objectClass -eq "user" -and $member.sAMAccountName) {
                            # For users, get full user object using SamAccountName
                            try {
                                $userObject = Get-ADUser -Identity $member.sAMAccountName -Properties mail, givenName, surname, SamAccountName, Department, Title, Manager, Description @AdParams
                                if ($userObject) {
                                    $members += $userObject
                                }
                            }
                            catch {
                                Write-Warning "Failed to get user object for SamAccountName '$($member.sAMAccountName)': $($_.Exception.Message)"
                            }
                        }
                    }
                    catch {
                        Write-Warning "Failed to get member object for '$memberDN': $($_.Exception.Message)"
                    }
                }
                Write-Host "      Successfully processed $($members.Count) members from distribution group" -ForegroundColor DarkGray
            } else {
                Write-Host "      No members found in distribution group" -ForegroundColor DarkGray
            }
        }
        catch {
            Write-Warning "Failed to get members for distribution group '$($Group.Name)': $($_.Exception.Message)"
        }
    }
    
    return $members
}

# Excluded group check
function Test-ExcludedGroup {
    param(
        [object]$Group,
        [object]$ProcessingOptions
    )
    
    # Check if group is disabled (if excludeDisabledGroups is enabled)
    if ($ProcessingOptions.excludeDisabledGroups) {
        # In AD, groups don't have an "enabled" property like users, but we can check if they're in a disabled state
        # For now, we'll check if the group has certain system attributes that indicate it's disabled
        if ($Group.GroupCategory -eq "Security" -and $Group.GroupScope -eq "DomainLocal" -and $Group.Name.StartsWith("$")) {
            Write-Host "    Excluding disabled/system group: $($Group.Name)" -ForegroundColor Yellow
            return $true
        }
    }
    
    # Check if group is a system group (if excludeSystemGroups is enabled)
    if ($ProcessingOptions.excludeSystemGroups) {
        # Prefix and name lists come exclusively from processingOptions
        $systemGroupPrefixes = $ProcessingOptions.systemGroupPrefixes
        $systemGroupNames    = $ProcessingOptions.systemGroupNames

        if (-not $systemGroupPrefixes) { $systemGroupPrefixes = @() }
        if (-not $systemGroupNames)    { $systemGroupNames    = @() }
        
        foreach ($prefix in $systemGroupPrefixes) {
            if ($Group.Name.StartsWith($prefix)) {
                Write-Host "    Excluding system group: $($Group.Name) (prefix: $prefix)" -ForegroundColor Yellow
                return $true
            }
        }
        
        if ($systemGroupNames -contains $Group.Name) {
            Write-Host "    Excluding system group: $($Group.Name) (known system group)" -ForegroundColor Yellow
            return $true
        }
        
        # Exclude groups with certain distinguished name patterns
        if ($Group.DistinguishedName -match "CN=Builtin|CN=Users,DC=") {
            Write-Host "    Excluding system group: $($Group.Name) (system container)" -ForegroundColor Yellow
            return $true
        }
    }
    
    return $false
}

# Recursive member fetch
function Get-NestedGroupMembers {
    param(
        [object]$Group,
        [hashtable]$AdParams,
        [int]$MaxDepth = 10,
        [int]$CurrentDepth = 0,
        [array]$ProcessedGroups = @()
    )
    
    if ($CurrentDepth -ge $MaxDepth) {
        Write-Host "    Max recursion depth ($MaxDepth) reached for group: $($Group.Name)" -ForegroundColor Yellow
        return @()
    }
    
    # Prevent infinite loops by tracking processed groups
    if ($ProcessedGroups -contains $Group.DistinguishedName) {
        Write-Host "    Circular reference detected, skipping group: $($Group.Name)" -ForegroundColor Yellow
        return @()
    }
    
    $newProcessedGroups = $ProcessedGroups + $Group.DistinguishedName
    $allMembers = @()
    
    try {
        $directMembers = Get-GroupMembers -Group $Group -AdParams $AdParams
        
        # Handle null result from Get-GroupMembers
        if ($null -eq $directMembers -or $directMembers.Count -eq 0) {
            Write-Host "    No members found for group: $($Group.Name)" -ForegroundColor DarkGray
            return @()
        }
        
        foreach ($member in $directMembers) {
            if ($member.objectClass -eq "user") {
                # Add user with membership source info
                $memberInfo = @{
                    User = $member
                    SourceGroup = $Group.Name
                    MembershipPath = if ($CurrentDepth -eq 0) { $Group.Name } else { "$($Group.Name) (nested)" }
                    Depth = $CurrentDepth
                }
                $allMembers += $memberInfo
            }
            elseif ($member.objectClass -eq "group") {
                # Recursively get members from nested group
                try {
                    $nestedGroup = Get-ADGroup -Identity $member.DistinguishedName @AdParams
                    $nestedMembers = Get-NestedGroupMembers -Group $nestedGroup -AdParams $AdParams -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1) -ProcessedGroups $newProcessedGroups
                    
                    # Update membership path for nested members
                    foreach ($nestedMember in $nestedMembers) {
                        $nestedMember.MembershipPath = "$($Group.Name) -> $($nestedMember.MembershipPath)"
                        $allMembers += $nestedMember
                    }
                }
                catch {
                    Write-Warning "Failed to process nested group $($member.DistinguishedName): $($_.Exception.Message)"
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to get members for group $($Group.Name): $($_.Exception.Message)"
    }
    
    return $allMembers
}

# Lookup user email by name
function Get-ADUserEmailByName {
    param(
        [string]$FullName,
        [hashtable]$AdParams,
        [bool]$UseADModule = $true
    )
    
    if ([string]::IsNullOrWhiteSpace($FullName)) {
        return ""
    }
    
    # Clean and parse the name
    $cleanName = $FullName.Trim()
    $nameParts = $cleanName -split '\s+'
    
    if ($nameParts.Count -eq 0) {
        return ""
    }
    
    try {
        if ($UseADModule) {
            Write-Host "    Searching AD for user: $cleanName" -ForegroundColor DarkGray
            
            # Build search filters
            $searchFilters = @()
            
            if ($nameParts.Count -eq 1) {
                # Single name - search in multiple fields
                $singleName = $nameParts[0]
                $searchFilters += "DisplayName -like '*$singleName*'"
                $searchFilters += "givenName -like '*$singleName*'"
                $searchFilters += "surname -like '*$singleName*'"
                $searchFilters += "Name -like '*$singleName*'"
            }
            elseif ($nameParts.Count -eq 2) {
                # First and Last name
                $firstName = $nameParts[0]
                $lastName = $nameParts[1]
                
                # Try exact match first
                $searchFilters += "(givenName -eq '$firstName' -and surname -eq '$lastName')"
                $searchFilters += "(givenName -eq '$lastName' -and surname -eq '$firstName')"  # In case they're reversed
                
                # Try partial matches
                $searchFilters += "(givenName -like '*$firstName*' -and surname -like '*$lastName*')"
                $searchFilters += "(givenName -like '*$lastName*' -and surname -like '*$firstName*')"
                
                # Try display name matches
                $searchFilters += "DisplayName -like '*$firstName*$lastName*'"
                $searchFilters += "DisplayName -like '*$lastName*$firstName*'"
            }
            else {
                # Multiple names - try as display name
                $searchFilters += "DisplayName -like '*$cleanName*'"
                
                # Try first and last name from the parts
                $firstName = $nameParts[0]
                $lastName = $nameParts[-1]  # Last element
                $searchFilters += "(givenName -like '*$firstName*' -and surname -like '*$lastName*')"
            }
            
            $allResults = @()
            
            # Execute searches
            foreach ($filter in $searchFilters) {
                try {
                    Write-Host "      Trying filter: $filter" -ForegroundColor DarkGray
                    $results = Get-ADUser -Filter $filter -Properties mail, givenName, surname, DisplayName, SamAccountName @AdParams
                    
                    if ($results) {
                        foreach ($result in $results) {
                            # Avoid duplicates
                            if ($allResults | Where-Object { $_.SamAccountName -eq $result.SamAccountName }) {
                                continue
                            }
                            $allResults += $result
                        }
                    }
                }
                catch {
                    Write-Host "      Filter failed: $($_.Exception.Message)" -ForegroundColor DarkGray
                    continue
                }
                
                # If we found results with the current filter, check if we can narrow it down
                if ($allResults.Count -gt 0) {
                    break
                }
            }
            
            Write-Host "      Found $($allResults.Count) potential matches" -ForegroundColor DarkGray
            
            if ($allResults.Count -eq 0) {
                Write-Host "      No users found for: $cleanName" -ForegroundColor Yellow
                return ""
            }
            elseif ($allResults.Count -eq 1) {
                $user = $allResults[0]
                
                # Check if user is enabled - if disabled or can't be found, return empty string
                try {
                    $userWithStatus = Get-ADUser -Identity $user.SamAccountName -Properties mail, Enabled @AdParams
                    if (-not $userWithStatus.Enabled) {
                        Write-Host "      User found but is disabled: $($user.DisplayName) ($($user.SamAccountName))" -ForegroundColor Yellow
                        return ""
                    }
                    $email = Get-SafeValue $userWithStatus.mail
                    Write-Host "      Found single match: $($user.DisplayName) ($($user.SamAccountName)) - Email: $email" -ForegroundColor Green
                    return $email
                }
                catch {
                    Write-Host "      User found but can't retrieve status: $($user.DisplayName) ($($user.SamAccountName))" -ForegroundColor Yellow
                    return ""
                }
            }
            else {
                # Multiple results - try to narrow down using first name
                Write-Host "      Multiple matches found, attempting to narrow down using first name..." -ForegroundColor Yellow
                
                if ($nameParts.Count -ge 1) {
                    $firstName = $nameParts[0]
                    $filteredResults = $allResults | Where-Object { 
                        $_.givenName -like "*$firstName*" -or $_.DisplayName -like "*$firstName*"
                    }
                    
                    if ($filteredResults.Count -eq 1) {
                        $user = $filteredResults[0]
                        
                        # Check if user is enabled - if disabled or can't be found, return empty string
                        try {
                            $userWithStatus = Get-ADUser -Identity $user.SamAccountName -Properties mail, Enabled @AdParams
                            if (-not $userWithStatus.Enabled) {
                                Write-Host "      User found but is disabled: $($user.DisplayName) ($($user.SamAccountName))" -ForegroundColor Yellow
                                return ""
                            }
                            $email = Get-SafeValue $userWithStatus.mail
                            Write-Host "      Narrowed down to single match using first name: $($user.DisplayName) ($($user.SamAccountName)) - Email: $email" -ForegroundColor Green
                            return $email
                        }
                        catch {
                            Write-Host "      User found but can't retrieve status: $($user.DisplayName) ($($user.SamAccountName))" -ForegroundColor Yellow
                            return ""
                        }
                    }
                    elseif ($filteredResults.Count -gt 1) {
                        # Still multiple matches - log them and return the first one with an email
                        Write-Host "      Still multiple matches after first name filter:" -ForegroundColor Yellow
                        foreach ($result in $filteredResults) {
                            $email = Get-SafeValue $result.mail
                            Write-Host "        - $($result.DisplayName) ($($result.SamAccountName)) - Email: $email" -ForegroundColor Yellow
                        }
                        
                        # Return the first user with a non-empty email and is enabled
                        foreach ($potentialUser in $filteredResults) {
                            if ([string]::IsNullOrWhiteSpace($potentialUser.mail)) { continue }
                            
                            try {
                                $userWithStatus = Get-ADUser -Identity $potentialUser.SamAccountName -Properties mail, Enabled @AdParams
                                if ($userWithStatus.Enabled) {
                                    $email = Get-SafeValue $userWithStatus.mail
                                    Write-Host "      Using first enabled match with email: $($userWithStatus.DisplayName) - Email: $email" -ForegroundColor Cyan
                                    return $email
                                }
                                else {
                                    Write-Host "      Skipping disabled user: $($potentialUser.DisplayName) ($($potentialUser.SamAccountName))" -ForegroundColor Yellow
                                }
                            }
                            catch {
                                Write-Host "      Skipping user (can't retrieve status): $($potentialUser.DisplayName) ($($potentialUser.SamAccountName))" -ForegroundColor Yellow
                                continue
                            }
                        }
                        Write-Host "      No enabled matches have email addresses" -ForegroundColor Yellow
                        return ""
                    }
                    else {
                        # First name filter eliminated all matches - use original results
                        Write-Host "      First name filter eliminated all matches, using original results" -ForegroundColor Yellow
                    }
                }
                
                # Log all matches and return the first one with an email
                Write-Host "      Multiple matches found:" -ForegroundColor Yellow
                foreach ($result in $allResults) {
                    $email = Get-SafeValue $result.mail
                    Write-Host "        - $($result.DisplayName) ($($result.SamAccountName)) - Email: $email" -ForegroundColor Yellow
                }
                
                # Return the first user with a non-empty email and is enabled
                foreach ($potentialUser in $allResults) {
                    if ([string]::IsNullOrWhiteSpace($potentialUser.mail)) { continue }
                    
                    try {
                        $userWithStatus = Get-ADUser -Identity $potentialUser.SamAccountName -Properties mail, Enabled @AdParams
                        if ($userWithStatus.Enabled) {
                            $email = Get-SafeValue $userWithStatus.mail
                            Write-Host "      Using first enabled match with email: $($userWithStatus.DisplayName) - Email: $email" -ForegroundColor Cyan
                            return $email
                        }
                        else {
                            Write-Host "      Skipping disabled user: $($potentialUser.DisplayName) ($($potentialUser.SamAccountName))" -ForegroundColor Yellow
                        }
                    }
                    catch {
                        Write-Host "      Skipping user (can't retrieve status): $($potentialUser.DisplayName) ($($potentialUser.SamAccountName))" -ForegroundColor Yellow
                        continue
                    }
                }
                Write-Host "      No enabled matches have email addresses" -ForegroundColor Yellow
                return ""
            }
        }
        else {
            # LDAP search would go here
            Write-Host "      LDAP user search not yet implemented" -ForegroundColor Yellow
            return ""
        }
    }
    catch {
        Write-Warning "Failed to search AD for user '$cleanName': $($_.Exception.Message)"
        return ""
    }
}

# Extract owner info (regex)
function Get-OwnerInformation {
    param(
        [string]$InfoText,
        [array]$RegexPatterns
    )
    
    $result = @{
        PrimaryOwnerEmail = ""
        SecondaryOwnerEmail = ""
        PrimaryOwnerName = ""
        SecondaryOwnerName = ""
    }
    
    if ([string]::IsNullOrEmpty($InfoText)) {
        return $result
    }
    
    # Replace line breaks with spaces for some patterns, but keep original for line-based patterns
    $infoTextSingleLine = $InfoText -replace "`r`n|`r|`n", " "
    
    # 1) Attempt extraction using externally supplied RegexPatterns (from groups.json) if provided
    if ($RegexPatterns -and $RegexPatterns.Count -gt 0) {
        foreach ($regexEntry in $RegexPatterns) {
            # Ensure object has the required properties
            if (-not ($regexEntry.PSObject.Properties["pattern"])) { continue }
            $pattern = $regexEntry.pattern
            $captureGroup = 1
            if ($regexEntry.PSObject.Properties["captureGroup"]) {
                $captureGroup = [int]$regexEntry.captureGroup
            }
            $name = ""
            if ($regexEntry.PSObject.Properties["name"]) { $name = $regexEntry.name }

            if ($InfoText -match $pattern) {
                # If captureGroup is 0, use entire match; otherwise use specified group index
                $value = if ($captureGroup -eq 0) { $Matches[0] } else { $Matches[$captureGroup] }
                $value = $value.Trim()

                switch -Regex ($name) {
                    "Primary.*Email" {
                        if ([string]::IsNullOrEmpty($result.PrimaryOwnerEmail)) { $result.PrimaryOwnerEmail = $value }
                        break
                    }
                    "Secondary.*Email" {
                        if ([string]::IsNullOrEmpty($result.SecondaryOwnerEmail)) { $result.SecondaryOwnerEmail = $value }
                        break
                    }
                    "Owner Email Generic" {
                        if ([string]::IsNullOrEmpty($result.PrimaryOwnerEmail)) { $result.PrimaryOwnerEmail = $value }
                        break
                    }
                    "Primary.*Name" {
                        if ([string]::IsNullOrEmpty($result.PrimaryOwnerName)) { $result.PrimaryOwnerName = $value }
                        break
                    }
                    "Secondary.*Name" {
                        if ([string]::IsNullOrEmpty($result.SecondaryOwnerName)) { $result.SecondaryOwnerName = $value }
                        break
                    }
                    default { }
                }
            }
        }
    }
    # After custom patterns, continue with built-in extraction for any missing fields
    
    # Comprehensive regex patterns for PRIMARY owners
    $primaryEmailPatterns = @(
        "Primary Owner:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        "P:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        "Primary:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        "Owner:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        "Owned by:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
    )
    
    $primaryNamePatterns = @(
        "Primary Owner:\s*([A-Za-z]+(?:\s+[A-Za-z]+)+)",
        "P:\s*([A-Za-z]+(?:\s+[A-Za-z]+)+)",
        "Primary:\s*([A-Za-z]+(?:\s+[A-Za-z]+)+)",
        "Owner:\s*([A-Za-z]+(?:\s+[A-Za-z]+)+)",
        "Owned by:\s*([A-Za-z]+(?:\s+[A-Za-z]+)+)"
    )
    
    # Comprehensive regex patterns for SECONDARY owners
    $secondaryEmailPatterns = @(
        "Secondary Owner:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        "S:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        "Secondary:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        "Backup:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        "Alt:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
    )
    
    $secondaryNamePatterns = @(
        "Secondary Owner:\s*([A-Za-z]+(?:\s+[A-Za-z]+)+)",
        "S:\s*([A-Za-z]+(?:\s+[A-Za-z]+)+)",
        "Secondary:\s*([A-Za-z]+(?:\s+[A-Za-z]+)+)",
        "Backup:\s*([A-Za-z]+(?:\s+[A-Za-z]+)+)",
        "Alt:\s*([A-Za-z]+(?:\s+[A-Za-z]+)+)"
    )
    
    # Special patterns for combined formats like "P: John Doe S: Jane Smith"
    $combinedPatterns = @(
        "P:\s*([A-Za-z]+(?:\s+[A-Za-z]+)+).*?S:\s*([A-Za-z]+(?:\s+[A-Za-z]+)+)",
        "Primary:\s*([A-Za-z]+(?:\s+[A-Za-z]+)+).*?Secondary:\s*([A-Za-z]+(?:\s+[A-Za-z]+)+)",
        "Owner:\s*([A-Za-z]+(?:\s+[A-Za-z]+)+).*?Backup:\s*([A-Za-z]+(?:\s+[A-Za-z]+)+)"
    )
    
    # Try combined patterns first (for formats like "P: John Doe S: Jane Smith")
    foreach ($pattern in $combinedPatterns) {
        if ($infoTextSingleLine -match $pattern) {
            $result.PrimaryOwnerName = $Matches[1].Trim()
            $result.SecondaryOwnerName = $Matches[2].Trim()
            break
        }
    }
    
    # If no combined pattern matched, try individual patterns
    if ([string]::IsNullOrEmpty($result.PrimaryOwnerName)) {
        # Try primary email patterns
        foreach ($pattern in $primaryEmailPatterns) {
            if ($InfoText -match $pattern) {
                $result.PrimaryOwnerEmail = $Matches[1].Trim()
                break
            }
        }
        
        # Try primary name patterns
        foreach ($pattern in $primaryNamePatterns) {
            if ($InfoText -match $pattern) {
                $result.PrimaryOwnerName = $Matches[1].Trim()
                break
            }
        }
    }
    
    if ([string]::IsNullOrEmpty($result.SecondaryOwnerName)) {
        # Try secondary email patterns
        foreach ($pattern in $secondaryEmailPatterns) {
            if ($InfoText -match $pattern) {
                $result.SecondaryOwnerEmail = $Matches[1].Trim()
                break
            }
        }
        
        # Try secondary name patterns
        foreach ($pattern in $secondaryNamePatterns) {
            if ($InfoText -match $pattern) {
                $result.SecondaryOwnerName = $Matches[1].Trim()
                break
            }
        }
    }
    
    # Multi-line processing for cases where owners are on separate lines
    $lines = $InfoText -split "`r`n|`r|`n"
    foreach ($line in $lines) {
        $line = $line.Trim()
        
        # Check for primary owner in this line
        if ([string]::IsNullOrEmpty($result.PrimaryOwnerName) -and [string]::IsNullOrEmpty($result.PrimaryOwnerEmail)) {
            if ($line -match "^(Primary|P|Owner|Owned by):\s*(.+)") {
                $ownerInfo = $Matches[2].Trim()
                if ($ownerInfo -match "@") {
                    $result.PrimaryOwnerEmail = $ownerInfo
                } else {
                    $result.PrimaryOwnerName = $ownerInfo
                }
            }
        }
        
        # Check for secondary owner in this line
        if ([string]::IsNullOrEmpty($result.SecondaryOwnerName) -and [string]::IsNullOrEmpty($result.SecondaryOwnerEmail)) {
            if ($line -match "^(Secondary|S|Backup|Alt):\s*(.+)") {
                $ownerInfo = $Matches[2].Trim()
                if ($ownerInfo -match "@") {
                    $result.SecondaryOwnerEmail = $ownerInfo
                } else {
                    $result.SecondaryOwnerName = $ownerInfo
                }
            }
        }
    }
    
    # If we have names but no emails, try to convert names to emails using common patterns
    if (-not [string]::IsNullOrEmpty($result.PrimaryOwnerName) -and [string]::IsNullOrEmpty($result.PrimaryOwnerEmail)) {
        # Look for email in the same info text that might belong to the primary owner
        if ($InfoText -match "([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})") {
            $result.PrimaryOwnerEmail = $Matches[1]
        }
    }
    
    return $result
}

# Logical grouping helper
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

# Pick best owner from logical set
function Get-LogicalGroupOwnerInformation {
    param(
        [object]$LogicalGroup,
        [array]$RegexPatterns
    )
    
    $bestOwnerInfo = @{
        PrimaryOwnerEmail = ""
        SecondaryOwnerEmail = ""
        PrimaryOwnerName = ""
        SecondaryOwnerName = ""
        SourceGroup = ""
    }
    
    Write-Host "Extracting owner information from logical group with $($LogicalGroup.Groups.Count) subgroups" -ForegroundColor DarkGray
    
    # Check each subgroup for owner information
    foreach ($subGroupInfo in $LogicalGroup.Groups) {
        $subGroup = $subGroupInfo.Group
        $subGroupOwnerInfo = Get-OwnerInformation -InfoText (Get-SafeValue $subGroup.Info) -RegexPatterns $RegexPatterns
        
        Write-Host "  Checking subgroup: $($subGroup.Name)" -ForegroundColor DarkGray
        
        # If we find complete owner info (both primary and secondary), use it
        if ((-not [string]::IsNullOrEmpty($subGroupOwnerInfo.PrimaryOwnerName) -or -not [string]::IsNullOrEmpty($subGroupOwnerInfo.PrimaryOwnerEmail)) -and
            (-not [string]::IsNullOrEmpty($subGroupOwnerInfo.SecondaryOwnerName) -or -not [string]::IsNullOrEmpty($subGroupOwnerInfo.SecondaryOwnerEmail))) {
            
            Write-Host "    Found complete owner info in $($subGroup.Name)" -ForegroundColor Green
            $bestOwnerInfo.PrimaryOwnerEmail = $subGroupOwnerInfo.PrimaryOwnerEmail
            $bestOwnerInfo.SecondaryOwnerEmail = $subGroupOwnerInfo.SecondaryOwnerEmail
            $bestOwnerInfo.PrimaryOwnerName = $subGroupOwnerInfo.PrimaryOwnerName
            $bestOwnerInfo.SecondaryOwnerName = $subGroupOwnerInfo.SecondaryOwnerName
            $bestOwnerInfo.SourceGroup = $subGroup.Name
            break
        }
        
        # If we don't have any owner info yet, use what we find
        if ([string]::IsNullOrEmpty($bestOwnerInfo.PrimaryOwnerName) -and [string]::IsNullOrEmpty($bestOwnerInfo.PrimaryOwnerEmail) -and
            [string]::IsNullOrEmpty($bestOwnerInfo.SecondaryOwnerName) -and [string]::IsNullOrEmpty($bestOwnerInfo.SecondaryOwnerEmail)) {
            
            if (-not [string]::IsNullOrEmpty($subGroupOwnerInfo.PrimaryOwnerName) -or -not [string]::IsNullOrEmpty($subGroupOwnerInfo.PrimaryOwnerEmail) -or
                -not [string]::IsNullOrEmpty($subGroupOwnerInfo.SecondaryOwnerName) -or -not [string]::IsNullOrEmpty($subGroupOwnerInfo.SecondaryOwnerEmail)) {
                
                Write-Host "    Found partial owner info in $($subGroup.Name)" -ForegroundColor Yellow
                $bestOwnerInfo.PrimaryOwnerEmail = $subGroupOwnerInfo.PrimaryOwnerEmail
                $bestOwnerInfo.SecondaryOwnerEmail = $subGroupOwnerInfo.SecondaryOwnerEmail
                $bestOwnerInfo.PrimaryOwnerName = $subGroupOwnerInfo.PrimaryOwnerName
                $bestOwnerInfo.SecondaryOwnerName = $subGroupOwnerInfo.SecondaryOwnerName
                $bestOwnerInfo.SourceGroup = $subGroup.Name
            }
        }
        
        # Fill in missing primary owner if we have it in this subgroup
        if ([string]::IsNullOrEmpty($bestOwnerInfo.PrimaryOwnerName) -and [string]::IsNullOrEmpty($bestOwnerInfo.PrimaryOwnerEmail)) {
            if (-not [string]::IsNullOrEmpty($subGroupOwnerInfo.PrimaryOwnerName) -or -not [string]::IsNullOrEmpty($subGroupOwnerInfo.PrimaryOwnerEmail)) {
                Write-Host "    Found primary owner in $($subGroup.Name)" -ForegroundColor Cyan
                $bestOwnerInfo.PrimaryOwnerEmail = $subGroupOwnerInfo.PrimaryOwnerEmail
                $bestOwnerInfo.PrimaryOwnerName = $subGroupOwnerInfo.PrimaryOwnerName
                if ([string]::IsNullOrEmpty($bestOwnerInfo.SourceGroup)) {
                    $bestOwnerInfo.SourceGroup = $subGroup.Name
                }
            }
        }
        
        # Fill in missing secondary owner if we have it in this subgroup
        if ([string]::IsNullOrEmpty($bestOwnerInfo.SecondaryOwnerName) -and [string]::IsNullOrEmpty($bestOwnerInfo.SecondaryOwnerEmail)) {
            if (-not [string]::IsNullOrEmpty($subGroupOwnerInfo.SecondaryOwnerName) -or -not [string]::IsNullOrEmpty($subGroupOwnerInfo.SecondaryOwnerEmail)) {
                Write-Host "    Found secondary owner in $($subGroup.Name)" -ForegroundColor Cyan
                $bestOwnerInfo.SecondaryOwnerEmail = $subGroupOwnerInfo.SecondaryOwnerEmail
                $bestOwnerInfo.SecondaryOwnerName = $subGroupOwnerInfo.SecondaryOwnerName
                if ([string]::IsNullOrEmpty($bestOwnerInfo.SourceGroup)) {
                    $bestOwnerInfo.SourceGroup = $subGroup.Name
                }
            }
        }
    }
    
    if (-not [string]::IsNullOrEmpty($bestOwnerInfo.SourceGroup)) {
        Write-Host "  Best owner info extracted from: $($bestOwnerInfo.SourceGroup)" -ForegroundColor Green
    } else {
        Write-Host "  No owner information found in any subgroup" -ForegroundColor Red
    }
    
    return $bestOwnerInfo
}

# Process groups (skip if PrivilegeOnly mode)
if (-not $PrivilegeOnly) {
    Write-Host "Processing groups..." -ForegroundColor Cyan

$totalGroupConfigs = $groupsConfig.groups.Count
$currentGroupConfigIndex = 0

foreach ($groupConfig in $groupsConfig.groups) {
    $currentGroupConfigIndex++
    $ouPath = $groupConfig.path
    $category = $groupConfig.category
    $logicalConfig = $groupConfig.Logical
    
    # Progress bar for group OU processing
    Write-Progress -Activity "Processing Group OUs" -Status "Processing OU: $ouPath (Category: $category)" -PercentComplete (($currentGroupConfigIndex / $totalGroupConfigs) * 100) -Id 1
    
    Write-Host "Processing OU: $ouPath (Category: $category)" -ForegroundColor Yellow
    
    try {
        if ($useADModule) {
            # Get groups just in this OU (no recursion) unless JSON overrides
            $searchScope = if ($groupConfig.searchScope) { $groupConfig.searchScope } else { 'OneLevel' }
            $allGroups = Get-ADGroup -Filter * -SearchBase $ouPath -SearchScope $searchScope -Properties Name, Description, Info, GroupCategory, GroupScope, DistinguishedName, whenCreated @adParams
            Write-Host "Found $($allGroups.Count) total groups in OU" -ForegroundColor Cyan
            
            # Log group types for debugging
            $groupTypes = $allGroups | Group-Object GroupCategory | ForEach-Object { "$($_.Name): $($_.Count)" }
            Write-Host "Group types found: $($groupTypes -join ', ')" -ForegroundColor DarkGray
            
            # Filter groups based on processing options
            $groups = @()
            foreach ($group in $allGroups) {
                if (-not (Test-ExcludedGroup -Group $group -ProcessingOptions $groupsConfig.processingOptions)) {
                    $groups += $group
                }
            }
            Write-Host "After filtering: $($groups.Count) groups will be processed" -ForegroundColor Cyan
            
            # Group logical groups together
            $logicalGroups = @{}
            $standaloneGroups = @()
            
            foreach ($group in $groups) {
                $logicalInfo = Get-LogicalGroupInfo -GroupName $group.Name -LogicalConfig $logicalConfig
                Write-Host "Group $($group.Name): IsLogical=$($logicalInfo.IsLogical), BaseName=$($logicalInfo.BaseName), Access=$($logicalInfo.LogicalAccess)" -ForegroundColor DarkGray
                
                if ($logicalInfo.IsLogical) {
                    if (-not $logicalGroups.ContainsKey($logicalInfo.BaseName)) {
                        $logicalGroups[$logicalInfo.BaseName] = @{
                            BaseName = $logicalInfo.BaseName
                            Groups = @()
                            Category = $category
                            OUPath = $ouPath
                            AccessLevels = @()
                        }
                    }
                    $logicalGroups[$logicalInfo.BaseName].Groups += @{
                        Group = $group
                        LogicalAccess = $logicalInfo.LogicalAccess
                        Suffix = $logicalInfo.Suffix
                    }
                    $logicalGroups[$logicalInfo.BaseName].AccessLevels += $logicalInfo.LogicalAccess
                } else {
                    $standaloneGroups += $group
                }
            }
            
            # Process logical groups
            $totalLogicalGroups = $logicalGroups.Keys.Count
            $totalStandaloneGroups = $standaloneGroups.Count
            $totalGroupsInOU = $totalLogicalGroups + $totalStandaloneGroups
            $currentLogicalGroupIndex = 0
            
            foreach ($logicalGroupName in $logicalGroups.Keys) {
                $currentLogicalGroupIndex++
                $logicalGroup = $logicalGroups[$logicalGroupName]
                
                # Progress bar for logical group processing
                Write-Progress -Activity "Processing Groups in OU" -Status "Processing logical group: $($logicalGroup.BaseName)" -PercentComplete (($currentLogicalGroupIndex / $totalGroupsInOU) * 100) -Id 2 -ParentId 1
                
                # ============================================
                # Immutable flag & access-order handling
                # ============================================
                $immutableFlag = $false
                if ($null -ne $logicalConfig -and ($logicalConfig.PSObject.Properties.Name -contains 'Immutable')) {
                    $immutableFlag = [bool]$logicalConfig.Immutable
                }
                
                # Build an ordered list of access levels from the grouping map so we can
                # later maintain consistent ordering when we have to merge multiple
                # access values for the same user (Immutable scenario)
                $accessOrder = @()
                if ($null -ne $logicalConfig -and $logicalConfig.grouping) {
                    foreach ($suffix in $logicalConfig.grouping.PSObject.Properties.Name) {
                        $accessOrder += $logicalConfig.grouping.$suffix
                    }
                }
                
                Write-Host "Processing logical group: $($logicalGroup.BaseName) with $($logicalGroup.Groups.Count) subgroups" -ForegroundColor Yellow
                
                # Use the first group for common properties like description and owners
                $primaryGroup = $logicalGroup.Groups[0].Group
                $groupGuid = Get-SimpleObjectGuid $primaryGroup $false
                $reviewPackageID = New-SimpleGuid "$($logicalGroup.BaseName)|$ReviewID|$groupGuid"
                
                # Extract owner information
                $ownerInfo = Get-LogicalGroupOwnerInformation -LogicalGroup $logicalGroup -RegexPatterns $groupsConfig.ownerRegexPatterns
                
                # Format owner display - lookup emails from AD if we have names
                $primaryOwnerDisplay = ""
                $secondaryOwnerDisplay = ""
                
                # Handle Primary Owner
                if (-not [string]::IsNullOrEmpty($ownerInfo.PrimaryOwnerEmail)) {
                    $primaryOwnerDisplay = $ownerInfo.PrimaryOwnerEmail
                } elseif (-not [string]::IsNullOrEmpty($ownerInfo.PrimaryOwnerName)) {
                    Write-Host "  Looking up primary owner: $($ownerInfo.PrimaryOwnerName)" -ForegroundColor Cyan
                    $primaryOwnerEmail = Get-ADUserEmailByName -FullName $ownerInfo.PrimaryOwnerName -AdParams $adParams -UseADModule $useADModule
                    if (-not [string]::IsNullOrEmpty($primaryOwnerEmail)) {
                        $primaryOwnerDisplay = $primaryOwnerEmail
                        Write-Host "  Primary owner email found: $primaryOwnerEmail" -ForegroundColor Green
                    } else {
                        $primaryOwnerDisplay = ""
                        Write-Host "  Primary owner not found or disabled" -ForegroundColor Yellow
                    }
                }
                
                # Handle Secondary Owner
                if (-not [string]::IsNullOrEmpty($ownerInfo.SecondaryOwnerEmail)) {
                    $secondaryOwnerDisplay = $ownerInfo.SecondaryOwnerEmail
                } elseif (-not [string]::IsNullOrEmpty($ownerInfo.SecondaryOwnerName)) {
                    Write-Host "  Looking up secondary owner: $($ownerInfo.SecondaryOwnerName)" -ForegroundColor Cyan
                    $secondaryOwnerEmail = Get-ADUserEmailByName -FullName $ownerInfo.SecondaryOwnerName -AdParams $adParams -UseADModule $useADModule
                    if (-not [string]::IsNullOrEmpty($secondaryOwnerEmail)) {
                        $secondaryOwnerDisplay = $secondaryOwnerEmail
                        Write-Host "  Secondary owner email found: $secondaryOwnerEmail" -ForegroundColor Green
                    } else {
                        $secondaryOwnerDisplay = ""
                        Write-Host "  Secondary owner not found or disabled" -ForegroundColor Yellow
                    }
                }
                
                # Combine all access levels for the logical group
                $combinedAccessLevels = ($logicalGroup.AccessLevels | Sort-Object -Unique) -join ", "
                
                # Create package record
                $package = New-Object PSObject
                $package | Add-Member -MemberType NoteProperty -Name "ReviewID" -Value $ReviewID
                $package | Add-Member -MemberType NoteProperty -Name "GroupID" -Value $groupGuid
                $package | Add-Member -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                $package | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $logicalGroup.BaseName
                $package | Add-Member -MemberType NoteProperty -Name "PrimaryOwnerEmail" -Value $primaryOwnerDisplay
                $package | Add-Member -MemberType NoteProperty -Name "SecondaryOwnerEmail" -Value $secondaryOwnerDisplay
                $package | Add-Member -MemberType NoteProperty -Name "OUPath" -Value $ouPath
                $package | Add-Member -MemberType NoteProperty -Name "Tag" -Value $category
                $package | Add-Member -MemberType NoteProperty -Name "Description" -Value (Get-SafeValue $primaryGroup.Description)
                $package | Add-Member -MemberType NoteProperty -Name "DateCreated" -Value (Get-SafeValue $primaryGroup.whenCreated)
                $package | Add-Member -MemberType NoteProperty -Name "LogicalGrouping" -Value $true
                $package | Add-Member -MemberType NoteProperty -Name "LogicalAccess" -Value $combinedAccessLevels
                # New column indicating whether Immutable logic was applied
                $package | Add-Member -MemberType NoteProperty -Name "Immutable" -Value $immutableFlag
                
                $packages1 += $package
                
                # Process members from all subgroups
                foreach ($subGroupInfo in $logicalGroup.Groups) {
                    $subGroup = $subGroupInfo.Group
                    $logicalAccess = $subGroupInfo.LogicalAccess
                    
                    Write-Host "Processing subgroup: $($subGroup.Name) (Access: $logicalAccess)" -ForegroundColor Gray
                    
                    try {
                        # Use enhanced member processing with depth control and membership source tracking
                        $allMembers = @()
                        
                        if ($groupsConfig.processingOptions.includeNestedGroups) {
                            # Get all members including nested with depth control
                            $allMembers = Get-NestedGroupMembers -Group $subGroup -AdParams $adParams -MaxDepth $groupsConfig.processingOptions.maxRecursionDepth
                        } else {
                            # Get only direct members
                            $directMembers = Get-GroupMembers -Group $subGroup -AdParams $adParams
                            if ($null -ne $directMembers -and $directMembers.Count -gt 0) {
                                foreach ($member in $directMembers) {
                                    if ($member.objectClass -eq "user") {
                                        $memberInfo = @{
                                            User = $member
                                            SourceGroup = $subGroup.Name
                                            MembershipPath = $subGroup.Name
                                            Depth = 0
                                        }
                                        $allMembers += $memberInfo
                                    }
                                }
                            }
                        }
                        
                        Write-Host "Found $($allMembers.Count) total members in subgroup $($subGroup.Name)" -ForegroundColor DarkGray
                        
                        # Track members to respect supersede rules
                        if (-not $logicalGroup.ContainsKey('MemberTracker')) { $logicalGroup['MemberTracker'] = @{} }
                        $memberTracker = $logicalGroup['MemberTracker']
                        
                        foreach ($memberInfo in $allMembers) {
                            # Validate member info and user object
                            if (-not $memberInfo -or -not $memberInfo.User) {
                                Write-Warning "Invalid member info object, skipping"
                                continue
                            }
                            
                            # Check if user object has required properties
                            if (-not $memberInfo.User.sAMAccountName -and -not $memberInfo.User.distinguishedName) {
                                Write-Warning "User object missing both SamAccountName and distinguishedName, skipping"
                                continue
                            }
                            
                            # Supersede access value (e.g. "Change") if provided in config
                            $supersedeAccess = ($logicalConfig.Supercede) -replace "^\s+|\s+$", "" -replace "\s+", " "
                            $supersedeAccess = $supersedeAccess.ToLower()

                            # If Immutable is enabled we deliberately ignore any Supersede
                            # logic – every distinct permission should be retained.
                            if ($immutableFlag) {
                                $supersedeAccess = ""
                            }

                            $normalizedAccess = ($logicalAccess -replace "^\s+|\s+$", "" -replace "\s+", " ").ToLower()
                            
                            # Always fetch complete user object using SamAccountName for consistency
                            $user = $null
                            $userIdentity = $null
                            
                            # Determine the best identifier to use
                            if ($memberInfo.User.sAMAccountName) {
                                $userIdentity = $memberInfo.User.sAMAccountName
                                Write-Host "        Fetching user by SamAccountName: $userIdentity" -ForegroundColor DarkGray
                            } elseif ($memberInfo.User.distinguishedName) {
                                $userIdentity = $memberInfo.User.distinguishedName
                                Write-Host "        Fetching user by DistinguishedName: $userIdentity" -ForegroundColor DarkGray
                            } else {
                                Write-Warning "User object missing both SamAccountName and DistinguishedName"
                                continue
                            }
                            
                            try {
                                # Always get fresh user object with ALL properties
                                $user = Get-ADUser -Identity $userIdentity -Properties mail, givenName, surname, SamAccountName, Department, Title, Manager, Description, DisplayName, EmployeeID, Company, Office, OfficePhone, MobilePhone, Enabled @adParams
                            }
                            catch {
                                Write-Warning "Failed to fetch AD user '$userIdentity': $($_.Exception.Message)"
                                continue
                            }

                            # Skip if user lookup failed
                            if (-not $user) { continue }

                            $isExempt = Test-ExemptUser -User $user -ExemptTerms $groupsConfig.processingOptions.ExemptUsers

                            # Get manager info
                            $managerName = ""
                            $managerEmail = ""
                            if ($user.Manager) {
                                try {
                                    $manager = Get-ADUser -Identity $user.Manager -Properties DisplayName, mail, Enabled @adParams
                                    if ($manager -and $manager.Enabled) {
                                        $managerName = Get-SafeValue $manager.DisplayName
                                        $managerEmail = Get-SafeValue $manager.mail
                                    }
                                } catch {}
                            }

                            $firstNameValue = if ($isExempt) { Get-SafeValue $user.SamAccountName } else { Get-SafeValue $user.givenName }

                            $memberObj = New-Object PSObject
                            $memberObj | Add-Member -MemberType NoteProperty -Name "FirstName" -Value $firstNameValue
                            $memberObj | Add-Member -MemberType NoteProperty -Name "LastName" -Value (Get-SafeValue $user.surname)
                            $memberObj | Add-Member -MemberType NoteProperty -Name "Username" -Value (Get-SafeValue $user.SamAccountName)
                            $memberObj | Add-Member -MemberType NoteProperty -Name "Email" -Value (Get-SafeValue $user.mail)
                            $userID = if ($user.ObjectGUID) { $user.ObjectGUID.ToString() } else { "" }
                            $memberObj | Add-Member -MemberType NoteProperty -Name "UserID" -Value $userID
                            $memberObj | Add-Member -MemberType NoteProperty -Name "Department" -Value (Get-SafeValue $user.Department)
                            $memberObj | Add-Member -MemberType NoteProperty -Name "JobTitle" -Value (Get-SafeValue $user.Title)
                            $memberObj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value (Get-SafeValue $user.DisplayName)
                            $memberObj | Add-Member -MemberType NoteProperty -Name "Company" -Value (Get-SafeValue $user.Company)
                            $memberObj | Add-Member -MemberType NoteProperty -Name "Office" -Value (Get-SafeValue $user.Office)
                            $memberObj | Add-Member -MemberType NoteProperty -Name "OfficePhone" -Value (Get-SafeValue $user.OfficePhone)
                            $memberObj | Add-Member -MemberType NoteProperty -Name "MobilePhone" -Value (Get-SafeValue $user.MobilePhone)
                            $memberObj | Add-Member -MemberType NoteProperty -Name "EmployeeID" -Value (Get-SafeValue $user.EmployeeID)
                            $memberObj | Add-Member -MemberType NoteProperty -Name "Enabled" -Value $user.Enabled
                            $memberObj | Add-Member -MemberType NoteProperty -Name "ManagerName" -Value $managerName
                            $memberObj | Add-Member -MemberType NoteProperty -Name "ManagerEmail" -Value $managerEmail
                            $memberObj | Add-Member -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                            
                            # Add membership source info if enabled
                            if ($groupsConfig.processingOptions.includeMembershipSource) {
                                $memberObj | Add-Member -MemberType NoteProperty -Name "DerivedGroup" -Value $memberInfo.SourceGroup
                                $memberObj | Add-Member -MemberType NoteProperty -Name "MembershipPath" -Value $memberInfo.MembershipPath
                            } else {
                                $derivedGroup = if ($memberInfo.Depth -eq 0) { "" } else { $memberInfo.SourceGroup }
                                $memberObj | Add-Member -MemberType NoteProperty -Name "DerivedGroup" -Value $derivedGroup
                            }
                            
                            $memberObj | Add-Member -MemberType NoteProperty -Name "LogicalAccess" -Value $logicalAccess
                            $memberObj | Add-Member -MemberType NoteProperty -Name "Exempt" -Value $isExempt
                            
                            $memberKey = "$($reviewPackageID)|$($user.SamAccountName)"

                            if ($memberTracker.ContainsKey($memberKey)) {
                                $existingObj = $memberTracker[$memberKey]

                                if ($immutableFlag) {
                                    # Merge LogicalAccess values in alphabetical order
                                    $existingAccesses = @()
                                    if (-not [string]::IsNullOrWhiteSpace($existingObj.LogicalAccess)) {
                                        $existingAccesses = $existingObj.LogicalAccess -split "\s*,\s*"
                                    }

                                    if (-not ($existingAccesses -contains $logicalAccess)) {
                                        $combinedAccesses = $existingAccesses + $logicalAccess
                                        # Sort alphabetically and join with ", "
                                        $sortedAccesses = $combinedAccesses | Sort-Object
                                        $existingObj.LogicalAccess = $sortedAccesses -join ", "
                                    }
                                    # Do NOT add another record to $packageMembers1 when immutable – we just updated the existing object.
                                }
                                elseif ($supersedeAccess -and ($normalizedAccess -eq $supersedeAccess)) {
                                    # Replace existing (lower priority) entry
                                    $packageMembers1.Remove($existingObj) | Out-Null
                                    $memberTracker[$memberKey] = $memberObj
                                    $packageMembers1 += $memberObj
                                } else {
                                    # Skip duplicate
                                    Write-Host "Skipping duplicate user $($memberInfo.User.SamAccountName) (already recorded)" -ForegroundColor DarkGray
                                }
                            } else {
                                $memberTracker[$memberKey] = $memberObj
                                $packageMembers1 += $memberObj
                            }
                        }
                    }
                    catch {
                        Write-Warning "Failed to get group members for $($subGroup.Name): $($_.Exception.Message)"
                    }
                }
            }
            
            # Process standalone (non-logical) groups
            foreach ($group in $standaloneGroups) {
                $currentLogicalGroupIndex++
                
                # Progress bar for individual group processing
                Write-Progress -Activity "Processing Groups in OU" -Status "Processing group: $($group.Name)" -PercentComplete (($currentLogicalGroupIndex / $totalGroupsInOU) * 100) -Id 2 -ParentId 1
                
                Write-Host "Processing standalone group: $($group.Name)" -ForegroundColor Gray
                
                $groupGuid = Get-SimpleObjectGuid $group $false
                $reviewPackageID = New-SimpleGuid "$($group.Name)|$ReviewID|$groupGuid"
                
                # Extract owner information
                $ownerInfo = Get-OwnerInformation -InfoText (Get-SafeValue $group.Info) -RegexPatterns $groupsConfig.ownerRegexPatterns
                
                # Format owner display - lookup emails from AD if we have names
                $primaryOwnerDisplay = ""
                $secondaryOwnerDisplay = ""
                
                # Handle Primary Owner
                if (-not [string]::IsNullOrEmpty($ownerInfo.PrimaryOwnerEmail)) {
                    $primaryOwnerDisplay = $ownerInfo.PrimaryOwnerEmail
                } elseif (-not [string]::IsNullOrEmpty($ownerInfo.PrimaryOwnerName)) {
                    Write-Host "  Looking up primary owner: $($ownerInfo.PrimaryOwnerName)" -ForegroundColor Cyan
                    $primaryOwnerEmail = Get-ADUserEmailByName -FullName $ownerInfo.PrimaryOwnerName -AdParams $adParams -UseADModule $useADModule
                    if (-not [string]::IsNullOrEmpty($primaryOwnerEmail)) {
                        $primaryOwnerDisplay = $primaryOwnerEmail
                        Write-Host "  Primary owner email found: $primaryOwnerEmail" -ForegroundColor Green
                    } else {
                        $primaryOwnerDisplay = ""
                        Write-Host "  Primary owner not found or disabled, leaving field empty" -ForegroundColor Yellow
                    }
                }
                
                # Handle Secondary Owner
                if (-not [string]::IsNullOrEmpty($ownerInfo.SecondaryOwnerEmail)) {
                    $secondaryOwnerDisplay = $ownerInfo.SecondaryOwnerEmail
                } elseif (-not [string]::IsNullOrEmpty($ownerInfo.SecondaryOwnerName)) {
                    Write-Host "  Looking up secondary owner: $($ownerInfo.SecondaryOwnerName)" -ForegroundColor Cyan
                    $secondaryOwnerEmail = Get-ADUserEmailByName -FullName $ownerInfo.SecondaryOwnerName -AdParams $adParams -UseADModule $useADModule
                    if (-not [string]::IsNullOrEmpty($secondaryOwnerEmail)) {
                        $secondaryOwnerDisplay = $secondaryOwnerEmail
                        Write-Host "  Secondary owner email found: $secondaryOwnerEmail" -ForegroundColor Green
                    } else {
                        $secondaryOwnerDisplay = ""
                        Write-Host "  Secondary owner not found or disabled, leaving field empty" -ForegroundColor Yellow
                    }
                }
                
                # Create package record
                $package = New-Object PSObject
                $package | Add-Member -MemberType NoteProperty -Name "ReviewID" -Value $ReviewID
                $package | Add-Member -MemberType NoteProperty -Name "GroupID" -Value $groupGuid
                $package | Add-Member -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                $package | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $group.Name
                $package | Add-Member -MemberType NoteProperty -Name "PrimaryOwnerEmail" -Value $primaryOwnerDisplay
                $package | Add-Member -MemberType NoteProperty -Name "SecondaryOwnerEmail" -Value $secondaryOwnerDisplay
                $package | Add-Member -MemberType NoteProperty -Name "OUPath" -Value $ouPath
                $package | Add-Member -MemberType NoteProperty -Name "Tag" -Value $category
                $package | Add-Member -MemberType NoteProperty -Name "Description" -Value (Get-SafeValue $group.Description)
                $package | Add-Member -MemberType NoteProperty -Name "DateCreated" -Value (Get-SafeValue $group.whenCreated)
                $package | Add-Member -MemberType NoteProperty -Name "LogicalGrouping" -Value $false
                $package | Add-Member -MemberType NoteProperty -Name "LogicalAccess" -Value ""
                # Stand-alone groups are never immutable
                $package | Add-Member -MemberType NoteProperty -Name "Immutable" -Value $false
                
                $packages1 += $package
                
                # Process group members
                try {
                    # Use enhanced member processing with depth control and membership source tracking
                    $allMembers = @()
                    
                    if ($groupsConfig.processingOptions.includeNestedGroups) {
                        # Get all members including nested with depth control
                        $allMembers = Get-NestedGroupMembers -Group $group -AdParams $adParams -MaxDepth $groupsConfig.processingOptions.maxRecursionDepth
                    } else {
                        # Get only direct members
                        $directMembers = Get-GroupMembers -Group $group -AdParams $adParams
                        if ($null -ne $directMembers -and $directMembers.Count -gt 0) {
                            foreach ($member in $directMembers) {
                                if ($member.objectClass -eq "user") {
                                    $memberInfo = @{
                                        User = $member
                                        SourceGroup = $group.Name
                                        MembershipPath = $group.Name
                                        Depth = 0
                                    }
                                    $allMembers += $memberInfo
                                }
                            }
                        }
                    }
                    
                    Write-Host "Found $($allMembers.Count) total members in standalone group $($group.Name)" -ForegroundColor DarkGray
                    
                    # Track members to avoid duplicates
                    $memberTracker = @{}
                    
                    foreach ($memberInfo in $allMembers) {
                        # Validate member info and user object
                        if (-not $memberInfo -or -not $memberInfo.User) {
                            Write-Warning "Invalid member info object, skipping"
                            continue
                        }
                        
                        # Check if user object has required properties
                        if (-not $memberInfo.User.sAMAccountName -and -not $memberInfo.User.distinguishedName) {
                            Write-Warning "User object missing both SamAccountName and distinguishedName, skipping"
                            continue
                        }
                        
                        try {
                            # Always fetch complete user object using SamAccountName for consistency
                            $user = $null
                            $userIdentity = $null
                            
                            # Determine the best identifier to use
                            if ($memberInfo.User.sAMAccountName) {
                                $userIdentity = $memberInfo.User.sAMAccountName
                                Write-Host "        Fetching user by SamAccountName: $userIdentity" -ForegroundColor DarkGray
                            } elseif ($memberInfo.User.distinguishedName) {
                                $userIdentity = $memberInfo.User.distinguishedName
                                Write-Host "        Fetching user by DistinguishedName: $userIdentity" -ForegroundColor DarkGray
                            } else {
                                Write-Warning "User object missing both SamAccountName and DistinguishedName"
                                continue
                            }
                            
                            try {
                                # Always get fresh user object with ALL properties
                                $user = Get-ADUser -Identity $userIdentity -Properties mail, givenName, surname, SamAccountName, Department, Title, Manager, Description, DisplayName, EmployeeID, Company, Office, OfficePhone, MobilePhone, Enabled @adParams
                            }
                            catch {
                                Write-Warning "Failed to fetch AD user '$userIdentity': $($_.Exception.Message)"
                                continue
                            }
                            
                            Write-Host "Processing user: $($user.SamAccountName)" -ForegroundColor DarkGray
                            
                            # Skip if user lookup failed
                            if (-not $user) { continue }
                            
                            # Check if user is exempt
                            $isExempt = Test-ExemptUser -User $user -ExemptTerms $groupsConfig.processingOptions.ExemptUsers
                            
                            # Get manager information
                            $managerName = ""
                            $managerEmail = ""
                            if ($user.Manager) {
                                try {
                                    $manager = Get-ADUser -Identity $user.Manager -Properties DisplayName, mail, Enabled @adParams
                                    if ($manager -and $manager.Enabled) {
                                        $managerName = Get-SafeValue $manager.DisplayName
                                        $managerEmail = Get-SafeValue $manager.mail
                                    }
                                } catch {
                                    Write-Warning "Failed to get manager info: $($_.Exception.Message)"
                                }
                            }
                            
                            # Determine FirstName value respecting Exempt status
                            $firstNameValue = if ($isExempt) { Get-SafeValue $user.SamAccountName } else { Get-SafeValue $user.givenName }
                            
                            $memberObj = New-Object PSObject
                            $memberObj | Add-Member -MemberType NoteProperty -Name "FirstName" -Value $firstNameValue
                            $memberObj | Add-Member -MemberType NoteProperty -Name "LastName" -Value (Get-SafeValue $user.surname)
                            $memberObj | Add-Member -MemberType NoteProperty -Name "Username" -Value (Get-SafeValue $user.SamAccountName)
                            $memberObj | Add-Member -MemberType NoteProperty -Name "Email" -Value (Get-SafeValue $user.mail)
                            $userID = if ($user.ObjectGUID) { $user.ObjectGUID.ToString() } else { "" }
                            $memberObj | Add-Member -MemberType NoteProperty -Name "UserID" -Value $userID
                            $memberObj | Add-Member -MemberType NoteProperty -Name "Department" -Value (Get-SafeValue $user.Department)
                            $memberObj | Add-Member -MemberType NoteProperty -Name "JobTitle" -Value (Get-SafeValue $user.Title)
                            $memberObj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value (Get-SafeValue $user.DisplayName)
                            $memberObj | Add-Member -MemberType NoteProperty -Name "Company" -Value (Get-SafeValue $user.Company)
                            $memberObj | Add-Member -MemberType NoteProperty -Name "Office" -Value (Get-SafeValue $user.Office)
                            $memberObj | Add-Member -MemberType NoteProperty -Name "OfficePhone" -Value (Get-SafeValue $user.OfficePhone)
                            $memberObj | Add-Member -MemberType NoteProperty -Name "MobilePhone" -Value (Get-SafeValue $user.MobilePhone)
                            $memberObj | Add-Member -MemberType NoteProperty -Name "EmployeeID" -Value (Get-SafeValue $user.EmployeeID)
                            $memberObj | Add-Member -MemberType NoteProperty -Name "Enabled" -Value $user.Enabled
                            $memberObj | Add-Member -MemberType NoteProperty -Name "ManagerName" -Value $managerName
                            $memberObj | Add-Member -MemberType NoteProperty -Name "ManagerEmail" -Value $managerEmail
                            $memberObj | Add-Member -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                            
                            # Add membership source info if enabled
                            if ($groupsConfig.processingOptions.includeMembershipSource) {
                                $memberObj | Add-Member -MemberType NoteProperty -Name "DerivedGroup" -Value $memberInfo.SourceGroup
                                $memberObj | Add-Member -MemberType NoteProperty -Name "MembershipPath" -Value $memberInfo.MembershipPath
                            } else {
                                $derivedGroup = if ($memberInfo.Depth -eq 0) { "" } else { $memberInfo.SourceGroup }
                                $memberObj | Add-Member -MemberType NoteProperty -Name "DerivedGroup" -Value $derivedGroup
                            }
                            
                            $memberObj | Add-Member -MemberType NoteProperty -Name "LogicalAccess" -Value ""
                            $memberObj | Add-Member -MemberType NoteProperty -Name "Exempt" -Value $isExempt
                            
                            $memberKey = "$($reviewPackageID)|$($user.SamAccountName)"

                            if ($memberTracker.ContainsKey($memberKey)) {
                                # Skip duplicate
                                Write-Host "Skipping duplicate user $($user.SamAccountName) (already recorded)" -ForegroundColor DarkGray
                            } else {
                                $memberTracker[$memberKey] = $memberObj
                                $packageMembers1 += $memberObj
                            }
                        }
                        catch {
                            Write-Warning "Failed to process user: $($_.Exception.Message)"
                            if ($memberInfo -and $memberInfo.User) {
                                Write-Warning "  User object properties: DistinguishedName=$($memberInfo.User.distinguishedName), ObjectClass=$($memberInfo.User.objectClass), SamAccountName=$($memberInfo.User.sAMAccountName)"
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Failed to get group members for $($group.Name): $($_.Exception.Message)"
                }
            }
        } else {
            Write-Host "LDAP processing for group enumeration not yet implemented" -ForegroundColor Yellow
            $allGroups = @()
        }
    }
    catch {
        Write-Warning "Failed to process OU: $($_.Exception.Message)"
    }
    
    # Clear the child progress bar when OU processing is complete
    Write-Progress -Activity "Processing Groups in OU" -Completed -Id 2
}

# Clear the main progress bar when all group processing is complete
Write-Progress -Activity "Processing Group OUs" -Completed -Id 1

} else {
    Write-Host "Skipping group processing (PrivilegeOnly mode)" -ForegroundColor Yellow
}

Write-Host "Found $($packages1.Count) groups with $($packageMembers1.Count) members" -ForegroundColor Green

# Process privileges
if (-not $GroupsOnly) {
    Write-Host "Processing privileges..." -ForegroundColor Cyan
    
    $totalPrivilegeOUs = $privilegeConfig.ouPaths.Count
    $currentPrivilegeOUIndex = 0
    
    foreach ($ouPath in $privilegeConfig.ouPaths) {
        $currentPrivilegeOUIndex++
        
        # Progress bar for privilege OU processing
        Write-Progress -Activity "Processing Privilege OUs" -Status "Processing OU: $ouPath" -PercentComplete (($currentPrivilegeOUIndex / $totalPrivilegeOUs) * 100) -Id 1
        
        Write-Host "Processing OU: $ouPath" -ForegroundColor Yellow
        
        try {
            # First test if the OU exists and is accessible
            Write-Host "  Testing OU accessibility..." -ForegroundColor DarkGray
            try {
                $testOU = Get-ADOrganizationalUnit -Identity $ouPath @adParams
                Write-Host "  OU accessible: $($testOU.Name)" -ForegroundColor Green
            }
            catch {
                Write-Warning "  Cannot access OU: $($_.Exception.Message)"
                continue
            }
            
            if ($useADModule) {
                # Get all users in the OU with required attributes
                Write-Host "  Querying users from OU..." -ForegroundColor DarkGray
                
                # Add timeout for the AD query
                $userSearchScope = if ($privilegeConfig.processingOptions.userSearchScope) { $privilegeConfig.processingOptions.userSearchScope } else { 'OneLevel' }

                $adJob = Start-Job -ScriptBlock {
                    param($ouPath, $adParams, $scope)
                    Import-Module ActiveDirectory
                    Get-ADUser -Filter * -SearchBase $ouPath -SearchScope $scope -Properties sAMAccountName, displayName, mail, department, title, manager, enabled, lastLogonDate, memberOf, distinguishedName, userPrincipalName, employeeID @adParams
                } -ArgumentList $ouPath, $adParams, $userSearchScope
                
                # Wait for job with timeout (configurable)
                $timeout = $privilegeConfig.processingOptions.queryTimeoutSeconds
                $completed = Wait-Job -Job $adJob -Timeout $timeout
                
                if ($completed) {
                    $users = Receive-Job -Job $adJob
                    Remove-Job -Job $adJob
                } else {
                    Write-Warning "  AD query timed out after $timeout seconds. Stopping job..."
                    Stop-Job -Job $adJob
                    Remove-Job -Job $adJob
                    Write-Warning "AD query for OU '$ouPath' timed out. This OU may be too large or there may be connectivity issues."
                    Write-Host "  SUGGESTION: Try increasing 'queryTimeoutSeconds' in privilege.json or reduce 'maxUsersPerOU'" -ForegroundColor Yellow
                    Write-Host "  SUGGESTION: Consider breaking large OUs into smaller sub-OUs for better performance" -ForegroundColor Yellow
                    continue
                }
                
                Write-Host "  Found $($users.Count) users to process" -ForegroundColor Green
                
                # Apply user limit if configured
                $maxUsers = $privilegeConfig.processingOptions.maxUsersPerOU
                if ($maxUsers -gt 0 -and $users.Count -gt $maxUsers) {
                    Write-Warning "  User count ($($users.Count)) exceeds limit ($maxUsers). Processing first $maxUsers users only."
                    $users = $users | Select-Object -First $maxUsers
                }
                
                $userCount = 0
                
                foreach ($user in $users) {
                    $userCount++
                    
                    # Progress bar for user processing
                    Write-Progress -Activity "Processing Users in OU" -Status "Processing user: $($user.SamAccountName)" -PercentComplete (($userCount / $users.Count) * 100) -Id 2 -ParentId 1
                    
                    # Progress reporting for all users when there are only 50
                    Write-Host "    Processing user $userCount/$($users.Count): $($user.SamAccountName)" -ForegroundColor DarkGray
                    
                    # Skip disabled users if configured
                    if (-not $privilegeConfig.processingOptions.includeDisabledUsers -and -not $user.enabled) {
                        Write-Host "      Skipping disabled user: $($user.SamAccountName)" -ForegroundColor Yellow
                        continue
                    }
                    
                    Write-Host "      Creating user package..." -ForegroundColor DarkGray
                    $userGuid = Get-SimpleObjectGuid $user $false
                    $reviewPackageID = New-SimpleGuid "$($user.SamAccountName)|$ReviewID|$userGuid"
                    
                    # Create user package (Reverification System Packages 1-2)
                    $package = New-Object PSObject
                    $package | Add-Member -MemberType NoteProperty -Name "ReviewID" -Value $ReviewID
                    $package | Add-Member -MemberType NoteProperty -Name "GroupID" -Value $userGuid
                    $package | Add-Member -MemberType NoteProperty -Name "GroupName" -Value (Get-SafeValue $user.DisplayName)
                    $package | Add-Member -MemberType NoteProperty -Name "OUPath" -Value $ouPath
                    $package | Add-Member -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                    
                    $packages2 += $package
                    
                    # Process user's group memberships
                    if ($user.memberOf) {
                        Write-Host "      Processing $($user.memberOf.Count) group memberships..." -ForegroundColor DarkGray
                        $groupCount = 0
                        
                        foreach ($groupDN in $user.memberOf) {
                            $groupCount++
                            Write-Host "        Group $groupCount/$($user.memberOf.Count): $groupDN" -ForegroundColor DarkGray
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
                                    Write-Host "          Getting group details..." -ForegroundColor DarkGray
                                    $group = Get-ADGroup -Identity $groupDN -Properties Description, whenCreated @adParams
                                    Write-Host "          Group found: $($group.Name)" -ForegroundColor DarkGray
                                    
                                    $groupGuid = Get-SimpleObjectGuid $group $false
                                    
                                    # Create privilege group record (Reverification Privilege Groups 1)
                                    $privilegeGroup = New-Object PSObject
                                    $privilegeGroup | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $group.Name
                                    $privilegeGroup | Add-Member -MemberType NoteProperty -Name "GroupID" -Value $groupGuid
                                    $privilegeGroup | Add-Member -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                                    $privilegeGroup | Add-Member -MemberType NoteProperty -Name "Description" -Value (Get-SafeValue $group.Description)
                                    $privilegeGroup | Add-Member -MemberType NoteProperty -Name "DateCreated" -Value (Get-SafeValue $group.whenCreated)
                                    
                                    $privilegeGroups += $privilegeGroup
                                    Write-Host "          Added privilege group record" -ForegroundColor DarkGray
                                }
                                catch {
                                    Write-Warning "          Failed to get group info for $groupDN : $($_.Exception.Message)"
                                }
                            } else {
                                Write-Host "          Group excluded by filter" -ForegroundColor Yellow
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
        
        # Clear the child progress bar when OU processing is complete
        Write-Progress -Activity "Processing Users in OU" -Completed -Id 2
    }
    
    # Clear the main progress bar when all privilege processing is complete
    Write-Progress -Activity "Processing Privilege OUs" -Completed -Id 1
    
    Write-Host "Found $($packages2.Count) users with $($privilegeGroups.Count) group memberships" -ForegroundColor Green
}

# Generate output
Write-Host "Generating output files..." -ForegroundColor Cyan

# Use -Output parameter if provided, otherwise use config.json OutputFolder
if ($Output) {
    $outputPath = $Output
    # Handle relative paths
    if ($Output -match "^\.\.") {
        $outputPath = Join-Path $scriptPath $Output
    }
} else {
    $outputPath = $config.OutputFolder
    if ($config.OutputFolder -match "^\.\.") {
        $outputPath = Join-Path $scriptPath $config.OutputFolder
    }
}

if (-not (Test-Path $outputPath)) {
    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
    Write-Host "Created output directory: $outputPath" -ForegroundColor Yellow
}

# Use -Name parameter if provided, otherwise use config.json OutputFiles
if ($Name) {
    $outputFiles = @{
        Packages1 = "${Name}_Packages1.csv"
        PackageMembers1 = "${Name}_PackageMembers1.csv"
        Packages2 = "${Name}_Packages2.csv"
        PrivilegeGroups = "${Name}_PrivilegeGroups.csv"
    }
} else {
    $outputFiles = @{
        Packages1 = $config.OutputFiles.Packages1 -replace '{ReviewId}', $ReviewID
        PackageMembers1 = $config.OutputFiles.PackageMembers1 -replace '{ReviewId}', $ReviewID
        Packages2 = $config.OutputFiles.Packages2 -replace '{ReviewId}', $ReviewID
        PrivilegeGroups = $config.OutputFiles.PrivilegeGroups -replace '{ReviewId}', $ReviewID
    }
}

# Export group-related files (skip if PrivilegeOnly)
if (-not $PrivilegeOnly) {
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
}

# Export privilege-related files (skip if GroupsOnly)  
if (-not $GroupsOnly) {
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

# Stop transcript if it was started
if ($TranscriptStarted) {
    try { Stop-Transcript | Out-Null } catch {}
}
