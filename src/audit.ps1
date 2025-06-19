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

# Helper function to check if a user is exempt
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

# Helper function to check if a group should be excluded
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
        $systemGroupPrefixes = @("Domain ", "Enterprise ", "Schema ", "BUILTIN\\", "NT AUTHORITY\\")
        $systemGroupNames = @("Domain Admins", "Domain Users", "Domain Guests", "Domain Controllers", "Enterprise Admins", "Schema Admins", "Authenticated Users", "Everyone")
        
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

# Helper function to get nested group members with depth control
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
        $directMembers = Get-ADGroupMember -Identity $Group @AdParams
        
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

# Helper function to search Active Directory for a user by name and return email
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

# Helper function to extract owner information using regex
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

# Helper function to extract the best owner information from logical groups
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

foreach ($groupConfig in $groupsConfig.groups) {
    $ouPath = $groupConfig.path
    $category = $groupConfig.category
    $logicalConfig = $groupConfig.Logical
    
    Write-Host "Processing OU: $ouPath (Category: $category)" -ForegroundColor Yellow
    
    try {
        if ($useADModule) {
            # Get all groups in the OU
            $allGroups = Get-ADGroup -Filter * -SearchBase $ouPath -Properties Name, Description, Info, GroupCategory, GroupScope, DistinguishedName @adParams
            Write-Host "Found $($allGroups.Count) total groups in OU" -ForegroundColor Cyan
            
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
            foreach ($logicalGroupName in $logicalGroups.Keys) {
                $logicalGroup = $logicalGroups[$logicalGroupName]
                
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
                $package | Add-Member -MemberType NoteProperty -Name "LogicalGrouping" -Value $true
                $package | Add-Member -MemberType NoteProperty -Name "LogicalAccess" -Value $combinedAccessLevels
                
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
                            $directMembers = Get-ADGroupMember -Identity $subGroup @adParams
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
                        
                        Write-Host "Found $($allMembers.Count) total members in subgroup $($subGroup.Name)" -ForegroundColor DarkGray
                        
                        foreach ($memberInfo in $allMembers) {
                            try {
                                $user = Get-ADUser -Identity $memberInfo.User.distinguishedName -Properties mail, givenName, surname, SamAccountName, Department, Title, Manager, Description @adParams
                                
                                Write-Host "Processing user: $($user.SamAccountName) with access: $logicalAccess" -ForegroundColor DarkGray
                                
                                # Check if user is exempt
                                $isExempt = Test-ExemptUser -User $user -ExemptTerms $groupsConfig.processingOptions.ExemptUsers
                                
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
                                
                                # Add membership source info if enabled
                                if ($groupsConfig.processingOptions.includeMembershipSource) {
                                    $memberObj | Add-Member -MemberType NoteProperty -Name "DerivedGroup" -Value $memberInfo.SourceGroup
                                    $memberObj | Add-Member -MemberType NoteProperty -Name "MembershipPath" -Value $memberInfo.MembershipPath
                                } else {
                                    $memberObj | Add-Member -MemberType NoteProperty -Name "DerivedGroup" -Value (if ($memberInfo.Depth -eq 0) { "" } else { $memberInfo.SourceGroup })
                                }
                                
                                $memberObj | Add-Member -MemberType NoteProperty -Name "LogicalAccess" -Value $logicalAccess
                                $memberObj | Add-Member -MemberType NoteProperty -Name "Exempt" -Value $isExempt
                                
                                $packageMembers1 += $memberObj
                            }
                            catch {
                                Write-Warning "Failed to process user: $($_.Exception.Message)"
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
                $package | Add-Member -MemberType NoteProperty -Name "LogicalGrouping" -Value $false
                $package | Add-Member -MemberType NoteProperty -Name "LogicalAccess" -Value ""
                
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
                        $directMembers = Get-ADGroupMember -Identity $group @adParams
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
                    
                    Write-Host "Found $($allMembers.Count) total members in standalone group $($group.Name)" -ForegroundColor DarkGray
                    
                    foreach ($memberInfo in $allMembers) {
                        try {
                            $user = Get-ADUser -Identity $memberInfo.User.distinguishedName -Properties mail, givenName, surname, SamAccountName, Department, Title, Manager, Description @adParams
                            
                            Write-Host "Processing user: $($user.SamAccountName)" -ForegroundColor DarkGray
                            
                            # Check if user is exempt
                            $isExempt = Test-ExemptUser -User $user -ExemptTerms $groupsConfig.processingOptions.ExemptUsers
                            
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
                            
                            # Add membership source info if enabled
                            if ($groupsConfig.processingOptions.includeMembershipSource) {
                                $memberObj | Add-Member -MemberType NoteProperty -Name "DerivedGroup" -Value $memberInfo.SourceGroup
                                $memberObj | Add-Member -MemberType NoteProperty -Name "MembershipPath" -Value $memberInfo.MembershipPath
                            } else {
                                $memberObj | Add-Member -MemberType NoteProperty -Name "DerivedGroup" -Value (if ($memberInfo.Depth -eq 0) { "" } else { $memberInfo.SourceGroup })
                            }
                            
                            $memberObj | Add-Member -MemberType NoteProperty -Name "LogicalAccess" -Value ""
                            $memberObj | Add-Member -MemberType NoteProperty -Name "Exempt" -Value $isExempt
                            
                            $packageMembers1 += $memberObj
                        }
                        catch {
                            Write-Warning "Failed to process user: $($_.Exception.Message)"
                        }
                    }
                }
                catch {
                    Write-Warning "Failed to get group members for $($group.Name): $($_.Exception.Message)"
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

} else {
    Write-Host "Skipping group processing (PrivilegeOnly mode)" -ForegroundColor Yellow
}

Write-Host "Found $($packages1.Count) groups with $($packageMembers1.Count) members" -ForegroundColor Green

# Process privileges
if (-not $GroupsOnly) {
    Write-Host "Processing privileges..." -ForegroundColor Cyan
    
    foreach ($ouPath in $privilegeConfig.ouPaths) {
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
                $adJob = Start-Job -ScriptBlock {
                    param($ouPath, $adParams)
                    Import-Module ActiveDirectory
                    Get-ADUser -Filter * -SearchBase $ouPath -Properties sAMAccountName, displayName, mail, department, title, manager, enabled, lastLogonDate, memberOf, distinguishedName, userPrincipalName, employeeID @adParams
                } -ArgumentList $ouPath, $adParams
                
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
                                    $group = Get-ADGroup -Identity $groupDN -Properties Description @adParams
                                    Write-Host "          Group found: $($group.Name)" -ForegroundColor DarkGray
                                    
                                    $groupGuid = Get-SimpleObjectGuid $group $false
                                    
                                    # Create privilege group record (Reverification Privilege Groups 1)
                                    $privilegeGroup = New-Object PSObject
                                    $privilegeGroup | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $group.Name
                                    $privilegeGroup | Add-Member -MemberType NoteProperty -Name "GroupID" -Value $groupGuid
                                    $privilegeGroup | Add-Member -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                                    $privilegeGroup | Add-Member -MemberType NoteProperty -Name "Description" -Value (Get-SafeValue $group.Description)
                                    
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
