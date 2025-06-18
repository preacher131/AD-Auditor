[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ReviewID,
    
    [switch]$GroupsOnly,
    [switch]$PrivilegeOnly,
    
    [string]$ConfigPath = $null
)

# PowerShell 5.1 compatibility
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Initialize paths
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ConfigPath) {
    $ConfigPath = Join-Path $scriptPath "..\configs"
}

Write-Host "=== AD Entitlement Review System ===" -ForegroundColor Cyan
Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Yellow
Write-Host "Review ID: $ReviewID" -ForegroundColor Green

# Load LDAP module
try {
    $ldapModule = Join-Path $scriptPath "Modules\LDAP.psm1"
    Import-Module $ldapModule -Force
    Write-Host "✓ LDAP module loaded" -ForegroundColor Green
}
catch {
    Write-Error "Failed to load LDAP module: $($_.Exception.Message)"
    exit 1
}

# Load configurations
Write-Host "Loading configurations..." -ForegroundColor Cyan

$config = $null
$groupsConfig = $null
$privilegeConfig = $null

try {
    $configFile = Join-Path $ConfigPath "config.json"
    $config = Get-Content $configFile -Raw | ConvertFrom-Json
    Write-Host "✓ Main config loaded" -ForegroundColor Green
    
    $groupsFile = Join-Path $ConfigPath "groups.json"
    $groupsConfig = Get-Content $groupsFile -Raw | ConvertFrom-Json
    Write-Host "✓ Groups config loaded" -ForegroundColor Green
    
    $privilegeFile = Join-Path $ConfigPath "privilege.json"
    $privilegeConfig = Get-Content $privilegeFile -Raw | ConvertFrom-Json
    Write-Host "✓ Privilege config loaded" -ForegroundColor Green
}
catch {
    Write-Error "Configuration loading failed: $($_.Exception.Message)"
    exit 1
}

# Helper functions
function Get-SafeString {
    param($Value, $Default = "")
    if ($Value -eq $null -or [string]::IsNullOrEmpty($Value)) {
        return $Default
    }
    return $Value.ToString()
}

function New-DeterministicGuid {
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
        Write-Warning "GUID generation failed for '$Input': $($_.Exception.Message)"
        return [System.Guid]::NewGuid().ToString()
    }
}

function Get-ObjectGuid {
    param($Object, [bool]$IsLdap = $false)
    
    try {
        if ($IsLdap) {
            if ($Object.Attributes -and $Object.Attributes.ContainsKey("objectGUID")) {
                $guidBytes = $Object.Attributes["objectGUID"][0]
                $guid = New-Object System.Guid -ArgumentList $guidBytes
                return $guid.ToString()
            }
            if ($Object.Attributes -and $Object.Attributes.ContainsKey("distinguishedName")) {
                return New-DeterministicGuid $Object.Attributes["distinguishedName"][0]
            }
        }
        else {
            if ($Object.ObjectGUID) {
                return $Object.ObjectGUID.ToString()
            }
        }
        return New-DeterministicGuid $Object.ToString()
    }
    catch {
        Write-Warning "Failed to get object GUID: $($_.Exception.Message)"
        return New-DeterministicGuid $Object.ToString()
    }
}

function Get-OwnerEmails {
    param([string]$InfoText)
    
    $result = @{
        PrimaryOwner = ""
        SecondaryOwner = ""
    }
    
    if ([string]::IsNullOrWhiteSpace($InfoText)) {
        return $result
    }
    
    if ($groupsConfig.ownerRegexPatterns) {
        foreach ($pattern in $groupsConfig.ownerRegexPatterns) {
            try {
                if ($InfoText -match $pattern.pattern) {
                    $email = $matches[$pattern.captureGroup]
                    
                    if ($pattern.name -like "*Primary*" -and [string]::IsNullOrEmpty($result.PrimaryOwner)) {
                        $result.PrimaryOwner = $email
                    }
                    elseif ($pattern.name -like "*Secondary*" -and [string]::IsNullOrEmpty($result.SecondaryOwner)) {
                        $result.SecondaryOwner = $email
                    }
                    elseif ([string]::IsNullOrEmpty($result.PrimaryOwner)) {
                        $result.PrimaryOwner = $email
                    }
                }
            }
            catch {
                Write-Warning "Owner pattern processing failed: $($_.Exception.Message)"
            }
        }
    }
    
    return $result
}

function Get-LogicalGroupInfo {
    param([string]$GroupName, $GroupConfig)
    
    $result = @{
        IsLogical = $false
        BaseName = $GroupName
        Access = Get-SafeString $GroupConfig.category
    }
    
    if (-not $GroupConfig.Logical.isLogical) {
        return $result
    }
    
    if ($GroupConfig.Logical.grouping) {
        $properties = $GroupConfig.Logical.grouping | Get-Member -MemberType NoteProperty
        foreach ($prop in $properties) {
            $suffix = $prop.Name
            if ($GroupName -like "*$suffix") {
                $result.IsLogical = $true
                $result.BaseName = $GroupName.Replace($suffix, "")
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

# Connection setup
Write-Host "Establishing connection..." -ForegroundColor Cyan

$useADModule = $false
$ldapConnection = $null
$adParams = @{}

$connectionType = "LDAP"
if ($config.Connection.Type) {
    $connectionType = $config.Connection.Type.ToUpper()
}
elseif ($config.Connection.UseLDAPS) {
    $connectionType = "LDAPS"
}

Write-Host "Connection type: $connectionType" -ForegroundColor Yellow
Write-Host "Domain Controller: $($config.DomainController)" -ForegroundColor Yellow

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
            Write-Host "✓ Connected using ActiveDirectory module" -ForegroundColor Green
        }
        catch {
            Write-Warning "ActiveDirectory module failed, falling back to LDAP: $($_.Exception.Message)"
            $connectionType = "LDAP"
        }
    }
    
    if ($connectionType -eq "LDAP" -or $connectionType -eq "LDAPS") {
        $useLDAPS = ($connectionType -eq "LDAPS")
        
        $ldapConnection = New-LdapConnection -Server $config.DomainController -UseLDAPS $useLDAPS -UseCurrentUser $config.Connection.UseCurrentUser -Username $config.Connection.CredentialProfile.Username -Password $config.Connection.CredentialProfile.Password -Domain $config.Connection.CredentialProfile.Domain
        
        $useADModule = $false
        Write-Host "✓ Connected using $connectionType" -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to establish connection: $($_.Exception.Message)"
    exit 1
}

# Initialize result collections
$packages1 = @()
$packageMembers1 = @()
$packages2 = @()
$privilegeGroups = @()

# Process groups
if (-not $PrivilegeOnly) {
    Write-Host "Processing groups..." -ForegroundColor Cyan
    
    foreach ($groupConfig in $groupsConfig.groups) {
        $baseDN = Get-SafeString $groupConfig.path
        Write-Host "  Processing OU: $baseDN" -ForegroundColor Yellow
        
        try {
            if ($useADModule) {
                $groups = Get-ADGroup -Filter * -SearchBase $baseDN -Properties Description, info @adParams
                
                foreach ($group in $groups) {
                    $logicalInfo = Get-LogicalGroupInfo $group.Name $groupConfig
                    $owners = Get-OwnerEmails (Get-SafeString $group.info)
                    $groupGuid = Get-ObjectGuid $group $false
                    $reviewPackageID = New-DeterministicGuid "$($logicalInfo.BaseName)|$ReviewID|$groupGuid"
                    
                    $package = New-Object PSObject
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "ReviewID" -Value $ReviewID
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "GroupID" -Value $groupGuid
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "GroupName" -Value $logicalInfo.BaseName
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "PrimaryOwnerEmail" -Value (Get-SafeString $owners.PrimaryOwner)
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "SecondaryOwnerEmail" -Value (Get-SafeString $owners.SecondaryOwner)
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "OUPath" -Value $baseDN
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "Tag" -Value (Get-SafeString $groupConfig.category)
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "Description" -Value (Get-SafeString $group.Description)
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "LogicalGrouping" -Value $logicalInfo.IsLogical
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "LogicalAccess" -Value (Get-SafeString $logicalInfo.Access)
                    
                    $packages1 += $package
                    
                    try {
                        $members = Get-ADGroupMember -Identity $group -Recursive @adParams | Where-Object { $_.objectClass -eq "user" }
                        
                        foreach ($member in $members) {
                            try {
                                $user = Get-ADUser -Identity $member.distinguishedName -Properties Department, Title, Manager, mail, givenName, surname @adParams
                                
                                $managerName = ""
                                $managerEmail = ""
                                
                                if ($user.Manager) {
                                    try {
                                        $mgr = Get-ADUser -Identity $user.Manager -Properties DisplayName, mail @adParams
                                        $managerName = Get-SafeString $mgr.DisplayName
                                        $managerEmail = Get-SafeString $mgr.mail
                                    }
                                    catch {
                                        # Manager lookup failed
                                    }
                                }
                                
                                $firstName = Get-SafeString $user.givenName
                                $lastName = Get-SafeString $user.surname
                                $fullName = "$firstName $lastName".Trim()
                                
                                $memberObj = New-Object PSObject
                                Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "FirstName" -Value $firstName
                                Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "LastName" -Value $lastName
                                Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "Email" -Value (Get-SafeString $user.mail)
                                Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "UserID" -Value $user.ObjectGUID.ToString()
                                Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "Username" -Value $fullName
                                Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "Department" -Value (Get-SafeString $user.Department)
                                Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "JobTitle" -Value (Get-SafeString $user.Title)
                                Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "ManagerName" -Value $managerName
                                Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "ManagerEmail" -Value $managerEmail
                                Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                                Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "DerivedGroup" -Value $group.Name
                                Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "LogicalAccess" -Value (Get-SafeString $logicalInfo.Access)
                                
                                $packageMembers1 += $memberObj
                            }
                            catch {
                                Write-Warning "Failed to process user: $($_.Exception.Message)"
                            }
                        }
                    }
                    catch {
                        Write-Warning "Failed to get group members: $($_.Exception.Message)"
                    }
                }
            }
            else {
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
                    
                    $logicalInfo = Get-LogicalGroupInfo $groupName $groupConfig
                    
                    $infoText = ""
                    if ($group.Attributes.ContainsKey("info")) {
                        $infoText = $group.Attributes["info"][0]
                    }
                    
                    $owners = Get-OwnerEmails $infoText
                    $groupGuid = Get-ObjectGuid $group $true
                    $reviewPackageID = New-DeterministicGuid "$($logicalInfo.BaseName)|$ReviewID|$groupGuid"
                    
                    $groupDescription = ""
                    if ($group.Attributes.ContainsKey("description")) {
                        $groupDescription = Get-SafeString $group.Attributes["description"][0]
                    }
                    
                    $package = New-Object PSObject
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "ReviewID" -Value $ReviewID
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "GroupID" -Value $groupGuid
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "GroupName" -Value $logicalInfo.BaseName
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "PrimaryOwnerEmail" -Value (Get-SafeString $owners.PrimaryOwner)
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "SecondaryOwnerEmail" -Value (Get-SafeString $owners.SecondaryOwner)
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "OUPath" -Value $baseDN
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "Tag" -Value (Get-SafeString $groupConfig.category)
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "Description" -Value $groupDescription
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "LogicalGrouping" -Value $logicalInfo.IsLogical
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "LogicalAccess" -Value (Get-SafeString $logicalInfo.Access)
                    
                    $packages1 += $package
                    
                    try {
                        if ($group.Attributes.ContainsKey("member")) {
                            foreach ($memberDN in $group.Attributes["member"]) {
                                try {
                                    $userEntry = Invoke-LdapSearch -Ldap $ldapConnection -BaseDN $memberDN -Filter "(objectClass=user)" -Attributes @("givenName","sn","mail","department","title","manager","displayName") | Select-Object -First 1
                                    
                                    if ($userEntry) {
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
                                            }
                                            catch {
                                                # Manager lookup failed
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
                                        
                                        $memberObj = New-Object PSObject
                                        Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "FirstName" -Value $firstName
                                        Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "LastName" -Value $lastName
                                        Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "Email" -Value $email
                                        Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "UserID" -Value (Get-ObjectGuid $userEntry $true)
                                        Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "Username" -Value $fullName
                                        Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "Department" -Value $department
                                        Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "JobTitle" -Value $jobTitle
                                        Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "ManagerName" -Value $managerName
                                        Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "ManagerEmail" -Value $managerEmail
                                        Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                                        Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "DerivedGroup" -Value $groupName
                                        Add-Member -InputObject $memberObj -MemberType NoteProperty -Name "LogicalAccess" -Value (Get-SafeString $logicalInfo.Access)
                                        
                                        $packageMembers1 += $memberObj
                                    }
                                }
                                catch {
                                    Write-Warning "Failed to process member: $($_.Exception.Message)"
                                }
                            }
                        }
                    }
                    catch {
                        Write-Warning "Failed to process group members: $($_.Exception.Message)"
                    }
                }
            }
        }
        catch {
            Write-Warning "Failed to process OU '$baseDN': $($_.Exception.Message)"
        }
    }
    
    Write-Host "  Found $($packages1.Count) groups with $($packageMembers1.Count) members" -ForegroundColor Green
}

# Process privileges
if (-not $GroupsOnly) {
    Write-Host "Processing privileges..." -ForegroundColor Cyan
    
    foreach ($ouPath in $privilegeConfig.ouPaths) {
        Write-Host "  Processing OU: $ouPath" -ForegroundColor Yellow
        
        try {
            if ($useADModule) {
                $users = Get-ADUser -Filter * -SearchBase $ouPath -Properties memberOf, DisplayName @adParams
                
                foreach ($user in $users) {
                    $userGuid = Get-ObjectGuid $user $false
                    $reviewPackageID = New-DeterministicGuid "$($user.SamAccountName)|$ReviewID|$userGuid"
                    
                    $package = New-Object PSObject
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "ReviewID" -Value $ReviewID
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "GroupID" -Value $userGuid
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "GroupName" -Value (Get-SafeString $user.DisplayName)
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "OUPath" -Value $ouPath
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                    
                    $packages2 += $package
                    
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
                                $groupGuid = Get-ObjectGuid $group $false
                                
                                $privilegeGroup = New-Object PSObject
                                Add-Member -InputObject $privilegeGroup -MemberType NoteProperty -Name "GroupName" -Value (Get-SafeString $group.Name)
                                Add-Member -InputObject $privilegeGroup -MemberType NoteProperty -Name "GroupID" -Value $groupGuid
                                Add-Member -InputObject $privilegeGroup -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                                Add-Member -InputObject $privilegeGroup -MemberType NoteProperty -Name "Description" -Value (Get-SafeString $group.Description)
                                
                                $privilegeGroups += $privilegeGroup
                            }
                            catch {
                                Write-Warning "Failed to get group info: $($_.Exception.Message)"
                            }
                        }
                    }
                }
            }
            else {
                $userFilter = "(objectClass=user)"
                $users = Invoke-LdapSearch -Ldap $ldapConnection -BaseDN $ouPath -Filter $userFilter -Attributes @("sAMAccountName","displayName","distinguishedName","memberOf")
                
                foreach ($user in $users) {
                    $userGuid = Get-ObjectGuid $user $true
                    
                    $samAccountName = ""
                    if ($user.Attributes.ContainsKey("sAMAccountName")) {
                        $samAccountName = Get-SafeString $user.Attributes["sAMAccountName"][0]
                    }
                    
                    $reviewPackageID = New-DeterministicGuid "$samAccountName|$ReviewID|$userGuid"
                    
                    $displayName = $samAccountName
                    if ($user.Attributes.ContainsKey("displayName")) {
                        $displayName = Get-SafeString $user.Attributes["displayName"][0]
                    }
                    
                    $package = New-Object PSObject
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "ReviewID" -Value $ReviewID
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "GroupID" -Value $userGuid
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "GroupName" -Value $displayName
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "OUPath" -Value $ouPath
                    Add-Member -InputObject $package -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                    
                    $packages2 += $package
                    
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
                                    $groupGuid = Get-ObjectGuid $groupEntry $true
                                    
                                    $groupName = ""
                                    if ($groupEntry.Attributes.ContainsKey("cn")) {
                                        $groupName = Get-SafeString $groupEntry.Attributes["cn"][0]
                                    }
                                    
                                    $groupDescription = ""
                                    if ($groupEntry.Attributes.ContainsKey("description")) {
                                        $groupDescription = Get-SafeString $groupEntry.Attributes["description"][0]
                                    }
                                    
                                    $privilegeGroup = New-Object PSObject
                                    Add-Member -InputObject $privilegeGroup -MemberType NoteProperty -Name "GroupName" -Value $groupName
                                    Add-Member -InputObject $privilegeGroup -MemberType NoteProperty -Name "GroupID" -Value $groupGuid
                                    Add-Member -InputObject $privilegeGroup -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                                    Add-Member -InputObject $privilegeGroup -MemberType NoteProperty -Name "Description" -Value $groupDescription
                                    
                                    $privilegeGroups += $privilegeGroup
                                }
                            }
                            catch {
                                Write-Warning "Failed to get group info: $($_.Exception.Message)"
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-Warning "Failed to process OU '$ouPath': $($_.Exception.Message)"
        }
    }
    
    Write-Host "  Found $($packages2.Count) users with $($privilegeGroups.Count) group memberships" -ForegroundColor Green
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
    Write-Host "  ✓ $($outputFiles.Packages1) ($($packages1.Count) records)" -ForegroundColor Green
}

if ($packageMembers1.Count -gt 0) {
    $filePath = Join-Path $outputPath $outputFiles.PackageMembers1
    $packageMembers1 | Export-Csv -Path $filePath -NoTypeInformation
    Write-Host "  ✓ $($outputFiles.PackageMembers1) ($($packageMembers1.Count) records)" -ForegroundColor Green
}

if ($packages2.Count -gt 0) {
    $filePath = Join-Path $outputPath $outputFiles.Packages2
    $packages2 | Export-Csv -Path $filePath -NoTypeInformation
    Write-Host "  ✓ $($outputFiles.Packages2) ($($packages2.Count) records)" -ForegroundColor Green
}

if ($privilegeGroups.Count -gt 0) {
    $filePath = Join-Path $outputPath $outputFiles.PrivilegeGroups
    $privilegeGroups | Export-Csv -Path $filePath -NoTypeInformation
    Write-Host "  ✓ $($outputFiles.PrivilegeGroups) ($($privilegeGroups.Count) records)" -ForegroundColor Green
}

Write-Host ""
Write-Host ("=" * 60) -ForegroundColor Green
Write-Host "✓ AD Entitlement Review completed successfully!" -ForegroundColor Green
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
