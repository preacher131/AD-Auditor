# ADConnection.psm1
# Module for Active Directory connection and query operations
# Provides RSAT cmdlet functionality with ADSI fallback

# Module-wide variables
$script:DirectoryContext = $null
$script:UseADSI = $false
$script:DomainController = $null

# Test if Active Directory module is available
function Test-ADModuleAvailable {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        return $true
    }
    catch {
        Write-Warning "Active Directory module not available. Falling back to ADSI."
        return $false
    }
}

# Initialize module and determine AD access method
function Initialize-ADAccess {
    $script:UseADSI = -not (Test-ADModuleAvailable)
    
    if ($script:UseADSI) {
        try {
            # Get current domain for ADSI operations
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $script:DomainController = $domain.PdcRoleOwner.Name
            Write-Verbose "Using ADSI with domain controller: $script:DomainController"
        }
        catch {
            Write-Error "Failed to initialize ADSI connection: $_"
            throw
        }
    }
    else {
        Write-Verbose "Using Active Directory PowerShell module"
    }
}

<#
.SYNOPSIS
Establishes connection to Active Directory

.DESCRIPTION
Accepts optional PSCredential and sets module-wide variable for later queries.
Automatically detects whether to use RSAT cmdlets or ADSI fallback.

.PARAMETER Credential
Optional PSCredential object for authentication

.PARAMETER Server
Optional domain controller to connect to

.EXAMPLE
Connect-Ad
Connect-Ad -Credential (Get-Credential)
#>
function Connect-Ad {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [string]$Server
    )
    
    try {
        # Initialize AD access method
        Initialize-ADAccess
        
        # Store connection context
        $script:DirectoryContext = @{
            Credential = $Credential
            Server = $Server
            Connected = $false
            UseADSI = $script:UseADSI
        }
        
        # Test connection
        if ($script:UseADSI) {
            Test-ADSIConnection -Credential $Credential -Server $Server
        }
        else {
            Test-RSATConnection -Credential $Credential -Server $Server
        }
        
        $script:DirectoryContext.Connected = $true
        Write-Verbose "Successfully connected to Active Directory"
    }
    catch {
        Write-Error "Failed to connect to Active Directory: $_"
        throw
    }
}

# Test RSAT connection
function Test-RSATConnection {
    param(
        [PSCredential]$Credential,
        [string]$Server
    )
    
    $params = @{}
    if ($Credential) { $params.Credential = $Credential }
    if ($Server) { $params.Server = $Server }
    
    # Test with a simple query
    $null = Get-ADDomain @params -ErrorAction Stop
}

# Test ADSI connection
function Test-ADSIConnection {
    param(
        [PSCredential]$Credential,
        [string]$Server
    )
    
    $domainPath = if ($Server) {
        "LDAP://$Server"
    }
    else {
        "LDAP://$script:DomainController"
    }
    
    if ($Credential) {
        $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($domainPath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
    }
    else {
        $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($domainPath)
    }
    
    # Test connection by accessing a property
    $null = $directoryEntry.distinguishedName
    $directoryEntry.Dispose()
}

<#
.SYNOPSIS
Generic wrapper for AD object queries

.DESCRIPTION
Wrapper around Get-ADGroup, Get-ADUser, etc., handling paging and property selection.
Automatically uses RSAT cmdlets or ADSI based on availability.

.PARAMETER ObjectType
Type of AD object (User, Group, Computer, OrganizationalUnit)

.PARAMETER Filter
LDAP filter or PowerShell filter expression

.PARAMETER Properties
Properties to retrieve

.PARAMETER SearchBase
Base DN for search

.PARAMETER SearchScope
Search scope (Base, OneLevel, Subtree)

.EXAMPLE
Get-AdObjects -ObjectType User -Filter "Name -like 'John*'" -Properties DisplayName, EmailAddress
Get-AdObjects -ObjectType Group -Filter "(&(objectClass=group)(cn=Domain*))" -SearchBase "OU=Groups,DC=contoso,DC=com"
#>
function Get-AdObjects {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('User', 'Group', 'Computer', 'OrganizationalUnit')]
        [string]$ObjectType,
        
        [Parameter(Mandatory = $true)]
        [string]$Filter,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Properties = @(),
        
        [Parameter(Mandatory = $false)]
        [string]$SearchBase,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [string]$SearchScope = 'Subtree'
    )
    
    if (-not $script:DirectoryContext -or -not $script:DirectoryContext.Connected) {
        throw "Not connected to Active Directory. Call Connect-Ad first."
    }
    
    try {
        if ($script:UseADSI) {
            return Get-AdObjectsViaADSI -ObjectType $ObjectType -Filter $Filter -Properties $Properties -SearchBase $SearchBase -SearchScope $SearchScope
        }
        else {
            return Get-AdObjectsViaRSAT -ObjectType $ObjectType -Filter $Filter -Properties $Properties -SearchBase $SearchBase -SearchScope $SearchScope
        }
    }
    catch {
        Write-Error "Failed to query AD objects: $_"
        throw
    }
}

# Get AD objects using RSAT cmdlets
function Get-AdObjectsViaRSAT {
    param(
        [string]$ObjectType,
        [string]$Filter,
        [string[]]$Properties,
        [string]$SearchBase,
        [string]$SearchScope
    )
    
    $params = @{
        Filter = $Filter
    }
    
    if ($Properties.Count -gt 0) { $params.Properties = $Properties }
    if ($SearchBase) { $params.SearchBase = $SearchBase }
    if ($SearchScope) { $params.SearchScope = $SearchScope }
    if ($script:DirectoryContext.Credential) { $params.Credential = $script:DirectoryContext.Credential }
    if ($script:DirectoryContext.Server) { $params.Server = $script:DirectoryContext.Server }
    
    switch ($ObjectType) {
        'User' { Get-ADUser @params }
        'Group' { Get-ADGroup @params }
        'Computer' { Get-ADComputer @params }
        'OrganizationalUnit' { Get-ADOrganizationalUnit @params }
    }
}

# Get AD objects using ADSI
function Get-AdObjectsViaADSI {
    param(
        [string]$ObjectType,
        [string]$Filter,
        [string[]]$Properties,
        [string]$SearchBase,
        [string]$SearchScope
    )
    
    $domainPath = if ($script:DirectoryContext.Server) {
        "LDAP://$($script:DirectoryContext.Server)"
    }
    else {
        "LDAP://$script:DomainController"
    }
    
    if ($SearchBase) {
        $domainPath += "/$SearchBase"
    }
    
    $directoryEntry = if ($script:DirectoryContext.Credential) {
        New-Object System.DirectoryServices.DirectoryEntry($domainPath, $script:DirectoryContext.Credential.UserName, $script:DirectoryContext.Credential.GetNetworkCredential().Password)
    }
    else {
        New-Object System.DirectoryServices.DirectoryEntry($domainPath)
    }
    
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
    
    # Convert PowerShell filter to LDAP filter if needed
    $ldapFilter = Convert-ToLDAPFilter -Filter $Filter -ObjectType $ObjectType
    $searcher.Filter = $ldapFilter
    
    # Set search scope
    switch ($SearchScope) {
        'Base' { $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base }
        'OneLevel' { $searcher.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel }
        'Subtree' { $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree }
    }
    
    # Add properties to load
    if ($Properties.Count -gt 0) {
        foreach ($prop in $Properties) {
            $searcher.PropertiesToLoad.Add($prop.ToLower()) | Out-Null
        }
    }
    
    # Set page size for large result sets
    $searcher.PageSize = 1000
    
    try {
        $results = $searcher.FindAll()
        $objects = @()
        
        foreach ($result in $results) {
            $obj = New-Object PSObject
            
            # Add standard properties
            $obj | Add-Member -MemberType NoteProperty -Name "DistinguishedName" -Value $result.Properties["distinguishedname"][0]
            $obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $result.Properties["name"][0]
            $obj | Add-Member -MemberType NoteProperty -Name "ObjectClass" -Value $result.Properties["objectclass"][-1]
            
            # Add requested properties
            foreach ($prop in $Properties) {
                $propLower = $prop.ToLower()
                if ($result.Properties.Contains($propLower)) {
                    $value = if ($result.Properties[$propLower].Count -eq 1) {
                        $result.Properties[$propLower][0]
                    }
                    else {
                        $result.Properties[$propLower]
                    }
                    $obj | Add-Member -MemberType NoteProperty -Name $prop -Value $value
                }
            }
            
            $objects += $obj
        }
        
        return $objects
    }
    finally {
        $results.Dispose()
        $searcher.Dispose()
        $directoryEntry.Dispose()
    }
}

# Convert PowerShell filter to LDAP filter
function Convert-ToLDAPFilter {
    param(
        [string]$Filter,
        [string]$ObjectType
    )
    
    # If already LDAP format (starts with parentheses), return as-is
    if ($Filter.StartsWith('(') -and $Filter.EndsWith(')')) {
        return $Filter
    }
    
    # Basic PowerShell to LDAP conversion
    $ldapFilter = $Filter
    $ldapFilter = $ldapFilter -replace ' -like ', '='
    $ldapFilter = $ldapFilter -replace ' -eq ', '='
    $ldapFilter = $ldapFilter -replace '\*', '*'
    
    # Add object class filter
    $objectClassFilter = switch ($ObjectType) {
        'User' { '(objectClass=user)(objectCategory=person)' }
        'Group' { '(objectClass=group)' }
        'Computer' { '(objectClass=computer)' }
        'OrganizationalUnit' { '(objectClass=organizationalUnit)' }
    }
    
    return "(&$objectClassFilter($ldapFilter))"
}

<#
.SYNOPSIS
Recursively gets group members avoiding cycles

.DESCRIPTION
Performs breadth-first walk avoiding cycles with HashSet of visited DNs.
Works with both RSAT cmdlets and ADSI fallback.

.PARAMETER GroupIdentity
Group name or distinguished name

.PARAMETER MaxDepth
Maximum recursion depth (default: 10)

.EXAMPLE
Get-GroupMembersRecursive -GroupIdentity "Domain Admins"
Get-GroupMembersRecursive -GroupIdentity "CN=MyGroup,OU=Groups,DC=contoso,DC=com" -MaxDepth 5
#>
function Get-GroupMembersRecursive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupIdentity,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxDepth = 10
    )
    
    if (-not $script:DirectoryContext -or -not $script:DirectoryContext.Connected) {
        throw "Not connected to Active Directory. Call Connect-Ad first."
    }
    
    $visitedGroups = New-Object System.Collections.Generic.HashSet[string]
    $allMembers = @()
    $groupsToProcess = New-Object System.Collections.Queue
    
    # Add initial group to queue
    $groupsToProcess.Enqueue(@{
        Identity = $GroupIdentity
        Depth = 0
        ParentGroup = $null
    })
    
    while ($groupsToProcess.Count -gt 0) {
        $currentGroup = $groupsToProcess.Dequeue()
        
        # Check depth limit
        if ($currentGroup.Depth -ge $MaxDepth) {
            Write-Warning "Maximum recursion depth ($MaxDepth) reached for group: $($currentGroup.Identity)"
            continue
        }
        
        try {
            # Get group DN for cycle detection
            $groupDN = Get-GroupDistinguishedName -Identity $currentGroup.Identity
            
            # Skip if already processed (cycle detection)
            if ($visitedGroups.Contains($groupDN)) {
                Write-Verbose "Skipping already processed group: $groupDN"
                continue
            }
            
            $visitedGroups.Add($groupDN) | Out-Null
            
            # Get direct members
            $members = Get-GroupDirectMembers -Identity $currentGroup.Identity
            
            foreach ($member in $members) {
                # Create member object with metadata
                $memberObj = [PSCustomObject]@{
                    DistinguishedName = $member.DistinguishedName
                    Name = $member.Name
                    ObjectClass = $member.ObjectClass
                    SamAccountName = $member.SamAccountName
                    ParentGroup = $groupDN
                    Depth = $currentGroup.Depth
                    DerivedGroup = if ($currentGroup.Depth -gt 0) { $currentGroup.ParentGroup } else { $null }
                }
                
                $allMembers += $memberObj
                
                # If member is a group, add to processing queue
                if ($member.ObjectClass -eq 'group') {
                    $groupsToProcess.Enqueue(@{
                        Identity = $member.DistinguishedName
                        Depth = $currentGroup.Depth + 1
                        ParentGroup = $groupDN
                    })
                }
            }
        }
        catch {
            Write-Warning "Failed to process group '$($currentGroup.Identity)': $_"
        }
    }
    
    return $allMembers
}

# Get group distinguished name
function Get-GroupDistinguishedName {
    param([string]$Identity)
    
    # If already a DN, return as-is
    if ($Identity -match '^CN=.*,.*DC=') {
        return $Identity
    }
    
    # Query for the group to get its DN
    $group = Get-AdObjects -ObjectType Group -Filter "Name -eq '$Identity'" -Properties DistinguishedName
    if ($group) {
        return $group[0].DistinguishedName
    }
    
    throw "Group not found: $Identity"
}

# Get direct group members
function Get-GroupDirectMembers {
    param([string]$Identity)
    
    if ($script:UseADSI) {
        return Get-GroupDirectMembersViaADSI -Identity $Identity
    }
    else {
        return Get-GroupDirectMembersViaRSAT -Identity $Identity
    }
}

# Get direct group members using RSAT
function Get-GroupDirectMembersViaRSAT {
    param([string]$Identity)
    
    $params = @{
        Identity = $Identity
    }
    
    if ($script:DirectoryContext.Credential) { $params.Credential = $script:DirectoryContext.Credential }
    if ($script:DirectoryContext.Server) { $params.Server = $script:DirectoryContext.Server }
    
    return Get-ADGroupMember @params
}

# Get direct group members using ADSI
function Get-GroupDirectMembersViaADSI {
    param([string]$Identity)
    
    $groupDN = Get-GroupDistinguishedName -Identity $Identity
    $domainPath = if ($script:DirectoryContext.Server) {
        "LDAP://$($script:DirectoryContext.Server)/$groupDN"
    }
    else {
        "LDAP://$script:DomainController/$groupDN"
    }
    
    $group = if ($script:DirectoryContext.Credential) {
        New-Object System.DirectoryServices.DirectoryEntry($domainPath, $script:DirectoryContext.Credential.UserName, $script:DirectoryContext.Credential.GetNetworkCredential().Password)
    }
    else {
        New-Object System.DirectoryServices.DirectoryEntry($domainPath)
    }
    
    try {
        $members = @()
        
        foreach ($memberDN in $group.member) {
            $memberPath = "LDAP://$script:DomainController/$memberDN"
            $member = if ($script:DirectoryContext.Credential) {
                New-Object System.DirectoryServices.DirectoryEntry($memberPath, $script:DirectoryContext.Credential.UserName, $script:DirectoryContext.Credential.GetNetworkCredential().Password)
            }
            else {
                New-Object System.DirectoryServices.DirectoryEntry($memberPath)
            }
            
            try {
                $memberObj = [PSCustomObject]@{
                    DistinguishedName = $member.distinguishedName[0]
                    Name = $member.name[0]
                    ObjectClass = $member.objectClass[-1]
                    SamAccountName = if ($member.sAMAccountName.Count -gt 0) { $member.sAMAccountName[0] } else { $null }
                }
                
                $members += $memberObj
            }
            finally {
                $member.Dispose()
            }
        }
        
        return $members
    }
    finally {
        $group.Dispose()
    }
}

# Export public functions
Export-ModuleMember -Function Connect-Ad, Get-AdObjects, Get-GroupMembersRecursive