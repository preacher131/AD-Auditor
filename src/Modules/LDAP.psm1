# LDAP.psm1 - Minimal LDAP connection helpers for AD Entitlement Review
# Only contains functions actually used by the audit script

function New-LdapConnection {
    <#
    .SYNOPSIS
        Creates a new LDAP connection to the specified server
    .DESCRIPTION
        Establishes an LDAP or LDAPS connection with the provided credentials
    .PARAMETER Server
        The LDAP server to connect to
    .PARAMETER UseLDAPS
        Whether to use LDAPS (secure LDAP over SSL)
    .PARAMETER UseCurrentUser
        Whether to use current user credentials
    .PARAMETER Username
        Username for authentication (if not using current user)
    .PARAMETER Password
        Password for authentication (if not using current user)
    .PARAMETER Domain
        Domain for authentication (if not using current user)
    .OUTPUTS
        System.DirectoryServices.Protocols.LdapConnection
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,
        
        [Parameter(Mandatory = $false)]
        [bool]$UseLDAPS = $true,
        
        [Parameter(Mandatory = $false)]
        [bool]$UseCurrentUser = $true,
        
        [Parameter(Mandatory = $false)]
        [string]$Username = $null,
        
        [Parameter(Mandatory = $false)]
        [string]$Password = $null,
        
        [Parameter(Mandatory = $false)]
        [string]$Domain = $null
    )
    
    $port = if ($UseLDAPS) { 636 } else { 389 }
    $ldapServer = "$Server`:$port"
    
    if ($UseCurrentUser) {
        $credential = [System.Net.CredentialCache]::DefaultNetworkCredentials
    } else {
        $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
        $credential = New-Object System.Net.NetworkCredential($Username, $securePassword, $Domain)
    }
    
    $ldap = New-Object System.DirectoryServices.Protocols.LdapConnection($ldapServer)
    $ldap.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
    $ldap.SessionOptions.SecureSocketLayer = $UseLDAPS
    $ldap.Credential = $credential
    
    try {
        $ldap.Bind()
        Write-Verbose "LDAP bind successful to $ldapServer"
        return $ldap
    } catch {
        throw "LDAP bind failed to $ldapServer`: $_"
    }
}

function Invoke-LdapSearch {
    <#
    .SYNOPSIS
        Performs an LDAP search operation
    .DESCRIPTION
        Executes an LDAP search with the specified parameters
    .PARAMETER Ldap
        The LDAP connection object
    .PARAMETER BaseDN
        The base distinguished name for the search
    .PARAMETER Filter
        The LDAP search filter
    .PARAMETER Attributes
        Array of attributes to retrieve (default: all attributes)
    .OUTPUTS
        System.DirectoryServices.Protocols.SearchResultEntryCollection
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.Protocols.LdapConnection]$Ldap,
        
        [Parameter(Mandatory = $true)]
        [string]$BaseDN,
        
        [Parameter(Mandatory = $true)]
        [string]$Filter,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Attributes = @("*")
    )
    
    try {
        $searchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
            $BaseDN, 
            $Filter, 
            [System.DirectoryServices.Protocols.SearchScope]::Subtree, 
            $Attributes
        )
        
        $searchResponse = $Ldap.SendRequest($searchRequest)
        return $searchResponse.Entries
    }
    catch {
        throw "LDAP search failed for BaseDN '$BaseDN' with filter '$Filter': $_"
    }
}

function Get-LdapUser {
    param(
        [System.DirectoryServices.Protocols.LdapConnection]$Ldap,
        [string]$BaseDN,
        [string]$SamAccountName
    )
    $filter = "(&(objectClass=user)(sAMAccountName=$SamAccountName))"
    return Invoke-LdapSearch -Ldap $Ldap -BaseDN $BaseDN -Filter $filter
}

function Get-LdapGroup {
    param(
        [System.DirectoryServices.Protocols.LdapConnection]$Ldap,
        [string]$BaseDN,
        [string]$GroupName
    )
    $filter = "(&(objectClass=group)(cn=$GroupName))"
    return Invoke-LdapSearch -Ldap $Ldap -BaseDN $BaseDN -Filter $filter
}

function Get-LdapGroupMembers {
    param(
        [System.DirectoryServices.Protocols.LdapConnection]$Ldap,
        [string]$GroupDN
    )
    $filter = "(distinguishedName=$GroupDN)"
    $entries = Invoke-LdapSearch -Ldap $Ldap -BaseDN $GroupDN -Filter $filter -Attributes @("member")
    if ($entries.Count -gt 0 -and $entries[0].Attributes["member"]) {
        return $entries[0].Attributes["member"]
    } else {
        return @()
    }
}

# Export only the functions that are actually used
Export-ModuleMember -Function New-LdapConnection, Invoke-LdapSearch 