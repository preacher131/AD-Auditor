function New-LdapConnection {
    param(
        [string]$Server,
        [bool]$UseLDAPS = $true,
        [bool]$UseCurrentUser = $true,
        [string]$Username = $null,
        [string]$Password = $null,
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
        Write-Verbose "LDAP bind successful!"
        return $ldap
    } catch {
        throw "LDAP bind failed: $_"
    }
}

function Invoke-LdapSearch {
    param(
        [System.DirectoryServices.Protocols.LdapConnection]$Ldap,
        [string]$BaseDN,
        [string]$Filter,
        [string[]]$Attributes = @("*")
    )
    $searchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
        $BaseDN, $Filter, [System.DirectoryServices.Protocols.SearchScope]::Subtree, $Attributes
    )
    $searchResponse = $Ldap.SendRequest($searchRequest)
    return $searchResponse.Entries
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