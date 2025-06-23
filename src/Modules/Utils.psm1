function Get-SafeValue {
    <#
    .SYNOPSIS
        Returns a safe, non-null string value.
    .PARAMETER Value
        The value to evaluate.
    .PARAMETER Default
        Default string to return when $Value is null or empty.
    #>
    param(
        $Value,
        [string]$Default = ""
    )

    if ($null -eq $Value) { return $Default }
    if ([string]::IsNullOrEmpty($Value)) { return $Default }
    return $Value.ToString()
}

function New-SimpleGuid {
    <#
    .SYNOPSIS
        Creates a deterministic GUID from the supplied input (SHA-256 first 16 bytes) or a new GUID when no input is provided.
    .PARAMETER Input
        Optional string used to generate a deterministic GUID.
    #>
    [CmdletBinding()]
    param(
        [string]$Input
    )

    if ([string]::IsNullOrWhiteSpace($Input)) {
        return [System.Guid]::NewGuid().ToString()
    }

    try {
        $hasher     = [System.Security.Cryptography.SHA256]::Create()
        $inputBytes = [System.Text.Encoding]::UTF8.GetBytes($Input)
        $hashBytes  = $hasher.ComputeHash($inputBytes)
        $guidBytes  = New-Object byte[] 16
        for ($i = 0; $i -lt 16; $i++) { $guidBytes[$i] = $hashBytes[$i] }
        $guid = New-Object System.Guid -ArgumentList $guidBytes
        $hasher.Dispose()
        return $guid.ToString()
    }
    catch {
        return [System.Guid]::NewGuid().ToString()
    }
}

function Get-SimpleObjectGuid {
    <#
    .SYNOPSIS
        Retrieves a GUID from an LDAP or AD object or generates a deterministic fallback GUID.
    .PARAMETER Object
        The LDAP/AD object.
    .PARAMETER IsLdap
        Indicate whether the object comes from .NET LDAP classes.
    #>
    param(
        $Object,
        [bool]$IsLdap = $false
    )

    try {
        if ($IsLdap) {
            if ($Object.Attributes["objectGUID"] -and $Object.Attributes["objectGUID"].Count -gt 0) {
                $guidBytes = $Object.Attributes["objectGUID"][0]
                $guid      = New-Object System.Guid -ArgumentList $guidBytes
                return $guid.ToString()
            }
            if ($Object.Attributes["distinguishedName"] -and $Object.Attributes["distinguishedName"].Count -gt 0) {
                return New-SimpleGuid $Object.Attributes["distinguishedName"][0]
            }
        }
        else {
            if ($Object.PSObject.Properties.Match("ObjectGUID").Count -gt 0 -and $Object.ObjectGUID) {
                return $Object.ObjectGUID.ToString()
            }
        }
        return New-SimpleGuid $Object.ToString()
    }
    catch {
        return New-SimpleGuid $Object.ToString()
    }
}

Export-ModuleMember -Function Get-SafeValue, New-SimpleGuid, Get-SimpleObjectGuid 
