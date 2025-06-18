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

# Initialize collections
$packages1 = @()
$packageMembers1 = @()
$packages2 = @()
$privilegeGroups = @()

# Process groups
if (-not $PrivilegeOnly) {
    Write-Host "Processing groups..." -ForegroundColor Cyan
    
    foreach ($groupConfig in $groupsConfig.groups) {
        $baseDN = Get-SafeValue $groupConfig.path
        Write-Host "Processing OU: $baseDN" -ForegroundColor Yellow
        
        try {
            if ($useADModule) {
                $groups = Get-ADGroup -Filter * -SearchBase $baseDN -Properties Description, info @adParams
                
                foreach ($group in $groups) {
                    $groupGuid = Get-SimpleObjectGuid $group $false
                    $reviewPackageID = New-SimpleGuid "$($group.Name)|$ReviewID|$groupGuid"
                    
                    $package = New-Object PSObject
                    $package | Add-Member -MemberType NoteProperty -Name "ReviewID" -Value $ReviewID
                    $package | Add-Member -MemberType NoteProperty -Name "GroupID" -Value $groupGuid
                    $package | Add-Member -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                    $package | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $group.Name
                    $package | Add-Member -MemberType NoteProperty -Name "OUPath" -Value $baseDN
                    $package | Add-Member -MemberType NoteProperty -Name "Description" -Value (Get-SafeValue $group.Description)
                    
                    $packages1 += $package
                    
                    try {
                        $members = Get-ADGroupMember -Identity $group -Recursive @adParams | Where-Object { $_.objectClass -eq "user" }
                        
                        foreach ($member in $members) {
                            try {
                                $user = Get-ADUser -Identity $member.distinguishedName -Properties mail, givenName, surname @adParams
                                
                                $memberObj = New-Object PSObject
                                $memberObj | Add-Member -MemberType NoteProperty -Name "FirstName" -Value (Get-SafeValue $user.givenName)
                                $memberObj | Add-Member -MemberType NoteProperty -Name "LastName" -Value (Get-SafeValue $user.surname)
                                $memberObj | Add-Member -MemberType NoteProperty -Name "Email" -Value (Get-SafeValue $user.mail)
                                $memberObj | Add-Member -MemberType NoteProperty -Name "UserID" -Value $user.ObjectGUID.ToString()
                                $memberObj | Add-Member -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                                $memberObj | Add-Member -MemberType NoteProperty -Name "DerivedGroup" -Value $group.Name
                                
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
                # LDAP processing - simplified
                $groupFilter = "(objectClass=group)"
                $groups = Invoke-LdapSearch -Ldap $ldapConnection -BaseDN $baseDN -Filter $groupFilter -Attributes @("cn","description","member")
                
                foreach ($group in $groups) {
                    if ($group.Attributes["cn"] -and $group.Attributes["cn"].Count -gt 0) {
                        $groupName = $group.Attributes["cn"][0]
                        $groupGuid = Get-SimpleObjectGuid $group $true
                        $reviewPackageID = New-SimpleGuid "$groupName|$ReviewID|$groupGuid"
                        
                        $package = New-Object PSObject
                        $package | Add-Member -MemberType NoteProperty -Name "ReviewID" -Value $ReviewID
                        $package | Add-Member -MemberType NoteProperty -Name "GroupID" -Value $groupGuid
                        $package | Add-Member -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                        $package | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $groupName
                        $package | Add-Member -MemberType NoteProperty -Name "OUPath" -Value $baseDN
                        
                        if ($group.Attributes["description"] -and $group.Attributes["description"].Count -gt 0) {
                            $package | Add-Member -MemberType NoteProperty -Name "Description" -Value $group.Attributes["description"][0]
                        }
                        else {
                            $package | Add-Member -MemberType NoteProperty -Name "Description" -Value ""
                        }
                        
                        $packages1 += $package
                        
                        # Process group members for LDAP
                        try {
                            if ($group.Attributes["member"] -and $group.Attributes["member"].Count -gt 0) {
                                foreach ($memberDN in $group.Attributes["member"]) {
                                    try {
                                        $userEntry = Invoke-LdapSearch -Ldap $ldapConnection -BaseDN $memberDN -Filter "(objectClass=user)" -Attributes @("givenName","sn","mail") | Select-Object -First 1
                                        
                                        if ($userEntry) {
                                            $memberObj = New-Object PSObject
                                            
                                            $firstName = ""
                                            if ($userEntry.Attributes["givenName"] -and $userEntry.Attributes["givenName"].Count -gt 0) {
                                                $firstName = $userEntry.Attributes["givenName"][0]
                                            }
                                            
                                            $lastName = ""
                                            if ($userEntry.Attributes["sn"] -and $userEntry.Attributes["sn"].Count -gt 0) {
                                                $lastName = $userEntry.Attributes["sn"][0]
                                            }
                                            
                                            $email = ""
                                            if ($userEntry.Attributes["mail"] -and $userEntry.Attributes["mail"].Count -gt 0) {
                                                $email = $userEntry.Attributes["mail"][0]
                                            }
                                            
                                            $memberObj | Add-Member -MemberType NoteProperty -Name "FirstName" -Value $firstName
                                            $memberObj | Add-Member -MemberType NoteProperty -Name "LastName" -Value $lastName
                                            $memberObj | Add-Member -MemberType NoteProperty -Name "Email" -Value $email
                                            $memberObj | Add-Member -MemberType NoteProperty -Name "UserID" -Value (Get-SimpleObjectGuid $userEntry $true)
                                            $memberObj | Add-Member -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                                            $memberObj | Add-Member -MemberType NoteProperty -Name "DerivedGroup" -Value $groupName
                                            
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
        }
        catch {
            Write-Warning "Failed to process OU: $($_.Exception.Message)"
        }
    }
    
    Write-Host "Found $($packages1.Count) groups with $($packageMembers1.Count) members" -ForegroundColor Green
}

# Process privileges
if (-not $GroupsOnly) {
    Write-Host "Processing privileges..." -ForegroundColor Cyan
    
    foreach ($ouPath in $privilegeConfig.ouPaths) {
        Write-Host "Processing OU: $ouPath" -ForegroundColor Yellow
        
        try {
            if ($useADModule) {
                $users = Get-ADUser -Filter * -SearchBase $ouPath -Properties memberOf, DisplayName @adParams
                
                foreach ($user in $users) {
                    $userGuid = Get-SimpleObjectGuid $user $false
                    $reviewPackageID = New-SimpleGuid "$($user.SamAccountName)|$ReviewID|$userGuid"
                    
                    $package = New-Object PSObject
                    $package | Add-Member -MemberType NoteProperty -Name "ReviewID" -Value $ReviewID
                    $package | Add-Member -MemberType NoteProperty -Name "GroupID" -Value $userGuid
                    $package | Add-Member -MemberType NoteProperty -Name "GroupName" -Value (Get-SafeValue $user.DisplayName)
                    $package | Add-Member -MemberType NoteProperty -Name "OUPath" -Value $ouPath
                    $package | Add-Member -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                    
                    $packages2 += $package
                    
                    if ($user.memberOf) {
                        foreach ($groupDN in $user.memberOf) {
                            $shouldExclude = $false
                            foreach ($excludePattern in $privilegeConfig.exclude) {
                                if ($groupDN -like $excludePattern) {
                                    $shouldExclude = $true
                                    break
                                }
                            }
                            
                            if (-not $shouldExclude) {
                                try {
                                    $group = Get-ADGroup -Identity $groupDN @adParams
                                    $groupGuid = Get-SimpleObjectGuid $group $false
                                    
                                    $privilegeGroup = New-Object PSObject
                                    $privilegeGroup | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $group.Name
                                    $privilegeGroup | Add-Member -MemberType NoteProperty -Name "GroupID" -Value $groupGuid
                                    $privilegeGroup | Add-Member -MemberType NoteProperty -Name "ReviewPackageID" -Value $reviewPackageID
                                    
                                    $privilegeGroups += $privilegeGroup
                                }
                                catch {
                                    Write-Warning "Failed to get group info: $($_.Exception.Message)"
                                }
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-Warning "Failed to process OU: $($_.Exception.Message)"
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
