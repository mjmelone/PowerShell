<#
    EnumUserRights.ps1
    by Michael Melone, Microsoft

    .SYNOPSIS

    Connects to hosts specified by -CriticalMachines, identifies user rights of interest, expands all group membership,
    and returns a CSV-formatted list of these accounts, their associated rights and which computer they have rights on, 
    as well as their membership information.

    .DESCRIPTION

    This script is designed to identify critical accounts for the purpose of compromise recovery.  A critical account 
    is one which has elevated rights to the operating system, which in turn translates to the ability to take over the
    machine.  
    
    Once a list of critical machines are identified, use this script to enumerate all critical accounts on those 
    machines in order to ensure comprehensive identification of high-risk accounts relative to those machines.  Accounts 
    identified in this list should be prevented from performing interactive or remoteinteractive logon to machines that 
    are not in the list of critical machines.

    .PARAMETER CriticalMachines

    This parameter is mandatory and should include an array of machine names to be used for user rights analysis.

    .PARAMETER OutputCSV

    This parameter specifies the location where the output file should be produced.  The file must not exist for
    validation to succeed.  By default, this parameter is set to ".\CriticalAccounts.csv"
    
    .PARAMETER UserRightsScript

    This parameter should point to the location of UserRights.psm1.  By default, this will be set to the following 
    location if not specified: '.\Dependencies\UserRights.psm1'

    As of the publish date, this script is available for download at the following site: 
    https://gallery.technet.microsoft.com/scriptcenter/Grant-Revoke-Query-user-26e259b0

    .EXAMPLE

    Enumerate all critical accounts (based on user right) from computer TestMachine1

    .\EnumUserRights.ps1 -CriticalMachines TestMachine1

   .NOTES

   Version | Date        | Version Notes 
   --------+-------------+---------------------------------------------------------------------------------------------------------
    1.0    | 30 Nov 2016 | Initial release

#>

param(
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    $UserRightsScript = (Resolve-Path '.\Dependencies\UserRights.psm1').path,
    [parameter(Mandatory=$True)]
    [System.Collections.Generic.List[String]] $CriticalMachines,
    [ValidateScript({-not (Test-Path $_ -Pathtype Leaf)})]
    [string] $OutputCSV = ".\CriticalAccounts.csv"
)

Write-Debug "Initiating execution of EnumUserRights"

# <prerequisite check>
Write-Debug "Ensuring window is running with elevation"
# Ensure we are running in an elevated window
$boolIsAdmin = (New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

if (-not $boolIsAdmin) {
    Write-Error "This script is not being executed in an elevated session.  Please re-launch PowerShell with elevation and try again."
    Return -1
}

Write-Debug "Loading dependent module UserRights.ps1"

#Load user rights PS1
try {
    Import-Module -Name $UserRightsScript -ErrorAction Stop
} catch {
    Write-Error "An error was encountered while trying to load UserRights.psm1.  Please ensure that code execution is RemoteSigned."
    Return -1
}

Write-Debug "Loading Active Directory cmdlets"

# Try to load the Active Directory cmdlets
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "The Active Directory cmdlets were not found on this system.  Please install them and try again."
    Return -1
}

# </prerequisite Check>

Write-Debug "Creating type definitions"

# Create the struct for an individual result
Add-Type -TypeDefinition @"
    public struct CriticalAccount
    {
        public string Domain;
        public string SAMAccountName;
        public string MachineName;
        public string UserRight;
        public string RootPrincipal;
        public string MembershipPath;
    }

    public struct AccountMembership
    {
        public string Account;
        public string MembershipPath;
    }
"@

# <functions>

Function Get-DomainFromDN {
    <#
        Get-DomainFromDN
        by Michael Melone, Microsoft

        .SYNOPSIS

        This function accepts a distinguishedName attribute from Active Directory and retrieves the associated
        AD domain.

        .DESCRIPTION

        This function is used to improve performance when a large number of domain name resolutions must be 
        performed.  To accomplish this, a global hashtable is defined and will hold the results of any resolved
        domains for future inquiries.

        .PARAMETER DistinguishedName

        This is the distinguishedName attribute of any directory services object.
    #>
    param(
        [parameter(Mandatory=$True)]
        [string] $DistinguishedName
    )

    Write-Debug "Get-DomainFromDN: Resolving domain for the following DN: $DistinguishedName"

    if (-not $global:hshDomains) {
        Write-Debug "Get-DomainFromDN: Initializing global domain hashtable"
        # Create a global list of domains
        $global:hshDomains = @{}
    }

    $intDomainDNStart = $DistinguishedName.IndexOf("DC=")
    $strDomainDN = $DistinguishedName.Substring($intDomainDNStart, $DistinguishedName.length - $intDomainDNStart)
    $strDomainDN = $strDomainDN.replace(",DC=",".").TrimStart("DC=")

    Write-Debug "Get-DomainFromDN: Determining if domain is in hashtable: $strDomainDN"
    if ($global:hshDomains.ContainsKey($strDomainDN)) {
        Write-Debug "Get-DomainFromDN: Domain was in hashtable, returning cached instance."
        return $global:hshDomains[$strDomainDN]
    } else {
        Write-Debug "Get-DomainFromDN: Domain was not in hashtable.  Resolving."
        try {
            $Domain = Get-ADDomain -Identity $strDomainDN -ErrorAction Stop
        } catch {
            Write-Error "Get-DomainFromDN: unable to resolve the following domain: $strDomainDN"
            return $Null 
        }

        Write-Debug "Get-DomainFromDN: Domain successfully resolved.  Adding to hashtable and returning."
        $global:hshDomains.Add($strDomainDN,$Domain)
        return $Domain
    }
}

Function Get-XADObject {
    <#
    .SYNOPSIS
    Get-XADObject is designed to allow querying of Active Directory objects across
    multiple Active Directory domains.
    
    .DESCRIPTION
    Get-XADObject enables searching of objects in other Active Directory domains 
    without needing to map a PSDrive to that domain, resolve the domain separately,
    or find a live domain controller in another domain.  In addition, this function
    adds a number of helpful properties to the returned object to enable subsequent
    queries without needing to resolve this information.

    Objects returned from Get-XADObject use the same .Net object class normally
    provided by the native PowerShell cmdlets with the following additions:
    
    DomainPartitionDN: The distinguished name of the associated domain partition

    DomainDNS: The FQDN of the associated domain partition

    DomainNetBIOS: The NetBIOS name of the associated domain partition

    DomainController: The domain controller from where the object was retrieved

    IdentityReference: The domain\NetBIOS formatted principal reference (useful for
                       parsing access control entries)

    #>

    param(
        [string] $DistinguishedName,
        [string] $UPN,
        [string] $Domain,
        [string] $LDAPFilter = "",
        [string] $SAMAccountName,
        [switch] $User,
        [switch] $Group,
        [switch] $Computer,
        [string[]] $Properties = "*"
    )

#Temporary work-around to avoid dead SID issues
if ($Domain -like "S-1-5-*") {return $Null}

    #Ensure we have the ActiveDirectory module installed
    if (-not (Get-Module ActiveDirectory)) {
        try {
            Import-Module ActiveDirectory
        } catch {
            Write-Error "The Active Directory cmdlets are not installed."
            Return $Null
        }
    }

    #Try to get the domain from the UPN, DN, or Domain switches
    if ($Domain) {
        try {
            $objDomain = Get-ADDomain -Identity $Domain
        } catch {
            if (-not ($UPN -or $DistinguishedName)) {
                Write-Error "Unable to resolve the domain ""$Domain"""
                return $Null
            }
        }
    }

    if ($DistinguishedName) {
        #Convert the DN into the corresponding DNS name
        $intDomainDNStart = $DistinguishedName.IndexOf("DC=")
        $strDomainDN = $DistinguishedName.Substring($intDomainDNStart, $DistinguishedName.length - $intDomainDNStart)
        $strDomainDN = $strDomainDN.replace(",DC=",".").TrimStart("DC=")
        
        #Try to get the domain
        try {
            $objDomain = Get-ADDomain -Identity $strDomainDN
        } catch {
            #The DN is either improperly formatted or references a domain not available in the GC
            Write-Error "The supplied Distinguished Name ($DistinguishedName) appears to be invalid"
            Return $Null
        }
    }

    if ($UPN -and (-not $objDomain)) {
        #Try to use the UPN to resolve the domain
        try {
            $objDomain = Get-ADDomain -Identity $UPN.Split("@")[1]
        } catch {
            #This is our last attempt.  Fail.
            Write-Error "Unable to resolve a domain for the specified UPN ($UPN)."
            Return $Null
        }
    } elseif (-not $objDomain) {
        Write-Error "Unable to resolve a domain from the supplied information."
        Return $Null
    }
    

    #Get a Domain Controller from the domain
    try {
        $objDC = Get-ADDomainController -Discover -DomainName $objDomain.DNSRoot
    } catch {
        #An issue was encountered locating a Global Catalog server
        Write-Error "An issue was encountered when locating a domain controller for the $($objDomain.dnsroot) domain."
        Return $Null
    }

    #Build LDAP Query
    if ($DistinguishedName) {
        #Since distinguishedName is a unique attribute only one can be returned
        $strLDAP = "(distinguishedName=$DistinguishedName)"
    } else {
        $strLDAP = $LDAPFilter
        if ($User) {
            $strLDAP = "$strLDAP(objectClass=user)"
        } elseif ($Computer) {
            $strLDAP = "$strLDAP(objectClass=computer)"
        } elseif ($Group) {
            $strLDAP = "$strLDAP(objectClass=group)"
        }

        if ($SAMAccountName) {
            $strLDAP = "$strLDAP(sAMAccountName=$SAMAccountName)"
        }

        if ($UPN) {
            $strLDAP = "$strLDAP(userPrincipalName=$UPN)"
        }
    }

    write-debug "Get-XADObject: Performing query - LDAP Filter: $strLDAP DC: $($objDC.HostName[0]) SearchBase: $($objDomain.DistinguishedName)"

    Get-ADObject -Server $objDC.HostName[0] -LDAPFilter "(&$strLDAP)" -SearchBase $objDomain.DistinguishedName -SearchScope Subtree -Properties objectClass, distinguishedName | %{
        $strDN = $_.DistinguishedName
        Switch ($_.objectClass) {
            "user"{$objResult = Get-ADUser -Partition "$($objDomain.DistinguishedName)" -Server $objDC.HostName[0] -Identity $strDN -Properties $Properties}
            "computer" {$objResult = Get-ADComputer -Partition "$($objDomain.DistinguishedName)" -Server $objDC.HostName[0] -Identity $strDN -Properties $Properties}
            "group" {$objResult = Get-ADGroup -Partition "$($objDomain.DistinguishedName)" -Server $objDC.HostName[0] -Identity $strDN -Properties $Properties}
            "organizationalUnit" {$objResult = Get-ADOrganizationalUnit -Partition "$($objDomain.DistinguishedName)" -Server $objDC.HostName[0] -Identity $strDN -Properties $Properties}
            else {$objResult = Get-ADObject -Partition "$($objDomain.DistinguishedName)" -Server $objDC.HostName[0] -Identity $strDN -Properties $Properties}
        }

        if ($objResult) {
            $objResult | Add-Member -NotePropertyName DomainPartitionDN -NotePropertyValue $objDomain.DistinguishedName -Force
            $objResult | Add-Member -NotePropertyName DomainDNS -NotePropertyValue $objDomain.DNSRoot -Force
            $objResult | Add-Member -NotePropertyName DomainNetBIOS -NotePropertyValue $objDomain.Name -Force
            $objResult | Add-Member -NotePropertyName DomainController -NotePropertyValue $objDC.HostName[0] -Force
            if ($objResult.sAMAccountName) {
                $objResult | Add-Member -NotePropertyName IdentityReference -NotePropertyValue "$($objDomain.Name)\$($objResult.sAMAccountName)" -Force
            }
        }

        Return $objResult
    }
}

Function Get-ADAccountRecursiveGroupMembers {
    <#
        Get-ADAccountRecursiveGroupMembers
        by Michael Melone, Microsoft

        .SYNOPSIS

        This function recursively enumerates group membership of a specified Active Directory principal as well as the path
        that was taken to membership.  Additionally, all groups are returned (unlike Get-ADGroupMember).

        This function will determine if the target is a group or not - if you pass it a user account it will simply return 
        that account without membership.

        .PARAMETER SAMAccountName
        
        This is the sAMAccountName attribute of the account to be resolved.

        .PARAMETER Domain

        This is the domain of the account

        .PARAMETER SizeLimit

        This is the maximum number of members that this function will resolve, defaulted to 100.  If a group has more than
        SizeLimit members, it will respond that the "member" is the count of members of that group instead of resolving
        them all.

        .PARAMETER MembershipPath

        This is only designed for use with recursion - it is the path taken to the current account being enumerated.
    #>
    param(
        [parameter(Mandatory=$True)]
        [string] $SAMAccountName,
        [parameter(Mandatory=$True)]
        [string] $Domain,
        [string] $MembershipPath = "$Domain\$SAMAccountName",
        [System.Collections.Generic.list[string]] $ResolvedAccounts = (New-Object System.Collections.Generic.list[string]),
        [int] $SizeLimit = 100
    )

    Write-Debug "Get-ADAccountRecursiveGroupMembers: Performing recursive enumeration of $Domain\$SAMAccountName with a SizeLimit of $SizeLimit"
    # Determine if a cache has already been created
    if (-not $global:hshADAccountCache) {
        Write-Debug "Get-ADAccountRecursiveGroupMembers: Creating AD Account cache"
        # Create a new cache
        $global:hshADAccountCache = @{}
    }

    Write-Debug "Get-ADAccountRecursiveGroupMembers: Determining if target principal is in cache"
    # Determine if the requested account is in the cache
    if ($global:hshADAccountCache.ContainsKey("$Domain\$SAMAccountName".ToLower())) {
        Write-Debug "Get-ADAccountRecursiveGroupMembers: Cache hit, returning results from cache."
        # The cache already has the resolved \ expanded group.  Return that instead of performing resolutions
        return $global:hshADAccountCache["$Domain\$SAMAccountName".ToLower()]
    }

    Write-Debug "Get-ADAccountRecursiveGroupMembers: Cache miss.  Enumerating membership."

    # Determine if the account is one of the special identities
    $arrSpecialIdentities = @('Anonymous Logon', 'Authenticated Users', 'Batch', 'Creator Group', 'Creator Owner', 'Dialup', 'Digest Authentication', 'Enterprise Domain Controllers',
                                'Everyone', 'Interactive',  'Local Service', 'LocalSystem', 'Network' , 'Network Service', 'NTLM Authentication', 'Other Organization', 'Principal Self',
                                'Remote Interactive Logon', 'Restricted', 'SChannel Authentication', 'Service', 'Terminal Server User', 'This Organization', 'Window Manager\Window Manager Group')

    if ($arrSpecialIdentities.Contains($SAMAccountName)) {
        Write-Debug "Get-ADAccountRecursiveGroupMembers: Account is a special identity, returning "
        # This is a special identity and will not be able to be resolved.  Return as result.
        $mbrCurrent = New-Object AccountMembership
        $mbrCurrent.Account = "$Domain\$SAMAccountName"
        $mbrCurrent.MembershipPath = $MembershipPath
        Return $mbrCurrent
    }

    # Create a new list for results 
    $lstGroupMembers = (New-Object System.Collections.Generic.List[AccountMembership])

    # Get AD object
    try {
        Write-Debug "Get-ADAccountRecursiveGroupMembers: Calling Get-XADObject with the following parameters: SAMAccountName: $SAMAccountName Domain: $Domain -Properties distinguishedName, objectClass"
        $objCurrent = Get-XADObject -SAMAccountName $SAMAccountName -Domain $Domain -Properties @("distinguishedName", "objectClass")
    } catch {
        Write-Error "Unable to retrieve the following AD object: $Domain\$SAMAccountName."
        Return $Null 
    }

    # Ensure we got a result
    if ($objCurrent) {
        Write-Debug "Get-ADAccountRecursiveGroupMembers: Received the following result from Get-XADObject: $($objCurrent.distinguishedName)"

        # Determine if this is a group
        if ($objCurrent.objectClass -eq 'group') {
            Write-Debug "Get-ADAccountRecursiveGroupMembers: Target is a group.  Enumerating membership."
            # Add the current account to the list of resolved accounts
            $ResolvedAccounts.Add($objCurrent.distinguishedName)
            
            # Get group membership and add each to 
            $arrGroupMembers = Get-ADGroupMember -Identity $objCurrent.distinguishedName -Server $objCurrent.DomainController | ?{-not $ResolvedAccounts.Contains($_.distinguishedName)}

            # See if we met or exceeded the membership threshold
            if ($arrGroupMembers.count -ge $SizeLimit) {
                Write-Debug "Get-ADAccountRecursiveGroupMembers: Membership exceeded size limit, returning count of accounts."
                $mbrCurrent = New-Object AccountMembership
                $mbrCurrent.Account = "$($arrGroupMembers.count) accounts"
                $mbrCurrent.MembershipPath = "$($arrGroupMembers.count) accounts -> are members of -> $MembershipPath"
                $lstGroupMembers.add($mbrCurrent)
            } else {
                Write-Debug "Get-ADAccountRecursiveGroupMembers: $($arrGroupMembers.count) members found."
                $mbrCurrent = New-Object AccountMembership
                $mbrCurrent.Account = "$($objCurrent.Domain)\$($objCurrent.sAMAccountName)"
                $mbrCurrent.MembershipPath = "$Domain\$SAMAccountName -> is a member of -> $MembershipPath"
                $lstGroupMembers.add($mbrCurrent)

                $arrGroupMembers | %{
                    Write-Debug "Get-ADAccountRecursiveGroupMembers: Getting sAMAccountName for the following account $($_.distinguishedName)"
                    $adoCurrentMember = Get-XADObject $_.distinguishedName -Properties @("sAMAccountName", "objectClass")
                    # Determine if the member is a group or not
                    if ($adoCurrentMember.objectClass -like 'Group') {
                        Write-Debug "Get-ADAccountRecursiveGroupMembers: Member is a group, recursing."
                        Get-ADAccountRecursiveGroupMembers -SAMAccountName $adoCurrentMember.sAMAccountName -Domain $adoCurrentMember.DomainNetBIOS -ResolvedAccounts $ResolvedAccounts -MembershipPath "$($adoCurrentMember.DomainNetBIOS)\$($adoCurrentMember.sAMAccountName) -> is a member of -> $MembershipPath" | %{
                            $lstGroupMembers.Add($_)
                        }
                    } else {
                        Write-Debug "Get-ADAccountRecursiveGroupMembers: Adding member $($adoCurrentMember.DomainNetBIOS)\$($adoCurrentMember.sAMAccountName) to the list"
                        # Add the current account to the list   
                        $mbrCurrent = New-Object AccountMembership
                        $mbrCurrent.Account = "$($adoCurrentMember.DomainNetBIOS)\$($adoCurrentMember.sAMAccountName)"
                        $mbrCurrent.MembershipPath = "$($adoCurrentMember.DomainNetBIOS)\$($adoCurrentMember.sAMAccountName) -> is a member of -> $MembershipPath"
                        $lstGroupMembers.Add($mbrCurrent)
                    }
                }
            }
        }
    } else {
        Write-Error "The following object was not found in Active Directory: $Domain\$SAMAccountName"
        Return $Null
    }

    Write-Debug "Get-ADAccountRecursiveGroupMembers: Adding current member to the cache"
    # Add the result to the cache for future lookups
    $global:hshADAccountCache.add("$Domain\$SAMAccountName".ToLower(),$lstGroupMembers)

    Return $lstGroupMembers
}

Function Get-LocalAccountRecursiveMembership {
    param(
        [parameter(Mandatory=$True)]
        [string] $MachineName,
        [parameter(Mandatory=$True)]
        [string] $LocalAccount,
        [string] $LocalDomain = (Get-WmiObject win32_computersystem -Computer $MachineName | Select name).name
    )

    Write-Debug "Get-LocalAccountRecursiveMembership: Initiating search for account $LocalAccount on machine $MachineName"
    # Determine if the local account cache has already been created
    if (-not $Global:hshLocalAccountCache) {
        Write-Debug "LocalAccountRecursiveMembership: Creating local account cache."
        $Global:hshLocalAccountCache = @{}
    }
    
    # Determine if the account cache already has this account
    if ($global:hshLocalAccountCache.ContainsKey("$MachineName\$LocalAccount".ToLower())) {
        Write-Debug "LocalAccountRecursiveMembership: Cache hit.  Returning result from cache."
        # We have already resolved this account.  Return from cache.
        return $Global:hshLocalAccountCache["$MachineName\$LocalAccount".ToLower()]
    }

    Write-Debug "LocalAccountRecursiveMembership: Cache miss.  Looking up account."
    $lstGroupMembers = New-Object System.Collections.Generic.List[AccountMembership]

    # Determine if the account is one of the special identities
    $arrSpecialIdentities = @('Anonymous Logon', 'Authenticated Users', 'Batch', 'Creator Group', 'Creator Owner', 'Dialup', 'Digest Authentication', 'Enterprise Domain Controllers',
                                'Everyone', 'Interactive',  'Local Service', 'LocalSystem', 'Network' , 'Network Service', 'NTLM Authentication', 'Other Organization', 'Principal Self',
                                'Remote Interactive Logon', 'Restricted', 'SChannel Authentication', 'Service', 'Terminal Server User', 'This Organization', 'Window Manager\Window Manager Group')

    if ($arrSpecialIdentities.Contains($LocalAccount)) {
        Write-Debug "LocalAccountRecursiveMembership: Account is a special identity.  Returning."
        # This is a special identity and will not be able to be resolved.  Return as result.
        $mbrCurrent = New-Object AccountMembership
        $mbrCurrent.Account = $LocalAccount
        $mbrCurrent.MembershipPath = $LocalAccount
        Return $mbrCurrent
    }

    # Try to get the local account
    if ($LocalAccount -like '*\*') {
        $strSAMAccountName = $LocalAccount.split('\')[1]
    } else {
        $strSAMAccountName = $LocalAccount
    }
    Write-Debug "LocalAccountRecursiveMembership: Connecting to WinNT://$MachineName/$strSAMAccountName"
    $wmiTarget = [adsi] "WinNT://$MachineName/$strSAMAccountName"

    # Determine if the account is a group or a user
    If ($wmiTarget.psbase.SchemaClassName -eq 'Group') {
        Write-Debug "LocalAccountRecursiveMembership: Target is a group.  Enumerating membership."
        # Target is a group, enumerate membership and recursively call Get-LocalAccountRecursiveMembership
        $wmiGroupMembers = gwmi -query "select PartComponent, __Server from Win32_GroupUser where GroupComponent=`"Win32_Group.Domain='$LocalDomain',Name='$strSAMAccountName'`"" -ComputerName $MachineName
        
        # Ensure we recieved a result
        if ($wmiGroupMembers) {
            $wmiGroupMembers.partcomponent |
                %{                     
                    # Convert PartComponent into domain and account
                    $_.split(':')[1].split(".")[1].split(",") | %{
                        if ($_.split("=")[0] -eq 'Domain') {
                            $strAccountDomain = $_.split("=")[1].trim('"')
                        } elseif ($_.split("=")[0] -eq "Name") {
                            $strAccountName = $_.split("=")[1].trim('"')
                        }
                    }
                    
                    if ($arrSpecialIdentities.Contains($strAccountName)) {
                        Write-Debug "LocalAccountRecursiveMembership: Member is a special identity. Domain: $strAccountDomain SAMAccountName: $strAccountName"
                        # This is a special identity and will not be able to be resolved.  Return as result.
                        $mbrCurrent = New-Object AccountMembership
                        $mbrCurrent.Account = "$strAccountDomain\$strAccountName"
                        $mbrCurrent.MembershipPath = "$strAccountDomain\$strAccountName"
                        $lstGroupMembers.add($mbrCurrent)
                    } elseif ($strAccountDomain -eq $LocalDomain) {
                        Write-Debug "LocalAccountRecursiveMembership: Member is a local account. Domain: $strAccountDomain SAMAccountName: $strAccountName"
                        # Local groups cannot recurse.  Add to the list and continue.                          
                        $mbrCurrent = New-Object AccountMembership
                        $mbrCurrent.Account = "$strAccountDomain\$strAccountName"
                        $mbrCurrent.MembershipPath = "$strAccountDomain\$strAccountName -> is a member of -> $LocalDomain\$strSAMAccountName"
                        $lstGroupMembers.add($mbrCurrent)
                    } else {
                        Write-Debug "LocalAccountRecursiveMembership: Member is an AD principal.  Calling Get-ADAccountRecursiveGroupMembers Domain: $strAccountDomain SAMAccountName: $strAccountName"
                        Get-ADAccountRecursiveGroupMembers -Domain $strAccountDomain -SAMAccountName $strAccountName -MembershipPath "$strAccountDomain\$strAccountName -> is a member of -> $LocalDomain\$strSAMAccountName" | %{
                            $lstGroupMembers.Add($_)
                        }
                    }
                }
            }
            
        } else {
            # Account is a user.  Add to the list
            $mbrCurrent = New-Object AccountMembership
            $mbrCurrent.Account = $LocalAccount
            $mbrCurrent.MembershipPath = $LocalAccount
            $lstGroupMembers.Add($mbrCurrent)
        }

    # Add the results to the hashtable
    $global:hshLocalAccountCache.Add("$MachineName\$LocalAccount".ToLower(), $lstGroupMembers)

    # Return the results
    Return $lstGroupMembers
}

Function Get-CriticalAccounts {
    <#
        Get-CriticalAccounts
        by Michael Melone, Microsoft

        .SYNOPSIS

        This function enumerates all accounts that have some form of elevated access to a given machine based on user rights.

        .DESCRIPTION

        This function identifies all critical accounts (those having administrator-equivalent access through user rights) including
        those who obtain it through group membership (either local or Active Directory).

        For this function to work, the account used must have local administrator access to the target machine.

        .PARAMETER MachineName

        This is the machine to analyze for critical accounts.
    #>
    param(
        [parameter(Mandatory=$True)]
        [string] $MachineName
    )

    # Create a new list of CriticalAccounts
    $lstCriticalAccounts = New-Object System.Collections.Generic.List[CriticalAccount]

    # Get computer MachineName
    $strMachineName = (Get-WmiObject win32_computersystem -Computer $MachineName | Select name).name

    Get-AccountsWithUserRight -Computer $MachineName -Right SeTrustedCredManAccessPrivilege, SeTcbPrivilege, SeInteractiveLogonRight, SeRemoteInteractiveLogonRight, 
            SeBackupPrivilege, SeSystemtimePrivilege, SeCreateTokenPrivilege, SeCreatePermanentPrivilege, SeCreateSymbolicLinkPrivilege, 
            SeDebugPrivilege, SeAuditPrivilege, SeImpersonatePrivilege, SeLoadDriverPrivilege, SeBatchLogonRight, SeServiceLogonRight, 
            SeSecurityPrivilege, SeRelabelPrivilege, SeManageVolumePrivilege, SeProfileSingleProcessPrivilege, SeSystemProfilePrivilege, 
            SeRestorePrivilege, SeSyncAgentPrivilege, SeTakeOwnershipPrivilege | 
        ?{$_.account} | 
        %{
            # Loop through each user rights
            foreach ($hshUserRight in $_) {
                foreach ($strUser in $_.account) {
                    # Determine if the account is local, domain, or oprhaned
                    If ($strUser -like 'BUILTIN\*' -or $strUser -like 'NT AUTHORITY\*' -or $strUser -like 'NT SERVICE\*' -or $strUser -like "$strMachineName\*") {
                        # Account is local
                        Get-LocalAccountRecursiveMembership -MachineName $MachineName -LocalAccount $strUser -LocalDomain $strMachineName | %{
                            # Create a new CriticalAccount
                            $crtUser = New-Object CriticalAccount
                            $crtUser.MachineName = $strMachineName
                            $crtUser.UserRight = $hshUserRight.Right
                            $crtUser.RootPrincipal = $strUser
                            $crtUser.Domain = $_.Account.split('\')[0]
                            $crtUser.SAMAccountName = $_.Account.split('\')[1]                          
                            $crtUser.MembershipPath = $_.MembershipPath
                            
                            # Add the CriticalUser to the list
                            $lstCriticalAccounts.add($crtUser)
                        }
                    } elseif ($strUser -like "*\*") {
                        # User is domain
                        Get-ADAccountRecursiveGroupMembers -Domain $strUser.split('\')[0] -SAMAccountName $strUser.split('\')[1] | %{
                            # Create a new CriticalAccount
                            $crtUser = New-Object CriticalAccount
                            $crtUser.MachineName = $strMachineName
                            $crtUser.UserRight = $hshUserRight.Right
                            $crtUser.RootPrincipal = $strUser
                            $crtUser.Domain = $_.Account.split('\')[0]
                            $crtUser.SAMAccountName = $_.Account.split('\')[1]                           
                            $crtUser.MembershipPath = $_.MembershipPath

                            # Add the CriticalUser to the list
                            $lstCriticalAccounts.add($crtUser)
                        }
                    } else {
                        # User should be Orphan. 
                        $crtUser = New-Object CriticalAccount
                        $crtUser.MachineName = $strMachineName
                        $crtUser.UserRight = $hshUserRight.Right
                        $crtUser.RootPrincipal = $strUser 
                        $crtUser.SAMAccountName = $strUser
                        $crtUser.MembershipPath = $strUser

                        # Add the CriticalUser to the list
                        $lstCriticalAccounts.add($crtUser)
                    }
                }
            }
        }
    return $lstCriticalAccounts
}

# </functions>

#Iterate through each machine in $CriticalMachines
ForEach($strMachine in $CriticalMachines) {
    Write-Debug "Calling Get-CriticalAccounts on $strMachine"
    Get-CriticalAccounts -MachineName $strMachine | Export-csv $OutputCSV -Append -NoTypeInformation
}

# Reset all caches
Remove-Variable -name hshLocalAccountCache -scope global
Remove-Variable -name hshADAccountCache -scope global
Remove-Variable -name hshDomains -scope global

# This Sample Code is provided for the purpose of illustration only and is not intended to be used 
# in a production environment. THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" 
# WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED 
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. We grant You a nonexclusive, 
# royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code 
# form of the Sample Code, provided that You agree: (i) to not use Our name, logo, or trademarks to 
# market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright 
# notice on Your software product in which the Sample Code is embedded; and (iii) to indemnify, hold 
# harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys’ 
# fees, that arise or result from the use or distribution of the Sample Code.

# This sample script is not supported under any Microsoft standard support program or service. 
# The sample script is provided AS IS without warranty of any kind. Microsoft further disclaims 
# all implied warranties including, without limitation, any implied warranties of merchantability 
# or of fitness for a particular purpose. The entire risk arising out of the use or performance of 
# the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, 
# or anyone else involved in the creation, production, or delivery of the scripts be liable for any 
# damages whatsoever (including, without limitation, damages for loss of business profits, business 
# interruption, loss of business information, or other pecuniary loss) arising out of the use of or 
# inability to use the sample scripts or documentation, even if Microsoft has been advised of the 
# possibility of such damages 
