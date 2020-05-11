<#
	Get-ADAdminAccounts
	by Michael Melone, Microsoft

	.SYNOPSIS
	This script enumerates access control entries which can be leveraged to provide elevated access
	to an Active Directory domain.

	.DESCRIPTION
	This script will identify any principals that have the ability to tamper with an Active Directory domain in an
	administrative fashion.  If the principal is a group, its membership will be enumerated as well as the path 
	that led the principal to be identified as a critical account.

	.PARAMETER Domain
	This is one or more Active Directory domains to be assessed.  

	.PARAMETER OutputCSV
	This is the location where the CSV output will be generated.  

	.EXAMPLE
	The following command will enumerate critical accounts for the domain lab.net

	.\Get-ADAdminAccounts.ps1 -Domain 'lab.net'

	.NOTES
	Version | Date    | Author   | Notes
	========+=========+==========+===========================================================
	 1.0    | 02DEC16 | mimelone | Initial release
     1.1    | 27FEB17 | apetito  | Added try/catch blocks around TypeDefinitions
	 1.2	| 03MAR17 | mimelone | Updated DN parsing by Get-XADUser, added IsActive bit
	 1.3    | 29MAR17 | mimelone | Updated group recursion to include all paths to principal instead of only first path discovered
     1.4    | 30MAR17 | mimelone | Added user rights enumeration to script, reduced output by removing rights GUIDs
	 1.5    | 31MAR17 | mimelone | Added objectClass to results, added HTML output
	 1.6    | 19APR17 | mimelone | Added sIDHistory enumeration, code should now be PowerShell 2.0 compliant
	 1.7	| 22JUN17 | mimelone | Updated checks for AdminSDHolder to account for certain delegations
#>

param(
	[parameter(mandatory=$True)]
    [string[]] $Domain,
	[ValidateScript({-not (Test-Path $_ -PathType Leaf)})]
	[string] $OutputCSV = '.\ADCriticalAccounts.csv'
)

try {
    Import-Module ActiveDirectory
} catch {
    Write-Error "The Active Directory cmdlets are not installed.  Please install these cmdlets and try again."
    return -1
}

# Create the struct for an individual result
try { [CriticalDomainAccount] | Out-Null } 
catch {
Add-Type -TypeDefinition @"
    public struct CriticalDomainAccount
    {
        public string Domain;
		public string Object;
		public string AccountDomain;
        public string SAMAccountName;
		public string objectClass;
        public string RootPrincipal;
		public string ActiveDirectoryRights;
		public string ObjectType;
		public string InheritedObjectType;
		public string TranslatedObjectType;
		public string TranslatedInheritedObjectType;
        public string MembershipPath;
		public string IsEnabled;
    }
"@
}
try { [AccountMembership] | Out-Null } 
catch {
Add-Type -TypeDefinition @"
    public struct AccountMembership
    {
        public string Account;
        public string MembershipPath;
        public string IsEnabled;
		public string objectClass;
    }
"@
}

# Create a hashtable for translating AD guids to names
$hshADGUID = @{}
$hshADGUID.add('00000000-0000-0000-0000-000000000000', 'Generic All')
$hshADGUID.Add('2628a46a-a6ad-4ae0-b854-2b12d9fe6f9e', 'Account class')
$hshADGUID.Add('bf967a86-0de6-11d0-a285-00aa003049e2', 'Computer class')
$hshADGUID.Add('bf967a9c-0de6-11d0-a285-00aa003049e2', 'Group class')
$hshADGUID.Add('bf967aba-0de6-11d0-a285-00aa003049e2', 'User class')
$hshADGUID.Add('bf967915-0de6-11d0-a285-00aa003049e2', 'Account Expires attribute')
$hshADGUID.Add('00fbf30c-91fe-11d1-aebc-0000f80367c1', 'Alt Security Identities attribute')
$hshADGUID.Add('bf96792d-0de6-11d0-a285-00aa003049e2', 'Bad Password Time attribute')
$hshADGUID.Add('bf96792e-0de6-11d0-a285-00aa003049e2', 'Bad Pwd Count attribute')
$hshADGUID.Add('bf9679c0-0de6-11d0-a285-00aa003049e2', 'Member attribute')
$hshADGUID.Add('bf967a0a-0de6-11d0-a285-00aa003049e2', 'Pwd Last Set attribute')
$hshADGUID.Add('c7407360-20bf-11d0-a768-00aa006e0529', 'Domain Password property set')
$hshADGUID.Add('4c164200-20c0-11d0-a768-00aa006e0529', 'User Account Restrictions property set')
$hshADGUID.Add('e2a36dc9-ae17-47c3-b58b-be34c55ba633', 'Create Inbound Forest Trust extended right')
$hshADGUID.Add('3e0f7e18-2c7a-4c10-ba82-4d926db99a3e', 'DS Clone Domain Controller extended right')
$hshADGUID.Add('2f16c4a5-b98e-432c-952a-cb388ba33f2e', 'DS Execute Intentions Script extended right')
$hshADGUID.Add('9923a32a-3607-11d2-b9be-0000f87a36b2', 'DS Install Replica extended right')
$hshADGUID.Add('1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', 'DS Replication Get Changes All extended right')
$hshADGUID.Add('89e95b76-444d-4c62-991a-0facbeda640c', 'DS Replication Get Changes in Filtered Set extended right')
$hshADGUID.Add('1131f6ac-9c07-11d1-f79f-00c04fc2dcd2', 'DS Replication Manage Topology extended right')
$hshADGUID.Add('ba33815a-4f93-4c76-87f3-57574bff8109', 'Migrate SID History extended right')
$hshADGUID.Add('1131f6ae-9c07-11d1-f79f-00c04fc2dcd2', 'Read Only Replication Secret Synchronization extended right')
$hshADGUID.Add('45ec5156-db7e-47bb-b53f-dbeb2d03c40f', 'Reanimate Tombstones extended right')
$hshADGUID.Add('be2bb760-7f46-11d2-b9ad-00c04f79f805', 'Update Schema Cache extended right')

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
        $arrDN = $DistinguishedName.Split(',')
        $strDomainDNS = [string]::Empty
        $arrDN | %{
            if ($_.StartsWith('DC=')) {
                $strDomainDNS = "$strDomainDNS.$($_.split('=')[1])"
            }
        }
        $strDomainDNS = $strDomainDNS.TrimStart('.')
        
        #Try to get the domain
        try {
            $objDomain = Get-ADDomain -Identity $strDomainDNS
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
        [int] $SizeLimit = 100,
        [switch] $InitCache,
        [switch] $InitSidHistory
    )

    Write-Debug "Get-ADAccountRecursiveGroupMembers: Performing recursive enumeration of $Domain\$SAMAccountName with a SizeLimit of $SizeLimit"
    # Determine if a cache has already been created
    if ($InitCache -or -not $global:hshADAccountCache) {
        Write-Debug "Get-ADAccountRecursiveGroupMembers: Creating AD Account cache"
        # Create a new cache
        $global:hshADAccountCache = @{}
    }

    # Determine if sIDHistory dictionary already exists
    if ($InitSidHistory -or -not $global:dicSIDHistory) {
        Write-Debug "Get-ADAccountRecursiveGroupMembers: Creating new sIDHistory dictionary"
        # Create a new domain list and add the current domain's NetBIOSName
        $lstDomains = [System.Collections.Generic.List[string]](Get-ADDomain).NetBIOSName

        # Get all outbound or bidirectionally trusted domains
        $arrTrusts = Get-ADTrust -Filter {(Direction -eq 'Outbound') -or (Direction -eq 'BiDirectional')}

        $arrTrusts | %{
            if ($_.Direction -eq 'BiDirectional') {
                $lstDomains.Add((Get-ADDomain -Identity $_.Target).NetBIOSName)
            } else {
                Write-Warning "Outbound trust to domain $($_.Target) prevents sIDHistory enumeration.  If configured, an account with a sIDHistory value containing the SID of an account from this domain may be trusted by this domain.  
Forest Transitive: $($_.ForestTransitive)
Selective Authentication: $($_.SelectiveAuthentication)
SID Filtering Quarantined: $($_.SIDFilteringQuarantined) 
SID Filtering Forest Aware: $($_.SIDFilteringForestAware)
TGT Delegation: $($_.TGTDelegation)"
            }
        }

        # Build an empty hashtable for fast lookups of sIDHistory
        $global:dicSIDHistory = New-Object 'System.Collections.Generic.Dictionary [[string],[system.collections.generic.list[string]]]'

        # Iterate through each trusted domain
        foreach ($strDomain in $lstDomains) {
            # Get a domain controller from the domain
            $strDC = Get-ADDomainController -DomainName $strDomain -ForceDiscover -Service ADWS -Discover

            # Get sIDHistory for all domains and trusted domains
            $arrSIDHistoryAccounts = Get-ADObject -LDAPFilter "(sIDHistory=*)" -Server $strDC.HostName[0] -Properties sIDHistory, sAMAccountName

            foreach ($adoAccount in $arrSIDHistoryAccounts) {
                $adoAccount.SIDHistory | %{
                    if ($global:dicSIDHistory.ContainsKey($_.value)) {
                        $global:dicSIDHistory[$_.value].add(($strDomain + "\" + $adoAccount.sAMAccountName))
                    } else {
                        $lstAccounts = New-Object System.Collections.Generic.List[string]
                        $lstAccounts.Add(($strDomain + "\" + $adoAccount.sAMAccountName))
                        $global:dicSIDHistory.add($_.value,$lstAccounts)
                    }
                }
            }
        }
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
                                'Remote Interactive Logon', 'Restricted', 'SChannel Authentication', 'Service', 'Terminal Server User', 'This Organization', 'Window Manager\Window Manager Group', 'SYSTEM', 'ENTERPRISE DOMAIN CONTROLLERS')

    if ($arrSpecialIdentities.Contains($SAMAccountName)) {
        Write-Debug "Get-ADAccountRecursiveGroupMembers: Account is a special identity, returning "
        # This is a special identity and will not be able to be resolved.  Return as result.
        $mbrCurrent = New-Object AccountMembership
        $mbrCurrent.Account = "$Domain\$SAMAccountName"
        $mbrCurrent.MembershipPath = $MembershipPath
		$mbrCurrent.objectClass = "SpecialIdentity"
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

        # Determine if the SID for the account is in the sIDHistory of any other known account
        Write-Debug "Get-ADAccountRecursiveGroupMembers: Checking sIDHistory table"
        if ($global:dicSIDHistory.ContainsKey($objCurrent.SID.value)) {
            Write-Debug "Get-ADAccountRecursiveGroupMembers: sIDHistory present."
            # Account is referenced in sIDHistory.  
            $global:dicSIDHistory[$objCurrent.SID.value] | %{
                Write-Debug "Get-ADAccountRecursiveGroupMembers: Analyzing sIDHistory member $_"
                $objSidHistoryMember = Get-XADObject -Domain $_.split('\')[0] -SAMAccountName $_.split('\')[1] -Properties objectClass
                if ($objSidHistoryMember.objectClass -eq 'group') {
                    Write-Debug "Get-ADAccountRecursiveGroupMembers: sIDHistory member $_ is a group - recursing membership"
                    
                    if (-not $ResolvedAccounts.contains($objSidHistoryMember.distinguishedname)) {
                        
                        # Update resolved accounts
                        $ResolvedAccounts.Add($objSidHistoryMember.distinguishedName)

                        # Recurse Membership
                        Get-ADAccountRecursiveGroupMembers -SAMAccountName $_.split('\')[1] -Domain $_.split('\')[0] -MembershipPath "$_ -> has a sIDHistory entry for -> $MembershipPath" -ResolvedAccounts $ResolvedAccounts | %{
                            # Add members to result
                            $lstGroupMembers.Add($_)
                        }
                    }
                }
                $mbrCurrent = New-Object AccountMembership
				$mbrCurrent.Account = $_
				$mbrCurrent.MembershipPath = "$_ -> has a sIDHistory entry for -> $MembershipPath"
                $mbrCurrent.IsEnabled = $objSidHistoryMember.Enabled
				$mbrCurrent.objectClass = $objSidHistoryMember.objectClass
				$lstGroupMembers.add($mbrCurrent)
            }
        }

        # Determine if this is a group
        if ($objCurrent.objectClass -eq 'group') {
            Write-Debug "Get-ADAccountRecursiveGroupMembers: Target is a group.  Enumerating membership."
            # Add the current account to the list of resolved accounts
            $ResolvedAccounts.Add($objCurrent.distinguishedName)
            
            # Get group membership and add each to list
            $arrGroupMembers = Get-ADGroupMember -Identity $objCurrent.distinguishedName -Server $objCurrent.DomainController

            # See if we met or exceeded the membership threshold
			if ($arrGroupMembers) {
				if ($arrGroupMembers.count -ge $SizeLimit) {
					Write-Debug "Get-ADAccountRecursiveGroupMembers: Membership exceeded size limit, returning count of accounts."
					$mbrCurrent = New-Object AccountMembership
					$mbrCurrent.Account = "$($arrGroupMembers.count) accounts"
					$mbrCurrent.MembershipPath = "$($arrGroupMembers.count) accounts -> are members of -> $MembershipPath"
					$mbrCurrent.objectClass = "GroupMembership"
					$lstGroupMembers.add($mbrCurrent)
				} else {
					Write-Debug "Get-ADAccountRecursiveGroupMembers: $($arrGroupMembers.count) members found."
					<##>

					$arrGroupMembers | ?{-not $ResolvedAccounts.Contains($_.distinguishedName)} | %{
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
							$mbrCurrent.IsEnabled = $adoCurrentMember.Enabled
							$mbrCurrent.objectClass = $adoCurrentMember.objectClass
                            $lstGroupMembers.Add($mbrCurrent)
						}
					}
				}
			}
        }
		$mbrCurrent = New-Object AccountMembership
		$mbrCurrent.Account = "$Domain\$sAMAccountName"
		$mbrCurrent.MembershipPath = $MembershipPath
		$mbrCurrent.objectClass = $objCurrent.objectClass
		$lstGroupMembers.add($mbrCurrent)
    } else {
        Write-Error "The following object was not found in Active Directory: $Domain\$SAMAccountName"
        Return $Null
    }

    Write-Debug "Get-ADAccountRecursiveGroupMembers: Adding current member to the cache"
    # Add the result to the cache for future lookups
    if (-not $global:hshADAccountCache.ContainsKey("$Domain\$SAMAccountName")) {
        $global:hshADAccountCache.add("$Domain\$SAMAccountName".ToLower(),$lstGroupMembers)
    }

    Return $lstGroupMembers
}

function Get-TemporaryFilePath {

    #Get a folder for the temporary file
    if (test-path $env:TEMP) {
        $strTempFolder = $env:TEMP
    } elseif (test-path $env:TMP) {
        $strTempFolder = $env:TMP
    } elseif (test-path $env:USERPROFILE) {
        $strTempFolder = $env:USERPROFILE
    } else {
        #Too many failed attempts, something is wrong
        Write-Error "An error was encountered when trying to obtain a temporary file."
        Return $Null
    }

    $a = 0
    #Loop until we get a working file or 10 failures
    while ((-not $objFile) -and ($a -le 10)) {
        $strRandomFileName = "$(Get-Random).tmp"
		$strTempFilePath = Join-Path $strTempFolder $strRandomFileName
        #Determine if the file already exists
        if (-not (test-path $strTempFilePath)) {
			Return $strTempFilePath
        }

        $a++
    }

    Write-Error "Unable to find an available temporary file location after 10 tries."
	return [string]::Empty
}

$aclCriticalDomainACLs = @()

foreach ($strDomain in $Domain) {
    
    # Determine if domain is NetBIOS or DNS
    if ($strDomain -like '*.*') {
        # Converting to NetBIOS name for consistency
        $strDomain = (Get-ADDomain -Identity $strDomain).NetBIOSName
    }

	Get-ADDomain $strDomain | %{
		$strDomainDN = $_.DistinguishedName
		$strDomainNetBIOS = $_.NetBIOSName
	}

	(Get-Acl "AD:\$strDomainDN").access | ?{
		$_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and (
			(
				(
					$_.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::AccessSystemSecurity) -or 
					$_.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)	-or 
					$_.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::GenericWrite) -or 
					$_.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::Synchronize) -or 
					$_.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -or 
					$_.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)	-or 
					$_.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty)
				) -and $_.ObjectType -in @(
					'00000000-0000-0000-0000-000000000000' # All Objects
					, '19195a5b-6da0-11d0-afd3-00c04fd930c9' # Domain DNS (root of the domain)
				)
			) -or (
				$_.ActiveDirectoryRights.HasFlag(([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)) -and $_.ObjectType -in @(
					'00000000-0000-0000-0000-000000000000' # Full control
					# Property sets
					, 'c7407360-20bf-11d0-a768-00aa006e0529' # Domain Password property set
					, '4c164200-20c0-11d0-a768-00aa006e0529' # User Account Restrictions property set
					# Individual extended rights
					, 'e2a36dc9-ae17-47c3-b58b-be34c55ba633' # Create Inbound Forest Trust
					, '3e0f7e18-2c7a-4c10-ba82-4d926db99a3e' # DS Clone Domain Controller
					, '2f16c4a5-b98e-432c-952a-cb388ba33f2e' # DS Execute Intentions Script
					, '9923a32a-3607-11d2-b9be-0000f87a36b2' # DS Install Replica
					, '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' # DS Replication Get Changes All (includes secrets)
					, '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2' # DS Replication Manage Topology
					, 'ba33815a-4f93-4c76-87f3-57574bff8109' # Migrate SID History
					, '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2' # Read  Only Replication Secret Synchronization
					, '45ec5156-db7e-47bb-b53f-dbeb2d03c40f' # Reanimate Tombstones
					# , '0bc1554e-0a99-11d1-adbb-00c04fd8d5cd' # Recalculate Hierarchy - not much of a concern, but probably shouldn't be delegated
					# , '62dd28a8-7f46-11d2-b9ad-00c04f79f805' # Recalculate Security Inheritance - same as prior
					, 'be2bb760-7f46-11d2-b9ad-00c04f79f805' # Update Schema Cache
					# , 'ab721a53-1e2f-11d0-9819-00aa0040529b' # Allows changing of a user password - low impact
				)
			)
		)
	} | %{
		$aclCriticalDomainACLs += $_ | Add-Member -NotePropertyName "Object" -NotePropertyValue $strDomainDN -PassThru |
			Add-Member -NotePropertyName "Domain" -NotePropertyValue $strDomain -PassThru  |
			Add-Member -NotePropertyName "DomainNetBIOS" -NotePropertyValue $strDomainNetBIOS -PassThru
	}

	# Get ACL for the AdminSD holder
	(Get-ACL "AD:\CN=AdminSDHolder,CN=System,$strDomainDN").access | ?{
		$_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and (
			$_.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::AccessSystemSecurity) -or 
			$_.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)	-or 
			$_.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::GenericWrite) -or 
			$_.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::Synchronize) -or 
			$_.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -or 
			$_.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)	-or 
			$_.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty)
		) -and (
			$_.ObjectType -in @(
				'00000000-0000-0000-0000-000000000000' # All Objects
				, '2628a46a-a6ad-4ae0-b854-2b12d9fe6f9e' # Account class
				, 'bf967a86-0de6-11d0-a285-00aa003049e2' # Computer class
				, 'bf967a9c-0de6-11d0-a285-00aa003049e2' # Group class
				, 'bf967aba-0de6-11d0-a285-00aa003049e2' # User class
				, 'bf967915-0de6-11d0-a285-00aa003049e2' # Account Expires
				, '00fbf30c-91fe-11d1-aebc-0000f80367c1' # Alt Security Identities
				, 'bf96792d-0de6-11d0-a285-00aa003049e2' # Bad Password Time
				, 'bf96792e-0de6-11d0-a285-00aa003049e2' # Bad Pwd Count
				, 'bf9679c0-0de6-11d0-a285-00aa003049e2' # Member
				, 'bf967a0a-0de6-11d0-a285-00aa003049e2' # Pwd Last Set
			) -and $_.InheritedObjectType -in @(
				'00000000-0000-0000-0000-000000000000' # All Properties
				, 'bf967915-0de6-11d0-a285-00aa003049e2' # Account Expires
				, '00fbf30c-91fe-11d1-aebc-0000f80367c1' # Alt Security Identities
				, 'bf96792d-0de6-11d0-a285-00aa003049e2' # Bad Password Time
				, 'bf96792e-0de6-11d0-a285-00aa003049e2' # Bad Pwd Count
				, 'bf9679c0-0de6-11d0-a285-00aa003049e2' # Member
				, 'bf967a0a-0de6-11d0-a285-00aa003049e2' # Pwd Last Set
                , 'bf967aba-0de6-11d0-a285-00aa003049e2' # User class
                , 'bf967a86-0de6-11d0-a285-00aa003049e2' # Computer class
				, 'bf967a9c-0de6-11d0-a285-00aa003049e2' # Group class

			)
		)
	} | %{
		$aclCriticalDomainACLs += $_ | 
			Add-Member -NotePropertyName "Object" -NotePropertyValue "CN=AdminSDHolder,CN=System,$strDomainDN" -PassThru |
			Add-Member -NotePropertyName "Domain" -NotePropertyValue $strDomain -PassThru |
			Add-Member -NotePropertyName "DomainNetBIOS" -NotePropertyValue $strDomainNetBIOS -PassThru
	}
}

# Create a new list of critical accounts
$lstCriticalDomainAccounts = New-Object System.Collections.Generic.List[CriticalDomainAccount]

# Loop through each relevant ACE
foreach ($aceCurrent in $aclCriticalDomainACLs) {
	# Determine if the domain is BUILTIN or NT AUTHORITY, if so swap with domain
	if ($aceCurrent.identityreference.value.split('\')[0] -in @('BUILTIN', 'NT AUTHORITY')) {
		$strDomain = $aceCurrent.DomainNetBIOS
	} else {
		$strDomain = $aceCurrent.identityreference.value.split('\')[0]
	}
	Get-ADAccountRecursiveGroupMembers -SAMAccountName $aceCurrent.identityreference.value.split('\')[1] -Domain $strDomain | %{
		$crtCurrent = New-Object CriticalDomainAccount
		$crtCurrent.Domain = $aceCurrent.Domain
		$crtCurrent.Object = $aceCurrent.Object
		$crtCurrent.AccountDomain = $_.account.split('\')[0]
        $crtCurrent.SAMAccountName = $_.account.split('\')[1]
		$crtCurrent.objectClass = $_.objectClass
        $crtCurrent.RootPrincipal = $aceCurrent.IdentityReference.value
		$crtCurrent.ActiveDirectoryRights = $aceCurrent.ActiveDirectoryRights.ToString()
		$crtCurrent.ObjectType = $aceCurrent.ObjectType.guid
		$crtCurrent.InheritedObjectType = $aceCurrent.InheritedObjectType.guid
		$crtCurrent.TranslatedObjectType = $hshADGUID[($aceCurrent.ObjectType.guid)]
		$crtCurrent.TranslatedInheritedObjectType = $hshADGUID[$aceCurrent.InheritedObjectType.guid]
        $crtCurrent.MembershipPath = $_.MembershipPath
        $crtCurrent.IsEnabled = $_.IsEnabled

		$lstCriticalDomainAccounts.add($crtCurrent)
	}
}

# User rights processing
foreach ($strDomain in $Domain) {
    # Determine if domain is NetBIOS or DNS
    if ($strDomain -like '*.*') {
        # Converting to NetBIOS name for consistency
        $strDomain = (Get-ADDomain -Identity $strDomain).NetBIOSName
    }

	Write-Debug "Get-ADAdminAccounts: Beginning user rights enumeration for domain $strDomain"
	# Try to get GPO report from a DC through discovery
	$strDC = (Get-ADDomainController -Discover -DomainName $strDomain).HostName[0]
	Write-Debug "Get-ADAdminAccounts: Selecting $strDC as domain controller for RSOP assessment."
	$boolSuccess = $false
	try {
		$strRSOPTempFile = (Get-TemporaryFilePath)
		Write-Debug "Get-ADAdminAccounts: Temporary file for RSOP: $strRSOPTempFile"
		Get-GPResultantSetOfPolicy -Computer $strDC -Path $strRSOPTempFile -ReportType Xml -ErrorAction Stop | Out-Null
		Write-Debug "Get-ADAdminAccounts: Get-GPResultantSetOfPolicy succeeded"
		$boolSuccess = $True
	} catch {
		Write-Debug "Get-ADAdminAccounts: Get-GPResultantSetOfPolicy failed.  Deleting temp file."
		Remove-Item $strRSOPTempFile -Force -ErrorAction SilentlyContinue

		# Get a list of domain controllers for the domain
		$arrDC = (Get-ADDomain -Identity $strDomain).ReplicaDirectoryServers | ?{$_ -ne $strDC}
		$a = 0
		if ($arrDC.count -gt 10) {
			$aMax = 10
		} else {
			$aMax = $arrDC.count
		}
		Write-Warning "An error occurred while attempting to obtain RSOP from $strDC.  Trying $aMax DC's at random"
		While ($a -lt $aMax) {
			$a++
			try {
				$strRSOPTempFile = (Get-TemporaryFilePath)
				$strDC = $arrDC[$a] 
				Write-Debug "Get-ADAdminAccounts: Attempting RSOP on $strDC"
				Get-GPResultantSetOfPolicy -Computer $strDC -Path $strRSOPTempFile -ReportType Xml -ErrorAction Stop | Out-Null
				Write-Debug "Get-ADAdminAccounts: RSOP succeeded"
				$boolSuccess = $True 
			} catch {
				Write-Debug "Get-ADAdminAccounts: RSOP failed"
				Remove-Item $strRSOPTempFile -Force
			}
		}
	}

	Write-Debug "Get-ADAdminAccounts: beginning user right parsing code"
	if ($boolSuccess) {
		Write-Debug "Get-ADAdminAccounts: Reading RSOP output"
		$xmlRSOP = [xml](gc $strRSOPTempFile)

		# Create an array of special identities that cannot be enumerated \ recursed
		$arrSpecialIdentities = @('Anonymous Logon', 'Authenticated Users', 'Batch', 'Creator Group', 'Creator Owner', 'Dialup', 'Digest Authentication', 'Enterprise Domain Controllers',
            'Everyone', 'Interactive',  'Local Service', 'LocalSystem', 'Network' , 'Network Service', 'NTLM Authentication', 'Other Organization', 'Principal Self',
            'Remote Interactive Logon', 'Restricted', 'SChannel Authentication', 'Service', 'Terminal Server User', 'This Organization', 'Window Manager\Window Manager Group', 'NT SERVICE\WdiServiceHost')

		# Enumerate user rights
		$xmlRSOP.rsop.ComputerResults.ExtensionData.extension.UserRightsAssignment |
			?{$_.Name -in @('SeTrustedCredManAccessPrivilege', 'SeTcbPrivilege', 'SeInteractiveLogonRight', 'SeRemoteInteractiveLogonRight', 
            'SeBackupPrivilege', 'SeSystemtimePrivilege', 'SeCreateTokenPrivilege', 'SeCreatePermanentPrivilege', 'SeCreateSymbolicLinkPrivilege', 
            'SeDebugPrivilege', 'SeAuditPrivilege', 'SeImpersonatePrivilege', 'SeLoadDriverPrivilege', 'SeBatchLogonRight', 'SeServiceLogonRight', 
            'SeSecurityPrivilege', 'SeRelabelPrivilege', 'SeManageVolumePrivilege', 'SeProfileSingleProcessPrivilege', 'SeSystemProfilePrivilege', 
            'SeRestorePrivilege', 'SeSyncAgentPrivilege', 'SeTakeOwnershipPrivilege')} | %{
				$strUserRight = $_.Name

				Write-Debug "Get-ADAdminAccounts: Enumerating user right $strUserRight"
				foreach ($strUser in $_.Member.name.'#text') {
					Write-Debug "Get-ADAdminAccounts: Analyzing $strUser, user right $strUserRight"
					# There is no such thing as a true local account relative to a domain controller, therefore local accounts will not be checked
					if ($strUser -in $arrSpecialIdentities) {
						Write-Debug "Get-ADAdminAccounts: User $strUser was identified as a special identity."
						# User is a special identity which cannot be recursed.  Adding to results
						$cdaCurrent = New-Object CriticalDomainAccount
						$cdaCurrent.Domain = $strDomain
						$cdaCurrent.Object = $strDC
						$cdaCurrent.AccountDomain = $strDomain
						$cdaCurrent.SAMAccountName = $strUser
						$cdaCurrent.objectClass = "SpecialIdentity"
						$cdaCurrent.RootPrincipal = $strUser
						$cdaCurrent.ActiveDirectoryRights = $strUserRight
						$cdaCurrent.ObjectType = [string]::Empty
						$cdaCurrent.InheritedObjectType = [string]::Empty
						$cdaCurrent.TranslatedObjectType = "UserRight"
						$cdaCurrent.TranslatedInheritedObjectType = [string]::Empty
						$cdaCurrent.MembershipPath = $strUser
						$cdaCurrent.IsEnabled = 'True'
						$lstCriticalDomainAccounts.add($cdaCurrent)
					} else {
						Write-Debug "Get-ADAdminAccounts: User $strUser was identified as a normal account"
						# Principal is a domain account
						if ($strUser -like "*\*") {
							$arrUser = $strUser.split('\')
							$strPrincipalDomain = $arrUser[0]
							$strPrincipalUser = $arrUser[1]
						} else {
							$strPrincipalDomain = $strDomain
							$strPrincipalUser = $strUser
						}
						Write-Debug "Get-ADAdminAccounts: Calling Get-ADAccountRecursiveGroupMembers -SAMAccountName $strPrincipalUser -Domain $strPrincipalDomain"
						Get-ADAccountRecursiveGroupMembers -SAMAccountName $strPrincipalUser -Domain $strPrincipalDomain | %{
							$cdaCurrent = New-Object CriticalDomainAccount
							$cdaCurrent.Domain = $strDomain
							$cdaCurrent.Object = $strDC
							$cdaCurrent.AccountDomain = $_.account.split('\')[0]
							$cdaCurrent.SAMAccountName = $_.account.split('\')[1]
							$cdaCurrent.objectClass = $_.objectClass
							$cdaCurrent.RootPrincipal = $strUser
							$cdaCurrent.ActiveDirectoryRights = $strUserRight
							$cdaCurrent.ObjectType = [string]::Empty
							$cdaCurrent.InheritedObjectType = [string]::Empty
							$cdaCurrent.TranslatedObjectType = "UserRight"
							$cdaCurrent.TranslatedInheritedObjectType = [string]::Empty
							$cdaCurrent.MembershipPath = $_.MembershipPath
							$cdaCurrent.IsEnabled = $_.IsEnabled
							$lstCriticalDomainAccounts.add($cdaCurrent)
						}
					}
					Write-Debug "Get-ADAdminAccounts: Critical accounts list now has $($lstCriticalDomainAccounts.count) members"
				}
		}
	} else {
		Write-Error "Unable to obtain a group policy result after $aMax attempts.  Omitting user rights."
	}
}

# Create verbose report
$lstCriticalDomainAccounts | 
    Select Domain, Object, AccountDomain, SAMAccountName, objectClass, RootPrincipal, ActiveDirectoryRights, TranslatedObjectType, TranslatedInheritedObjectType, MembershipPath, IsEnabled | 
    Export-Csv $OutputCSV -NoTypeInformation

# Create the HTML report
Write-Debug "Get-ADAdminAccounts: Beginning HTML report creation"

Write-Debug "Get-ADAdminAccounts: Loading system.web namespace"
[System.Reflection.Assembly]::LoadWithPartialName("System.web") | Out-Null

function ConvertTo-HTMLEncoding {
	param(
		[parameter(mandatory=$True, Position=1)]
		[string] $String
	)
	Return ([System.Web.HttpUtility]::HtmlEncode($String))
}

# Create HTML header
$htmReport = "
<!DOCTYPE html>
<html>
	<head>
		<meta charset=""UTF-8"">
		<title>Active Directory Admin Account Report</title>
<style type=""text/css"">
p {
    padding: 0;
    margin: 0;
} 

body {
background: #fff url(images/bg.jpg) repeat-x;
font-family: Arial, Helvetica, sans-serif;
font-size: 12px;
line-height: 18px;
color: #333333;;
}

h1 {
font-size: 30px;
font-weight: 100;
padding: 50px 0 15px 0;
}

h2 {
color: #3692AF;
font-size: 19px;
font-weight: 100;
padding: 10px 0 2px 0;
line-height: 12px;
}

h3 {
font-size: 12px;
color: #666;
}

table.accessControlEntriesTable {
	font-family: verdana,arial,sans-serif;
	font-size:11px;
	color:#333333;
	border-width: 1px;
	border-color: #999999;
	border-collapse: collapse;
}
table.accessControlEntriesTable th {
	padding: 0px;
	background: #d5e3e4;
	background: url(data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiA/Pgo8c3ZnIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgd2lkdGg9IjEwMCUiIGhlaWdodD0iMTAwJSIgdmlld0JveD0iMCAwIDEgMSIgcHJlc2VydmVBc3BlY3RSYXRpbz0ibm9uZSI+CiAgPGxpbmVhckdyYWRpZW50IGlkPSJncmFkLXVjZ2ctZ2VuZXJhdGVkIiBncmFkaWVudFVuaXRzPSJ1c2VyU3BhY2VPblVzZSIgeDE9IjAlIiB5MT0iMCUiIHgyPSIwJSIgeTI9IjEwMCUiPgogICAgPHN0b3Agb2Zmc2V0PSIwJSIgc3RvcC1jb2xvcj0iI2Q1ZTNlNCIgc3RvcC1vcGFjaXR5PSIxIi8+CiAgICA8c3RvcCBvZmZzZXQ9IjQwJSIgc3RvcC1jb2xvcj0iI2NjZGVlMCIgc3RvcC1vcGFjaXR5PSIxIi8+CiAgICA8c3RvcCBvZmZzZXQ9IjEwMCUiIHN0b3AtY29sb3I9IiNiM2M4Y2MiIHN0b3Atb3BhY2l0eT0iMSIvPgogIDwvbGluZWFyR3JhZGllbnQ+CiAgPHJlY3QgeD0iMCIgeT0iMCIgd2lkdGg9IjEiIGhlaWdodD0iMSIgZmlsbD0idXJsKCNncmFkLXVjZ2ctZ2VuZXJhdGVkKSIgLz4KPC9zdmc+);
	background: -moz-linear-gradient(top,  #d5e3e4 0%, #ccdee0 40%, #b3c8cc 100%);
	background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,#d5e3e4), color-stop(40%,#ccdee0), color-stop(100%,#b3c8cc));
	background: -webkit-linear-gradient(top,  #d5e3e4 0%,#ccdee0 40%,#b3c8cc 100%);
	background: -o-linear-gradient(top,  #d5e3e4 0%,#ccdee0 40%,#b3c8cc 100%);
	background: -ms-linear-gradient(top,  #d5e3e4 0%,#ccdee0 40%,#b3c8cc 100%);
	background: linear-gradient(to bottom,  #d5e3e4 0%,#ccdee0 40%,#b3c8cc 100%);
	border: 1px solid #999999;
}
table.accessControlEntriesTable td {
	padding: 0px;
	background: #ebecda;
	background: url(data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiA/Pgo8c3ZnIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgd2lkdGg9IjEwMCUiIGhlaWdodD0iMTAwJSIgdmlld0JveD0iMCAwIDEgMSIgcHJlc2VydmVBc3BlY3RSYXRpbz0ibm9uZSI+CiAgPGxpbmVhckdyYWRpZW50IGlkPSJncmFkLXVjZ2ctZ2VuZXJhdGVkIiBncmFkaWVudFVuaXRzPSJ1c2VyU3BhY2VPblVzZSIgeDE9IjAlIiB5MT0iMCUiIHgyPSIwJSIgeTI9IjEwMCUiPgogICAgPHN0b3Agb2Zmc2V0PSIwJSIgc3RvcC1jb2xvcj0iI2ViZWNkYSIgc3RvcC1vcGFjaXR5PSIxIi8+CiAgICA8c3RvcCBvZmZzZXQ9IjQwJSIgc3RvcC1jb2xvcj0iI2UwZTBjNiIgc3RvcC1vcGFjaXR5PSIxIi8+CiAgICA8c3RvcCBvZmZzZXQ9IjEwMCUiIHN0b3AtY29sb3I9IiNjZWNlYjciIHN0b3Atb3BhY2l0eT0iMSIvPgogIDwvbGluZWFyR3JhZGllbnQ+CiAgPHJlY3QgeD0iMCIgeT0iMCIgd2lkdGg9IjEiIGhlaWdodD0iMSIgZmlsbD0idXJsKCNncmFkLXVjZ2ctZ2VuZXJhdGVkKSIgLz4KPC9zdmc+);
	background: -moz-linear-gradient(top,  #ebecda 0%, #e0e0c6 40%, #ceceb7 100%);
	background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,#ebecda), color-stop(40%,#e0e0c6), color-stop(100%,#ceceb7));
	background: -webkit-linear-gradient(top,  #ebecda 0%,#e0e0c6 40%,#ceceb7 100%);
	background: -o-linear-gradient(top,  #ebecda 0%,#e0e0c6 40%,#ceceb7 100%);
	background: -ms-linear-gradient(top,  #ebecda 0%,#e0e0c6 40%,#ceceb7 100%);
	background: linear-gradient(to bottom,  #ebecda 0%,#e0e0c6 40%,#ceceb7 100%);
	border: 1px solid #999999;
}
table.accessControlEntriesTable th p{
	margin:0px;
	padding:8px;
	border-top: 1px solid #eefafc;
	border-bottom:0px;
	border-left: 1px solid #eefafc;
	border-right:0px;
}
table.accessControlEntriesTable td p{
	margin:0px;
	padding:8px;
	border-top: 1px solid #fcfdec;
	border-bottom:0px;
	border-left: 1px solid #fcfdec;;
	border-right:0px;
}
ul.permissionsGranted {
	list-style-type: none;
}
</style>
	</head>
	<body>
		<p>Report generated: $(ConvertTo-HTMLEncoding ((Get-Date).ToString()))</p>
		<p>Domains analyzed: $(ConvertTo-HTMLEncoding ([string]::Join(", ",$Domain)))</p>
		<p>Script executed from: $(ConvertTo-HTMLEncoding $env:COMPUTERNAME)</p>
		<p>Script executed by: $(ConvertTo-HTMLEncoding ($env:USERDOMAIN + "\" + $env:USERNAME))</p>"

# Loop through each domain
Write-Debug "Get-ADAdminAccounts: Iterating through each domain"
foreach ($strDomain in $Domain) {

	if ($strDomain -like '*.*') {
        # Converting to NetBIOS name for consistency
        $strDomain = (Get-ADDomain -Identity $strDomain).NetBIOSName
    }

	Write-Debug "Get-ADAdminAccounts: Current domain: $strDomain"
	$arrDomainResults = $lstCriticalDomainAccounts | ?{$_.Domain -like $strDomain}

	Write-Debug "Get-ADAdminAccounts: $($lstCriticalDomainAccounts.count) critical account entries identified"
	# Add domain as primary header
	$htmReport += "<h1>Domain: $(ConvertTo-HTMLEncoding $strDomain)</h1>"

	$arrCriticalAccounts = $arrDomainResults | Select-Object accountdomain, SAMAccountName, objectClass, IsEnabled -Unique
	Write-Debug "Get-ADAdminAccounts: $($arrCriticalAccounts.count) distinct critical accounts identified"
	foreach ($objCriticalAccount in $arrCriticalAccounts) {
		Write-Debug "Get-ADAdminAccounts: Current account information - Domain: $($objCriticalAccount.AccountDomain) SAMAccountName: $($objCriticalAccount.SAMAccountName)"
		if ($objCriticalAccount.samaccountname -like "*\*") {
			$htmReport += "<h2>Account: $(ConvertTo-HTMLEncoding ($objCriticalAccount.SAMAccountName))</h2>"
		} else {
			$htmReport += "<h2>Account: $(ConvertTo-HTMLEncoding ($objCriticalAccount.AccountDomain + "\" + $objCriticalAccount.SAMAccountName))</h2>"
		}

		$htmReport += "<p>Object Class: $(ConvertTo-HTMLEncoding $objCriticalAccount.objectClass)</p>"
		if (-not [string]::IsNullOrEmpty($objCriticalAccount.IsEnabled)) {
			$htmReport += "<p>Enabled: $($objCriticalAccount.IsEnabled)</p>"
		}
		$htmReport += "<h3>Enabling Membership</h3>
		<ul>"
		
		# Create an array of ACE's where the account received elevated access
		$arrAccountResults = $arrDomainResults | 
		?{$_.AccountDomain -eq $objCriticalAccount.AccountDomain -and $_.SAMAccountName -eq $objCriticalAccount.SAMAccountName} 

		# Get a list of unique MembershipPath attributes for the user
		$arrDirectMemberships = @()
		$arrAccountResults | 
			Select-Object MembershipPath -Unique| %{
				$arrMembershipPath = $_.MembershipPath -replace " -> is a member of ","" -replace " -> has a sIDHistory entry for " -split "-> "
				if ($arrMembershipPath.Count -gt 1) {
					$arrDirectMemberships += $arrMembershipPath[1]
				} else {
					$arrDirectMemberships += $arrMembershipPath[0]
				}
			}
		# Add each direct enabling membership to the UL
		$arrDirectMemberships | Sort-Object -Unique | %{
			$htmReport += "<li>$(ConvertTo-HTMLEncoding $_)</li>"
		}
		$htmReport += "</ul>
		<h3>Access Control List Entries</h3>
		<div style=""overflow-x:auto;"">
		<table class=""accessControlEntriesTable"">
			<colgroup><col/><col/><col/><col/></colgroup> 
			<tr><th>Permissioned Object</th><th>Principal Granted Access</th><th>Permissions Granted</th><th>Membership Path (ordered by depth)</th></tr>"
		# Add each access control entry where the principal was found
		$arrAccountResults | Select-Object object, RootPrincipal, ActiveDirectoryRights, MembershipPath | %{
			$htmReport += "<tr><td>$(ConvertTo-HTMLEncoding $_.object)</td><td>$(ConvertTo-HTMLEncoding $_.RootPrincipal)</td>"
			$htmReport += "<td><ul class=""permissionsGranted"">" + ($_.ActiveDirectoryRights.split(',') | %{"<li>$(ConvertTo-HTMLEncoding $_)</li>"}) + "</ul></td>"
			$htmReport += "<td><ol class=""membershipPath"">" + ($_.MembershipPath -replace " -> is a member of ","" -replace " -> has a sIDHistory entry for " -split "-> " | %{"<li>$(ConvertTo-HTMLEncoding $_)</li>"}) + "</ol></td></tr>"
		}
		$htmReport += "</table></div>"
	}
	# Close unordered list
	$htmReport += "</ul>"
}

# Create HTML footer
$htmReport += "
	</body>
</html>"

# Export HTML to the same folder as CSV output.
$htmReport | Out-File (Join-Path (Split-Path $OutputCSV -Parent) "ADCriticalAccounts.html")

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
