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
        [Microsoft.ActiveDirectory.Management.ADObject[]] $ADObject,
        $RecursedObjects = (New-Object System.Collections.Generic.List[string])
    )
        
    # Loop through each ADObject
    foreach ($adoCurrent in $ADObject) {
        Write-Debug "Get-ADAccountRecursiveGroupMembers: Performing recursive enumeration of $($adoCurrent.DistinguishedName)"
        # Determine if a cache has already been created
        if (-not $global:hshADAccountCache) {
            Write-Debug "Get-ADAccountRecursiveGroupMembers: Creating AD Account cache"
            # Create a new cache
            $global:hshADAccountCache = @{}
        }

        # Add current object DN to recursed objects
        $RecursedObjects.Add($adoCurrent.DistinguishedName)

        # Create a list for results
        $lstGroupMembers = New-Object System.Collections.Generic.List[Microsoft.ActiveDirectory.Management.ADObject]

        Write-Debug "Get-ADAccountRecursiveGroupMembers: Determining if target principal is in cache"
        # Determine if the requested account is in the cache
        if ($global:hshADAccountCache.ContainsKey($adoCurrent.DistinguishedName)) {
            Write-Debug "Get-ADAccountRecursiveGroupMembers: Cache hit, returning results from cache."
            # The cache already has the resolved \ expanded group.  Return that instead of performing resolutions
            return $global:hshADAccountCache[$adoCurrent.DistinguishedName]
        }

        Write-Debug "Get-ADAccountRecursiveGroupMembers: Cache miss.  Enumerating membership."

        # Determine if this is a group
        if ($adoCurrent.objectClass -eq 'group') {
            Write-Debug "Get-ADAccountRecursiveGroupMembers: Target is a group.  Enumerating membership."
            
            # Get group membership and add each 
            $adoCurrent | 
                Get-ADGroupMember | 
                ?{-not $RecursedObjects.contains($_.DistinguishedName)} | 
                %{
					if ($_.objectClass -like 'Group') {
						Write-Debug "Get-ADAccountRecursiveGroupMembers: Member is a group, recursing."
						Get-ADAccountRecursiveGroupMembers -ADObject $_ -RecursedObjects $RecursedObjects | %{
							$lstGroupMembers.Add($_)
						}
					} else {
						Write-Debug "Get-ADAccountRecursiveGroupMembers: Adding member $($_.distinguishedName) to the list"
						# Add the current account to the list   
                        $lstGroupMembers.Add($_)
					}
				}
        }

        Write-Debug "Get-ADAccountRecursiveGroupMembers: Adding current member to the cache"
        # Add the result to the cache for future lookups
        $global:hshADAccountCache.add($adoCurrent.DistinguishedName, $lstGroupMembers)
        $lstGroupMembers.Add($adoCurrent)
    }

    Return $lstGroupMembers.GetEnumerator() | Sort-Object -Unique
}

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
