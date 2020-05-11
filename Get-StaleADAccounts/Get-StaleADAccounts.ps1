<#
    .DESCRIPTION
    Get-StaleADAccounts
    Developed by Michael Melone, Microsoft 
    mimelone@microsoft.com

    This script is designed to assist in the detection and modification of stale
    Active Directory user and computer accounts.  To use this script, load the
    entire script into memory first, then call the functions contained within.

    The Generate-StaleAccountReport function is designed to identify unused 
    Active Directory user and computer accounts based on the last time their
    password was updated and the last time they logged on interactively.  Please
    note that the dates referenced by the LastLogonTimestamp refer to the last
    interactive Windows logon and may not be updated by service accounts or 
    other non-interactive authentications.

    The output of the Generate-StaleAccountReport function can be returned to
    stdout (default) or to a CSV file for use with the Move-ApprovedADObjects
    function.  Before use, be sure to update the MoveObject value for each
    object to be moved to True to include it for movement.

    .NOTES
    Version | Date      | Alias    | Comments
    --------+-----------+----------+-----------------------------------------------
     1.0    | 17DEC2013 | mimelone | Initial script development.
#>

Function Generate-StaleAccountReport {
    param(
        [ValidateScript({$_ -gt 0})]
        [int] $MaxPWDays = 120,
        [ValidateScript({$_ -gt 0})]
        [int] $MaxLastLogonDays = 120,
        [string] $CSVPath,
        [ValidateSet("Users","Computers","UsersAndComputers")]
        [string] $ObjectClass = "users"
    )
    <#
        .SYNOPSIS
        The Generate-StaleAccountReport function generates an array of computers from
        Active Directory that appear to be stale.
        
        .DESCRIPTION
        The Generate-StaleAccountReport function generates an array of computers based
        on a query of Active Directory that tests for password age and last logon date.
        Output is provided either as an array of computer objects (default) or as a
        CSV report if the -CSVPath switch is specified.

        .PARAMETER MaxPwdDays
        This parameter specifies the maximum number of days that a password can remain
        unchanged before the script identifies the account as a stale account.

        .PARAMETER MaxLastLogonDays
        This parameter specifies the maxumum number of days since the last account 
        logon before the script identifies the account as a stale account.

        .PARAMETER ObjectClass
        The ObjectClass switch allows the user to specify whether to search for users
        or computers.  If no input is specified, users will be assumed.

        .PARAMETER CSVPath
        If this switch is specified, the output will be exported in CSV format to the
        path specified.
    #>

    #Convert inputs to negative versions
    $intMaxPWDDays = $MaxPWDays - ($MaxPWDays * 2)
    $intMaxLastLogonDays = $MaxLastLogonDays - ($MaxLastLogonDays * 2)

    #Get the current date
    $datNow = Get-Date

    #Determine the values for the LDAP filter
    Switch($ObjectClass) {
        "Users" {
            $strLDAPFilter = "(&(objectClass=user)(objectCategory=person)"
        }
        "Computers" {
            $strLDAPFilter = "(&(objectClass=computer)(objectCategory=computer)"
        }
        "UsersAndComputers" {
            $strLDAPFilter = "(&(|(objectClass=user)(objectClass=computer))"
        }
    }
    $strLDAPFilter = "$strLDAPFilter(|(pwdLastSet<=$($datNow.AddDays($intMaxPWDDays).ToFileTimeUtc()))(lastLogonTimestamp<=$($datNow.AddDays($intMaxLastLogonDays).ToFileTimeUTC()))(!(lastLogonTimestamp=*))))"

    $lstResults = New-Object 'System.Collections.Generic.List[PSObject]'
    
    Get-ADObject -LDAPFilter $strLDAPFilter -Properties distinguishedName, sAMAccountName, name, objectClass, pwdLastSet, operatingSystemVersion, lastLogonTimestamp, whenChanged, whenCreated | %{
        $psoResult = New-Object PSObject
        $psoResult | Add-Member -NotePropertyName distinguishedName -NotePropertyValue $_.distinguishedName
        $psoResult | Add-Member -NotePropertyName sAMAccountName -NotePropertyValue $_.sAMAccountName
        $psoResult | Add-Member -NotePropertyName name -NotePropertyValue $_.name
        $psoResult | Add-Member -NotePropertyName objectClass -NotePropertyValue $_.objectClass
        $psoresult | Add-Member -NotePropertyName pwdLastSet -NotePropertyValue ([datetime]::fromfiletimeutc($_.pwdLastSet))
        $psoResult | Add-Member -NotePropertyName lastLogonTimestamp -NotePropertyValue ([datetime]::fromfiletimeutc($_.lastLogonTimestamp))
        $psoResult | Add-Member -NotePropertyName whenChanged -NotePropertyValue $_.whenChanged
        $psoResult | Add-Member -NotePropertyName whenCreated -NotePropertyValue $_.whenCreated
        $psoResult | Add-Member -NotePropertyName Enabled -NotePropertyValue ($_.Enabled -eq $True)
        $psoResult | Add-Member -NotePropertyName MoveObject -NotePropertyValue $False

        #Get user or computer specific data
        if ($_.objectClass -eq "computer") {
            $psoResult | Add-Member -NotePropertyName operatingSystemVersion -NotePropertyValue $_.operatingSystemVersion
        } else {

        }
        
        $lstResults.add($psoResult)
    }

    if ($CSVPath) {
        $lstResults | Export-Csv $CSVPath -NoTypeInformation
    } else {
        return $lstResults
    }
}

Function Move-ApprovedADObjects {
    param(
        [parameter(mandatory=$True)]
        [ValidateScript({Test-Path -Path $_ -PathType Leaf})]
        [string] $CSVReport,
        [parameter(mandatory=$True)]
        [validateScript({Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$_)"})]
        [string] $TargetOU,
        [string] $MoveReport = "MoveReport-$(Get-Date -Format "ddMMMyyyy-HH-MM-ssa").csv"
    )
    
    <#
        .SYNOPSIS
        This function moves targets sourced from a CSV-formatted file to the OU specified
        by the -TargetOU switch based on a value of True in the MoveObject column.

        .DESCRIPTION
        This function is designed to work with the CSV-formatted output of the 
        Generate-StaleAccountReport function.  The report must be manually modified to
        enable accounts for movement by changing the value of the MoveObject column for
        the object to True.  Once input, the function will prompt the user for approval
        to move the number of objects identified by the script, then iterate through each
        object and move it to the OU specified by the -TargetOU switch.  If an error
        occurs while moving an object, a warning will be written to the screen upon
        script completion noting the number of errors that occurred.
        
        A report of all objects including their success or failure to move will be output
        at the destination specified by the MoveReport switch (by default, a file named
        MoveReport-<dateTime>.csv located in the operating directory of the script).

        .PARAMETER CSVReport
        The CSVReport parameter is used to specify the file contianing a CAV-formatted
        list of distinguishedNames of objects to move with a column named "MoveObject"
        used to determine whether the object will be moved.

        .PARAMETER TargetOU
        The TargetOU switch specifies the distingushedName of the destination OU for the
        target accounts.

        .PARAMETER MoveReport
        The MoveReport parameter specifies the file to use for outputting the
        report of objects moved during the operation as well as any failures encountered.
    #>

    try {
        #import CSV and filter objects where MoveObject is not set to True
        [array] $arrTargets = Import-Csv $CSVReport | ?{$_.MoveObject -eq $True}
    } catch {
        Write-Error "An error occurred while importing the CSV report from $CSVReport."
        return $Null
    }

    if ($arrTargets.count -gt 0) {
        $intResult = (New-Object -comobject wscript.shell).popup("About to move $($arrTargets.count) targets to the following OU: $TargetOU.  Do you want to continue?",0,"Moving AD Accounts",4)
    
        $arrResults = @()
        $intErrors = 0
        $a = 0

        if ($intResult -eq 6) {
            $a++
            Write-Progress -Activity "Moving $($arrTargets.count) computers" -PercentComplete (($a / $arrTargets.count) * 100)
            foreach ($objTarget in $arrTargets) {
                try {
                    Move-ADObject $objTarget.distinguishedName -TargetPath $TargetOU
                    $objTarget | Add-Member -NotePropertyName "Moved" -NotePropertyValue $True
                    $objTarget | Add-Member -NotePropertyName "Error" -NotePropertyValue $False
                } catch {
                    $intErrors++
                    $objTarget | Add-Member -NotePropertyName "Moved" -NotePropertyValue $False
                    $objTarget | Add-Member -NotePropertyName "Error" -NotePropertyValue $True
                }

                #update MoveObject to False to prevent accidental subsequent move attempts
                $objTarget.MoveObject = $False

                [array] $arrResults += $objTarget
            }
        }
        #Create MoveReport
        try {
            $arrResults | Export-CSV -Path $MoveReport -NoTypeInformation
        } catch {
            Write-Error "An error occurred while trying to create a move report at the following location: $MoveReport"
        }

        if ($intErrors -gt 0) {
            Write-Warning "Warning: $intErrors errors occurred during the execution of this script.  Please see the report located at $MoveReport for details."
        }

        Write-Host "$(($arrTargets.count - $intErrors)) targets moved."

    } else {
        Write-Host "No targets were selected for movement"
        return $Null
    }
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
