<#
    InfoEdge
    Microsoft DaRT Team

    .SYNOPSIS
    This script collects information about a Windows endpoint for use with Microsoft
    Detection and Response Team (DaRT) engagements.

    .DESCRIPTION
    This script collects registry values, WMI query results, local security policy
    information, event log entries, update status, scheduled tasks, and other information
    about the operating environment to facilitate Microsoft DaRT engagements.

    .PARAMETER Config
    This should be pointed to an XML configuration file containing the information to
    be gathered, defaults to .\InfoEdgeConfig.xml

    .PARAMETER OutputFile
    This is the file where the output will be written in JSON format, which will default
    to .\<MachineDomain>#<MachineName>#InfoEdge.json.

    .EXAMPLE
    powershell.exe .\InfoEdge.ps1

    .NOTES
    New-Object System.Collections.Generic.List[T] 
    has been replaced with
    $typList = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
    $typList = $typList.MakeGenericType(@(('T' -as "Type")))
    $var = [Activator]::CreateInstance($typList)
    for PowerShell v2 compatibility.

    Version | Alias    | Date    | Notes
    --------+----------+---------+--------------------------------------------------------
     1.0    | charrod  |         | Initial version of Agility
     2.0    | rkluit   | JAN18   | Adaptation & update, rename to InfoEdge
     3.0    | mimelone | 16JUN18 | Addition of local security policy, upgrade of local user
            |          |         |  and group enumeration, addition of MSERT, generalized
            |          |         |  registry key and WMI collection, output changed to JSON
#>

param(
    #[validatescript({[xml] (Get-Content $_)})]
    [string] $Config = '.\InfoEdgeConfig.xml',
    [string] $OutputFile = ".\$($env:USERDOMAIN)#$($env:COMPUTERNAME)#InfoEdge.json"
)

# Set the operating directory to the script's directory
Set-Location (Split-Path -Parent $MyInvocation.MyCommand.Path)

Add-Type -Language CSharp -TypeDefinition '
public class RegistryValueReport
{
    public string Value;
    public string ValueName;
    public bool ValueExists;
}
public class RegistryKeyReport
{
    public string hive;
    public string key;
    public bool KeyExists;
    public bool AllValues;
    public bool AllChildKeys;
    public RegistryValueReport[] Values;
}
public class WmiReport
{
    public string Query;
    public string Namespace;
    public System.Collections.Generic.Dictionary<string,string>[] Results;
}
public class GroupMember
{
    public string Domain;
    public string Name;
    public string SID;
    public string ObjectClass;
}
public class LocalGroup
{
    public string Domain;
    public string SID;
    public string Name;
    public GroupMember[] Members;
}
public class LocalUser
{
    public string Domain;
    public string Name;
    public string SID;
    public bool PasswordExpires;
    public string Description;
    public bool PasswordChangeable;
    public bool PasswordRequired;
    public bool Disabled;
}
public class Trustee
{
    public string Domain;
    public string Name;
    public string SID;
}
public class PrivilegeRight
{
    public string Name;
    public Trustee[] Trustees;
}
public class LocalSecurityPolicy
{
    public PrivilegeRight[] PrivilegeRights;
    public System.Collections.Generic.Dictionary<string,string> SystemAccess;
    public System.Collections.Generic.Dictionary<string,string> EventAudit;
    public System.Collections.Generic.Dictionary<string,string> RegistryValues;
}
public class TaskPrincipal
{
    public string Id;
    public string LogonType;
    public string PrincipalType;
    public string Domain;
    public string Name;
    public string SID;
    public string RunLevel;
    public string ProcessTokenSidType;
    public string DisplayName;
    public string RequiredPrivileges;
}
public class TaskReport
{
    public string Name;
    public string Path;
    public bool Enabled;
    public System.DateTime? LastRunTime;
    public System.DateTime? NextRunTime;
    public TaskPrincipal[] Principals;
    public string[] RequiredPrivileges;
    public string[] Commands;
    public string Xml;
}
public class MalwareInfection
{
    public string ThreatName;
    public string ContainerFile;
    public string File;
    public string ContainerSHA1;
    public string SHA1;
    public string SigSequence;
}
public class UpdateStatus
{
    public string ID;
    public string GUID;
    public bool IsInstalled;
    public string KBID;
    public string OtherIDs;
    public string References;
    public string RestartRequired;
    public string Severity;
    public string Title;
    public string Type;
}
public class PendingUpdate
{
    public string Title;
    public string Description;
    public bool IsBeta;
    public bool IsDownloaded;
    public bool IsHidden;
    public bool IsInstalled;
    public bool IsMandatory;
    public bool IsUninstallable;
    public int MaxDownloadSize;
    public string MsrcSeverity;
    public int Type;
    public bool RestartRequired;
    public string[] CveIDs;
}
public class InstalledUpdate
{
    public System.DateTime Date;
    public string Title;
    public string Description;
    public string ClientApplicationID;
    public int Operation;
    public int ResultCode;
}
public class UpdateReport
{
    public bool PendingSuccess;
    public InstalledUpdate[] InstalledUpdates;
    public PendingUpdate[] PendingUpdates;
}
public class EventLogEntryReport
{
    public string LogName;
    public int ID;
    public string ProviderName;
    public string ProviderID;
    public System.DateTime? TimeCreated;
    public string LevelDisplayName;
    public string TaskDisplayName;
    public string Message;
}
public class EndpointReport
{
    public string ComputerDNSName;
    public string DnsHostName;
    public string ComputerNetBiosName;
    public string Domain;
    public int DomainRole;
    public System.DateTime? ReportDate;
    public int UTCOffsetInMinutes;
    public int ReportDurationInSeconds;
    public RegistryKeyReport[] RegistryKeyReports;
    public WmiReport[] WmiReports;
    public LocalGroup[] LocalGroups;
    public LocalUser[] LocalUsers;
    public LocalSecurityPolicy LocalSecurityPolicy;
    public string[] WinRMTrustedHosts;
    public TaskReport[] ScheduledTasks;
    public MalwareInfection[] MalwareInfections;
    public UpdateReport UpdateReport;
    public EventLogEntryReport[] Events;
}'

Function Get-RegistryKeyReport {
    <#
        Get-RegistryKeyReport

        .SYNOPSIS
        This function collects requested registry keys and values
        from an endpoint.

        .PARAMETER Hive
        The registry hive to conenct to (HKLM or HKU currently supported)

        .PARAMETER Key
        The specific registry key to collect

        .PARAMETER Value
        An optional specific value to be collected

        .PARAMETER GetAllValues
        Boolean parameter which specifies that all values for any keys in scope
        should be collected

        .PARAMETER GetChildKeys
        Boolean parameter which collects all direct children of the requested key.
        Value specifications from above are carried to child keys.

        .NOTES
        Requires the following types
        public class RegistryValueReport
        {
            public string Value;
            public string ValueName;
            public bool ValueExists;
        }
        public class RegistryKeyReport
        {
            public string hive;
            public string key;
            public bool KeyExists;
            public bool AllValues;
            public bool AllChildKeys;
            public RegistryValueReport[] Values;
        }
    #>
    param(
            [parameter(mandatory=$True)]
            [ValidateSet('HKLM','HKU')]
            [string] $Hive,
            [parameter(mandatory=$True)]
            [string] $Key,
            [string] $Value,
            [bool] $GetAllValues = $false,
            [bool] $GetChildKeys = $false
    )

    Function Get-RegistryValueReport {
        <#
            Get-RegistryValueReport

            .SYNOPSIS
            This function collects requested registry values from 
            from a specific key on an endpoint.

            .PARAMETER Hive
            The registry hive to conenct to (HKLM or HKU currently supported)

            .PARAMETER Key
            The specific registry key to collect

            .PARAMETER Value
            An optional specific value to be collected

            .PARAMETER GetAllValues
            Boolean parameter which specifies that all values for any keys in scope
            should be collected

            .NOTES
            Requires the following type
            
            public class RegistryValueReport
            {
                public string Value;
                public string ValueName;
                public bool ValueExists;
            }
        #>
        param(
            [parameter(mandatory=$True)]
            [ValidateSet('HKLM','HKU')]
            [string] $Hive,
            [parameter(mandatory=$True)]
            [string] $Key,
            [string] $Value,
            [bool] $GetAllValues = $false
        )
        
        Write-Debug "Get-RegistryValueReport: Entering Get-RegistryValueReport Hive: $Hive Key: $Key Value: $Value GetAllValues: $GetAllValues"
        # Create a list for the value(s)
        $typList = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
        $typList = $typList.MakeGenericType(@(('RegistryValueReport' -as "Type")))
        $lstValues = [Activator]::CreateInstance($typList)
        
        # Set up the registry path string
        $strRegPath = "$Hive`:\$Key"
        
        if ($GetAllValues) {
            # Try to get the properties
            $arrProperties = (Get-Item $strRegPath).GetValueNames()

            # Loop through each value and create a result
            foreach ($strProperty in $arrProperties) {
                $strValue = (Get-ItemProperty -Path $strRegPath -Name $strProperty)."$strProperty"

                # Create value for result, add properties, add to list
                $rvrValue = New-Object RegistryValueReport
                $rvrValue.ValueExists = $True
                $rvrValue.ValueName = $strProperty
                $rvrValue.Value = $strValue
                $lstValues.Add($rvrValue)
            }

            return $lstValues
        } elseif (-not [string]::IsNullOrEmpty($Value)) {
            # Create a new value
            $rvrValue = New-Object RegistryValueReport

            # Try to get the property
            try {
                $strValue = (Get-ItemProperty -Path $strRegPath -Name $Value)."$Value"
                $rvrValue.Value = $strValue
                $boolValueExists = $True
            } catch {
                $boolValueExists = $false
            }

            # Update the result object and add to key
            $rvrValue.ValueExists = $boolValueExists
            $rvrValue.ValueName = $Value

            $lstValues.Add($rvrValue)
        }

        Write-Debug "Get-RegistryValueReport: Returning $($lstValues.count) reports"
        return $lstValues 
    }

    Write-Debug "Get-RegistryKeyReport: Entering Get-RegistryValueReport Hive: $Hive Key: $Key Value: $Value GetAllValues: $GetAllValues GetChildKeys: $GetChildKeys"
    # Create a new list for output
    $typList = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
    $typList = $typList.MakeGenericType(@(('RegistryKeyReport' -as "Type")))
    $lstResults = [Activator]::CreateInstance($typList)

    # Determine if HKU has been mapped, if not - map it
    try {
        Get-PSDrive -Name 'hku' -ErrorAction Stop | Out-Null
    } catch {
        # Map HKEY_Users as HKU
        New-PSDrive HKU Registry HKEY_USERS | Out-Null
    }

    # Create a new report object
    $rkrResult = New-Object RegistryKeyReport
    $rkrResult.Hive = $Hive
    $rkrResult.Key = $Key
    $rkrResult.AllValues = $GetAllValues
    $rkrResult.AllChildKeys = $GetChildKeys

    # Join hive and key, test path
    $strRegPath = "$Hive`:\$Key"

    # Determine if the value exists
    $boolExists = Test-Path $strRegPath
    $rkrResult.KeyExists = $boolExists

    if ($boolExists) {
        
        # Call Get-RegistryValueReport to get values
        Write-Debug "Get-RegistryKeyReport: Calling Get-RegistryValueReport -Hive $Hive -Key $Key -Value $Value -GetAllValues $GetAllValues"
        $arrValues = Get-RegistryValueReport -Hive $Hive -Key $Key -Value $Value -GetAllValues $GetAllValues

        # Create a new list for values, add each value to the list
        $typList = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
        $typList = $typList.MakeGenericType(@(('RegistryValueReport' -as "Type")))
        $lstValues = [Activator]::CreateInstance($typList)
        
        foreach ($regValue in $arrValues) {
            $lstValues.Add(([RegistryValueReport] $regValue))
        }

        # Set the registrykeyreport Values attribute to the list
        $rkrResult.Values = $lstValues

        # Add the result to the list
        $lstResults.Add($rkrResult)

        # Determine if child keys are requested
        if ($GetChildKeys) {
            $arrChildKeys = (Get-Item $strRegPath).GetSubKeyNames()
            foreach ($strKey in $arrChildKeys) {
                $strNewKey = Join-Path $strRegPath $strKey
                $strNewKey = $strNewKey.Substring(($strNewKey.IndexOf(':') + 2), $strNewKey.Length - ($strNewKey.IndexOf(':') + 2))
                if ($GetAllValues) {
                    Write-Debug "Get-RegistryKeyReport: Calling Get-RegistryKeyReport -Hive $Hive -Key $strNewKey -GetAllValues"
                    $rkrResult = Get-RegistryKeyReport -Hive $Hive -Key $strNewKey -GetAllValues
                } else {
                    Write-Debug "Get-RegistryKeyReport: Calling Get-RegistryKeyReport -Hive $Hive -Key $strNewKey"
                    $rkrResult = Get-RegistryKeyReport -Hive $Hive -Key $strNewKey
                }
                Write-Debug "Get-RegistryKeyReport: Received the following result from Get-RegistryValueReport"

                # Add each result to the results
                $lstResults.Add(([RegistryKeyReport] $rkrResult))
            }
        }
    }

    return $lstResults
}

Function Get-WmiReport {
    <#
        Get-WmiReport

        .SYNOPSIS
        This function will run a WMI query on an endpoint and return
        a report of its attributes.

        .PARAMETER Query
        The WMI query to be run

        .PARAMETER Namespace
        Optional - used to denote the namespace in which to run the 
        query.

        .NOTES
        Requires the following types
        public class WmiReport
        {
            public string Query;
            public string Namespace;
            public System.Collections.HashTable[] Results;
        }
    #>
    param(
        [parameter(mandatory=$True)]
        [string] $Query,
        [string] $Namespace
    )

    Write-Debug "Get-WmiReport: Entering Get-WmiReport.  Query: $Query Namespace: $Namespace InvokeMethod: $InvokeMethod"
    # Create a new WmiReport
    $wmrReport = New-Object WmiReport
    $wmrReport.Query = $Query
    $wmrReport.Namespace = $Namespace

    # Create a list for results
    $lstResults =  [activator]::CreateInstance(([System.Collections.Generic.List[System.Collections.Generic.Dictionary[string,string]]] -as 'Type'))

    # Run the specified query
    if ([string]::IsNullOrEmpty($Namespace)) {
        $wmiResults = Get-WmiObject -Query $Query
    } else {
        $wmiResults = Get-WmiObject -Namespace $Namespace -Query $Query
    }

    # Iterate through results if we received any
    foreach ($wmiResult in $wmiResults) {
        # Get a report for the result
        $hshResult = New-Object 'System.Collections.Generic.Dictionary[string,string]'

        # Get properties for the returned object
        $arrProperties = ($wmiResult | Get-Member -MemberType Property).name
        foreach ($strProperty in $arrProperties) {
            if (-not ([string]::IsNullOrEmpty($wmiResult."$strProperty"))) {
                $hshResult.Add($strProperty, $wmiResult."$strProperty")
            }
        }
        $lstResults.Add($hshresult)
    }
    
    # Add the results (if any) to the report
    $wmrReport.Results = $lstResults

    Write-Debug "Get-WmiReport: Exiting Get-WmiReport.  Returning $wmrReport"
    
    # Return the report
    return $wmrReport
}

Function Get-LocalGroups
 {
     <#
        Get-LocalGroups

        .SYNOPSIS
        This function enumerates all local groups and their immediate members

        .NOTES
        This function depends on the following type
        public class GroupMember
        {
            public string Domain;
            public string Name;
            public string SID;
            public string ObjectClass;
        }
        public class LocalGroup
        {
            public string Domain;
            public string SID;
            public string Name;
            public GroupMember[] Members;
        }
     #>
    # Create a new LocalGroup list
    $typList = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
    $typList = $typList.MakeGenericType(@(('LocalGroup' -as "Type")))
    $lstLocalGroups = [Activator]::CreateInstance($typList)
    
    # Determine if the machine is a Domain Controller
    $wmiDomainRole = (Get-WmiObject 'Win32_ComputerSystem' -Property DomainRole).DomainRole

    # If the machine is not a domain controller continue
    # Domain controllers are skipped to avoid redundancy in assessment
    if ($wmiDomainRole -le 3) {
        # Query all local groups
        $arrLocalGroups = Get-WmiObject -Query 'SELECT * FROM Win32_Group WHERE LocalAccount = True' 
        foreach ($wmiGroup in $arrLocalGroups) {
            # Create a new LocalGroup object
            $lcgCurrent = New-Object LocalGroup
            
            $lcgCurrent.name = $wmiGroup.Name
            $lcgCurrent.SID = $wmiGroup.SID
            $lcgCurrent.Domain = $wmiGroup.Domain

            $typList = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
            $typList = $typList.MakeGenericType(@(('GroupMember' -as "Type")))
            $lstMembers = [Activator]::CreateInstance($typList)
            
            # Get all group members
            $arrGroupMembers = (Get-WmiObject -Query "SELECT PartComponent FROM Win32_GroupUser WHERE GroupComponent=`"Win32_Group.Domain='$($wmiGroup.Domain)',Name='$($wmiGroup.name)'`"").PartComponent
            
            # Iterate through each group member
            foreach ($strGroupMember in $arrGroupMembers) {
                # Ensure we received a result
                if (-not [string]::IsNullOrEmpty($strGroupMember)) {
                    # Create a new GroupMember object
                    $mbrCurrent = New-Object GroupMember

                    # Parse the domain and name from the ManagementPath in the event we are unable to get the object using WMI (i.e. domain not available)
                    $mbrCurrent.Name = $strGroupMember.Substring($strGroupMember.IndexOf(',') + 1).Replace('Name=', '').Replace("`"", '')
                    $mbrCurrent.Domain = $strGroupMember.Split('.')[1].Split(',')[0].Replace('Domain=', '').Replace("`"", '')
                    
                    try {
                        # Try to use domain\user format for the NTAccount
                        $ntaMember = New-Object System.Security.Principal.NTAccount -ArgumentList "$($mbrCurrent.Domain)\$($mbrCurrent.Name)"
                        $mbrCurrent.Sid = $ntaMember.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    } catch {
                        # Try translating just the sAMAccountName
                        try {
                            $ntaMember = New-Object System.Security.Principal.NTAccount -ArgumentList "$($mbrCurrent.Name)"
                            $mbrCurrent.Sid = $ntaMember.Translate([System.Security.Principal.SecurityIdentifier]).Value
                        } catch {
                            Write-Warning "Unable to translate the following account: Name: $($mbrCurrent.Domain)\$($mbrCurrent.Name)"
                        }
                    }

                    
                    try {
                        # Cast the string to a ManagementPath and ManagementObject to get properties
                        $mgoGroupMember = New-Object System.Management.ManagementObject
                        $mgpGroupMember = [System.Management.ManagementPath] $strGroupMember
                        $mgoGroupMember.Path = $mgpGroupMember

                        # Try to get the object to get sid and class
                        $mgoGroupMember.Get()

                        # Get Sid and class from ManagementObject
                        $mbrCurrent.ObjectClass = $mgoGroupMember.__CLASS
                    } catch {
                        Write-Warning "Unable to get ManagementObject for $strGroupMember.  Domain may be unavailable."
                    }

                    # Add the result to the list
                    $lstMembers.add($mbrCurrent)
                }
            }
            
            # Add the trustees ship to the LocalGroup
            $lcgCurrent.Members = $lstMembers

            # Add the LocalGroup to the list
            $lstLocalGroups.add($lcgCurrent)
        }
    }       

    # Return the list
    return $lstLocalGroups
}

Function Get-LocalUsers {
    <#
        Get-LocalUsers

        .SYNOPSIS
        This function enumerates all local users and attributes of interest

        .NOTES
        This function requires the following type
        public class LocalUser
        {
            public string Domain;
            public string Name;
            public string SID;
            public bool PasswordExpires;
            public bool Description;
            public bool PasswordChangeable;
            public bool PasswordRequired;
            public bool Disabled;
        }

    #>
    # Create a new list to hold results
    $typList = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
    $typList = $typList.MakeGenericType(@(('LocalUser' -as "Type")))
    $lstLocalUsers = [Activator]::CreateInstance($typList)

    # Determine if the machine is a Domain Controller
    $wmiDomainRole = (Get-WmiObject 'Win32_ComputerSystem' -Property DomainRole).DomainRole

    # If the machine is not a domain controller continue
    # Domain controllers are skipped to avoid redundancy in assessment
    if ($wmiDomainRole -le 3) {
        # Get local users
        $arrLocalUsers = Get-WmiObject -Query 'SELECT * FROM Win32_UserAccount WHERE LocalAccount = True' 

        # Iterate through each user
        foreach ($wmiLocalUser in $arrLocalUsers) {
            # Build and populate LocalUser
            $lcuUser = New-Object LocalUser

            $lcuUser.Domain = $wmiLocalUser.Domain
            $lcuUser.Name = $wmiLocalUser.Name
            $lcuUser.Sid = $wmiLocalUser.Sid
            $lcuUser.PasswordExpires = $wmiLocalUser.PasswordExpires
            $lcuUser.Description = $wmiLocalUser.Description
            $lcuUser.PasswordChangeable = $wmiLocalUser.PasswordChangeable
            $lcuUser.PasswordRequired = $wmiLocalUser.PasswordRequired
            $lcuUser.Disabled = $wmiLocalUser.Disabled

            # Add to list
            $lstLocalUsers.add($lcuUser)
        }
    }

    # Return list
    return $lstLocalUsers
}

#Gets a new empty temporary file
function Get-TemporaryFile {
    <#
        Get-TemporaryFile

        .SYNOPSIS
        This function will create a new temporary file and return its path
    #>
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

        #Determine if the file already exists
        if (-not (test-path "$strTempFolder\$strRandomFileName")) {
            #Try to create the file
            try {
                $objFile = New-Item -Path (Join-Path $strTempFolder $strRandomFileName) -ItemType File
            } catch {
                $objFile = $Null
            }
        }

        $a++
    }

    return $objFile
}

Function Get-LocalSecurityPolicy {
    <#
        Get-LocalSecurityPolicy

        .SYNOPSIS
        This function utilizes secpol to enumerate the local security policy

        .NOTES
        This function is dependent on the Get-TemporaryFileFunction and the 
        following types
        public class Trustee
        {
            public string Domain;
            public string Name;
            public string SID;
        }
        public class PrivilegeRight
        {
            public string Name;
            public Trustee[] Trustees;
        }
        public class LocalSecurityPolicy
        {
            public PrivilegeRight[] PrivilegeRights;
            public System.Collections.Hashtable SystemAccess;
            public System.Collections.Hashtable EventAudit;
            public System.Collections.Hashtable RegistryValues;
        }
    #>
    param(
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string] $SeceditPath = "$($env:windir)\system32\secedit.exe"
    )

    #Function to read INI files developed by Michael Murgolo
    #http://blogs.technet.com/b/deploymentguys/archive/2010/07/15/reading-and-modifying-ini-files-with-scripts.aspx
    function Convert-IniFile
    { 
        param(
            [ValidateScript({Test-Path $_ -PathType Leaf})]
            [string]  $File
        )
        <#
            Convert-IniFile    

            .SYNOPSIS
            This function will convert an .ini file into nested hashtables

            .PARAMETER file
            The file to be converted
        #>
        $REGEX_INI_COMMENT_STRING = ";" 
        $REGEX_INI_SECTION_HEADER = "^\s*(?!$($REGEX_INI_COMMENT_STRING))\s*\[\s*(.*[^\s*])\s*]\s*$" 
        $REGEX_INI_KEY_VALUE_LINE = "^\s*(?!$($REGEX_INI_COMMENT_STRING))\s*([^=]*)\s*=\s*(.*)\s*$" 

        # Create a new dictionary of strings and dictionaries to hold results
        $dicResults = [activator]::CreateInstance(([System.Collections.Generic.Dictionary[string,System.Collections.Generic.Dictionary[string,string]]] -as 'Type'))

        # Parse the file using RegEx
        switch -regex -file $File { 
            # Detect a section header
            "$($REGEX_INI_SECTION_HEADER)" { 
                # Check if there is a current NameValueCollection
                if ($dicCurrent) {
                    # Add the previous section to the result dictionary
                    $dicResults.add($strSection, $dicCurrent)
                }

                # Set the current section header
                $strSection = $matches[1]

                # Create a new dictionary for the current section
                $dicCurrent = New-Object 'System.Collections.Generic.Dictionary[string,string]'
            } 

            # Detect values within the section
            "$($REGEX_INI_KEY_VALUE_LINE)" {
                # Ensure we have a section and key
                if ($matches[1] -ne $null -and $strSection -ne $null)
                {
                    # Add key and value to the dictionary object
                    $strKey = $matches[1].trim()
                    $strValue = $matches[2].trim()
                    $dicCurrent.Add($strKey, $strValue)
                }
            } 
        } 

        # Add the last NameValueCollection if present
        if ($dicCurrent) {
            $dicResults.add($strSection, $dicCurrent)
        }

        # Return result
        return $dicResults 
    }

    # Create a new Local SecurityPolicy for the results
    $lspCurrent = New-Object LocalSecurityPolicy

    #Get a new temporary file
    $filTemp = Get-TemporaryFile

    #Run secedit and export the user rights assignments to the temporary file
    try {
        Start-Process -FilePath $SeceditPath -ArgumentList "/export /cfg $filTemp" -Wait -WindowStyle Hidden
    } catch {
        Write-Error "An error occurrend when trying to launch secedit.exe from $SeceditPath"
    }

    #Convert INI to PowerShell objects
    $arrSecPol = Convert-IniFile -file $filTemp.FullName

    #Delete the temporary file
    Remove-Item $filTemp -Force

    ### Get user rights information
    #Create a new list to hold user rights
    $typList = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
    $typList = $typList.MakeGenericType(@(('PrivilegeRight' -as "Type")))
    $lstUserRights = [Activator]::CreateInstance($typList)

    $dicPR = $arrSecPol['Privilege Rights']
    foreach ($strRight in $dicPR.keys) {
        $usrRight = New-Object PrivilegeRight
        $usrRight.Name = $strRight


        #Iterate through each SID, translate to a user, and add to array
        $typList = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
        $typList = $typList.MakeGenericType(@(('Trustee' -as "Type")))
        $lstTrustees = [Activator]::CreateInstance($typList)

        Foreach ($strTrustee in $dicPR[$strRight].split(",")) {
            $truCurrent = New-Object Trustee

            # Determine what format we received
            switch -Wildcard ($strTrustee) {
                '`*S-1-*' {
                    # SID Processing
                    $truCurrent.Sid = $strTrustee.TrimStart('*')
                    try {
                        # Try to translate the SID to an NTAccount
                        $objSID = New-Object System.Security.Principal.SecurityIdentifier $truCurrent.Sid
                        $ntaCurrent = $objSID.Translate([System.Security.Principal.NTAccount])
                        $strTranslated = $ntaCurrent.ToString()

                        # Determine if a domain is specified
                        if ($strTranslated -like '*\*'){
                            $truCurrent.Domain = $strTranslated.split('\')[0]
                            $truCurrent.Name = $strTranslated.split('\')[1]
                        } else {
                            $truCurrent.Domain = $env:COMPUTERNAME
                            $truCurrent.Name = $strTranslated
                        }
                    } catch {
                        Write-Warning "Failed to translate SID $($truCurrent.Sid)"
                    }
                }
                default {
                    # Process NTAccount
                    $truCurrent.Domain = $strTrustee.split('\')[0]
                    $truCurrent.Name = $strTrustee.split('\')[1]

                    # Try to translate into SID
                    try {
                        $ntaCurrent = New-Object System.Security.Principal.NTAccount -ArgumentList $strTrustee
                        $sidCurrent = $ntaCurrent.Translate([System.Security.Principal.SecurityIdentifier])
                        $truCurrent.Sid = $sidCurrent.ToString()
                    } catch {
                        Write-Warning "Unable to translate account to SID: $strTrustee"
                    }
                }
            }
            $lstTrustees.add($truCurrent)
        }
        $usrRight.Trustees = $lstTrustees
        $lstUserRights.add($usrRight)
    }
    $lspCurrent.PrivilegeRights = $lstUserRights

    # Populate SystemAccess
    $lspCurrent.SystemAccess = [System.Collections.Generic.Dictionary[string,string]] $arrSecPol['System Access']

    # Populate EventAudit
    $lspCurrent.EventAudit = [System.Collections.Generic.Dictionary[string,string]] $arrSecPol['Event Audit']

    # Populate RegistryValues
    $lspCurrent.RegistryValues = [System.Collections.Generic.Dictionary[string,string]] $arrSecPol['Registry Values']

    # Return result
    return $lspCurrent
}

function Get-ScheduledTasks {
    <#
        Get-ScheduledTasks

        .SYNOPSIS
        This function will generate a report on all registered scheduled tasks
        on the system.

        .PARAMETER Folder
        The scheduled task folder to enumerate.  Enumeration is recursive.

        .PARAMETER ScheduleService
        This parameter is internal and used to pass the scheduled task service
        for recursion.

        .NOTES
        Task Scheduler XML Schema for reference: https://docs.microsoft.com/en-us/windows/desktop/TaskSchd/task-scheduler-schema
        This function depends on the following types
        public class Trustee
        {
            public string Domain;
            public string Name;
            public string SID;
        }
        public class TaskReport
        {
            public string Name;
            public string Path;
            public bool Enabled;
            public System.DateTime LastRunTime;
            public System.DateTime NextRunTime;
            public Trustee Author;
            public string[] RequiredPrivileges;
            public string[] Commands;
            public string Xml;
        }
    #>
    param(
        [string] $Folder = '\',
        $ScheduleService
    )

    # Determine if ScheduleService is null
    If (-not $ScheduleService) {
        $ScheduleService = New-Object -ComObject "Schedule.Service"
    }
    # Determine if ScheduleService is connected.  If not, try to connect
    if (-not $ScheduleService.Connected) {
        $ScheduleService.Connect()
    }

    # Create a list for results
    $typList = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
    $typList = $typList.MakeGenericType(@(('TaskReport' -as "Type")))
    $lstScheduledTasks = [Activator]::CreateInstance($typList)

    # Try to get tasks for the specified folder
    $arrTasks = @($ScheduleService.GetFolder($Folder).GetTasks(0))

    # Iterate through each task and build a report
    foreach ($objTask in $arrTasks) {
        # Begin populating TaskReport
        $tkrCurrent = New-Object TaskReport
        $tkrCurrent.Name = $objTask.Name
        $tkrCurrent.Path = $objTask.Path
        $tkrCurrent.Enabled = $objTask.Enabled
        $tkrCurrent.LastRunTime = $objTask.LastRunTime
        $tkrCurrent.NextRunTime = $objTask.NextRunTime

        # Parse the task XML to obtain author and command information
        $xmlTask = [xml] $objTask.xml

        # Get required privileges
        $tkrCurrent.RequiredPrivileges = $xmlTask.task.RequiredPrivileges.Privilege
        #$tkrCurrent.xml = $objTask.xml
        
        # Create a list for actions
        $lstActions = [activator]::CreateInstance(([System.Collections.Generic.List[string]] -as 'Type'))
        
        # Create a string array for commands
        $arrCommands = [activator]::CreateInstance(([System.Collections.Generic.List[string]] -as 'Type'))

        # Iterate through each command
        foreach ($xmeCommand in $xmlTask.task.actions.exec) {
            $strCommand = ""
            if ($xmeCommand.Command) {
                $strCommand = "Command: $($xmeCommand.Command)"
            }
            if ($xmeCommand.Arguments) {
                $strCommand = "$strCommand Arguments: $($xmeCommand.Arguments)"
            }
            if ($xmeCommand.WorkingDirectory) {
                $strCommand = "$strCommand Working Directory: $($xmeCommand.WorkingDirectory)"
            }
            $arrCommands.add($strCommand)
        }
        $tkrCurrent.Commands = $arrCommands

        # Get principal information
        # Create a new list for TaskPrincipals
        $typList = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
        $typList = $typList.MakeGenericType(@(('TaskPrincipal' -as "Type")))
        $lstTaskPrincipals = [Activator]::CreateInstance($typList)


        foreach ($xmePrincipal in $xmlTask.task.Principals.Principal) {
            $tplCurrent = New-Object TaskPrincipal
            
            # Set the ID and LogonType
            $tplCurrent.Id = $xmePrincipal.id
            $tplCurrent.LogonType = $xmePrincipal.LogonType
            $tplCurrent.RunLevel = $xmePrincipal.RunLevel
            $tplCurrent.ProcessTokenSidType = $xmePrincipal.ProcessTokenSidType
            if (-not ([string]::IsNullOrEmpty($xmePrincipal.DisplayName))) {
                $tplCurrent.DisplayName = [string]::Join(',', $xmePrincipal.DisplayName) #Per schema may be multivariate
            }
            if (-not ([string]::IsNullOrEmpty($xmePrincipal.RequiredPrivileges))) {
                $tplCurrent.RequiredPrivileges = [string]::Join(',', $xmePrincipal.RequiredPrivileges)
            }

            # Determine if the principal is a user or group
            if (-not ([string]::IsNullOrEmpty($xmePrincipal.GroupId))) {
                $strId = $xmePrincipal.GroupId
                $tplCurrent.PrincipalType = 'Group'
            } else {
                $strId = $xmePrincipal.UserId
                $tplCurrent.PrincipalType = 'User'
            }

            # Determine what format we received
            switch -Wildcard ($strID) {
                'S-1-*' {
                    # SID Processing
                    $tplCurrent.Sid = $strID
                    #try {
                        # Try to translate the SID to an NTAccount
                        $objSID = New-Object System.Security.Principal.SecurityIdentifier $strID
                        $ntaCurrent = $objSID.Translate([System.Security.Principal.NTAccount])
                        $strTranslated = $ntaCurrent.ToString()

                        # Determine if a domain is specified
                        if ($strTranslated -like '*\*'){
                            $tplCurrent.Domain = $strTranslated.split('\')[0]
                            $tplCurrent.Name = $strTranslated.split('\')[1]
                        } else {
                            $tplCurrent.Domain = $env:COMPUTERNAME
                            $tplCurrent.Name = $strTranslated
                        }
                    #} catch {
                    #    Write-Warning "Failed to translate SID $($truCurrent.Sid)"
                    #}
                }
                'AllUsers' {
                    # This appears to be a special case for the task scheduler, not a real principal
                    $tplCurrent.Domain = $env:COMPUTERNAME
                    $tplCurrent.Name = 'AllUsers'
                }
                default {
                    # Process NTAccount
                    if ($strId -like '*\*') {
                        $tplCurrent.Domain = $strID.split('\')[0]
                        $tplCurrent.Name = $strID.split('\')[1]
                    } else {
                        $tplCurrent.Domain = $env:COMPUTERNAME
                        $tplCurrent.Name = $strId
                    }

                    # Try to translate into SID
                    try {
                        $ntaCurrent = New-Object System.Security.Principal.NTAccount -ArgumentList $strID
                        $sidCurrent = $ntaCurrent.Translate([System.Security.Principal.SecurityIdentifier])
                        $tplCurrent.Sid = $sidCurrent.ToString()
                    } catch {
                        Write-Warning "Unable to translate account to SID."
                        Write-Warning $strID
                    }
                }
            }

            # Add the principal to the list
            $lstTaskPrincipals.add($tplCurrent)
        }

        # Set the author
        $tkrCurrent.Principals = $lstTaskPrincipals

        # Add the task to the list
        $lstScheduledTasks.add($tkrCurrent)
    }

    # Perform tail recursion if necessary
    $ScheduleService.GetFolder($Folder).GetFolders(0) | %{
        # Get scheduled tasks from the child folder
        Get-ScheduledTasks -ScheduleService $ScheduleService -Folder $_.path | %{
            # Add tasks from recursion
            $lstScheduledTasks.add([TaskReport] $_)
        }
    }

    # Return result
    return $lstScheduledTasks
}

Function Invoke-MSERTScan {
    <#
        Invoke-MSERTScan

        .SYNOPSIS
        This function will start a scan using the Microsoft Safety Scanner and
        return any detections made during the scan.

        .PARAMETER MSERTPath
        The path to MSERT.exe.  Defaults to .\msert.exe

        .PARAMETER RemoveMalware
        Boolean value which determines if any detected malware should be cleaned.

        .NOTES
        This function depends on the following type
        public class MalwareInfection
        {
            public string ThreatName;
            public string ContainerFile;
            public string File;
            public string ContainerSHA1;
            public string SHA1;
            public string SigSequence;
        }
    #>
    param(
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string] $MSERTPath = '.\msert.exe',
        [bool] $RemoveMalware = $False
    )

    $strMSERTPath = (Join-Path $env:windir "Debug\msert.log")

    # Delete any current MSERT.log
    if (Test-Path $strMSERTPath) {
        Remove-Item -Path $strMSERTPath -Force | Out-Null
    }

    # Run MSERT
    Write-Debug "Launching MSERT"
    if ($RemoveMalware) {
        Start-Process $MSERTPath -argumentlist "/q" -Wait -WindowStyle Hidden
    } else {
        Start-Process $MSERTPath -argumentlist "/n /q" -Wait -WindowStyle Hidden
    }

    $boolRunning = $True
    While ($boolRunning) {
        Start-Sleep -Seconds 15
        try {
            Get-Process -Name msert.exe -ErrorAction Stop
            $boolRunning = $true
        } catch {
            $boolRunning = $False
        }
    }

    # Parse MSERT Output
    $typList = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
    $typList = $typList.MakeGenericType(@(('MalwareInfection' -as "Type")))
    $lstDetections = [Activator]::CreateInstance($typList)

    $malInfection = New-Object MalwareInfection

    Switch -File $strMSERTPath -Wildcard {
        "Threat detected:*" {
            if ($malInfection.SigSequence) {    # This will only be defined if this is not the first threat.  Add to list.
                $lstDetections.Add($malInfection)
                $malInfection = New-Object MalwareInfection              
            }
            $malInfection.ThreatName = $_.substring(17,$_.length - 17).Trim()
        }
        "    containerfile:*" {
            $malInfection.ContainerFile = $_.substring(20,$_.length - 20).Trim()
        }
        "    file:*" {
            $malInfection.File = $_.substring(11,$_.length - 11).Trim()
        }
        "        SHA1:*" {
            if ($malInfection.ContainerFile -and -not $malInfection.ContainerSHA1) {  #If this is set, this should be the SHA1 of the containing file
                $malInfection.ContainerSHA1 = $_.substring(16,40)
            } else {
                $malInfection.SHA1 = $_.substring(16,40)
            }
        }
        "        SigSeq: *" {
            $malInfection.SigSequence = $_.substring(16,18)
        }
    }

    # Add the last threat if it exists
    if (-not [string]::IsNullOrEmpty($malInfection.ThreatName)) {
        $lstDetections.Add( $malInfection )
    }

    Return $lstDetections
}

Function Invoke-MBSAAssessment {
    <#
        Invoke-MBSAAssessment

        .SYNOPSIS
        This function will perform an MBSA offline patch assessment of the endpoint.

        .PARAMETER MBSAPath
        The path to mbsacli.exe, defaults to .\mbsacli.exe

        .PARAMETER WSUSCabPath
        The path to wsusscn2.cab, defaults to .\wsusscn2.cab
    #>
    param(
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string] $MBSAPath = '.\mbsacli.exe',
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string] $WSUSCabPath = '.\wsusscn2.cab'
    )

    Start-Process -FilePath $MBSAPath -ArgumentList "/catalog ""$WSUSCabPath"" /wi /xmlout" -RedirectStandardOutput (Join-Path $WorkingPath "$($strMachineName)_mbsa.xml") -Wait -NoNewWindow # WindowStyle Hidden and -RedirectStandardOutput cannot be used together on older versions of PowerShell

    # Parse output to gather update information
    $xmlUpdates = [xml] (Get-Content -Path (Join-Path $WorkingPath "$($strMachineName)_mbsa.xml"))
    
    # Enumerate through each check (removing nulls)
    if ($xmlUpdates.XMLOut.Check.Detail.UpdateData) {
        $typList = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
        $typList = $typList.MakeGenericType(@(('UpdateStatus' -as "Type")))
        $lstUpdates = [Activator]::CreateInstance($typList)

        ForEach ($objUpdate in $xmlUpdates.XMLOut.Check.Detail.UpdateData) {
            $updResult = New-Object UpdateStatus
            $updResult.ID = $objUpdate.ID
            $updResult.GUID = $objUpdate.GUID
            $updResult.IsInstalled = $objUpdate.IsInstalled
            $updResult.KBID = $objUpdate.KBID
            $updResult.OtherIDs = $objUpdate.OtherIDs
            $updResult.References = $objUpdate.References
            $updResult.RestartRequired = $objUpdate.RestartRequired
            $updResult.Severity = $objUpdate.Severity
            $updResult.Title = $objUpdate.Title
            $updResult.Type = $objUpdate.Type
            $lstUpdates.Add($updResult)
        }
    
        # Return the update list
        return $lstUpdates
    }
    
}

Function Get-WindowsUpdateReport {
    <#
        Get-WindowsUpdateReport

        .SYNOPSIS
        This function will check for pending and installed updates for the endpoint
        using the built-in Windows Update service

        .NOTES
        This function depends on the following types
        public class UpdateStatus
        {
            public string ID;
            public string GUID;
            public bool IsInstalled;
            public string KBID;
            public string OtherIDs;
            public string References;
            public string RestartRequired;
            public string Severity;
            public string Title;
            public string Type;
        }
        public class PendingUpdate
        {
            public string Title;
            public string Description;
            public bool IsBeta;
            public bool IsDownloaded;
            public bool IsHidden;
            public bool IsInstalled;
            public bool IsMandatory;
            public bool IsUninstallable;
            public int MaxDownloadSize;
            public string MsrcSeverity;
            public int Type;
            public bool RestartRequired;
            public string[] CveIDs;
        }
        public class InstalledUpdate
        {
            public System.DateTime Date;
            public string Title;
            public string Description;
            public string ClientApplicationID;
            public int Operation;
            public int ResultCode;
        }
        public class UpdateReport
        {
            public bool PendingSuccess;
            public InstalledUpdate[] InstalledUpdates;
            public PendingUpdate[] PendingUpdates;
        }
    #>
    # Create a new Windows Update session and check for available updates
    $comSession = [Activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session"))
    $wusSearcher = $comSession.CreateUpdateSearcher()

    # Configure searcher to compare against Windows Update
    $wusSearcher.online = $True

    # Query pending updates
    try {
        $wsrPending = $wusSearcher.Search('')
        $boolSuccess = $True
    } catch {
        # An error occurred - likely due to inability to connect to WSUS
        $boolSuccess = $False
    }

    $uprReport = New-Object UpdateReport
    $uprReport.PendingSuccess = $boolSuccess

    # If successful, go through available updates and add to list
    if ($boolSuccess) {
        # Iterate through each update and create a PendingUpdate
        foreach ($objPendingUpdate in $wsrPending) {
            $typList = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
            $typList = $typList.MakeGenericType(@(('PendingUpdate' -as "Type")))
            $lstPendingUpdates = [Activator]::CreateInstance($typList)

            # Create and populate a new PendingUpdate object
            $penUpdate = New-Object PendingUpdate
            $penUpdate.Title = $objPendingUpdate.Title
            $penUpdate.Description = $objPendingUpdate.Description
            $penUpdate.IsBeta = $objPendingUpdate.IsBeta
            $penUpdate.IsDownloaded = $objPendingUpdate.IsDownloaded
            $penUpdate.IsHidden = $objPendingUpdate.IsHidden
            $penUpdate.IsInstalled = $objPendingUpdate.IsInstalled
            $penUpdate.IsMandatory = $objPendingUpdate.IsMandatory
            $penUpdate.IsUninstallable = $objPendingUpdate.IsUninstallable
            $penUpdate.MaxDownloadSize = $objPendingUpdate.MaxDownloadSize
            $penUpdate.MsrcSeverity = $objPendingUpdate.MsrcSeverity
            $penUpdate.Type = $objPendingUpdate.Type
            $penUpdate.RestartRequired = $objPendingUpdate.RestartRequired
            $penUpdate.CveIDs = $objPendingUpdate.CveIDs

            # Add the result to the list
            $lstPendingUpdates.Add($penUpdate)
        }
        # Add the updates to the report
        $uprReport.PendingUpdates = $lstPendingUpdates
    }

    # Query all installed updates
    $wsrHistory = $wusSearcher.QueryHistory(0,$wusSearcher.GetTotalHistoryCount())

    # Create a new list for installed updates
    $typList = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
    $typList = $typList.MakeGenericType(@(('InstalledUpdate' -as "Type")))
    $lstInstalled = [Activator]::CreateInstance($typList)

    # Iterate through each installed update
    foreach ($objInstalledUpdate in $wsrHistory) {
        # Create and populate a new InstalledUpdate
        $insUpdate = New-Object InstalledUpdate
        $insUpdate.Date = $objInstalledUpdate.Date
        $insUpdate.Title = $objInstalledUpdate.Title
        $insUpdate.Description = $objInstalledUpdate.Description
        $insUpdate.ClientApplicationID = $objInstalledUpdate.ClientApplicationID
        $insUpdate.Operation = $objInstalledUpdate.Operation
        $insUpdate.ResultCode = $objInstalledUpdate.ResultCode

        # Add the result to the list
        $lstInstalled.add($insUpdate)
    }

    # Assign to the report
    $uprReport.InstalledUpdates = $lstInstalled

    # Return the report
    return $uprReport
}

Function Get-EventLogReport {
    <#
        Get-EventLogReport

        .SYNOPSIS
        This function queries a specified event log for a given ID and limits results
        to the value specified by MaxEvents.

        .PARAMETER EventLog
        The event log to query

        .PARAMETER EventID
        The event ID to query for

        .PARAMETER MaxEvents
        The maximum number of results to return, defaulted to 100

        .NOTES
        This function depends on the following type
        public class EventLogEntryReport
        {
            public string LogName;
            public int ID;
            public string ProviderName;
            public string ProviderID;
            public System.DateTime TimeCreated;
            public string LevelDisplayName;
            public string TaskDisplayName;
            public string Message;
        }
    #>
    param(
        [string] $EventLog,
        [int] $EventID,
        [int] $MaxEvents = 100
    )

    # Create a hashtable for filters
    $hshQuery = @{
        LogName = $EventLog;
        ID = $EventID
    }
    # Try to get the events
    $arrEvents = Get-WinEvent $hshQuery -MaxEvents $MaxEvents -ErrorAction SilentlyContinue

    # Create a list for the results
    $typList = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
    $typList = $typList.MakeGenericType(@(('EventLogEntryReport' -as "Type")))
    $lstEvents = [Activator]::CreateInstance($typList)

    # Iterate through each event and populate an EventLogEntryReport
    foreach ($objEvent in $arrEvents) {
        $evtCurrent = New-Object EventLogEntryReport
        $evtCurrent.LogName = $objEvent.LogName
        $evtCurrent.ID = $objEvent.ID
        $evtCurrent.ProviderName = $objEvent.ProviderName
        $evtCurrent.ProviderID = $objEvent.ProviderID
        $evtCurrent.TimeCreated = $objEvent.TimeCreated
        $evtCurrent.LevelDisplayName = $objEvent.LevelDisplayName
        $evtCurrent.TaskDisplayName = $objEvent.TaskDisplayName
        $evtCurrent.Message = $objEvent.Message

        # Add event to list
        $lstEvents.add($evtCurrent)
    }

    # Return list
    return $lstEvents
}

Write-Debug "Beginning assessment"

# Create a new EndpointReport
$eprEndpointReport = New-Object EndpointReport

<# ~*~*~*~*~* MAIN *~*~*~*~*~ #>

# Import configuration
$xmlConfig = [xml] (Get-Content $Config)

<#  This value is only for testing
$xmlConfig = [xml] '
<config>
    <registry enable="True">
        <regvalue hive="HKLM" key="SOFTWARE\Microsoft\Windows\CurrentVersion\Run" getallvalues="True"/>
        <regvalue hive="HKLM" key="SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo" property="TenantId"/>
        <regvalue hive="HKLM" key="SYSTEM\CurrentControlSet\Control\Terminal Server" property="fDenyTSConnections"/>
        <regvalue hive="HKLM" key="SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" property="SecurityLayer"/>
        <regvalue hive="HKLM" key="SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" property="UseLogonCredential"/>
        <regvalue hive="HKLM" key="System\CurrentControlSet\Control\Lsa\OSConfig" property="Security Packages"/>
        <!-- Collect firewall rules - ref: https://msdn.microsoft.com/en-us/library/ff719844.aspx for firewall rule parsing -->
        <regvalue hive="HKLM" key="SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules\" getallvalues="True"/>
        <regvalue hive="HKU" key="Software\Sysinternals" getallchildkeys="True"/>
    </registry>
    <wmi enable="True">
        <wmiquery query="select * from Win32_OperatingSystem"/>
        <wmiquery namespace="root\securitycenter2" query="SELECT * FROM AntiVirusProduct"/>
        <wmiquery query="select * from Win32_UserProfile"/>
        <wmiquery query="select * from  Win32_ComputerSystem"/>
        <wmiquery query="select * from Win32_Group" invokemethod="Members"/>
    </wmi>
    <events enable="True" limit="100">
        <eventquery logname="Security" eventid="1102"/>
        <eventquery logname="System" eventid="104"/>
        <eventquery logname="System" eventid="7045"/>
        <eventquery logname="System" eventid="7009"/>
    </events>
    <secpol enable="True"/>
    <msert enable="False" cleanmalware="False"/>
    <updates enable="True"/>
    <winrm enable="True"/>
    <localgroups enable="True"/>
    <localusers enable="True"/>
    <scheduledtasks enable="True"/>
</config>'
#>

# Populate machine information into report
$wmiComputerSystem = Get-WmiObject Win32_ComputerSystem -Property Name, DnsHostName, Domain, DomainRole
$eprEndpointReport.DnsHostName = $wmiComputerSystem.DnsHostName
$eprEndpointReport.ComputerNetBiosName = $wmiComputerSystem.Name
$eprEndpointReport.Domain = $wmiComputerSystem.Domain
$eprEndpointReport.DomainRole = $wmiComputerSystem.DomainRole

# Determine if the machine is a member of a domain
if ($wmiComputerSystem.DomainRole -eq 0) {
    # Set DnsHostName to DnsHostName without domain
    $eprEndpointReport.ComputerDNSName = $wmiComputerSystem.DnsHostName
} else {
    # Set DnsHostName with domain
    $eprEndpointReport.ComputerDNSName = "$($wmiComputerSystem.DnsHostName).$($wmiComputerSystem.Domain)"
}

# Get timestamp and UTC offset
$datStart = Get-Date
$eprEndpointReport.ReportDate = $datStart
$eprEndpointReport.UTCOffsetInMinutes = ((Get-Date) - (Get-Date).ToUniversalTime()).TotalMinutes

<#~*~*~*~*~* Begin windows event collection *~*~*~*~*~#>

# Determine if event log querying is enabled
if ($xmlConfig.config.events.enable -like 'true') {
    Write-Debug "Beginning event log query"

    # Determine if a limit was set
    if ($xmlConfig.config.events.limit) {
        $intEventLimit = $xmlConfig.config.events.limit
    } else {
        # Default limit to 100 if not specified
        $intEventLimit = 100
    }
    # Create a list of event log results
    $typList = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
    $typList = $typList.MakeGenericType(@(('EventLogEntryReport' -as "Type")))
    $lstEvents = [Activator]::CreateInstance($typList)

    # Iterate through each eventlog query
    foreach ($xmeEventLogQuery in $xmlConfig.config.events.eventquery) {
        $arrEvents = Get-EventLogReport -EventLog $xmeEventLogQuery.LogName -EventID $xmeEventLogQuery.eventid -MaxEvents $intEventLimit
        foreach ($evtReport in $arrEvents) {
            $lstEvents.add(([EventLogEntryReport] $evtReport))
        }
    }

    # Add results to the report
    $eprEndpointReport.Events = $lstEvents
}

<# ~*~*~*~*~* Collect WinRM Trusted Hosts *~*~*~*~*~ #>

if ($xmlConfig.config.WinRM.enable -like 'true') {
    Write-Debug "Beginning WinRM Trusted Hosts collection"
    $boolWasRunning = ((Get-Service -Name WinRM).status -ne 'Running')

    if (-not $boolWasRunning) {
        # Try to start the service
        Start-Service -Name WinRM -ErrorAction SilentlyContinue | Out-Null
    }

    if ((Get-Service -Name WinRM).status -eq 'Running') {
        # Try to obtain trusted WinRM Hosts
        try {
            $eprEndpointReport.WinRMTrustedHosts = Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction Stop | select -ExpandProperty Value
        } catch {
            Write-Warning "Unable to obtain a list of WinRM Hosts."
        }
    }

    if (-not $boolWasRunning) {
        # Stop the service to return the machine to its original state
        Stop-Service WinRM | Out-Null
    }
    Write-Debug "Completed WinRM Trusted Hosts collection"
}

<# ~*~*~*~*~* Collect registry report *~*~*~*~*~ #>

if ($xmlConfig.config.registry.enable -like 'true') {
    Write-Debug "Beginning registry key collection"
    # Create a new list to hold registry reports
    $typList = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
    $typList = $typList.MakeGenericType(@(('RegistryKeyReport' -as "Type")))
    $lstRegistry = [Activator]::CreateInstance($typList)

    # Determine if HKU has been mapped, if not - map it
    try {
        Get-PSDrive -Name 'hku' -ErrorAction Stop | Out-Null
    } catch {
        # Map HKEY_Users as HKU
        New-PSDrive HKU Registry HKEY_USERS | Out-Null
    }

    # Create a list of HKU keys
    $arrHKU = (get-item hku:\).getsubkeynames()

    # Loop through each value to collect
    foreach ($xmeReport in $xmlConfig.config.registry.regvalue) {
        Write-Debug "Beginning registry key report.  Hive: $($xmeReport.Hive) Key: $($xmeReport.Key) Value $($xmeReport.Value) GetAllValues: $($xmeReport.GetAllValues -like 'true') GetAllChildKeys: $($xmeReport.GetAllChildKeys -like 'true')"
        
        # Determine if the hive is HKU
        if ($xmeReport.hive -like 'HKU') {
            # Since we are looking at HKEY_Users we will need to iterate through each profile's subkey
            foreach ($strProfile in $arrHKU) {
                $strKey = Join-Path $strProfile $xmeReport.Key
                $arrResults = Get-RegistryKeyReport -Hive $xmeReport.hive -Key $strKey -GetAllValues ($xmeReport.GetAllValues  -like 'true') -GetChildKeys ($xmeReport.GetChildKeys  -like 'true')

                # Add each result to the list
                foreach ($rkrResult in $arrResults) {
                    $lstRegistry.Add(([RegistryKeyReport] $rkrResult))
                }
            }
        } else {
            # Process as normal
            $arrResults = Get-RegistryKeyReport -Hive $xmeReport.hive -Key $xmeReport.key -GetAllValues ($xmeReport.GetAllValues -like 'true') -GetChildKeys ($xmeReport.GetChildKeys -like 'true')
            foreach ($rkrResult in $arrResults) {
                $lstRegistry.Add(([RegistryKeyReport] $rkrResult))
            }
        }
    }

    # Set the value on the report
    $eprEndpointReport.RegistryKeyReports = $lstRegistry
    Write-Debug "Completed registry key collection"
}

<# ~*~*~*~*~* WMI Report Collection *~*~*~*~*~ #>

# Determine if WMI collection is enabled
if ($xmlConfig.config.wmi.enable -like 'true') {
    Write-Debug "Beginning WMI collection"

    # Create a list for results
    $typList = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
    $typList = $typList.MakeGenericType(@(('WmiReport' -as "Type")))
    $lstWMI = [Activator]::CreateInstance($typList)

    # Iterate through each WMI report
    foreach ($xmeWMIReport in $xmlConfig.config.wmi.wmiquery) {
        
        # Determine if a namespace was specified
        if ($xmeWMIReport.Namespace) {
            $arrResults = Get-WmiReport -Namespace $xmeWMIReport.Namespace -Query $xmeWMIReport.query
        } else {
            # Attempt to collect the WMI object
            $arrResults = Get-WmiReport -Query $xmeWMIReport.query
        }

        # Iterate through results, add to list
        foreach ($wmiResult in $arrResults) {
            # Add to the list
            $lstWMI.Add(([WmiReport] $wmiResult))
        }
    }

    # Attach WMI reports to endpoint report
    $eprEndpointReport.WmiReports = $lstWMI

    Write-Debug "Completed WMI collection"
}

<# ~*~*~*~*~* Local Group collection *~*~*~*~*~ #>

if ($xmlConfig.config.localgroups.enable -like 'true') {
    Write-Debug "Beginning collection of local groups"

    # Collect local groups
    $arrLocalGroups = Get-LocalGroups

    # Add to list and explicitly cast
    $typList = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
    $typList = $typList.MakeGenericType(@(('LocalGroup' -as "Type")))
    $lstLocalGroups = [Activator]::CreateInstance($typList)

    foreach ($lcgGroup in $arrLocalGroups) {
        $lstLocalGroups.add(([LocalGroup] $lcgGroup))
    }

    # Attach result to report
    $eprEndpointReport.LocalGroups = $lstLocalGroups
    Write-Debug "Completed collection of local groups"
}

<# ~*~*~*~*~* Local User Collection *~*~*~*~*~ #>

if ($xmlConfig.config.localusers.enable -like 'true') {
    Write-Debug "Beginning collection of local users"

    # Collect local users
    $arrLocalUsers = Get-LocalUsers

    # Add to a list and explicitly cast
    $typList = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
    $typList = $typList.MakeGenericType(@(('LocalUser' -as "Type")))
    $lstLocalUsers = [Activator]::CreateInstance($typList)

    foreach ($objUser in $arrLocalUsers) {
        $lstLocalUsers.Add(([LocalUser] $objUser))
    }

    # Add to endpoint report
    $eprEndpointReport.LocalUsers = $lstLocalUsers
    Write-Debug "Completed collection of local users"
}

<# ~*~*~*~*~* Secpol *~*~*~*~*~ #>

if ($xmlConfig.config.secpol.enable -like 'true') {
    Write-Debug "Beginning secpol collection"
    
    # Get the Local Security Policy report
    $lspReport = Get-LocalSecurityPolicy

    # Add to the endpoint report
    $eprEndpointReport.LocalSecurityPolicy = [LocalSecurityPolicy] $lspReport
    
    Write-Debug "Completed secpol collection"
}

<# ~*~*~*~*~* MSERT *~*~*~*~*~ #>

if ($xmlConfig.config.msert.enable -like 'true') {
    Write-Debug "Beginning MSERT Scan"

    # Begin scan
    $arrDetections = Invoke-MSERTScan -RemoveMalware ($xmlConfig.config.msert.removemalware -like 'true')

    # Iterate through results and cast to a list
    $typList = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
    $typList = $typList.MakeGenericType(@(('MalwareInfection' -as "Type")))
    $lstDetections = [Activator]::CreateInstance($typList)

    foreach ($detDetection in $arrDetections) {
        $lstDetections.Add([MalwareInfection] $detDetection)
    }

    # Add to endpoint report
    $eprEndpointReport.MalwareInfections = $lstDetections

    Write-Debug "Completed MSERT Scan"
}

<# ~*~*~*~*~* Updates *~*~*~*~*~ #>

# Determine if updates are enabled
if ($xmlConfig.config.updates.enable -like 'true') {
    # Get update report
    $uprReport = Get-WindowsUpdateReport

    # Add to endpoint report
    $eprEndpointReport.UpdateReport = [UpdateReport] $uprReport
}

<# ~*~*~*~*~* Scheduled Tasks *~*~*~*~*~ #>

if ($xmlConfig.config.scheduledtasks.enable -like 'true') {
    $arrTasks = Get-ScheduledTasks

    # Create a list of TaskReports and add each to the list
    $typList = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
    $typList = $typList.MakeGenericType(@(('TaskReport' -as "Type")))
    $lstTasks = [Activator]::CreateInstance($typList)

    foreach ($schTask in $arrTasks) {
        $lstTasks.Add(([TaskReport] $schTask))
    }

    # Assign the taskreports list to the endpointreport
    $eprEndpointReport.ScheduledTasks = $lstTasks
}

# Set report duration
$eprEndpointReport.ReportDurationInSeconds = [int] ((Get-Date) - ($datStart)).TotalSeconds

<# ~*~*~*~*~* Produce JSON Output *~*~*~*~*~ #>

# Determine if we have ConvertTo-JSON available
try {
    $eprEndpointReport | ConvertTo-Json -Depth 100 -Compress | Out-File $OutputFile -Force
} catch {
    # Implement our own JSON conversion using .Net 3.5+
    add-type -assembly system.web.extensions

    $jssSerializer=new-object system.web.script.serialization.javascriptSerializer
    $strJson = $jssSerializer.Serialize($eprEndpointReport)
    $strJson | Out-File $OutputFile -Force
}
