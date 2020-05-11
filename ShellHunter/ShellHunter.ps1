<#
    .Synopsis
    Webshell hunting script

    .Description
    This script enumerates directories published by IIS and searches files
    in these directories for a set of supplied indicators.

    .Parameter Indicators
    This is a list of indicators to search for

    .Parameter Outputfile
    This is the file where the results are output in CSV format.

    .Parameter IndicatorFile
    A list of indicators in a text file to search for

    .Parameter ScanPaths
    An optional list of paths to scan.

    .Example
    ShellHunter.ps1 -Indicators 'Sauce', 'MoreSauce'
#>
param(
    [parameter(ParameterSetName='Array',Mandatory=$True)]
    [string[]] $Indicators,
    [parameter(ParameterSetName='File',Mandatory=$True)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string] $IndicatorFile,
    [string[]] $ScanPaths,
    [ValidateScript({-not (Test-Path $_ -pathtype -Leaf)})]
    [string] $OutputFile = ".\$($env:COMPUTERNAME)-ShellHunter.csv"
)

# Custom type for results for speed
Add-Type '
public class ShellHunterResult
{
    public string RealPath;
    public System.DateTime Created;
    public System.DateTime Modified;
    public System.DateTime Accessed;
    public string FileVersion;
    public string CompanyName;
    public string Language;
    public string LegalCopyright;
    public string OriginalFileName;
    public string ProductName;
    public int Length;
    public int MatchedIndicatorCount;
    public string Indicators;
}'

# This is a workaround because PowerShell 2.0 can't use New-Object to create <T> classes
$type = ("System.Collections.Generic.List"+'`'+"1") -as "Type"
$type= $type.MakeGenericType("ShellHunterResult" -as "Type")
$lstResults = [Activator]::CreateInstance($type)


$lstPublishedDirectories = New-Object 'System.Collections.Generic.List[string]'

# Build list of indicators
$lstIndicators = New-Object 'System.Collections.Generic.List[string]'
$Indicators | ?{-not [string]::IsNullOrEmpty($_)} | %{
    $lstIndicators.add($_)
}

######################
# IndicatorFile Mode #
######################

if ($null -ne $IndicatorFile)
{
    Write-Debug "Importing IndicatorFile"
    
    Get-Content $IndicatorFile | ?{-not [string]::IsNullOrEmpty($_)} | %{
        Write-Debug "Adding indicator $_"
        $lstIndicators.Add($_)
    }

}

if ($lstIndicators.count -eq 0) 
{
    Write-Error "No indicators specified."
}


##########################
# Load IIS Configuration #
##########################

# Determine if IIS config file is present
$strIISCfgPath = Join-Path $env:windir 'system32\inetsrv\config\applicationHost.config'

if (Test-Path $strIISCfgPath) {
    Write-Debug "IIS configuration found.  Attempting to import."
    $xmlIISCfg = [xml] (gc $strIISCfgPath)

    Write-Debug "Enumerating virtual directories"
    $xmlIISCfg.GetElementsByTagName('virtualDirectory') | %{
        # Expand any environmental variables
        $strCurrentPath = [System.Environment]::ExpandEnvironmentVariables($_.physicalPath)

        # Add the directory to the list
        $lstPublishedDirectories.add($strCurrentPath)
    }
}

# Add any explicit scan paths specified as a switch
foreach ($strScanPath in $ScanPaths)
{
    $lstPublishedDirectories.add($strScanPath)
}

################################
# Deduplication and Path Check #
################################
Write-Debug "Beginning directory deduplication and parent \ child checks.  Initial count: $($lstPublishedDirectories.count)"
$lstDirectoriesToScan = New-Object 'System.Collections.Generic.List[string]'

# Deduplicate the scan paths to avoid duplication
$lstPublishedDirectories = $lstPublishedDirectories | Sort-Object -Unique

Write-Debug "Deduplicated count: $($lstPublishedDirectories.count).  Filtering null paths."

# Filter out null paths
$lstPublishedDirectories =  [string[]] ($lstPublishedDirectories | ?{-not [string]::IsNullOrEmpty($_)})

Write-Debug "Count without nulls: $($lstPublishedDirectories.count)"

# Check for parent \ child relationships to avoid duplicate scans
foreach ($strDirectory in $lstPublishedDirectories) 
{
    # Check to see if the current directory is a child of any of the other directores
    Write-Debug "Testing path existence: $strDirectory"
    if ((Test-Path $strDirectory -pathtype Container)) 
    {
        <#
        Write-Debug "Checking parent \ child relationships with other sites."
        $uriCurrent = New-Object 'System.Uri' -argumentlist $strDirectory

        # Iterate through each path to scan and see if this is a child of any other path
        $lstPublishedDirectories | %{
            $uriComparison = New-Object 'System.Uri' -argumentlist $_

            # Checking to see if path is a child
            if ((-not $uriComparison.equals($uriCurrent)) -and $uriComparison.IsBaseOf($uriCurrent))
            {
                Write-Debug "Parent folder found.  Parent folder: $($uriComparison.OriginalString) Child Folder: $strDirectory"
                # Move to next item in Foreach statement
                continue
            }
        }
        #>

        # We passed all of the checks, add the directory to the list of directories to scan
        Write-Debug "Adding directory to list of directories to scan: $strDirectory"
        $lstDirectoriesToScan.add($strDirectory)
    } else {
        Write-Warning "The following path was published, but does not appear to exist: $strDirectory"
    }
}

Write-Debug "Final count of directories to scan: $($lstDirectoriesToScan.count)"

#############
# Scan loop #
#############
$DirectoryCounter = 0
$DirectoryCount = $lstDirectoriesToScan.count
foreach ($strScanParent in $lstDirectoriesToScan)
{
    $DirectoryCounter++
    Write-Debug "Beginning enumeration of $strScanParent.  Directory $DirectoryCounter of $DirectoryCount"

    $arrFilesToScan = Get-ChildItem $strScanParent -Recurse | ?{-not $_.PSIsContainer}

    Write-Debug "Files to scan under $strScanParent : $($arrFilesToScan.count)"

    $FileCounter = 0
    $FileCount = $arrFilesToScan.count
    foreach ($objFileToScan in $arrFilesToScan)
    {
        $FileCounter++
        Write-Debug "Scanning file $strFileToScan.  File $FileCounter of $FileCount"

        $resCurrent = New-Object 'ShellHunterResult'
        $strFileToScan = $objFileToScan.FullName

        # Populate file-specific attributes
        $resCurrent.RealPath = $strFileToScan
        $resCurrent.Created = $objFileToScan.CreationTimeUtc
        $resCurrent.Modified = $objFileToScan.LastWriteTimeUtc
        $resCurrent.Accessed = $objFileToScan.LastAccessTimeUtc
        $resCurrent.FileVersion = $objFileToScan.FileVersion
        $resCurrent.CompanyName = $objFileToScan.CompanyName
        $resCurrent.Language = $objFileToScan.Language
        $resCurrent.LegalCopyright = $objFileToScan.LegalCopyright
        $resCurrent.OriginalFileName = $objFileToScan.OriginalFileName
        $resCurrent.ProductName = $objFileToScan.ProductName
        $resCurrent.Length = $objFileToScan.Length

        # Create a new list for matching indicators
        $lstIndicatorMatches = New-Object 'System.Collections.Generic.List[string]'

        Write-Debug "Beginning indicator search"
        # Search for any indicators
        Select-String -Path $strFileToScan -Pattern $lstIndicators -SimpleMatch | %{
            $strFinding = "Line: $($_.LineNumber) Indicator: $($_.Pattern) MatchingRows: $($_.matches -join ', ')"
            Write-Warning "Indicator Found: $strFinding"
            $lstIndicatorMatches.add($strFinding)
        }
        Write-Debug "Endning indicator search"

        # Update result
        $resCurrent.MatchedIndicatorCount = $lstIndicatorMatches.count
        if ($lstIndicatorMatches.count -gt 0)
        {
            $resCurrent.Indicators = ($lstIndicatorMatches -join '; ')
        } else {
            $resCurrent.Indicators = ''
        }
        $lstResults.Add($resCurrent)
    }
}

# Output the results to a file
$lstResults | Export-Csv -NoTypeInformation $OutputFile

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
