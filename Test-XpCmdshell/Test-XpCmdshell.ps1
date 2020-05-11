<#
    Test-XpCmdshell

    .SYNOPSIS
    This script will test servers to determine if the xp_cmdshell function is enabled.

    .DESCRIPTION
    Servers with xp_cmdshell turned on may be able to be used by an attacker to execute arbitraty
    code as the SQL server service if a vulnerability exists that allows them to run arbitrary
    queries, such as a SQL injection vulnerability.  Code is executed under the context of the
    identity of the SQL server account on the SQL server itself.  If this server provides access
    or authorization to servers that the attacker does not have without leveraging the 
    vulnerability, this can provide a significant foothold for the attacker.

    To use this script, provide a list of one or more servers to the -DatabaseServers parameter.
    The identity used to execute this script must be a valid user to the database server.

    .PARAMETER DatabaseServers
    This parameter specifies one or more database servers to check to determine if xp_cmdshell is 
    enabled.

    .PARAMETER Report
    The report parameter specifies the location and name where the report will be generated.  The
    file must not already exist at that location.  If not specified, the report will be generated
    in the operating directory with a name of "Test-XpCmdShellReport.csv"

    .EXAMPLE
    To run the test on servers db1 and db2
    
    Test-XpCmdShell -DatabaseServers db1, db2

    .EXAMPLE
    To run the test on server db3 and output the report to c:\MyReport.csv

    Test-XpCmdShell -DatabaseServers db3 -Report "c:\MyReport.csv"

    .NOTES
     Date   | Alias    | Notes
    --------+----------+---------------------------------------------------------
    14MAR17 | mimelone | Initial Release
#>
param(
    [parameter(mandatory=$True)]
    [string[]] $DatabaseServers,
    [ValidateScript({-not (Test-Path $_ -PathType Leaf)})]
    [string] $Report = ".\Test-XpCmdShellReport.csv"
)

$lstResults = New-Object System.Collections.Generic.List[PSObject]

Function TestForXpCmdshell {
    param(
        [parameter(mandatory = $True)]
        $Server
    )

    #Create and open a connection to the SQL Server
    $sqlConn = New-Object System.Data.SqlClient.SqlConnection

    $sqlConn.ConnectionString =  "Data Source=$Server;Integrated Security=True;Connect Timeout=15;Encrypt=False;TrustServerCertificate=False"

    #Try to open the connection to the database
    try {
        $sqlConn.Open()

        $cmdSQLCommand = $sqlConn.CreateCommand()
        $cmdSQLCommand.CommandText = "
            SELECT name AS [Configuration], CONVERT(INT, ISNULL(value, value_in_use)) AS [IsEnabled]
                FROM  master.sys.configurations
                WHERE  name = 'xp_cmdshell'"
        $sqlData = New-Object System.Data.SqlClient.SqlDataAdapter($cmdSQLCommand)
        $sqlDataset = New-Object System.Data.DataSet
        try {
            $sqlData.Fill($sqlDataset) | Out-Null
        } catch {
            Write-error "An error occurred while attempting to query $_"
            return $Null
        }
    } catch {
        Write-Error "An error was encountered when trying to open the connection to the following database server: $Server"
        Return $Null
    }

    Return [bool]$sqlDataset.tables[0].Rows[0].IsEnabled
}

$a = 0
$intCount = $arrServers.count
$DatabaseServers | %{
    $a++
    if ($intCount) {
        Write-Progress -Activity "Scanning server $_" -PercentComplete (($a/$intCount)*100)
    }
    $psoResult = New-Object PSObject
    $psoResult | Add-Member -NotePropertyName Server -NotePropertyValue $_
    $objResult = (TestForXpCmdshell -Server $_)
    if ($objResult -eq $Null) {
        $psoResult | Add-Member -NotePropertyName Result -NotePropertyValue "Fail"
    } else {
        $psoResult | Add-Member -NotePropertyName Result -NotePropertyValue $objResult
    }
    $lstResults.Add($psoResult)
}

$lstResults | Export-Csv $Report -NoTypeInformation

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
