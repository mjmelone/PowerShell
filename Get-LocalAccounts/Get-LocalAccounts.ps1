param(
    [parameter(mandatory=$True)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    $ComputerFile,
    [ValidateScript({-not (Test-Path $_ -PathType Leaf)})]
    $OutputCSV = ".\Get-LocalAccounts-Output.csv"
)

$arrComputers = gc $ComputerFile
$lstResults = New-Object System.Collections.Generic.List[PSObject]

foreach ($strComputer in $arrComputers) {
    $boolConnected = $false
    try {
        Test-Connection -Protocol DCOM -DcomAuthentication Connect -ComputerName $strCOmputer -Quiet
        $boolConnected = $True
    } catch {
        Write-Warning "Unable to ping computer $strComputer"
    }

    if ($boolConnected) {
        $arrLocalAccounts = Get-WmiObject -ComputerName $strComputer -Query "Select * from Win32_UserAccount Where LocalAccount = True"
        ForEach ($objLocalAccount in $arrLocalAccounts) {
            # Bind to the user object to get additional info
            $dsoUser = [adsi] "WinNT://$strComputer/$($objLocalAccount.name),user"
            $psoResult = New-Object PSObject
            $psoResult
            Get-Member -MemberType Property -InputObject $dsoUser | %{
                $psoResult | Add-Member -NotePropertyName $_.Name -NotePropertyValue $dsoUser.($_.name).value
            }

            Get-Member -MemberType Property -InputObject $objLocalAccount | ?{$_.name -notin (Get-Member -InputObject $psoResult).name} | %{
                $psoResult | Add-Member -NotePropertyName $_.Name -NotePropertyValue $objLocalAccount.($_.name)
            }
            $lstResults.add($psoResult)
        }
    }
}

$lstResults.GetEnumerator() | Export-Csv $OutputCSV -NoTypeInformation

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
