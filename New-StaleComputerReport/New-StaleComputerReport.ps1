<#
    New-StaleComputerReport

    .SYNOPSIS
    This script will enumerate computer accounts in the current domain and identify accounts which may be stale

    .NOTES
     Ver | Date    | Alias    | Notes
    -----+---------+----------+---------------------------------
     1.0 | 11DEC17 | mimelone | Initial Release
	 1.1 | 08JAN17 | mimelone | Fixed bug with enabled bit

#>

param(
    [int] $LikelyActiveThreshold = 30,
    [int] $PossiblyActiveThreshold = 90,
    [ValidateScript({-not (Test-Path $_)})]
    [string] $OutputFile = '.\StaleComputerReport.csv'
)

$now = Get-Date
$lstComputers = New-Object 'System.Collections.Generic.List[PSObject]'

Get-ADComputer -Filter * -Properties passwordlastset, lastlogondate, OperatingSystem, OPeratingSystemVersion, DnsHostName |
    %{
        $psoComputer = New-Object PSObject
        $psoComputer | 
            Add-Member -NotePropertyName PasswordLastSet -NotePropertyValue $_.PasswordLastSet -PassThru |
            Add-Member -NotePropertyName LastLogonDate -NotePropertyValue $_.LastLogonDate -PassThru |
            Add-Member -NotePropertyName DistinguishedName -NotePropertyValue $_.DistinguishedName -PassThru |
            Add-Member -NotePropertyName SAMAccountName -NotePropertyValue $_.SamAccountName -PassThru |
            Add-Member -NotePropertyName Name -NotePropertyValue $_.name -PassThru |
            Add-Member -NotePropertyName SID -NotePropertyValue $_.SID.value -PassThru |
            Add-Member -NotePropertyName DNSHostName -NotePropertyValue $_.DNSHostName -PassThru |
            Add-Member -NotePropertyName OperatingSystem -NotePropertyValue $_.OperatingSystem -PassThru |
            Add-Member -NotePropertyName OperatingSystemVersion -NotePropertyValue $_.OperatingSystemVersion -PassThru | 
			Add-Member -NotePropertyName Enabled -NotePropertyValue $_.Enabled

        if ($psoComputer.PasswordLastSet -ne $Null) {
            $psoComputer | 
                Add-Member -NotePropertyName PasswordAgeInDays -NotePropertyValue ($now.Subtract([datetime] $_.PasswordlastSet)).Days
        } else {
            $psoComputer | 
                Add-Member -NotePropertyName PasswordAgeInDays -NotePropertyValue $Null
        }

        if ($_.LastLogonDate) {
            $psoComputer |
                Add-Member -NotePropertyName LastLoginInDays -NotePropertyValue ($now.Subtract([datetime] $_.LastLogonDate)).Days 
        } else {
            $psoComputer | 
                Add-Member -NotePropertyName LastLoginInDays -NotePropertyValue $Null
        }

        If ($psoComputer.PasswordAgeInDays -ne $Null -and $psoComputer.LastLoginInDays -ne $Null -and $psoComputer.Enabled -and ($psoComputer.PasswordAgeInDays -le $LikelyActiveThreshold -or $psoComputer.LastLoginInDays -le $LikelyActiveThreshold)) {
            $IsActive = 'LikelyActive'
        } elseif ($psoComputer.PasswordAgeInDays -ne $Null -and $psoComputer.LastLoginInDays -ne $Null -and ($psoComputer.PasswordAgeInDays -le $PossiblyActiveThreshold -or $psoComputer.LastLoginInDays -le $PossiblyActiveThreshold)) {
            $IsActive = 'PossiblyActive'
        } else {
            $IsActive = 'LikelyInactive'
        }
        $psoComputer | Add-Member -NotePropertyName IsStale -NotePropertyValue $IsActive

        $lstComputers.add($psoComputer)
    }

$lstComputers | Export-Csv -NoTypeInformation $OutputFile

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
