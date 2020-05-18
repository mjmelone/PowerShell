<#
.SYNOPSIS
This function adds Defender exclusions to a GPO

.DESCRIPTION
This function works with the ActiveDirectory PowerShell module to simplify
adding Defender exclusions to group policy objects.  To use it, you can 
pass in a GPO from Get-GPO and specify the exclusion you want to add.

.PARAMETER GPO
This is a GPO from the Get-GPO or New-GPO cmdlet from the ActiveDirectory
PowerShell cmdlets.

.PARAMETER ExclusionType
This defines the type of exclusion to add.  Options are
- Extension (file extension)
- Path (folder path)
- Process (process name)
Note that no validation is performed on this input, so please validate
your configurations

.PARAMETER Exclusion
This is the string to exclude.  Examples include:
.mdf
c:\myfolder\
myprocess.exe

.EXAMPLE
$gpo = Get-GPO -Name "Defender Exclusions" 
Add-DefenderExclusionToGpo -GPO $gpo -ExclusionType Extension -Exclusion ".mdf"

.NOTES
Created by Michael Melone

This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment. THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree: (i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys’ fees, that arise or result from the use or distribution of the Sample Code.

This sample script is not supported under any Microsoft standard support program or service. The sample script is provided AS IS without warranty of any kind. Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages.
#>
function Add-DefenderExclusionToGpo
{
    param(
        [parameter(Mandatory=$true)]
        [ValidateScript({Get-Gpo $_.id})]
        $GPO,
        [parameter(Mandatory=$true)]
        [validateset("Extension","Path","Process")]
        [string] $ExclusionType,
        [parameter(Mandatory=$true)]
        [string] $Exclusion
    )

    # Determine which keys to set
    switch ($ExclusionType) {
        "Extension" {  
            # Set the registry key
            $KeyName = 'HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions\Extensions'
        }
        "Path" {
            # Set the registry key
            $KeyName = 'HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths'
        }
        "Process" {
            # Set the registry key
            $KeyName = 'HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions\Processes'
        }
        Default {
            Write-Error "Invalid option for ExclusionType: $ExclusionType"
        }
    }

    try {
        Set-GPRegistryValue -Guid $Gpo.id -Key $KeyName -ValueName $Exclusion -Type String -Value "0" | Out-Null
    } catch {
        throw "Add-DefenderExclusionToGpo: Failed to add the exclusion to the GPO.  Please ensure you have permissions to edit the policy and that Active Directory is functioning normally."
    }
}
