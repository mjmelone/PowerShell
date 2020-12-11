# Enter your tenant ID, Client ID, and Client Secret below.
# Script requires WindowsDefenderATP\TI.ReadWrite.All API permissions
$tenant = '' # Set this to your AAD Tenant ID
$ClientId = '' # Set this to an app identity with the following API permission: WindowsDefenderATP\TI.ReadWrite.All
$ClientSecret = '' # Set this to your client secret for the account


<#
.SYNOPSIS
This script generates a report of duplicate indicators found in Defender for Endpoint
and can delete these indicators if desired.

.DESCRIPTION
Defender for Endpoint allows users to create duplicate indicators which may pose a problem
due to the indicator limit. This script enumerates all indicators on the tenant and identifies
any duplicates based on rbacGroupIds and indicatorValue. 

Detected duplicates can be either reported on and \ or deleted based on the switches provided.

.PARAMETER Delete
If the -Delete switch is specified, the list of indicators to be deleted will be listed out in
table form. You will then be prompted as to whether you would like to delete these indicators.
Any entry other than 'y' be treated as a 'no' for safety.

This script does not have any logic for handling duplicate indicators based on priority, response
action, or any other attribute. It will indiscriminitely keep the first instance of an indicator 
and consider any subsequent ones duplicates (translation: delete)

.PARAMETER Report
If specified, this will create a CSV formatted report of all duplicate indicators found on the
tenant. To use this feature, specify -Report followed by a full path to the output report
(including the filename).

.PARAMETER JWTToken
This is an access token to Defender for Endpoint

.EXAMPLE
Get-DuplicateDefenderIndicators -JWTToken $AccessToken -Report ".\DuplicateIndicatorReport.csv" -Delete

.NOTES
Developed by Michael Melone, Principal Program Manager, Microsoft 365 Defender

This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment. THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree: (i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneysâ€™ fees, that arise or result from the use or distribution of the Sample Code.

This sample script is not supported under any Microsoft standard support program or service. The sample script is provided AS IS without warranty of any kind. Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages.
#>

function Get-DuplicateDefenderIndicators
{
    param(
        [switch] $Delete,
        [string] $Report,
        [string] $JWTToken
    )

    $IndicatorsApi = "https://api.securitycenter.windows.com/api/indicators"

    $Headers = @{}
    $Headers.Add("Authorization","$($AccessToken.token_type) "+ " " + "$($AccessToken.access_token)")

    $IndicatorList = Invoke-RestMethod -Method Get -Uri $IndicatorsApi -Headers $Headers

    # Iterate through each indicator and search for duplicates
    $IndicatorsSeen = New-Object 'System.Collections.Generic.Dictionary[string,int]'
    $IndicatorsToDelete = New-Object 'System.Collections.Generic.Dictionary[int, int]'

    $IndicatorList.value | 
        ?{$_.createdBySource -ne 'TVM' -and $_.indicatorType -ne 'WebCategory'} |
        %{
            $IndicatorAndRbacGroup = "$($_.rbacGroupIds)\$($_.indicatorValue)"
            if ($IndicatorsSeen.ContainsKey($IndicatorAndRbacGroup))
            {
                $IndicatorsToDelete.Add($_.id, $IndicatorsSeen[$IndicatorAndRbacGroup])
            } else {
                $IndicatorsSeen.Add("$($_.rbacGroupIds)\$($_.indicatorValue)", $_.id)
            }
        }
    
    Write-Output "$($IndicatorsToDelete.count) duplicate indicators found"

    if ($IndicatorsToDelete.count -gt 0)
    {
        if ($Report)
        {
            $IndicatorList.value | 
                ?{$IndicatorsToDelete.ContainsKey($_.id) -or $IndicatorsToDelete.ContainsValue($_.id)} |
                export-csv -NoTypeInformation $Report
        }

        if ($Delete)
        {
            Write-Host "Indicators being deleted:"
            $IndicatorList.value | 
                ?{$IndicatorsToDelete.ContainsKey($_.id)} | 
                Format-Table id, indicatorType, indicatorValue, action, createdBy, creationTimeDateTimeUtc
            Write-Host "------------------------------------------------------------"
            $x = Read-Host -Prompt "About to delete $($IndicatorsToDelete.Count) indicators. Continue? (y/n)"

            if ($x.tolower() -eq 'y')
            {
                # Delete indicators
                $IndicatorsToDelete.Keys | %{
                    Invoke-RestMethod -Method Delete -Uri "$IndicatorsApi/$($_)" -Headers $Headers
                }
            }
        }
    }
}


$resource = 'https://api.securitycenter.windows.com/'

# Get an authentication token
$RequestAccessTokenUri = "https://login.microsoftonline.com/$tenant/oauth2/token"
$body = "grant_type=client_credentials&client_id=$ClientId&client_secret=$ClientSecret&resource=$Resource"

$AccessToken = Invoke-RestMethod -Method Post -Uri $RequestAccessTokenUri -Body $body -ContentType 'application/x-www-form-urlencoded'

Get-DuplicateDefenderIndicators -JWTToken $AccessToken -Report ".\DuplicateIndicatorReport.csv" -Delete
