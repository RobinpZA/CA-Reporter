function Get-WellKnownAppId {
    <#
    .SYNOPSIS
        Returns a hashtable mapping well-known application IDs to friendly names.
    #>
    [CmdletBinding()]
    param()

    @{
        '00000002-0000-0ff1-ce00-000000000000' = 'Office 365 Exchange Online'
        '00000003-0000-0ff1-ce00-000000000000' = 'Office 365 SharePoint Online'
        '67ad5377-2d78-4ac2-a867-6300cda00e85' = 'Office 365'
        '00000006-0000-0ff1-ce00-000000000000' = 'Microsoft Office 365 Portal'
        'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' = 'Azure Portal'
        '797f4846-ba00-4fd7-ba43-dac1f8f63013' = 'Azure Service Management'
        '04b07795-8ddb-461a-bbee-02f9e1bf7b46' = 'Azure CLI'
        '1950a258-227b-4e31-a9cf-717495945fc2' = 'Azure PowerShell'
        '00000003-0000-0000-c000-000000000000' = 'Microsoft Graph'
        '0000000a-0000-0000-c000-000000000000' = 'Microsoft Intune'
        'd4ebce55-015a-49b5-a083-c84d1797ae8c' = 'Microsoft Intune Enrollment'
        'de8bc8b5-d9f9-48b1-a8ad-b748da725064' = 'Microsoft 365 Compliance Center'
        '00000007-0000-0ff1-ce00-000000000000' = 'Microsoft Power BI'
        'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe' = 'Microsoft Teams'
        '5e3ce6c0-2b1f-4285-8d4b-75ee78787346' = 'Microsoft Teams Web Client'
        '00000015-0000-0000-c000-000000000000' = 'Microsoft Dynamics CRM'
        'fc780465-2017-40d4-a0c5-307022471b92' = 'Microsoft Exchange REST API'
        '00b41c95-dab0-4487-9791-b9d2c32c80f2' = 'Office 365 Management APIs'
        '09abbdfd-ed23-44ee-a2d9-a627aa1c90f3' = 'Microsoft Defender for Cloud Apps'
        'Office365'                             = 'Office 365 (Suite)'
        'MicrosoftAdminPortals'                 = 'Microsoft Admin Portals'
        'All'                                   = 'All Cloud Apps'
        'None'                                  = 'None'
    }
}
