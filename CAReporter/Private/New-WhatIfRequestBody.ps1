function New-WhatIfRequestBody {
    <#
    .SYNOPSIS
        Builds the JSON request body for the Graph What-If evaluate endpoint.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserId,

        [Parameter(Mandatory)]
        [string[]]$IncludeApplications,

        [string]$DevicePlatform,
        [string]$ClientAppType = 'browser',
        [string]$SignInRiskLevel = 'none',
        [string]$UserRiskLevel = 'none',
        [string]$Country,
        [string]$IpAddress,
        [string]$InsiderRiskLevel,
        [string]$ServicePrincipalRiskLevel,
        [hashtable]$DeviceInfo,
        [bool]$AppliedPoliciesOnly = $false
    )

    $body = @{
        signInIdentity  = @{
            '@odata.type' = '#microsoft.graph.userSignIn'
            userId        = $UserId
        }
        signInContext    = @{
            '@odata.type'         = '#microsoft.graph.applicationContext'
            includeApplications   = @($IncludeApplications)
        }
        signInConditions = @{
            clientAppType  = $ClientAppType
            signInRiskLevel = $SignInRiskLevel
            userRiskLevel   = $UserRiskLevel
        }
        appliedPoliciesOnly = $AppliedPoliciesOnly
    }

    if ($DevicePlatform) {
        $body.signInConditions['devicePlatform'] = $DevicePlatform
    }
    if ($Country) {
        $body.signInConditions['country'] = $Country
    }
    if ($IpAddress) {
        $body.signInConditions['ipAddress'] = $IpAddress
    }
    if ($InsiderRiskLevel) {
        $body.signInConditions['insiderRiskLevel'] = $InsiderRiskLevel
    }
    if ($ServicePrincipalRiskLevel) {
        $body.signInConditions['servicePrincipalRiskLevel'] = $ServicePrincipalRiskLevel
    }
    if ($DeviceInfo) {
        $body.signInConditions['deviceInfo'] = $DeviceInfo
    }

    $body
}
