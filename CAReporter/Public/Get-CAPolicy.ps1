function Get-CAPolicy {
    <#
    .SYNOPSIS
        Retrieves all Conditional Access policies from the tenant.
    .DESCRIPTION
        Fetches all CA policies using Microsoft Graph, including enabled,
        disabled, and report-only policies.
    .PARAMETER IncludeDisabled
        Include policies in 'disabled' state.
    .PARAMETER IncludeReportOnly
        Include policies in 'enabledForReportingButNotEnforced' state.
    .EXAMPLE
        Get-CAPolicy
    .EXAMPLE
        Get-CAPolicy -IncludeDisabled -IncludeReportOnly
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludeDisabled,
        [switch]$IncludeReportOnly
    )

    Write-Verbose '[CAReporter] Retrieving Conditional Access policies...'

    $allPolicies = @()
    $uri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'

    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        $allPolicies += $response.value
        $uri = $response.'@odata.nextLink'
    } while ($uri)

    Write-Verbose "[CAReporter] Found $($allPolicies.Count) total CA policies"

    # Filter based on state
    $filtered = $allPolicies | Where-Object {
        $include = $false
        if ($_.state -eq 'enabled') { $include = $true }
        if ($IncludeReportOnly -and $_.state -eq 'enabledForReportingButNotEnforced') { $include = $true }
        if ($IncludeDisabled -and $_.state -eq 'disabled') { $include = $true }
        $include
    }

    $stateBreakdown = $allPolicies | Group-Object -Property state | ForEach-Object { "$($_.Name): $($_.Count)" }
    Write-Verbose "[CAReporter] Policy states: $($stateBreakdown -join ', ')"
    Write-Verbose "[CAReporter] Returning $($filtered.Count) policies after filtering"

    $filtered | Sort-Object displayName
}
