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

    Write-Host '[CAReporter] Retrieving Conditional Access policies...' -ForegroundColor Cyan

    $allPolicies = @()
    $uri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'

    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        $allPolicies += $response.value
        $uri = $response.'@odata.nextLink'
    } while ($uri)

    Write-Host "[CAReporter] Found $($allPolicies.Count) total CA policies" -ForegroundColor Green

    # Filter based on state
    $filtered = $allPolicies | Where-Object {
        $include = $false
        if ($_.state -eq 'enabled') { $include = $true }
        if ($IncludeReportOnly -and $_.state -eq 'enabledForReportingButNotEnforced') { $include = $true }
        if ($IncludeDisabled -and $_.state -eq 'disabled') { $include = $true }
        $include
    }

    $stateBreakdown = $allPolicies | Group-Object -Property state | ForEach-Object { "$($_.Name): $($_.Count)" }
    Write-Host "[CAReporter] Policy states: $($stateBreakdown -join ', ')" -ForegroundColor DarkGray
    Write-Host "[CAReporter] Returning $($filtered.Count) policies after filtering" -ForegroundColor Green

    $filtered | Sort-Object displayName
}
