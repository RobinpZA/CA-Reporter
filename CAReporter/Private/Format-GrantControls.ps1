function Format-GrantControls {
    <#
    .SYNOPSIS
        Formats grant controls from a What-If result into a human-readable string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $PolicyResult
    )

    if (-not $PolicyResult.grantControls) {
        return 'None (Session controls only)'
    }

    $gc = $PolicyResult.grantControls
    $controls = @()

    if ($gc.builtInControls) {
        foreach ($ctrl in $gc.builtInControls) {
            switch ($ctrl) {
                'mfa'                            { $controls += 'Require MFA' }
                'block'                          { $controls += 'Block Access' }
                'compliantDevice'                { $controls += 'Require Compliant Device' }
                'domainJoinedDevice'             { $controls += 'Require Hybrid Azure AD Join' }
                'approvedApplication'            { $controls += 'Require Approved App' }
                'compliantApplication'           { $controls += 'Require App Protection Policy' }
                'passwordChange'                 { $controls += 'Require Password Change' }
                default                          { $controls += $ctrl }
            }
        }
    }

    if ($gc.authenticationStrength) {
        $controls += "Auth Strength: $($gc.authenticationStrength.displayName)"
    }

    if ($gc.termsOfUse -and $gc.termsOfUse.Count -gt 0) {
        $controls += "Terms of Use ($($gc.termsOfUse.Count))"
    }

    $operator = if ($gc.operator) { " $($gc.operator) " } else { ' AND ' }
    ($controls -join $operator).Trim()
}
