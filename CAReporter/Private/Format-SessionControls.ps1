function Format-SessionControls {
    <#
    .SYNOPSIS
        Formats session controls from a What-If result into a human-readable string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $PolicyResult
    )

    if (-not $PolicyResult.sessionControls) {
        return 'None'
    }

    $sc = $PolicyResult.sessionControls
    $controls = @()

    if ($sc.applicationEnforcedRestrictions -and $sc.applicationEnforcedRestrictions.isEnabled) {
        $controls += 'App Enforced Restrictions'
    }
    if ($sc.cloudAppSecurity -and $sc.cloudAppSecurity.isEnabled) {
        $type = if ($sc.cloudAppSecurity.cloudAppSecurityType) { " ($($sc.cloudAppSecurity.cloudAppSecurityType))" } else { '' }
        $controls += "Cloud App Security$type"
    }
    if ($sc.signInFrequency -and $sc.signInFrequency.isEnabled) {
        $val = $sc.signInFrequency.value
        $unit = $sc.signInFrequency.type
        $controls += "Sign-in Frequency: $val $unit"
    }
    if ($sc.persistentBrowser -and $sc.persistentBrowser.isEnabled) {
        $mode = $sc.persistentBrowser.mode
        $controls += "Persistent Browser: $mode"
    }
    if ($sc.continuousAccessEvaluation -and $sc.continuousAccessEvaluation.mode) {
        $controls += "CAE: $($sc.continuousAccessEvaluation.mode)"
    }
    if ($sc.secureSignInSession) {
        $controls += 'Secure Sign-in Session'
    }

    if ($controls.Count -eq 0) { return 'None' }
    $controls -join ', '
}
