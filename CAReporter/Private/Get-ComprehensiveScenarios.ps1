function Get-ComprehensiveScenarios {
    <#
    .SYNOPSIS
        Builds a matrix of sign-in scenarios for comprehensive MFA gap analysis.
    .DESCRIPTION
        Returns an array of scenario hashtables covering:
        - Modern auth (browser + mobile/desktop) across multiple device platforms
        - Legacy auth (Exchange Active Sync, Other legacy protocols) — no platform dimension
        - Optional location variants for country- and IP-based policy testing
        - Optional policy-driven platform pruning: if no enabled policy uses platform
          conditions, platform-specific scenarios are collapsed to a single Any-platform
          scenario, avoiding redundant API calls without losing gap coverage.

        Scenario counts per profile (before location expansion):
        - Quick    :  1  (browser / any platform)
        - Standard : 18  (modern auth + EAS legacy)
        - Thorough : 42  (modern auth + EAS + other legacy)

        Each country or IP address in -Countries/-IpAddresses adds a full copy of the
        base scenarios tagged with that location, multiplying the total count accordingly.
    .PARAMETER Profile
        Scenario depth: Quick (1), Standard (18), or Thorough (42).
    .PARAMETER Applications
        Optional override for the application list. Replaces profile defaults.
        Accepts friendly names (e.g. 'Office365') or GUIDs.
    .PARAMETER Countries
        Optional list of two-letter country codes. Each code adds a full copy of the
        base scenarios tagged with that country. Useful for testing CA named locations
        and country-based Conditional Access policies. E.g. @('CN', 'RU', 'NG').
    .PARAMETER IpAddresses
        Optional list of IP addresses. Each IP adds a full copy of the base scenarios
        tagged with that address. Useful for testing trusted/untrusted named locations.
    .PARAMETER Policies
        Optional array of CA policy objects (from Get-CAPolicy). When supplied, the
        function inspects whether any enabled policy contains platform conditions. If
        none do, platform-specific scenarios are collapsed to a single Any-platform
        scenario per app/client combination — dramatically reducing scenario count
        without losing MFA gap coverage.
    .EXAMPLE
        Get-ComprehensiveScenarios -Profile Standard
    .EXAMPLE
        Get-ComprehensiveScenarios -Profile Thorough -Countries @('CN','RU') -IpAddresses @('10.0.0.1')
    .EXAMPLE
        Get-ComprehensiveScenarios -Profile Standard -Applications @('Office365','AzurePortal','MicrosoftGraph')
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Quick', 'Standard', 'Thorough')]
        [string]$Profile = 'Standard',

        [string[]]$Applications,

        [string[]]$Countries,

        [string[]]$IpAddresses,

        # When provided, enables policy-driven platform pruning.
        [array]$Policies
    )

    # --- Profile dimensions ---
    $profileApps = @{
        Quick    = @('Office365')
        Standard = @('Office365', 'AzurePortal')
        Thorough = @('Office365', 'AzurePortal', 'MicrosoftGraph')
    }
    $profileModernClients = @{
        Quick    = @('browser')
        Standard = @('browser', 'mobileAppsAndDesktopClients')
        Thorough = @('browser', 'mobileAppsAndDesktopClients')
    }
    # Legacy auth: EAS covers Exchange Active Sync, 'other' covers IMAP/POP/SMTP AUTH
    # Platform is irrelevant for legacy protocols — always tested without a platform filter
    $profileLegacyClients = @{
        Quick    = @()
        Standard = @('exchangeActiveSync')
        Thorough = @('exchangeActiveSync', 'other')
    }
    $profilePlatforms = @{
        Quick    = @('')
        Standard = @('windows', 'iOS', 'android', 'macOS')
        Thorough = @('windows', 'iOS', 'android', 'macOS', 'linux', '')
    }

    $apps          = if ($Applications) { $Applications } else { $profileApps[$Profile] }
    $modernClients = $profileModernClients[$Profile]
    $legacyClients = $profileLegacyClients[$Profile]
    $platforms     = $profilePlatforms[$Profile]

    # --- Policy-driven platform pruning -----------------------------------
    # If no enabled policy distinguishes between device platforms (no policy has a
    # platform condition), every platform variant produces identical CA results.
    # In that case, collapse to a single Any-platform scenario per app/client pair.
    if ($Policies) {
        $platformsInPolicies = $Policies | ForEach-Object {
            @($_.conditions.platforms.includePlatforms) + @($_.conditions.platforms.excludePlatforms)
        } | Where-Object { $_ } | Select-Object -Unique

        if ($platformsInPolicies.Count -eq 0) {
            # No policy cares about platform — keep only the 'Any' (empty) platform.
            $platforms = @('')
            Write-Verbose '[CAReporter] Platform pruning: no platform conditions in policies — collapsed to Any-platform scenarios'
        }
        else {
            # Keep only platforms actually referenced in policy conditions plus 'Any'.
            # 'Any' is retained so we always have a baseline scenario that catches
            # policies with no platform filter.
            $platforms = @('') + ($platformsInPolicies | Where-Object { $_ -in $platforms })
            $platforms = $platforms | Select-Object -Unique
            Write-Verbose "[CAReporter] Platform pruning: retained $($platforms.Count) platform(s) referenced in policies"
        }
    }

    $platformLabels = @{
        ''             = 'Any'
        'windows'      = 'Windows'
        'iOS'          = 'iOS'
        'android'      = 'Android'
        'macOS'        = 'macOS'
        'linux'        = 'Linux'
        'windowsPhone' = 'Windows Phone'
    }
    $clientLabels = @{
        'browser'                     = 'Browser'
        'mobileAppsAndDesktopClients' = 'Mobile/Desktop'
        'exchangeActiveSync'          = 'EAS (Legacy)'
        'easSupported'                = 'EAS Supported'
        'other'                       = 'Other (Legacy)'
    }

    # --- Phase 1: Build base scenarios ---
    $baseList = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($app in $apps) {
        # Modern auth: client × platform matrix
        foreach ($client in $modernClients) {
            foreach ($platform in $platforms) {
                $platLabel   = if ($platformLabels.ContainsKey($platform)) { $platformLabels[$platform] } else { $platform }
                $clientLabel = if ($clientLabels.ContainsKey($client))     { $clientLabels[$client] }     else { $client }
                $baseList.Add(@{
                    Application    = $app
                    ClientAppType  = $client
                    DevicePlatform = $platform
                    Country        = ''
                    IpAddress      = ''
                    LabelBody      = "$app / $clientLabel / $platLabel"
                })
            }
        }

        # Legacy auth: no platform dimension (protocol does not send platform info)
        foreach ($client in $legacyClients) {
            $clientLabel = if ($clientLabels.ContainsKey($client)) { $clientLabels[$client] } else { $client }
            $baseList.Add(@{
                Application    = $app
                ClientAppType  = $client
                DevicePlatform = ''
                Country        = ''
                IpAddress      = ''
                LabelBody      = "$app / $clientLabel / Any"
            })
        }
    }

    # --- Phase 2: Location variants ---
    $locationVariants = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($country in $Countries) {
        $code = $country.ToUpper()
        foreach ($base in $baseList) {
            $v = $base.Clone()
            $v['Country']   = $code
            $v['LabelBody'] = "$($base.LabelBody) [$code]"
            $locationVariants.Add($v)
        }
    }

    foreach ($ip in $IpAddresses) {
        foreach ($base in $baseList) {
            $v = $base.Clone()
            $v['IpAddress'] = $ip
            $v['LabelBody'] = "$($base.LabelBody) [IP: $ip]"
            $locationVariants.Add($v)
        }
    }

    # --- Phase 3: Combine, number, and finalise labels ---
    $allList = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($s in $baseList)         { $allList.Add($s) }
    foreach ($s in $locationVariants) { $allList.Add($s) }

    $idx = 1
    foreach ($scenario in $allList) {
        $scenario['Index'] = $idx
        $scenario['Label'] = "S${idx}: $($scenario.LabelBody)"
        $scenario.Remove('LabelBody')
        $idx++
    }

    , $allList.ToArray()
}
