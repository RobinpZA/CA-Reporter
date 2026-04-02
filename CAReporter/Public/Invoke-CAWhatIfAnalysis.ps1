function Invoke-CAWhatIfAnalysis {
    <#
    .SYNOPSIS
        Runs Conditional Access What-If evaluations for users against applications.
    .DESCRIPTION
        Uses the Microsoft Graph beta endpoint POST /identity/conditionalAccess/evaluate
        to simulate sign-in scenarios for each user against specified applications.
        Returns structured results showing which policies apply to each user.
    .PARAMETER Users
        Array of user objects (must have 'id' and 'userPrincipalName' properties).
    .PARAMETER Applications
        Array of application IDs to test. Defaults to common M365 apps.
    .PARAMETER Policies
        Optional pre-fetched policy array for enrichment. If not provided, policies
        are included in the response from the What-If API.
    .PARAMETER ClientAppType
        Client app type for the simulation. Default: 'browser'.
    .PARAMETER DevicePlatform
        Device platform for the simulation.
    .PARAMETER SignInRiskLevel
        Sign-in risk level. Default: 'none'.
    .PARAMETER UserRiskLevel
        User risk level. Default: 'none'.
    .PARAMETER Country
        Two-letter country code for the simulation.
    .PARAMETER IpAddress
        IP address for the simulation.
    .PARAMETER ThrottleDelayMs
        Delay in milliseconds between API calls to avoid throttling. Default: 50.
    .PARAMETER IncludeAllPolicies
        When set, returns all policies (not just applied ones) in results.
    .EXAMPLE
        $results = Invoke-CAWhatIfAnalysis -Users $users -Applications @('67ad5377-2d78-4ac2-a867-6300cda00e85')
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Users,

        [string[]]$Applications = @('Office365'),

        [array]$Policies,

        [string]$ClientAppType = 'browser',
        [string]$DevicePlatform,
        [string]$SignInRiskLevel = 'none',
        [string]$UserRiskLevel = 'none',
        [string]$Country,
        [string]$IpAddress,
        [int]$ThrottleDelayMs = 50,
        [switch]$IncludeAllPolicies,

        [string]$ScenarioLabel,

        # Pre-computed fingerprint data from Get-UserCaFingerprints.
        # When supplied, only one representative user per CA profile is evaluated;
        # results are then expanded to all users in that profile.
        [hashtable]$FingerprintData
    )

    # Resolve friendly application names to GUIDs
    $nameToGuid = @{}
    foreach ($kv in $script:AppCompletions.GetEnumerator()) { $nameToGuid[$kv.Key] = $kv.Value }
    $Applications = @($Applications | ForEach-Object {
        if ($nameToGuid.ContainsKey($_)) { $nameToGuid[$_] } else { $_ }
    })

    $uri = 'https://graph.microsoft.com/beta/identity/conditionalAccess/evaluate'

    # --- Build a set of auth strength policy IDs that are phishing-resistant ---
    # Fetch all auth strength policies once and classify each based on its
    # allowedCombinations. A strength is phishing-resistant only if every
    # combination it allows uses exclusively phishing-resistant methods.
    # Built-in phishing-resistant methods (per Microsoft Entra documentation):
    #   fido2, windowsHelloForBusiness, x509CertificateMultiFactor
    # Note: Passwordless MFA (built-in GUID ...0003) is NOT classified here
    # because its allowedCombinations include Authenticator passwordless which
    # is not phishing-resistant.
    $phishingResistantMethods = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($m in @('fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor')) {
        $phishingResistantMethods.Add($m) | Out-Null
    }

    $phishingResistantStrengthIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    try {
        $asUri = "https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies?`$select=id,displayName,allowedCombinations"
        $asResp = Invoke-MgGraphRequest -Method GET -Uri $asUri -ErrorAction Stop
        foreach ($as in $asResp.value) {
            if ($as.allowedCombinations -and $as.allowedCombinations.Count -gt 0) {
                $nonPhish = @($as.allowedCombinations | Where-Object { -not $phishingResistantMethods.Contains($_) })
                if ($nonPhish.Count -eq 0) {
                    $phishingResistantStrengthIds.Add($as.id) | Out-Null
                    Write-Verbose "[CAReporter]   Phishing-resistant auth strength detected: '$($as.displayName)' ($($as.id))"
                }
            }
        }
        Write-Verbose "[CAReporter] Auth strengths: $($asResp.value.Count) total, $($phishingResistantStrengthIds.Count) classified as phishing-resistant"
    }
    catch {
        Write-Verbose "[CAReporter] Could not fetch auth strength policies — falling back to built-in GUID: $_"
        # Fallback: Microsoft's built-in 'Phishing-resistant MFA' auth strength
        $phishingResistantStrengthIds.Add('00000000-0000-0000-0000-000000000004') | Out-Null
    }

    # When FingerprintData is provided, only evaluate representative users and
    # expand results to equivalent users afterwards.
    $usersToEvaluate = if ($FingerprintData) { $FingerprintData.Representatives } else { $Users }
    $actualUserCount = if ($FingerprintData) { $FingerprintData.TotalUsers }      else { $Users.Count }
    if ($FingerprintData) {
        Write-Verbose "[CAReporter] Deduplication active: evaluating $($usersToEvaluate.Count) representative users (covers $actualUserCount total)"
    }

    $totalTests = $usersToEvaluate.Count * $Applications.Count
    $results = [System.Collections.Generic.List[object]]::new()
    $appNameCache = @{}
    $counter = 0
    $errors = @()
    $startTime = Get-Date

    Write-Verbose "[CAReporter] Starting What-If analysis: $($usersToEvaluate.Count) users x $($Applications.Count) apps = $totalTests evaluations"

    foreach ($app in $Applications) {
        $appName = Resolve-AppDisplayName -AppId $app -AppNameCache $appNameCache
        Write-Verbose "[CAReporter]   Testing application: $appName ($app)"

        foreach ($user in $usersToEvaluate) {
            $counter++
            $pctComplete = [math]::Round(($counter / $totalTests) * 100, 1)
            $statusSuffix = if ($FingerprintData) { " [$($FingerprintData.UniqueCount) profiles / $actualUserCount users]" } else { '' }

            Write-Progress -Activity 'CA What-If Analysis' `
                -Status "$counter of $totalTests ($pctComplete%) - $($user.userPrincipalName)$statusSuffix" `
                -PercentComplete $pctComplete

            $bodyParams = @{
                UserId              = $user.id
                IncludeApplications = @($app)
                ClientAppType       = $ClientAppType
                SignInRiskLevel     = $SignInRiskLevel
                UserRiskLevel       = $UserRiskLevel
                AppliedPoliciesOnly = (-not $IncludeAllPolicies)
            }
            if ($DevicePlatform) { $bodyParams['DevicePlatform'] = $DevicePlatform }
            if ($Country) { $bodyParams['Country'] = $Country }
            if ($IpAddress) { $bodyParams['IpAddress'] = $IpAddress }

            $body = New-WhatIfRequestBody @bodyParams

            try {
                $response = Invoke-MgGraphRequest -Method POST -Uri $uri `
                    -Body ($body | ConvertTo-Json -Depth 10) `
                    -ContentType 'application/json' `
                    -ErrorAction Stop

                $policiesReturned = @($response.value)

                foreach ($policyResult in $policiesReturned) {
                    # Verbose: log any auth strength returned so admins can diagnose detection
                    if ($policyResult.grantControls.authenticationStrength) {
                        $as = $policyResult.grantControls.authenticationStrength
                        Write-Verbose "[CAReporter]   Auth strength in result — Policy: '$($policyResult.displayName)' | Id: '$($as.id)' | Name: '$($as.displayName)' | Combinations: $($as.allowedCombinations -join ', ')"
                    }
                    $results.Add([PSCustomObject]@{
                        UserId              = $user.id
                        UserPrincipalName   = $user.userPrincipalName
                        UserDisplayName     = $user.displayName
                        UserType            = $user.userType
                        ApplicationId       = $app
                        ApplicationName     = $appName
                        PolicyId            = $policyResult.id
                        PolicyDisplayName   = $policyResult.displayName
                        PolicyState         = $policyResult.state
                        PolicyApplies       = $policyResult.policyApplies
                        AnalysisReasons     = $policyResult.analysisReasons
                        GrantControls       = (Format-GrantControls -PolicyResult $policyResult)
                        GrantControlsRaw    = $policyResult.grantControls
                        SessionControls     = (Format-SessionControls -PolicyResult $policyResult)
                        SessionControlsRaw  = $policyResult.sessionControls
                        PolicyConditions    = $policyResult.conditions
                        IsBlocking          = ($policyResult.grantControls.builtInControls -contains 'block')
                        RequiresMfa         = (
                            ($policyResult.grantControls.builtInControls -contains 'mfa') -or
                            ($policyResult.grantControls.authenticationStrength.requirementsSatisfied -eq 'mfa')
                        )
                        RequiresCompliance  = ($policyResult.grantControls.builtInControls -contains 'compliantDevice')
                        RequiresHybridJoin  = ($policyResult.grantControls.builtInControls -contains 'domainJoinedDevice')
                        RequiresPhishingResistantMfa = (& {
                            $as = $policyResult.grantControls.authenticationStrength
                            if (-not $as) { return $false }
                            # Primary: match by policy ID from pre-fetched classified set
                            if ($as.id -and $phishingResistantStrengthIds.Contains($as.id)) { return $true }
                            # Fallback: classify from allowedCombinations returned in this response.
                            # The evaluate API may not return an id even when a strength is applied.
                            if ($as.allowedCombinations -and $as.allowedCombinations.Count -gt 0) {
                                $nonPhish = @($as.allowedCombinations |
                                    Where-Object { -not $phishingResistantMethods.Contains($_) })
                                if ($nonPhish.Count -eq 0) {
                                    Write-Verbose "[CAReporter]   Auth strength '$($as.displayName)' classified as phishing-resistant via allowedCombinations (id not matched in pre-fetch)"
                                    return $true
                                }
                            }
                            return $false
                        })
                        AuthStrengthName    = $policyResult.grantControls.authenticationStrength.displayName
                        ScenarioLabel       = $ScenarioLabel
                        Timestamp           = (Get-Date).ToString('o')
                    })
                }

                # If no policies returned for this user/app combo, record a "no policy" entry
                if ($policiesReturned.Count -eq 0 -and -not $IncludeAllPolicies) {
                    $results.Add([PSCustomObject]@{
                        UserId              = $user.id
                        UserPrincipalName   = $user.userPrincipalName
                        UserDisplayName     = $user.displayName
                        UserType            = $user.userType
                        ApplicationId       = $app
                        ApplicationName     = $appName
                        PolicyId            = $null
                        PolicyDisplayName   = '(No policies applied)'
                        PolicyState         = 'N/A'
                        PolicyApplies       = $false
                        AnalysisReasons     = 'noPoliciesApplied'
                        GrantControls       = 'None'
                        GrantControlsRaw    = $null
                        SessionControls     = 'None'
                        SessionControlsRaw  = $null
                        PolicyConditions    = $null
                        IsBlocking          = $false
                        RequiresMfa         = $false
                        RequiresCompliance  = $false
                        RequiresHybridJoin  = $false
                        ScenarioLabel       = $ScenarioLabel
                        Timestamp           = (Get-Date).ToString('o')
                    })
                }
            }
            catch {
                $errMsg = $_.Exception.Message
                Write-Warning "[CAReporter] Error evaluating user $($user.userPrincipalName) for app $appName : $errMsg"
                $errors += @{
                    User    = $user.userPrincipalName
                    App     = $appName
                    Error   = $errMsg
                }

                $results.Add([PSCustomObject]@{
                    UserId              = $user.id
                    UserPrincipalName   = $user.userPrincipalName
                    UserDisplayName     = $user.displayName
                    UserType            = $user.userType
                    ApplicationId       = $app
                    ApplicationName     = $appName
                    PolicyId            = $null
                    PolicyDisplayName   = '(Evaluation Error)'
                    PolicyState         = 'error'
                    PolicyApplies       = $false
                    AnalysisReasons     = "error: $errMsg"
                    GrantControls       = 'Error'
                    GrantControlsRaw    = $null
                    SessionControls     = 'Error'
                    SessionControlsRaw  = $null
                    PolicyConditions    = $null
                    IsBlocking          = $false
                    RequiresMfa         = $false
                    RequiresCompliance  = $false
                    RequiresHybridJoin  = $false
                    ScenarioLabel       = $ScenarioLabel
                    Timestamp           = (Get-Date).ToString('o')
                })

                # Throttling - back off on 429
                if ($errMsg -match '429|throttl') {
                    Write-Warning '[CAReporter] Throttled by Graph API. Waiting 30 seconds...'
                    Start-Sleep -Seconds 30
                }
            }

            if ($ThrottleDelayMs -gt 0) {
                Start-Sleep -Milliseconds $ThrottleDelayMs
            }
        }
    }

    Write-Progress -Activity 'CA What-If Analysis' -Completed

    # ── Fan out representative results to equivalent users ───────────────────
    if ($FingerprintData -and $FingerprintData.EquivalentUsers.Count -gt 0) {
        $repResults = $results.ToArray()
        foreach ($repId in $FingerprintData.EquivalentUsers.Keys) {
            $equivalents = $FingerprintData.EquivalentUsers[$repId] | Where-Object { $_.id -ne $repId }
            if (-not $equivalents) { continue }
            $repUserResults = $repResults | Where-Object { $_.UserId -eq $repId }
            foreach ($eqUser in $equivalents) {
                foreach ($r in $repUserResults) {
                    $results.Add([PSCustomObject]@{
                        UserId              = $eqUser.id
                        UserPrincipalName   = $eqUser.userPrincipalName
                        UserDisplayName     = $eqUser.displayName
                        UserType            = $eqUser.userType
                        ApplicationId       = $r.ApplicationId
                        ApplicationName     = $r.ApplicationName
                        PolicyId            = $r.PolicyId
                        PolicyDisplayName   = $r.PolicyDisplayName
                        PolicyState         = $r.PolicyState
                        PolicyApplies       = $r.PolicyApplies
                        AnalysisReasons     = $r.AnalysisReasons
                        GrantControls       = $r.GrantControls
                        GrantControlsRaw    = $r.GrantControlsRaw
                        SessionControls     = $r.SessionControls
                        SessionControlsRaw  = $r.SessionControlsRaw
                        PolicyConditions    = $r.PolicyConditions
                        IsBlocking                   = $r.IsBlocking
                        RequiresMfa                  = $r.RequiresMfa
                        RequiresCompliance           = $r.RequiresCompliance
                        RequiresHybridJoin           = $r.RequiresHybridJoin
                        RequiresPhishingResistantMfa = $r.RequiresPhishingResistantMfa
                        AuthStrengthName             = $r.AuthStrengthName
                        ScenarioLabel                = $r.ScenarioLabel
                        Timestamp                    = $r.Timestamp
                    })
                }
            }
        }
    }

    $elapsed = (Get-Date) - $startTime
    Write-Verbose "[CAReporter] Analysis complete: $($results.Count) results in $($elapsed.ToString('mm\:ss'))"
    if ($errors.Count -gt 0) {
        Write-Verbose "[CAReporter] Encountered $($errors.Count) errors during evaluation"
    }

    [PSCustomObject]@{
        Results      = $results.ToArray()
        Errors       = $errors
        Summary      = @{
            TotalUsers         = $actualUserCount
            UniqueProfiles     = if ($FingerprintData) { $FingerprintData.UniqueCount } else { $null }
            TotalApps          = $Applications.Count
            TotalEvaluations   = $totalTests
            TotalResults       = $results.Count
            TotalErrors        = $errors.Count
            Duration           = $elapsed
            Timestamp          = (Get-Date).ToString('o')
            Applications       = $Applications
            ApplicationNames   = @($Applications | ForEach-Object { Resolve-AppDisplayName -AppId $_ -AppNameCache $appNameCache })
            ScenarioLabel      = $ScenarioLabel
            ClientAppType      = $ClientAppType
            DevicePlatform     = $DevicePlatform
            SignInRiskLevel    = $SignInRiskLevel
            UserRiskLevel      = $UserRiskLevel
            Country            = $Country
            IpAddress          = $IpAddress
        }
    }
}
