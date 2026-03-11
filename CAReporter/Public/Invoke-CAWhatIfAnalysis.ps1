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
        [switch]$IncludeAllPolicies
    )

    # Resolve friendly application names to GUIDs
    $nameToGuid = @{}
    foreach ($kv in $script:AppCompletions.GetEnumerator()) { $nameToGuid[$kv.Key] = $kv.Value }
    $Applications = @($Applications | ForEach-Object {
        if ($nameToGuid.ContainsKey($_)) { $nameToGuid[$_] } else { $_ }
    })

    $uri = 'https://graph.microsoft.com/beta/identity/conditionalAccess/evaluate'
    $totalTests = $Users.Count * $Applications.Count
    $results = [System.Collections.Generic.List[object]]::new()
    $appNameCache = @{}
    $counter = 0
    $errors = @()
    $startTime = Get-Date

    Write-Host "[CAReporter] Starting What-If analysis: $($Users.Count) users x $($Applications.Count) apps = $totalTests evaluations" -ForegroundColor Cyan

    foreach ($app in $Applications) {
        $appName = Resolve-AppDisplayName -AppId $app -AppNameCache $appNameCache
        Write-Host "[CAReporter]   Testing application: $appName ($app)" -ForegroundColor DarkGray

        foreach ($user in $Users) {
            $counter++
            $pctComplete = [math]::Round(($counter / $totalTests) * 100, 1)

            Write-Progress -Activity 'CA What-If Analysis' `
                -Status "$counter of $totalTests ($pctComplete%) - $($user.userPrincipalName)" `
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
    $elapsed = (Get-Date) - $startTime

    Write-Host "[CAReporter] Analysis complete: $($results.Count) results in $($elapsed.ToString('mm\:ss'))" -ForegroundColor Green
    if ($errors.Count -gt 0) {
        Write-Host "[CAReporter] Encountered $($errors.Count) errors during evaluation" -ForegroundColor Yellow
    }

    [PSCustomObject]@{
        Results      = $results.ToArray()
        Errors       = $errors
        Summary      = @{
            TotalUsers        = $Users.Count
            TotalApps         = $Applications.Count
            TotalEvaluations  = $totalTests
            TotalResults      = $results.Count
            TotalErrors       = $errors.Count
            Duration          = $elapsed
            Timestamp         = (Get-Date).ToString('o')
            Applications      = $Applications
            ApplicationNames  = @($Applications | ForEach-Object { Resolve-AppDisplayName -AppId $_ -AppNameCache $appNameCache })
            ClientAppType     = $ClientAppType
            DevicePlatform    = $DevicePlatform
            SignInRiskLevel   = $SignInRiskLevel
            UserRiskLevel     = $UserRiskLevel
            Country           = $Country
            IpAddress         = $IpAddress
        }
    }
}
