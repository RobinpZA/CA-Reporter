function Get-CAWhatIfReport {
    <#
    .SYNOPSIS
        One-command orchestrator that connects, gathers data, runs What-If analysis, and generates a report.
    .DESCRIPTION
        This is the main entry point for the CAReporter module. It:
        1. Verifies/establishes a Microsoft Graph connection
        2. Retrieves all Conditional Access policies
        3. Retrieves tenant users (with optional limits)
        4. Runs the What-If evaluation for each user against specified applications
        5. Generates a comprehensive HTML report

        Required Graph permissions: Policy.Read.All, Directory.Read.All, Application.Read.All
    .PARAMETER MaxUsers
        Maximum number of users to evaluate. Default 0 = all users.
    .PARAMETER Applications
        Array of application IDs to test against. Defaults to Office 365.
        Common IDs:
        - Office 365:                 67ad5377-2d78-4ac2-a867-6300cda00e85
        - Exchange Online:            00000002-0000-0ff1-ce00-000000000000
        - SharePoint Online:          00000003-0000-0ff1-ce00-000000000000
        - Azure Portal:               c44b4083-3bb0-49c1-b47d-974e53cbdf3c
        - Microsoft Graph:            00000003-0000-0000-c000-000000000000
        - Microsoft Teams:            cc15fd57-2c6c-4117-a88c-83b1d56b4bbe
        - Microsoft Intune:           0000000a-0000-0000-c000-000000000000
    .PARAMETER IncludeReportOnly
        Include report-only policies in the evaluation and report.
    .PARAMETER IncludeDisabled
        Include disabled policies in the report (they won't apply in What-If).
    .PARAMETER IncludeGuests
        Include guest users in the evaluation.
    .PARAMETER ExcludeDisabledUsers
        Exclude disabled user accounts from evaluation.
    .PARAMETER ClientAppType
        Client app type for the What-If simulation. Default: 'browser'.
        Values: browser, mobileAppsAndDesktopClients, exchangeActiveSync, easSupported, other
    .PARAMETER DevicePlatform
        Device platform for the simulation.
        Values: android, iOS, windows, windowsPhone, macOS, linux
    .PARAMETER SignInRiskLevel
        Sign-in risk level. Values: none, low, medium, high. Default: none.
    .PARAMETER UserRiskLevel
        User risk level. Values: none, low, medium, high. Default: none.
    .PARAMETER Country
        Two-letter country code for the simulation (e.g., 'US', 'GB', 'FR').
    .PARAMETER IpAddress
        IP address for the simulation.
    .PARAMETER OutputPath
        Path for the HTML report. Default: auto-generated with timestamp.
    .PARAMETER OpenReport
        Automatically open the generated report in the default browser.
    .PARAMETER ThrottleDelayMs
        Delay between Graph API calls in milliseconds. Default: 50.
    .PARAMETER SkipConnection
        Skip the connection step (assumes already connected).
    .EXAMPLE
        Get-CAWhatIfReport

        Connects to Graph, evaluates all users against Office 365, generates report.
    .EXAMPLE
        Get-CAWhatIfReport -MaxUsers 20 -OpenReport

        Evaluates first 20 users and opens the report.
    .EXAMPLE
        Get-CAWhatIfReport -Applications @('67ad5377-2d78-4ac2-a867-6300cda00e85','c44b4083-3bb0-49c1-b47d-974e53cbdf3c') -IncludeReportOnly -SignInRiskLevel 'high'

        Tests Office 365 and Azure Portal with high sign-in risk, includes report-only policies.
    .EXAMPLE
        Get-CAWhatIfReport -MaxUsers 100 -ExcludeDisabledUsers -ClientAppType 'mobileAppsAndDesktopClients' -DevicePlatform 'iOS'

        Tests 100 enabled users signing in from iOS mobile app.
    .EXAMPLE
        Get-CAWhatIfReport -Comprehensive -ScenarioProfile Thorough -MaxUsers 50 -OpenReport

        Runs comprehensive MFA gap analysis across 42 sign-in scenarios for 50 users.
    .EXAMPLE
        Get-CAWhatIfReport -Comprehensive -ScenarioProfile Standard -ComprehensiveCountries @('CN','RU') -OpenReport

        Standard scenarios plus country variants for China and Russia to test location-based policies.
    #>
    [CmdletBinding()]
    param(
        [int]$MaxUsers = 0,

        [string[]]$Applications = @('Office365'),

        [switch]$IncludeReportOnly,
        [switch]$IncludeDisabled,
        [switch]$IncludeGuests,
        [switch]$ExcludeDisabledUsers,

        [ValidateSet('browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'easSupported', 'other')]
        [string]$ClientAppType = 'browser',

        [ValidateSet('android', 'iOS', 'windows', 'windowsPhone', 'macOS', 'linux')]
        [string]$DevicePlatform,

        [ValidateSet('none', 'low', 'medium', 'high')]
        [string]$SignInRiskLevel = 'none',

        [ValidateSet('none', 'low', 'medium', 'high')]
        [string]$UserRiskLevel = 'none',

        [string]$Country,
        [string]$IpAddress,

        [string]$OutputPath,

        [switch]$OpenReport,

        [int]$ThrottleDelayMs = 50,

        [switch]$SkipConnection,

        [switch]$DisconnectWhenDone,

        [switch]$Comprehensive,

        [ValidateSet('Quick', 'Standard', 'Thorough')]
        [string]$ScenarioProfile = 'Standard',

        [string[]]$ComprehensiveCountries,

        [string[]]$ComprehensiveIpAddresses
    )

    $InformationPreference = 'Continue'
    $totalStart = Get-Date

    Write-Information '================================================================'
    Write-Information '  CA Reporter - Conditional Access What-If Analysis'
    Write-Information '================================================================'
    Write-Information ''

    # --- Step 1: Connection ---
    if (-not $SkipConnection) {
        $ctx = Get-MgContext
        if (-not $ctx) {
            Write-Information '[Step 1/5] Connecting to Microsoft Graph...'
            Connect-CAReporter
        }
        else {
            Write-Information "[Step 1/5] Already connected as $($ctx.Account) to tenant $($ctx.TenantId)"
        }
    }
    else {
        Write-Information '[Step 1/5] Skipping connection (SkipConnection specified)'
    }

    # --- Step 2: Get policies ---
    Write-Information ''
    Write-Information '[Step 2/5] Retrieving Conditional Access policies...'
    $policyParams = @{}
    if ($IncludeReportOnly) { $policyParams['IncludeReportOnly'] = $true }
    if ($IncludeDisabled)   { $policyParams['IncludeDisabled']   = $true }
    $policies = Get-CAPolicy @policyParams

    if ($policies.Count -eq 0) {
        Write-Warning '[CAReporter] No Conditional Access policies found. Aborting.'
        return
    }

    # --- Step 3: Get users ---
    Write-Information ''
    Write-Information '[Step 3/5] Retrieving tenant users...'
    $userParams = @{}
    if ($MaxUsers -gt 0)       { $userParams['MaxUsers']        = $MaxUsers }
    if ($IncludeGuests)        { $userParams['IncludeGuests']    = $true }
    if ($ExcludeDisabledUsers) { $userParams['ExcludeDisabled']  = $true }
    $users = Get-CATenantUsers @userParams

    if ($users.Count -eq 0) {
        Write-Warning '[CAReporter] No users found. Aborting.'
        return
    }

    # --- Step 3b: Build user CA fingerprints for deduplication ---
    # Groups users that share identical CA-relevant group/role memberships so we
    # only submit one evaluate API call per unique profile, then fan out results.
    Write-Information ''
    Write-Information '[Step 3b/5] Building user CA profiles for deduplication...'
    $fingerprintData = Get-UserCaFingerprints -Policies $policies -Users $users
    if ($fingerprintData.UniqueCount -lt $fingerprintData.TotalUsers) {
        $saved = $fingerprintData.TotalUsers - $fingerprintData.UniqueCount
        Write-Information "  Deduplication: $($fingerprintData.TotalUsers) users → $($fingerprintData.UniqueCount) unique CA profiles (saves ~$saved evaluate calls per scenario)"
    }
    else {
        Write-Information "  Deduplication: all $($fingerprintData.TotalUsers) users have distinct CA profiles (no savings)"
    }

    # --- Branch: Comprehensive vs. Single Scenario ---
    if ($Comprehensive) {
        # Build scenario matrix — pass policies for platform pruning
        $scenarioParams = @{ Profile = $ScenarioProfile; Policies = $policies }
        if ($PSBoundParameters.ContainsKey('Applications') -and
            ($Applications.Count -ne 1 -or $Applications[0] -ne 'Office365')) {
            $scenarioParams['Applications'] = $Applications
        }
        if ($ComprehensiveCountries)   { $scenarioParams['Countries']    = $ComprehensiveCountries }
        if ($ComprehensiveIpAddresses) { $scenarioParams['IpAddresses']  = $ComprehensiveIpAddresses }
        $scenarios = Get-ComprehensiveScenarios @scenarioParams
        $totalSteps = $scenarios.Count + 1  # +1 for report generation

        Write-Information ''
        Write-Information "[Step 4/$($scenarios.Count + 4)] Running comprehensive What-If analysis ($($scenarios.Count) scenarios)..."
        $evalCalls  = $fingerprintData.UniqueCount * $scenarios.Count
        $totalCalls = $fingerprintData.TotalUsers * $scenarios.Count
        Write-Information "  Profile: $ScenarioProfile | Users: $($users.Count) | Unique profiles: $($fingerprintData.UniqueCount) | Scenarios: $($scenarios.Count)"
        Write-Information "  Evaluate API calls: $evalCalls (vs $totalCalls without deduplication)"
        Write-Information ''

        $scenarioResults = [System.Collections.Generic.List[object]]::new()
        $scenarioIndex = 0

        foreach ($scenario in $scenarios) {
            $scenarioIndex++
            Write-Information "  [$scenarioIndex/$($scenarios.Count)] $($scenario.Label)"

            $analysisParams = @{
                Users              = $users
                Applications       = @($scenario.Application)
                Policies           = $policies
                ClientAppType      = $scenario.ClientAppType
                SignInRiskLevel    = 'none'
                UserRiskLevel      = 'none'
                ThrottleDelayMs    = $ThrottleDelayMs
                IncludeAllPolicies = $true
                ScenarioLabel      = $scenario.Label
            }
            if ($scenario.DevicePlatform) { $analysisParams['DevicePlatform'] = $scenario.DevicePlatform }
            # Scenario-level location takes precedence; fall back to top-level Country/IpAddress
            $effectiveCountry = if ($scenario.Country)   { $scenario.Country }   else { $Country }
            $effectiveIp      = if ($scenario.IpAddress) { $scenario.IpAddress } else { $IpAddress }
            if ($effectiveCountry) { $analysisParams['Country']   = $effectiveCountry }
            if ($effectiveIp)      { $analysisParams['IpAddress'] = $effectiveIp }

            # Stamp resolved location back onto scenario so the gap report legend can display it
            $scenario['EffectiveCountry']   = $effectiveCountry
            $scenario['EffectiveIpAddress'] = $effectiveIp

            $result = Invoke-CAWhatIfAnalysis @analysisParams -FingerprintData $fingerprintData
            $scenarioResults.Add($result)
        }

        # Generate gap report
        Write-Information ''
        Write-Information "[Step $($scenarios.Count + 4)/$($scenarios.Count + 4)] Generating gap analysis report..."
        $reportParams = @{
            ScenarioResults = $scenarioResults.ToArray()
            Scenarios       = $scenarios
            Policies        = $policies
        }
        if ($OutputPath)  { $reportParams['OutputPath'] = $OutputPath }
        if ($OpenReport)  { $reportParams['OpenReport']  = $true }

        $report = Export-CAGapReport @reportParams

        # --- Done ---
        $totalElapsed = (Get-Date) - $totalStart
        Write-Information ''
        Write-Information '================================================================'
        Write-Information '  Gap Analysis Complete!'
        Write-Information "  Total time: $($totalElapsed.ToString('mm\:ss'))"
        Write-Information "  Report: $($report.Path)"
        Write-Information "  Size: $([math]::Round($report.FileSize / 1KB, 1)) KB"
        Write-Information "  Coverage: $($report.CoveragePct)% fully covered, $($report.GapUsers) user(s) with gaps"
        Write-Information '================================================================'

        if ($DisconnectWhenDone) {
            Write-Information '[CAReporter] Disconnecting from Microsoft Graph...'
            Disconnect-MgGraph | Out-Null
            Write-Information '[CAReporter] Disconnected.'
        }

        [PSCustomObject]@{
            Report          = $report
            ScenarioResults = $scenarioResults.ToArray()
            Scenarios       = $scenarios
            Policies        = $policies
            Users           = $users
            Duration        = $totalElapsed
        }
    }
    else {
        # --- Step 4: What-If Analysis (single scenario) ---
        Write-Information ''
        Write-Information '[Step 4/5] Running What-If evaluations...'
        $analysisParams = @{
            Users           = $users
            Applications    = $Applications
            Policies        = $policies
            ClientAppType   = $ClientAppType
            SignInRiskLevel = $SignInRiskLevel
            UserRiskLevel   = $UserRiskLevel
            ThrottleDelayMs = $ThrottleDelayMs
            IncludeAllPolicies = $true
        }
        if ($DevicePlatform) { $analysisParams['DevicePlatform'] = $DevicePlatform }
        if ($Country)        { $analysisParams['Country']        = $Country }
        if ($IpAddress)      { $analysisParams['IpAddress']      = $IpAddress }

        $analysis = Invoke-CAWhatIfAnalysis @analysisParams -FingerprintData $fingerprintData

        # --- Step 5: Generate Report ---
        Write-Information ''
        Write-Information '[Step 5/5] Generating HTML report...'
        $reportParams = @{
            AnalysisResults = $analysis
            Policies        = $policies
        }
        if ($OutputPath)  { $reportParams['OutputPath'] = $OutputPath }
        if ($OpenReport)  { $reportParams['OpenReport']  = $true }

        $report = Export-CAReport @reportParams

        # --- Done ---
        $totalElapsed = (Get-Date) - $totalStart
        Write-Information ''
        Write-Information '================================================================'
        Write-Information '  Report Complete!'
        Write-Information "  Total time: $($totalElapsed.ToString('mm\:ss'))"
        Write-Information "  Report: $($report.Path)"
        Write-Information "  Size: $([math]::Round($report.FileSize / 1KB, 1)) KB"
        Write-Information '================================================================'

        if ($DisconnectWhenDone) {
            Write-Information '[CAReporter] Disconnecting from Microsoft Graph...'
            Disconnect-MgGraph | Out-Null
            Write-Information '[CAReporter] Disconnected.'
        }

        [PSCustomObject]@{
            Report        = $report
            Analysis      = $analysis
            Policies      = $policies
            Users         = $users
            Duration      = $totalElapsed
        }
    }
}
