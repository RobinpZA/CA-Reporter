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

        [switch]$DisconnectWhenDone
    )

    $totalStart = Get-Date

    # Resolve friendly application names to GUIDs
    $appMap = (Get-WellKnownAppId)
    $nameToGuid = @{}
    foreach ($kv in $script:AppCompletions.GetEnumerator()) { $nameToGuid[$kv.Key] = $kv.Value }
    $Applications = @($Applications | ForEach-Object {
        if ($nameToGuid.ContainsKey($_)) { $nameToGuid[$_] } else { $_ }
    })

    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host '  CA Reporter - Conditional Access What-If Analysis' -ForegroundColor Cyan
    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host ''

    # --- Step 1: Connection ---
    if (-not $SkipConnection) {
        $ctx = Get-MgContext
        if (-not $ctx) {
            Write-Host '[Step 1/5] Connecting to Microsoft Graph...' -ForegroundColor Yellow
            Connect-CAReporter
        }
        else {
            Write-Host "[Step 1/5] Already connected as $($ctx.Account) to tenant $($ctx.TenantId)" -ForegroundColor Green
        }
    }
    else {
        Write-Host '[Step 1/5] Skipping connection (SkipConnection specified)' -ForegroundColor DarkGray
    }

    # --- Step 2: Get policies ---
    Write-Host '' -ForegroundColor Cyan
    Write-Host '[Step 2/5] Retrieving Conditional Access policies...' -ForegroundColor Yellow
    $policyParams = @{}
    if ($IncludeReportOnly) { $policyParams['IncludeReportOnly'] = $true }
    if ($IncludeDisabled)   { $policyParams['IncludeDisabled']   = $true }
    $policies = Get-CAPolicy @policyParams

    if ($policies.Count -eq 0) {
        Write-Warning '[CAReporter] No Conditional Access policies found. Aborting.'
        return
    }

    # --- Step 3: Get users ---
    Write-Host '' -ForegroundColor Cyan
    Write-Host '[Step 3/5] Retrieving tenant users...' -ForegroundColor Yellow
    $userParams = @{}
    if ($MaxUsers -gt 0)       { $userParams['MaxUsers']        = $MaxUsers }
    if ($IncludeGuests)        { $userParams['IncludeGuests']    = $true }
    if ($ExcludeDisabledUsers) { $userParams['ExcludeDisabled']  = $true }
    $users = Get-CATenantUsers @userParams

    if ($users.Count -eq 0) {
        Write-Warning '[CAReporter] No users found. Aborting.'
        return
    }

    # --- Step 4: What-If Analysis ---
    Write-Host '' -ForegroundColor Cyan
    Write-Host '[Step 4/5] Running What-If evaluations...' -ForegroundColor Yellow
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

    $analysis = Invoke-CAWhatIfAnalysis @analysisParams

    # --- Step 5: Generate Report ---
    Write-Host '' -ForegroundColor Cyan
    Write-Host '[Step 5/5] Generating HTML report...' -ForegroundColor Yellow
    $reportParams = @{
        AnalysisResults = $analysis
        Policies        = $policies
    }
    if ($OutputPath)  { $reportParams['OutputPath'] = $OutputPath }
    if ($OpenReport)  { $reportParams['OpenReport']  = $true }

    $report = Export-CAReport @reportParams

    # --- Done ---
    $totalElapsed = (Get-Date) - $totalStart
    Write-Host '' -ForegroundColor Cyan
    Write-Host '================================================================' -ForegroundColor Green
    Write-Host '  Report Complete!' -ForegroundColor Green
    Write-Host "  Total time: $($totalElapsed.ToString('mm\:ss'))" -ForegroundColor Green
    Write-Host "  Report: $($report.Path)" -ForegroundColor Green
    Write-Host "  Size: $([math]::Round($report.FileSize / 1KB, 1)) KB" -ForegroundColor Green
    Write-Host '================================================================' -ForegroundColor Green

    if ($DisconnectWhenDone) {
        Write-Host '[CAReporter] Disconnecting from Microsoft Graph...' -ForegroundColor Yellow
        Disconnect-MgGraph | Out-Null
        Write-Host '[CAReporter] Disconnected.' -ForegroundColor Green
    }

    [PSCustomObject]@{
        Report        = $report
        Analysis      = $analysis
        Policies      = $policies
        Users         = $users
        Duration      = $totalElapsed
    }
}
