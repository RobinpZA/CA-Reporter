function Export-CAReport {
    <#
    .SYNOPSIS
        Generates a comprehensive, filterable HTML report from CA What-If analysis results.
    .DESCRIPTION
        Takes the output from Invoke-CAWhatIfAnalysis and generates a rich HTML report with:
        - Executive summary with key metrics
        - Policy inventory table
        - User-Policy impact matrix (heatmap)
        - Detailed per-user findings
        - Grant/session controls breakdown
        - Interactive filtering and search
    .PARAMETER AnalysisResults
        The output object from Invoke-CAWhatIfAnalysis.
    .PARAMETER Policies
        Array of CA policy objects from Get-CAPolicy.
    .PARAMETER OutputPath
        Path for the HTML report file.
    .PARAMETER TenantName
        Optional display name for the tenant.
    .PARAMETER OpenReport
        Automatically open the report in the default browser.
    .EXAMPLE
        Export-CAReport -AnalysisResults $analysis -Policies $policies -OutputPath '.\CAReport.html'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        $AnalysisResults,

        [Parameter(Mandatory)]
        [array]$Policies,

        [string]$OutputPath = ".\CA-WhatIf-Report_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').html",

        [string]$TenantName,

        [switch]$OpenReport
    )

    Write-Verbose '[CAReporter] Generating HTML report...'

    $results = $AnalysisResults.Results
    $summary = $AnalysisResults.Summary
    $errors  = $AnalysisResults.Errors

    # Determine tenant name
    if (-not $TenantName) {
        try {
            $org = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=displayName' -ErrorAction Stop
            $TenantName = $org.value[0].displayName
        }
        catch {
            $TenantName = 'M365 Tenant'
        }
    }

    # ----- Compute summary statistics -----
    # Only count enforced (enabled) policies for the summary cards
    $enabledPolicyIds = @($Policies | Where-Object { $_.state -eq 'enabled' }).id
    $enforcedResults  = @($results | Where-Object { $_.PolicyApplies -eq $true -and $_.PolicyId -in $enabledPolicyIds })

    $uniqueUsers    = @($results | Select-Object -Property UserId -Unique)
    $uniquePolicies = @($results | Where-Object { $_.PolicyId } | Select-Object -Property PolicyId -Unique)
    $appliedResults = @($results | Where-Object { $_.PolicyApplies -eq $true })

    $usersWithBlock = @($enforcedResults | Where-Object { $_.IsBlocking } | Select-Object -Property UserId -Unique)
    $usersWithMfa   = @($enforcedResults | Where-Object { $_.RequiresMfa } | Select-Object -Property UserId -Unique)
    # A user has "no policies" only if no enabled policy applies to them
    $usersWithEnforcedPolicy = @($enforcedResults | Select-Object -Property UserId -Unique)
    $usersNoPolicies = @($uniqueUsers | Where-Object { $_.UserId -notin $usersWithEnforcedPolicy.UserId })

    $pctMfaCoverage = if ($uniqueUsers.Count -gt 0) { [math]::Round(($usersWithMfa.Count / $uniqueUsers.Count) * 100, 1) } else { 0 }
    $pctBlocked     = if ($uniqueUsers.Count -gt 0) { [math]::Round(($usersWithBlock.Count / $uniqueUsers.Count) * 100, 1) } else { 0 }
    $pctNone        = if ($uniqueUsers.Count -gt 0) { [math]::Round(($usersNoPolicies.Count / $uniqueUsers.Count) * 100, 1) } else { 0 }

    # ----- Build policy summary data -----
    $policySummaryRows = ''
    foreach ($policy in $Policies) {
        $pId = $policy.id
        $stateClass = switch ($policy.state) {
            'enabled'                              { 'state-enabled' }
            'enabledForReportingButNotEnforced'     { 'state-reportonly' }
            'disabled'                             { 'state-disabled' }
            default                                { '' }
        }
        $stateLabel = switch ($policy.state) {
            'enabled'                              { 'Enabled' }
            'enabledForReportingButNotEnforced'     { 'Report-Only' }
            'disabled'                             { 'Disabled' }
            default                                { $policy.state }
        }

        $affectedUserCount = @($results | Where-Object { $_.PolicyId -eq $pId -and $_.PolicyApplies }).UserId | Select-Object -Unique | Measure-Object | Select-Object -ExpandProperty Count

        # Grant controls from policy
        $grantText = 'None'
        if ($policy.grantControls) {
            $ctrls = @()
            if ($policy.grantControls.builtInControls) {
                $ctrls += $policy.grantControls.builtInControls
            }
            if ($policy.grantControls.authenticationStrength) {
                $ctrls += "AuthStrength:$($policy.grantControls.authenticationStrength.displayName)"
            }
            if ($ctrls.Count -gt 0) {
                $op = if ($policy.grantControls.operator) { " $($policy.grantControls.operator) " } else { ' AND ' }
                $grantText = $ctrls -join $op
            }
        }

        # Applications
        $apps = @()
        if ($policy.conditions -and $policy.conditions.applications) {
            $appCond = $policy.conditions.applications
            if ($appCond.includeApplications) {
                $apps = $appCond.includeApplications
            }
        }
        $appText = if ($apps -contains 'All') { 'All Apps' }
                   elseif ($apps -contains 'Office365') { 'Office 365' }
                   elseif ($apps -contains 'MicrosoftAdminPortals') { 'Admin Portals' }
                   elseif ($apps.Count -gt 3) { "$($apps.Count) apps" }
                   elseif ($apps.Count -gt 0) { $apps -join ', ' }
                   else { 'N/A' }

        # Users scope
        $userScope = 'Unknown'
        if ($policy.conditions -and $policy.conditions.users) {
            $uc = $policy.conditions.users
            if ($uc.includeUsers -contains 'All') { $userScope = 'All Users' }
            elseif ($uc.includeUsers -contains 'GuestsOrExternalUsers') { $userScope = 'Guests/External' }
            elseif ($uc.includeGroups -and $uc.includeGroups.Count -gt 0) { $userScope = "$($uc.includeGroups.Count) group(s)" }
            elseif ($uc.includeRoles -and $uc.includeRoles.Count -gt 0) { $userScope = "$($uc.includeRoles.Count) role(s)" }
            elseif ($uc.includeUsers -and $uc.includeUsers.Count -gt 0) { $userScope = "$($uc.includeUsers.Count) user(s)" }
        }

        $escapedName = [System.Net.WebUtility]::HtmlEncode($policy.displayName)
        $escapedGrant = [System.Net.WebUtility]::HtmlEncode($grantText)
        $escapedApp = [System.Net.WebUtility]::HtmlEncode($appText)
        $escapedScope = [System.Net.WebUtility]::HtmlEncode($userScope)

        $policySummaryRows += @"
            <tr data-policy-id="$pId" data-state="$($policy.state)">
                <td>$escapedName</td>
                <td><span class="badge $stateClass">$stateLabel</span></td>
                <td>$escapedScope</td>
                <td>$escapedApp</td>
                <td>$escapedGrant</td>
                <td class="text-center">$affectedUserCount</td>
            </tr>
"@
    }

    # ----- Build user impact matrix -----
    $matrixPolicies = @($Policies | Where-Object { $_.state -ne 'disabled' } | Sort-Object displayName)
    $matrixUsers = @($results | Select-Object UserId, UserPrincipalName, UserDisplayName -Unique | Sort-Object UserPrincipalName)

    # Build header columns for matrix
    $matrixHeaderCols = ''
    foreach ($p in $matrixPolicies) {
        $shortName = [System.Net.WebUtility]::HtmlEncode($p.displayName)
        if ($shortName.Length -gt 30) { $shortName = $shortName.Substring(0, 27) + '...' }
        $matrixHeaderCols += "<th class='matrix-col-header' title='$([System.Net.WebUtility]::HtmlEncode($p.displayName))'>$shortName</th>`n"
    }

    # Build matrix rows
    $matrixRows = ''
    $matrixRowCount = 0
    foreach ($u in $matrixUsers) {
        $matrixRowCount++
        $escapedUpn = [System.Net.WebUtility]::HtmlEncode($u.UserPrincipalName)
        $escapedName = [System.Net.WebUtility]::HtmlEncode($u.UserDisplayName)

        $cells = ''
        foreach ($p in $matrixPolicies) {
            $match = $results | Where-Object {
                $_.UserId -eq $u.UserId -and $_.PolicyId -eq $p.id -and $_.PolicyApplies -eq $true
            } | Select-Object -First 1

            if ($match) {
                if ($match.IsBlocking) {
                    $cells += "<td class='matrix-cell cell-block' title='Block'>B</td>"
                }
                elseif ($match.RequiresPhishingResistantMfa) {
                    $cells += "<td class='matrix-cell cell-phishing-resistant' title='Phishing-Resistant MFA'>PR</td>"
                }
                elseif ($match.RequiresMfa -and $match.RequiresCompliance) {
                    $cells += "<td class='matrix-cell cell-mfa-compliance' title='MFA + Device Compliance'>MC</td>"
                }
                elseif ($match.RequiresMfa) {
                    $cells += "<td class='matrix-cell cell-mfa' title='MFA Required'>M</td>"
                }
                elseif ($match.RequiresCompliance) {
                    $cells += "<td class='matrix-cell cell-compliance' title='Device Compliance'>C</td>"
                }
                else {
                    $cells += "<td class='matrix-cell cell-grant' title='Grant with controls'>G</td>"
                }
            }
            else {
                $cells += "<td class='matrix-cell cell-na' title='Not Applied'>-</td>"
            }
        }

        $matrixRows += "<tr><td class='matrix-user' title='$escapedUpn'>$escapedName</td>$cells</tr>`n"
    }

    # ----- Build detailed findings rows -----
    $detailRows = ''
    foreach ($r in ($results | Sort-Object UserPrincipalName, PolicyDisplayName)) {
        $statusClass = if ($r.PolicyApplies -and $r.IsBlocking) { 'status-block' }
                       elseif ($r.PolicyApplies -and $r.RequiresMfa) { 'status-mfa' }
                       elseif ($r.PolicyApplies) { 'status-grant' }
                       elseif ($r.PolicyState -eq 'error') { 'status-error' }
                       else { 'status-na' }

        $statusText = if ($r.PolicyApplies -and $r.IsBlocking) { 'Blocked' }
                      elseif ($r.PolicyApplies -and $r.RequiresMfa) { 'MFA Required' }
                      elseif ($r.PolicyApplies) { 'Applied' }
                      elseif ($r.PolicyState -eq 'error') { 'Error' }
                      elseif ($r.AnalysisReasons -eq 'noPoliciesApplied') { 'No Policies' }
                      else { 'Not Applied' }

        $escapedUpn = [System.Net.WebUtility]::HtmlEncode($r.UserPrincipalName)
        $escapedDisplay = [System.Net.WebUtility]::HtmlEncode($r.UserDisplayName)
        $escapedPolicy = [System.Net.WebUtility]::HtmlEncode($r.PolicyDisplayName)
        $escapedApp = [System.Net.WebUtility]::HtmlEncode($r.ApplicationName)
        $escapedGrant = [System.Net.WebUtility]::HtmlEncode($r.GrantControls)
        $escapedSession = [System.Net.WebUtility]::HtmlEncode($r.SessionControls)

        $detailRows += @"
            <tr class="detail-row" data-status="$statusText" data-policy="$escapedPolicy" data-user="$escapedUpn" data-app="$escapedApp">
                <td title="$escapedUpn">$escapedDisplay</td>
                <td>$escapedUpn</td>
                <td>$escapedApp</td>
                <td>$escapedPolicy</td>
                <td><span class="badge $statusClass">$statusText</span></td>
                <td>$escapedGrant</td>
                <td>$escapedSession</td>
            </tr>
"@
    }

    # ----- Effective outcome per user -----
    # Block always wins. Otherwise, the user must satisfy the UNION of all
    # grant controls required across every applied policy.
    # Only consider enabled (enforced) policies — report-only policies are informational only.
    $effectiveOutcomeRows = ''
    foreach ($u in $matrixUsers) {
        $userResults = @($results | Where-Object { $_.UserId -eq $u.UserId -and $_.PolicyApplies -eq $true -and $_.PolicyId -in $enabledPolicyIds })
        $escapedName = [System.Net.WebUtility]::HtmlEncode($u.UserDisplayName)
        $escapedUpn = [System.Net.WebUtility]::HtmlEncode($u.UserPrincipalName)

        $isBlocked = $false
        $blockingPolicy = ''
        $requiresMfa = $false
        $requiresCompliance = $false
        $requiresHybridJoin = $false
        $otherControls = [System.Collections.Generic.List[string]]::new()

        foreach ($r in $userResults) {
            if ($r.IsBlocking) {
                $isBlocked = $true
                if (-not $blockingPolicy) { $blockingPolicy = $r.PolicyDisplayName }
            }
            if ($r.RequiresMfa)        { $requiresMfa = $true }
            if ($r.RequiresCompliance) { $requiresCompliance = $true }
            if ($r.RequiresHybridJoin) { $requiresHybridJoin = $true }
            # Collect any additional grant control text not already covered
            if ($r.GrantControls -and $r.GrantControls -ne 'None' -and $r.GrantControls -ne 'Error') {
                foreach ($ctrl in ($r.GrantControls -split ' AND | OR ')) {
                    $ctrl = $ctrl.Trim()
                    if ($ctrl -and $ctrl -notin @('Require MFA','Require Compliant Device','Require Hybrid Azure AD Join','Block') -and $ctrl -notin $otherControls) {
                        $otherControls.Add($ctrl)
                    }
                }
            }
        }

        $totalApplied = $userResults.Count
        $allPolicies = ($userResults | ForEach-Object { [System.Net.WebUtility]::HtmlEncode($_.PolicyDisplayName) }) -join ', '
        if (-not $allPolicies) { $allPolicies = '(None)' }

        if ($isBlocked) {
            $effectiveAction = 'Blocked'
            $effectiveClass = 'status-block'
            $requirements = 'Access denied'
            $determiningInfo = [System.Net.WebUtility]::HtmlEncode($blockingPolicy)
        }
        elseif ($totalApplied -eq 0) {
            $effectiveAction = 'No Policies'
            $effectiveClass = 'status-na'
            $requirements = 'None'
            $determiningInfo = '(None)'
        }
        else {
            $effectiveAction = 'Grant'
            $effectiveClass = 'status-grant'
            $reqParts = [System.Collections.Generic.List[string]]::new()
            if ($requiresMfa)        { $reqParts.Add('MFA') }
            if ($requiresCompliance) { $reqParts.Add('Compliant Device') }
            if ($requiresHybridJoin) { $reqParts.Add('Hybrid Azure AD Join') }
            foreach ($c in $otherControls) { $reqParts.Add($c) }
            if ($reqParts.Count -eq 0) { $reqParts.Add('Grant with Controls') }
            $requirements = ($reqParts | ForEach-Object { [System.Net.WebUtility]::HtmlEncode($_) }) -join ' + '
            $determiningInfo = $allPolicies
        }

        $effectiveOutcomeRows += @"
            <tr data-outcome="$effectiveAction">
                <td title="$escapedUpn">$escapedName</td>
                <td>$escapedUpn</td>
                <td><span class="badge $effectiveClass">$effectiveAction</span></td>
                <td>$requirements</td>
                <td title="$allPolicies">$determiningInfo</td>
                <td class="text-center">$totalApplied</td>
            </tr>
"@
    }

    # ----- Coverage gap users -----
    $gapRows = ''
    foreach ($u in $usersNoPolicies) {
        $userObj = $results | Where-Object { $_.UserId -eq $u.UserId } | Select-Object -First 1
        $escapedUpn = [System.Net.WebUtility]::HtmlEncode($userObj.UserPrincipalName)
        $escapedName = [System.Net.WebUtility]::HtmlEncode($userObj.UserDisplayName)
        $escapedType = [System.Net.WebUtility]::HtmlEncode($userObj.UserType)
        $gapRows += "<tr><td>$escapedName</td><td>$escapedUpn</td><td>$escapedType</td></tr>`n"
    }

    # ----- Error rows -----
    $errorRows = ''
    foreach ($e in $errors) {
        $escapedUser = [System.Net.WebUtility]::HtmlEncode($e.User)
        $escapedApp = [System.Net.WebUtility]::HtmlEncode($e.App)
        $escapedErr = [System.Net.WebUtility]::HtmlEncode($e.Error)
        $errorRows += "<tr><td>$escapedUser</td><td>$escapedApp</td><td>$escapedErr</td></tr>`n"
    }

    # ----- Scenario parameters -----
    $appNamesDisplay = if ($summary.ApplicationNames -and $summary.ApplicationNames.Count -gt 0) {
        ($summary.ApplicationNames | ForEach-Object { [System.Net.WebUtility]::HtmlEncode($_) }) -join ', '
    } else { 'Office 365' }

    $scenarioInfo = @"
        <div class="scenario-params">
            <span><strong>Applications:</strong> $appNamesDisplay</span>
            <span><strong>Client App:</strong> $([System.Net.WebUtility]::HtmlEncode($summary.ClientAppType))</span>
            <span><strong>Platform:</strong> $(if ($summary.DevicePlatform) { [System.Net.WebUtility]::HtmlEncode($summary.DevicePlatform) } else { 'Any' })</span>
            <span><strong>Sign-in Risk:</strong> $([System.Net.WebUtility]::HtmlEncode($summary.SignInRiskLevel))</span>
            <span><strong>User Risk:</strong> $([System.Net.WebUtility]::HtmlEncode($summary.UserRiskLevel))</span>
            <span><strong>Country:</strong> $(if ($summary.Country) { [System.Net.WebUtility]::HtmlEncode($summary.Country) } else { 'Any' })</span>
            <span><strong>IP:</strong> $(if ($summary.IpAddress) { [System.Net.WebUtility]::HtmlEncode($summary.IpAddress) } else { 'Any' })</span>
            <span><strong>Users Evaluated:</strong> $($summary.TotalUsers)</span>
        </div>
"@

    $escapedTenantName = [System.Net.WebUtility]::HtmlEncode($TenantName)
    $reportDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $durationStr = $summary.Duration.ToString('mm\:ss')

    # ----- Full HTML -----
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CA What-If Report - $escapedTenantName</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Sora:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');

        :root {
            --bg-primary:    #050d1a;
            --bg-secondary:  #091524;
            --bg-card:       #0c1e35;
            --bg-hover:      #122540;
            --text-primary:  #ddeeff;
            --text-secondary:#6b95bb;
            --text-muted:    #2f4d66;
            --border-color:  #162d4a;
            --accent-blue:   #00aaff;
            --accent-green:  #00e676;
            --accent-orange: #ffa726;
            --accent-red:    #ff3366;
            --accent-purple: #b24fff;
            --accent-cyan:   #00e5ff;
            --glow-blue:     rgba(0, 170, 255, 0.3);
            --glow-green:    rgba(0, 230, 118, 0.25);
            --glow-red:      rgba(255, 51, 102, 0.3);
            --glow-orange:   rgba(255, 167, 38, 0.25);
            --glow-purple:   rgba(178, 79, 255, 0.25);
            --glow-cyan:     rgba(0, 229, 255, 0.25);
            --font-sans: 'Sora', -apple-system, 'Segoe UI', sans-serif;
            --font-mono: 'JetBrains Mono', 'Cascadia Code', monospace;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: var(--font-sans);
            background-color: var(--bg-primary);
            background-image:
                radial-gradient(ellipse 80% 50% at 20% 20%, rgba(0, 80, 180, 0.12) 0%, transparent 60%),
                radial-gradient(ellipse 60% 40% at 80% 80%, rgba(0, 30, 100, 0.1) 0%, transparent 60%),
                radial-gradient(circle, #162d4a 1px, transparent 1px);
            background-size: 100% 100%, 100% 100%, 30px 30px;
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }

        .container { max-width: 1600px; margin: 0 auto; padding: 28px 24px; }

        /* Header */
        .header {
            position: relative;
            background: linear-gradient(135deg, #0a1e3d 0%, #060e1e 60%, #0a1428 100%);
            border: 1px solid var(--border-color);
            border-radius: 14px;
            padding: 36px 36px 28px;
            margin-bottom: 24px;
            overflow: hidden;
        }
        .header::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 2px;
            background: linear-gradient(90deg, transparent 0%, var(--accent-cyan) 40%, var(--accent-blue) 60%, transparent 100%);
        }
        .header::after {
            content: '';
            position: absolute;
            top: -100px; right: -100px;
            width: 340px; height: 340px;
            background: radial-gradient(circle, rgba(0, 170, 255, 0.06) 0%, transparent 70%);
            pointer-events: none;
        }
        .header h1 {
            font-size: 28px;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: linear-gradient(135deg, #ffffff 30%, var(--accent-cyan) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 6px;
        }
        .header .subtitle {
            color: var(--accent-blue);
            font-size: 13px;
            font-weight: 500;
            letter-spacing: 0.3px;
        }
        .header-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 16px;
        }
        .header-meta span {
            font-family: var(--font-mono);
            font-size: 11px;
            color: var(--text-muted);
            padding: 4px 10px;
            background: rgba(22, 45, 74, 0.5);
            border: 1px solid var(--border-color);
            border-radius: 4px;
        }

        /* Summary cards */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
            gap: 14px;
            margin-bottom: 24px;
        }
        .summary-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 22px 20px;
            text-align: center;
            position: relative;
            overflow: hidden;
            transition: transform 0.2s ease, border-color 0.2s ease;
        }
        .summary-card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 2px;
        }
        .summary-card:hover { transform: translateY(-2px); border-color: rgba(255,255,255,0.08); }
        .summary-card .value {
            font-size: 40px;
            font-weight: 800;
            font-family: var(--font-mono);
            line-height: 1.1;
            letter-spacing: -1px;
        }
        .summary-card .label {
            color: var(--text-secondary);
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            margin-top: 6px;
        }
        .value-blue   { color: var(--accent-blue);   text-shadow: 0 0 24px var(--glow-blue); }
        .value-green  { color: var(--accent-green);  text-shadow: 0 0 24px var(--glow-green); }
        .value-orange { color: var(--accent-orange); text-shadow: 0 0 24px var(--glow-orange); }
        .value-red    { color: var(--accent-red);    text-shadow: 0 0 24px var(--glow-red); }
        .value-purple { color: var(--accent-purple); text-shadow: 0 0 24px var(--glow-purple); }
        .value-cyan   { color: var(--accent-cyan);   text-shadow: 0 0 24px var(--glow-cyan); }
        .summary-card:has(.value-blue)::before   { background: linear-gradient(90deg, transparent, var(--accent-blue), transparent); }
        .summary-card:has(.value-green)::before  { background: linear-gradient(90deg, transparent, var(--accent-green), transparent); }
        .summary-card:has(.value-orange)::before { background: linear-gradient(90deg, transparent, var(--accent-orange), transparent); }
        .summary-card:has(.value-red)::before    { background: linear-gradient(90deg, transparent, var(--accent-red), transparent); }
        .summary-card:has(.value-purple)::before { background: linear-gradient(90deg, transparent, var(--accent-purple), transparent); }
        .summary-card:has(.value-cyan)::before   { background: linear-gradient(90deg, transparent, var(--accent-cyan), transparent); }

        /* Scenario */
        .scenario-params {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 14px 20px;
            margin-bottom: 24px;
            font-family: var(--font-mono);
            font-size: 11px;
        }
        .scenario-params span {
            color: var(--text-secondary);
            padding: 3px 10px;
            background: rgba(22, 45, 74, 0.5);
            border: 1px solid var(--border-color);
            border-radius: 4px;
        }
        .scenario-params strong { color: var(--accent-blue); font-weight: 600; }

        /* Sections */
        .section {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 24px;
            border-bottom: 1px solid var(--border-color);
            cursor: pointer;
            user-select: none;
            transition: background 0.15s ease;
        }
        .section-header:hover { background: var(--bg-hover); }
        .section-header h2 {
            font-size: 14px;
            font-weight: 700;
            letter-spacing: -0.1px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .section-header h2::before {
            content: '';
            display: inline-block;
            width: 3px;
            height: 16px;
            background: var(--accent-blue);
            border-radius: 2px;
            box-shadow: 0 0 8px var(--glow-blue);
            flex-shrink: 0;
        }
        .section-header .toggle { color: var(--text-muted); font-size: 16px; transition: transform 0.2s ease; }
        .section-body { padding: 0; }
        .section-body.collapsed { display: none; }

        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }
        thead th {
            background: var(--bg-secondary);
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 10px;
            letter-spacing: 0.8px;
            padding: 11px 16px;
            text-align: left;
            position: sticky;
            top: 0;
            z-index: 10;
            border-bottom: 1px solid var(--border-color);
        }
        thead th:first-child { border-left: 2px solid var(--accent-blue); }
        tbody td {
            padding: 10px 16px;
            border-bottom: 1px solid rgba(22, 45, 74, 0.6);
            vertical-align: middle;
        }
        tbody tr:nth-child(even) { background: rgba(9, 21, 36, 0.4); }
        tbody tr:hover { background: var(--bg-hover); }
        .text-center { text-align: center; }

        /* Badges */
        .badge {
            display: inline-flex;
            align-items: center;
            padding: 3px 9px;
            border-radius: 5px;
            font-family: var(--font-mono);
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.4px;
            border: 1px solid;
        }
        .state-enabled    { background: rgba(0, 230, 118, 0.1);  color: #00e676; border-color: rgba(0, 230, 118, 0.3); }
        .state-reportonly { background: rgba(255, 167, 38, 0.1); color: #ffa726; border-color: rgba(255, 167, 38, 0.3); }
        .state-disabled   { background: rgba(60, 80, 100, 0.15); color: #4a6a8a; border-color: rgba(60, 80, 100, 0.25); }
        .status-block  { background: rgba(255, 51, 102, 0.12); color: #ff3366; border-color: rgba(255, 51, 102, 0.35); }
        .status-mfa    { background: rgba(255, 167, 38, 0.12); color: #ffa726; border-color: rgba(255, 167, 38, 0.35); }
        .status-grant  { background: rgba(0, 230, 118, 0.1);  color: #00e676; border-color: rgba(0, 230, 118, 0.3); }
        .status-na     { background: rgba(30, 50, 70, 0.3);   color: #3d5a7a; border-color: rgba(30, 50, 70, 0.4); }
        .status-error  { background: rgba(178, 79, 255, 0.12); color: #b24fff; border-color: rgba(178, 79, 255, 0.35); }

        /* Matrix */
        .matrix-wrapper {
            overflow-x: auto;
            max-height: 600px;
            overflow-y: auto;
        }
        .matrix-wrapper table { font-size: 11px; }
        .matrix-col-header {
            writing-mode: vertical-rl;
            text-orientation: mixed;
            white-space: nowrap;
            max-width: 36px;
            padding: 8px 4px !important;
            font-size: 9px !important;
        }
        .matrix-user {
            white-space: nowrap;
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            position: sticky;
            left: 0;
            background: var(--bg-card);
            z-index: 5;
        }
        .matrix-cell {
            text-align: center;
            font-family: var(--font-mono);
            font-weight: 700;
            font-size: 10px;
            width: 34px;
            min-width: 34px;
            padding: 4px !important;
        }
        .cell-block              { background: rgba(255, 51, 102, 0.2);  color: #ff3366; }
        .cell-phishing-resistant { background: rgba(0, 229, 255, 0.15); color: #00e5ff; font-size: 0.6rem; letter-spacing: -0.5px; }
        .cell-mfa                { background: rgba(255, 167, 38, 0.2);  color: #ffa726; }
        .cell-compliance         { background: rgba(0, 170, 255, 0.15); color: #00aaff; }
        .cell-mfa-compliance     { background: rgba(178, 79, 255, 0.18); color: #b24fff; font-size: 0.6rem; letter-spacing: -0.5px; }
        .cell-grant              { background: rgba(0, 230, 118, 0.15); color: #00e676; }
        .cell-na                 { background: transparent; color: var(--text-muted); }

        /* Filters */
        .filter-bar {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            padding: 14px 20px;
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            align-items: center;
        }
        .filter-bar label {
            color: var(--text-muted);
            font-family: var(--font-mono);
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.8px;
        }
        .filter-bar input, .filter-bar select {
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: var(--text-primary);
            padding: 7px 12px;
            font-size: 12px;
            font-family: var(--font-sans);
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
        }
        .filter-bar input:focus, .filter-bar select:focus {
            outline: none;
            border-color: var(--accent-blue);
            box-shadow: 0 0 0 3px var(--glow-blue);
        }
        .filter-bar input[type=text] { min-width: 220px; }
        .result-count {
            margin-left: auto;
            color: var(--text-muted);
            font-family: var(--font-mono);
            font-size: 11px;
        }

        /* Legend */
        .legend {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            padding: 12px 20px;
            font-size: 11px;
            color: var(--text-secondary);
            border-bottom: 1px solid var(--border-color);
            background: rgba(9, 21, 36, 0.4);
        }
        .legend-item { display: flex; align-items: center; gap: 6px; }
        .legend-swatch {
            width: 22px; height: 22px;
            border-radius: 4px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-family: var(--font-mono);
            font-weight: 700;
            font-size: 9px;
        }

        /* Animations */
        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(10px); }
            to   { opacity: 1; transform: translateY(0); }
        }
        .header          { animation: fadeInUp 0.4s ease both; }
        .scenario-params { animation: fadeInUp 0.4s ease 0.05s both; }
        .summary-card    { animation: fadeInUp 0.4s ease both; }
        .summary-card:nth-child(1) { animation-delay: 0.10s; }
        .summary-card:nth-child(2) { animation-delay: 0.15s; }
        .summary-card:nth-child(3) { animation-delay: 0.20s; }
        .summary-card:nth-child(4) { animation-delay: 0.25s; }
        .summary-card:nth-child(5) { animation-delay: 0.30s; }
        .summary-card:nth-child(6) { animation-delay: 0.35s; }
        .section         { animation: fadeInUp 0.4s ease 0.2s both; }

        /* Print */
        @media print {
            body { background: #fff; color: #000; background-image: none; }
            .section-header .toggle { display: none; }
            .section-body.collapsed { display: block !important; }
            .filter-bar { display: none; }
            .header::before, .header::after { display: none; }
        }

        /* Scrollbar */
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: var(--bg-primary); }
        ::-webkit-scrollbar-thumb { background: var(--border-color); border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }

        /* Footer */
        .footer {
            text-align: center;
            padding: 24px;
            color: var(--text-muted);
            font-family: var(--font-mono);
            font-size: 11px;
            border-top: 1px solid var(--border-color);
            margin-top: 4px;
        }

        /* Tab switcher */
        .tab-bar {
            display: flex;
            gap: 0;
            border-bottom: 1px solid var(--border-color);
        }
        .tab-btn {
            padding: 10px 22px;
            background: none;
            border: none;
            color: var(--text-muted);
            font-family: var(--font-sans);
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            margin-bottom: -1px;
            transition: color 0.15s ease;
        }
        .tab-btn:hover { color: var(--text-secondary); }
        .tab-btn.active { color: var(--accent-blue); border-bottom-color: var(--accent-blue); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
    </style>
</head>
<body>
<div class="container">
    <!-- Header -->
    <div class="header">
        <h1>Conditional Access What-If Report</h1>
        <div class="subtitle">$escapedTenantName</div>
        <div class="header-meta">
            <span>Generated: $reportDate</span>
            <span>Duration: $durationStr</span>
            <span>Evaluations: $($summary.TotalEvaluations)</span>
        </div>
    </div>

    <!-- Scenario Parameters -->
    $scenarioInfo

    <!-- Summary Cards -->
    <div class="summary-grid">
        <div class="summary-card">
            <div class="value value-blue">$($uniqueUsers.Count)</div>
            <div class="label">Users Evaluated</div>
        </div>
        <div class="summary-card">
            <div class="value value-purple">$($Policies.Count)</div>
            <div class="label">CA Policies</div>
        </div>
        <div class="summary-card">
            <div class="value value-green">$pctMfaCoverage%</div>
            <div class="label">Users with MFA Policy</div>
        </div>
        <div class="summary-card">
            <div class="value value-red">$pctBlocked%</div>
            <div class="label">Users with Block Policy</div>
        </div>
        <div class="summary-card">
            <div class="value value-orange">$($usersNoPolicies.Count)</div>
            <div class="label">Users with No Policies</div>
        </div>
        <div class="summary-card">
            <div class="value value-cyan">$($errors.Count)</div>
            <div class="label">Evaluation Errors</div>
        </div>
    </div>

    <!-- Policy Inventory -->
    <div class="section">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Policy Inventory ($($Policies.Count) policies)</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-body">
            <div class="filter-bar">
                <label>Filter:</label>
                <input type="text" id="policyFilter" placeholder="Search policies..." oninput="filterPolicyTable()">
                <select id="policyStateFilter" onchange="filterPolicyTable()">
                    <option value="">All States</option>
                    <option value="enabled">Enabled</option>
                    <option value="enabledForReportingButNotEnforced">Report-Only</option>
                    <option value="disabled">Disabled</option>
                </select>
            </div>
            <div style="overflow-x: auto;">
                <table id="policyTable">
                    <thead>
                        <tr>
                            <th>Policy Name</th>
                            <th>State</th>
                            <th>User Scope</th>
                            <th>Applications</th>
                            <th>Grant Controls</th>
                            <th class="text-center">Users Affected</th>
                        </tr>
                    </thead>
                    <tbody>
                        $policySummaryRows
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- User-Policy Impact Matrix -->
    <div class="section">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>User-Policy Impact Matrix ($matrixRowCount users x $($matrixPolicies.Count) policies)</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-body">
            <div class="legend">
                <div class="legend-item"><span class="legend-swatch" style="background:#7f1d1d;">B</span> Block</div>
                <div class="legend-item"><span class="legend-swatch" style="background:#0f3330;color:#2dd4bf;font-size:0.65rem;letter-spacing:-0.5px;">PR</span> Phishing-Resistant MFA</div>
                <div class="legend-item"><span class="legend-swatch" style="background:#78350f;">M</span> Standard MFA</div>
                <div class="legend-item"><span class="legend-swatch" style="background:#1e3a5f;">C</span> Device Compliance</div>
                <div class="legend-item"><span class="legend-swatch" style="background:#4a2060;font-size:0.6rem;letter-spacing:-0.5px;">MC</span> MFA + Device Compliance</div>
                <div class="legend-item"><span class="legend-swatch" style="background:#14532d;">G</span> Grant with Controls</div>
                <div class="legend-item"><span class="legend-swatch" style="background:transparent;color:#64748b;border:1px solid #334155;">-</span> Not Applied</div>
            </div>
            <div class="filter-bar">
                <label>Search Users:</label>
                <input type="text" id="matrixUserFilter" placeholder="Filter by user name..." oninput="filterMatrix()">
            </div>
            <div class="matrix-wrapper">
                <table id="matrixTable">
                    <thead>
                        <tr>
                            <th style="position:sticky;left:0;z-index:11;background:var(--bg-primary);">User</th>
                            $matrixHeaderCols
                        </tr>
                    </thead>
                    <tbody>
                        $matrixRows
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Effective Outcome per User -->
    <div class="section">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Effective Outcome per User ($($matrixUsers.Count) users)</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-body">
            <div style="padding: 14px 20px; background: var(--bg-primary); border-bottom: 1px solid var(--border-color); font-size: 12px; color: var(--text-secondary);">
                <strong>How this works:</strong> <span class="badge status-block">Block</span> always overrides all other controls &mdash; if any policy blocks, access is denied.
                Otherwise, the user must satisfy the <strong>combined requirements</strong> from all applied policies (e.g., MFA + Compliant Device).
                Hover over the policies column to see all contributing policies.
            </div>
            <div class="filter-bar">
                <label>Search:</label>
                <input type="text" id="effectiveSearch" placeholder="Filter by user..." oninput="filterEffective()">
                <select id="effectiveStatusFilter" onchange="filterEffective()">
                    <option value="">All Outcomes</option>
                    <option value="Blocked">Blocked</option>
                    <option value="Grant">Grant</option>
                    <option value="No Policies">No Policies</option>
                </select>
                <span class="result-count" id="effectiveCount"></span>
            </div>
            <div style="overflow-x: auto; max-height: 600px; overflow-y: auto;">
                <table id="effectiveTable">
                    <thead>
                        <tr>
                            <th>Display Name</th>
                            <th>UPN</th>
                            <th>Effective Outcome</th>
                            <th>Combined Requirements</th>
                            <th>Policies</th>
                            <th class="text-center">Total Applied</th>
                        </tr>
                    </thead>
                    <tbody>
                        $effectiveOutcomeRows
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Detailed Findings -->
    <div class="section">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Detailed Findings ($($results.Count) results)</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-body">
            <div class="filter-bar">
                <label>Search:</label>
                <input type="text" id="detailSearch" placeholder="User, policy, or app..." oninput="filterDetails()">
                <select id="detailStatusFilter" onchange="filterDetails()">
                    <option value="">All Statuses</option>
                    <option value="Blocked">Blocked</option>
                    <option value="MFA Required">MFA Required</option>
                    <option value="Applied">Applied</option>
                    <option value="Not Applied">Not Applied</option>
                    <option value="No Policies">No Policies</option>
                    <option value="Error">Error</option>
                </select>
                <span class="result-count" id="detailCount"></span>
            </div>
            <div style="overflow-x: auto; max-height: 700px; overflow-y: auto;">
                <table id="detailTable">
                    <thead>
                        <tr>
                            <th>Display Name</th>
                            <th>UPN</th>
                            <th>Application</th>
                            <th>Policy</th>
                            <th>Status</th>
                            <th>Grant Controls</th>
                            <th>Session Controls</th>
                        </tr>
                    </thead>
                    <tbody>
                        $detailRows
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Coverage Gaps -->
    $(if ($usersNoPolicies.Count -gt 0) { @"
    <div class="section">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Coverage Gaps ($($usersNoPolicies.Count) users with no applied policies)</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-body">
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr><th>Display Name</th><th>UPN</th><th>User Type</th></tr>
                    </thead>
                    <tbody>
                        $gapRows
                    </tbody>
                </table>
            </div>
        </div>
    </div>
"@ })

    <!-- Errors -->
    $(if ($errors.Count -gt 0) { @"
    <div class="section">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Evaluation Errors ($($errors.Count))</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-body">
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr><th>User</th><th>Application</th><th>Error</th></tr>
                    </thead>
                    <tbody>
                        $errorRows
                    </tbody>
                </table>
            </div>
        </div>
    </div>
"@ })

    <!-- Footer -->
    <div class="footer">
        CA What-If Report generated by CAReporter PowerShell Module v1.0.0<br>
        Using Microsoft Graph Beta API &mdash; POST /identity/conditionalAccess/evaluate
    </div>
</div>

<script>
    // Section toggle
    function toggleSection(header) {
        const body = header.nextElementSibling;
        const toggle = header.querySelector('.toggle');
        body.classList.toggle('collapsed');
        toggle.innerHTML = body.classList.contains('collapsed') ? '&#9654;' : '&#9660;';
    }

    // Policy table filter
    function filterPolicyTable() {
        const search = document.getElementById('policyFilter').value.toLowerCase();
        const state = document.getElementById('policyStateFilter').value;
        const rows = document.querySelectorAll('#policyTable tbody tr');
        rows.forEach(r => {
            const text = r.textContent.toLowerCase();
            const rowState = r.getAttribute('data-state');
            const matchText = !search || text.includes(search);
            const matchState = !state || rowState === state;
            r.style.display = (matchText && matchState) ? '' : 'none';
        });
    }

    // Matrix filter
    function filterMatrix() {
        const search = document.getElementById('matrixUserFilter').value.toLowerCase();
        const rows = document.querySelectorAll('#matrixTable tbody tr');
        rows.forEach(r => {
            const user = r.querySelector('.matrix-user');
            if (user) {
                const text = (user.textContent + ' ' + (user.getAttribute('title') || '')).toLowerCase();
                r.style.display = (!search || text.includes(search)) ? '' : 'none';
            }
        });
    }

    // Detail table filter
    function filterDetails() {
        const search = document.getElementById('detailSearch').value.toLowerCase();
        const status = document.getElementById('detailStatusFilter').value;
        const rows = document.querySelectorAll('#detailTable tbody tr');
        let visible = 0;
        rows.forEach(r => {
            const text = r.textContent.toLowerCase();
            const rowStatus = r.getAttribute('data-status');
            const matchText = !search || text.includes(search);
            const matchStatus = !status || rowStatus === status;
            const show = matchText && matchStatus;
            r.style.display = show ? '' : 'none';
            if (show) visible++;
        });
        document.getElementById('detailCount').textContent = visible + ' of ' + rows.length + ' results';
    }

    // Effective outcome filter
    function filterEffective() {
        const search = document.getElementById('effectiveSearch').value.toLowerCase();
        const status = document.getElementById('effectiveStatusFilter').value;
        const rows = document.querySelectorAll('#effectiveTable tbody tr');
        let visible = 0;
        rows.forEach(r => {
            const text = r.textContent.toLowerCase();
            const rowOutcome = r.getAttribute('data-outcome') || '';
            const matchText = !search || text.includes(search);
            const matchStatus = !status || rowOutcome === status;
            const show = matchText && matchStatus;
            r.style.display = show ? '' : 'none';
            if (show) visible++;
        });
        document.getElementById('effectiveCount').textContent = visible + ' of ' + rows.length + ' users';
    }

    // Animate summary card counters on load
    function animateValue(el) {
        const raw = el.textContent.trim();
        const pct = raw.endsWith('%');
        const num = parseFloat(raw);
        if (isNaN(num)) return;
        const dur = 900, start = performance.now();
        (function step(now) {
            const t = Math.min((now - start) / dur, 1);
            const ease = 1 - Math.pow(1 - t, 3);
            const cur = num * ease;
            el.textContent = (Number.isInteger(num) ? Math.round(cur) : cur.toFixed(1)) + (pct ? '%' : '');
            if (t < 1) requestAnimationFrame(step);
        })(start);
    }

    // Initialize counts
    document.addEventListener('DOMContentLoaded', () => {
        filterDetails();
        filterEffective();
        document.querySelectorAll('.summary-card .value').forEach(animateValue);
    });
</script>
</body>
</html>
"@

    # Write file
    $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

    if ($PSCmdlet.ShouldProcess($resolvedPath, 'Write HTML report')) {
        $html | Out-File -FilePath $resolvedPath -Encoding utf8 -Force

        Write-Verbose "[CAReporter] Report saved to: $resolvedPath"

        if ($OpenReport) {
            Start-Process $resolvedPath
        }

        [PSCustomObject]@{
            Path     = $resolvedPath
            FileSize = (Get-Item $resolvedPath).Length
        }
    }
}
