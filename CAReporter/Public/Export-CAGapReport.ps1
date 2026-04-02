function Export-CAGapReport {
    <#
    .SYNOPSIS
        Generates a gap-focused HTML report from comprehensive What-If analysis results.
    .DESCRIPTION
        Aggregates results from multiple sign-in scenarios to show per-user MFA coverage
        across all tested conditions. Highlights users who lack MFA protection under
        specific scenarios, producing a heatmap and detailed gap table.
    .PARAMETER ScenarioResults
        Array of analysis result objects (from Invoke-CAWhatIfAnalysis), one per scenario.
    .PARAMETER Scenarios
        Array of scenario hashtables from Get-ComprehensiveScenarios.
    .PARAMETER Policies
        Array of CA policy objects from Get-CAPolicy.
    .PARAMETER OutputPath
        Path for the HTML report file.
    .PARAMETER TenantName
        Optional display name for the tenant.
    .PARAMETER OpenReport
        Automatically open the report in the default browser.
    .EXAMPLE
        Export-CAGapReport -ScenarioResults $results -Scenarios $scenarios -Policies $policies -OpenReport
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [array]$ScenarioResults,

        [Parameter(Mandatory)]
        [array]$Scenarios,

        [Parameter(Mandatory)]
        [array]$Policies,

        [string]$OutputPath = ".\CA-GapReport_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').html",

        [string]$TenantName,

        [switch]$OpenReport
    )

    Write-Verbose '[CAReporter] Generating gap analysis report...'

    # Determine tenant name
    if (-not $TenantName) {
        try {
            $org = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=displayName' -ErrorAction Stop
            $TenantName = $org.value[0].displayName
        }
        catch {
            $TenantName = 'Unknown Tenant'
        }
    }

    # --- Build per-user per-scenario coverage map ---
    # Key: UserPrincipalName, Value: hashtable of scenario index → status
    $userMap = [ordered]@{}
    $enabledPolicyIds = @($Policies | Where-Object { $_.state -eq 'enabled' } | ForEach-Object { $_.id })

    for ($si = 0; $si -lt $ScenarioResults.Count; $si++) {
        $scenarioIndex = $si + 1
        $results = $ScenarioResults[$si].Results

        # Group results by user
        $byUser = $results | Group-Object -Property UserPrincipalName

        foreach ($group in $byUser) {
            $upn = $group.Name
            if (-not $userMap.Contains($upn)) {
                $userMap[$upn] = @{
                    DisplayName = $group.Group[0].UserDisplayName
                    Scenarios   = @{}   # scenarioIndex → @{Status; Tooltip}
                }
            }

            # Determine effective status from enabled policies only
            $userResults = $group.Group | Where-Object {
                $_.PolicyState -eq 'enabled' -or $_.PolicyState -eq 'N/A' -or $_.PolicyState -eq 'error'
            }

            $isBlocked         = $userResults | Where-Object { $_.IsBlocking -and $_.PolicyApplies }
            $hasPhishResist    = $userResults | Where-Object { $_.RequiresPhishingResistantMfa -and $_.PolicyApplies }
            $hasCompliance     = $userResults | Where-Object { ($_.RequiresCompliance -or $_.RequiresHybridJoin) -and $_.PolicyApplies }
            $hasMfa            = $userResults | Where-Object { $_.RequiresMfa -and (-not $_.RequiresPhishingResistantMfa) -and $_.PolicyApplies }
            $hasGrant          = $userResults | Where-Object { $_.PolicyApplies -and -not $_.IsBlocking -and -not $_.RequiresMfa }
            $hasError          = $userResults | Where-Object { $_.PolicyState -eq 'error' }
            $noPolicy          = $userResults | Where-Object { $_.PolicyState -eq 'N/A' }

            # Does the user have BOTH phishing-resistant MFA AND a compliance requirement?
            $hasPhishCompliance = $userResults | Where-Object { $_.RequiresPhishingResistantMfa -and ($_.RequiresCompliance -or $_.RequiresHybridJoin) -and $_.PolicyApplies }
            # Does the user have BOTH standard MFA AND a compliance requirement (in the same or different policies)?
            $hasMfaCompliance  = ($hasMfa -and $hasCompliance)

            $status = if ($isBlocked) {
                'Blocked'
            }
            elseif ($hasPhishCompliance) {
                'PhishingResistantCompliance'
            }
            elseif ($hasPhishResist) {
                'PhishingResistant'
            }
            elseif ($hasMfaCompliance) {
                'MFACompliance'
            }
            elseif ($hasMfa) {
                'MFA'
            }
            elseif ($hasGrant) {
                'Grant'
            }
            elseif ($hasError) {
                'Error'
            }
            else {
                'NoPolicy'
            }

            # Build tooltip: include auth strength name(s) and compliance requirements
            $tooltip = $status
            if ($status -in @('PhishingResistant', 'PhishingResistantCompliance')) {
                $strengthNames = @($hasPhishResist |
                    Where-Object { $_.AuthStrengthName } |
                    Select-Object -ExpandProperty AuthStrengthName -Unique)
                $tip = if ($strengthNames.Count -gt 0) { "Phishing-Resistant MFA: $($strengthNames -join ', ')" } else { 'Phishing-Resistant MFA' }
                if ($status -eq 'PhishingResistantCompliance') { $tip += ' + Device Compliance' }
                $tooltip = $tip
            }
            elseif ($status -in @('MFA', 'MFACompliance')) {
                $strengthNames = @($hasMfa |
                    Where-Object { $_.AuthStrengthName } |
                    Select-Object -ExpandProperty AuthStrengthName -Unique)
                $tip = if ($strengthNames.Count -gt 0) { "MFA (Auth Strength: $($strengthNames -join ', '))" } else { 'MFA' }
                if ($status -eq 'MFACompliance') { $tip += ' + Device Compliance' }
                $tooltip = $tip
            }

            $userMap[$upn].Scenarios[$scenarioIndex] = @{ Status = $status; Tooltip = $tooltip }
        }
    }

    # --- Compute summary stats ---
    $totalUsers   = $userMap.Count
    $totalScenarios = $Scenarios.Count
    $usersFullyCovered        = 0
    $usersWithGaps            = 0
    $usersAtRisk              = 0  # users with NoPolicy in any scenario
    $usersFullyPhishResistant = 0  # users where every scenario is PhishingResistant or Blocked

    foreach ($entry in $userMap.GetEnumerator()) {
        $statuses = @($entry.Value.Scenarios.Values | ForEach-Object { $_.Status })
        $hasGap            = $statuses -contains 'Grant' -or $statuses -contains 'NoPolicy'
        $hasNoPolicy       = $statuses -contains 'NoPolicy'
        $allProtected      = -not $hasGap
        $allPhishResistant = ($statuses | Where-Object { $_ -notin @('PhishingResistant', 'PhishingResistantCompliance', 'Blocked') }).Count -eq 0

        if ($allProtected)      { $usersFullyCovered++ }
        else                    { $usersWithGaps++ }
        if ($hasNoPolicy)       { $usersAtRisk++ }
        if ($allPhishResistant) { $usersFullyPhishResistant++ }
    }

    $pctCovered     = if ($totalUsers -gt 0) { [math]::Round(($usersFullyCovered / $totalUsers) * 100, 1) } else { 0 }
    $pctPhishResist = if ($totalUsers -gt 0) { [math]::Round(($usersFullyPhishResistant / $totalUsers) * 100, 1) } else { 0 }
    $pctGaps        = if ($totalUsers -gt 0) { [math]::Round(($usersWithGaps / $totalUsers) * 100, 1) } else { 0 }
    $hasAnyGaps     = $usersWithGaps -gt 0

    # --- Build scenario legend ---
    $legendHasCountry = $Scenarios | Where-Object { $_.EffectiveCountry }
    $legendHasIp      = $Scenarios | Where-Object { $_.EffectiveIpAddress }

    $scenarioLegendHeader = '<tr><th>ID</th><th>Application</th><th>Client App Type</th><th>Device Platform</th>'
    if ($legendHasCountry) { $scenarioLegendHeader += '<th>Country</th>' }
    if ($legendHasIp)      { $scenarioLegendHeader += '<th>IP Address</th>' }
    $scenarioLegendHeader += '</tr>'

    $scenarioLegendRows = ($Scenarios | ForEach-Object {
        $s = $_
        $row = "<tr><td class='scenario-tag'>S$($s.Index)</td><td>$($s.Application)</td><td>$($s.ClientAppType)</td><td>$(if ($s.DevicePlatform) { $s.DevicePlatform } else { 'Any' })</td>"
        if ($legendHasCountry) { $row += "<td>$(if ($s.EffectiveCountry)   { [System.Web.HttpUtility]::HtmlEncode($s.EffectiveCountry) }   else { '<span style=''color:var(--text-muted)''>Any</span>' })</td>" }
        if ($legendHasIp)      { $row += "<td>$(if ($s.EffectiveIpAddress) { [System.Web.HttpUtility]::HtmlEncode($s.EffectiveIpAddress) } else { '<span style=''color:var(--text-muted)''>Any</span>' })</td>" }
        $row + '</tr>'
    }) -join "`n"

    # --- Build heatmap rows ---
    $heatmapRows = [System.Text.StringBuilder]::new()
    foreach ($entry in $userMap.GetEnumerator()) {
        $upn  = $entry.Key
        $data = $entry.Value
        $hasUserGap  = ($data.Scenarios.Values | Where-Object { $_.Status -eq 'Grant' -or $_.Status -eq 'NoPolicy' }).Count -gt 0
        $hasPhishGap = ($data.Scenarios.Values | Where-Object { $_.Status -notin @('PhishingResistant', 'PhishingResistantCompliance', 'Blocked') }).Count -gt 0
        $gapClass    = if ($hasUserGap) { 'has-gap' } else { 'fully-covered' }
        if ($hasPhishGap) { $gapClass += ' phishing-gap' }

        [void]$heatmapRows.Append("<tr class='$gapClass' data-upn='$([System.Web.HttpUtility]::HtmlAttributeEncode($upn))'>")
        [void]$heatmapRows.Append("<td class='user-cell' title='$([System.Web.HttpUtility]::HtmlAttributeEncode($upn))'>$([System.Web.HttpUtility]::HtmlEncode($data.DisplayName))<br/><span class='upn'>$([System.Web.HttpUtility]::HtmlEncode($upn))</span></td>")

        for ($si = 1; $si -le $totalScenarios; $si++) {
            $cell = if ($data.Scenarios.ContainsKey($si)) { $data.Scenarios[$si] } else { @{ Status = 'NoData'; Tooltip = '-' } }
            $st   = $cell.Status
            $tip  = $cell.Tooltip
            $cellClass = switch ($st) {
                'PhishingResistantCompliance' { 'cell-phishing-resistant-compliance' }
                'PhishingResistant'           { 'cell-phishing-resistant' }
                'MFACompliance'               { 'cell-mfa-compliance' }
                'MFA'                         { 'cell-mfa' }
                'Blocked'                     { 'cell-blocked' }
                'Grant'                       { 'cell-gap' }
                'NoPolicy'                    { 'cell-nopolicy' }
                'Error'                       { 'cell-error' }
                default                       { 'cell-nodata' }
            }
            $cellText = switch ($st) {
                'PhishingResistantCompliance' { 'PC' }
                'PhishingResistant'           { 'P' }
                'MFACompliance'               { 'MC' }
                'MFA'                         { 'M' }
                'Blocked'                     { 'B' }
                'Grant'                       { '!' }
                'NoPolicy'                    { 'X' }
                'Error'                       { 'E' }
                default                       { '-' }
            }
            [void]$heatmapRows.Append("<td class='heatmap-cell $cellClass' title='$([System.Web.HttpUtility]::HtmlAttributeEncode($tip))'>$cellText</td>")
        }
        [void]$heatmapRows.AppendLine('</tr>')
    }

    # --- Build gap details rows ---
    $gapDetailRows = [System.Text.StringBuilder]::new()
    $gapUsers = $userMap.GetEnumerator() | Where-Object {
        ($_.Value.Scenarios.Values | Where-Object { $_.Status -eq 'Grant' -or $_.Status -eq 'NoPolicy' }).Count -gt 0
    } | Sort-Object {
        @($_.Value.Scenarios.GetEnumerator() | Where-Object { $_.Value.Status -eq 'Grant' -or $_.Value.Status -eq 'NoPolicy' }).Count
    } -Descending

    foreach ($entry in $gapUsers) {
        $upn  = $entry.Key
        $data = $entry.Value
        $gaps = $data.Scenarios.GetEnumerator() | Where-Object { $_.Value.Status -eq 'Grant' -or $_.Value.Status -eq 'NoPolicy' } | Sort-Object Key

        $gapCount = @($gaps).Count
        $gapScenarios = ($gaps | ForEach-Object {
            "<span class='scenario-tag'>S$($_.Key)</span> ($($_.Value.Status))"
        }) -join ', '

        [void]$gapDetailRows.AppendLine("<tr>")
        [void]$gapDetailRows.AppendLine("<td>$([System.Web.HttpUtility]::HtmlEncode($data.DisplayName))</td>")
        [void]$gapDetailRows.AppendLine("<td class='upn'>$([System.Web.HttpUtility]::HtmlEncode($upn))</td>")
        [void]$gapDetailRows.AppendLine("<td class='gap-count'>$gapCount / $totalScenarios</td>")
        [void]$gapDetailRows.AppendLine("<td>$gapScenarios</td>")
        [void]$gapDetailRows.AppendLine('</tr>')
    }

    # --- Alert banner ---
    $alertBanner = if ($hasAnyGaps) {
        "<div class='alert alert-danger'>&#9888; $usersWithGaps user(s) have MFA coverage gaps across tested scenarios</div>"
    }
    else {
        "<div class='alert alert-success'>&#10004; All $totalUsers users are protected by MFA or blocked across all tested scenarios</div>"
    }

    # --- Build full HTML ---
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>CA Gap Analysis Report - $([System.Web.HttpUtility]::HtmlEncode($TenantName))</title>
<style>
:root {
    --bg-primary: #0f172a;
    --bg-secondary: #1e293b;
    --bg-tertiary: #334155;
    --text-primary: #f1f5f9;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --accent-blue: #3b82f6;
    --accent-green: #22c55e;
    --accent-red: #ef4444;
    --accent-yellow: #eab308;
    --accent-orange: #f97316;
    --accent-purple: #a855f7;
    --accent-teal: #2dd4bf;
    --border: #334155;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    padding: 2rem;
}
.container { max-width: 1400px; margin: 0 auto; }
h1 { font-size: 1.8rem; margin-bottom: 0.25rem; }
.subtitle { color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1.5rem; }
.alert {
    padding: 1rem 1.25rem;
    border-radius: 8px;
    font-weight: 600;
    margin-bottom: 1.5rem;
    font-size: 1rem;
}
.alert-danger  { background: rgba(239,68,68,0.15); border: 1px solid var(--accent-red); color: var(--accent-red); }
.alert-success { background: rgba(34,197,94,0.15); border: 1px solid var(--accent-green); color: var(--accent-green); }

/* Summary cards */
.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
}
.summary-card {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.25rem;
    text-align: center;
}
.summary-card .value { font-size: 2rem; font-weight: 700; }
.summary-card .label { color: var(--text-secondary); font-size: 0.85rem; margin-top: 0.25rem; }
.card-green  .value { color: var(--accent-green);  }
.card-red    .value { color: var(--accent-red);    }
.card-yellow .value { color: var(--accent-yellow); }
.card-blue   .value { color: var(--accent-blue);   }
.card-purple .value { color: var(--accent-purple); }
.card-teal   .value { color: var(--accent-teal);   }

/* Sections */
.section {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 1.5rem;
    overflow: hidden;
}
.section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem 1.25rem;
    background: var(--bg-tertiary);
    cursor: pointer;
    user-select: none;
}
.section-header h2 { font-size: 1.1rem; }
.section-header .toggle { font-size: 1.2rem; color: var(--text-secondary); }
.section-body { padding: 1.25rem; }
.section-body.collapsed { display: none; }

/* Tables */
table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
}
th {
    background: var(--bg-tertiary);
    padding: 0.6rem 0.75rem;
    text-align: left;
    color: var(--text-secondary);
    font-weight: 600;
    position: sticky;
    top: 0;
    z-index: 1;
}
td { padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); }

/* Scenario legend */
.scenario-tag {
    display: inline-block;
    background: var(--accent-blue);
    color: #fff;
    font-size: 0.75rem;
    font-weight: 700;
    padding: 0.15rem 0.45rem;
    border-radius: 4px;
    margin-right: 0.25rem;
}

/* Heatmap */
.heatmap-container { overflow-x: auto; }
.heatmap-cell {
    text-align: center;
    font-weight: 700;
    font-size: 0.8rem;
    min-width: 36px;
    width: 36px;
}
.cell-phishing-resistant-compliance { background: rgba(45,212,191,0.35); color: var(--accent-teal); font-size: 0.65rem; letter-spacing: -0.5px; border: 1px solid rgba(45,212,191,0.5); }
.cell-phishing-resistant { background: rgba(45,212,191,0.25); color: var(--accent-teal); }
.cell-mfa-compliance { background: rgba(34,197,94,0.35);  color: var(--accent-green); font-size: 0.65rem; letter-spacing: -0.5px; border: 1px solid rgba(34,197,94,0.5); }
.cell-mfa      { background: rgba(34,197,94,0.25);  color: var(--accent-green);  }
.cell-blocked  { background: rgba(59,130,246,0.25); color: var(--accent-blue);   }
.cell-gap      { background: rgba(249,115,22,0.3);  color: var(--accent-orange); }
.cell-nopolicy { background: rgba(239,68,68,0.3);   color: var(--accent-red);    }
.cell-error    { background: rgba(168,85,247,0.25); color: var(--accent-purple); }
.cell-nodata   { background: var(--bg-tertiary);     color: var(--text-muted);    }
.user-cell { white-space: nowrap; min-width: 200px; }
.upn { font-size: 0.75rem; color: var(--text-muted); }

/* Gap count */
.gap-count { font-weight: 700; color: var(--accent-red); }

/* Filter bar */
.filter-bar {
    display: flex;
    gap: 0.75rem;
    align-items: center;
    margin-bottom: 1rem;
    flex-wrap: wrap;
}
.filter-bar input, .filter-bar select {
    background: var(--bg-primary);
    border: 1px solid var(--border);
    color: var(--text-primary);
    padding: 0.4rem 0.6rem;
    border-radius: 4px;
    font-size: 0.85rem;
}
.filter-bar input { flex: 1; min-width: 200px; }
.filter-bar label { color: var(--text-secondary); font-size: 0.85rem; }

/* Legend */
.legend { display: flex; gap: 1.5rem; margin-bottom: 1rem; flex-wrap: wrap; }
.legend-item { display: flex; align-items: center; gap: 0.4rem; font-size: 0.8rem; color: var(--text-secondary); }
.legend-swatch { width: 20px; height: 20px; border-radius: 3px; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 0.75rem; }

/* Print styles */
@media print {
    body { background: white; color: #1a1a1a; }
    .section-header { background: #e5e7eb; }
    .summary-card { border-color: #d1d5db; }
    .filter-bar { display: none; }
}
</style>
</head>
<body>
<div class="container">
    <h1>&#128737; CA Gap Analysis Report</h1>
    <p class="subtitle">$([System.Web.HttpUtility]::HtmlEncode($TenantName)) &mdash; Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &mdash; $totalScenarios scenario(s) tested</p>

    $alertBanner

    <!-- Summary cards -->
    <div class="summary-grid">
        <div class="summary-card card-blue"><div class="value">$totalUsers</div><div class="label">Users Evaluated</div></div>
        <div class="summary-card card-purple"><div class="value">$totalScenarios</div><div class="label">Scenarios Tested</div></div>
        <div class="summary-card card-green"><div class="value">$pctCovered%</div><div class="label">Fully Covered (MFA)</div></div>
        <div class="summary-card card-teal"><div class="value">$pctPhishResist%</div><div class="label">Phishing-Resistant Coverage</div></div>
        <div class="summary-card card-red"><div class="value">$usersWithGaps</div><div class="label">Users with Gaps</div></div>
        <div class="summary-card card-yellow"><div class="value">$usersAtRisk</div><div class="label">No Policy (any scenario)</div></div>
        <div class="summary-card"><div class="value">$($enabledPolicyIds.Count)</div><div class="label">Enforced Policies</div></div>
    </div>

    <!-- Scenario Legend -->
    <div class="section">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Scenario Legend</h2><span class="toggle">&#9660;</span>
        </div>
        <div class="section-body">
            <table>
                <thead>$scenarioLegendHeader</thead>
                <tbody>$scenarioLegendRows</tbody>
            </table>
        </div>
    </div>

    <!-- Coverage Heatmap -->
    <div class="section">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Coverage Heatmap</h2><span class="toggle">&#9660;</span>
        </div>
        <div class="section-body">
            <div class="legend">
                <div class="legend-item"><div class="legend-swatch cell-phishing-resistant-compliance">PC</div> Phishing-Resistant MFA + Compliance</div>
                <div class="legend-item"><div class="legend-swatch cell-phishing-resistant">P</div> Phishing-Resistant MFA</div>
                <div class="legend-item"><div class="legend-swatch cell-mfa-compliance">MC</div> MFA + Device Compliance</div>
                <div class="legend-item"><div class="legend-swatch cell-mfa">M</div> Standard MFA</div>
                <div class="legend-item"><div class="legend-swatch cell-blocked">B</div> Blocked</div>
                <div class="legend-item"><div class="legend-swatch cell-gap">!</div> Grant (No MFA)</div>
                <div class="legend-item"><div class="legend-swatch cell-nopolicy">X</div> No Policy</div>
                <div class="legend-item"><div class="legend-swatch cell-error">E</div> Error</div>
            </div>
            <div class="filter-bar">
                <input type="text" id="heatmapSearch" placeholder="Search users..." oninput="filterHeatmap()"/>
                <label for="heatmapFilter">Show:</label>
                <select id="heatmapFilter" onchange="filterHeatmap()">
                    <option value="all">All Users</option>
                    <option value="gaps">MFA Gaps</option>
                    <option value="phish-gaps">Phishing-Resistant Gaps</option>
                    <option value="covered">Fully Covered (MFA)</option>
                </select>
            </div>
            <div class="heatmap-container">
                <table id="heatmapTable">
                    <thead>
                        <tr>
                            <th>User</th>
                            $(($Scenarios | ForEach-Object { "<th class='heatmap-cell' title='$($_.Label)'>S$($_.Index)</th>" }) -join "`n")
                        </tr>
                    </thead>
                    <tbody>
                        $($heatmapRows.ToString())
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Gap Details -->
    <div class="section">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Gap Details ($(@($gapUsers).Count) users)</h2><span class="toggle">&#9660;</span>
        </div>
        <div class="section-body$(if (-not $hasAnyGaps) { ' collapsed' })">
            $(if ($hasAnyGaps) {
                @"
            <div class="filter-bar">
                <input type="text" id="gapSearch" placeholder="Search gap users..." oninput="filterGaps()"/>
            </div>
            <table id="gapTable">
                <thead><tr><th>Display Name</th><th>UPN</th><th>Gaps</th><th>Unprotected Scenarios</th></tr></thead>
                <tbody>$($gapDetailRows.ToString())</tbody>
            </table>
"@
            } else {
                '<p style="color: var(--accent-green); font-weight: 600;">No MFA gaps detected across all tested scenarios.</p>'
            })
        </div>
    </div>
</div>

<script>
function toggleSection(header) {
    var body = header.nextElementSibling;
    var toggle = header.querySelector('.toggle');
    if (body.classList.contains('collapsed')) {
        body.classList.remove('collapsed');
        toggle.innerHTML = '&#9660;';
    } else {
        body.classList.add('collapsed');
        toggle.innerHTML = '&#9654;';
    }
}

function filterHeatmap() {
    var search = document.getElementById('heatmapSearch').value.toLowerCase();
    var filter = document.getElementById('heatmapFilter').value;
    var rows = document.querySelectorAll('#heatmapTable tbody tr');
    rows.forEach(function(row) {
        var upn = (row.getAttribute('data-upn') || '').toLowerCase();
        var textMatch = !search || upn.indexOf(search) !== -1 || row.textContent.toLowerCase().indexOf(search) !== -1;
        var filterMatch = filter === 'all' ||
            (filter === 'gaps' && row.classList.contains('has-gap')) ||
            (filter === 'phish-gaps' && row.classList.contains('phishing-gap')) ||
            (filter === 'covered' && row.classList.contains('fully-covered'));
        row.style.display = (textMatch && filterMatch) ? '' : 'none';
    });
}

function filterGaps() {
    var search = document.getElementById('gapSearch').value.toLowerCase();
    var rows = document.querySelectorAll('#gapTable tbody tr');
    rows.forEach(function(row) {
        row.style.display = row.textContent.toLowerCase().indexOf(search) !== -1 ? '' : 'none';
    });
}
</script>
</body>
</html>
"@

    if ($PSCmdlet.ShouldProcess($OutputPath, 'Write gap analysis report')) {
        $html | Out-File -FilePath $OutputPath -Encoding utf8 -Force
        Write-Verbose "[CAReporter] Gap report saved to: $OutputPath"

        if ($OpenReport) {
            Start-Process $OutputPath
        }

        [PSCustomObject]@{
            Path     = (Resolve-Path $OutputPath).Path
            FileSize = (Get-Item $OutputPath).Length
            Users    = $totalUsers
            Scenarios = $totalScenarios
            GapUsers = $usersWithGaps
            CoveragePct = $pctCovered
        }
    }
}
