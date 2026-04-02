# CAReporter - Conditional Access What-If Reporter

A PowerShell module that tests **all Conditional Access policies** against **all users** in an M365 tenant using the Microsoft Graph **What-If API** and generates a comprehensive, filterable **HTML report**.

## Features

- **Full Tenant Analysis** - Evaluate every user against every CA policy using the Graph beta What-If endpoint
- **Comprehensive MFA Gap Analysis** - Run a full scenario matrix (app × client type × platform) with `-Comprehensive` to find users who lack MFA protection under _any_ sign-in condition; tracks **phishing-resistant MFA** and **device compliance** requirements independently and surfaces them as distinct heatmap cells
- **Graphical Interface** - Built-in WPF GUI (`Show-CAReporterGUI`) for easy point-and-click configuration, including comprehensive mode controls
- **Friendly Application Names** - Tab-completable application names (e.g., `Office365`, `AzurePortal`, `MicrosoftTeams`) instead of raw GUIDs
- **Interactive HTML Reports** — two report types:
  - **Standard report** — executive summary, policy inventory, user-policy heatmap, effective outcomes, detailed findings, and coverage gaps
  - **Gap analysis report** — alert banner, summary cards, scenario legend, coverage heatmap (users × scenarios), and gap details table sorted by exposure
- **Enforced-Only Metrics** - Summary cards and effective outcomes only count enabled policies; report-only policies are shown separately for visibility
- **Flexible Scenario Testing** - Customise client app type, device platform, risk levels, country, and IP address
- **Throttling Protection** - Configurable delays and automatic back-off on Graph API throttling
- **Report-Only Support** - Include report-only and disabled policies for complete visibility
- **Auto-Disconnect** - Optional `-DisconnectWhenDone` switch to cleanly disconnect from Microsoft Graph after report generation

## Prerequisites

- **PowerShell 7.0+**
- **Microsoft.Graph.Authentication** module (v2.0+)
- Microsoft Entra ID with Conditional Access policies configured
- One of:
  - Interactive user account with sufficient permissions
  - App registration with certificate-based auth

### Required Graph API Permissions

| Permission | Type | Purpose |
|---|---|---|
| `Policy.Read.All` | Delegated or Application | Read CA policies and run What-If |
| `Directory.Read.All` | Delegated or Application | Read user and group information |
| `Application.Read.All` | Delegated or Application | Resolve application display names |

> **Note:** The What-If API uses the beta endpoint (`POST /identity/conditionalAccess/evaluate`) which is subject to change.

## Installation

```powershell
# Clone the repository
git clone https://github.com/yourusername/CA-Reporter.git
cd CA-Reporter

# Install the required Graph module if not already installed
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

# Import the module
Import-Module .\CAReporter\CAReporter.psd1
```

## Quick Start

```powershell
# Import the module
Import-Module .\CAReporter\CAReporter.psd1

# Option 1: Launch the GUI (easiest — includes comprehensive mode)
Show-CAReporterGUI

# Option 2: Run a standard report from the command line
Get-CAWhatIfReport -OpenReport

# Option 3: Run a comprehensive MFA gap analysis (recommended for gap identification)
Get-CAWhatIfReport -Comprehensive -OpenReport

# Test first 20 users only (faster for initial testing)
Get-CAWhatIfReport -MaxUsers 20 -OpenReport
```

## Usage Examples

### Basic - All users against Office 365

```powershell
Get-CAWhatIfReport -OpenReport
```

### Multiple Applications (using friendly names)

```powershell
# Test Office 365, Azure Portal, and Microsoft Teams
# Use Tab to auto-complete application names!
Get-CAWhatIfReport -Applications Office365, AzurePortal, MicrosoftTeams -OpenReport

# Raw GUIDs still work if needed
Get-CAWhatIfReport -Applications @(
    '67ad5377-2d78-4ac2-a867-6300cda00e85',  # Office 365
    'c44b4083-3bb0-49c1-b47d-974e53cbdf3c',  # Azure Portal
    'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe'   # Microsoft Teams
) -OpenReport
```

### Test Specific Scenario - iOS Mobile App with High Risk

```powershell
Get-CAWhatIfReport -MaxUsers 50 `
    -ClientAppType 'mobileAppsAndDesktopClients' `
    -DevicePlatform 'iOS' `
    -SignInRiskLevel 'high' `
    -OpenReport
```

### Include Report-Only Policies, Exclude Disabled Users, and Auto-Disconnect

```powershell
Get-CAWhatIfReport -IncludeReportOnly `
    -ExcludeDisabledUsers `
    -OutputPath '.\Reports\CA-Report.html' `
    -DisconnectWhenDone `
    -OpenReport
```

### Comprehensive MFA Gap Analysis

The `-Comprehensive` switch tests every user against a matrix of sign-in scenarios (app × client type × platform) to find MFA coverage gaps that a single fixed scenario would miss.

```powershell
# Standard profile: 18 scenarios (2 apps × 2 client types × 4 platforms + 2 legacy auth)
Get-CAWhatIfReport -Comprehensive -OpenReport

# Thorough profile: 42 scenarios — most complete coverage check
Get-CAWhatIfReport -Comprehensive -ScenarioProfile Thorough -MaxUsers 100 -OpenReport

# Quick profile: 1 scenario — fast sanity check (Office 365 / browser / any platform)
Get-CAWhatIfReport -Comprehensive -ScenarioProfile Quick -OpenReport

# Test whether policies enforce location rules — doubles the scenario count per country
Get-CAWhatIfReport -Comprehensive -ScenarioProfile Standard `
    -ComprehensiveCountries @('CN', 'RU', 'NG') -OpenReport

# Test named-location coverage with specific IP addresses
Get-CAWhatIfReport -Comprehensive -ScenarioProfile Standard `
    -ComprehensiveIpAddresses @('203.0.113.42') -OpenReport
```

**Scenario profiles:**

| Profile | Scenarios | Apps | Client Types | Platforms |
|---|---|---|---|---|
| `Quick` | 1 | Office 365 | Browser | Any |
| `Standard` (default) | 18 | Office 365, Azure Portal | Browser, Mobile/Desktop, **EAS (Legacy)** | Windows, iOS, Android, macOS |
| `Thorough` | 42 | Office 365, Azure Portal, Microsoft Graph | Browser, Mobile/Desktop, **EAS + Other (Legacy)** | Windows, iOS, Android, macOS, Linux, Any |

> [!TIP]
> Use `ScenarioProfile Thorough` for compliance reviews or initial assessments. Use `Quick` or `Standard` for regular scheduled checks.

### Test from a Specific Location

```powershell
Get-CAWhatIfReport -MaxUsers 100 `
    -Country 'FR' `
    -IpAddress '92.205.185.202' `
    -OpenReport
```

### Generate a Gap Report Directly

```powershell
# Run scenarios manually and generate the gap report
Connect-CAReporter
$policies  = Get-CAPolicy
$users     = Get-CATenantUsers -MaxUsers 50 -ExcludeDisabled
$scenarios = Get-ComprehensiveScenarios -Profile Standard  # internal helper

$scenarioResults = foreach ($s in $scenarios) {
    $p = @{ Users = $users; Applications = @($s.Application)
            ClientAppType = $s.ClientAppType; ScenarioLabel = $s.Label
            IncludeAllPolicies = $true }
    if ($s.DevicePlatform) { $p['DevicePlatform'] = $s.DevicePlatform }
    Invoke-CAWhatIfAnalysis @p
}

Export-CAGapReport -ScenarioResults $scenarioResults -Scenarios $scenarios -Policies $policies -OpenReport
```

### Step-by-Step (Advanced)

```powershell
# Connect manually first
Connect-CAReporter

# Get policies
$policies = Get-CAPolicy -IncludeReportOnly

# Get users (first 50)
$users = Get-CATenantUsers -MaxUsers 50 -ExcludeDisabled

# Run analysis
$analysis = Invoke-CAWhatIfAnalysis -Users $users `
    -Applications @('67ad5377-2d78-4ac2-a867-6300cda00e85') `
    -ClientAppType 'browser'

# Generate report
Export-CAReport -AnalysisResults $analysis -Policies $policies -OpenReport

# Explore results programmatically
$analysis.Results | Where-Object { $_.IsBlocking } | Format-Table UserPrincipalName, PolicyDisplayName
$analysis.Results | Where-Object { -not $_.PolicyApplies } | Select-Object UserPrincipalName -Unique
```

### Using the GUI

```powershell
# Launch the graphical interface
Show-CAReporterGUI
```

The GUI provides a point-and-click interface with:
- Multi-select application list with all well-known apps
- Dropdowns for client app type, device platform, and risk levels
- Text fields for country code and IP address
- Checkboxes for user/policy options, auto-open, and auto-disconnect
- Output path configuration

## Cmdlet Reference

| Cmdlet | Description |
|---|---|
| `Show-CAReporterGUI` | **Launches the graphical interface** for easy configuration (includes comprehensive mode) |
| `Get-CAWhatIfReport` | One-command orchestrator — standard or comprehensive mode |
| `Connect-CAReporter` | Connects to Microsoft Graph with required scopes |
| `Get-CAPolicy` | Retrieves all Conditional Access policies |
| `Get-CATenantUsers` | Retrieves tenant users with filtering options |
| `Invoke-CAWhatIfAnalysis` | Runs What-If evaluations (core engine); accepts `-ScenarioLabel` for tagging |
| `Export-CAReport` | Generates the standard interactive HTML report |
| `Export-CAGapReport` | Generates the MFA gap analysis HTML report from multi-scenario results |

### `Get-CAWhatIfReport` key parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Comprehensive` | Switch | — | Enables comprehensive scenario matrix mode |
| `-ScenarioProfile` | String | `Standard` | `Quick` / `Standard` / `Thorough` — controls scenario count |
| `-ComprehensiveCountries` | String[] | — | ISO 3166-1 alpha-2 codes (e.g. `CN`, `RU`). Each country generates a full copy of the base scenario set, testing whether policies enforce location-based controls. |
| `-ComprehensiveIpAddresses` | String[] | — | IP addresses or CIDR ranges. Each entry generates a full copy of the base scenario set, testing named location policy coverage. |
| `-MaxUsers` | Int | 0 (all) | Limit number of users evaluated |
| `-Applications` | String[] | `Office365` | App friendly names or GUIDs to test |
| `-ClientAppType` | String | `browser` | Client type for single-scenario mode |
| `-DevicePlatform` | String | — | Platform for single-scenario mode |
| `-OpenReport` | Switch | — | Open the HTML report when complete |
| `-DisconnectWhenDone` | Switch | — | Disconnect from Graph after completion |

## Supported Applications

Use the friendly name with `-Applications` (tab-completable) or the raw GUID:

| Friendly Name | Application | App ID |
|---|---|---|
| `Office365` | Office 365 | `67ad5377-2d78-4ac2-a867-6300cda00e85` |
| `ExchangeOnline` | Exchange Online | `00000002-0000-0ff1-ce00-000000000000` |
| `SharePointOnline` | SharePoint Online | `00000003-0000-0ff1-ce00-000000000000` |
| `Office365Portal` | Office 365 Portal | `00000006-0000-0ff1-ce00-000000000000` |
| `AzurePortal` | Azure Portal | `c44b4083-3bb0-49c1-b47d-974e53cbdf3c` |
| `AzureServiceManagement` | Azure Service Management | `797f4846-ba00-4fd7-ba43-dac1f8f63013` |
| `AzureCLI` | Azure CLI | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` |
| `AzurePowerShell` | Azure PowerShell | `1950a258-227b-4e31-a9cf-717495945fc2` |
| `MicrosoftGraph` | Microsoft Graph | `00000003-0000-0000-c000-000000000000` |
| `MicrosoftIntune` | Microsoft Intune | `0000000a-0000-0000-c000-000000000000` |
| `IntuneEnrollment` | Intune Enrollment | `d4ebce55-015a-49b5-a083-c84d1797ae8c` |
| `ComplianceCenter` | M365 Compliance Center | `de8bc8b5-d9f9-48b1-a8ad-b748da725064` |
| `PowerBI` | Microsoft Power BI | `00000007-0000-0ff1-ce00-000000000000` |
| `MicrosoftTeams` | Microsoft Teams | `cc15fd57-2c6c-4117-a88c-83b1d56b4bbe` |
| `TeamsWebClient` | Teams Web Client | `5e3ce6c0-2b1f-4285-8d4b-75ee78787346` |
| `DynamicsCRM` | Dynamics CRM | `00000015-0000-0000-c000-000000000000` |
| `ExchangeRESTAPI` | Exchange REST API | `fc780465-2017-40d4-a0c5-307022471b92` |
| `Office365ManagementAPI` | O365 Management APIs | `00b41c95-dab0-4487-9791-b9d2c32c80f2` |
| `DefenderCloudApps` | Defender for Cloud Apps | `09abbdfd-ed23-44ee-a2d9-a627aa1c90f3` |

## Report Sections

CAReporter generates two distinct report types depending on the mode used.

### Standard Report (`Export-CAReport`)

#### Scenario Parameters
Displays all selected parameters at the top of the report: applications tested (resolved to friendly names), client app type, device platform, risk levels, country, IP address, and user count.

### Executive Summary
Key metrics at a glance: user count, policy count, MFA coverage percentage, blocked users, users with no CA policies, and evaluation errors. **Only counts enforced (enabled) policies** — report-only policies are excluded from these metrics.

### Policy Inventory
All CA policies with state, user scope, applications, and grant controls. Searchable and filterable by state.

### User-Policy Impact Matrix
A colour-coded heatmap showing which policies apply to which users:
- **B** (Red) = Block Access
- **M** (Orange) = MFA Required
- **C** (Blue) = Device Compliance Required
- **MC** (Purple) = MFA + Device Compliance Required (policy requires both)
- **G** (Green) = Grant with other controls
- **-** (Grey) = Not Applied

### Effective Outcome per User
Shows the **real-world effective result** for each user based on all enforced policies:
- **Block** always overrides all other controls — if any enabled policy blocks, access is denied
- Otherwise, the user must satisfy the **combined requirements** from all applied enabled policies (e.g., MFA + Compliant Device)
- Lists all contributing policies per user with total count
- Filterable by outcome (Blocked, Grant, No Policies)

> **Note:** Report-only policies are excluded from effective outcome calculations since they don't enforce controls.

### Detailed Findings
Every evaluation result in a searchable, filterable table. Filter by status (Blocked, MFA Required, Applied, Not Applied, Error).

### Coverage Gaps
Users who have **no enforced CA policies applied** — these are potential security gaps.

---

### Gap Analysis Report (`Export-CAGapReport`)

Generated when using `-Comprehensive`. Aggregates results across all tested scenarios to give a cross-condition view of MFA coverage.

#### Alert Banner
A prominent banner at the top flags whether any gaps were found, or confirms all users are fully covered.

#### Summary Cards
At-a-glance metrics: users evaluated, scenarios tested, % fully covered, users with gaps, users with no policy in any scenario, and enabled policy count.

#### Scenario Legend
Maps each scenario ID (S1, S2, ...) to its application, client app type, and device platform so heatmap cells can be interpreted.

#### Coverage Heatmap
A users × scenarios matrix showing the effective status per cell:
- **PC** (Teal, bold border) = Phishing-Resistant MFA + Device Compliance Required
- **P** (Teal) = Phishing-Resistant MFA Required
- **MC** (Green, bold border) = Standard MFA + Device Compliance Required
- **M** (Green) = Standard MFA Required
- **B** (Blue) = Blocked
- **!** (Orange) = Grant with no MFA — potential gap
- **X** (Red) = No policy applied — unprotected
- **E** (Purple) = Evaluation error

Filterable by user name and by coverage status (all / gaps only / fully covered).

#### Gap Details Table
Lists only users who have at least one gap, sorted by gap count descending. Shows the specific scenario IDs where protection is missing.

## How It Works

1. **User Enumeration** - Retrieves user accounts from Microsoft Graph with pagination
2. **Policy Retrieval** - Fetches all Conditional Access policies via the v1.0 endpoint
3. **User De-duplication (Comprehensive mode)** - Groups users into CA-equivalent profiles based on their transitive group memberships, role assignments, and guest/member type. Only one representative per unique profile is evaluated; results are fanned out to all equivalent users. This can reduce evaluate API calls significantly in tenants where many users share the same group/role memberships.
4. **Platform Pruning (Comprehensive mode)** - Inspects the fetched policies before generating scenarios. If no policy references platform conditions, the scenario matrix collapses platform to `Any` only. If some policies reference specific platforms, only those platforms (plus `Any`) are tested, removing scenarios that could never produce a different result.
5. **What-If Evaluation** - For each representative user × scenario, calls `POST /beta/identity/conditionalAccess/evaluate` with the simulated sign-in context
6. **Result Processing** - Parses grant controls, session controls, and policy applicability; expands representative results back to all equivalent users
7. **Report Generation** - Builds a self-contained HTML file with embedded CSS/JS for filtering and interactivity

## Known Limitations

- The What-If API is in **beta** and may change
- Large tenants (1000+ users × multiple apps) can still take time; in comprehensive mode, user de-duplication and platform pruning reduce the number of evaluate API calls, but the saving depends on how many unique CA profiles exist in the tenant
- The What-If API does not support all policy conditions (e.g., some device state evaluations)
- Session controls visibility depends on the API response
- Named location evaluation requires providing an IP or country in the scenario
- **PC cell detection** requires phishing-resistant MFA _and_ device compliance to originate from the **same policy**; if they come from separate policies, the cell shows **MC** instead. This is a known limitation of per-policy result parsing.

## Acknowledgements

Inspired by and building on concepts from:
- [Conditional Access Validator](https://github.com/jasperbaes/Conditional-Access-Validator) by Jasper Baes
- [idPowerToys CA Documenter](https://idpowertoys.merill.net/ca) by Merill Fernando
- [Maester CA What-If Tests](https://maester.dev/docs/ca-what-if) by the Maester team

## License

MIT License - See [LICENSE](LICENSE) for details.
