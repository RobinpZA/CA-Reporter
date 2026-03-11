# CAReporter - Conditional Access What-If Reporter

A PowerShell module that tests **all Conditional Access policies** against **all users** in an M365 tenant using the Microsoft Graph **What-If API** and generates a comprehensive, filterable **HTML report**.

## Features

- **Full Tenant Analysis** - Evaluate every user against every CA policy using the Graph beta What-If endpoint
- **Graphical Interface** - Built-in WPF GUI (`Show-CAReporterGUI`) for easy point-and-click configuration
- **Friendly Application Names** - Tab-completable application names (e.g., `Office365`, `AzurePortal`, `MicrosoftTeams`) instead of raw GUIDs
- **Interactive HTML Report** with:
  - Executive summary with key metrics (MFA coverage %, blocked users, coverage gaps)
  - Full scenario parameters display (applications, client app, platform, risk levels, country, IP)
  - Policy inventory table with state/scope/controls breakdown
  - User-Policy impact matrix (colour-coded heatmap)
  - **Effective Outcome per User** - Shows combined grant requirements across all enforced policies, with Block always taking precedence
  - Detailed per-user findings with filtering and search
  - Coverage gap identification (users with no policies applied)
  - Error tracking and reporting
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

# Option 1: Launch the GUI (easiest)
Show-CAReporterGUI

# Option 2: Run a full report from the command line (will prompt for Graph sign-in)
Get-CAWhatIfReport -OpenReport

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

### Test from a Specific Location

```powershell
Get-CAWhatIfReport -MaxUsers 100 `
    -Country 'FR' `
    -IpAddress '92.205.185.202' `
    -OpenReport
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
| `Show-CAReporterGUI` | **Launches the graphical interface** for easy configuration |
| `Get-CAWhatIfReport` | One-command orchestrator (recommended CLI entry point) |
| `Connect-CAReporter` | Connects to Microsoft Graph with required scopes |
| `Get-CAPolicy` | Retrieves all Conditional Access policies |
| `Get-CATenantUsers` | Retrieves tenant users with filtering options |
| `Invoke-CAWhatIfAnalysis` | Runs What-If evaluations (core engine) |
| `Export-CAReport` | Generates the HTML report from analysis results |

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

### Scenario Parameters
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

## How It Works

1. **User Enumeration** - Retrieves user accounts from Microsoft Graph with pagination
2. **Policy Retrieval** - Fetches all Conditional Access policies via the v1.0 endpoint
3. **What-If Evaluation** - For each user × application combination, calls `POST /beta/identity/conditionalAccess/evaluate` with a simulated sign-in scenario
4. **Result Processing** - Parses grant controls, session controls, and policy applicability
5. **Report Generation** - Builds a self-contained HTML file with embedded CSS/JS for filtering and interactivity

## Known Limitations

- The What-If API is in **beta** and may change
- Large tenants (1000+ users × multiple apps) will take time due to per-user API calls
- The What-If API does not support all policy conditions (e.g., some device state evaluations)
- Session controls visibility depends on the API response
- Named location evaluation requires providing an IP or country in the scenario

## Acknowledgements

Inspired by and building on concepts from:
- [Conditional Access Validator](https://github.com/jasperbaes/Conditional-Access-Validator) by Jasper Baes
- [idPowerToys CA Documenter](https://idpowertoys.merill.net/ca) by Merill Fernando
- [Maester CA What-If Tests](https://maester.dev/docs/ca-what-if) by the Maester team

## License

MIT License - See [LICENSE](LICENSE) for details.
