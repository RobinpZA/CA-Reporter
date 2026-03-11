#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Example: Basic usage of the CAReporter module.
.DESCRIPTION
    Demonstrates different ways to use Get-CAWhatIfReport and the individual cmdlets.
#>

# Import the module
Import-Module "$PSScriptRoot\..\CAReporter\CAReporter.psd1" -Force

# ============================================================================
# Example 1: Quick report (all users, Office 365, default scenario)
# ============================================================================
Write-Host '=== Example 1: Quick Full Report ===' -ForegroundColor Cyan
$result = Get-CAWhatIfReport -OpenReport

# ============================================================================
# Example 2: Limited user count for testing
# ============================================================================
Write-Host '=== Example 2: First 10 Users ===' -ForegroundColor Cyan
$result = Get-CAWhatIfReport -MaxUsers 10 -OpenReport

# ============================================================================
# Example 3: Multiple apps, include report-only policies
# ============================================================================
Write-Host '=== Example 3: Multi-App with Report-Only ===' -ForegroundColor Cyan
$result = Get-CAWhatIfReport -Applications @(
    '67ad5377-2d78-4ac2-a867-6300cda00e85',  # Office 365
    'c44b4083-3bb0-49c1-b47d-974e53cbdf3c',  # Azure Portal
    'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe'   # Microsoft Teams
) -IncludeReportOnly -MaxUsers 25 -OpenReport

# ============================================================================
# Example 4: High-risk scenario from France on iOS
# ============================================================================
Write-Host '=== Example 4: High-Risk iOS Scenario ===' -ForegroundColor Cyan
$result = Get-CAWhatIfReport -MaxUsers 50 `
    -ClientAppType 'mobileAppsAndDesktopClients' `
    -DevicePlatform 'iOS' `
    -SignInRiskLevel 'high' `
    -Country 'FR' `
    -OutputPath '.\HighRisk-iOS-Report.html' `
    -OpenReport

# ============================================================================
# Example 5: Step-by-step for programmatic analysis
# ============================================================================
Write-Host '=== Example 5: Step-by-Step Analysis ===' -ForegroundColor Cyan

# Connect
Connect-CAReporter

# Get data
$policies = Get-CAPolicy -IncludeReportOnly
$users = Get-CATenantUsers -MaxUsers 20 -ExcludeDisabled

# Run analysis
$analysis = Invoke-CAWhatIfAnalysis -Users $users `
    -Applications @('67ad5377-2d78-4ac2-a867-6300cda00e85')

# Explore results
Write-Host "`n--- Users blocked from Office 365 ---" -ForegroundColor Red
$analysis.Results | Where-Object { $_.IsBlocking -and $_.PolicyApplies } |
    Format-Table UserPrincipalName, PolicyDisplayName, GrantControls -AutoSize

Write-Host "`n--- Users requiring MFA ---" -ForegroundColor Yellow
$analysis.Results | Where-Object { $_.RequiresMfa -and $_.PolicyApplies } |
    Format-Table UserPrincipalName, PolicyDisplayName -AutoSize

Write-Host "`n--- Users with NO policies applied (coverage gaps) ---" -ForegroundColor Magenta
$analysis.Results | Where-Object { $_.AnalysisReasons -eq 'noPoliciesApplied' } |
    Select-Object UserPrincipalName -Unique |
    Format-Table -AutoSize

# Generate report
Export-CAReport -AnalysisResults $analysis -Policies $policies -OpenReport
