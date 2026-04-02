@{
    RootModule        = 'CAReporter.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'a3f7c8d1-2e4b-4f6a-9c1d-8e5f2b3a7d9e'
    Author            = 'Robin Pieterse'
    CompanyName       = 'Community'
    Copyright         = '(c) 2026. All rights reserved.'
    Description       = 'Tests all Conditional Access policies against all users in an M365 tenant using the Microsoft Graph What-If API and generates a comprehensive, filterable HTML report.'

    PowerShellVersion    = '7.0'
    CompatiblePSEditions = @('Core')

    RequiredModules   = @(
        @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0' }
    )

    FunctionsToExport = @(
        'Connect-CAReporter'
        'Get-CAPolicy'
        'Get-CATenantUsers'
        'Invoke-CAWhatIfAnalysis'
        'Export-CAReport'
        'Export-CAGapReport'
        'Get-CAWhatIfReport'
        'Show-CAReporterGUI'
    )

    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('ConditionalAccess', 'WhatIf', 'M365', 'Security', 'Report', 'Entra', 'AzureAD')
            ProjectUri = 'https://github.com/RobinpZA/CA-Reporter'
            LicenseUri = 'https://github.com/RobinpZA/CA-Reporter/blob/main/LICENSE'
        }
    }
}
