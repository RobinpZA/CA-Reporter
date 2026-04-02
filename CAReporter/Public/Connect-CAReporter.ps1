function Connect-CAReporter {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph with the required scopes for CA What-If testing.
    .DESCRIPTION
        Wraps Connect-MgGraph with the minimum required scopes for running
        Conditional Access What-If evaluations and reading user/policy data.
    .PARAMETER TenantId
        Optional tenant ID to connect to a specific tenant.
    .PARAMETER ClientId
        Optional client/app ID for app-based authentication.
    .PARAMETER CertificateThumbprint
        Optional certificate thumbprint for app-based authentication.
    .EXAMPLE
        Connect-CAReporter
    .EXAMPLE
        Connect-CAReporter -TenantId 'contoso.onmicrosoft.com'
    #>
    [CmdletBinding()]
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$CertificateThumbprint
    )

    $requiredScopes = @(
        'Policy.Read.All'
        'Directory.Read.All'
        'Application.Read.All'
    )

    $connectParams = @{
        Scopes   = $requiredScopes
        NoWelcome = $true
    }

    if ($TenantId)              { $connectParams['TenantId']              = $TenantId }
    if ($ClientId)              { $connectParams['ClientId']              = $ClientId }
    if ($CertificateThumbprint) { $connectParams['CertificateThumbprint'] = $CertificateThumbprint }

    Write-Verbose '[CAReporter] Connecting to Microsoft Graph...'
    Connect-MgGraph @connectParams -ErrorAction Stop

    # Verify connection
    $ctx = Get-MgContext
    if (-not $ctx) {
        throw 'Failed to connect to Microsoft Graph. Please check your credentials and try again.'
    }

    Write-Verbose "[CAReporter] Connected to tenant: $($ctx.TenantId)"
    Write-Verbose "[CAReporter] Account: $($ctx.Account)"
    Write-Verbose "[CAReporter] Scopes: $($ctx.Scopes -join ', ')"
    $ctx
}
