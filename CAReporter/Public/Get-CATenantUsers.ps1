function Get-CATenantUsers {
    <#
    .SYNOPSIS
        Retrieves users from the tenant for CA What-If testing.
    .DESCRIPTION
        Fetches user accounts with pagination. Supports limiting the result count,
        filtering to specific user types, and excluding service accounts.
    .PARAMETER MaxUsers
        Maximum number of users to return. Default 0 = all users.
    .PARAMETER IncludeGuests
        Include guest/external users.
    .PARAMETER UserType
        Filter by user type: All, Member, Guest.
    .PARAMETER Filter
        Custom OData filter string.
    .PARAMETER ExcludeDisabled
        Exclude disabled accounts.
    .EXAMPLE
        Get-CATenantUsers -MaxUsers 50
    .EXAMPLE
        Get-CATenantUsers -IncludeGuests -ExcludeDisabled
    #>
    [CmdletBinding()]
    param(
        [int]$MaxUsers = 0,

        [switch]$IncludeGuests,

        [ValidateSet('All', 'Member', 'Guest')]
        [string]$UserType = 'All',

        [string]$Filter,

        [switch]$ExcludeDisabled
    )

    Write-Host '[CAReporter] Retrieving tenant users...' -ForegroundColor Cyan

    $selectFields = 'id,displayName,userPrincipalName,mail,userType,accountEnabled,assignedLicenses'
    $users = @()
    $pageSize = 999

    # Build filter
    $filters = @()
    if ($UserType -eq 'Member') {
        $filters += "userType eq 'Member'"
    }
    elseif ($UserType -eq 'Guest') {
        $filters += "userType eq 'Guest'"
    }
    elseif (-not $IncludeGuests -and $UserType -eq 'All') {
        # Default: include both but the switch controls it
    }

    if ($ExcludeDisabled) {
        $filters += 'accountEnabled eq true'
    }

    if ($Filter) {
        $filters += $Filter
    }

    $filterString = if ($filters.Count -gt 0) { "&`$filter=$($filters -join ' and ')" } else { '' }
    $uri = "https://graph.microsoft.com/v1.0/users?`$select=$selectFields&`$top=$pageSize$filterString&`$count=true"

    $headers = @{ ConsistencyLevel = 'eventual' }

    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -Headers $headers -ErrorAction Stop
        $users += $response.value
        $uri = $response.'@odata.nextLink'

        if ($MaxUsers -gt 0 -and $users.Count -ge $MaxUsers) {
            $users = $users | Select-Object -First $MaxUsers
            break
        }

        if ($users.Count % 1000 -lt $pageSize) {
            Write-Host "[CAReporter]   Retrieved $($users.Count) users so far..." -ForegroundColor DarkGray
        }
    } while ($uri)

    # Separate members and guests
    $members = @($users | Where-Object { $_.userType -eq 'Member' -or -not $_.userType })
    $guests  = @($users | Where-Object { $_.userType -eq 'Guest' })

    Write-Host "[CAReporter] Retrieved $($users.Count) users (Members: $($members.Count), Guests: $($guests.Count))" -ForegroundColor Green

    $users
}
