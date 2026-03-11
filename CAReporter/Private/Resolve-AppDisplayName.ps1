function Resolve-AppDisplayName {
    <#
    .SYNOPSIS
        Resolves an application ID to a friendly display name.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AppId,

        [hashtable]$AppNameCache = @{}
    )

    $wellKnown = Get-WellKnownAppId

    if ($wellKnown.ContainsKey($AppId)) {
        return $wellKnown[$AppId]
    }

    if ($AppNameCache.ContainsKey($AppId)) {
        return $AppNameCache[$AppId]
    }

    # Try to resolve via Graph
    try {
        $sp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$AppId'&`$select=displayName" -ErrorAction Stop
        if ($sp.value -and $sp.value.Count -gt 0) {
            $name = $sp.value[0].displayName
            $AppNameCache[$AppId] = $name
            return $name
        }
    }
    catch {
        # Swallow lookup failures
    }

    return $AppId
}
