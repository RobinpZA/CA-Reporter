function Get-MerillAppInfo {
    <#
    .SYNOPSIS
        Returns a hashtable mapping Microsoft first-party app IDs to display names.
    .DESCRIPTION
        Fetches the community-maintained app list from https://github.com/merill/microsoft-info
        on first call and caches the result for the remainder of the session. Returns an empty
        hashtable silently if the download fails (e.g. no internet access).
    #>
    [CmdletBinding()]
    param()

    if ($null -ne $script:MerillAppCache) {
        return $script:MerillAppCache
    }

    try {
        $uri  = 'https://raw.githubusercontent.com/merill/microsoft-info/main/_info/MicrosoftApps.json'
        $data = Invoke-RestMethod -Uri $uri -TimeoutSec 15 -ErrorAction Stop

        $cache       = @{}
        $searchIndex = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($entry in $data) {
            if ($entry.AppId -and $entry.AppDisplayName) {
                # Prefer Graph-sourced entries; only write if not already present so that
                # Graph entries (which come first in the file) win over EntraDocs entries.
                if (-not $cache.ContainsKey($entry.AppId)) {
                    $cache[$entry.AppId] = $entry.AppDisplayName
                }
                # Build a search index from Graph-sourced entries only — these correspond
                # to actual service principals that can be used in CA What-If evaluation.
                # EntraDocs entries include Graph permission/role names, not real apps.
                if ($entry.Source -eq 'Graph') {
                    $searchIndex.Add([PSCustomObject]@{
                        id   = [string]$entry.AppId
                        name = [string]$entry.AppDisplayName
                    })
                }
            }
        }

        $script:MerillAppCache       = $cache
        $script:MerillAppSearchIndex = $searchIndex
        Write-Verbose "Loaded $($cache.Count) app names from merill/microsoft-info ($($searchIndex.Count) in search index)"
    }
    catch {
        # Network unavailable or endpoint changed — fail gracefully
        $script:MerillAppCache       = @{}
        $script:MerillAppSearchIndex = @()
        Write-Verbose "Could not fetch merill/microsoft-info app list: $_"
    }

    return $script:MerillAppCache
}
