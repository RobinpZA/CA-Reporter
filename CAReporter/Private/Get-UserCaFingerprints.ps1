function Get-UserCaFingerprints {
    <#
    .SYNOPSIS
        Groups users into CA-equivalent clusters to minimise evaluate API calls.
    .DESCRIPTION
        Analyses which Conditional Access policy conditions actually differentiate
        users from one another, then builds a fingerprint for each user based on:
            - User type (Member / Guest)
            - Which policy-referenced security groups they belong to (transitive)
            - Which policy-referenced directory roles they hold
            - Which policies explicitly target them by user ID (include / exclude)

        Users with identical fingerprints will produce identical CA What-If results
        for any given scenario. One representative per fingerprint is evaluated;
        results are then expanded to all equivalent users — reducing API calls
        without losing coverage.

        Performance: O(policy-groups) + O(policy-roles) Graph API calls, not O(users).
        A tenant with 500 users but only 8 policy-referenced groups will reduce
        evaluation volume to ~8 unique profiles.
    .PARAMETER Policies
        Array of CA policy objects (from Get-CAPolicy).
    .PARAMETER Users
        Array of user objects (from Get-CATenantUsers).
    .OUTPUTS
        Hashtable with:
          Representatives  - array of one user object per unique fingerprint
          EquivalentUsers  - hashtable mapping representative user ID to all
                             users sharing that fingerprint (including the rep)
          UniqueCount      - number of distinct CA profiles found
          TotalUsers       - original user count
    .EXAMPLE
        $fp = Get-UserCaFingerprints -Policies $policies -Users $users
        Write-Host "$($fp.UniqueCount) unique CA profiles for $($fp.TotalUsers) users"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Policies,

        [Parameter(Mandatory)]
        [array]$Users
    )

    $uuidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

    # Fast lookup set for user IDs in scope
    $userIdSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($u in $Users) { $userIdSet.Add($u.id) | Out-Null }

    # ── Collect all condition identifiers referenced across policies ─────────
    $groupIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $roleIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    # userId → Set of "policyId:inc" / "policyId:exc" strings
    $userPolicyMarkers = @{}

    foreach ($policy in $Policies) {
        $polId = $policy.id

        foreach ($gid in @($policy.conditions.users.includeGroups)) {
            if ($gid -and $gid -match $uuidPattern) { $groupIds.Add($gid) | Out-Null }
        }
        foreach ($gid in @($policy.conditions.users.excludeGroups)) {
            if ($gid -and $gid -match $uuidPattern) { $groupIds.Add($gid) | Out-Null }
        }

        foreach ($rid in @($policy.conditions.users.includeRoles)) {
            if ($rid -and $rid -match $uuidPattern) { $roleIds.Add($rid) | Out-Null }
        }
        foreach ($rid in @($policy.conditions.users.excludeRoles)) {
            if ($rid -and $rid -match $uuidPattern) { $roleIds.Add($rid) | Out-Null }
        }

        foreach ($uid in @($policy.conditions.users.includeUsers)) {
            if ($uid -and $uid -match $uuidPattern -and $userIdSet.Contains($uid)) {
                if (-not $userPolicyMarkers.ContainsKey($uid)) {
                    $userPolicyMarkers[$uid] = [System.Collections.Generic.HashSet[string]]::new()
                }
                $userPolicyMarkers[$uid].Add("$polId`:inc") | Out-Null
            }
        }
        foreach ($uid in @($policy.conditions.users.excludeUsers)) {
            if ($uid -and $uid -match $uuidPattern -and $userIdSet.Contains($uid)) {
                if (-not $userPolicyMarkers.ContainsKey($uid)) {
                    $userPolicyMarkers[$uid] = [System.Collections.Generic.HashSet[string]]::new()
                }
                $userPolicyMarkers[$uid].Add("$polId`:exc") | Out-Null
            }
        }
    }

    Write-Verbose "[CAReporter] User deduplication indexing: $($groupIds.Count) policy groups, $($roleIds.Count) policy roles, $($userPolicyMarkers.Count) explicitly-targeted users"

    # ── Fetch transitive members for each policy-referenced group ────────────
    # userGroupMembership[userId] = Set of groupIds the user belongs to
    $userGroupMembership = @{}
    foreach ($u in $Users) {
        $userGroupMembership[$u.id] = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
    }

    $gi = 0
    foreach ($groupId in $groupIds) {
        $gi++
        Write-Progress -Activity 'CA Reporter: Indexing group memberships' `
            -Status "Group $gi of $($groupIds.Count)" `
            -PercentComplete ([math]::Round($gi / [Math]::Max($groupIds.Count, 1) * 100))
        try {
            $uri = "https://graph.microsoft.com/v1.0/groups/$groupId/transitiveMembers/microsoft.graph.user?`$select=id&`$top=999"
            do {
                $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
                foreach ($member in $resp.value) {
                    if ($userGroupMembership.ContainsKey($member.id)) {
                        $userGroupMembership[$member.id].Add($groupId) | Out-Null
                    }
                }
                $uri = $resp.'@odata.nextLink'
            } while ($uri)
        }
        catch {
            Write-Verbose "[CAReporter]   Could not fetch members for group $groupId - $_"
        }
    }
    Write-Progress -Activity 'CA Reporter: Indexing group memberships' -Completed

    # ── Fetch members for each policy-referenced directory role ──────────────
    # userRoleMembership[userId] = Set of roleTemplateIds the user holds
    $userRoleMembership = @{}
    foreach ($u in $Users) {
        $userRoleMembership[$u.id] = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
    }

    $ri = 0
    foreach ($roleTemplateId in $roleIds) {
        $ri++
        Write-Progress -Activity 'CA Reporter: Indexing role memberships' `
            -Status "Role $ri of $($roleIds.Count)" `
            -PercentComplete ([math]::Round($ri / [Math]::Max($roleIds.Count, 1) * 100))
        try {
            $roleUri = "https://graph.microsoft.com/v1.0/directoryRoles?`$filter=roleTemplateId eq '$roleTemplateId'&`$select=id"
            $roleResp    = Invoke-MgGraphRequest -Method GET -Uri $roleUri -ErrorAction Stop
            $roleObjectId = $roleResp.value[0].id
            if ($roleObjectId) {
                $uri = "https://graph.microsoft.com/v1.0/directoryRoles/$roleObjectId/members?`$select=id&`$top=999"
                do {
                    $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
                    foreach ($member in $resp.value) {
                        if ($userRoleMembership.ContainsKey($member.id)) {
                            $userRoleMembership[$member.id].Add($roleTemplateId) | Out-Null
                        }
                    }
                    $uri = $resp.'@odata.nextLink'
                } while ($uri)
            }
        }
        catch {
            Write-Verbose "[CAReporter]   Could not fetch members for role $roleTemplateId - $_"
        }
    }
    Write-Progress -Activity 'CA Reporter: Indexing role memberships' -Completed

    # ── Build fingerprint per user ───────────────────────────────────────────
    # fingerprint string → list of users sharing it
    $fingerprintMap = @{}

    foreach ($user in $Users) {
        $groups  = ($userGroupMembership[$user.id] | Sort-Object) -join ','
        $roles   = ($userRoleMembership[$user.id]  | Sort-Object) -join ','
        $markers = if ($userPolicyMarkers.ContainsKey($user.id)) {
            ($userPolicyMarkers[$user.id] | Sort-Object) -join ','
        }
        else { '' }

        $fp = "$($user.userType)|g:$groups|r:$roles|m:$markers"

        if (-not $fingerprintMap.ContainsKey($fp)) {
            $fingerprintMap[$fp] = [System.Collections.Generic.List[object]]::new()
        }
        $fingerprintMap[$fp].Add($user)
    }

    # ── Build output ─────────────────────────────────────────────────────────
    $representatives = [System.Collections.Generic.List[object]]::new()
    $equivalentUsers = @{}  # repId → array of all users in that fingerprint group

    foreach ($fp in $fingerprintMap.Keys) {
        $group = $fingerprintMap[$fp]
        $rep   = $group[0]
        $representatives.Add($rep)
        $equivalentUsers[$rep.id] = $group.ToArray()
    }

    $saved = $Users.Count - $fingerprintMap.Count
    Write-Verbose "[CAReporter] User deduplication: $($Users.Count) users → $($fingerprintMap.Count) unique CA profiles (~$saved evaluate API calls saved per scenario)"

    @{
        Representatives = $representatives.ToArray()
        EquivalentUsers = $equivalentUsers
        UniqueCount     = $fingerprintMap.Count
        TotalUsers      = $Users.Count
    }
}
