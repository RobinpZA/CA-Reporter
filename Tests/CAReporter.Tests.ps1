#Requires -Modules Pester

BeforeAll {
    $ModulePath = Join-Path $PSScriptRoot '..' 'CAReporter' 'CAReporter.psd1'

    # Dot-source private functions directly for unit testing
    $PrivatePath = Join-Path $PSScriptRoot '..' 'CAReporter' 'Private'
    Get-ChildItem -Path "$PrivatePath\*.ps1" | ForEach-Object { . $_.FullName }

    # Initialise the module-scope cache that Resolve-AppDisplayName depends on
    $script:WellKnownAppIds = Get-WellKnownAppId
}

Describe 'Module manifest' {
    BeforeAll {
        $Manifest = Test-ModuleManifest -Path (Join-Path $PSScriptRoot '..' 'CAReporter' 'CAReporter.psd1')
    }

    It 'Has a valid manifest' {
        $Manifest | Should -Not -BeNullOrEmpty
    }

    It 'Has the correct root module' {
        $Manifest.RootModule | Should -Be 'CAReporter.psm1'
    }

    It 'Exports expected functions' {
        $Expected = @(
            'Connect-CAReporter'
            'Export-CAGapReport'
            'Export-CAReport'
            'Get-CAPolicy'
            'Get-CATenantUsers'
            'Get-CAWhatIfReport'
            'Invoke-CAWhatIfAnalysis'
            'Show-CAReporterGUI'
        )
        $Manifest.ExportedFunctions.Keys | Sort-Object | Should -Be ($Expected | Sort-Object)
    }

    It 'Has CompatiblePSEditions set to Core' {
        $Manifest.CompatiblePSEditions | Should -Contain 'Core'
    }

    It 'Requires PowerShell 7.0' {
        $Manifest.PowerShellVersion | Should -Be '7.0'
    }

    It 'Has a non-empty ProjectUri' {
        $Manifest.PrivateData.PSData.ProjectUri | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-WellKnownAppId' {
    BeforeAll {
        $AppIds = Get-WellKnownAppId
    }

    It 'Returns a hashtable' {
        $AppIds | Should -BeOfType [hashtable]
    }

    It 'Contains Office 365 entry' {
        $AppIds['67ad5377-2d78-4ac2-a867-6300cda00e85'] | Should -Be 'Office 365'
    }

    It 'Contains Microsoft Graph entry' {
        $AppIds['00000003-0000-0000-c000-000000000000'] | Should -Be 'Microsoft Graph'
    }

    It 'Has no invalid GUIDs (all keys are valid GUIDs or well-known aliases)' {
        $WellKnownAliases = @('Office365', 'MicrosoftAdminPortals', 'All', 'None')
        foreach ($key in $AppIds.Keys) {
            if ($key -notin $WellKnownAliases) {
                { [guid]::Parse($key) } | Should -Not -Throw -Because "Key '$key' should be a valid GUID"
            }
        }
    }
}

Describe 'Format-GrantControls' {
    It 'Returns friendly text for MFA' {
        $mock = @{
            grantControls = @{
                builtInControls = @('mfa')
                operator        = 'OR'
            }
        }
        $result = Format-GrantControls -PolicyResult $mock
        $result | Should -BeLike '*Require MFA*'
    }

    It 'Returns Block Access for block control' {
        $mock = @{
            grantControls = @{
                builtInControls = @('block')
            }
        }
        $result = Format-GrantControls -PolicyResult $mock
        $result | Should -BeLike '*Block Access*'
    }

    It 'Returns session-only message when no grant controls' {
        $mock = @{ grantControls = $null }
        $result = Format-GrantControls -PolicyResult $mock
        $result | Should -Be 'None (Session controls only)'
    }

    It 'Joins multiple controls with operator' {
        $mock = @{
            grantControls = @{
                builtInControls = @('mfa', 'compliantDevice')
                operator        = 'AND'
            }
        }
        $result = Format-GrantControls -PolicyResult $mock
        $result | Should -BeLike '*Require MFA*AND*Require Compliant Device*'
    }
}

Describe 'Format-SessionControls' {
    It 'Returns None when no session controls' {
        $mock = @{ sessionControls = $null }
        Format-SessionControls -PolicyResult $mock | Should -Be 'None'
    }

    It 'Formats sign-in frequency' {
        $mock = @{
            sessionControls = @{
                signInFrequency = @{
                    isEnabled = $true
                    value     = 4
                    type      = 'hours'
                }
            }
        }
        $result = Format-SessionControls -PolicyResult $mock
        $result | Should -BeLike '*Sign-in Frequency: 4 hours*'
    }
}

Describe 'New-WhatIfRequestBody' {
    It 'Builds a valid request body with required parameters' {
        $body = New-WhatIfRequestBody -UserId 'user-123' -IncludeApplications @('app-456')
        $body.signInIdentity.userId | Should -Be 'user-123'
        $body.signInContext.includeApplications | Should -Contain 'app-456'
        $body.signInConditions.clientAppType | Should -Be 'browser'
    }

    It 'Includes optional DevicePlatform when specified' {
        $body = New-WhatIfRequestBody -UserId 'u1' -IncludeApplications @('a1') -DevicePlatform 'windows'
        $body.signInConditions.devicePlatform | Should -Be 'windows'
    }

    It 'Includes Country and IpAddress when specified' {
        $body = New-WhatIfRequestBody -UserId 'u1' -IncludeApplications @('a1') -Country 'US' -IpAddress '1.2.3.4'
        $body.signInConditions.country | Should -Be 'US'
        $body.signInConditions.ipAddress | Should -Be '1.2.3.4'
    }

    It 'Does not include DevicePlatform when not specified' {
        $body = New-WhatIfRequestBody -UserId 'u1' -IncludeApplications @('a1')
        $body.signInConditions.ContainsKey('devicePlatform') | Should -BeFalse
    }
}

Describe 'Resolve-AppDisplayName' {
    It 'Resolves a well-known app ID to a friendly name' {
        $result = Resolve-AppDisplayName -AppId '00000003-0000-0000-c000-000000000000'
        $result | Should -Be 'Microsoft Graph'
    }

    It 'Returns the AppId when not found in cache or well-known list' {
        # Mock Invoke-MgGraphRequest to fail (no Graph connection in tests)
        Mock Invoke-MgGraphRequest { throw 'not connected' }
        $unknownId = '99999999-9999-9999-9999-999999999999'
        $result = Resolve-AppDisplayName -AppId $unknownId
        $result | Should -Be $unknownId
    }

    It 'Uses the AppNameCache when available' {
        $cache = @{ 'cached-id' = 'Cached App Name' }
        $result = Resolve-AppDisplayName -AppId 'cached-id' -AppNameCache $cache
        $result | Should -Be 'Cached App Name'
    }
}

Describe 'Get-ComprehensiveScenarios' {
    It 'Quick profile returns 1 scenario' {
        $scenarios = Get-ComprehensiveScenarios -Profile Quick
        $scenarios.Count | Should -Be 1
    }

    It 'Standard profile returns 18 scenarios' {
        $scenarios = Get-ComprehensiveScenarios -Profile Standard
        $scenarios.Count | Should -Be 18
    }

    It 'Thorough profile returns 42 scenarios' {
        $scenarios = Get-ComprehensiveScenarios -Profile Thorough
        $scenarios.Count | Should -Be 42
    }

    It 'Each scenario has required keys' {
        $scenarios = Get-ComprehensiveScenarios -Profile Standard
        foreach ($s in $scenarios) {
            $s.Keys | Should -Contain 'Application'
            $s.Keys | Should -Contain 'ClientAppType'
            $s.Keys | Should -Contain 'DevicePlatform'
            $s.Keys | Should -Contain 'Country'
            $s.Keys | Should -Contain 'IpAddress'
            $s.Keys | Should -Contain 'Label'
            $s.Keys | Should -Contain 'Index'
        }
    }

    It 'Accepts custom Applications override' {
        $scenarios = Get-ComprehensiveScenarios -Profile Quick -Applications @('AzurePortal', 'MicrosoftGraph')
        $scenarios.Count | Should -Be 2
        $scenarios[0].Application | Should -Be 'AzurePortal'
        $scenarios[1].Application | Should -Be 'MicrosoftGraph'
    }

    It 'Labels are sequential' {
        $scenarios = Get-ComprehensiveScenarios -Profile Standard
        for ($i = 0; $i -lt $scenarios.Count; $i++) {
            $scenarios[$i].Index | Should -Be ($i + 1)
        }
    }

    It 'Standard profile includes EAS (legacy auth) scenarios' {
        $scenarios = Get-ComprehensiveScenarios -Profile Standard
        $legacyScenarios = $scenarios | Where-Object { $_.ClientAppType -eq 'exchangeActiveSync' }
        $legacyScenarios.Count | Should -BeGreaterThan 0
    }

    It 'Thorough profile includes both EAS and Other legacy auth scenarios' {
        $scenarios = Get-ComprehensiveScenarios -Profile Thorough
        $eas   = $scenarios | Where-Object { $_.ClientAppType -eq 'exchangeActiveSync' }
        $other = $scenarios | Where-Object { $_.ClientAppType -eq 'other' }
        $eas.Count   | Should -BeGreaterThan 0
        $other.Count | Should -BeGreaterThan 0
    }

    It 'Legacy auth scenarios have empty DevicePlatform' {
        $scenarios = Get-ComprehensiveScenarios -Profile Standard
        $legacy = $scenarios | Where-Object { $_.ClientAppType -eq 'exchangeActiveSync' }
        foreach ($s in $legacy) {
            $s.DevicePlatform | Should -Be ''
        }
    }

    It '-Countries adds location variant copies of all base scenarios' {
        $base     = Get-ComprehensiveScenarios -Profile Standard
        $withLoc  = Get-ComprehensiveScenarios -Profile Standard -Countries @('CN', 'RU')
        $withLoc.Count | Should -Be ($base.Count * 3)  # base + 2 country copies
        $cnScenarios = $withLoc | Where-Object { $_.Country -eq 'CN' }
        $cnScenarios.Count | Should -Be $base.Count
    }

    It '-IpAddresses adds IP variant copies of all base scenarios' {
        $base    = Get-ComprehensiveScenarios -Profile Standard
        $withIp  = Get-ComprehensiveScenarios -Profile Standard -IpAddresses @('1.2.3.4')
        $withIp.Count | Should -Be ($base.Count * 2)  # base + 1 IP copy
        $ipScenarios = $withIp | Where-Object { $_.IpAddress -eq '1.2.3.4' }
        $ipScenarios.Count | Should -Be $base.Count
    }

    It 'Country codes are uppercased' {
        $scenarios = Get-ComprehensiveScenarios -Profile Quick -Countries @('cn')
        $locationScenarios = @($scenarios | Where-Object { $_.Country })
        $locationScenarios[0].Country | Should -Be 'CN'
    }

    It 'All scenarios have sequential index after location expansion' {
        $scenarios = Get-ComprehensiveScenarios -Profile Standard -Countries @('US')
        for ($i = 0; $i -lt $scenarios.Count; $i++) {
            $scenarios[$i].Index | Should -Be ($i + 1)
        }
    }

    Context 'Policy-driven platform pruning' {
        It 'Collapses to Any-platform when no policy has platform conditions' {
            $policies = @(
                @{ conditions = @{ platforms = $null } },
                @{ conditions = @{ platforms = @{ includePlatforms = @(); excludePlatforms = @() } } }
            )
            $pruned = Get-ComprehensiveScenarios -Profile Standard -Policies $policies
            $platformsUsed = $pruned | Select-Object -ExpandProperty DevicePlatform -Unique
            # Legacy auth always has empty platform; modern auth should also be empty (Any) after pruning
            $modernScenarios = $pruned | Where-Object { $_.ClientAppType -in @('browser', 'mobileAppsAndDesktopClients') }
            $modernPlatforms = @($modernScenarios | Select-Object -ExpandProperty DevicePlatform -Unique)
            $modernPlatforms.Count | Should -Be 1
            $modernPlatforms[0] | Should -Be ''
        }

        It 'Prunes to only referenced platforms when policies specify them' {
            $policies = @(
                @{ conditions = @{ platforms = @{ includePlatforms = @('windows', 'iOS'); excludePlatforms = @() } } }
            )
            $pruned = Get-ComprehensiveScenarios -Profile Thorough -Policies $policies
            $modernScenarios  = $pruned | Where-Object { $_.ClientAppType -eq 'browser' }
            $platformsUsed    = @($modernScenarios | Select-Object -ExpandProperty DevicePlatform -Unique)
            # Should keep: '' (Any), windows, iOS — not android, macOS, linux
            $platformsUsed | Should -Contain ''
            $platformsUsed | Should -Contain 'windows'
            $platformsUsed | Should -Contain 'iOS'
            $platformsUsed | Should -Not -Contain 'android'
            $platformsUsed | Should -Not -Contain 'linux'
        }

        It 'Returns fewer scenarios than without -Policies when no platform conditions exist' {
            $policiesNoPlatform = @(
                @{ conditions = @{ platforms = $null } }
            )
            $unpruned = Get-ComprehensiveScenarios -Profile Standard
            $pruned   = Get-ComprehensiveScenarios -Profile Standard -Policies $policiesNoPlatform
            $pruned.Count | Should -BeLessThan $unpruned.Count
        }
    }
}

Describe 'Get-UserCaFingerprints' {
    BeforeAll {
        # Load the function (private functions are already dot-sourced by BeforeAll at the top)
        # Build a minimal set of test users with proper GUID-format IDs (the function
        # uses a UUID pattern to identify real object references in policy conditions)
        $script:fpUsers = @(
            [PSCustomObject]@{ id = 'aaaaaaaa-0000-0000-0000-000000000001'; userPrincipalName = 'a@corp.com'; displayName = 'A'; userType = 'Member' },
            [PSCustomObject]@{ id = 'bbbbbbbb-0000-0000-0000-000000000002'; userPrincipalName = 'b@corp.com'; displayName = 'B'; userType = 'Member' },
            [PSCustomObject]@{ id = 'cccccccc-0000-0000-0000-000000000003'; userPrincipalName = 'c@corp.com'; displayName = 'C'; userType = 'Guest' }
        )
    }

    It 'When policies have no group/role conditions, all users with same type share a fingerprint' {
        # Policies with only All-users conditions — no groups/roles/explicit IDs
        $policies = @(
            @{ id = 'p1'; conditions = @{
                users = @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() }
            }}
        )
        # Mock Invoke-MgGraphRequest — no groups to fetch, so it should never be called
        Mock Invoke-MgGraphRequest { throw 'should not be called' }

        $result = Get-UserCaFingerprints -Policies $policies -Users $script:fpUsers
        # Members share a type; Guest is different type
        $result.UniqueCount | Should -Be 2   # 'Member' profile + 'Guest' profile
        $result.TotalUsers  | Should -Be 3
    }

    It 'Returns one representative per unique fingerprint' {
        $policies = @(
            @{ id = 'p1'; conditions = @{
                users = @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() }
            }}
        )
        Mock Invoke-MgGraphRequest { throw 'should not be called' }

        $result = Get-UserCaFingerprints -Policies $policies -Users $script:fpUsers
        $result.Representatives.Count | Should -Be $result.UniqueCount
    }

    It 'Each representative maps to a non-empty EquivalentUsers list' {
        $policies = @(
            @{ id = 'p1'; conditions = @{
                users = @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() }
            }}
        )
        Mock Invoke-MgGraphRequest { throw 'should not be called' }

        $result = Get-UserCaFingerprints -Policies $policies -Users $script:fpUsers
        foreach ($rep in $result.Representatives) {
            $result.EquivalentUsers[$rep.id].Count | Should -BeGreaterOrEqual 1
        }
    }

    It 'Explicitly excluded user gets a unique fingerprint' {
        $policies = @(
            @{ id = 'p1111111-0000-0000-0000-000000000001'; conditions = @{
                users = @{
                    includeUsers  = @('All')
                    excludeUsers  = @('bbbbbbbb-0000-0000-0000-000000000002')   # explicitly excluded
                    includeGroups = @()
                    excludeGroups = @()
                    includeRoles  = @()
                    excludeRoles  = @()
                }
            }}
        )
        Mock Invoke-MgGraphRequest { throw 'should not be called' }

        $result = Get-UserCaFingerprints -Policies $policies -Users $script:fpUsers
        # user-b has unique fingerprint (excluded from p1), user-a and user-c have their own
        # There should be at least 3 unique fingerprints: (Member+excluded), (Member), (Guest)
        $result.UniqueCount | Should -BeGreaterOrEqual 3
    }

    It 'Total users in EquivalentUsers equals input user count' {
        $policies = @(
            @{ id = 'p1'; conditions = @{
                users = @{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() }
            }}
        )
        Mock Invoke-MgGraphRequest { throw 'should not be called' }

        $result    = Get-UserCaFingerprints -Policies $policies -Users $script:fpUsers
        $allMapped = $result.EquivalentUsers.Values | ForEach-Object { $_ } | Measure-Object
        $allMapped.Count | Should -Be $script:fpUsers.Count
    }
}
