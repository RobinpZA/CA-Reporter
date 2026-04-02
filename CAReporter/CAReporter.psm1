#Requires -Version 7.0

# CAReporter Module Loader
# Dot-source all private and public functions

$Private = @(Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue)
$Public  = @(Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1"  -ErrorAction SilentlyContinue)

foreach ($file in @($Private + $Public)) {
    try {
        . $file.FullName
    }
    catch {
        Write-Error "Failed to import function from $($file.FullName): $_"
    }
}

# Export public functions
Export-ModuleMember -Function $Public.BaseName

# Cache well-known app IDs at module scope for performance
$script:WellKnownAppIds = Get-WellKnownAppId

# --- Tab-completion for -Applications parameter ---
# Maps friendly alias names to well-known application GUIDs so users can
# press Tab and pick from a readable list instead of memorising GUIDs.
$script:AppCompletions = [ordered]@{
    'Office365'              = '67ad5377-2d78-4ac2-a867-6300cda00e85'
    'ExchangeOnline'         = '00000002-0000-0ff1-ce00-000000000000'
    'SharePointOnline'       = '00000003-0000-0ff1-ce00-000000000000'
    'Office365Portal'        = '00000006-0000-0ff1-ce00-000000000000'
    'AzurePortal'            = 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c'
    'AzureServiceManagement' = '797f4846-ba00-4fd7-ba43-dac1f8f63013'
    'AzureCLI'               = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
    'AzurePowerShell'        = '1950a258-227b-4e31-a9cf-717495945fc2'
    'MicrosoftGraph'         = '00000003-0000-0000-c000-000000000000'
    'MicrosoftIntune'        = '0000000a-0000-0000-c000-000000000000'
    'IntuneEnrollment'       = 'd4ebce55-015a-49b5-a083-c84d1797ae8c'
    'ComplianceCenter'       = 'de8bc8b5-d9f9-48b1-a8ad-b748da725064'
    'PowerBI'                = '00000007-0000-0ff1-ce00-000000000000'
    'MicrosoftTeams'         = 'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe'
    'TeamsWebClient'         = '5e3ce6c0-2b1f-4285-8d4b-75ee78787346'
    'DynamicsCRM'            = '00000015-0000-0000-c000-000000000000'
    'ExchangeRESTAPI'        = 'fc780465-2017-40d4-a0c5-307022471b92'
    'Office365ManagementAPI' = '00b41c95-dab0-4487-9791-b9d2c32c80f2'
    'DefenderCloudApps'      = '09abbdfd-ed23-44ee-a2d9-a627aa1c90f3'
}

$appCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    $script:AppCompletions.GetEnumerator() | Where-Object { $_.Key -like "$wordToComplete*" } | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new(
            $_.Key,            # completionText  (friendly name inserted)
            $_.Key,            # listItemText    (friendly name shown in menu)
            'ParameterValue',
            "$($_.Key) ($($_.Value))"  # toolTip
        )
    }
}

Register-ArgumentCompleter -CommandName Get-CAWhatIfReport      -ParameterName Applications -ScriptBlock $appCompleter
Register-ArgumentCompleter -CommandName Invoke-CAWhatIfAnalysis  -ParameterName Applications -ScriptBlock $appCompleter

# --- Tab-completion for -ScenarioProfile parameter ---
$scenarioProfileCompleter = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    @('Quick', 'Standard', 'Thorough') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}
Register-ArgumentCompleter -CommandName Get-CAWhatIfReport -ParameterName ScenarioProfile -ScriptBlock $scenarioProfileCompleter
