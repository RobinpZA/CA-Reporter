function Show-CAReporterGUI {
    <#
    .SYNOPSIS
        Launches a graphical interface for configuring and running CA What-If reports.
    .DESCRIPTION
        Opens a WPF-based GUI that lets the user select applications, client app type,
        device platform, risk levels, and other options, then runs Get-CAWhatIfReport
        with those settings.
    .EXAMPLE
        Show-CAReporterGUI
    #>
    [CmdletBinding()]
    param()

    # WPF requires STA; PowerShell 7 defaults to MTA, so run in a dedicated runspace
    Add-Type -AssemblyName PresentationFramework -ErrorAction Stop

    # -- Build the app-list from the module-level completion table --
    $appItems = [System.Collections.Generic.List[object]]::new()
    foreach ($kv in $script:AppCompletions.GetEnumerator()) {
        $appItems.Add([PSCustomObject]@{ Name = $kv.Key; Id = $kv.Value })
    }

    # ---- XAML ----
    [xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="CA Reporter" Width="640" Height="720"
        WindowStartupLocation="CenterScreen"
        Background="#0f172a" Foreground="#f1f5f9"
        ResizeMode="CanResizeWithGrip">
    <Window.Resources>
        <Style TargetType="Label">
            <Setter Property="Foreground" Value="#94a3b8"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Margin" Value="0,6,0,2"/>
        </Style>
        <Style x:Key="SectionHeader" TargetType="TextBlock">
            <Setter Property="Foreground" Value="#3b82f6"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Margin" Value="0,12,0,4"/>
        </Style>
        <Style TargetType="CheckBox">
            <Setter Property="Foreground" Value="#f1f5f9"/>
            <Setter Property="Margin" Value="0,4,12,4"/>
            <Setter Property="VerticalContentAlignment" Value="Center"/>
        </Style>
        <Style TargetType="ComboBox">
            <Setter Property="Margin" Value="0,0,0,4"/>
            <Setter Property="Height" Value="28"/>
        </Style>
        <Style TargetType="TextBox">
            <Setter Property="Margin" Value="0,0,0,4"/>
            <Setter Property="Height" Value="28"/>
            <Setter Property="VerticalContentAlignment" Value="Center"/>
        </Style>
    </Window.Resources>

    <Grid Margin="20">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Title -->
        <StackPanel Grid.Row="0" Margin="0,0,0,8">
            <TextBlock Text="CA Reporter" FontSize="22" FontWeight="Bold" Foreground="#f1f5f9"/>
            <TextBlock Text="Conditional Access What-If Analysis" FontSize="12" Foreground="#64748b"/>
        </StackPanel>

        <!-- Scrollable content -->
        <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" Margin="0,0,0,8">
            <StackPanel>

                <!-- Applications -->
                <TextBlock Style="{StaticResource SectionHeader}" Text="Applications"/>
                <ListBox Name="lstApps" Height="140" SelectionMode="Multiple"
                         Background="#1e293b" Foreground="#f1f5f9" BorderBrush="#334155"
                         DisplayMemberPath="Name"/>

                <!-- Client App Type -->
                <TextBlock Style="{StaticResource SectionHeader}" Text="Sign-In Conditions"/>
                <Label Content="Client App Type"/>
                <ComboBox Name="cmbClientApp">
                    <ComboBoxItem Content="browser" IsSelected="True"/>
                    <ComboBoxItem Content="mobileAppsAndDesktopClients"/>
                    <ComboBoxItem Content="exchangeActiveSync"/>
                    <ComboBoxItem Content="easSupported"/>
                    <ComboBoxItem Content="other"/>
                </ComboBox>

                <!-- Device Platform -->
                <Label Content="Device Platform"/>
                <ComboBox Name="cmbPlatform">
                    <ComboBoxItem Content="(Any)" IsSelected="True"/>
                    <ComboBoxItem Content="android"/>
                    <ComboBoxItem Content="iOS"/>
                    <ComboBoxItem Content="windows"/>
                    <ComboBoxItem Content="windowsPhone"/>
                    <ComboBoxItem Content="macOS"/>
                    <ComboBoxItem Content="linux"/>
                </ComboBox>

                <!-- Risk levels side by side -->
                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="12"/>
                        <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>
                    <StackPanel Grid.Column="0">
                        <Label Content="Sign-in Risk Level"/>
                        <ComboBox Name="cmbSignInRisk">
                            <ComboBoxItem Content="none" IsSelected="True"/>
                            <ComboBoxItem Content="low"/>
                            <ComboBoxItem Content="medium"/>
                            <ComboBoxItem Content="high"/>
                        </ComboBox>
                    </StackPanel>
                    <StackPanel Grid.Column="2">
                        <Label Content="User Risk Level"/>
                        <ComboBox Name="cmbUserRisk">
                            <ComboBoxItem Content="none" IsSelected="True"/>
                            <ComboBoxItem Content="low"/>
                            <ComboBoxItem Content="medium"/>
                            <ComboBoxItem Content="high"/>
                        </ComboBox>
                    </StackPanel>
                </Grid>

                <!-- Location -->
                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="12"/>
                        <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>
                    <StackPanel Grid.Column="0">
                        <Label Content="Country (2-letter code)"/>
                        <TextBox Name="txtCountry" MaxLength="2"/>
                    </StackPanel>
                    <StackPanel Grid.Column="2">
                        <Label Content="IP Address"/>
                        <TextBox Name="txtIpAddress"/>
                    </StackPanel>
                </Grid>

                <!-- User options -->
                <TextBlock Style="{StaticResource SectionHeader}" Text="User Options"/>
                <Label Content="Max Users (0 = all)"/>
                <TextBox Name="txtMaxUsers" Text="0"/>
                <WrapPanel Margin="0,4,0,0">
                    <CheckBox Name="chkIncludeGuests" Content="Include Guests"/>
                    <CheckBox Name="chkExcludeDisabled" Content="Exclude Disabled Users"/>
                </WrapPanel>

                <!-- Policy options -->
                <TextBlock Style="{StaticResource SectionHeader}" Text="Policy Options"/>
                <WrapPanel Margin="0,4,0,0">
                    <CheckBox Name="chkReportOnly" Content="Include Report-Only"/>
                    <CheckBox Name="chkDisabled" Content="Include Disabled"/>
                </WrapPanel>

                <!-- Comprehensive Mode -->
                <TextBlock Style="{StaticResource SectionHeader}" Text="Comprehensive Gap Analysis"/>
                <CheckBox Name="chkComprehensive" Content="Run comprehensive MFA gap analysis" Margin="0,4,0,4"/>
                <StackPanel Name="pnlScenarioProfile" Margin="20,0,0,0">
                    <Label Content="Scenario Profile"/>
                    <ComboBox Name="cmbScenarioProfile">
                        <ComboBoxItem Content="Quick" ToolTip="1 scenario — fast check"/>
                        <ComboBoxItem Content="Standard" IsSelected="True" ToolTip="18 scenarios — recommended"/>
                        <ComboBoxItem Content="Thorough" ToolTip="42 scenarios — most complete"/>
                    </ComboBox>
                    <Label Content="Additional Countries (comma-separated, e.g. CN, RU, NG)"/>
                    <TextBox Name="txtCompCountries" ToolTip="Each country code adds a full copy of the base scenarios to test location-based policies"/>
                    <Label Content="Additional IP Addresses (comma-separated)"/>
                    <TextBox Name="txtCompIpAddresses" ToolTip="Each IP adds a full copy of the base scenarios to test named-location policies"/>
                </StackPanel>

                <!-- Output -->
                <TextBlock Style="{StaticResource SectionHeader}" Text="Output"/>
                <CheckBox Name="chkOpenReport" Content="Open report in browser when complete" IsChecked="True"/>
                <CheckBox Name="chkDisconnect" Content="Disconnect from Microsoft Graph when complete"/>
                <Label Content="Output Path (leave blank for auto)"/>
                <TextBox Name="txtOutputPath"/>

            </StackPanel>
        </ScrollViewer>

        <!-- Buttons -->
        <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right">
            <Button Name="btnCancel" Content="Cancel" Width="90" Height="34" Margin="0,0,10,0"
                    Background="#334155" Foreground="#f1f5f9" BorderBrush="#475569"
                    FontSize="13" Cursor="Hand"/>
            <Button Name="btnRun" Content="Run Report" Width="120" Height="34"
                    Background="#3b82f6" Foreground="White" BorderBrush="#2563eb"
                    FontWeight="SemiBold" FontSize="13" Cursor="Hand"/>
        </StackPanel>
    </Grid>
</Window>
"@

    # ---- Create window ----
    $reader = [System.Xml.XmlNodeReader]::new($xaml)
    $window = [System.Windows.Markup.XamlReader]::Load($reader)

    # ---- Get controls ----
    $lstApps           = $window.FindName('lstApps')
    $cmbClientApp      = $window.FindName('cmbClientApp')
    $cmbPlatform       = $window.FindName('cmbPlatform')
    $cmbSignInRisk     = $window.FindName('cmbSignInRisk')
    $cmbUserRisk       = $window.FindName('cmbUserRisk')
    $txtCountry        = $window.FindName('txtCountry')
    $txtIpAddress      = $window.FindName('txtIpAddress')
    $txtMaxUsers       = $window.FindName('txtMaxUsers')
    $chkIncludeGuests  = $window.FindName('chkIncludeGuests')
    $chkExcludeDisabled = $window.FindName('chkExcludeDisabled')
    $chkReportOnly     = $window.FindName('chkReportOnly')
    $chkDisabled       = $window.FindName('chkDisabled')
    $chkComprehensive  = $window.FindName('chkComprehensive')
    $pnlScenarioProfile = $window.FindName('pnlScenarioProfile')
    $cmbScenarioProfile = $window.FindName('cmbScenarioProfile')
    $txtCompCountries    = $window.FindName('txtCompCountries')
    $txtCompIpAddresses  = $window.FindName('txtCompIpAddresses')
    $chkOpenReport     = $window.FindName('chkOpenReport')
    $chkDisconnect     = $window.FindName('chkDisconnect')
    $txtOutputPath     = $window.FindName('txtOutputPath')
    $btnRun            = $window.FindName('btnRun')
    $btnCancel         = $window.FindName('btnCancel')

    # Populate application list and pre-select Office365
    foreach ($item in $appItems) {
        $lstApps.Items.Add($item) | Out-Null
    }
    # Pre-select Office365
    for ($i = 0; $i -lt $lstApps.Items.Count; $i++) {
        if ($lstApps.Items[$i].Name -eq 'Office365') {
            $lstApps.SelectedItems.Add($lstApps.Items[$i]) | Out-Null
            break
        }
    }

    # ---- Result holder ----
    $script:guiResult = $null

    # ---- Button handlers ----
    $btnCancel.Add_Click({
        $window.DialogResult = $false
        $window.Close()
    })

    $btnRun.Add_Click({
        # Gather selections
        $selectedApps = @($lstApps.SelectedItems | ForEach-Object { $_.Name })
        if ($selectedApps.Count -eq 0) {
            [System.Windows.MessageBox]::Show(
                'Please select at least one application.',
                'CA Reporter', 'OK', 'Warning') | Out-Null
            return
        }

        $params = @{
            Applications    = $selectedApps
            ClientAppType   = $cmbClientApp.SelectedItem.Content.ToString()
            SignInRiskLevel = $cmbSignInRisk.SelectedItem.Content.ToString()
            UserRiskLevel   = $cmbUserRisk.SelectedItem.Content.ToString()
        }

        $platform = $cmbPlatform.SelectedItem.Content.ToString()
        if ($platform -ne '(Any)') { $params['DevicePlatform'] = $platform }

        $maxUsers = 0
        if ([int]::TryParse($txtMaxUsers.Text, [ref]$maxUsers) -and $maxUsers -gt 0) {
            $params['MaxUsers'] = $maxUsers
        }

        $country = $txtCountry.Text.Trim()
        if ($country) { $params['Country'] = $country }

        $ip = $txtIpAddress.Text.Trim()
        if ($ip) { $params['IpAddress'] = $ip }

        if ($chkIncludeGuests.IsChecked)   { $params['IncludeGuests']        = $true }
        if ($chkExcludeDisabled.IsChecked) { $params['ExcludeDisabledUsers'] = $true }
        if ($chkReportOnly.IsChecked)      { $params['IncludeReportOnly']    = $true }
        if ($chkDisabled.IsChecked)        { $params['IncludeDisabled']      = $true }
        if ($chkOpenReport.IsChecked)      { $params['OpenReport']           = $true }
        if ($chkDisconnect.IsChecked)      { $params['DisconnectWhenDone']   = $true }

        if ($chkComprehensive.IsChecked) {
            $params['Comprehensive']   = $true
            $params['ScenarioProfile'] = $cmbScenarioProfile.SelectedItem.Content.ToString()

            $compCountries = $txtCompCountries.Text.Trim()
            if ($compCountries) {
                $params['ComprehensiveCountries'] = @($compCountries -split '\s*,\s*' | Where-Object { $_ })
            }
            $compIps = $txtCompIpAddresses.Text.Trim()
            if ($compIps) {
                $params['ComprehensiveIpAddresses'] = @($compIps -split '\s*,\s*' | Where-Object { $_ })
            }
        }

        $outPath = $txtOutputPath.Text.Trim()
        if ($outPath) { $params['OutputPath'] = $outPath }

        $script:guiResult = $params
        $window.DialogResult = $true
        $window.Close()
    })

    # ---- Show dialog ----
    $dialogResult = $window.ShowDialog()

    if ($dialogResult -and $script:guiResult) {
        Write-Host '[CAReporter] Starting report with GUI selections...' -ForegroundColor Cyan
        Get-CAWhatIfReport @script:guiResult
    }
    else {
        Write-Host '[CAReporter] Cancelled.' -ForegroundColor DarkGray
    }
}
