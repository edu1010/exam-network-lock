using System.Collections.ObjectModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using ExamDesktop.Ui;
using ExamShared;

namespace ExamConfigGenerator;

/// <summary>Avalonia port of the WinForms generator: same sections, validation and signed output.</summary>
public sealed class MainWindow : Window
{
    private readonly List<(Control ctrl, string key)> _i18n = new();
    private readonly List<(Control control, string key)> _helpTargets = new();
    private readonly LanguageBar _languageBar;

    private readonly TextBox _passwordBox = Password();
    private readonly TextBox _confirmBox = Password();
    private readonly TextBox _adminPasswordBox = Password();
    private readonly TextBox _adminConfirmBox = Password();

    private readonly CheckBox _disableWifiCheck;
    private readonly CheckBox _disableBluetoothCheck;
    private readonly CheckBox _aiShieldCheck;
    private readonly CheckBox _raiseVolumeCheck;
    private readonly CheckBox _detectVmCheck;
    private readonly CheckBox _monitorCheck;
    private readonly TextBox _monitorTargetsBox = new() { Watermark = "192.168.1.70" };
    private readonly ComboBox _beepModeCombo = new() { Width = 300 };
    private readonly ComboBox _volumeCombo = new() { Width = 300 };

    private readonly ObservableCollection<string> _aiItems = new(ConfigDefaults.DefaultAiBlocklist);
    private readonly ObservableCollection<string> _appItems = new();
    private readonly ObservableCollection<string> _blockedAppItems = new();
    private readonly ListBox _aiList;
    private readonly ListBox _appList;
    private readonly ListBox _blockedAppList;
    private readonly TextBox _aiInput = new();
    private readonly TextBox _extensionsBox = new();
    private readonly TextBox _blockedExtensionsBox = new();
    private readonly CheckBox _restrictFolderCheck;
    private readonly ComboBox _workFolderModeCombo = new() { HorizontalAlignment = HorizontalAlignment.Stretch };
    private readonly TextBox _workFolderBox = new();
    private readonly TextBlock _workFolderHint = Ui.Muted();

    private readonly Button _generateButton = Ui.Primary(new Button());
    private readonly TextBlock _statusLabel = Ui.Muted();

    public MainWindow()
    {
        Width = 700;
        Height = 860;
        MinWidth = 560;
        MinHeight = 560;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        Background = Palette.Background;

        _languageBar = new LanguageBar(i => { Lang.Set((Language)i); ApplyLanguage(); });

        var content = new StackPanel { Margin = new Thickness(0, 0, 10, 0) };

        // --- Passwords ---
        var pwdStack = new StackPanel();
        AddPasswordRow(pwdStack, _passwordBox, "pwdA");
        AddPasswordRow(pwdStack, _confirmBox, "pwdAc");
        AddPasswordRow(pwdStack, _adminPasswordBox, "pwdB");
        AddPasswordRow(pwdStack, _adminConfirmBox, "pwdBc");
        content.Children.Add(Section("secPasswords", pwdStack));

        // --- Radios ---
        var radioStack = new StackPanel();
        _disableWifiCheck = AddCheck(radioStack, "chkWifi", true);
        _disableBluetoothCheck = AddCheck(radioStack, "chkBt", false);
        content.Children.Add(Section("secRadios", radioStack));

        // --- AI shield ---
        var aiStack = new StackPanel();
        _aiShieldCheck = AddCheck(aiStack, "chkAi", true);
        _raiseVolumeCheck = AddCheck(aiStack, "chkVol", true);
        _detectVmCheck = AddCheck(aiStack, "chkVm", true);
        _monitorCheck = AddCheck(aiStack, "chkMonitor", true);
        aiStack.Children.Add(HintLabel("monitorTargetsLabel", new Thickness(0, 6, 0, 2)));
        aiStack.Children.Add(Ui.InputWithButtons(_monitorTargetsBox, Btn("btnUseCurrentIp", UseCurrentIp)));

        // Alarm sound shape and volume (applies to every violation that beeps).
        aiStack.Children.Add(HintLabel("beepModeLabel", new Thickness(0, 8, 0, 2)));
        aiStack.Children.Add(_beepModeCombo);
        aiStack.Children.Add(HintLabel("volumeLabel", new Thickness(0, 8, 0, 2)));
        _volumeCombo.ItemsSource = new[] { "25%", "50%", "75%", "100%" };
        _volumeCombo.SelectedIndex = 3;
        aiStack.Children.Add(_volumeCombo);

        aiStack.Children.Add(HintLabel("aiListLabel", new Thickness(0, 8, 0, 2)));
        _aiList = List(_aiItems, 130);
        aiStack.Children.Add(_aiList);
        aiStack.Children.Add(Ui.InputWithButtons(_aiInput,
            Btn("btnAdd", () => AddToList(_aiItems, _aiInput)),
            Btn("btnRemove", () => RemoveSelected(_aiItems, _aiList))));
        content.Children.Add(Section("secAi", aiStack));

        // --- Allowed apps ---
        var appStack = new StackPanel();
        appStack.Children.Add(HintLabel("appsHint", new Thickness(0, 0, 0, 2)));
        appStack.Children.Add(HintLabel("appsPolicyHint", new Thickness(0, 0, 0, 8)));
        _appList = List(_appItems, 110);
        appStack.Children.Add(_appList);
        var appManual = new TextBox();
        appStack.Children.Add(Ui.InputWithButtons(appManual,
            Btn("btnAddExe", () => _ = BrowseExe(_appItems, "dlgExe")),
            Btn("btnAdd", () => AddToList(_appItems, appManual)),
            Btn("btnRemove", () => RemoveSelected(_appItems, _appList))));
        content.Children.Add(Section("secApps", appStack));

        var blockedStack = new StackPanel();
        blockedStack.Children.Add(HintLabel("blockedAppsHint", new Thickness(0, 0, 0, 6)));
        _blockedAppList = List(_blockedAppItems, 110);
        blockedStack.Children.Add(_blockedAppList);
        var blockedManual = new TextBox();
        blockedStack.Children.Add(Ui.InputWithButtons(blockedManual,
            Btn("btnBrowseExe", () => _ = BrowseExe(_blockedAppItems, "secBlockedApps")),
            Btn("btnAdd", () => AddToList(_blockedAppItems, blockedManual)),
            Btn("btnRemove", () => RemoveSelected(_blockedAppItems, _blockedAppList))));
        content.Children.Add(Section("secBlockedApps", blockedStack));
        _helpTargets.Add((_blockedAppList, "blockedAppsHint"));
        _helpTargets.Add((blockedManual, "blockedAppsHint"));

        // --- Files & folder ---
        var fileStack = new StackPanel();
        fileStack.Children.Add(HintLabel("extHint", new Thickness(0, 0, 0, 2)));
        _extensionsBox.Margin = new Thickness(0, 0, 0, 8);
        _extensionsBox.TextChanged += (_, _) => UpdateBlockedExtState();
        fileStack.Children.Add(_extensionsBox);

        fileStack.Children.Add(HintLabel("extBlockHint", new Thickness(0, 0, 0, 2)));
        _blockedExtensionsBox.Margin = new Thickness(0, 0, 0, 8);
        fileStack.Children.Add(_blockedExtensionsBox);

        _restrictFolderCheck = AddCheck(fileStack, "chkRestrict", false);
        fileStack.Children.Add(HintLabel("baseLabel", new Thickness(0, 6, 0, 2)));
        _workFolderModeCombo.SelectionChanged += (_, _) => UpdateWorkFolderHint();
        fileStack.Children.Add(_workFolderModeCombo);

        fileStack.Children.Add(HintLabel("subLabel", new Thickness(0, 6, 0, 2)));
        _workFolderBox.TextChanged += (_, _) => UpdateWorkFolderHint();
        fileStack.Children.Add(Ui.InputWithButtons(_workFolderBox, Btn("btnBrowse", () => _ = BrowseFolder())));
        fileStack.Children.Add(_workFolderHint);
        content.Children.Add(Section("secFiles", fileStack));

        _generateButton.HorizontalAlignment = HorizontalAlignment.Stretch;
        _generateButton.HorizontalContentAlignment = HorizontalAlignment.Center;
        _generateButton.MinHeight = 40;
        _generateButton.Margin = new Thickness(0, 10, 0, 6);
        L(_generateButton, "btnGenerate");
        _generateButton.Click += async (_, _) => await GenerateConfig();

        var root = new Grid { Margin = new Thickness(16), RowDefinitions = new RowDefinitions("Auto,*,Auto,Auto") };
        root.Children.Add(Ui.Cell(_languageBar, 0));
        root.Children.Add(Ui.Cell(new ScrollViewer { Content = content, Margin = new Thickness(0, 8, 0, 0) }, 1));
        root.Children.Add(Ui.Cell(_generateButton, 2));
        root.Children.Add(Ui.Cell(_statusLabel, 3));
        Content = root;

        foreach (var (control, key) in new (Control, string)[]
        {
            (_monitorTargetsBox, "monitorTargetsLabel"), (_beepModeCombo, "beepModeLabel"),
            (_volumeCombo, "volumeLabel"), (_aiList, "aiListLabel"), (_aiInput, "aiListLabel"),
            (_appList, "appsHint"), (appManual, "appsHint"), (_extensionsBox, "extHint"),
            (_blockedExtensionsBox, "extBlockHint"), (_workFolderModeCombo, "baseLabel"),
            (_workFolderBox, "subLabel"), (_workFolderHint, "chkRestrict")
        }) _helpTargets.Add((control, key));

        ApplyLanguage();
    }

    // ----- Language -----

    private void ApplyLanguage()
    {
        Title = Lang.T("title");
        foreach (var (ctrl, key) in _i18n)
        {
            SetText(ctrl, Lang.T(key));
        }

        RebuildCombo(_workFolderModeCombo, "comboConfig", "comboDesktop", "comboDocuments", "comboFixed");
        RebuildCombo(_beepModeCombo, "beepContinuous", "beepThree");
        UpdateWorkFolderHint();
        UpdateBlockedExtState();

        _languageBar.Select((int)Lang.Current);
        foreach (var (control, key) in _helpTargets)
        {
            ToolTip.SetTip(control, UiHelp.Get(key, (int)Lang.Current));
        }
    }

    private static void SetText(Control ctrl, string text)
    {
        switch (ctrl)
        {
            case TextBlock t: t.Text = text; break;
            case ContentControl c: c.Content = text; break;
        }
    }

    private static void RebuildCombo(ComboBox combo, params string[] keys)
    {
        var idx = combo.SelectedIndex;
        combo.ItemsSource = keys.Select(Lang.T).ToArray();
        combo.SelectedIndex = idx < 0 ? 0 : idx;
    }

    // An allow-list is stricter than a block-list (it permits ONLY the listed extensions), so once
    // the teacher fills in allowed extensions the block-list is redundant: disable and clear it.
    private void UpdateBlockedExtState()
    {
        var hasAllowList = !string.IsNullOrWhiteSpace(_extensionsBox.Text);
        if (hasAllowList)
        {
            _blockedExtensionsBox.Text = string.Empty;
        }

        _blockedExtensionsBox.IsEnabled = !hasAllowList;
    }

    // ----- UI builders -----

    private T L<T>(T ctrl, string key) where T : Control
    {
        _i18n.Add((ctrl, key));
        _helpTargets.Add((ctrl, key));
        SetText(ctrl, Lang.T(key));
        return ctrl;
    }

    private Control Section(string key, Control body)
    {
        var header = new TextBlock { FontWeight = FontWeight.SemiBold, FontSize = 15, Foreground = Palette.Text, Margin = new Thickness(0, 0, 0, 8) };
        _i18n.Add((header, key));
        SetText(header, Lang.T(key));
        return Ui.Card(new StackPanel { Children = { header, body } });
    }

    private TextBlock HintLabel(string key, Thickness margin)
    {
        var label = Ui.Muted();
        label.Margin = margin;
        return L(label, key);
    }

    private static TextBox Password() => new() { PasswordChar = '•', RevealPassword = false };

    private void AddPasswordRow(StackPanel stack, TextBox box, string key)
    {
        var label = new TextBlock { Foreground = Palette.Text, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 0, 2) };
        L(label, key);
        stack.Children.Add(label);
        box.Margin = new Thickness(0, 0, 0, 6);
        stack.Children.Add(box);
        _helpTargets.Add((box, key));
    }

    private CheckBox AddCheck(StackPanel parent, string key, bool isChecked)
    {
        var check = new CheckBox { IsChecked = isChecked, Margin = new Thickness(0, 2) };
        // Long labels must wrap instead of widening the window.
        var text = new TextBlock { TextWrapping = TextWrapping.Wrap };
        L(text, key);
        _helpTargets.Add((check, key));
        check.Content = text;
        parent.Children.Add(check);
        return check;
    }

    private Button Btn(string key, Action action)
    {
        var button = Ui.Secondary(new Button());
        L(button, key);
        button.Click += (_, _) => action();
        return button;
    }

    private static ListBox List(ObservableCollection<string> items, double height) => new()
    {
        ItemsSource = items,
        Height = height,
        Margin = new Thickness(0, 0, 0, 6),
        Background = Palette.Surface,
        BorderBrush = Palette.Border,
        BorderThickness = new Thickness(1)
    };

    private static void AddToList(ObservableCollection<string> items, TextBox input)
    {
        var value = (input.Text ?? string.Empty).Trim();
        if (value.Length == 0)
        {
            return;
        }

        if (!items.Contains(value))
        {
            items.Add(value);
        }

        input.Text = string.Empty;
    }

    private static void RemoveSelected(ObservableCollection<string> items, ListBox list)
    {
        if (list.SelectedItem is string selected)
        {
            items.Remove(selected);
        }
    }

    private async Task BrowseExe(ObservableCollection<string> target, string titleKey)
    {
        // Linux executables have no extension, so any file is accepted; the bare file name is stored.
        var file = await Pickers.OpenFile(this, Lang.T(titleKey), ("*.exe", new[] { "*.exe" }));
        if (file is null)
        {
            return;
        }

        var name = Path.GetFileName(file);
        if (!target.Contains(name))
        {
            target.Add(name);
        }
    }

    private async Task BrowseFolder()
    {
        var folder = await Pickers.OpenFolder(this, Lang.T("dlgFolder"));
        if (folder is null)
        {
            return;
        }

        _workFolderModeCombo.SelectedIndex = 3; // Fixed path (Absolute)
        _workFolderBox.Text = folder;
        UpdateWorkFolderHint();
    }

    private void UseCurrentIp()
    {
        var ip = DetectCurrentMonitorIp();
        if (string.IsNullOrWhiteSpace(ip))
        {
            _ = Warn(Lang.T("valCurrentIp"));
            return;
        }

        _monitorTargetsBox.Text = ip;
    }

    private string SelectedWorkFolderMode() => _workFolderModeCombo.SelectedIndex switch
    {
        1 => WorkFolderModes.Desktop,
        2 => WorkFolderModes.Documents,
        3 => WorkFolderModes.Absolute,
        _ => WorkFolderModes.ConfigFolder
    };

    private void UpdateWorkFolderHint()
    {
        var sub = _workFolderBox.Text?.Trim() ?? "";
        _workFolderHint.Text = SelectedWorkFolderMode() switch
        {
            WorkFolderModes.Desktop => string.Format(Lang.T("hintDesktop"), sub.Length > 0 ? sub : Lang.T("allDesktop")),
            WorkFolderModes.Documents => string.Format(Lang.T("hintDocuments"), sub.Length > 0 ? sub : Lang.T("allDocuments")),
            WorkFolderModes.Absolute => Lang.T("hintAbsolute"),
            _ => Lang.T("hintConfig")
        };
    }

    private Task Warn(string message)
    {
        SetStatus(message);
        return MessageBox.Show(this, message, Lang.T("msgTitle"), MessageKind.Warning);
    }

    // ----- Config generation -----

    private async Task GenerateConfig()
    {
        var password = _passwordBox.Text ?? "";
        var confirm = _confirmBox.Text ?? "";
        var adminPassword = _adminPasswordBox.Text ?? "";
        var adminConfirm = _adminConfirmBox.Text ?? "";

        if (string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(adminPassword))
        {
            await Warn(Lang.T("valBothPwd"));
            return;
        }

        if (!string.Equals(password, confirm, StringComparison.Ordinal))
        {
            await Warn(Lang.T("valConfirmA"));
            return;
        }

        if (!string.Equals(adminPassword, adminConfirm, StringComparison.Ordinal))
        {
            await Warn(Lang.T("valConfirmB"));
            return;
        }

        if (string.Equals(password, adminPassword, StringComparison.Ordinal))
        {
            await Warn(Lang.T("valDistinct"));
            return;
        }

        var workFolderMode = SelectedWorkFolderMode();
        var folderText = _workFolderBox.Text?.Trim() ?? "";
        var workFolderAbsolute = workFolderMode == WorkFolderModes.Absolute ? folderText : "";
        var workFolderRelative = workFolderMode == WorkFolderModes.Absolute ? "" : folderText;

        if (_restrictFolderCheck.IsChecked == true && workFolderMode == WorkFolderModes.Absolute && workFolderAbsolute.Length == 0)
        {
            await Warn(Lang.T("valFixedPath"));
            return;
        }

        var fileName = await Pickers.SaveFile(this, Lang.T("dlgSave"), "exam.config", "config", ("Config (*.config)", new[] { "*.config" }));
        if (fileName is null)
        {
            return;
        }

        try
        {
            const int iterations = 150_000;

            var salt = new byte[16];
            RandomNumberGenerator.Fill(salt);
            var hashBase64 = PasswordHasher.HashPassword(password, salt, iterations, 32);

            var adminSalt = new byte[16];
            RandomNumberGenerator.Fill(adminSalt);
            var adminHashBase64 = PasswordHasher.HashPassword(adminPassword, adminSalt, iterations, 32);

            var logSecret = new byte[32];
            RandomNumberGenerator.Fill(logSecret);

            var allowedExtensions = ParseExtensions(_extensionsBox.Text ?? "");

            var payload = new ConfigPayload
            {
                Version = 2,
                SaltBase64 = Convert.ToBase64String(salt),
                Iterations = iterations,
                PasswordHashBase64 = hashBase64,
                AdminSaltBase64 = Convert.ToBase64String(adminSalt),
                AdminPasswordHashBase64 = adminHashBase64,
                LogSecretBase64 = Convert.ToBase64String(logSecret),
                DisableWifi = _disableWifiCheck.IsChecked == true,
                DisableBluetooth = _disableBluetoothCheck.IsChecked == true,
                AiShieldEnabled = _aiShieldCheck.IsChecked == true,
                RaiseVolumeOnAi = _raiseVolumeCheck.IsChecked == true,
                DetectVirtualMachines = _detectVmCheck.IsChecked == true,
                MonitorBroadcast = _monitorCheck.IsChecked == true,
                MonitorTargets = ParseMonitorTargets(_monitorTargetsBox.Text ?? ""),
                BeepOnViolation = true,
                BeepMode = _beepModeCombo.SelectedIndex == 1 ? BeepModes.ThreeBeeps : BeepModes.Continuous,
                AlarmVolumePercent = _volumeCombo.SelectedIndex switch { 0 => 25, 1 => 50, 2 => 75, _ => 100 },
                AiBlocklist = _aiItems.ToArray(),
                AllowedProcesses = _appItems.ToArray(),
                BlockedProcesses = _blockedAppItems.Count == 0 ? null : _blockedAppItems.ToArray(),
                AllowedFileExtensions = allowedExtensions,
                // An allow-list already restricts to ONLY the listed extensions, so a block-list
                // would be redundant; keep it empty whenever the allow-list is in use.
                BlockedFileExtensions = allowedExtensions.Length > 0
                    ? Array.Empty<string>()
                    : ParseExtensions(_blockedExtensionsBox.Text ?? ""),
                WorkFolderMode = workFolderMode,
                WorkFolderRelative = workFolderRelative,
                WorkFolder = workFolderAbsolute,
                RestrictToWorkFolder = _restrictFolderCheck.IsChecked == true
            };

            var payloadJson = ConfigSerializer.SerializePayload(payload);
            var hmac = ConfigIntegrityService.ComputeHmacBase64(payloadJson);

            var envelope = new ConfigEnvelope { Payload = payload, HmacBase64 = hmac };
            var configJson = ConfigSerializer.SerializeEnvelope(envelope);
            File.WriteAllText(fileName, configJson, Encoding.UTF8);

            SetStatus(string.Format(Lang.T("statusGen"), fileName));
            await MessageBox.Show(this, string.Format(Lang.T("genOk"), fileName), Lang.T("msgTitle"));
        }
        catch (Exception ex)
        {
            SetStatus(string.Format(Lang.T("genErr"), ex.Message));
            await MessageBox.Show(this, string.Format(Lang.T("genErr"), ex.Message), Lang.T("msgTitle"), MessageKind.Error);
        }
    }

    private static string[] ParseExtensions(string raw)
    {
        return raw
            .Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(e => e.StartsWith('.') ? e.ToLowerInvariant() : "." + e.ToLowerInvariant())
            .Distinct()
            .ToArray();
    }

    private static string[] ParseMonitorTargets(string raw)
    {
        return raw
            .Split(new[] { ',', ';', ' ', '\r', '\n', '\t' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static string? DetectCurrentMonitorIp()
    {
        var candidates = new List<(int Score, string Address)>();

        foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (networkInterface.OperationalStatus != OperationalStatus.Up ||
                networkInterface.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
            {
                continue;
            }

            var properties = networkInterface.GetIPProperties();
            var gateways = properties.GatewayAddresses
                .Select(g => g.Address)
                .Where(g => g.AddressFamily == AddressFamily.InterNetwork && !g.Equals(IPAddress.Any))
                .ToArray();

            foreach (var unicast in properties.UnicastAddresses)
            {
                if (unicast.Address.AddressFamily != AddressFamily.InterNetwork ||
                    unicast.IPv4Mask is null ||
                    !IsUsableIpv4(unicast.Address))
                {
                    continue;
                }

                var score = IsPrivateIpv4(unicast.Address) ? 20 : 0;
                if (gateways.Any(g => IsSameSubnet(unicast.Address, g, unicast.IPv4Mask)))
                {
                    score += 100;
                }
                else if (gateways.Length > 0)
                {
                    score += 60;
                }

                var adapterText = (networkInterface.Name + " " + networkInterface.Description).ToLowerInvariant();
                if (adapterText.Contains("virtualbox") ||
                    adapterText.Contains("vmware") ||
                    adapterText.Contains("hyper-v") ||
                    adapterText.Contains("docker") ||
                    adapterText.Contains("virbr") ||
                    adapterText.Contains("br-"))
                {
                    score -= 40;
                }

                candidates.Add((score, unicast.Address.ToString()));
            }
        }

        return candidates
            .OrderByDescending(c => c.Score)
            .ThenBy(c => c.Address, StringComparer.Ordinal)
            .FirstOrDefault()
            .Address;
    }

    private static bool IsUsableIpv4(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return bytes[0] != 0 && bytes[0] != 127 && !(bytes[0] == 169 && bytes[1] == 254);
    }

    private static bool IsPrivateIpv4(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return bytes[0] == 10 ||
               (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
               (bytes[0] == 192 && bytes[1] == 168);
    }

    private static bool IsSameSubnet(IPAddress address, IPAddress gateway, IPAddress mask)
    {
        var addressBytes = address.GetAddressBytes();
        var gatewayBytes = gateway.GetAddressBytes();
        var maskBytes = mask.GetAddressBytes();

        for (var i = 0; i < addressBytes.Length; i++)
        {
            if ((addressBytes[i] & maskBytes[i]) != (gatewayBytes[i] & maskBytes[i]))
            {
                return false;
            }
        }

        return true;
    }

    private void SetStatus(string message)
    {
        _statusLabel.Text = message;
    }
}
