using System.Security.Cryptography;
using System.Text;
using ExamShared;

namespace ExamConfigGenerator;

public sealed class MainForm : Form
{
    private const int SectionWidth = 600;

    private readonly List<(Control ctrl, string key)> _i18n = new();
    private readonly List<Button> _flagButtons = new();

    private readonly TextBox _passwordBox;
    private readonly TextBox _confirmBox;
    private readonly TextBox _adminPasswordBox;
    private readonly TextBox _adminConfirmBox;

    private readonly CheckBox _disableWifiCheck;
    private readonly CheckBox _disableBluetoothCheck;
    private readonly CheckBox _aiShieldCheck;
    private readonly CheckBox _raiseVolumeCheck;
    private readonly CheckBox _detectVmCheck;
    private readonly CheckBox _monitorCheck;
    private readonly ComboBox _beepModeCombo;
    private readonly ComboBox _volumeCombo;

    private readonly ListBox _aiList;
    private readonly TextBox _aiInput;
    private readonly ListBox _appList;
    private readonly TextBox _extensionsBox;
    private readonly TextBox _blockedExtensionsBox;
    private readonly CheckBox _restrictFolderCheck;
    private readonly ComboBox _workFolderModeCombo;
    private readonly TextBox _workFolderBox;
    private readonly Label _workFolderHint;

    private readonly Button _generateButton;
    private readonly Label _statusLabel;

    public MainForm()
    {
        Width = 680;
        Height = 820;
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(640, 600);
        BackColor = Theme.Background;
        Font = Theme.Base;
        ForeColor = Theme.Text;

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(16),
            ColumnCount = 1,
            RowCount = 4,
            BackColor = Theme.Background
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));   // language bar
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));   // content
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 48));   // generate
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));   // status

        root.Controls.Add(BuildLanguageBar(), 0, 0);

        var content = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoScroll = true,
            BackColor = Theme.Background
        };

        // --- Passwords ---
        var pwdSection = Section("secPasswords");
        var pwdGrid = SectionGrid(4);
        _passwordBox = AddPasswordRow(pwdGrid, 0, "pwdA");
        _confirmBox = AddPasswordRow(pwdGrid, 1, "pwdAc");
        _adminPasswordBox = AddPasswordRow(pwdGrid, 2, "pwdB");
        _adminConfirmBox = AddPasswordRow(pwdGrid, 3, "pwdBc");
        pwdSection.Controls.Add(pwdGrid);
        content.Controls.Add(pwdSection);

        // --- Radios ---
        var radioSection = Section("secRadios");
        var radioStack = VerticalStack();
        _disableWifiCheck = AddCheck(radioStack, "chkWifi", true);
        _disableBluetoothCheck = AddCheck(radioStack, "chkBt", false);
        radioSection.Controls.Add(radioStack);
        content.Controls.Add(radioSection);

        // --- AI shield ---
        var aiSection = Section("secAi");
        var aiStack = VerticalStack();
        _aiShieldCheck = AddCheck(aiStack, "chkAi", true);
        _raiseVolumeCheck = AddCheck(aiStack, "chkVol", true);
        _detectVmCheck = AddCheck(aiStack, "chkVm", true);
        _monitorCheck = AddCheck(aiStack, "chkMonitor", true);

        // Alarm sound shape and volume (applies to every violation that beeps).
        aiStack.Controls.Add(HintLabel("beepModeLabel", new Padding(0, 8, 0, 2)));
        _beepModeCombo = new ComboBox
        {
            Width = 300,
            DropDownStyle = ComboBoxStyle.DropDownList,
            FlatStyle = FlatStyle.Flat,
            Font = Theme.Base,
            Margin = new Padding(0, 0, 0, 6)
        };
        aiStack.Controls.Add(_beepModeCombo);

        aiStack.Controls.Add(HintLabel("volumeLabel", new Padding(0, 4, 0, 2)));
        _volumeCombo = new ComboBox
        {
            Width = 300,
            DropDownStyle = ComboBoxStyle.DropDownList,
            FlatStyle = FlatStyle.Flat,
            Font = Theme.Base,
            Margin = new Padding(0, 0, 0, 6)
        };
        _volumeCombo.Items.AddRange(new object[] { "25%", "50%", "75%", "100%" });
        _volumeCombo.SelectedIndex = 3;
        aiStack.Controls.Add(_volumeCombo);

        aiStack.Controls.Add(HintLabel("aiListLabel", new Padding(0, 8, 0, 2)));
        _aiList = new ListBox { Width = SectionWidth - 30, Height = 120, Margin = new Padding(0, 0, 0, 6) };
        Theme.StyleList(_aiList);
        foreach (var d in ConfigDefaults.DefaultAiBlocklist)
        {
            _aiList.Items.Add(d);
        }

        aiStack.Controls.Add(_aiList);
        _aiInput = new TextBox { Width = 360 };
        Theme.StyleInput(_aiInput);
        aiStack.Controls.Add(InputWithButtons(_aiInput,
            ("btnAdd", () => AddToList(_aiList, _aiInput)),
            ("btnRemove", () => RemoveSelected(_aiList))));
        aiSection.Controls.Add(aiStack);
        content.Controls.Add(aiSection);

        // --- Allowed apps ---
        var appSection = Section("secApps");
        var appStack = VerticalStack();
        appStack.Controls.Add(HintLabel("appsHint", new Padding(0, 0, 0, 2)));
        _appList = new ListBox { Width = SectionWidth - 30, Height = 100, Margin = new Padding(0, 0, 0, 6) };
        Theme.StyleList(_appList);
        appStack.Controls.Add(_appList);
        var appManual = new TextBox { Width = 260 };
        Theme.StyleInput(appManual);
        appStack.Controls.Add(InputWithButtons(appManual,
            ("btnAddExe", BrowseExe),
            ("btnAdd", () => AddToList(_appList, appManual)),
            ("btnRemove", () => RemoveSelected(_appList))));
        appSection.Controls.Add(appStack);
        content.Controls.Add(appSection);

        // --- Files & folder ---
        var fileSection = Section("secFiles");
        var fileStack = VerticalStack();
        fileStack.Controls.Add(HintLabel("extHint", new Padding(0, 0, 0, 2)));
        _extensionsBox = new TextBox { Width = SectionWidth - 30, Margin = new Padding(0, 0, 0, 8) };
        Theme.StyleInput(_extensionsBox);
        _extensionsBox.TextChanged += (_, _) => UpdateBlockedExtState();
        fileStack.Controls.Add(_extensionsBox);

        fileStack.Controls.Add(HintLabel("extBlockHint", new Padding(0, 0, 0, 2)));
        _blockedExtensionsBox = new TextBox { Width = SectionWidth - 30, Margin = new Padding(0, 0, 0, 8) };
        Theme.StyleInput(_blockedExtensionsBox);
        fileStack.Controls.Add(_blockedExtensionsBox);

        _restrictFolderCheck = AddCheck(fileStack, "chkRestrict", false);
        fileStack.Controls.Add(HintLabel("baseLabel", new Padding(0, 6, 0, 2)));
        _workFolderModeCombo = new ComboBox
        {
            Width = SectionWidth - 30,
            DropDownStyle = ComboBoxStyle.DropDownList,
            FlatStyle = FlatStyle.Flat,
            Font = Theme.Base
        };
        _workFolderModeCombo.SelectedIndexChanged += (_, _) => UpdateWorkFolderHint();
        fileStack.Controls.Add(_workFolderModeCombo);

        fileStack.Controls.Add(HintLabel("subLabel", new Padding(0, 6, 0, 2)));
        _workFolderBox = new TextBox { Width = 440 };
        Theme.StyleInput(_workFolderBox);
        fileStack.Controls.Add(InputWithButtons(_workFolderBox, ("btnBrowse", BrowseFolder)));

        _workFolderHint = new Label { Text = "", AutoSize = true, ForeColor = Theme.TextMuted, Margin = new Padding(0, 2, 0, 0) };
        fileStack.Controls.Add(_workFolderHint);

        fileSection.Controls.Add(fileStack);
        content.Controls.Add(fileSection);

        root.Controls.Add(content, 0, 1);

        _generateButton = new Button { Dock = DockStyle.Fill, Margin = new Padding(0, 6, 0, 6) };
        Theme.StylePrimary(_generateButton);
        L(_generateButton, "btnGenerate");
        _generateButton.Click += (_, _) => GenerateConfig();
        root.Controls.Add(_generateButton, 0, 2);

        _statusLabel = new Label { Text = "", Dock = DockStyle.Fill, AutoSize = false, TextAlign = ContentAlignment.MiddleLeft, ForeColor = Theme.TextMuted };
        root.Controls.Add(_statusLabel, 0, 3);

        Controls.Add(root);

        ApplyLanguage();
    }

    // ----- Language -----

    private Control BuildLanguageBar()
    {
        var bar = new FlowLayoutPanel
        {
            Anchor = AnchorStyles.Right,
            AutoSize = true,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Margin = new Padding(0),
            BackColor = Theme.Background
        };

        foreach (var language in new[] { Language.En, Language.Ca, Language.Es })
        {
            var lang = language;
            var btn = new Button
            {
                Width = 40,
                Height = 26,
                FlatStyle = FlatStyle.Flat,
                Image = Flags.For(lang),
                ImageAlign = ContentAlignment.MiddleCenter,
                Margin = new Padding(4, 0, 0, 0),
                Cursor = Cursors.Hand,
                Tag = lang
            };
            btn.FlatAppearance.MouseOverBackColor = Theme.Background;
            btn.Click += (_, _) => { Lang.Set(lang); ApplyLanguage(); };
            _flagButtons.Add(btn);
            bar.Controls.Add(btn);
        }

        return bar;
    }

    private void ApplyLanguage()
    {
        Text = Lang.T("title");
        foreach (var (ctrl, key) in _i18n)
        {
            ctrl.Text = Lang.T(key);
        }

        RebuildCombo();
        RebuildBeepModeCombo();
        UpdateWorkFolderHint();
        UpdateBlockedExtState();

        foreach (var btn in _flagButtons)
        {
            var selected = (Language)btn.Tag! == Lang.Current;
            btn.FlatAppearance.BorderSize = selected ? 2 : 1;
            btn.FlatAppearance.BorderColor = selected ? Theme.Accent : Theme.Border;
        }
    }

    private void RebuildCombo()
    {
        var idx = _workFolderModeCombo.SelectedIndex;
        _workFolderModeCombo.Items.Clear();
        _workFolderModeCombo.Items.AddRange(new object[]
        {
            Lang.T("comboConfig"),
            Lang.T("comboDesktop"),
            Lang.T("comboDocuments"),
            Lang.T("comboFixed")
        });
        _workFolderModeCombo.SelectedIndex = idx < 0 ? 0 : idx;
    }

    // An allow-list is stricter than a block-list (it permits ONLY the listed extensions), so once
    // the teacher fills in allowed extensions the block-list is redundant: disable and clear it.
    private void UpdateBlockedExtState()
    {
        var hasAllowList = !string.IsNullOrWhiteSpace(_extensionsBox.Text);
        if (hasAllowList)
        {
            _blockedExtensionsBox.Clear();
        }

        _blockedExtensionsBox.Enabled = !hasAllowList;
    }

    private void RebuildBeepModeCombo()
    {
        var idx = _beepModeCombo.SelectedIndex;
        _beepModeCombo.Items.Clear();
        _beepModeCombo.Items.AddRange(new object[]
        {
            Lang.T("beepContinuous"),
            Lang.T("beepThree")
        });
        _beepModeCombo.SelectedIndex = idx < 0 ? 0 : idx;
    }

    // ----- UI builders -----

    private T L<T>(T ctrl, string key) where T : Control
    {
        _i18n.Add((ctrl, key));
        ctrl.Text = Lang.T(key);
        return ctrl;
    }

    private GroupBox Section(string key)
    {
        var box = Theme.Section(Lang.T(key));
        _i18n.Add((box, key));
        return box;
    }

    private Label HintLabel(string key, Padding margin)
    {
        var label = new Label { AutoSize = true, ForeColor = Theme.TextMuted, Margin = margin };
        return L(label, key);
    }

    private static TableLayoutPanel SectionGrid(int rows)
    {
        var grid = new TableLayoutPanel
        {
            ColumnCount = 2,
            RowCount = rows,
            Width = SectionWidth - 24,
            AutoSize = true,
            BackColor = Theme.Background
        };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 230));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        return grid;
    }

    private static FlowLayoutPanel VerticalStack()
    {
        return new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoSize = true,
            Width = SectionWidth - 24,
            BackColor = Theme.Background
        };
    }

    private TextBox AddPasswordRow(TableLayoutPanel grid, int row, string key)
    {
        var label = new Label { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, ForeColor = Theme.Text };
        L(label, key);
        grid.Controls.Add(label, 0, row);
        var box = new TextBox { UseSystemPasswordChar = true, Dock = DockStyle.Fill, Margin = new Padding(0, 4, 0, 4) };
        Theme.StyleInput(box);
        grid.Controls.Add(box, 1, row);
        return box;
    }

    private CheckBox AddCheck(Control parent, string key, bool isChecked)
    {
        var check = new CheckBox { Checked = isChecked, AutoSize = true, ForeColor = Theme.Text, Margin = new Padding(0, 3, 0, 3) };
        L(check, key);
        parent.Controls.Add(check);
        return check;
    }

    private FlowLayoutPanel InputWithButtons(Control input, params (string key, Action action)[] buttons)
    {
        var row = new FlowLayoutPanel { FlowDirection = FlowDirection.LeftToRight, AutoSize = true, WrapContents = false, Margin = new Padding(0, 0, 0, 8), BackColor = Theme.Background };
        row.Controls.Add(input);
        foreach (var (key, action) in buttons)
        {
            var button = new Button { AutoSize = true, Margin = new Padding(6, 0, 0, 0), Padding = new Padding(8, 4, 8, 4) };
            Theme.StyleSecondary(button);
            L(button, key);
            button.Click += (_, _) => action();
            row.Controls.Add(button);
        }

        return row;
    }

    private static void AddToList(ListBox list, TextBox input)
    {
        var value = input.Text.Trim();
        if (value.Length == 0)
        {
            return;
        }

        if (!list.Items.Contains(value))
        {
            list.Items.Add(value);
        }

        input.Clear();
    }

    private static void RemoveSelected(ListBox list)
    {
        if (list.SelectedItem is not null)
        {
            list.Items.Remove(list.SelectedItem);
        }
    }

    private void BrowseExe()
    {
        using var dialog = new OpenFileDialog
        {
            Title = Lang.T("dlgExe"),
            Filter = "*.exe|*.exe|*.*|*.*"
        };

        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            var name = Path.GetFileName(dialog.FileName);
            if (!_appList.Items.Contains(name))
            {
                _appList.Items.Add(name);
            }
        }
    }

    private void BrowseFolder()
    {
        using var dialog = new FolderBrowserDialog { Description = Lang.T("dlgFolder") };
        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            _workFolderModeCombo.SelectedIndex = 3; // Fixed path (Absolute)
            _workFolderBox.Text = dialog.SelectedPath;
            UpdateWorkFolderHint();
        }
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
        if (_workFolderHint is null)
        {
            return;
        }

        var sub = _workFolderBox?.Text?.Trim() ?? "";
        _workFolderHint.Text = SelectedWorkFolderMode() switch
        {
            WorkFolderModes.Desktop => string.Format(Lang.T("hintDesktop"), sub.Length > 0 ? sub : Lang.T("allDesktop")),
            WorkFolderModes.Documents => string.Format(Lang.T("hintDocuments"), sub.Length > 0 ? sub : Lang.T("allDocuments")),
            WorkFolderModes.Absolute => Lang.T("hintAbsolute"),
            _ => Lang.T("hintConfig")
        };
    }

    private void Warn(string message)
    {
        SetStatus(message);
        MessageBox.Show(this, message, Lang.T("msgTitle"), MessageBoxButtons.OK, MessageBoxIcon.Warning);
    }

    // ----- Config generation -----

    private void GenerateConfig()
    {
        var password = _passwordBox.Text;
        var confirm = _confirmBox.Text;
        var adminPassword = _adminPasswordBox.Text;
        var adminConfirm = _adminConfirmBox.Text;

        if (string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(adminPassword))
        {
            Warn(Lang.T("valBothPwd"));
            return;
        }

        if (!string.Equals(password, confirm, StringComparison.Ordinal))
        {
            Warn(Lang.T("valConfirmA"));
            return;
        }

        if (!string.Equals(adminPassword, adminConfirm, StringComparison.Ordinal))
        {
            Warn(Lang.T("valConfirmB"));
            return;
        }

        if (string.Equals(password, adminPassword, StringComparison.Ordinal))
        {
            Warn(Lang.T("valDistinct"));
            return;
        }

        var workFolderMode = SelectedWorkFolderMode();
        var folderText = _workFolderBox.Text.Trim();
        var workFolderAbsolute = workFolderMode == WorkFolderModes.Absolute ? folderText : "";
        var workFolderRelative = workFolderMode == WorkFolderModes.Absolute ? "" : folderText;

        if (_restrictFolderCheck.Checked && workFolderMode == WorkFolderModes.Absolute && workFolderAbsolute.Length == 0)
        {
            Warn(Lang.T("valFixedPath"));
            return;
        }

        var saveDialog = new SaveFileDialog
        {
            Title = Lang.T("dlgSave"),
            Filter = "Config Files (*.config)|*.config|All Files (*.*)|*.*",
            FileName = "exam.config"
        };

        if (saveDialog.ShowDialog(this) != DialogResult.OK)
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

            var allowedExtensions = ParseExtensions(_extensionsBox.Text);

            var payload = new ConfigPayload
            {
                Version = 2,
                SaltBase64 = Convert.ToBase64String(salt),
                Iterations = iterations,
                PasswordHashBase64 = hashBase64,
                AdminSaltBase64 = Convert.ToBase64String(adminSalt),
                AdminPasswordHashBase64 = adminHashBase64,
                LogSecretBase64 = Convert.ToBase64String(logSecret),
                DisableWifi = _disableWifiCheck.Checked,
                DisableBluetooth = _disableBluetoothCheck.Checked,
                AiShieldEnabled = _aiShieldCheck.Checked,
                RaiseVolumeOnAi = _raiseVolumeCheck.Checked,
                DetectVirtualMachines = _detectVmCheck.Checked,
                MonitorBroadcast = _monitorCheck.Checked,
                BeepOnViolation = true,
                BeepMode = _beepModeCombo.SelectedIndex == 1 ? BeepModes.ThreeBeeps : BeepModes.Continuous,
                AlarmVolumePercent = _volumeCombo.SelectedIndex switch { 0 => 25, 1 => 50, 2 => 75, _ => 100 },
                AiBlocklist = _aiList.Items.Cast<string>().ToArray(),
                AllowedProcesses = _appList.Items.Cast<string>().ToArray(),
                AllowedFileExtensions = allowedExtensions,
                // An allow-list already restricts to ONLY the listed extensions, so a block-list
                // would be redundant; keep it empty whenever the allow-list is in use.
                BlockedFileExtensions = allowedExtensions.Length > 0
                    ? Array.Empty<string>()
                    : ParseExtensions(_blockedExtensionsBox.Text),
                WorkFolderMode = workFolderMode,
                WorkFolderRelative = workFolderRelative,
                WorkFolder = workFolderAbsolute,
                RestrictToWorkFolder = _restrictFolderCheck.Checked
            };

            var payloadJson = ConfigSerializer.SerializePayload(payload);
            var hmac = ConfigIntegrityService.ComputeHmacBase64(payloadJson);

            var envelope = new ConfigEnvelope { Payload = payload, HmacBase64 = hmac };
            var configJson = ConfigSerializer.SerializeEnvelope(envelope);
            File.WriteAllText(saveDialog.FileName, configJson, Encoding.UTF8);

            SetStatus(string.Format(Lang.T("statusGen"), saveDialog.FileName));
            MessageBox.Show(this, string.Format(Lang.T("genOk"), saveDialog.FileName), Lang.T("msgTitle"), MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            SetStatus(string.Format(Lang.T("genErr"), ex.Message));
            MessageBox.Show(this, string.Format(Lang.T("genErr"), ex.Message), Lang.T("msgTitle"), MessageBoxButtons.OK, MessageBoxIcon.Error);
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

    private void SetStatus(string message)
    {
        _statusLabel.Text = message;
    }
}
