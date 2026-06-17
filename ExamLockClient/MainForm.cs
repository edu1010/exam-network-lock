using System.Text;
using ExamShared;

namespace ExamLockClient;

public sealed class MainForm : Form
{
    private readonly ShieldControl _shield;
    private readonly Label _statusLabel;
    private readonly Label _configPathLabel;
    private readonly Label _radioStateLabel;
    private readonly Label _configTitleLabel;
    private readonly Label _radiosTitleLabel;
    private readonly Label _incidentsTitleLabel;
    private readonly Label _pwdALabel;
    private readonly Label _pwdBLabel;
    private readonly ListBox _incidentList;
    private readonly TextBox _restorePasswordBox;
    private readonly TextBox _adminPasswordBox;
    private readonly Button _restoreButton;
    private readonly Button _adminButton;
    private readonly Button _loadConfigButton;
    private readonly List<Button> _flagButtons = new();

    private ConfigPayload? _config;
    private SecureLogService? _log;
    private SessionStateService? _session;
    private readonly NetworkAdapterService _network = new();
    private readonly RadioService _radio = new();
    private readonly AudioAlerter _audio = new();

    private AiConnectionMonitor? _aiMonitor;
    private DnsCacheMonitor? _dnsMonitor;
    private ThreatProcessMonitor? _threatMonitor;
    private ProcessMonitor? _processMonitor;
    private FileActivityMonitor? _fileMonitor;
    private MonitorReporter? _reporter;
    private string _stateStr = "Idle";

    private string _configPath = string.Empty;
    private bool _adminAuthenticated;
    private bool _closeLogged;
    private bool _wifiDisableFailed;
    private bool _submissionMode;
    private bool _threatActive;   // an AI/DNS/tool/VM threat is currently sounding the alarm

    private bool _redActive;
    private bool _yellowActive;
    private readonly HashSet<string> _reported = new();

    private ShieldControl.ShieldStatus _lastShield = ShieldControl.ShieldStatus.Idle;
    private bool _shieldInitialized;

    public MainForm()
    {
        Width = 600;
        Height = 720;
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.Sizable;
        MinimumSize = new Size(560, 620);
        MaximizeBox = true;
        MinimizeBox = true;
        BackColor = Theme.Background;
        Font = Theme.Base;
        ForeColor = Theme.Text;

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(16),
            ColumnCount = 1,
            RowCount = 6,
            BackColor = Theme.Background
        };
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));  // language bar
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 210)); // shield
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 64));  // info card
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // incidents
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 132)); // controls card
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));  // status

        layout.Controls.Add(BuildLanguageBar(), 0, 0);

        _shield = new ShieldControl { Dock = DockStyle.Fill };
        layout.Controls.Add(_shield, 0, 1);

        // --- Info card: config path + radios ---
        var infoCard = Theme.Card();
        infoCard.Dock = DockStyle.Fill;
        var infoGrid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 2, BackColor = Theme.Surface };
        infoGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 70));
        infoGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        _configTitleLabel = MutedLabel("");
        infoGrid.Controls.Add(_configTitleLabel, 0, 0);
        _configPathLabel = ValueLabel("");
        infoGrid.Controls.Add(_configPathLabel, 1, 0);
        _radiosTitleLabel = MutedLabel("");
        infoGrid.Controls.Add(_radiosTitleLabel, 0, 1);
        _radioStateLabel = ValueLabel("—");
        infoGrid.Controls.Add(_radioStateLabel, 1, 1);
        infoCard.Controls.Add(infoGrid);
        layout.Controls.Add(infoCard, 0, 2);

        // --- Incidents ---
        var incidentsCard = Theme.Card();
        incidentsCard.Dock = DockStyle.Fill;
        var incidentsLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, BackColor = Theme.Surface };
        incidentsLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 22));
        incidentsLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        _incidentsTitleLabel = new Label { Text = "", Dock = DockStyle.Fill, Font = Theme.Heading, ForeColor = Theme.Text };
        incidentsLayout.Controls.Add(_incidentsTitleLabel, 0, 0);
        _incidentList = new ListBox
        {
            Dock = DockStyle.Fill,
            BorderStyle = BorderStyle.None,
            BackColor = Theme.Surface,
            ForeColor = Theme.Text,
            Font = Theme.Base,
            IntegralHeight = false
        };
        incidentsLayout.Controls.Add(_incidentList, 0, 1);
        incidentsCard.Controls.Add(incidentsLayout);
        layout.Controls.Add(incidentsCard, 0, 3);

        // --- Controls card: passwords + load ---
        var controlsCard = Theme.Card();
        controlsCard.Dock = DockStyle.Fill;
        var controls = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 3, BackColor = Theme.Surface };
        controls.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150));
        controls.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        controls.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150));
        controls.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
        controls.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
        controls.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));

        _pwdALabel = MutedLabel("");
        controls.Controls.Add(_pwdALabel, 0, 0);
        _restorePasswordBox = new TextBox { UseSystemPasswordChar = true, Dock = DockStyle.Fill, Margin = new Padding(0, 3, 8, 3) };
        Theme.StyleInput(_restorePasswordBox);
        controls.Controls.Add(_restorePasswordBox, 1, 0);
        _restoreButton = new Button { Dock = DockStyle.Fill, Margin = new Padding(0, 2, 0, 2) };
        Theme.StyleSecondary(_restoreButton);
        _restoreButton.Click += (_, _) => AttemptRestoreWifi();
        controls.Controls.Add(_restoreButton, 2, 0);

        _pwdBLabel = MutedLabel("");
        controls.Controls.Add(_pwdBLabel, 0, 1);
        _adminPasswordBox = new TextBox { UseSystemPasswordChar = true, Dock = DockStyle.Fill, Margin = new Padding(0, 3, 8, 3) };
        Theme.StyleInput(_adminPasswordBox);
        controls.Controls.Add(_adminPasswordBox, 1, 1);
        _adminButton = new Button { Dock = DockStyle.Fill, Margin = new Padding(0, 2, 0, 2) };
        Theme.StylePrimary(_adminButton);
        _adminButton.Click += (_, _) => AttemptAdminClose();
        controls.Controls.Add(_adminButton, 2, 1);

        _loadConfigButton = new Button { Dock = DockStyle.Fill, Margin = new Padding(0, 2, 0, 2) };
        Theme.StyleSecondary(_loadConfigButton);
        _loadConfigButton.Click += (_, _) => LoadConfig(true);
        controls.Controls.Add(_loadConfigButton, 2, 2);

        controlsCard.Controls.Add(controls);
        layout.Controls.Add(controlsCard, 0, 4);

        _statusLabel = new Label { Text = "", Dock = DockStyle.Fill, AutoSize = false, TextAlign = ContentAlignment.MiddleLeft, ForeColor = Theme.TextMuted };
        layout.Controls.Add(_statusLabel, 0, 5);

        Controls.Add(layout);

        Load += (_, _) => LoadConfig(false);
        FormClosing += OnFormClosing;

        ApplyLanguage();
    }

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
        _configTitleLabel.Text = Lang.T("config");
        _radiosTitleLabel.Text = Lang.T("radios");
        _incidentsTitleLabel.Text = Lang.T("incidents");
        _pwdALabel.Text = Lang.T("pwdA");
        _pwdBLabel.Text = Lang.T("pwdB");
        _restoreButton.Text = Lang.T("restoreBtn");
        _adminButton.Text = Lang.T("closeBtn");
        _loadConfigButton.Text = Lang.T("loadBtn");

        if (_config is null)
        {
            _configPathLabel.Text = Lang.T("notLoaded");
        }

        foreach (var btn in _flagButtons)
        {
            var selected = (Language)btn.Tag! == Lang.Current;
            btn.FlatAppearance.BorderSize = selected ? 2 : 1;
            btn.FlatAppearance.BorderColor = selected ? Theme.Accent : Theme.Border;
        }

        UpdateShield();
    }

    private static Label MutedLabel(string text) => new()
    {
        Text = text,
        Dock = DockStyle.Fill,
        TextAlign = ContentAlignment.MiddleLeft,
        ForeColor = Theme.TextMuted,
        Font = Theme.Base
    };

    private static Label ValueLabel(string text) => new()
    {
        Text = text,
        Dock = DockStyle.Fill,
        TextAlign = ContentAlignment.MiddleLeft,
        ForeColor = Theme.Text,
        Font = Theme.Base,
        AutoEllipsis = true
    };

    // ----- Config loading -----

    private void LoadConfig(bool forceDialog)
    {
        if (_config is not null)
        {
            return;
        }

        var candidate = FindDefaultConfig();
        if (!forceDialog && candidate is not null)
        {
            TryLoadConfig(candidate);
            return;
        }

        using var openDialog = new OpenFileDialog
        {
            Title = Lang.T("dlgSelectConfig"),
            Filter = "Config Files (*.config)|*.config|All Files (*.*)|*.*"
        };

        if (openDialog.ShowDialog(this) != DialogResult.OK)
        {
            SetStatus(Lang.T("needConfig"));
            return;
        }

        TryLoadConfig(openDialog.FileName);
    }

    private static string? FindDefaultConfig()
    {
        var cwd = Path.Combine(Environment.CurrentDirectory, "exam.config");
        if (File.Exists(cwd))
        {
            return cwd;
        }

        var appDir = Path.Combine(AppContext.BaseDirectory, "exam.config");
        return File.Exists(appDir) ? appDir : null;
    }

    private void TryLoadConfig(string path)
    {
        try
        {
            var json = File.ReadAllText(path, Encoding.UTF8);
            var envelope = ConfigSerializer.DeserializeEnvelope(json);
            var payloadJson = ConfigSerializer.SerializePayload(envelope.Payload);

            if (!ConfigIntegrityService.VerifyHmac(payloadJson, envelope.HmacBase64))
            {
                SetStatus(Lang.T("integrityFail"));
                return;
            }

            _config = envelope.Payload;
            _configPath = path;
            _configPathLabel.Text = path;

            InitializeServices(path, _config.LogSecretBase64);
            _log?.Append(LogEvents.AppStarted);
            _log?.Append(LogEvents.ConfigValid);

            StartLockdown();
        }
        catch (Exception ex)
        {
            SetStatus(string.Format(Lang.T("loadFail"), ex.Message));
        }
    }

    private void InitializeServices(string configPath, string logSecretBase64)
    {
        var dir = Path.GetDirectoryName(configPath) ?? AppContext.BaseDirectory;
        var logPath = Path.Combine(dir, "examlog.jsonl");
        var sessionPath = Path.Combine(dir, "session.lock");

        _log = new SecureLogService(logPath, logSecretBase64);
        _session = new SessionStateService(sessionPath);
        _reporter = new MonitorReporter(logPath);

        if (_session.HasUncleanPreviousSession())
        {
            _log.Append(LogEvents.UncleanPreviousSession);
        }

        _session.MarkSessionStart();
    }

    // ----- Lockdown orchestration -----

    private async void StartLockdown()
    {
        if (_config is null)
        {
            return;
        }

        _audio.Pattern = _config.BeepMode == BeepModes.ThreeBeeps
            ? BeepPattern.ThreeBeeps
            : BeepPattern.Continuous;
        _audio.VolumePercent = _config.AlarmVolumePercent is > 0 and <= 100
            ? _config.AlarmVolumePercent
            : 100;

        var radioStates = new List<string>();

        if (_config.DisableWifi)
        {
            if (_network.DisableWifi(out var error))
            {
                _log?.Append(LogEvents.WifiDisabled);
                radioStates.Add(Lang.T("wifiOff"));
                _wifiDisableFailed = false;
            }
            else
            {
                _log?.Append(LogEvents.WifiDisableFailed, error);
                radioStates.Add(Lang.T("wifiOffFail"));
                _wifiDisableFailed = true;
            }
        }
        else
        {
            radioStates.Add(Lang.T("wifiWatched"));
        }

        if (_config.DisableBluetooth)
        {
            var (ok, error) = await _radio.SetBluetoothAsync(false);
            if (ok)
            {
                _log?.Append(LogEvents.BluetoothDisabled);
                radioStates.Add(Lang.T("btOff"));
            }
            else
            {
                _log?.Append(LogEvents.BluetoothFailed, error);
                radioStates.Add(Lang.T("btFail"));
            }
        }

        _radioStateLabel.Text = string.Join("    ", radioStates);

        StartMonitors();

        if (_config.MonitorBroadcast)
        {
            _reporter?.Start();
        }

        UpdateShield();
        AddIncident(Lang.T("lockStarted"));
        SetStatus(Lang.T("statusActive"));
    }

    private void StartMonitors()
    {
        if (_config is null)
        {
            return;
        }

        if (_config.AiShieldEnabled)
        {
            var blocklist = _config.AiBlocklist.Length > 0
                ? _config.AiBlocklist
                : ConfigDefaults.DefaultAiBlocklist;
            _aiMonitor = new AiConnectionMonitor(blocklist);
            _aiMonitor.AiConnectionDetected += desc => RunOnUi(() => OnAiDetected(desc));
            _aiMonitor.Start();

            _dnsMonitor = new DnsCacheMonitor(blocklist);
            _dnsMonitor.AiHostnameResolved += host => RunOnUi(() => OnAiDns(host));
            _dnsMonitor.Start();
        }

        if (_config.AiShieldEnabled || _config.DetectVirtualMachines)
        {
            _threatMonitor = new ThreatProcessMonitor(_config.AiShieldEnabled, _config.DetectVirtualMachines);
            _threatMonitor.AiToolDetected += name => RunOnUi(() => OnAiTool(name));
            _threatMonitor.VmDetected += name => RunOnUi(() => OnVmDetected(name));
            _threatMonitor.Start();
        }

        if (_config.AllowedProcesses.Length > 0)
        {
            _processMonitor = new ProcessMonitor(_config.AllowedProcesses);
            _processMonitor.UnknownProcessStarted += exe => RunOnUi(() => OnUnknownProcess(exe));
            _processMonitor.Start();
        }

        if (_config.AllowedFileExtensions.Length > 0 || _config.BlockedFileExtensions.Length > 0 || _config.RestrictToWorkFolder)
        {
            var configDir = Path.GetDirectoryName(_configPath) ?? AppContext.BaseDirectory;
            var workFolder = WorkFolderResolver.Resolve(_config, configDir);
            var restrict = _config.RestrictToWorkFolder && workFolder.Length > 0;
            _fileMonitor = new FileActivityMonitor(
                _config.AllowedFileExtensions, workFolder, restrict, _config.AllowedProcesses, _config.BlockedFileExtensions);
            _fileMonitor.ForbiddenFileDetected += f => RunOnUi(() => OnForbiddenFile(f));
            _fileMonitor.OutsideFolderDetected += f => RunOnUi(() => OnOutsideFolder(f));
            _fileMonitor.UnknownFileDetected += f => RunOnUi(() => OnUnknownFile(f));
            _fileMonitor.Start();
        }
    }

    // ----- Incident handlers -----

    private void OnAiDetected(string desc) =>
        RaiseAiAlarm("AI:" + desc, LogEvents.AiDetected, desc, "incAi", "statusAi");

    private void OnAiDns(string host) =>
        RaiseAiAlarm("DNS:" + host, LogEvents.AiDnsDetected, host, "incAi", "statusAi");

    private void OnAiTool(string name) =>
        RaiseAiAlarm("TOOL:" + name, LogEvents.AiToolDetected, name, "incAiTool", "statusAi");

    private void RaiseAiAlarm(string dedupKey, string logEvent, string data, string incidentKey, string statusKey)
    {
        if (!_reported.Add(dedupKey))
        {
            return;
        }

        _log?.Append(logEvent, data);
        AddIncident(string.Format(Lang.T(incidentKey), data));
        if (_config?.RaiseVolumeOnAi == true)
        {
            _audio.RaiseVolume();
        }

        _audio.StartAlarm();
        _threatActive = true;
        SetRed(Lang.T(statusKey));
    }

    private void OnVmDetected(string name)
    {
        if (!_reported.Add("VM:" + name))
        {
            return;
        }

        _log?.Append(LogEvents.VmDetected, name);
        AddIncident(string.Format(Lang.T("incVm"), name));
        if (_config?.BeepOnViolation == true)
        {
            _audio.StartAlarm();
            _threatActive = true;
        }

        SetRed(Lang.T("statusVm"));
    }

    private void OnForbiddenFile(string file)
    {
        if (_submissionMode || !_reported.Add("FILE:" + file))
        {
            return;
        }

        _log?.Append(LogEvents.ForbiddenFile, file);
        AddIncident(string.Format(Lang.T("incForbidden"), file));
        if (_config?.BeepOnViolation == true)
        {
            _audio.StartAlarm();
        }

        SetRed(Lang.T("statusForbidden"));
    }

    private void OnOutsideFolder(string file)
    {
        if (_submissionMode || !_reported.Add("OUT:" + file))
        {
            return;
        }

        _log?.Append(LogEvents.OutsideFolder, file);
        AddIncident(string.Format(Lang.T("incOutside"), file));
        if (_config?.BeepOnViolation == true)
        {
            _audio.StartAlarm();
        }

        SetRed(Lang.T("statusOutside"));
    }

    private void OnUnknownProcess(string exe)
    {
        if (!_reported.Add("PROC:" + exe))
        {
            return;
        }

        _log?.Append(LogEvents.UnknownProcess, exe);
        AddIncident(string.Format(Lang.T("incUnknownProc"), exe));
        SetYellow(string.Format(Lang.T("statusUnknownProc"), exe));
    }

    private void OnUnknownFile(string file)
    {
        if (_submissionMode || !_reported.Add("UFILE:" + file))
        {
            return;
        }

        _log?.Append(LogEvents.UnknownFile, file);
        AddIncident(string.Format(Lang.T("incUnknownFile"), file));
        SetYellow(string.Format(Lang.T("statusUnknownFile"), file));
    }

    private void SetRed(string status)
    {
        _redActive = true;
        SetStatus(status);
        UpdateShield();
    }

    private void SetYellow(string status)
    {
        _yellowActive = true;
        SetStatus(status);
        UpdateShield();
    }

    private void UpdateShield()
    {
        if (_config is null)
        {
            _shield.Status = ShieldControl.ShieldStatus.Idle;
            _shield.Caption = Lang.T("waitingConfig");
            _stateStr = "Idle";
            return;
        }

        var state = _redActive ? ShieldControl.ShieldStatus.Red
            : _yellowActive ? ShieldControl.ShieldStatus.Yellow
            : ShieldControl.ShieldStatus.Green;

        _stateStr = state.ToString();
        ReportState();

        _shield.Status = state;
        _shield.Caption = state switch
        {
            ShieldControl.ShieldStatus.Red => Lang.T("shieldDanger"),
            ShieldControl.ShieldStatus.Yellow => Lang.T("shieldAttention"),
            _ => Lang.T("shieldProtected")
        };

        // Log shield transitions only (avoid spamming the log on every refresh).
        if (!_shieldInitialized || state != _lastShield)
        {
            _log?.Append(state switch
            {
                ShieldControl.ShieldStatus.Red => LogEvents.ShieldRed,
                ShieldControl.ShieldStatus.Yellow => LogEvents.ShieldYellow,
                _ => LogEvents.ShieldGreen
            });
            _lastShield = state;
            _shieldInitialized = true;
        }
    }

    // ----- Passwords -----

    private void AttemptRestoreWifi()
    {
        if (_config is null)
        {
            SetStatus(Lang.T("needValidConfig"));
            return;
        }

        var password = _restorePasswordBox.Text;
        _restorePasswordBox.Clear();
        if (!PasswordHasher.VerifyPassword(password, _config.SaltBase64, _config.Iterations, _config.PasswordHashBase64))
        {
            _log?.Append(LogEvents.UnlockFailed);
            SetStatus(Lang.T("wrongA"));
            return;
        }

        _log?.Append(LogEvents.UnlockSuccess);
        ReenableRadios();
        EnterSubmissionMode();
        SetStatus(Lang.T("wifiRestored"));
    }

    // Password A restores internet so students can open the browser and upload the exam.
    // From here, normal browsing touches files outside the exam folder, so folder checking
    // would only produce false alarms: stop it and silence the alarm. The AI/VM shield stays
    // active and will sound again if a new AI connection or tool appears.
    private void EnterSubmissionMode()
    {
        if (_submissionMode)
        {
            return;
        }

        _submissionMode = true;
        _fileMonitor?.Dispose();
        _fileMonitor = null;

        // Silence folder-violation beeping. StopAlarm stops the single shared alarm thread,
        // so if an AI/VM threat is still active we re-arm it — that shield must stay audible.
        _audio.StopAlarm();
        if (_threatActive)
        {
            _audio.StartAlarm();
        }

        AddIncident(Lang.T("submissionMode"));
    }

    private async void ReenableRadios()
    {
        if (_config is null)
        {
            return;
        }

        var states = new List<string>();
        if (!_wifiDisableFailed && _config.DisableWifi)
        {
            if (_network.EnableWifi(out var error))
            {
                _log?.Append(LogEvents.WifiEnabled);
                states.Add(Lang.T("wifiOn"));
            }
            else
            {
                _log?.Append(LogEvents.WifiEnableFailed, error);
                states.Add(Lang.T("wifiOnFail"));
            }
        }

        if (_config.DisableBluetooth)
        {
            var (ok, _) = await _radio.SetBluetoothAsync(true);
            if (ok)
            {
                _log?.Append(LogEvents.BluetoothEnabled);
                states.Add(Lang.T("btOn"));
            }
        }

        _log?.Append(LogEvents.WifiRestored);
        if (states.Count > 0)
        {
            _radioStateLabel.Text = string.Join("    ", states);
        }
    }

    private async void AttemptAdminClose()
    {
        if (_config is null)
        {
            SetStatus(Lang.T("needValidConfig"));
            return;
        }

        var password = _adminPasswordBox.Text;
        _adminPasswordBox.Clear();
        if (!PasswordHasher.VerifyPassword(password, _config.AdminSaltBase64, _config.Iterations, _config.AdminPasswordHashBase64))
        {
            _log?.Append(LogEvents.AdminAuthFailed);
            SetStatus(Lang.T("wrongB"));
            return;
        }

        // Acknowledge: stop alarms, clear the AI/violation state, re-enable radios, then close.
        _audio.StopAlarm();
        if (_redActive)
        {
            _log?.Append(LogEvents.AiCleared);
        }

        StopMonitors();
        ReenableRadios();
        _log?.Append(LogEvents.AdminClose);

        _adminAuthenticated = true;
        await Task.Yield();
        Close();
    }

    // ----- Lifecycle -----

    private void StopMonitors()
    {
        _aiMonitor?.Dispose();
        _dnsMonitor?.Dispose();
        _threatMonitor?.Dispose();
        _processMonitor?.Dispose();
        _fileMonitor?.Dispose();
        _aiMonitor = null;
        _dnsMonitor = null;
        _threatMonitor = null;
        _processMonitor = null;
        _fileMonitor = null;
    }

    private void OnFormClosing(object? sender, FormClosingEventArgs e)
    {
        if (!_adminAuthenticated)
        {
            e.Cancel = true;
            SetStatus(Lang.T("needBToExit"));
            return;
        }

        if (!_closeLogged)
        {
            _audio.StopAlarm();
            StopMonitors();
            _log?.Append(LogEvents.NormalExit);
            _session?.MarkSessionCleanEnd();
            _closeLogged = true;
        }

        _reporter?.Dispose();
        _audio.Dispose();
    }

    // ----- Helpers -----

    private void RunOnUi(Action action)
    {
        if (IsDisposed)
        {
            return;
        }

        try
        {
            if (InvokeRequired)
            {
                BeginInvoke(action);
            }
            else
            {
                action();
            }
        }
        catch (ObjectDisposedException)
        {
        }
        catch (InvalidOperationException)
        {
        }
    }

    private void AddIncident(string text)
    {
        var stamped = $"{DateTime.Now:HH:mm:ss}  {text}";
        _incidentList.Items.Insert(0, stamped);
        while (_incidentList.Items.Count > 200)
        {
            _incidentList.Items.RemoveAt(_incidentList.Items.Count - 1);
        }
    }

    private void SetStatus(string message)
    {
        _statusLabel.Text = message;
        ReportState();
    }

    private void ReportState()
    {
        _reporter?.SetState(_stateStr, _statusLabel.Text);
    }
}
