using System.Collections.ObjectModel;
using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using ExamLockClient.App.Controls;
using ExamLockClient.Core.Monitoring;
using ExamLockClient.Core.Platform;
using ExamShared;

namespace ExamLockClient.App.Views;

public sealed class MainWindow : Window
{
    private readonly IPlatform _platform = PlatformFactory.Current;

    private readonly ShieldControl _shield = new();
    private readonly TextBlock _configPathValue = new();
    private readonly TextBlock _radioStateValue = new() { Text = "—" };
    private readonly TextBlock _statusLabel = new();
    private readonly ObservableCollection<string> _incidents = new();

    private readonly TextBlock _configTitle = new();
    private readonly TextBlock _radiosTitle = new();
    private readonly TextBlock _incidentsTitle = new() { FontWeight = FontWeight.SemiBold };
    private readonly TextBlock _pwdALabel = new();
    private readonly TextBlock _pwdBLabel = new();
    private readonly TextBox _restorePasswordBox = new() { PasswordChar = '•' };
    private readonly TextBox _adminPasswordBox = new() { PasswordChar = '•' };
    private readonly Button _restoreButton = new();
    private readonly Button _adminButton = new();
    private readonly Button _loadConfigButton = new();
    private readonly Button _reopenElevatedButton = new();

    private readonly AudioAlerter _audio;

    private ConfigPayload? _config;
    private SecureLogService? _log;
    private SessionStateService? _session;
    private MonitorReporter? _reporter;

    private AiConnectionMonitor? _aiMonitor;
    private DnsCacheMonitor? _dnsMonitor;
    private ThreatProcessMonitor? _threatMonitor;
    private ProcessMonitor? _processMonitor;
    private FileActivityMonitor? _fileMonitor;

    private string _configPath = string.Empty;
    private string _stateStr = "Idle";
    private bool _adminAuthenticated;
    private bool _relaunchClosing;
    private bool _closeLogged;
    private bool _wifiDisableFailed;
    private bool _submissionMode;
    private bool _threatActive;
    private bool _redActive;
    private bool _yellowActive;
    private readonly HashSet<string> _reported = new();

    private ShieldControl.ShieldStatus _lastShield = ShieldControl.ShieldStatus.Idle;
    private bool _shieldInitialized;

    public MainWindow()
    {
        _audio = new AudioAlerter(_platform);

        Width = 680;
        Height = 800;
        MinWidth = 600;
        MinHeight = 720;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        Background = Palette.BackgroundBrush;
        FontFamily = FontFamily.Parse(Palette.FontFamily);

        var root = new Grid
        {
            Margin = new Thickness(16),
            RowDefinitions = new RowDefinitions("Auto,180,Auto,*,Auto,Auto")
        };

        root.Children.Add(Place(BuildLanguageBar(), 0));
        root.Children.Add(Place(_shield, 1));
        root.Children.Add(Place(BuildInfoCard(), 2));
        root.Children.Add(Place(BuildIncidentsCard(), 3));
        root.Children.Add(Place(BuildControlsCard(), 4));

        _statusLabel.Foreground = Palette.TextMutedBrush;
        _statusLabel.TextWrapping = TextWrapping.Wrap;
        _statusLabel.Margin = new Thickness(2, 6, 0, 0);
        root.Children.Add(Place(_statusLabel, 5));

        Content = root;

        Lang.Changed += ApplyLanguage;
        ApplyLanguage();

        Opened += async (_, _) => await LoadConfig(forceDialog: false);
    }

    private static Control Place(Control control, int row)
    {
        Grid.SetRow(control, row);
        return control;
    }

    // ----- UI construction -----

    private Control BuildLanguageBar()
    {
        var bar = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Spacing = 6
        };

        foreach (var (lang, label) in new[] { (Language.En, "EN"), (Language.Ca, "CA"), (Language.Es, "ES") })
        {
            var captured = lang;
            var btn = new Button { Content = label, Width = 44, Tag = lang };
            ToolTip.SetTip(btn, lang switch { Language.Ca => "Català", Language.Es => "Español", _ => "English" });
            btn.Click += (_, _) => Lang.Set(captured);
            bar.Children.Add(btn);
        }

        return bar;
    }

    private Border BuildInfoCard()
    {
        var grid = new Grid
        {
            ColumnDefinitions = new ColumnDefinitions("70,*"),
            RowDefinitions = new RowDefinitions("Auto,Auto")
        };

        _configTitle.Foreground = Palette.TextMutedBrush;
        _radiosTitle.Foreground = Palette.TextMutedBrush;
        _configPathValue.Foreground = Palette.TextBrush;
        _configPathValue.TextTrimming = TextTrimming.CharacterEllipsis;
        _radioStateValue.Foreground = Palette.TextBrush;
        _radioStateValue.TextWrapping = TextWrapping.Wrap;
        _configPathValue.PointerEntered += (_, _) => ToolTip.SetTip(_configPathValue, _configPathValue.Text);

        grid.Children.Add(Cell(_configTitle, 0, 0));
        grid.Children.Add(Cell(_configPathValue, 0, 1));
        grid.Children.Add(Cell(_radiosTitle, 1, 0));
        grid.Children.Add(Cell(_radioStateValue, 1, 1));

        return Card(grid);
    }

    private Border BuildIncidentsCard()
    {
        var list = new ListBox
        {
            ItemsSource = _incidents,
            Background = Palette.SurfaceBrush,
            BorderThickness = new Thickness(0)
        };

        var layout = new Grid { RowDefinitions = new RowDefinitions("Auto,*") };
        list.PointerEntered += (_, _) => ToolTip.SetTip(list, UiHelp.Get("incidents", (int)Lang.Current));
        layout.Children.Add(Cell(_incidentsTitle, 0, 0));
        layout.Children.Add(Cell(list, 1, 0));

        return Card(layout);
    }

    private Border BuildControlsCard()
    {
        var grid = new Grid
        {
            ColumnDefinitions = new ColumnDefinitions("*,Auto"),
            RowDefinitions = new RowDefinitions("Auto,Auto,Auto,Auto,Auto")
        };

        _pwdALabel.Foreground = Palette.TextMutedBrush;
        _pwdALabel.VerticalAlignment = VerticalAlignment.Center;
        _pwdBLabel.Foreground = Palette.TextMutedBrush;
        _pwdBLabel.VerticalAlignment = VerticalAlignment.Center;
        _pwdALabel.TextWrapping = TextWrapping.Wrap;
        _pwdBLabel.TextWrapping = TextWrapping.Wrap;
        foreach (var button in new[] { _restoreButton, _adminButton, _loadConfigButton, _reopenElevatedButton })
        {
            button.MinHeight = 36;
            button.Padding = new Thickness(12, 6);
            button.Margin = new Thickness(4, 4, 0, 4);
            button.HorizontalAlignment = HorizontalAlignment.Stretch;
            button.HorizontalContentAlignment = HorizontalAlignment.Center;
        }
        _restorePasswordBox.Margin = _adminPasswordBox.Margin = new Thickness(0, 4, 8, 4);

        _restoreButton.Click += (_, _) => AttemptRestoreWifi();
        _adminButton.Click += async (_, _) => await AttemptAdminClose();
        _adminButton.Background = Palette.AccentBrush;
        _adminButton.Foreground = Brushes.White;
        _loadConfigButton.Click += async (_, _) => await LoadConfig(forceDialog: true);
        _reopenElevatedButton.Click += async (_, _) => await AttemptReopenElevated();

        grid.Children.Add(Cell(_pwdALabel, 0, 0));
        Grid.SetColumnSpan(_pwdALabel, 2);
        grid.Children.Add(Cell(_restorePasswordBox, 1, 0));
        grid.Children.Add(Cell(_restoreButton, 1, 1));

        grid.Children.Add(Cell(_pwdBLabel, 2, 0));
        Grid.SetColumnSpan(_pwdBLabel, 2);
        grid.Children.Add(Cell(_adminPasswordBox, 3, 0));
        grid.Children.Add(Cell(_adminButton, 3, 1));

        var reopen = Cell(_reopenElevatedButton, 4, 0);
        grid.Children.Add(reopen);
        grid.Children.Add(Cell(_loadConfigButton, 4, 1));

        return Card(grid);
    }

    private static Border Card(Control child) => new()
    {
        Background = Palette.SurfaceBrush,
        BorderBrush = Palette.BorderBrush,
        BorderThickness = new Thickness(1),
        CornerRadius = new CornerRadius(6),
        Padding = new Thickness(12),
        Margin = new Thickness(0, 0, 0, 10),
        Child = child
    };

    private static Control Cell(Control control, int row, int col)
    {
        Grid.SetRow(control, row);
        Grid.SetColumn(control, col);
        return control;
    }

    private void ApplyLanguage()
    {
        Title = Lang.T("title");
        _configTitle.Text = Lang.T("config");
        _radiosTitle.Text = Lang.T("radios");
        _incidentsTitle.Text = Lang.T("incidents");
        _pwdALabel.Text = Lang.T("pwdA");
        _pwdBLabel.Text = Lang.T("pwdB");
        _restoreButton.Content = Lang.T("restoreBtn");
        _adminButton.Content = Lang.T("closeBtn");
        _loadConfigButton.Content = Lang.T("loadBtn");
        _reopenElevatedButton.Content = Lang.T("reopenAdminBtn");
        _reopenElevatedButton.IsVisible = !_platform.IsElevated;
        foreach (var (control, key) in new (Control, string)[]
        {
            (_pwdALabel, "pwdA"), (_restorePasswordBox, "pwdA"), (_restoreButton, "pwdA"),
            (_pwdBLabel, "pwdB"), (_adminPasswordBox, "pwdB"), (_adminButton, "pwdB"),
            (_loadConfigButton, "loadBtn"), (_reopenElevatedButton, "reopenAdminBtn"),
            (_incidentsTitle, "incidents"), (_radioStateValue, "radios"), (_shield, "shield")
        }) ToolTip.SetTip(control, UiHelp.Get(key, (int)Lang.Current));

        if (_config is null)
        {
            _configPathValue.Text = Lang.T("notLoaded");
        }

        UpdateShield();
    }

    // ----- Config loading -----

    private async Task LoadConfig(bool forceDialog)
    {
        if (_config is not null)
        {
            return;
        }

        var candidate = Program.StartupConfigPath;
        if (!forceDialog && !string.IsNullOrWhiteSpace(candidate) && File.Exists(candidate))
        {
            TryLoadConfig(candidate);
            return;
        }

        candidate = FindDefaultConfig();
        if (!forceDialog && candidate is not null)
        {
            TryLoadConfig(candidate);
            return;
        }

        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = Lang.T("dlgSelectConfig"),
            AllowMultiple = false,
            FileTypeFilter = new[]
            {
                new FilePickerFileType("Config") { Patterns = new[] { "*.config" } },
                FilePickerFileTypes.All
            }
        });

        if (files.Count == 0)
        {
            SetStatus(Lang.T("needConfig"));
            return;
        }

        TryLoadConfig(files[0].Path.LocalPath);
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
            _configPathValue.Text = path;

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
        _reporter = new MonitorReporter(logPath, _config?.MonitorTargets);

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

        _audio.Pattern = _config.BeepMode == BeepModes.ThreeBeeps ? BeepPattern.ThreeBeeps : BeepPattern.Continuous;
        _audio.VolumePercent = _config.AlarmVolumePercent is > 0 and <= 100 ? _config.AlarmVolumePercent : 100;

        var radioStates = new List<string>();

        if (_config.DisableWifi)
        {
            if (_platform.DisableWifi(out var error))
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
            var (ok, error) = await _platform.SetBluetoothAsync(false);
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

        _radioStateValue.Text = string.Join("    ", radioStates);

        StartMonitors();

        if (_config.MonitorBroadcast)
        {
            _reporter?.Start();
        }

        AddIncident(Lang.T("lockStarted"));
        if (NeedsElevationButIsNot())
        {
            AddIncident(Lang.T("incNoAdmin"));
            SetYellow(Lang.T("statusNoAdmin"));
        }
        else
        {
            UpdateShield();
            SetStatus(Lang.T("statusActive"));
        }
    }

    private void StartMonitors()
    {
        if (_config is null)
        {
            return;
        }

        if (_config.AiShieldEnabled)
        {
            var blocklist = _config.AiBlocklist.Length > 0 ? _config.AiBlocklist : ConfigDefaults.DefaultAiBlocklist;
            _aiMonitor = new AiConnectionMonitor(_platform, blocklist);
            _aiMonitor.AiConnectionDetected += evidence => RunOnUi(() => OnAiDetected(evidence));
            _aiMonitor.Start();

            _dnsMonitor = new DnsCacheMonitor(_platform, blocklist);
            _dnsMonitor.AiHostnameResolved += host => RunOnUi(() => OnAiDns(host));
            _dnsMonitor.Start();
        }

        if (_config.AiShieldEnabled || _config.DetectVirtualMachines)
        {
            _threatMonitor = new ThreatProcessMonitor(_platform, _config.AiShieldEnabled, _config.DetectVirtualMachines);
            _threatMonitor.AiToolDetected += name => RunOnUi(() => OnAiTool(name));
            _threatMonitor.VmDetected += name => RunOnUi(() => OnVmDetected(name));
            _threatMonitor.Start();
        }

        if (_config.AllowedProcesses.Length > 0 || _config.BlockedProcesses is { Length: > 0 })
        {
            _processMonitor = new ProcessMonitor(_platform, _config.AllowedProcesses, _config.BlockedProcesses);
            _processMonitor.UnknownProcessStarted += exe => RunOnUi(() => OnUnknownProcess(exe));
            _processMonitor.BlockedProcessDetected += exe => RunOnUi(() => OnBlockedProcess(exe));
            _processMonitor.Start();
        }

        if (_config.AllowedFileExtensions.Length > 0 || _config.BlockedFileExtensions.Length > 0 || _config.RestrictToWorkFolder)
        {
            var configDir = Path.GetDirectoryName(_configPath) ?? AppContext.BaseDirectory;
            var workFolder = WorkFolderResolver.Resolve(_config, configDir);
            var restrict = _config.RestrictToWorkFolder && workFolder.Length > 0;
            _fileMonitor = new FileActivityMonitor(
                _platform, _config.AllowedFileExtensions, workFolder, restrict, _config.AllowedProcesses, _config.BlockedFileExtensions);
            _fileMonitor.ForbiddenFileDetected += f => RunOnUi(() => OnForbiddenFile(f));
            _fileMonitor.OutsideFolderDetected += f => RunOnUi(() => OnOutsideFolder(f));
            _fileMonitor.UnknownFileDetected += f => RunOnUi(() => OnUnknownFile(f));
            _fileMonitor.Start();
        }
    }

    // ----- Incident handlers -----

    private void OnAiDetected(AiConnectionEvidence evidence)
    {
        if (evidence.IsStudentFacingProcess)
        {
            RaiseAiAlarm("AI:" + evidence.DedupKey, LogEvents.AiDetected, evidence.Summary, "incAi", "statusAi");
            return;
        }

        RaiseAiWarning("AIWARN:" + evidence.DedupKey, LogEvents.AiUnattributedDetected, evidence.Summary, "incAiPossible", "statusAiPossible");
    }

    private void OnAiDns(string host) =>
        RaiseAiWarning("DNS:" + host, LogEvents.AiDnsDetected, host, "incAiPossible", "statusAiPossible");

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

    private void RaiseAiWarning(string dedupKey, string logEvent, string data, string incidentKey, string statusKey)
    {
        if (!_reported.Add(dedupKey))
        {
            return;
        }

        _log?.Append(logEvent, data);
        AddIncident(string.Format(Lang.T(incidentKey), data));
        SetYellow(Lang.T(statusKey));
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

    private void OnBlockedProcess(string exe)
    {
        if (!_reported.Add("BLOCKEDPROC:" + exe)) return;
        _log?.Append(LogEvents.BlockedProcess, exe);
        AddIncident(string.Format(Lang.T("incBlockedProc"), exe));
        SetRed(string.Format(Lang.T("statusBlockedProc"), exe));
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

        var password = _restorePasswordBox.Text ?? string.Empty;
        _restorePasswordBox.Text = string.Empty;
        if (!PasswordHasher.VerifyPassword(password, _config.SaltBase64, _config.Iterations, _config.PasswordHashBase64))
        {
            _log?.Append(LogEvents.UnlockFailed);
            SetStatus(Lang.T("wrongA"));
            return;
        }

        _log?.Append(LogEvents.UnlockSuccess);
        _ = ReenableRadios();
        EnterSubmissionMode();
        SetStatus(Lang.T("wifiRestored"));
    }

    private void EnterSubmissionMode()
    {
        if (_submissionMode)
        {
            return;
        }

        _submissionMode = true;
        _fileMonitor?.Dispose();
        _fileMonitor = null;

        _audio.StopAlarm();
        if (_threatActive)
        {
            _audio.StartAlarm();
        }

        AddIncident(Lang.T("submissionMode"));
    }

    private async Task ReenableRadios()
    {
        if (_config is null)
        {
            return;
        }

        var states = new List<string>();
        if (!_wifiDisableFailed && _config.DisableWifi)
        {
            if (_platform.EnableWifi(out var error))
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
            var (ok, _) = await _platform.SetBluetoothAsync(true);
            if (ok)
            {
                _log?.Append(LogEvents.BluetoothEnabled);
                states.Add(Lang.T("btOn"));
            }
        }

        _log?.Append(LogEvents.WifiRestored);
        if (states.Count > 0)
        {
            _radioStateValue.Text = string.Join("    ", states);
        }
    }

    private async Task AttemptAdminClose()
    {
        if (_config is null)
        {
            SetStatus(Lang.T("needValidConfig"));
            return;
        }

        var password = _adminPasswordBox.Text ?? string.Empty;
        _adminPasswordBox.Text = string.Empty;
        if (!PasswordHasher.VerifyPassword(password, _config.AdminSaltBase64, _config.Iterations, _config.AdminPasswordHashBase64))
        {
            _log?.Append(LogEvents.AdminAuthFailed);
            SetStatus(Lang.T("wrongB"));
            return;
        }

        _audio.StopAlarm();
        if (_redActive)
        {
            _log?.Append(LogEvents.AiCleared);
        }

        StopMonitors();
        await ReenableRadios();
        _log?.Append(LogEvents.AdminClose);

        _adminAuthenticated = true;
        Close();
    }

    private async Task AttemptReopenElevated()
    {
        if (_platform.IsElevated)
        {
            _reopenElevatedButton.IsVisible = false;
            return;
        }

        var exe = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exe))
        {
            SetStatus(Lang.T("adminRelaunchFail"));
            return;
        }

        var args = _configPath.Length > 0 ? new[] { "--config", _configPath } : Array.Empty<string>();
        _reopenElevatedButton.IsEnabled = false;
        bool started;
        try
        {
            started = await Task.Run(() => _platform.TryRelaunchElevated(exe, args));
        }
        finally
        {
            _reopenElevatedButton.IsEnabled = true;
        }
        if (!started)
        {
            SetStatus(Lang.T("adminRelaunchCanceled"));
            return;
        }

        _relaunchClosing = true;
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

    protected override void OnClosing(WindowClosingEventArgs e)
    {
        if (!_adminAuthenticated && !_relaunchClosing)
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
        Lang.Changed -= ApplyLanguage;

        base.OnClosing(e);
    }

    // ----- Helpers -----

    private static void RunOnUi(Action action) => Dispatcher.UIThread.Post(action);

    private void AddIncident(string text)
    {
        _incidents.Insert(0, $"{DateTime.Now:HH:mm:ss}  {text}");
        while (_incidents.Count > 200)
        {
            _incidents.RemoveAt(_incidents.Count - 1);
        }
    }

    private void SetStatus(string message)
    {
        _statusLabel.Text = message;
        ReportState();
    }

    private bool NeedsElevationButIsNot() =>
        _config is not null && !_platform.IsElevated && (_config.DisableWifi || _config.DisableBluetooth);

    private void ReportState() => _reporter?.SetState(_stateStr, _statusLabel.Text ?? string.Empty);
}
