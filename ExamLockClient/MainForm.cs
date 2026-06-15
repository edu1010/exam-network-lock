using System.Text;
using ExamShared;

namespace ExamLockClient;

public sealed class MainForm : Form
{
    private readonly ShieldControl _shield;
    private readonly Label _statusLabel;
    private readonly Label _configPathLabel;
    private readonly Label _radioStateLabel;
    private readonly ListBox _incidentList;
    private readonly TextBox _restorePasswordBox;
    private readonly TextBox _adminPasswordBox;
    private readonly Button _restoreButton;
    private readonly Button _adminButton;
    private readonly Button _loadConfigButton;

    private ConfigPayload? _config;
    private SecureLogService? _log;
    private SessionStateService? _session;
    private readonly NetworkAdapterService _network = new();
    private readonly RadioService _radio = new();
    private readonly AudioAlerter _audio = new();

    private AiConnectionMonitor? _aiMonitor;
    private ProcessMonitor? _processMonitor;
    private FileActivityMonitor? _fileMonitor;

    private string _configPath = string.Empty;
    private bool _adminAuthenticated;
    private bool _closeLogged;
    private bool _wifiDisableFailed;

    private bool _redActive;
    private bool _yellowActive;
    private readonly HashSet<string> _reported = new();

    private ShieldControl.ShieldStatus _lastShield = ShieldControl.ShieldStatus.Idle;
    private bool _shieldInitialized;

    public MainForm()
    {
        Text = "Escudo de examen";
        Width = 600;
        Height = 700;
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        MinimizeBox = true;
        BackColor = Theme.Background;
        Font = Theme.Base;
        ForeColor = Theme.Text;

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(16),
            ColumnCount = 1,
            RowCount = 5,
            BackColor = Theme.Background
        };
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 230)); // shield
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 64));  // info card
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // incidents
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 132)); // controls card
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));  // status

        _shield = new ShieldControl { Dock = DockStyle.Fill, Caption = "Esperando…" };
        layout.Controls.Add(_shield, 0, 0);

        // --- Info card: config path + radios ---
        var infoCard = Theme.Card();
        infoCard.Dock = DockStyle.Fill;
        var infoGrid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 2, BackColor = Theme.Surface };
        infoGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 70));
        infoGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        infoGrid.Controls.Add(MutedLabel("Config"), 0, 0);
        _configPathLabel = ValueLabel("(no cargada)");
        infoGrid.Controls.Add(_configPathLabel, 1, 0);
        infoGrid.Controls.Add(MutedLabel("Radios"), 0, 1);
        _radioStateLabel = ValueLabel("—");
        infoGrid.Controls.Add(_radioStateLabel, 1, 1);
        infoCard.Controls.Add(infoGrid);
        layout.Controls.Add(infoCard, 0, 1);

        // --- Incidents ---
        var incidentsCard = Theme.Card();
        incidentsCard.Dock = DockStyle.Fill;
        var incidentsLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2, BackColor = Theme.Surface };
        incidentsLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 22));
        incidentsLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var incidentsTitle = new Label { Text = "Incidencias", Dock = DockStyle.Fill, Font = Theme.Heading, ForeColor = Theme.Text };
        incidentsLayout.Controls.Add(incidentsTitle, 0, 0);
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
        layout.Controls.Add(incidentsCard, 0, 2);

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

        controls.Controls.Add(MutedLabel("Contraseña A (Wi-Fi)"), 0, 0);
        _restorePasswordBox = new TextBox { UseSystemPasswordChar = true, Dock = DockStyle.Fill, Margin = new Padding(0, 3, 8, 3) };
        Theme.StyleInput(_restorePasswordBox);
        controls.Controls.Add(_restorePasswordBox, 1, 0);
        _restoreButton = new Button { Text = "Restaurar Wi-Fi", Dock = DockStyle.Fill, Margin = new Padding(0, 2, 0, 2) };
        Theme.StyleSecondary(_restoreButton);
        _restoreButton.Click += (_, _) => AttemptRestoreWifi();
        controls.Controls.Add(_restoreButton, 2, 0);

        controls.Controls.Add(MutedLabel("Contraseña B (cerrar)"), 0, 1);
        _adminPasswordBox = new TextBox { UseSystemPasswordChar = true, Dock = DockStyle.Fill, Margin = new Padding(0, 3, 8, 3) };
        Theme.StyleInput(_adminPasswordBox);
        controls.Controls.Add(_adminPasswordBox, 1, 1);
        _adminButton = new Button { Text = "Cerrar programa", Dock = DockStyle.Fill, Margin = new Padding(0, 2, 0, 2) };
        Theme.StylePrimary(_adminButton);
        _adminButton.Click += (_, _) => AttemptAdminClose();
        controls.Controls.Add(_adminButton, 2, 1);

        _loadConfigButton = new Button { Text = "Cargar config…", Dock = DockStyle.Fill, Margin = new Padding(0, 2, 0, 2) };
        Theme.StyleSecondary(_loadConfigButton);
        _loadConfigButton.Click += (_, _) => LoadConfig(true);
        controls.Controls.Add(_loadConfigButton, 2, 2);

        controlsCard.Controls.Add(controls);
        layout.Controls.Add(controlsCard, 0, 3);

        _statusLabel = new Label { Text = "", Dock = DockStyle.Fill, AutoSize = false, TextAlign = ContentAlignment.MiddleLeft, ForeColor = Theme.TextMuted };
        layout.Controls.Add(_statusLabel, 0, 4);

        Controls.Add(layout);

        Load += (_, _) => LoadConfig(false);
        FormClosing += OnFormClosing;

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
            Title = "Selecciona exam.config",
            Filter = "Config Files (*.config)|*.config|All Files (*.*)|*.*"
        };

        if (openDialog.ShowDialog(this) != DialogResult.OK)
        {
            SetStatus("Se necesita un archivo de configuración para empezar.");
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
                SetStatus("La integridad de la configuración no es válida.");
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
            SetStatus($"No se pudo cargar la configuración: {ex.Message}");
        }
    }

    private void InitializeServices(string configPath, string logSecretBase64)
    {
        var dir = Path.GetDirectoryName(configPath) ?? AppContext.BaseDirectory;
        var logPath = Path.Combine(dir, "examlog.jsonl");
        var sessionPath = Path.Combine(dir, "session.lock");

        _log = new SecureLogService(logPath, logSecretBase64);
        _session = new SessionStateService(sessionPath);

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

        var radioStates = new List<string>();

        if (_config.DisableWifi)
        {
            if (_network.DisableWifi(out var error))
            {
                _log?.Append(LogEvents.WifiDisabled);
                radioStates.Add("Wi-Fi: desactivado");
                _wifiDisableFailed = false;
            }
            else
            {
                _log?.Append(LogEvents.WifiDisableFailed, error);
                radioStates.Add("Wi-Fi: fallo al desactivar");
                _wifiDisableFailed = true;
            }
        }
        else
        {
            radioStates.Add("Wi-Fi: activo (vigilado)");
        }

        if (_config.DisableBluetooth)
        {
            var (ok, error) = await _radio.SetBluetoothAsync(false);
            if (ok)
            {
                _log?.Append(LogEvents.BluetoothDisabled);
                radioStates.Add("BT: desactivado");
            }
            else
            {
                _log?.Append(LogEvents.BluetoothFailed, error);
                radioStates.Add("BT: fallo");
            }
        }

        _radioStateLabel.Text = string.Join("    ", radioStates);

        StartMonitors();

        UpdateShield();
        AddIncident("Bloqueo iniciado.");
        SetStatus("Examen en curso. El escudo está activo.");
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
        }

        if (_config.AllowedProcesses.Length > 0)
        {
            _processMonitor = new ProcessMonitor(_config.AllowedProcesses);
            _processMonitor.UnknownProcessStarted += exe => RunOnUi(() => OnUnknownProcess(exe));
            _processMonitor.Start();
        }

        if (_config.AllowedFileExtensions.Length > 0 || _config.RestrictToWorkFolder)
        {
            var configDir = Path.GetDirectoryName(_configPath) ?? AppContext.BaseDirectory;
            var workFolder = WorkFolderResolver.Resolve(_config, configDir);
            var restrict = _config.RestrictToWorkFolder && workFolder.Length > 0;
            _fileMonitor = new FileActivityMonitor(
                _config.AllowedFileExtensions, workFolder, restrict, _config.AllowedProcesses);
            _fileMonitor.ForbiddenFileDetected += f => RunOnUi(() => OnForbiddenFile(f));
            _fileMonitor.OutsideFolderDetected += f => RunOnUi(() => OnOutsideFolder(f));
            _fileMonitor.UnknownFileDetected += f => RunOnUi(() => OnUnknownFile(f));
            _fileMonitor.Start();
        }
    }

    // ----- Incident handlers -----

    private void OnAiDetected(string desc)
    {
        if (!_reported.Add("AI:" + desc))
        {
            return;
        }

        _log?.Append(LogEvents.AiDetected, desc);
        AddIncident($"⚠ IA detectada: {desc}");
        if (_config?.RaiseVolumeOnAi == true)
        {
            _audio.RaiseVolumeToMax();
        }

        _audio.StartAlarm();
        SetRed("Conexión a IA detectada. Avisa al profesor.");
    }

    private void OnForbiddenFile(string file)
    {
        if (!_reported.Add("FILE:" + file))
        {
            return;
        }

        _log?.Append(LogEvents.ForbiddenFile, file);
        AddIncident($"⛔ Archivo no permitido: {file}");
        if (_config?.BeepOnViolation == true)
        {
            _audio.StartAlarm();
        }

        SetRed("Se ha abierto un archivo no permitido.");
    }

    private void OnOutsideFolder(string file)
    {
        if (!_reported.Add("OUT:" + file))
        {
            return;
        }

        _log?.Append(LogEvents.OutsideFolder, file);
        AddIncident($"⛔ Fuera de la carpeta de examen: {file}");
        if (_config?.BeepOnViolation == true)
        {
            _audio.StartAlarm();
        }

        SetRed("Se está trabajando fuera de la carpeta del examen.");
    }

    private void OnUnknownProcess(string exe)
    {
        if (!_reported.Add("PROC:" + exe))
        {
            return;
        }

        _log?.Append(LogEvents.UnknownProcess, exe);
        AddIncident($"❔ Programa desconocido: {exe}");
        SetYellow($"Programa no autorizado abierto: {exe}");
    }

    private void OnUnknownFile(string file)
    {
        if (!_reported.Add("UFILE:" + file))
        {
            return;
        }

        _log?.Append(LogEvents.UnknownFile, file);
        AddIncident($"❔ Archivo desconocido: {file}");
        SetYellow($"Archivo de tipo no reconocido: {file}");
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
            _shield.Caption = "Esperando configuración…";
            return;
        }

        var state = _redActive ? ShieldControl.ShieldStatus.Red
            : _yellowActive ? ShieldControl.ShieldStatus.Yellow
            : ShieldControl.ShieldStatus.Green;

        _shield.Status = state;
        _shield.Caption = state switch
        {
            ShieldControl.ShieldStatus.Red => "PELIGRO",
            ShieldControl.ShieldStatus.Yellow => "ATENCIÓN",
            _ => "PROTEGIDO"
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
            SetStatus("Carga una configuración válida primero.");
            return;
        }

        var password = _restorePasswordBox.Text;
        _restorePasswordBox.Clear();
        if (!PasswordHasher.VerifyPassword(password, _config.SaltBase64, _config.Iterations, _config.PasswordHashBase64))
        {
            _log?.Append(LogEvents.UnlockFailed);
            SetStatus("Contraseña A incorrecta.");
            return;
        }

        _log?.Append(LogEvents.UnlockSuccess);
        ReenableRadios();
        SetStatus("Wi-Fi restaurado. El escudo sigue activo.");
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
                states.Add("Wi-Fi: activo");
            }
            else
            {
                _log?.Append(LogEvents.WifiEnableFailed, error);
                states.Add("Wi-Fi: fallo al activar");
            }
        }

        if (_config.DisableBluetooth)
        {
            var (ok, _) = await _radio.SetBluetoothAsync(true);
            if (ok)
            {
                _log?.Append(LogEvents.BluetoothEnabled);
                states.Add("BT: activo");
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
            SetStatus("Carga una configuración válida primero.");
            return;
        }

        var password = _adminPasswordBox.Text;
        _adminPasswordBox.Clear();
        if (!PasswordHasher.VerifyPassword(password, _config.AdminSaltBase64, _config.Iterations, _config.AdminPasswordHashBase64))
        {
            _log?.Append(LogEvents.AdminAuthFailed);
            SetStatus("Contraseña B incorrecta.");
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
        _processMonitor?.Dispose();
        _fileMonitor?.Dispose();
        _aiMonitor = null;
        _processMonitor = null;
        _fileMonitor = null;
    }

    private void OnFormClosing(object? sender, FormClosingEventArgs e)
    {
        if (!_adminAuthenticated)
        {
            e.Cancel = true;
            SetStatus("Introduce la contraseña B (cerrar) para salir.");
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
    }
}
