using System.Text;
using ExamShared;

namespace ExamLockClient;

public sealed class MainForm : Form
{
    private readonly Label _statusLabel;
    private readonly Label _configPathLabel;
    private readonly Label _wifiStateLabel;
    private readonly TextBox _passwordBox;
    private readonly Button _unlockButton;
    private readonly Button _loadConfigButton;

    private ConfigPayload? _config;
    private SecureLogService? _log;
    private SessionStateService? _session;
    private readonly NetworkAdapterService _network = new();
    private string _configPath = string.Empty;
    private bool _unlocked;
    private bool _closeLogged;
    private bool _passwordVerified;
    private bool _wifiDisableFailed;

    public MainForm()
    {
        Text = "Exam Lock Client";
        Width = 640;
        Height = 300;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(12),
            ColumnCount = 2,
            RowCount = 6
        };

        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 160));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        layout.Controls.Add(new Label { Text = "Config File", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft }, 0, 0);
        _configPathLabel = new Label { Text = "(not loaded)", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
        layout.Controls.Add(_configPathLabel, 1, 0);

        layout.Controls.Add(new Label { Text = "Wi-Fi State", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft }, 0, 1);
        _wifiStateLabel = new Label { Text = "Unknown", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
        layout.Controls.Add(_wifiStateLabel, 1, 1);

        layout.Controls.Add(new Label { Text = "Unlock Password", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft }, 0, 2);
        _passwordBox = new TextBox { UseSystemPasswordChar = true, Dock = DockStyle.Fill };
        layout.Controls.Add(_passwordBox, 1, 2);

        _unlockButton = new Button { Text = "Unlock", Dock = DockStyle.Fill };
        _unlockButton.Click += (_, _) => AttemptUnlock();
        layout.Controls.Add(_unlockButton, 1, 3);

        _loadConfigButton = new Button { Text = "Load Config", Dock = DockStyle.Fill };
        _loadConfigButton.Click += (_, _) => LoadConfig(true);
        layout.Controls.Add(_loadConfigButton, 1, 4);

        _statusLabel = new Label { Text = "", Dock = DockStyle.Fill, AutoSize = false, TextAlign = ContentAlignment.TopLeft };
        layout.SetColumnSpan(_statusLabel, 2);
        layout.Controls.Add(_statusLabel, 0, 5);

        Controls.Add(layout);

        Load += (_, _) => LoadConfig(false);
        FormClosing += OnFormClosing;
    }

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

        var openDialog = new OpenFileDialog
        {
            Title = "Select exam.config",
            Filter = "Config Files (*.config)|*.config|All Files (*.*)|*.*"
        };

        if (openDialog.ShowDialog(this) != DialogResult.OK)
        {
            SetStatus("Config file required to start.");
            return;
        }

        TryLoadConfig(openDialog.FileName);
    }

    private string? FindDefaultConfig()
    {
        var cwd = Path.Combine(Environment.CurrentDirectory, "exam.config");
        if (File.Exists(cwd))
        {
            return cwd;
        }

        var appDir = Path.Combine(AppContext.BaseDirectory, "exam.config");
        if (File.Exists(appDir))
        {
            return appDir;
        }

        return null;
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
                SetStatus("Config integrity check failed.");
                return;
            }

            _config = envelope.Payload;
            _configPath = path;
            _configPathLabel.Text = path;

            InitializeServices(path, _config.LogSecretBase64);
            _log?.Append("APP_STARTED");
            _log?.Append("CONFIG_VALID");

            DisableWifi();
        }
        catch (Exception ex)
        {
            SetStatus($"Failed to load config: {ex.Message}");
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
            _log.Append("UNCLEAN_PREVIOUS_SESSION_DETECTED");
        }

        _session.MarkSessionStart();
    }

    private void DisableWifi()
    {
        if (_network.DisableWifi(out var error))
        {
            _wifiStateLabel.Text = "Disabled";
            _log?.Append("WIFI_DISABLED");
            SetStatus("Wi-Fi disabled. Enter password to unlock.");
            _wifiDisableFailed = false;
        }
        else
        {
            _wifiStateLabel.Text = "Disable failed";
            _log?.Append("WIFI_DISABLE_FAILED", error);
            SetStatus($"Failed to disable Wi-Fi: {error}");
            _wifiDisableFailed = true;
        }
    }

    private void AttemptUnlock()
    {
        if (_config is null)
        {
            SetStatus("Load a valid config first.");
            return;
        }

        var password = _passwordBox.Text;
        if (PasswordHasher.VerifyPassword(password, _config.SaltBase64, _config.Iterations, _config.PasswordHashBase64))
        {
            _passwordVerified = true;
            _log?.Append("UNLOCK_SUCCESS");
            if (_wifiDisableFailed)
            {
                SetStatus("Password accepted. Wi-Fi disable failed earlier, you may close the app.");
                return;
            }

            if (_network.EnableWifi(out var error))
            {
                _wifiStateLabel.Text = "Enabled";
                _log?.Append("WIFI_ENABLED");
                _unlocked = true;
                SetStatus("Unlocked. You may close the app.");
            }
            else
            {
                _wifiStateLabel.Text = "Enable failed";
                _log?.Append("WIFI_ENABLE_FAILED", error);
                SetStatus($"Failed to enable Wi-Fi: {error}");
            }
        }
        else
        {
            _log?.Append("UNLOCK_FAILED");
            SetStatus("Wrong password.");
        }
    }

    private void OnFormClosing(object? sender, FormClosingEventArgs e)
    {
        if (!_passwordVerified)
        {
            e.Cancel = true;
            SetStatus("Unlock required before exit.");
            return;
        }

        if (!_closeLogged)
        {
            _log?.Append("NORMAL_EXIT");
            _session?.MarkSessionCleanEnd();
            _closeLogged = true;
        }
    }

    private void SetStatus(string message)
    {
        _statusLabel.Text = message;
    }
}
