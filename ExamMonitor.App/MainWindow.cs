using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Templates;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using ExamDesktop.Ui;
using ExamShared;

namespace ExamMonitor;

/// <summary>Avalonia port of the WinForms teacher dashboard: live grid of students over the LAN.</summary>
public sealed class MainWindow : Window
{
    private sealed class ClientRow
    {
        public string User = "";
        public string Machine = "";
        public string State = "Idle";
        public string StatusText = "";
        public string ConfigMode = "";
        public string Ip = "";
        public DateTime LastSeen;
        public readonly SortedDictionary<int, LogEntry> Entries = new();
        public string Key => User + "@" + Machine;
    }

    /// <summary>One rendered grid line.</summary>
    private sealed record GridLine(string Key, string State, string Incident, string Events, string Integrity, string Seen, IBrush Back, IBrush Fore);

    // Column widths shared by the header and every row so they line up like a DataGridView.
    private const string Columns = "2*,1.2*,3*,0.8*,1.4*,1.2*";
    private const int StaleSeconds = 20;

    private static readonly IBrush GreenBack = Palette.Brush(187, 247, 208);
    private static readonly IBrush AmberBack = Palette.Brush(253, 230, 138);
    private static readonly IBrush RedBack = Palette.Brush(254, 202, 202);
    private static readonly IBrush IdleBack = Palette.Brush(229, 231, 235);

    private readonly Dictionary<string, ClientRow> _clients = new();
    private readonly MonitorListener _listener = new();
    private readonly LanguageBar _languageBar;

    private readonly ListBox _grid = Ui.TableRows(new ListBox());
    private readonly Grid _header = new() { ColumnDefinitions = new ColumnDefinitions(Columns) };
    private readonly TextBlock[] _headerCells = new TextBlock[6];
    private readonly TextBlock _statusLabel = Ui.Muted();
    private readonly SelectableTextBlock _addressLabel = new() { Foreground = Palette.TextMuted, TextWrapping = TextWrapping.Wrap };
    private readonly Button _loadButton = Ui.Secondary(new Button());
    private readonly Button _saveButton = Ui.Secondary(new Button());
    private readonly Button _pushButton = Ui.Secondary(new Button());
    private readonly Button _pushExamButton = Ui.Secondary(new Button());
    private readonly DispatcherTimer _refresh = new() { Interval = TimeSpan.FromSeconds(1) };

    private string? _logSecret;
    private string _statusOverride = "";

    public MainWindow()
    {
        Width = 980;
        Height = 620;
        MinWidth = 640;
        MinHeight = 360;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        Background = Palette.Background;

        _languageBar = new LanguageBar(i => { Lang.Set((Language)i); ApplyLanguage(); });

        _loadButton.Click += async (_, _) => await LoadConfig();
        _saveButton.Click += async (_, _) => await SaveLogs();
        _pushButton.Click += async (_, _) => await PushConfig(exam: false);
        _pushExamButton.Click += async (_, _) => await PushConfig(exam: true);

        var toolbar = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*,Auto"), Margin = new Thickness(0, 0, 0, 10) };
        toolbar.Children.Add(Ui.Cell(new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6, Children = { _loadButton, _saveButton, _pushButton, _pushExamButton } }, 0, 0));
        toolbar.Children.Add(Ui.Cell(_languageBar, 0, 2));

        for (var i = 0; i < _headerCells.Length; i++)
        {
            _headerCells[i] = new TextBlock { FontWeight = FontWeight.SemiBold, Foreground = Palette.TextMuted, Margin = new Thickness(8, 6), TextTrimming = TextTrimming.CharacterEllipsis };
            _header.Children.Add(Ui.Cell(_headerCells[i], 0, i));
        }

        _grid.Background = Palette.Surface;
        _grid.ItemTemplate = Ui.RowTemplate<GridLine>(BuildRow);

        var table = new Grid { RowDefinitions = new RowDefinitions("Auto,*") };
        table.Children.Add(Ui.Cell(new Border { Child = _header, BorderBrush = Palette.Border, BorderThickness = new Thickness(0, 0, 0, 1) }, 0));
        table.Children.Add(Ui.Cell(_grid, 1));

        var root = new Grid { Margin = new Thickness(12), RowDefinitions = new RowDefinitions("Auto,*,Auto,Auto") };
        root.Children.Add(Ui.Cell(toolbar, 0));
        root.Children.Add(Ui.Cell(new Border
        {
            Child = table,
            Background = Palette.Surface,
            BorderBrush = Palette.Border,
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(6),
            ClipToBounds = true
        }, 1));
        _statusLabel.Margin = new Thickness(2, 8, 0, 0);
        root.Children.Add(Ui.Cell(_statusLabel, 2));
        _addressLabel.Margin = new Thickness(2, 4, 0, 0);
        root.Children.Add(Ui.Cell(_addressLabel, 3));
        Content = root;

        _listener.StatusReceived += m => Dispatcher.UIThread.Post(() => OnStatus(m));
        _listener.LogReceived += m => Dispatcher.UIThread.Post(() => OnLog(m));

        _refresh.Tick += (_, _) => RefreshGrid();
        _refresh.Start();

        Opened += (_, _) =>
        {
            TryAutoLoadConfig();
            try
            {
                _listener.Start();
            }
            catch (Exception ex)
            {
                // Another monitor already owns the UDP port: say so instead of crashing.
                _statusOverride = ex.Message;
                _statusLabel.Text = ex.Message;
            }
        };
        Closing += (_, _) =>
        {
            _refresh.Stop();
            _listener.Dispose();
        };

        ApplyLanguage();
    }

    private static Control BuildRow(GridLine line)
    {
        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions(Columns), Background = line.Back };
        var values = new[] { line.Key, line.State, line.Incident, line.Events, line.Integrity, line.Seen };
        for (var i = 0; i < values.Length; i++)
        {
            var cell = new TextBlock
            {
                Text = values[i],
                Foreground = line.Fore,
                Margin = new Thickness(8, 6),
                TextTrimming = TextTrimming.CharacterEllipsis,
                FontWeight = i == 0 ? FontWeight.SemiBold : FontWeight.Normal
            };
            ToolTip.SetTip(cell, values[i]);
            grid.Children.Add(Ui.Cell(cell, 0, i));
        }

        return grid;
    }

    // ----- Language -----

    private void ApplyLanguage()
    {
        Title = Lang.T("title");
        _loadButton.Content = Lang.T("loadBtn");
        _saveButton.Content = Lang.T("saveBtn");
        _pushButton.Content = Lang.T("pushBtn");
        ToolTip.SetTip(_pushButton, Lang.T("pushTip"));
        _pushExamButton.Content = Lang.T("pushExamBtn");
        ToolTip.SetTip(_pushExamButton, Lang.T("pushExamTip"));
        var keys = new[] { "colStudent", "colState", "colIncident", "colEvents", "colIntegrity", "colSeen" };
        for (var i = 0; i < keys.Length; i++)
        {
            _headerCells[i].Text = Lang.T(keys[i]);
        }

        _languageBar.Select((int)Lang.Current);
        SetIdleStatus();
        RefreshGrid();
    }

    // ----- Incoming messages -----

    private void OnStatus(StatusMessage m)
    {
        var row = Upsert(m.User, m.Machine);
        row.State = m.State;
        row.StatusText = m.StatusText;
        row.ConfigMode = m.ConfigMode;
        row.Ip = m.SourceIp;
        row.LastSeen = DateTime.Now;
    }

    private void OnLog(LogChunkMessage m)
    {
        var row = Upsert(m.User, m.Machine);
        row.LastSeen = DateTime.Now;
        foreach (var e in m.Entries)
        {
            row.Entries[e.Sequence] = e;
        }
    }

    private ClientRow Upsert(string user, string machine)
    {
        var key = user + "@" + machine;
        if (!_clients.TryGetValue(key, out var row))
        {
            row = new ClientRow { User = user, Machine = machine };
            _clients[key] = row;
        }

        return row;
    }

    // ----- Grid -----

    private void RefreshGrid()
    {
        var selectedKey = (_grid.SelectedItem as GridLine)?.Key;
        var lines = new List<GridLine>();

        foreach (var row in _clients.Values.OrderBy(r => r.Key, StringComparer.OrdinalIgnoreCase))
        {
            var seconds = (int)Math.Max(0, (DateTime.Now - row.LastSeen).TotalSeconds);
            var stale = seconds > StaleSeconds;
            lines.Add(new GridLine(
                row.Key,
                row.ConfigMode == "default" ? StateText(row.State) + " · " + Lang.T("modeDefault") : StateText(row.State),
                row.StatusText,
                row.Entries.Count.ToString(),
                Integrity(row),
                string.Format(Lang.T("secondsAgo"), seconds),
                stale ? IdleBack : StateBack(row.State),
                stale ? Palette.TextMuted : Palette.Text));
        }

        _grid.ItemsSource = lines;
        _grid.SelectedItem = lines.FirstOrDefault(l => l.Key == selectedKey);
    }

    private string StateText(string state) => state switch
    {
        "Green" => Lang.T("stGreen"),
        "Yellow" => Lang.T("stYellow"),
        "Red" => Lang.T("stRed"),
        _ => Lang.T("stIdle")
    };

    private static IBrush StateBack(string state) => state switch
    {
        "Green" => GreenBack,
        "Yellow" => AmberBack,
        "Red" => RedBack,
        _ => IdleBack
    };

    private string Integrity(ClientRow row)
    {
        if (row.Entries.Count == 0)
        {
            return "";
        }

        if (_logSecret is null)
        {
            return Lang.T("intNoKey");
        }

        var ordered = row.Entries.Values.ToList();
        // Need a contiguous chain from sequence 1 to verify.
        if (ordered[0].Sequence != 1 || ordered[^1].Sequence != ordered.Count)
        {
            return Lang.T("intPartial");
        }

        return LogChainVerifier.Verify(ordered, _logSecret) ? Lang.T("intOk") : Lang.T("intFail");
    }

    // ----- Config (for integrity verification) -----

    private void TryAutoLoadConfig()
    {
        var candidate = Path.Combine(Environment.CurrentDirectory, "exam.config");
        if (!File.Exists(candidate))
        {
            candidate = Path.Combine(AppContext.BaseDirectory, "exam.config");
        }

        if (File.Exists(candidate))
        {
            TryLoadConfig(candidate);
        }
        else
        {
            SetIdleStatus();
        }
    }

    private async Task LoadConfig()
    {
        var file = await Pickers.OpenFile(this, Lang.T("loadBtn"), ("Config (*.config)", new[] { "*.config" }));
        if (file is not null)
        {
            TryLoadConfig(file);
        }
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
                _statusLabel.Text = Lang.T("configInvalid");
                return;
            }

            _logSecret = envelope.Payload.LogSecretBase64;
            _statusLabel.Text = Lang.T("configLoaded");
        }
        catch
        {
            _statusLabel.Text = Lang.T("configInvalid");
        }
    }

    private void SetIdleStatus()
    {
        _statusLabel.Text = _statusOverride.Length > 0
            ? _statusOverride
            : Lang.T("listening") + "   " + (_logSecret is null ? Lang.T("noConfig") : Lang.T("configLoaded"));
        var ips = LocalIpv4Addresses();
        _addressLabel.Text = ips.Length > 0
            ? string.Format(Lang.T("listeningOn"), string.Join(", ", ips), MonitorProtocol.UdpPort)
            : string.Empty;
    }

    /// <summary>This PC's LAN IPv4 addresses: what students need when broadcast cannot reach the monitor.</summary>
    private static string[] LocalIpv4Addresses()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Where(n => !n.Name.StartsWith("docker", StringComparison.OrdinalIgnoreCase) && !n.Name.StartsWith("br-", StringComparison.Ordinal)
                    && !n.Name.StartsWith("veth", StringComparison.Ordinal) && !n.Name.StartsWith("virbr", StringComparison.Ordinal))
                .SelectMany(n => n.GetIPProperties().UnicastAddresses)
                .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a.Address))
                .Select(a => a.Address.ToString())
                .Distinct()
                .ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    // ----- Push config -----

    /// <summary>
    /// Sends a config to the students seen recently: as their new default config, or (exam) as an
    /// exam to start now on those running their default config. A pushed exam is not kept as the
    /// default, so the next launch goes back to the default config.
    /// </summary>
    private async Task PushConfig(bool exam)
    {
        var title = Lang.T(exam ? "pushExamBtn" : "pushBtn");
        var path = await Pickers.OpenFile(this, title, ("Config (*.config)", new[] { "*.config" }));
        if (path is null)
        {
            return;
        }

        string json;
        try
        {
            json = File.ReadAllText(path, Encoding.UTF8);
        }
        catch
        {
            json = "";
        }

        var envelope = DefaultConfigStore.TryParseSigned(json);
        if (envelope is null)
        {
            await MessageBox.Show(this, Lang.T("configInvalid"), title, MessageKind.Error);
            return;
        }

        // Guard against the wrong button: an exam config installed as the default would lock the
        // students down every time they open the app.
        if (exam == (envelope.Payload.IsDefaultConfig == true))
        {
            await MessageBox.Show(this, Lang.T(exam ? "pushIsDefault" : "pushNotDefault"), title, MessageKind.Warning);
            return;
        }

        var targets = _clients.Values
            .Where(r => (DateTime.Now - r.LastSeen).TotalSeconds <= StaleSeconds && IPAddress.TryParse(r.Ip, out _))
            .Where(r => !exam || r.ConfigMode == "default")
            .OrderBy(r => r.Key, StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (targets.Count == 0)
        {
            await MessageBox.Show(this, Lang.T(exam ? "pushExamNoClients" : "pushNoClients"), title, MessageKind.Warning);
            return;
        }

        var password = await PasswordPrompt.Show(this, string.Format(Lang.T(exam ? "pushExamPrompt" : "pushPrompt"), targets.Count), title, Lang.T("pushSend"), Lang.T("cancel"));
        if (string.IsNullOrEmpty(password))
        {
            return;
        }

        _pushButton.IsEnabled = _pushExamButton.IsEnabled = false;
        _statusLabel.Text = string.Format(Lang.T("pushing"), targets.Count);
        (string Key, string? Error)[] results;
        try
        {
            results = await Task.WhenAll(targets.Select(async r =>
                (r.Key, await ConfigPushSender.PushAsync(IPAddress.Parse(r.Ip), exam ? ConfigPushTargets.Exam : ConfigPushTargets.Default,
                    Path.GetFileName(path), json, password))));
        }
        finally
        {
            _pushButton.IsEnabled = _pushExamButton.IsEnabled = true;
        }

        var failed = results.Where(r => r.Error is not null).ToList();
        var done = string.Format(Lang.T(exam ? "pushExamDone" : "pushDone"), results.Length - failed.Count, results.Length);
        var text = new StringBuilder(done);
        foreach (var (key, error) in failed)
        {
            text.Append('\n').Append(key).Append(": ").Append(PushErrorText(error!));
        }

        _statusLabel.Text = done;
        await MessageBox.Show(this, text.ToString(), title, failed.Count == 0 ? MessageKind.Info : MessageKind.Warning);
    }

    private static string PushErrorText(string error) => error switch
    {
        ConfigPushErrors.Auth => Lang.T("pushErrAuth"),
        ConfigPushErrors.Invalid => Lang.T("configInvalid"),
        ConfigPushErrors.NoAuthority => Lang.T("pushErrNoConfig"),
        ConfigPushErrors.Save => Lang.T("pushErrSave"),
        ConfigPushErrors.Busy => Lang.T("pushErrBusy"),
        ConfigPushErrors.WrongKind => Lang.T("pushErrKind"),
        _ => Lang.T("pushErrUnreachable")
    };

    // ----- Save -----

    private async Task SaveLogs()
    {
        var folder = await Pickers.OpenFolder(this, Lang.T("saveBtn"));
        if (folder is null)
        {
            return;
        }

        foreach (var row in _clients.Values)
        {
            if (row.Entries.Count == 0)
            {
                continue;
            }

            var safe = string.Join("_", row.Key.Split(Path.GetInvalidFileNameChars()));
            var file = Path.Combine(folder, $"examlog_{safe}.jsonl");
            var sb = new StringBuilder();
            foreach (var e in row.Entries.Values)
            {
                sb.AppendLine(JsonSerializer.Serialize(e));
            }

            try
            {
                File.WriteAllText(file, sb.ToString(), Encoding.UTF8);
            }
            catch
            {
                // skip files that fail to write
            }
        }

        _statusLabel.Text = string.Format(Lang.T("savedTo"), folder);
    }
}
