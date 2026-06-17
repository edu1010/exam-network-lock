using System.Text;
using System.Text.Json;
using ExamShared;

namespace ExamMonitor;

public sealed class MainForm : Form
{
    private sealed class ClientRow
    {
        public string User = "";
        public string Machine = "";
        public string State = "Idle";
        public string StatusText = "";
        public DateTime LastSeen;
        public readonly SortedDictionary<int, LogEntry> Entries = new();
        public string Key => User + "@" + Machine;
    }

    private readonly Dictionary<string, ClientRow> _clients = new();
    private readonly MonitorListener _listener = new();
    private readonly List<Button> _flagButtons = new();

    private readonly DataGridView _grid;
    private readonly Label _statusLabel;
    private readonly Button _loadButton;
    private readonly Button _saveButton;

    private string? _logSecret;

    public MainForm()
    {
        Width = 920;
        Height = 600;
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Theme.Background;
        Font = Theme.Base;
        ForeColor = Theme.Text;

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(12),
            ColumnCount = 1,
            RowCount = 3,
            BackColor = Theme.Background
        };
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 38)); // toolbar
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); // grid
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 24)); // status

        // Toolbar: buttons (left) + flags (right)
        var toolbar = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 1, BackColor = Theme.Background };
        toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        toolbar.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight, AutoSize = true, WrapContents = false, BackColor = Theme.Background };
        _loadButton = new Button { AutoSize = true, Padding = new Padding(8, 4, 8, 4), Margin = new Padding(0, 2, 6, 2) };
        Theme.StyleSecondary(_loadButton);
        _loadButton.Click += (_, _) => LoadConfig();
        _saveButton = new Button { AutoSize = true, Padding = new Padding(8, 4, 8, 4), Margin = new Padding(0, 2, 0, 2) };
        Theme.StyleSecondary(_saveButton);
        _saveButton.Click += (_, _) => SaveLogs();
        buttons.Controls.Add(_loadButton);
        buttons.Controls.Add(_saveButton);
        toolbar.Controls.Add(buttons, 0, 0);
        toolbar.Controls.Add(BuildLanguageBar(), 2, 0);
        layout.Controls.Add(toolbar, 0, 0);

        _grid = new DataGridView
        {
            Dock = DockStyle.Fill,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            ReadOnly = true,
            RowHeadersVisible = false,
            AllowUserToResizeRows = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            MultiSelect = false,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
            BackgroundColor = Theme.Surface,
            BorderStyle = BorderStyle.None,
            EnableHeadersVisualStyles = false,
            Font = Theme.Base
        };
        _grid.ColumnHeadersDefaultCellStyle.BackColor = Theme.Surface;
        _grid.ColumnHeadersDefaultCellStyle.ForeColor = Theme.TextMuted;
        _grid.ColumnHeadersDefaultCellStyle.Font = Theme.Bold;
        _grid.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.Single;
        for (var i = 0; i < 6; i++)
        {
            _grid.Columns.Add("c" + i, "");
        }

        _grid.Columns[1].FillWeight = 60;
        _grid.Columns[3].FillWeight = 50;
        _grid.Columns[4].FillWeight = 60;
        _grid.Columns[5].FillWeight = 60;
        layout.Controls.Add(_grid, 0, 1);

        _statusLabel = new Label { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, ForeColor = Theme.TextMuted };
        layout.Controls.Add(_statusLabel, 0, 2);

        Controls.Add(layout);

        _listener.StatusReceived += m => RunOnUi(() => OnStatus(m));
        _listener.LogReceived += m => RunOnUi(() => OnLog(m));

        var refresh = new System.Windows.Forms.Timer { Interval = 1000 };
        refresh.Tick += (_, _) => RefreshGrid();
        refresh.Start();

        Load += (_, _) =>
        {
            TryAutoLoadConfig();
            _listener.Start();
        };
        FormClosing += (_, _) => _listener.Dispose();

        ApplyLanguage();
    }

    // ----- Language -----

    private Control BuildLanguageBar()
    {
        var bar = new FlowLayoutPanel { Anchor = AnchorStyles.Right, AutoSize = true, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Margin = new Padding(0), BackColor = Theme.Background };
        foreach (var language in new[] { Language.En, Language.Ca, Language.Es })
        {
            var lang = language;
            var btn = new Button { Width = 40, Height = 26, FlatStyle = FlatStyle.Flat, Image = Flags.For(lang), ImageAlign = ContentAlignment.MiddleCenter, Margin = new Padding(4, 0, 0, 0), Cursor = Cursors.Hand, Tag = lang };
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
        _loadButton.Text = Lang.T("loadBtn");
        _saveButton.Text = Lang.T("saveBtn");
        _grid.Columns[0].HeaderText = Lang.T("colStudent");
        _grid.Columns[1].HeaderText = Lang.T("colState");
        _grid.Columns[2].HeaderText = Lang.T("colIncident");
        _grid.Columns[3].HeaderText = Lang.T("colEvents");
        _grid.Columns[4].HeaderText = Lang.T("colIntegrity");
        _grid.Columns[5].HeaderText = Lang.T("colSeen");

        foreach (var btn in _flagButtons)
        {
            var selected = (Language)btn.Tag! == Lang.Current;
            btn.FlatAppearance.BorderSize = selected ? 2 : 1;
            btn.FlatAppearance.BorderColor = selected ? Theme.Accent : Theme.Border;
        }

        SetIdleStatus();
        RefreshGrid();
    }

    // ----- Incoming messages -----

    private void OnStatus(StatusMessage m)
    {
        var row = Upsert(m.User, m.Machine);
        row.State = m.State;
        row.StatusText = m.StatusText;
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
        var selectedKey = _grid.CurrentRow?.Tag as string;
        _grid.Rows.Clear();

        foreach (var row in _clients.Values.OrderBy(r => r.Key, StringComparer.OrdinalIgnoreCase))
        {
            var seconds = (int)Math.Max(0, (DateTime.Now - row.LastSeen).TotalSeconds);
            var stale = seconds > 20;
            var index = _grid.Rows.Add(
                row.Key,
                StateText(row.State),
                row.StatusText,
                row.Entries.Count.ToString(),
                Integrity(row),
                string.Format(Lang.T("secondsAgo"), seconds));

            var gridRow = _grid.Rows[index];
            gridRow.Tag = row.Key;
            var back = stale ? Theme.Idle : StateColor(row.State);
            gridRow.DefaultCellStyle.BackColor = back;
            gridRow.DefaultCellStyle.SelectionBackColor = back; // keep the state colour when selected
            gridRow.DefaultCellStyle.SelectionForeColor = stale ? Theme.TextMuted : Theme.Text;
            if (stale)
            {
                gridRow.DefaultCellStyle.ForeColor = Theme.TextMuted;
            }

            if (row.Key == selectedKey)
            {
                gridRow.Selected = true;
            }
        }
    }

    private string StateText(string state) => state switch
    {
        "Green" => Lang.T("stGreen"),
        "Yellow" => Lang.T("stYellow"),
        "Red" => Lang.T("stRed"),
        _ => Lang.T("stIdle")
    };

    private static Color StateColor(string state) => state switch
    {
        "Green" => Theme.Green,
        "Yellow" => Theme.Amber,
        "Red" => Theme.Red,
        _ => Theme.Idle
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

    private void LoadConfig()
    {
        using var dialog = new OpenFileDialog
        {
            Title = Lang.T("loadBtn"),
            Filter = "Config Files (*.config)|*.config|All Files (*.*)|*.*"
        };

        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            TryLoadConfig(dialog.FileName);
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
        _statusLabel.Text = Lang.T("listening") + "   " + (_logSecret is null ? Lang.T("noConfig") : Lang.T("configLoaded"));
    }

    // ----- Save -----

    private void SaveLogs()
    {
        using var dialog = new FolderBrowserDialog { Description = Lang.T("saveBtn") };
        if (dialog.ShowDialog(this) != DialogResult.OK)
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
            var file = Path.Combine(dialog.SelectedPath, $"examlog_{safe}.jsonl");
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

        _statusLabel.Text = string.Format(Lang.T("savedTo"), dialog.SelectedPath);
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
}
